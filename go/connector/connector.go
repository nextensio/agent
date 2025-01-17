package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	nhttp2 "gitlab.com/nextensio/common/go/transport/http2"
	"gitlab.com/nextensio/common/go/transport/netconn"
	websock "gitlab.com/nextensio/common/go/transport/websocket"
)

type flowKey struct {
	sport uint32
	dport uint32
	proto uint32
	src   string
	dest  string
}

type flowTuns struct {
	app  common.Transport
	gwRx common.Transport
}

var Version = "Development"
var pool common.NxtPool
var flowLock sync.RWMutex
var flows map[flowKey]*flowTuns
var gw_onboarded bool
var onboarded bool
var uniqueId string
var controller string
var regInfo RegistrationInfo
var regInfoLock sync.RWMutex
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var appStreams chan common.NxtStream
var unique uuid.UUID
var gateway *string
var keyFile *string
var sharedKey string
var cluster string
var ports []int = []int{}
var gatewayIP uint32
var deviceName string
var totGoRoutines int32

func flowAdd(key *flowKey, app common.Transport) {
	flowLock.Lock()
	defer flowLock.Unlock()

	flows[*key] = &flowTuns{app: app, gwRx: nil}
}

func flowDel(key *flowKey) {
	flowLock.Lock()
	defer flowLock.Unlock()

	tun := flows[*key]
	if tun != nil {
		delete(flows, *key)
		if tun.gwRx != nil {
			tun.gwRx.Close()
		}
	}

}

func flowGet(key flowKey, gwRx common.Transport) common.Transport {
	flowLock.Lock()
	defer flowLock.Unlock()

	tun := flows[key]
	if tun != nil {
		tun.gwRx = gwRx
		return tun.app
	}
	return nil
}

func gwToAppClose(tun common.Transport, dest ConnStats) {
	tun.Close()
	if dest.Conn != nil {
		dest.Conn.Close()
	}
}

var cacert []byte

// Stream coming from the gateway, send data over tcp/udp socket on the connector
func gwToApp(lg *log.Logger, tun common.Transport, dest ConnStats) {
	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			lg.Printf("gwToApp read error %v\n", err)
			gwToAppClose(tun, dest)
			return
		}
		tlen := 0
		for _, l := range buf.Slices {
			tlen += len(l)
		}
		lg.Printf("Received stream from gw with %d slices and data length %d\n", len(buf.Slices), tlen)
		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Onboard:
			lg.Println("Got onboard response")
		case *nxthdr.NxtHdr_Flow:
			isHttp := false
			if dest.Conn == nil {
				flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
				lg.Printf("Got new flow from %s for %s\n", flow.SourceAgent, flow.Dest)
				if flow.TraceCtx != "" {
					// Save the time now for calculating the process elapsed time when sending the packet back to
					// the connector in appToGw()
					flow.ProcessingDuration = uint64(time.Now().UnixNano())
				}
				key := flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
				dest.Conn = flowGet(key, tun)
				if dest.Conn == nil {
					method := ""
					if flow.Proto == common.HTTP {
						isHttp = true
						lg.Printf("Agentless HTTP flow received for %s from %s:%d\n", flow.HttpMethod, flow.Dest, flow.Dport)
						// open http connection to app server
						reqhdr := make(http.Header)
						for i, k := range flow.HttpKeys {
							reqhdr.Add(k, flow.HttpValues[i])
							lg.Printf("HTTP header [%d]: %s: %s\n", i, k, flow.HttpValues[i])
						}
						method = flow.HttpMethod
						dest.Conn = nhttp2.NewClient(mainCtx, lg, pool, cacert, flow.Dest,
							flow.Dest, int(flow.Dport), reqhdr, &totGoRoutines, 10000, 1000, false)
					} else if flow.Proto == common.TCP {
						lg.Println("Agent TCP flow received")
						dest.Conn = netconn.NewClient(mainCtx, lg, pool, "tcp", flow.DestSvc, flow.Dport)
					} else {
						lg.Println("Agent UDP flow received")
						dest.Conn = netconn.NewClient(mainCtx, lg, pool, "udp", flow.DestSvc, flow.Dport)
					}
					// the appStreams passed here never gets used
					e := dest.Conn.Dial(appStreams, method)
					if e != nil {
						lg.Printf("Could not dial out %s to app %s\n", method, flow.DestSvc)
						gwToAppClose(tun, dest)
						return
					}
					lg.Printf("Dialed out %s to app %s\n", method, flow.DestSvc)

					// This flow is originated for the first time from the gateway
					// to connector, so lets create a reverse direction here. Otherwise
					// the flow is originated from the connector to gateway, so reverse already exists
					newTun := tun.NewStream(nil)
					if newTun == nil {
						lg.Println("Could not open new stream to gw")
						gwToAppClose(tun, dest)
						return
					}
					lg.Println("Opened new stream to gw")

					// copy the flow
					newFlow := *flow
					// Swap source and dest agents
					s, d := newFlow.SourceAgent, newFlow.DestAgent
					newFlow.SourceAgent, newFlow.DestAgent = d, s
					newFlow.ResponseData = true
					newFlow.HttpKeys = []string{}
					newFlow.HttpValues = []string{}
					var timeout time.Duration
					if newFlow.Proto == common.UDP {
						timeout = UDP_AGER
					} else {
						timeout = TCP_AGER
					}
					lg.Printf("Forking process to reply back to gw from app %s\n", flow.DestSvc)
					go appToGw(lg, &dest, newTun, timeout, &newFlow, tun)
				}
			}
			var e error
			if isHttp {
				lg.Println("Writing buf to http connection")
				e = dest.Conn.Write(nil, buf)
				lg.Println("Returned from write to http connection")
			} else {
				lg.Println("Writing buf to TCP/UDP connection")
				e = dest.Conn.Write(hdr, buf)
				lg.Println("Returned from write to TCP/UDP connection")
			}
			if e != nil {
				lg.Printf("Gw to app write failed - %v\n", e)
				gwToAppClose(tun, dest)
				return
			}
			lg.Println("Gw to app write done")
			dest.Tx += 1
		}
	}
}

func appToGwClose(src *ConnStats, dest common.Transport, gwRx common.Transport, key *flowKey) {
	src.Conn.Close()
	dest.Close()
	if gwRx != nil {
		gwRx.Close()
	}
	if key != nil {
		flowDel(key)
	}
}

// Data coming back from a tcp/udp socket. Send the data over the gateway
// stream that initially created the socket
// NOTE NOTE NOTE: The flow structure here is "pointed to"/referred by every single
// packet, the assumption is the flow structure doesnt change. So if we suddenly change
// the flow structure in one packet, it can mess up the previous packets. So if we need
// to change the flow structure, it has to be a copy first
func appToGw(lg *log.Logger, src *ConnStats, dest common.Transport, timeout time.Duration, flow *nxthdr.NxtFlow, gwRx common.Transport) {

	var key *flowKey
	var destAgent string = ""
	// If the destination (Tx) closes, close the rx also so the entire goroutine exits and
	// the close is cascaded to the the cluster
	dest.CloseCascade(src.Conn)
	lg.Printf("Entered appToGw for response from app %s\n", flow.DestSvc)

	for {
		src.Conn.SetReadDeadline(time.Now().Add(timeout))
		rx := src.Rx
		tx := src.Tx
		hdr, buf, err := src.Conn.Read()
		if err != nil {
			lg.Printf("appToGw: read error from app - %v", err)
			ignore := false
			if err.Err != nil {
				if e, ok := err.Err.(net.Error); ok && e.Timeout() {
					// We have not had any rx/tx for the RFC stipulated flow ageout time period,
					// so close the session, this will trigger a cascade of closes upto the connector
					if rx == src.Rx && tx == src.Tx {
						lg.Println("Flow aged out", *flow)
					} else {
						ignore = true
					}
				}
			}
			if !ignore {
				appToGwClose(src, dest, gwRx, key)
				return
			}
		}
		lg.Println("appToGw: read response from app")
		src.Rx += 1
		// if hdr is nil, that means this is a gateway originated flow, if its non-nil then
		// its a connector originated flow (a "server" NetConn). If hdr is nil, then the
		// flow details are passed in as a copy of the flow that came in from the gateway.
		// If hdr is non-nil, that contains details parsed from the packet, so we construct
		// a flow using those parsed details
		if hdr == nil {
			lg.Println("appToGw: flow from gw")
			var hdrFlow *nxthdr.NxtFlow
			if flow.TraceCtx != "" {
				// Calculate the elapsed time for processing this packet before sending it back to connector
				start := time.Unix(0, int64(flow.ProcessingDuration))
				elapsed := time.Since(start).Nanoseconds()
				// The flow is already being used by previously sent packets which are possibly
				// queued up to be sent. The flow contents will be used to decide the on-wire
				// data length etc.. So if we suddenly change that here, the previous packet's
				// on wire length will get messed up, so create a copy of the flow and change that
				newFlow := *flow
				newFlow.ProcessingDuration = uint64(elapsed)
				hdrFlow = &newFlow
				//Set the flow.TraceCtx to NULL after the first pkt as we dont need to carry the same traceCtx
				flow.TraceCtx = ""
			} else {
				hdrFlow = flow
			}
			hdr = &nxthdr.NxtHdr{}
			hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: hdrFlow}
		} else {
			// We are saving this flow in the hashtable only in the case of a "connector originated flow",
			// because when the response comes back from the gateway, we need to find the socket for the
			// connector origin side of the flow. We could keep this common for connector/gateway originated
			// and cache the flow all the time, but there is no need as of today and hence why waste memory
			// since the bulk of the use case will be gateway originated flows
			lg.Println("appToGw: flow from Connector")
			flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			if destAgent == "" {
				// TODO: Do we need the reginfoLock here ? I think not because when we get
				// onboarding results we are just replacing stuff rather than adding/deleting stuff
				for _, d := range regInfo.Domains {
					if strings.Contains(flow.DestSvc, d.Name) {
						destAgent = d.Name
					}
				}
				// No service advertised that matches the one we want
				if destAgent == "" {
					lg.Printf("appToGw: Closing connection as service to %s not found\n", destAgent)
					appToGwClose(src, dest, gwRx, key)
					return
				}
			}
			flow.SourceAgent = regInfo.ConnectID
			flow.DestAgent = destAgent
			flow.ResponseData = false
			if key == nil {
				key = &flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
				flowAdd(key, src.Conn)
			}
		}
		e := dest.Write(hdr, buf)
		if e != nil {
			lg.Printf("appToGw: write to gw failed - %v\n", e)
			appToGwClose(src, dest, gwRx, key)
			return
		}
		lg.Println("appToGw: write to gw successful")
	}
}

func monitorController(lg *log.Logger) {
	var keepalive uint = 30
	force_onboard := false

	last_keepalive := time.Now()
	for {
		if onboarded {
			if uint(time.Since(last_keepalive).Seconds()) >= keepalive {
				force_onboard = ControllerKeepalive(lg, controller, sharedKey, regInfo.Version)
				last_keepalive = time.Now()
			}
		}
		if !onboarded || force_onboard {
			if ControllerOnboard(lg, controller, sharedKey) {
				onboarded = true
				force_onboard = false
				gw_onboarded = false
				if regInfo.Keepalive == 0 {
					keepalive = 5 * 60
				} else {
					keepalive = regInfo.Keepalive
				}
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// Create a websocket session to the gateway
func dialWebsocket(ctx context.Context, lg *log.Logger, regInfo *RegistrationInfo, c chan common.NxtStream) common.Transport {
	regInfoLock.RLock()
	req := http.Header{}
	req.Add("x-nextensio-connect", regInfo.ConnectID)
	// Ask for a keepalive to be sent once in two seconds
	wsock := websock.NewClient(ctx, lg, pool, []byte(string(regInfo.CACert)), regInfo.Gateway, regInfo.Gateway, 443, req, 2*1000)
	regInfoLock.RUnlock()
	if err := wsock.Dial(c, ""); err != nil {
		lg.Println("Cannot dial websocket", err, regInfo.ConnectID)
		return nil
	}

	return wsock
}

// Create a tunnel/session to the gateway with the given encap. We can expect
// more and more encap types to get added here over time (like rsocket for example)
func DialGateway(ctx context.Context, lg *log.Logger, encap string, regInfo *RegistrationInfo, c chan common.NxtStream) common.Transport {
	if encap == "websocket" {
		return dialWebsocket(ctx, lg, regInfo, c)
	} else {
		panic(encap)
	}
}

// Protobuf encode the device onboard information and send to the gateway
func OnboardTunnel(lg *log.Logger, tunnel common.Transport, isAgent bool, regInfo *RegistrationInfo, uuid string) *common.NxtError {
	regInfoLock.RLock()
	p := &nxthdr.NxtOnboard{
		Agent: isAgent, Userid: regInfo.Userid, Uuid: uuid,
		AccessToken: regInfo.AccessToken, Services: regInfo.Services,
		Cluster:   regInfo.Cluster,
		ConnectId: regInfo.ConnectID,
	}
	regInfoLock.RUnlock()

	hdr := nxthdr.NxtHdr{Hdr: &nxthdr.NxtHdr_Onboard{p}}
	err := tunnel.Write(&hdr, &common.NxtBufs{Slices: net.Buffers{}})
	if err != nil {
		return err
	}
	return nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func getGatewayIP(lg *log.Logger) {
	ips, e := net.LookupIP(regInfo.Gateway)
	if e == nil {
		for _, ip := range ips {
			i := ip.To4()
			if i != nil {
				gatewayIP = ip2int(i)
				lg.Println("Gateway IP is ", gatewayIP)
				break
			}
		}
	} else {
		lg.Println("Cannot find gateway IP: ", e)
	}
}

// If the gateway tunnel goes down for any reason, re-create a new tunnel
func monitorGw(lg *log.Logger) {
	for {
		if onboarded {
			if gw_onboarded && gatewayIP == 0 {
				getGatewayIP(lg)
			}
			if gwTun == nil || gwTun.IsClosed() {
				gw_onboarded = false
				gatewayIP = 0
				// Override gateway if one is suppled on command line
				if regInfo.Gateway == "" || *gateway != "gateway.nextensio.net" {
					regInfo.Gateway = *gateway
				}
				cluster = getClusterName(regInfo.Gateway)
				gwTun = DialGateway(mainCtx, lg, "websocket", &regInfo, gwStreams)
				if gwTun != nil {
					// The only data this will get is onboard response/control messages,
					// data does not flow on the first stream (stream 0)
					go gwToApp(lg, gwTun, ConnStats{})
				}
			} else {
				if !gw_onboarded {
					if OnboardTunnel(lg, gwTun, false, &regInfo, uniqueId) == nil {
						lg.Println("Onboarded with gateway")
						gw_onboarded = true
						// Note that we are not launching an goroutines to read/write out of this
						// stream (first stream to the gateway), appToGw() always creates a new
						// stream over this session. Eventually we will support L3 raw ip pkt mode
						// for our agent and at that time the first stream will be used to tx/rx
						// all L3 packets
					} else {
						gwTun.Close()
						gatewayIP = 0
					}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func getClusterName(gateway string) string {
	if len(gateway) <= len(".nextensio.net") {
		return "unknown"
	}
	end := len(gateway) - len(".nextensio.net")
	return gateway[0:end]
}

func args() (*log.Logger, *os.File) {
	var fptr *os.File
	var err error
	var version bool

	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	gateway = flag.String("gateway", "gateway.nextensio.net", "Gateway name")
	keyFile = flag.String("key", "/opt/nextensio/connector.key", "Secret Key file name")
	p := flag.String("ports", "", "Ports to listen on, comma seperated")
	logFile := flag.String("logfile", "/tmp/connector.log", "Log file name")
	flag.BoolVar(&version, "version", false, "Show the Connector version information")
	flag.Parse()

	if version {
		fmt.Printf("Connector version - %s \n", Version)
		os.Exit(0)
	}
	if *logFile != "" {
		fmt.Println("Creating logfile ", *logFile)
		fptr, err = os.OpenFile(*logFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	lg := log.New(fptr, "CNTR: ", log.Ldate|log.Ltime)
	if *p != "" {
		plist := strings.Split(*p, ",")
		for _, l := range plist {
			p1, e := strconv.Atoi(l)
			if e != nil {
				fmt.Println("Ports need to be comma seperated integers: ", *p)
				os.Exit(1)
			}
			ports = append(ports, p1)
		}
	}
	controller = *c
	if _, err := os.Stat(*keyFile); err == nil {
		s, e := ioutil.ReadFile(*keyFile)
		if e != nil {
			fmt.Println("Cannot read from key file: ", *keyFile, e)
			os.Exit(1)
		}
		sharedKey = string(s)
	} else if err != nil {
		// If there is no such file, then treat the input as the key itself
		sharedKey = *keyFile
	} else {
		fmt.Println("key file does not exist: ", *keyFile, err)
		os.Exit(1)
	}
	sharedKey = strings.TrimSpace(sharedKey)
	sharedKey = strings.TrimRight(strings.TrimLeft(sharedKey, "\n"), "\n")
	lg.Println("Connector version : ", Version)
	lg.Println(*c, *gateway, cluster, ports)
	return lg, fptr
}

func svrListen(lg *log.Logger, conn *netconn.NetConn, port int) {
	for {
		conn.Listen(appStreams)
		lg.Fatalf("Listen failed on port ", port)
	}
}

func svrAccept(lg *log.Logger) {
	for {
		select {
		case stream := <-appStreams:
			if gwTun == nil {
				// We are not ready yet
				stream.Stream.Close()
			} else {
				newTun := gwTun.NewStream(nil)
				if newTun == nil {
					lg.Println("Cannot create new gateway stream")
					stream.Stream.Close()
				} else {
					// Right now we support only tcp
					var dest ConnStats
					dest.Conn = stream.Stream
					go appToGw(lg, &dest, newTun, TCP_AGER, nil, nil)
				}
			}
		}
	}
}

func deviceInfo() {
	host := "localhost"
	h, e := os.Hostname()
	if e == nil {
		host = h
	}
	deviceName = fmt.Sprintf("%s [%d]", host, os.Getpid())
}

func main() {
	deviceInfo()
	pool = common.NewPool(64 * 1024)
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	appStreams = make(chan common.NxtStream)
	flows = make(map[flowKey]*flowTuns)
	lg, fptr := args()
	if fptr != nil {
		defer fptr.Close()
	}
	uniqueId = unique.String()
	go monitorController(lg)
	go monitorGw(lg)

	for _, p := range ports {
		// Right now we support only tcp
		conn := netconn.NewClient(mainCtx, lg, pool, "tcp", "", uint32(p))
		go svrListen(lg, conn, p)
	}
	go svrAccept(lg)
	go getLocalIP()

	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			var dest ConnStats
			go gwToApp(lg, stream.Stream, dest)
		}
	}
}
