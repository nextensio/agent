package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"gitlab.com/nextensio/common/go/transport/netconn"
	"golang.org/x/crypto/ssh/terminal"
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

var flowLock sync.RWMutex
var flows map[flowKey]*flowTuns

var controller string
var regInfo RegistrationInfo
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var appStreams chan common.NxtStream
var unique uuid.UUID
var username *string
var password *string
var idp *string
var clientid *string
var gateway *string
var ports []int = []int{}

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

// Stream coming from the gateway, send data over tcp/udp socket on the connector
func gwToApp(lg *log.Logger, tun common.Transport, dest ConnStats) {

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			gwToAppClose(tun, dest)
			return
		}
		if dest.Conn == nil {
			flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			key := flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
			dest.Conn = flowGet(key, tun)
			if dest.Conn == nil {
				if flow.Proto == common.TCP {
					dest.Conn = netconn.NewClient(mainCtx, lg, "tcp", flow.DestSvc, flow.Dport)
				} else {
					dest.Conn = netconn.NewClient(mainCtx, lg, "udp", flow.DestSvc, flow.Dport)
				}
				// the appStreams passed here never gets used
				e := dest.Conn.Dial(appStreams)
				if e != nil {
					gwToAppClose(tun, dest)
					return
				}

				// This flow is originated for the first time from the gateway
				// to connector, so lets create a reverse direction here. Otherwise
				// the flow is originated from the connector to gateway, so reverse already exists
				newTun := tun.NewStream(nil)
				if newTun == nil {
					gwToAppClose(tun, dest)
					return
				}
				// copy the flow
				newFlow := *flow
				// Swap source and dest agents
				s, d := newFlow.SourceAgent, newFlow.DestAgent
				newFlow.SourceAgent, newFlow.DestAgent = d, s
				newFlow.ResponseData = true
				var timeout time.Duration
				if newFlow.Proto == common.TCP {
					timeout = TCP_AGER
				} else {
					timeout = UDP_AGER
				}
				go appToGw(lg, &dest, newTun, timeout, &newFlow, tun)
			}
		}
		e := dest.Conn.Write(hdr, buf)
		if e != nil {
			gwToAppClose(tun, dest)
			return
		}
		dest.Tx += 1
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
func appToGw(lg *log.Logger, src *ConnStats, dest common.Transport, timeout time.Duration, flow *nxthdr.NxtFlow, gwRx common.Transport) {

	var key *flowKey
	var destAgent string
	// If the destination (Tx) closes, close the rx also so the entire goroutine exits and
	// the close is cascaded to the the cluster
	dest.CloseCascade(src.Conn)

	for {
		src.Conn.SetReadDeadline(time.Now().Add(timeout))
		rx := src.Rx
		tx := src.Tx
		hdr, buf, err := src.Conn.Read()
		if err != nil {
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
		src.Rx += 1
		// if hdr is nil, that means this is a gateway originated flow, if its non-nil then
		// its a connector originated flow (a "server" NetConn). If hdr is nil, then the
		// flow details are passed in as a copy of the flow that came in from the gateway.
		// If hdr is non-nil, that contains details parsed from the packet, so we construct
		// a flow using those parsed details
		if hdr == nil {
			hdr = &nxthdr.NxtHdr{}
			hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: flow}
		} else {
			// We are saving this flow in the hashtable only in the case of a "connector originated flow",
			// because when the response comes back from the gateway, we need tp find the socket for the
			// connector origin side of the flow. We could keep this common for connector/gateway originated
			// and cache the flow all the time, but there is no need as of today and hence why waste memory
			// since the bulk of the use case will be gateway originated flows
			flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			if destAgent == "" {
				for _, d := range regInfo.Domains {
					if strings.Contains(flow.DestSvc, d) {
						destAgent = d
					}
				}
				// No service advertised that matches the one we want
				if destAgent == "" {
					appToGwClose(src, dest, gwRx, key)
					return
				}
			}
			flow.SourceAgent = regInfo.Services[0]
			flow.DestAgent = destAgent
			flow.ResponseData = false
			if key == nil {
				key = &flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
				flowAdd(key, src.Conn)
			}
		}
		e := dest.Write(hdr, buf)
		if e != nil {
			appToGwClose(src, dest, gwRx, key)
			return
		}
	}
}

// If the gateway tunnel goes down for any reason, re-create a new tunnel
func monitorGw(lg *log.Logger) {
	flaps := 0
	count := 0
	for {
		if gwTun == nil || gwTun.IsClosed() {
			if gwTun != nil {
				flaps += 1
			}
			// Override gateway if one is suppled on command line
			if *gateway != "" {
				regInfo.Host = *gateway
			}
			newTun := DialGateway(mainCtx, lg, "websocket", &regInfo, gwStreams)
			if newTun != nil {
				if OnboardTunnel(lg, newTun, false, &regInfo, unique.String()) == nil {
					gwTun = newTun
					// Note that we are not launching an goroutines to read/write out of this
					// stream (first stream to the gateway), appToGw() always creates a new
					// stream over this session. Eventually we will support L3 raw ip pkt mode
					// for our agent and at that time the first stream will be used to tx/rx
					// all L3 packets
				} else {
					newTun.Close()
					flaps += 1
				}
			} else {
				flaps += 1
			}
		}
		time.Sleep(2 * time.Second)
		count += 1
		if count >= 5 { /* 10 seconds */
			if flaps >= 3 {
				// Too many flaps, try onboarding again, maybe some parameters have been changed
				// on the controller
				authAndOnboard(lg)
				lg.Println("Re onboarding")
			}
			count = 0
			flaps = 0
		}
	}
}

func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Nextensio Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Nextensio Password: ")
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	username = flag.String("username", "", "connector onboarding userid")
	password = flag.String("password", "", "connector onboarding password")
	idp = flag.String("idp", "https://dev-24743301.okta.com", "IDP to use to onboard")
	clientid = flag.String("client", "0oav0q3hn65I4Zkmr5d6", "IDP client id")
	gateway = flag.String("gateway", "", "Gateway name")
	p := flag.String("ports", "", "Ports to listen on, comma seperated")
	flag.Parse()
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
	if *username == "" || *password == "" {
		*username, *password = credentials()
	}
	fmt.Println(*c, *username, *password, *idp, *clientid, *gateway, ports)
}

func authAndOnboard(lg *log.Logger) bool {
	tokens := authenticate(*idp, *clientid, *username, *password)
	if tokens == nil {
		lg.Println("Unable to authenticate connector with the IDP")
		return false
	}
	regInfo = RegistrationInfo{}
	regInfo.AccessToken = tokens.AccessToken
	return OktaInit(lg, &regInfo, controller)
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
			lg.Println("Accept stream")
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

func main() {
	common.MAXBUF = (64 * 1024)
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	appStreams = make(chan common.NxtStream)
	flows = make(map[flowKey]*flowTuns)
	lg := log.New(os.Stdout, "CNTR\n", 0)
	args()
	for {
		if authAndOnboard(lg) == false {
			lg.Println("Unable to authenticate connector, retrying in five seconds")
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}
	go monitorGw(lg)

	for _, p := range ports {
		// Right now we support only tcp
		conn := netconn.NewClient(mainCtx, lg, "tcp", "", uint32(p))
		go svrListen(lg, conn, p)
	}
	go svrAccept(lg)

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
