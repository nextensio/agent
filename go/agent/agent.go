package agent

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"nextensio/agent/shared"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/fd"
	proxy "gitlab.com/nextensio/common/transport/l3proxy"
	"gitlab.com/nextensio/common/transport/webproxy"
)

const NXT_AGENT_PROXY = 8080

type flowKey struct {
	port  uint16
	proto int
}

type Iface struct {
	Fd int
	IP net.IP
}

var controller string
var regInfo shared.RegistrationInfo
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var appStreams chan common.NxtStream
var flowLock sync.RWMutex
var flows map[flowKey]common.Transport
var unique uuid.UUID
var directMode int

func flowAdd(key flowKey, tun common.Transport) {
	flowLock.Lock()
	flows[key] = tun
	flowLock.Unlock()
}

func flowDel(key flowKey, tun common.Transport) {
	flowLock.Lock()
	delete(flows, key)
	flowLock.Unlock()
}

func flowGet(key flowKey) common.Transport {
	var tun common.Transport
	flowLock.RLock()
	tun = flows[key]
	flowLock.RUnlock()
	return tun
}

// As of now we just send dns requests directly out bypassing nextensio. It is a TODO
// to parse dns requests for private domains registered with nextensio, and send a dns
// response back for those domains. The directOut/directIN APIs are for packets like dns
// that can end up bypassing nextensio
func directIn(lg *log.Logger, src *shared.ConnStats, dest common.Transport, flow *nxthdr.NxtFlow) {
	for {
		buf := make([]byte, common.MAXBUF)
		if flow.Proto == common.TCP {
			src.Conn.SetReadDeadline(time.Now().Add(shared.TCP_AGER))
		} else {
			src.Conn.SetReadDeadline(time.Now().Add(shared.UDP_AGER))
		}
		rx := src.Rx
		tx := src.Tx
		n, err := src.Conn.Read(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				// We have not had any rx/tx for the RFC stipulated flow ageout time period,
				// so close the session, this will trigger a cascade of closes upto the connector
				if rx == src.Rx && tx == src.Tx {
					src.Conn.Close()
					dest.Close()
					lg.Println("Flow aged out", flow)
					return
				}
			} else {
				// Error can be EOF with valid data (n != 0)
				if err != io.EOF || n == 0 {
					src.Conn.Close()
					dest.Close()
					return
				}
			}
		}
		src.Rx += 1
		hdr := nxthdr.NxtHdr{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: flow}
		e := dest.Write(&hdr, net.Buffers{buf[:n]})
		if e != nil {
			src.Conn.Close()
			dest.Close()
			return
		}
	}
}

func directOut(lg *log.Logger, tun common.Transport, flow *nxthdr.NxtFlow, buf net.Buffers) {
	var err *common.NxtError
	var hdr *nxthdr.NxtHdr
	if flow == nil {
		hdr, buf, err = tun.Read()
		if err != nil {
			tun.Close()
			return
		}
		flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
	}

	var e error
	dest := shared.ConnStats{}
	addr := fmt.Sprintf("%s:%d", flow.Dest, flow.Dport)
	if flow.Proto == common.TCP {
		dest.Conn, e = net.Dial("tcp", addr)
	} else {
		dest.Conn, e = net.Dial("udp", addr)
	}
	if e != nil {
		tun.Close()
		return
	}
	go directIn(lg, &dest, tun, flow)

	for {
		for _, b := range buf {
			_, e := dest.Conn.Write(b)
			if e != nil {
				tun.Close()
				dest.Conn.Close()
				return
			}
			dest.Tx += 1
		}
		_, buf, err = tun.Read()
		if err != nil {
			tun.Close()
			dest.Conn.Close()
			return
		}
	}
}

// Stream coming from the gateway, find the corresponding app stream and send
// the data to the app on that stream
func gwToApp(lg *log.Logger, tun common.Transport) {
	var dest common.Transport

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			tun.Close()
			if dest != nil {
				dest.Close()
			}
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		if dest == nil {
			key := flowKey{port: uint16(flow.Sport), proto: int(flow.Proto)}
			dest = flowGet(key)
			// As of today, agents are expected to only initiate flows, some day when
			// we allow agent to agent talk, we can do some kind of app lookup here
			// and create a new session to the app
			if dest == nil {
				tun.Close()
				return
			}
		}
		err = dest.Write(hdr, buf)
		if err != nil {
			tun.Close()
			dest.Close()
			return
		}
	}
}

// Stream coming from the app. Create a new stream to the gateway and send the
// data to the gateway
func appToGw(lg *log.Logger, tun common.Transport) {
	var dest common.Transport
	var key flowKey
	var seen bool
	var destAgent string = ""

	if gwTun == nil {
		tun.Close()
		return
	}
	dest = gwTun.NewStream(nil)
	if dest == nil {
		tun.Close()
		return
	}

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			tun.Close()
			dest.Close()
			if seen {
				flowDel(key, tun)
			}
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		// Flows that needs to bypass Nextensio. TODO: This is quite hacky at the
		// moment, we need a more nicer way to figure out the bypass-nextensio
		// flows rather than adding list of if statementes here
		if flow.Dport == 53 {
			dest.Close()
			// Copy the flow, it points inside a huge data buffer which we dont want to hold up
			go directOut(lg, tun, &*flow, buf)
			return
		}
		if !seen {
			key.port = uint16(flow.Sport)
			key.proto = int(flow.Proto)
			flowAdd(key, tun)
			seen = true
			// If we could not get a valid service name and has to default to IP address,
			// then we just have to rely on customer punching in the IP/subnet and us routing
			// based on that information
			if net.ParseIP(flow.DestAgent) == nil {
				// If the domain doesnt match any of the customer private domains, then its
				// default internet service, otherwise its a customer private service
				destAgent = "default-internet"
				for _, d := range regInfo.Domains {
					if strings.Contains(strings.ToLower(flow.DestAgent), strings.ToLower(d)) {
						destAgent = d
						break
					}
				}
			} else {
				lg.Println("Forward to ip address", flow.DestAgent, flow.Dest, "proto", flow.Proto)
				destAgent = "default-internet"
			}
		}
		if destAgent != "" {
			flow.DestAgent = destAgent
		}
		flow.SourceAgent = regInfo.ConnectID
		flow.OriginAgent = regInfo.ConnectID
		err = dest.Write(hdr, buf)
		if err != nil {
			tun.Close()
			dest.Close()
			flowDel(key, tun)
			return
		}
	}
}

// If the gateway tunnel goes down for any reason, re-create a new tunnel
func monitorGw(lg *log.Logger) {
	for {
		if gwTun == nil || gwTun.IsClosed() {
			newTun := shared.DialGateway(mainCtx, lg, "websocket", &regInfo, gwStreams)
			if newTun != nil {
				if shared.OnboardTunnel(lg, newTun, true, &regInfo, unique.String()) == nil {
					gwTun = newTun
					// Note that we are not launching an goroutines to read/write out of this
					// stream (first stream to the gateway), appToGw() always creates a new
					// stream over this session. Eventually we will support L3 raw ip pkt mode
					// for our agent and at that time the first stream will be used to tx/rx
					// all L3 packets
				} else {
					newTun.Close()
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// Onboarding succesfully completed. Now start listening for data from the apps,
// and establish tunnels to the gateway
func onboarded(lg *log.Logger) {
	// We listen for an http proxy request
	p := webproxy.NewListener(mainCtx, lg, NXT_AGENT_PROXY)
	go p.Listen(appStreams)
	// Go get the gateway tunnel up
	go monitorGw(lg)
}

func monitorStreams(lg *log.Logger) {
	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			go gwToApp(lg, stream.Stream)
		case stream := <-appStreams:
			if directMode != 0 {
				go directOut(lg, stream.Stream, nil, nil)
			} else {
				go appToGw(lg, stream.Stream)
			}
		}
	}
}

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	s := flag.String("service", "", "services advertised by this agent")
	flag.Parse()
	controller = *c
	svcs := strings.TrimSpace(*s)
	regInfo.Services = strings.Fields(svcs)
}

// LoginFile is the location where the IDP/Okta login webpages are stored,
// which user can access from the browsert on their device and onboard the agent
//
// pktFD if 0 is just ignored. If non zero, its assumed to be the descriptor
// for a device which gives us L3 packets, which we terminate and get udp/tcp
// out of it
func AgentInit(lg *log.Logger, direct int) {
	directMode = direct
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	appStreams = make(chan common.NxtStream)
	flows = make(map[flowKey]common.Transport)

	args()
	shared.OktaInit(lg, &regInfo, controller, onboarded)
	go monitorStreams(lg)
}

func AgentIface(lg *log.Logger, iface *Iface) {
	// If the agent has a source of l3 IP packets, then we also try and
	// terminate them to get tcp/udp out of it and forward them. The l3proxy
	// is a combination of a source of l3 IP packets (a file descriptor here)
	// and a proxy that terminates the packets to tcp/udp
	f := fd.NewClient(mainCtx, lg, uintptr(iface.Fd))
	f.Dial(appStreams)
	p := proxy.NewListener(mainCtx, lg, f, iface.IP)
	go p.Listen(appStreams)
}
