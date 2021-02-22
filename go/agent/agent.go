package agent

import (
	"context"
	"flag"
	"log"
	"net"
	"nextensio/agent/shared"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/fd"
	proxy "gitlab.com/nextensio/common/transport/l3proxy"
	"gitlab.com/nextensio/common/transport/netconn"
	"gitlab.com/nextensio/common/transport/webproxy"
)

const NXT_AGENT_PROXY = 8080

type flowInfo struct {
	app  common.Transport
	gwRx common.Transport
}

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
var flows map[flowKey]*flowInfo
var unique uuid.UUID
var directMode int
var initDone bool
var onboardedOnce bool
var initLock sync.Mutex
var tunDisco int
var tunConn int
var tunLastDisco time.Time
var directFlows int32
var osplatform int

func flowAdd(key flowKey, tun common.Transport) {
	flowLock.Lock()
	flows[key] = &flowInfo{app: tun}
	flowLock.Unlock()
}

func flowDel(key flowKey) {
	flowLock.Lock()
	info := flows[key]
	if info != nil && info.gwRx != nil {
		info.gwRx.Close()
	}
	delete(flows, key)
	flowLock.Unlock()
}

func flowGet(key flowKey, gwRx common.Transport) common.Transport {
	var tun common.Transport
	flowLock.RLock()
	info := flows[key]
	if info != nil {
		tun = info.app
		info.gwRx = gwRx
	}
	flowLock.RUnlock()
	return tun
}

func directInClose(src *shared.ConnStats, dest common.Transport) {
	src.Conn.Close()
	dest.Close()
}

// As of now we just send dns requests directly out bypassing nextensio. It is a TODO
// to parse dns requests for private domains registered with nextensio, and send a dns
// response back for those domains. The directOut/directIN APIs are for packets like dns
// that can end up bypassing nextensio
func directIn(lg *log.Logger, src *shared.ConnStats, dest common.Transport, flow *nxthdr.NxtFlow) {
	for {
		if flow.Proto == common.TCP {
			src.Conn.SetReadDeadline(time.Now().Add(shared.TCP_AGER))
		} else {
			src.Conn.SetReadDeadline(time.Now().Add(shared.UDP_AGER))
		}
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
						lg.Println("Flow aged out", flow)
					} else {
						ignore = true
					}
				}
			}
			if !ignore {
				directInClose(src, dest)
				return
			}
		}
		src.Rx += 1
		hdr = &nxthdr.NxtHdr{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: flow}
		e := dest.Write(hdr, buf)
		if e != nil {
			directInClose(src, dest)
			return
		}
	}
}

func directOutClose(tun common.Transport, dest shared.ConnStats) {
	tun.Close()
	if dest.Conn != nil {
		dest.Conn.Close()
	}
	atomic.AddInt32(&directFlows, -1)
}

func directOut(lg *log.Logger, tun common.Transport, flow *nxthdr.NxtFlow, buf net.Buffers) {
	var err *common.NxtError
	var hdr *nxthdr.NxtHdr
	dest := shared.ConnStats{}

	if flow == nil {
		hdr, buf, err = tun.Read()
		if err != nil {
			directOutClose(tun, dest)
			return
		}
		flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
	}

	if flow.Proto == common.TCP {
		dest.Conn = netconn.NewClient(mainCtx, lg, "tcp", flow.Dest, flow.Dport)
	} else {
		dest.Conn = netconn.NewClient(mainCtx, lg, "udp", flow.Dest, flow.Dport)
	}
	e := dest.Conn.Dial(appStreams)
	if e != nil {
		directOutClose(tun, dest)
		return
	}
	go directIn(lg, &dest, tun, flow)

	for {
		e := dest.Conn.Write(hdr, buf)
		if e != nil {
			directOutClose(tun, dest)
			return
		}
		dest.Tx += 1
		_, buf, err = tun.Read()
		if err != nil {
			directOutClose(tun, dest)
			return
		}
	}
}

func gwToAppClose(tun common.Transport, dest common.Transport) {
	tun.Close()
	if dest != nil {
		dest.Close()
	}
}

// Stream coming from the gateway, find the corresponding app stream and send
// the data to the app on that stream
func gwToApp(lg *log.Logger, tun common.Transport) {
	var dest common.Transport

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			gwToAppClose(tun, dest)
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		if dest == nil {
			key := flowKey{port: uint16(flow.Sport), proto: int(flow.Proto)}
			dest = flowGet(key, tun)
			// As of today, agents are expected to only initiate flows, some day when
			// we allow agent to agent talk, we can do some kind of app lookup here
			// and create a new session to the app
			if dest == nil {
				gwToAppClose(tun, dest)
				return
			}
		}
		err = dest.Write(hdr, buf)
		if err != nil {
			gwToAppClose(tun, dest)
			return
		}
	}
}

func appToGwClose(tun common.Transport, dest common.Transport, seen bool, key flowKey) {
	tun.Close()
	if dest != nil {
		dest.Close()
	}
	if seen {
		flowDel(key)
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
		appToGwClose(tun, dest, seen, key)
		return
	}
	dest = gwTun.NewStream(nil)
	if dest == nil {
		appToGwClose(tun, dest, seen, key)
		return
	}
	// If the destination (Tx) closes, close the rx also so the entire goroutine exits and
	// the close is cascaded to the the cluster
	dest.CloseCascade(tun)

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			appToGwClose(tun, dest, seen, key)
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		// Flows that needs to bypass Nextensio. TODO: This is quite hacky at the
		// moment, we need a more nicer way to figure out the bypass-nextensio
		// flows rather than adding list of if statementes here
		if flow.Dport == 53 {
			dest.Close()
			atomic.AddInt32(&directFlows, 1)
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
			appToGwClose(tun, dest, seen, key)
			return
		}
	}
}

// If the gateway tunnel goes down for any reason, re-create a new tunnel
func monitorGw(lg *log.Logger) {
	var tmp common.Transport
	for {
		if gwTun == nil || gwTun.IsClosed() {
			if gwTun != tmp {
				tunDisco += 1
				tunConn = 0
				tunLastDisco = time.Now()
				tmp = gwTun
			}
			newTun := shared.DialGateway(mainCtx, lg, "websocket", &regInfo, gwStreams)
			if newTun != nil {
				if shared.OnboardTunnel(lg, newTun, true, &regInfo, unique.String()) == nil {
					gwTun = newTun
					tunConn = 1
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
	if !onboardedOnce {
		// We listen for an http proxy request
		p := webproxy.NewListener(mainCtx, lg, NXT_AGENT_PROXY)
		go p.Listen(appStreams)
		// Go get the gateway tunnel up
		go monitorGw(lg)
		onboardedOnce = true
	} else {
		// Well if the user is tryng to onboard again, we should disconnect
		// our gateway tunnels and reconnect with the new onboarding info
		if gwTun != nil {
			gwTun.Close()
		}
	}
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

// direct is usually a test-only mode where if set to value 1, the agent is being instructed
// to send all traffic directly to internet bypassing nextensio tunnels.
// Various agents like android/ios may end up calling AgentInit multiple times depending
// on how their UI/Networking components are loaded and in which order etc.., so we ensure
// the init is done just once
func AgentInit(lg *log.Logger, osplat int, direct int) {
	initLock.Lock()
	if !initDone {
		directMode = direct
		mainCtx = context.Background()
		unique = uuid.New()
		gwStreams = make(chan common.NxtStream)
		appStreams = make(chan common.NxtStream)
		flows = make(map[flowKey]*flowInfo)
		osplatform = osplat

		args()
		shared.OktaInit(lg, &regInfo, controller, onboarded)
		go monitorStreams(lg)
		initDone = true
	}
	initLock.Unlock()
}

func AgentIface(lg *log.Logger, iface *Iface) {
	// If the agent has a source of l3 IP packets, then we also try and
	// terminate them to get tcp/udp out of it and forward them. The l3proxy
	// is a combination of a source of l3 IP packets (a file descriptor here)
	// and a proxy that terminates the packets to tcp/udp
	f := fd.NewClient(mainCtx, osplatform, lg, uintptr(iface.Fd))
	f.Dial(appStreams)
	p := proxy.NewListener(mainCtx, lg, f, iface.IP)
	go p.Listen(appStreams)
}

type AgentStats struct {
	Alloc             uint64
	TotalAlloc        uint64
	Sys               uint64
	Mallocs           uint64
	Frees             uint64
	PauseTotalNs      uint64
	NumGC             uint32
	DirectFlows       int32
	NumFlows          int
	NumGoroutine      int
	TunnelDisconnects int
	TunnelConnected   int
	TunnelDiscoSecs   int
}

func GetStats() *AgentStats {
	var m AgentStats
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)
	m.NumGoroutine = runtime.NumGoroutine()
	m.Alloc = rtm.Alloc
	m.TotalAlloc = rtm.TotalAlloc
	m.Sys = rtm.Sys
	m.Mallocs = rtm.Mallocs
	m.Frees = rtm.Frees
	m.PauseTotalNs = rtm.PauseTotalNs
	m.NumGC = rtm.NumGC

	m.TunnelDisconnects = tunDisco
	m.TunnelConnected = tunConn
	if tunDisco != 0 {
		m.TunnelDiscoSecs = int(time.Now().Sub(tunLastDisco) / time.Second)
	}
	flowLock.Lock()
	m.NumFlows = len(flows)
	flowLock.Unlock()
	m.DirectFlows = directFlows

	return &m
}
