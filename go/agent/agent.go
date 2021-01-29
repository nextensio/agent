package main

import (
	"context"
	"flag"
	"net"
	"nextensio/agent/shared"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/webproxy"
)

const NXT_AGENT_PROXY = 8080

type flowKey struct {
	port  uint16
	proto int
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

// Stream coming from the gateway, find the corresponding app stream and send
// the data to the app on that stream
func gwToApp(tun common.Transport) {
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
func appToGw(tun common.Transport) {
	var dest common.Transport
	var key flowKey
	var added bool

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
			if added {
				flowDel(key, tun)
			}
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		if !added {
			key.port = uint16(flow.Sport)
			key.proto = int(flow.Proto)
			flowAdd(key, tun)
			added = true
		}
		// If we could not get a valid service name and has to default to IP address,
		// then we just have to rely on customer punching in the IP/subnet and us routing
		// based on that information
		if net.ParseIP(flow.DestAgent) == nil {
			// If the domain doesnt match any of the customer private domains, then its
			// default internet service, otherwise its a customer private service
			flow.DestAgent = "default-internet"
			for _, d := range regInfo.Domains {
				if strings.Contains(flow.DestAgent, d) {
					flow.DestAgent = d
					break
				}
			}
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
func monitorGw() {
	for {
		if gwTun == nil || gwTun.IsClosed() {
			newTun := shared.DialGateway(mainCtx, "websocket", &regInfo, gwStreams)
			if newTun != nil {
				if shared.OnboardTunnel(newTun, true, &regInfo, unique.String()) == nil {
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
func onboarded() {
	p := webproxy.NewListener(NXT_AGENT_PROXY)
	go p.Listen(appStreams)
	go monitorGw()
}

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	s := flag.String("service", "", "services advertised by this agent")
	flag.Parse()
	controller = *c
	svcs := strings.TrimSpace(*s)
	regInfo.Services = strings.Fields(svcs)
}

func main() {
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	appStreams = make(chan common.NxtStream)
	flows = make(map[flowKey]common.Transport)

	args()
	shared.OktaInit(&regInfo, controller, onboarded)

	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			go gwToApp(stream.Stream)
		case stream := <-appStreams:
			go appToGw(stream.Stream)
		}
	}
}
