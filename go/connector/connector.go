package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"gitlab.com/nextensio/common/go/transport/netconn"
)

var controller string
var regInfo RegistrationInfo
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var unusedAppStreams chan common.NxtStream
var unique uuid.UUID
var username *string
var password *string

func gwToAppClose(tun common.Transport, dest ConnStats) {
	tun.Close()
	if dest.Conn != nil {
		dest.Conn.Close()
	}
}

// Stream coming from the gateway, create a new tcp/udp socket
// and send the data over that socket
func gwToApp(lg *log.Logger, tun common.Transport) {
	var dest ConnStats

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			gwToAppClose(tun, dest)
			return
		}
		if dest.Conn == nil {
			flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			if flow.Proto == common.TCP {
				dest.Conn = netconn.NewClient(mainCtx, lg, "tcp", flow.Dest, flow.Dport)
			} else {
				dest.Conn = netconn.NewClient(mainCtx, lg, "udp", flow.Dest, flow.Dport)
			}
			e := dest.Conn.Dial(unusedAppStreams)
			if e != nil {
				gwToAppClose(tun, dest)
				return
			}
			newTun := tun.NewStream(nil)
			if newTun == nil {
				gwToAppClose(tun, dest)
				return
			}
			go appToGw(lg, &dest, newTun, *flow, tun)
		}
		e := dest.Conn.Write(hdr, buf)
		if e != nil {
			gwToAppClose(tun, dest)
			return
		}
		dest.Tx += 1
	}
}

func appToGwClose(src *ConnStats, dest common.Transport, gwRx common.Transport) {
	src.Conn.Close()
	dest.Close()
	gwRx.Close()
}

// Data coming back from a tcp/udp socket. Send the data over the gateway
// stream that initially created the socket
func appToGw(lg *log.Logger, src *ConnStats, dest common.Transport, flow nxthdr.NxtFlow, gwRx common.Transport) {

	// Swap source and dest agents
	s, d := flow.SourceAgent, flow.DestAgent
	flow.SourceAgent, flow.DestAgent = d, s

	// If the destination (Tx) closes, close the rx also so the entire goroutine exits and
	// the close is cascaded to the the cluster
	dest.CloseCascade(src.Conn)

	for {
		if flow.Proto == common.TCP {
			src.Conn.SetReadDeadline(time.Now().Add(TCP_AGER))
		} else {
			src.Conn.SetReadDeadline(time.Now().Add(UDP_AGER))
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
				appToGwClose(src, dest, gwRx)
				return
			}
		}
		src.Rx += 1
		hdr = &nxthdr.NxtHdr{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
		e := dest.Write(hdr, buf)
		if e != nil {
			appToGwClose(src, dest, gwRx)
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

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	s := flag.String("service", "", "services advertised by this agent")
	username = flag.String("username", "", "connector onboarding userid")
	password = flag.String("password", "", "connector onboarding password")
	flag.Parse()
	controller = *c
	svcs := strings.TrimSpace(*s)
	regInfo.Services = strings.Fields(svcs)
}

func authAndOnboard(lg *log.Logger) bool {
	tokens := authenticate("https://dev-635657.okta.com", *username, *password)
	if tokens == nil {
		lg.Println("Unable to authenticate connector with the IDP")
		return false
	}
	regInfo = RegistrationInfo{}
	regInfo.AccessToken = tokens.AccessToken
	return OktaInit(lg, &regInfo, controller)
}

func main() {
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	unusedAppStreams = make(chan common.NxtStream)
	lg := log.New(os.Stdout, "CNTR", 0)
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

	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			go gwToApp(lg, stream.Stream)
		}
	}
}
