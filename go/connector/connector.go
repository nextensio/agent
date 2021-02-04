package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"nextensio/agent/shared"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

var controller string
var regInfo shared.RegistrationInfo
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var unique uuid.UUID

// Stream coming from the gateway, create a new tcp/udp socket
// and send the data over that socket
func gwToApp(tun common.Transport) {
	dest := shared.ConnStats{}

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			tun.Close()
			if dest.Conn != nil {
				dest.Conn.Close()
			}
			return
		}
		if dest.Conn == nil {
			flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			addr := fmt.Sprintf("%s:%d", flow.Dest, flow.Dport)
			var e error
			if flow.Proto == common.TCP {
				dest.Conn, e = net.Dial("tcp", addr)
			} else {
				dest.Conn, e = net.Dial("udp", addr)
			}
			if e != nil {
				tun.Close()
				return
			}
			newTun := tun.NewStream(nil)
			if newTun == nil {
				tun.Close()
				dest.Conn.Close()
				return
			}
			go appToGw(&dest, newTun, *flow)
		}
		for _, b := range buf {
			_, e := dest.Conn.Write(b)
			if e != nil {
				tun.Close()
				dest.Conn.Close()
				return
			}
			dest.Tx += 1
		}
	}
}

// Data coming back from a tcp/udp socket. Send the data over the gateway
// stream that initially created the socket
func appToGw(src *shared.ConnStats, dest common.Transport, flow nxthdr.NxtFlow) {

	// Swap source and dest agents
	s, d := flow.SourceAgent, flow.DestAgent
	flow.SourceAgent, flow.DestAgent = d, s

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
					log.Println("Flow aged out", flow)
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
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
		e := dest.Write(&hdr, net.Buffers{buf[:n]})
		if e != nil {
			src.Conn.Close()
			dest.Close()
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
				if shared.OnboardTunnel(newTun, false, &regInfo, unique.String()) == nil {
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
	go monitorGw(lg)
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
	lg := log.New(os.Stdout, "CNTR", 0)
	args()
	shared.OktaInit(lg, &regInfo, controller, onboarded)

	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			go gwToApp(stream.Stream)
		}
	}
}
