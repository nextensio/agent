package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"nextensio/agent/conntrack"
	"sync"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/dtls"
	"gitlab.com/nextensio/common/transport/quic"
	websock "gitlab.com/nextensio/common/transport/websocket"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var onboardC common.OnboardInfo
var flowLock sync.RWMutex
var natv4Table conntrack.NatTable
var flowv4Table conntrack.FlowV4Table
var l3Intf common.Transport
var gwSessionC common.Transport
var cChan chan common.NxtStream

// TODO: We got a l4 session from the gateway, we need to translate that to
// a Unix L4 tcp/udp socket and return a transport corresponding to that
func createL4(hdr *nxthdr.NxtHdr) common.Transport {
	return nil
}

func outsideToInside(buffer net.Buffers) *conntrack.FlowV4 {
	// For now we assume L3 forwarded packets come in one single buffer
	p := gopacket.NewPacket(buffer[0], layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	var sip [4]byte
	var dip [4]byte
	copy(sip[0:], []byte(ip.SrcIP.To4()))
	copy(dip[0:], []byte(ip.DstIP.To4()))
	flowLock.Lock()
	flow := flowv4Table.Fetch(&p)
	flowLock.Unlock()
	if flow == nil {
		return nil
	}
	flowLock.Lock()
	err := flowv4Table.Dnat(&p)
	flowLock.Unlock()
	if err != nil {
		return nil
	}
	return flow
}

func insideToOutside(source common.Transport, buffer net.Buffers) *conntrack.FlowV4 {
	// For now we assume L3 forwarded packets come in one single buffer
	p := gopacket.NewPacket(buffer[0], layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	var sip [4]byte
	var dip [4]byte
	copy(sip[0:], []byte(ip.SrcIP.To4()))
	copy(dip[0:], []byte(ip.DstIP.To4()))
	flowLock.Lock()
	flow := flowv4Table.Create(&p)
	flowLock.Unlock()
	if flow == nil {
		log.Println("Cannot create flow")
		return nil
	}
	flowLock.Lock()
	err := flowv4Table.Snat(&p)
	flowLock.Unlock()
	if err != nil {
		log.Println("Cannot SNAT flow")
		return nil
	}
	return flow
}

// Read raw packets from the interface
func appL3C(ctx context.Context, intf common.Transport) {
	for {
		if gwSessionC == nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	for {
		hdr, readBuf, err := intf.Read()
		if err != nil {
			log.Println("Read error ", err)
			intf.Close()
			return
		}
		flow := outsideToInside(readBuf)
		if flow == nil {
			log.Println("Unknown flow")
			continue
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			err := gwSessionC.Write(hdr, readBuf)
			if err != nil {
				log.Println("Write error")
				continue
			}
		default:
			// we dont expect anyting other than NxtFlow
			log.Println("Unexpected nxt header ", t)
			intf.Close()
			return
		}
	}
}

func intfDummy(ctx context.Context) {
	dummy := DummySink{}
	tchan := make(chan common.NxtStream)
	go dummy.Listen(tchan)
	for {
		select {
		case d := <-tchan:
			l3Intf = d.Stream
			go appL3C(ctx, d.Stream)
		}
	}
}

func connectorOnboard(encap string) {
	onboardC.Userid = "connector1"
	onboardC.Uniqueid = "connector1"
	onboardC.GwName = "gateway.nextensio.net"
	onboardC.GwIP = "127.0.0.1"
	if encap == "dtls" {
		onboardC.GwPort = 4444
	} else if encap == "quic" {
		onboardC.GwPort = 4445
	} else if encap == "websocket" {
		onboard.GwPort = 4446
	}
	content, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}
	onboardC.CaCert = content
}

// protobuf encode the device onboard information and send to the gateway
func sendonboardC(tunnel common.Transport) {
	p := &nxthdr.NxtOnboard{Userid: onboardC.Userid, Uuid: onboardC.Uniqueid}
	hdr := nxthdr.NxtHdr{Hdr: &nxthdr.NxtHdr_Onboard{p}}
	err := tunnel.Write(&hdr, net.Buffers{})
	if err != nil {
		log.Printf("%s\n", err)
	}
}

// Create a dtls session to the gateway
func dialDtlsC(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
	retry := 0
	dtls := dtls.NewClient(ctx, onboardC.CaCert, serverName, serverIP, port)
	for err := dtls.Dial(cChan); err != nil; err = dtls.Dial(cChan) {
		dtls.Close()
		retry++
		if retry >= 5 {
			return nil
		}
		log.Println("Cannot connect to cluster, will retry: ", retry, err)
	}

	return dtls
}

// Create a quic session to the gateway
func dialQuicC(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
	retry := 0
	quic := quic.NewClient(ctx, onboard.CaCert, serverIP, port)
	for err := quic.Dial(aChan); err != nil; err = quic.Dial(aChan) {
		quic.Close()
		retry++
		if retry >= 5 {
			return nil
		}
		log.Println("Cannot connect to cluster, will retry: ", retry, err)
	}

	return quic
}

// Create a websocket session to the gateway
func dialWebsocketC(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
	retry := 0
	wsock := websock.NewClient(ctx, onboard.CaCert, serverName, serverIP, port, nil)
	for err := wsock.Dial(aChan); err != nil; err = wsock.Dial(aChan) {
		wsock.Close()
		retry++
		if retry >= 5 {
			return nil
		}
		log.Println("Cannot connect to cluster, will retry: ", retry, err)
	}

	return wsock
}

// Gateway streams brings us raw l3 packets. The l3 stream is the first stream we create, using
// which we also onboard.
func gwL3C(ctx context.Context, gw common.Transport) {
	for {
		hdr, readBuf, err := gw.Read()
		if err != nil {
			log.Println("Read error ", err)
			gw.Close()
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			flow := insideToOutside(gw, readBuf)
			if flow == nil {
				log.Println("Cannot find flow")
				continue
			}
			err := l3Intf.Write(hdr, readBuf)
			if err != nil {
				log.Println("Write error")
				continue
			}
		default:
			// we dont expect anyting other than the above
			log.Println("Unexpected nxt header ", t)
			gw.Close()
			return
		}
	}
}

func gwL4C(ctx context.Context, gw common.Transport) {
	var app common.Transport
	for {
		hdr, readBuf, err := gw.Read()
		if err != nil {
			log.Println("Read error ", err)
			gw.Close()
			if app != nil {
				app.Close()
			}
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			if app == nil {
				app = createL4(hdr)
				if app == nil {
					log.Println("Cannot create L4 session")
					gw.Close()
					return
				}
			}
			err := app.Write(hdr, readBuf)
			if err != nil {
				log.Println("Write error")
				gw.Close()
				app.Close()
				return
			}
		default:
			// we dont expect anyting other than the above
			log.Println("Unexpected nxt header ", t)
			gw.Close()
			if app != nil {
				app.Close()
			}
			return
		}
	}
}

func newGwSessionC(ctx context.Context, encap string) common.Transport {
	retry := 0
	var tunnel common.Transport
	if encap == "dtls" {
		tunnel = dialDtlsC(ctx, onboardC.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	} else if encap == "quic" {
		tunnel = dialQuicC(ctx, onboardC.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	} else if encap == "websocket" {
		tunnel = dialWebsocketC(ctx, onboardC.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	}

	for {
		sendonboardC(tunnel)
		// Remember the transport need not be TCP, so the message delivery is not
		// guaranteed, so we wait for a response for some time and if we dont get
		// one, then we resend. Hence set the socket to blocking-with-timeout to
		// read a response with a timeout
		tunnel.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		hdr, _, err := tunnel.Read()
		if err != nil {
			switch err := err.Err.(type) {
			case net.Error:
				if err.Timeout() {
					retry++
					if retry >= 50 {
						log.Println("Unable to establish gateway tunnel")
						return nil
					}
					continue
				}
			}
			log.Println("Handshake read error")
			return nil
		}

		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Onboard:
			log.Println("Handshaked with gateway")
			// Set the socket back to blocking on read
			tunnel.SetReadDeadline(time.Time{})
			return tunnel
		}
	}
}

func gwSessionMgrC(ctx context.Context, encap string) {
	for {
		if gwSessionC == nil || gwSessionC.IsClosed() {
			gwSessionC = newGwSessionC(ctx, encap)
			if gwSessionC != nil {
				go gwL3C(ctx, gwSessionC)
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func incomingStream(ctx context.Context) {
	for {
		select {
		case stream := <-cChan:
			go gwL4C(ctx, stream.Stream)
		}
	}
}

func ConnectorInit(ctx context.Context, sourceIP string, encap string) {
	natv4Table = conntrack.NewNatV4Table(net.ParseIP(sourceIP))
	flowv4Table = conntrack.NewFlowV4Table(natv4Table)
	cChan = make(chan common.NxtStream)
	connectorOnboard(encap)
	go incomingStream(ctx)
	go intfDummy(ctx)
	go gwSessionMgrC(ctx, encap)
}
