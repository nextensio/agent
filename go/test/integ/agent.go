package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/dtls"
	"gitlab.com/nextensio/common/transport/quic"
	websock "gitlab.com/nextensio/common/transport/websocket"
)

var onboard common.OnboardInfo
var l3App common.Transport
var gwSession common.Transport
var aChan chan common.NxtStream

// get device onboard information from onboarding process
func agentOnboard(encap string) {
	onboard.Userid = "agent1"
	onboard.Uniqueid = "agent1"
	onboard.GwIP = "127.0.0.1"
	onboard.GwName = "gateway.nextensio.net"
	if encap == "dtls" {
		onboard.GwPort = 4444
	} else if encap == "quic" {
		onboard.GwPort = 4445
	} else if encap == "websocket" {
		onboard.GwPort = 4446
	}
	content, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}
	onboard.CaCert = content
}

// App side gives us raw L3 packets, all goes over one gateway tunnel. The current
// design requires that there is only one global raw L3 transport towards the app side
func appL3(ctx context.Context, app common.Transport) {
	for {
		if gwSession == nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}
	for {
		hdr, readBuf, err := app.Read()
		if err != nil {
			log.Println("App raw Read error ", err)
			app.Close()
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			err := gwSession.Write(hdr, readBuf)
			if err != nil {
				log.Println("Appraw Write error", err)
				continue
			}
		default:
			// we dont expect anyting other than NxtFlow
			log.Println("Unexpected nxt header ", t)
			app.Close()
			return
		}
	}
}

// App gives us a single L4 session, and we create a unique gateway stream for this session
func appL4(ctx context.Context, app common.Transport) {
	gw := getGwStream(ctx, true)
	if gw == nil {
		app.Close()
		return
	}
	go gwL4(ctx, gw, app)

	for {
		hdr, readBuf, err := app.Read()
		if err != nil {
			log.Println("Appgw1to1 Read error ", err)
			app.Close()
			gw.Close()
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			err := gw.Write(hdr, readBuf)
			if err != nil {
				app.Close()
				gw.Close()
				log.Println("Appgw1to1 Write error")
				return
			}
		default:
			// we dont expect anyting other than the above
			log.Println("Unexpected nxt header", t)
			app.Close()
			gw.Close()
			return
		}
	}
}

// Gateway streams brings us raw l3 packets. The l3 stream is the first stream we create, using
// which we also onboard.
func gwL3(ctx context.Context, gw common.Transport) {

	for {
		hdr := &nxthdr.NxtHdr{}
		hdr, readBuf, err := gw.Read()
		if err != nil {
			log.Println("gwL3 Read error ", err)
			gw.Close()
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			if l3App == nil {
				log.Println("Cannot find l3App")
				continue
			}
			err := l3App.Write(hdr, readBuf)
			if err != nil {
				log.Println("GWL3 Write error ", err)
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

func gwL4(ctx context.Context, gw common.Transport, app common.Transport) {

	for {
		hdr := &nxthdr.NxtHdr{}
		hdr, readBuf, err := gw.Read()
		if err != nil {
			log.Println("Gw1to1App Read error ", err)
			app.Close()
			gw.Close()
			return
		}
		switch t := hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			//flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		default:
			// we dont expect anyting other than NxtFlow
			log.Println("Unexpected nxt header", t)
			app.Close()
			gw.Close()
			return
		}
		err = app.Write(hdr, readBuf)
		if err != nil {
			app.Close()
			gw.Close()
			log.Println("GWL4 Write error")
			return
		}
	}
}

func getGwStream(ctx context.Context, create bool) common.Transport {
	if gwSession == nil {
		return nil
	}
	new := gwSession.NewStream(nil)
	if new == nil {
		// If we cant get a new stream, then theres something wrong with the
		// transport itself, close it and let it reopen and try again
		gwSession.Close()
	}
	return new
}

// protobuf encode the device onboard information and send to the gateway
func sendonboard(tunnel common.Transport) {
	p := &nxthdr.NxtOnboard{Userid: onboard.Userid, Uuid: onboard.Uniqueid}
	hdr := nxthdr.NxtHdr{Hdr: &nxthdr.NxtHdr_Onboard{p}}
	err := tunnel.Write(&hdr, net.Buffers{})
	if err != nil {
		log.Printf("%s\n", err)
	}
}

// Create a dtls session to the gateway
func dialDtls(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
	retry := 0
	dtls := dtls.NewClient(ctx, onboard.CaCert, serverName, serverIP, port)
	for err := dtls.Dial(aChan); err != nil; err = dtls.Dial(aChan) {
		dtls.Close()
		retry++
		if retry >= 5 {
			return nil
		}
		log.Println("Cannot connect to cluster, will retry: ", retry, err)
	}

	return dtls
}

// Create a Quic session to the gateway
func dialQuic(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
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

// Create a Websocket session to the gateway
func dialWebsocket(ctx context.Context, serverName string, serverIP string, port int) common.Transport {
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

func newGwSession(ctx context.Context, encap string) common.Transport {
	retry := 0
	var tunnel common.Transport
	if encap == "dtls" {
		tunnel = dialDtls(ctx, onboard.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	} else if encap == "quic" {
		tunnel = dialQuic(ctx, onboard.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	} else if encap == "websocket" {
		tunnel = dialWebsocket(ctx, onboard.GwName, onboard.GwIP, onboard.GwPort)
		if tunnel == nil {
			return nil
		}
	}

	for {
		sendonboard(tunnel)
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
						log.Println("Unable to read onboard response from gateway tunnel")
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

func gwSessionMgr(ctx context.Context, encap string) {
	for {
		if gwSession == nil || gwSession.IsClosed() {
			gwSession = newGwSession(ctx, encap)
			if gwSession != nil {
				gwL3(ctx, gwSession)
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func appDummy(ctx context.Context, testComplete *bool) {
	tchan := make(chan common.NxtStream)
	dummy := CreateDummySource(testComplete)
	go dummy.Listen(tchan)

	for {
		select {
		case d := <-tchan:
			l3App = d.Stream
			go appL3(ctx, d.Stream)
		}
	}
}

func AgentInit(ctx context.Context, encap string, testComplete *bool) {
	// As of today, agent doesnt expect streams initiated from outside, its always
	// streams initiated from agent to outside. But if that changes some day, we can
	// always spawn a goroutine to listen on sChan, just like connector does
	aChan = make(chan common.NxtStream)
	agentOnboard(encap)
	go gwSessionMgr(ctx, encap)
	go appDummy(ctx, testComplete)
}
