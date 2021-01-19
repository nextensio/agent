package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gitlab.com/nextensio/common/transport/dtls"
	nhttp2 "gitlab.com/nextensio/common/transport/http2"
	"gitlab.com/nextensio/common/transport/quic"
	websock "gitlab.com/nextensio/common/transport/websocket"

	"github.com/google/uuid"
)

type agentInfo struct {
	onboard nxthdr.NxtOnboard
	tunnel  common.Transport
}

type podInfo struct {
	pending bool
	tunnel  common.Transport
}

var aLock sync.RWMutex
var tunnels map[uuid.UUID]*agentInfo
var agents map[string]*agentInfo
var pLock sync.RWMutex
var pods map[string]*podInfo
var unusedChan chan common.NxtStream

func tunnelAdd(Suuid uuid.UUID, tunnel common.Transport, onboard *nxthdr.NxtOnboard) {
	aLock.Lock()
	agent := &agentInfo{onboard: *onboard, tunnel: tunnel}
	tunnels[Suuid] = agent
	agents[onboard.Uuid] = agent
	aLock.Unlock()
}

func tunnelDel(Suuid uuid.UUID, tunnel common.Transport) {
	aLock.Lock()
	a := tunnels[Suuid]
	if a != nil && a.tunnel == tunnel {
		delete(tunnels, Suuid)
		delete(agents, a.onboard.Uuid)
	}
	aLock.Unlock()
}

func tunnelGet(Suuid uuid.UUID) *agentInfo {
	aLock.RLock()
	a := tunnels[Suuid]
	aLock.RUnlock()
	return a
}

func agentGet(uuid string) *agentInfo {
	aLock.RLock()
	a := agents[uuid]
	aLock.RUnlock()
	return a
}

func podGet(ctx context.Context, pod string) common.Transport {
	var tunnel common.Transport
	var pending bool = false

	// Try read lock first since the most common case should be that tunnels are
	// already setup
	pLock.RLock()
	p := pods[pod]
	if p != nil {
		tunnel = p.tunnel
		pending = p.pending
	}
	pLock.RUnlock()

	// The uncommon/infrequent case. Multiple goroutines will try to connect to the
	// same pod, so we should not end up creating multiple tunnels to the same pod,
	// hence the pending flag etc..
	if tunnel == nil && !pending {
		pLock.Lock()
		p = pods[pod]
		if p == nil {
			pods[pod] = &podInfo{pending: true, tunnel: nil}
			go podDial(ctx, pod)
		} else {
			tunnel = p.tunnel
		}
		pLock.Unlock()
	}

	return tunnel
}

func podDial(ctx context.Context, pod string) {
	var pubKey []byte
	var headers http.Header = make(map[string][]string)
	headers.Add("x-nextensio-uniqueid", uuid.New().String())
	client := nhttp2.NewClient(ctx, pubKey, "internal", pod, 8888, headers)
	// For pod to pod connectivity, a pod will always dial-out another one,
	// we dont expect a stream to come in from the other end on a dial-out session,
	// and hence the reason we use the unusedChan on which no one is listening.
	// This is a unidirectional session, we just write on this. Writing from the
	// other end will end up with the other end dialling a new connection
	err := client.Dial(unusedChan)
	if err != nil {
		return
	}
	pLock.Lock()
	pods[pod].pending = false
	pods[pod].tunnel = client
	pLock.Unlock()
}

func routeAdd(onboard *nxthdr.NxtOnboard) {

}

func routeLookup(hdr *nxthdr.NxtFlow) (string, string) {
	if hdr.Source == "agent1" {
		return "connector1", "127.0.0.1"
	} else {
		return "agent1", "127.0.0.1"
	}
}

func routeL3(ctx context.Context, onboard *nxthdr.NxtOnboard, hdr *nxthdr.NxtHdr, buffer net.Buffers) {
	flowHdr := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
	flowHdr.Source = onboard.Uuid
	var ipaddr string
	flowHdr.Dest, ipaddr = routeLookup(flowHdr)
	if ipaddr == "local" {
		dTun := agentGet(flowHdr.Dest)
		if dTun == nil {
			log.Println("Cant get dest tunnel for ", flowHdr.Dest)
			return
		}
		err := dTun.tunnel.Write(hdr, buffer)
		if err != nil {
			log.Println("Local Destination write failed ", flowHdr.Dest, err)
			return
		}
	} else {
		dTun := podGet(ctx, ipaddr)
		if dTun == nil {
			return
		}
		err := dTun.Write(hdr, buffer)
		if err != nil {
			log.Println("Remote Destination write failed ", flowHdr.Dest, ipaddr, err)
			return
		}
	}
}

func routeL4(ctx context.Context, onboard *nxthdr.NxtOnboard, hdr *nxthdr.NxtHdr, buffer net.Buffers) {

}

// Agent/Connector is trying to connect to minion. The first stream from the agent/connector
// will be used to onboard and send L3 data. The next streams on the session will not need
// onboarding, and they will send L4 data. There will be one stream per L4 session, there will
// be just one stream (first stream) for all L3 data
func handleAgent(ctx context.Context, Suuid uuid.UUID, tunnel common.Transport) {
	var onboarded = false
	var l4 = false

	// If there is a stream from the agent on which we have onboarded, thats
	// all we need, we onboard on just one stream.
	agent := tunnelGet(Suuid)
	if agent != nil {
		onboarded = true
		l4 = true
	}

	for {
		hdr, agentBuf, err := tunnel.Read()
		if err != nil {
			tunnel.Close()
			tunnelDel(Suuid, tunnel)
			log.Println("Agent read error", err)
			return
		}
		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Onboard:
			err := tunnel.Write(hdr, agentBuf)
			if err != nil {
				log.Println("Handshake failed")
			} else if onboarded == false {
				onboard := hdr.Hdr.(*nxthdr.NxtHdr_Onboard)
				onboarded = true
				tunnelAdd(Suuid, tunnel, onboard.Onboard)
				agent = tunnelGet(Suuid)
				routeAdd(onboard.Onboard)
				log.Println("Onboarded tunnel ", onboard.Onboard.Uuid)
			}
		case *nxthdr.NxtHdr_Flow:
			// We dont want to get data before we get the onboarding info
			if !onboarded {
				tunnel.Close()
				tunnelDel(Suuid, tunnel)
				log.Println("Got data before handshake ")
				return
			} else {
				if l4 {
					routeL4(ctx, &agent.onboard, hdr, agentBuf)
				} else {
					routeL3(ctx, &agent.onboard, hdr, agentBuf)
				}
			}
		}
	}
}

func handleInterPod(Suuid uuid.UUID, tunnel common.Transport) {

	for {
		hdr, podBuf, err := tunnel.Read()
		if err != nil {
			tunnel.Close()
			tunnelDel(Suuid, tunnel)
			log.Println("InterPod Error", err)
			return
		}
		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Flow:
			flowHdr := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			dTun := agentGet(flowHdr.Dest)
			if dTun == nil {
				log.Println("Interpod: cant get dest tunnel for ", flowHdr.Dest)
				return
			}
			err := dTun.tunnel.Write(hdr, podBuf)
			if err != nil {
				log.Println("Interpod: local Destination write failed ", flowHdr.Dest, err)
				return
			}
		}
	}
}

func getKeys() ([]byte, []byte) {
	pvtKey, err := ioutil.ReadFile("./pems/server.pem")
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	return pvtKey, pubKey
}

func RouterInit(ctx context.Context) {
	tunnels = make(map[uuid.UUID]*agentInfo)
	agents = make(map[string]*agentInfo)
	pods = make(map[string]*podInfo)
	unusedChan = make(chan common.NxtStream)
}

// Open a DTLS server side socket and listen for incoming connections
// from agents, and for each agent connection, spawn a goroutine to handle that
func OutsideListenerDTLS(ctx context.Context) {
	pvtKey, pubKey := getKeys()
	server := dtls.NewListener(ctx, pvtKey, pubKey, 4444)
	tchan := make(chan common.NxtStream)
	go server.Listen(tchan)
	for {
		select {
		case client := <-tchan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			go handleAgent(ctx, client.Parent, client.Stream)
		}
	}
}

// Open a Quic server side socket and listen for incoming connections
// from agents, and for each agent connection, spawn a goroutine to handle that
func OutsideListenerQuic(ctx context.Context) {
	pvtKey, pubKey := getKeys()
	server := quic.NewListener(ctx, pvtKey, pubKey, 4445)
	tchan := make(chan common.NxtStream)
	go server.Listen(tchan)
	for {
		select {
		case client := <-tchan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			go handleAgent(ctx, client.Parent, client.Stream)
		}
	}
}

// Open a Websocket server side socket and listen for incoming connections
// from agents, and for each agent connection, spawn a goroutine to handle that
func OutsideListenerWebsocket(ctx context.Context) {
	pvtKey, pubKey := getKeys()
	server := websock.NewListener(ctx, pvtKey, pubKey, 4446)
	tchan := make(chan common.NxtStream)
	go server.Listen(tchan)
	for {
		select {
		case client := <-tchan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			go handleAgent(ctx, client.Parent, client.Stream)
		}
	}
}

// Open a Quic socket to listen for incoming connections from other pods in the
// same cluster or other pods from outside this cluster
func InsideListenerHttp2(ctx context.Context) {
	var pvtKey []byte
	var pubKey []byte
	server := nhttp2.NewListener(ctx, pvtKey, pubKey, 8888, "x-nextensio-uniqueid")
	tchan := make(chan common.NxtStream)
	go server.Listen(tchan)
	for {
		select {
		case client := <-tchan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			go handleInterPod(client.Parent, client.Stream)
		}
	}
}

func InsideListener(ctx context.Context) {
	InsideListenerHttp2(ctx)
}

func OutsideListener(ctx context.Context, encap string) {
	if encap == "dtls" {
		OutsideListenerDTLS(ctx)
	} else if encap == "quic" {
		OutsideListenerQuic(ctx)
	} else if encap == "websocket" {
		OutsideListenerWebsocket(ctx)
	}
}
