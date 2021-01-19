package main

import (
	"context"
	"testing"
	"time"
)

// NOTE: The tests here wont run serially because multiple minion servers launched in parallel
// will have conflicting ports etc.. Of course it can be made to work, for now run tests
// individually by saying "go test -run TestAgentGatewayDTLS" etc.. Or just use the testall.sh
// script in this directory

func TestAgentGatewayDTLS(t *testing.T) {
	testComplete := false
	mainCtx := context.Background()
	go OutsideListener(mainCtx, "dtls")
	go InsideListener(mainCtx)
	time.Sleep(1 * time.Second)
	AgentInit(mainCtx, "dtls", &testComplete)
	ConnectorInit(mainCtx, "1.1.1.1", "dtls")
	RouterInit(mainCtx)
	for !testComplete {
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentGatewayQuic(t *testing.T) {
	testComplete := false
	mainCtx := context.Background()
	go OutsideListener(mainCtx, "quic")
	go InsideListener(mainCtx)
	time.Sleep(1 * time.Second)
	AgentInit(mainCtx, "quic", &testComplete)
	ConnectorInit(mainCtx, "1.1.1.1", "quic")
	RouterInit(mainCtx)
	for !testComplete {
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentGatewayWebsocket(t *testing.T) {
	testComplete := false
	mainCtx := context.Background()
	go OutsideListener(mainCtx, "websocket")
	go InsideListener(mainCtx)
	time.Sleep(1 * time.Second)
	AgentInit(mainCtx, "websocket", &testComplete)
	ConnectorInit(mainCtx, "1.1.1.1", "websocket")
	RouterInit(mainCtx)
	for !testComplete {
		time.Sleep(10 * time.Millisecond)
	}
}
