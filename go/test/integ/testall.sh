#!/usr/bin/env bash

go test -run TestAgentGatewayDTLS
go test -run TestAgentGatewayQuic
go test -run TestAgentGatewayWebsocket
