//
// NXT Connector (NCTR)
// Author: Rudy Z, Uday K.
// Date: April 4th, 2019
//
'use strict'

require('dotenv').config();
require('log-timestamp')(function () { return new Date().toISOString() + ' %s' });

const minimist = require('minimist');
const WebSocket = require('ws');
const http = require('http');
const net = require('net');
const httpParser = require('http-string-parser');
const urlParser = require('url');
const common = require('./nxt_common.js');
const bindSockets = require('./nxt_bind_sockets.js');
const AsyncSocket = require('./nxt_async_socket.js');

var streamid = 1;
var nxtOnboarded = false;
var nxtOnboardPending = false;


let registrationInfo = {
    host: '',
    accessToken: '',
    connectID: '',
    userid: ''
};

// 
// Websocket Tunnel
// 
var dialoutAsyncWsTunnel = null;
var extension = null;
var services = []

//
// Process arguments
//
common.setArgs(minimist(process.argv.slice(2), {
    string: ['service', 'gateway', 'controller'],
    boolean: ['usage'],
    alias: { u: 'usage', g: 'gateway' },
    default: { service: '', gateway: '', controller: 'server.nextensio.net:8080' }
}));

if (common.getArgs().usage) {
    common.printUsages();
    process.exit(0);
}

var login = require('fs'),
    okta = require('http');
// Port on which single sign on can be done using browser
okta.createServer(function (req, res) {
    if (!nxtOnboarded) {
        login.readFile("./public/login.html", function (err, data) {
            if (err) {
                res.writeHead(404);
                res.end(JSON.stringify(err));
                return;
            }
            res.writeHead(200);
            res.end(data);
        });
    } else {
        res.writeHead(201);
        res.end('');
    }
}).listen(8180);

// Port on which Single sign on sends tokens back to us
var httpServer = http.createServer(function (req, res) {
    let path = urlParser.parse(req.url, true).pathname;
    let query = urlParser.parse(req.url, true).query;
    registrationInfo.accessToken = query.access;
    if (path === '/accessid/') {
        if (!nxtOnboarded && !nxtOnboardPending) {
            nxtOnboardPending = true;
            nxtOnboard();
        }
    }
    res.writeHead(200, { 'Access-Control-Allow-Origin': '*' });
    res.end();
}).listen(8081);


//
// Common function to handle data coming from the cluster
//
function packetFromCluster(nxtAsyncTunnel, message) {
    let clientAsyncSocket;

    var ret = common.parseWsPayload(nxtAsyncTunnel, message);
    if (ret == null) {
        console.log("Null payload")
        return
    }

    let myPayload = ret[0]
    let flow = ret[1]
    let orig = { ...flow }
    clientAsyncSocket = common.getNxtFlowToTcp(flow);
    if (typeof clientAsyncSocket === 'undefined') {
        createNewSocket(nxtAsyncTunnel, flow);
        clientAsyncSocket = common.getNxtFlowToTcp(orig);
        if (typeof clientAsyncSocket === 'undefined') {
            console.log('Cannot create socket for flow', flow)
            return
        }
    }
    clientAsyncSocket.send(myPayload);
}

// ############################## HUGE TODO ####################################
// If we get data before the socket is fully connected, then we have to queue it
// up someplace. Also in situations like the tcpConn running into error/getting
// closed, we have to propagate that all the way back to the agent rather than
// just logging an error. Error handling in agent/connector/common code needs to
// be very very carefully looked at, wherever there are errors or packet drops etc..
// we need to cascade it all the way back
function createNewSocket(nxtAsyncTunnel, flow) {
    // open a TCP connection to the remote host
    var tcpConn = net.createConnection(flow.destPort, flow.dest, () => {
        console.log('Connected to', flow.dest, flow.destPort)
    });
    tcpConn.on('error', function (err) { console.log(err) });
    var clientAsyncSocket = new AsyncSocket(tcpConn,
        common.SOCKET_RING_BUFFER_SIZE);
    // Set flow host to the ingress gateway for the connector
    flow.host = registrationInfo.host;
    // Reverse the flow before storing
    [flow.destAgent, flow.sourceAgent] = [flow.sourceAgent, flow.destAgent];
    flow.txStreamid = streamid * 2
    streamid += 1

    common.storeNxtFlowToTcp(flow, clientAsyncSocket);
    common.storeNxtTcpToFlow(tcpConn, flow);
    bindSockets(nxtAsyncTunnel, clientAsyncSocket);
}

function nxtOnboard() {
    registrationInfo.sessionID = 'sid';
    registrationInfo.host = common.getArgs().gateway;

    var callback = function (response) {
        var str = '';

        //another chunk of data has been received, so append it to `str`
        response.on('data', function (chunk) {
            str += chunk;
        });

        //the whole response has been received, so we just print it out here
        response.on('end', function () {
            var data = JSON.parse(str);
            if (data.Result == 'ok') {
                registrationInfo.userid = data.userid;
                // If an explicit gateway is not provided, just take what controller gives
                if (common.getArgs().gateway == '') {
                    registrationInfo.host = data.gateway;
                }
                registrationInfo.connectID = data.connectid
                registrationInfo.CACert = String.fromCharCode(...data.cacert)
                if (common.getArgs().service.trim() !== '') {
                    services = common.getArgs().service.split(" ")
                }
                services.push(registrationInfo.connectID)
                registerAndCreateTunnel();
                nxtOnboarded = true;
            } else {
                console.log('Registration failed: ' + data.Result);
            }
            nxtOnboardPending = false;
        });
    }
    // async http call. 
    var http = require('http');
    http.get('http://' + common.getArgs().controller + '/api/v1/onboard/' + registrationInfo.accessToken, callback).
        on("error", (err) => {
            console.log("Error: " + err.message);
            nxtOnboardPending = false;
        });
}

function checkTunnel() {
    if (dialoutAsyncWsTunnel == null) {
        //console.log('Socket not yet created')
    } else if ((dialoutAsyncWsTunnel.websocket.readyState == WebSocket.CLOSED) ||
        ((dialoutAsyncWsTunnel.websocket.readyState == WebSocket.CLOSING))) {
        console.log('Websocket closed, reopening')
        common.clearNxtTcpToFlow();
        common.clearNxtFlowToTcp();
        var gatewayURL = 'wss://' + registrationInfo.host + ':443'
        dialoutAsyncWsTunnel = common.createNxtWsTunnel(gatewayURL,
            null,
            extension,
            packetFromCluster,
            registrationInfo, false, services);
    }
    setTimeout(checkTunnel, 1);
}

function registerAndCreateTunnel() {
    extension = {
        headers: {
            'x-nextensio-connect': registrationInfo.connectID,
        },
        ca: registrationInfo.CACert,
        secureProtocol: 'TLSv1_2_method'
    };
    var gatewayURL = 'wss://' + registrationInfo.host + ':443'
    dialoutAsyncWsTunnel = common.createNxtWsTunnel(gatewayURL,
        null,
        extension,
        packetFromCluster,
        registrationInfo, false, services);

    console.log('\nNCTR - scheduled 1 second timer');
    setTimeout(checkTunnel, 1);
}
