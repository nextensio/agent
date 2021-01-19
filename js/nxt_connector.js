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
// Common function to handle websocket message coming from Websocket Server or Tunnel
//
function handleRequestMessage(nxtAsyncTunnel, message) {
    let clientAsyncSocket;

    var ret = common.parseWsPayload(nxtAsyncTunnel, message);
    if (ret == null) {
        console.log("Null payload")
        return
    }

    let myPayload = ret[0]
    let flow = ret[1]
    let msgtype = ret[2]
    if (msgtype === 'CONNECT') {
        // Parse Body
        let connectReq = httpParser.parseRequest(myPayload.toString());

        let uri = urlParser.parse('http://' + connectReq.uri);
        let options = {
            host: `${uri.hostname}`,
            path: `${uri.path}`,
            port: `${uri.port}`,
            method: `${connectReq.method}`,
            headers: connectReq.headers
        };

        handleConnectRequest(nxtAsyncTunnel, flow, options);

    } else if (msgtype === 'TCP') {
        clientAsyncSocket = common.getNxtFlowToTcp(flow);
        if (typeof clientAsyncSocket === 'undefined') {
            console.log('NCTR - client key not found');
            return;
        } else {
            clientAsyncSocket.send(myPayload);
        }
    }
}

function handleConnectRequest(nxtAsyncTunnel, flow, options) {
    // open a TCP connection to the remote host
    var tcpConn = net.createConnection(options.port, options.host);
    tcpConn.on('error', function (err) { console.log(err) });
    tcpConn.on('connect', function () {
        console.log('   NCTR - connect OK for srcPort', flow.srcPort);
        // Construct HTTP Response
        let goodStatus = 'HTTP/1.1 200 Connection Established\r\n';
        let genStatus = 'proxy-agent: nxt-connector\r\n' +
            '\r\n';
        let body = Buffer.from(goodStatus + genStatus);

        //
        // Save the peer socket address at the connection time so that 
        // we can know which socket is closed when receiving the 'close' event. 
        //
        tcpConn.peerAddress = tcpConn.remoteAddress + " : " + tcpConn.remotePort;

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

        common.sendNxtTunnelInChunks(tcpConn, nxtAsyncTunnel, flow, body, false);
    });
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
            handleRequestMessage,
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
        handleRequestMessage,
        registrationInfo, false, services);

    console.log('\nNCTR - scheduled 1 second timer');
    setTimeout(checkTunnel, 1);
}
