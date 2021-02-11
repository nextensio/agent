//
// NXT Proxy Agent
// Author: Rudy Z, Uday K.
// Date: April 4th, 2019
//
'use strict'

require('dotenv').config();
require('log-timestamp')(function () { return new Date().toISOString() + ' %s' });

const minimist = require('minimist');
const WebSocket = require('ws');
const http = require('http');
const urlParser = require('url');
const common = require('./nxt_common.js');
const bindSockets = require('./nxt_bind_sockets.js');
const AsyncSocket = require('./nxt_async_socket.js');
const NXT_AGENT_PROXY = 8080;
const NXT_OKTA_RESULTS = 8081;
const NXT_OKTA_LOGIN = 8180

var streamid = 1;
var nxtOnboarded = false;
var nxtOnboardPending = false;
var nxtAsyncWsTunnel = null;
var extension = null;
var services = []

let registrationInfo = {
    host: '',
    accessToken: '',
    connectID: '',
    domains: [],
    CACert: '',
    userid: '',
};

//
// Process arguments
//
common.setArgs(minimist(process.argv.slice(2), {
    string: ['service', 'controller'],
    boolean: ['usages'],
    alias: { u: 'usages' },
    default: { service: '', controller: 'server.nextensio.net:8080' }
}));

if (common.getArgs().usages) {
    common.printUsages();
}


var oktaResults = http.createServer(function (req, res) {
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
}).listen(NXT_OKTA_RESULTS);

var webProxy = http.createServer(function (req, res) {
    res.writeHead(200);
    res.end();
}).listen(NXT_AGENT_PROXY);

webProxy.on('connect', function (req, socket, head) {
    //
    // Save the peer socket address at the connection time so that 
    // we can know which socket is closed when receiving the 'close' event. 
    //
    createNewSocket(req, nxtAsyncWsTunnel, socket);
    // Just say ok to the client right away, later if there are errors on the nextensio
    // side, we will end up tearing down this session anyways
    socket.write('HTTP/1.1 200 Connection Established\r\n' +
        'proxy-agent: nxt-connector\r\n' +
        '\r\n');
});

var login = require('fs'),
    okta = require('http');

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
}).listen(NXT_OKTA_LOGIN);

//
// This is the entry function to handle HTTPS connection request from the client
//
function createNewSocket(req, nxtAsyncTunnel, clientSocket) {
    //
    // NOTE: proxy.pac file is used to filter connect request
    //
    if (nxtAsyncWsTunnel == null) {
        console.log('NAGT - tunnel socket is not created yet');
        return;
    }

    var serverURL = urlParser.parse('https://' + req.url);

    try {
        // empty payload to send to the connector on getting CONNECT request,
        // we just need the connector to open sockets thats all
        var body = [];

        var d;
        var destService = 'default-internet';
        for (d of registrationInfo.domains) {
            if (serverURL.hostname.includes(d)) {
                destService = serverURL.hostname;
                break;
            }
        }

        var clientAsyncSocket = new AsyncSocket(clientSocket, common.SOCKET_RING_BUFFER_SIZE)

        var flow = common.createNxtFlow('L4',
            serverURL.hostname,
            serverURL.port,
            destService,
            clientSocket.remoteAddress,
            clientSocket.remotePort,
            registrationInfo.connectID,
            registrationInfo.connectID,
            -1,
            streamid * 2);
        streamid += 1;

        common.storeNxtFlowToTcp(flow, clientAsyncSocket);
        common.storeNxtTcpToFlow(clientSocket, flow);
        bindSockets(nxtAsyncTunnel, clientAsyncSocket);

        // Send to NXT Tunnel
        common.sendNxtTunnelInChunks(clientSocket, nxtAsyncTunnel, flow, Buffer.concat(body), false);
    }
    catch (err) {
        console.error('NXT Agent error in create and sent to ws tunnel!');
        console.error(err.stack);
    }
}


//
// The worker function to handle data received from NXT tunnel
//
function packetFromCluster(nxtAsyncTunnel, message) {
    let clientAsyncSocket;

    var ret = common.parseWsPayload(nxtAsyncTunnel, message);
    if (ret == null) {
        console.log("Null payload")
        return
    }
    var myPayload = ret[0]
    var flow = ret[1]
    clientAsyncSocket = common.getNxtFlowToTcp(flow);
    if (typeof clientAsyncSocket === 'undefined') {
        return;
    }
    // Handling  TCP Payload
    clientAsyncSocket.send(myPayload);
}


// #########################################################################################

function nxtOnboard() {
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
                registrationInfo.host = data.gateway
                registrationInfo.connectID = data.connectid
                registrationInfo.domains = data.domains
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
    http.get('https://' + common.getArgs().controller + '/api/v1/onboard/' + registrationInfo.accessToken, callback).
        on("error", (err) => {
            console.log("Error: " + err.message);
            nxtOnboardPending = false;
        });
}

function checkTunnel() {
    if (nxtAsyncWsTunnel == null) {
        //console.log('Socket not yet created')
    } else if ((nxtAsyncWsTunnel.websocket.readyState == WebSocket.CLOSED) ||
        ((nxtAsyncWsTunnel.websocket.readyState == WebSocket.CLOSING))) {
        console.log('Websocket closed, reopening')
        common.clearNxtTcpToFlow();
        common.clearNxtFlowToTcp();
        var gatewayURL = 'wss://' + registrationInfo.host + ':443'
        nxtAsyncWsTunnel = common.createNxtWsTunnel(gatewayURL,
            null,
            extension,
            packetFromCluster,
            registrationInfo, true, services);
    }
    setTimeout(checkTunnel, 1);
}


//
// Register and create Tunnel
//
function registerAndCreateTunnel() {
    extension = {
        headers: {
            'x-nextensio-connect': registrationInfo.connectID,
        },
        ca: registrationInfo.CACert,
        secureProtocol: 'TLSv1_2_method'
    }
    // Create the tunnel
    var gatewayURL = 'wss://' + registrationInfo.host + ':443'
    nxtAsyncWsTunnel = common.createNxtWsTunnel(gatewayURL,
        null,
        extension,
        packetFromCluster,
        registrationInfo, true, services);

    console.log('\nNAGT - scheduled 1 second timer');
    setTimeout(checkTunnel, 1);
}

