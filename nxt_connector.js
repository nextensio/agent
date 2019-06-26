//
// NXT Connector (NCTR)
// Author: Rudy Z, Uday K.
// Date: April 4th, 2019
//
require('dotenv').config();

const minimist = require('minimist');
const { Console } = require('console');
const { ServerResponse } = require('http');
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const httpDestServer = require('http-proxy');
const httpParser = require('http-string-parser');
const urlParser = require('url');
const common = require('./nxt_common.js');
const bindSockets = require('./nxt_bind_sockets.js');
const clientMap = require('./nxt_client_hash.js');
const httpsOpts = {
    key: fs.readFileSync('./server-key.pem'),
    cert: fs.readFileSync('./server-crt.pem'),
    ca: fs.readFileSync('./ca-crt.pem'),
    requestCert: true,
    rejectUnathorized: true
};
const express = require('express');
var request = require("request");

let registrationInfo = {
    destService : '',
    ingressGatewayAddr : '',
    host : '',
    accessToken : '',
    sessionID : '',
    connectID : '',
    uuid : '',
    codec : '',
    connectID : ''
};

// 
// NXT Connector is capable of handling 2 requests:
// 1. HTTP and WebSocket direct connection. Listening port 8082.
// 2. Websocket dial-out to NXT egress mesh network
//
const NXT_CONNECTOR_PORT = 8082;
const NXTS_CONNECTOR_PORT = 8084;

// 
// DestProxy: proxy HTTP request to destination. 
// Request coming in from HTTP port 8082 or WS Tunnel. 
//
var destProxy = new httpDestServer.createProxyServer({});

// 
// Websocket Tunnel
// 
var directWs = null;
var dialoutWs = null;
var previousFlow = null;

//
// Process arguments
//
common.setArgs(minimist(process.argv.slice(2), {
    string: [ 'service1', 'service2' ],
    boolean: [ 'local', 'cluster', 'multicluster', 'dynamic', 'usage', 'new_multicluster' ],
    alias: { l: 'local', c: 'cluster', m: 'multicluster', d: 'dynamic', u: 'usage', n: 'new_multicluster' },
    default: { service1: 'connector-1' }
}));

if (common.getArgs().usage) {
    common.printUsages();
    process.exit(0);
}

//
// Listen and handle HTTP request (HTTP Server)
//
const server = http.createServer(function(req, res) {
    console.log("NCTR - HTTP request received: ", JSON.stringify(req.headers, true, 2));
    
    let uri = urlParser.parse(req.url);
    if (uri.href === '/register') {
        // dynamic environment, need to create tunnel to gateway.ric.nextensio.net
        if (common.getArgs().dynamic) {
            registerAndCreateTunnel();
        }
        res.writeHead(200);
        res.end();
    } else {
        let hostname = 'http://' + req.headers['host'];
        console.log('NCTR - host: ', hostname);
        destProxy.web(req, res, { target: `${hostname}` } );
    }
});

//
// Listener on port NXT_CONNECTOR_PORT
//
server.listen(NXT_CONNECTOR_PORT);
console.log('NCTR - http server listening on port ' + `${NXT_CONNECTOR_PORT}`);

server.on('connect', function (req, socket, head) {
    console.log("NCTR - direct connected - connect request received!");
});
  
server.on('upgrade', function (req, socket, head) {
    console.log("NCTR - direct connected - upgrade request received!");
});

//
// HTTPS Web Server
//
const secureServer = https.createServer(httpsOpts, function (req, res) {
    console.log('NCTR handling HTTPS request callback, url: ' + req.url);
    let hostname = 'https://' + req.headers['host'];
    console.log("NCTR - host: ", hostname);
    destProxy.web(req, res, { target: `${hostname}` } );
});

//
// Listener on port NXTS_CONNECTOR_PORT
//
secureServer.listen(NXTS_CONNECTOR_PORT);
console.log('NXT Connector (NCTR) https server listening on port ' + `${NXTS_CONNECTOR_PORT}`);

secureServer.on('connect', function (req, socket, head) {
    console.log("NCTR - direct connected https server - conect");
});
  
secureServer.on('upgrade', function (req, socket, head) {
    console.log("NCTR - direct connected https server - upgrade");
});

function handleMultipleRequestMessages(ws, message) {
    // console.log('   NCTR - handle multiple request message (' + message.length + ') ------------------');

    var payloadArray = [];
    
    payloadArray = common.parseMultipleWsPayload(message);
    if (payloadArray[0].header === null) {
        console.log('\nNCTR - multiple requests handler - received message without nxt header');
        console.log(message);
        return;
    }
    // console.log('NCTR - number of payloads', payloadArray.length);

    let msgIndex = 0;
    for (msgIndex = 0; msgIndex < payloadArray.length; msgIndex++) {
        let payload = payloadArray[msgIndex];
        handleRequestMessage(ws, payload, false);
    }
}

//
// Common function to handle websocket message coming from Websocket Server or Tunnel
//
function handleRequestMessage(ws, payload, usePrevious) {
    //console.log('NCTR - handle request message');
    //console.log(JSON.stringify(payload.header));
    //console.log(payload.data.toString());

    let flow;
    let clientKey;
    let clientSocket;

    if (usePrevious) {
        if (previousFlow !== null) {
            flow = previousFlow;
            clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
            clientSocket = clientSrcMap.get(clientKey);
            if (typeof clientSocket === 'undefined') {
               console.log('NCTR - usePrevious, client socket is not found, drop message!');
            } else {
               console.log('NCTR - usePrevious, send message as-is');
               clientSocket.write(payload);
            }
        } else {
            console.log('NXT Agent - no previous flow recorded, print message');
            console.log(payload);
        }
        return;
    }

    // Parse Nxt Header
    let nxtReq = payload.header;
    flow = common.createNxtFlowObjectFromHeader(
                                common.getNxtFlowMsgType(nxtReq.headers), 
                                nxtReq.uri, 
                                nxtReq.headers);
    let msgtype = common.getNxtFlowMsgType(nxtReq.headers);
    if (msgtype === 'CONNECT') {
        // Parse Body
        let connectReq = httpParser.parseRequest(payload.data.toString());  

        //console.log('NCTR - body', connectReq);
        let uri = urlParser.parse('http://' + connectReq.uri);
        let options = {
            host: `${uri.hostname}`,
            path: `${uri.path}`,
            port: `${uri.port}`,
            method: `${connectReq.method}`,
            headers: connectReq.headers
        };

        handleConnectRequest(ws, flow, options);
    } else if (msgtype === 'GET') {
        // GET REQUEST
        //console.log('NCTR - GET payload');
        //console.log('NCTR - NXT HDR', JSON.stringify(nxtReq.headers));
        //console.log(payload.data.toString());
        
        let getReq = httpParser.parseRequest(payload.data.toString());

        // use nxtReq header to connect
        let uri = urlParser.parse('http://' + getReq.uri);
        let options = {
            host: '',
            port: ''
        };
        options.port = (uri.port === null) ? 80 : uri.port;
        options.host = getReq.headers.host;
        
        handleProxyRequest(ws, flow, options, payload.data);
    } else if (msgtype === 'TCP') {
        // TCP Data
        // console.log('   NCTR - processing TCP data ' +
        //             'srcPort: ' + flow.srcPort + ', ' +
        //             'srcIp: ' + flow.srcIp);
        clientKey = clientMap.createKey(flow.srcPort, flow.srcIp);
        clientSocket = clientMap.get(clientKey);
        if (typeof clientSocket === 'undefined') {
            console.log('NCTR - client key not found');
        } else {
            if (clientSocket instanceof Console) {
                // Console, used by test functions
                console.log('NCTR - write to destination (console)');
                clientSocket.log('[' + payload.data.toString() + ']');
            } else if (clientSocket instanceof ServerResponse) {
                // Response Object
                console.log('NCTR write to destination (ServerResponse)');
                let res = httpParser.parseResponse(payload.data.toString()); 
                if (res.statusCode !== undefined) { 
                    clientSocket.writeHead(res.statusCode, res.headers);
                }
                clientSocket.write(res.body);
                //clientSocket.end();
            } else {
                // console.log('NXT Connector write to destination (TCP)');
                clientSocket.write(payload.data);
            }
        }
    }
    previousFlow = flow;
}

function handleConnectRequest(ws, flow, options) {
    try {
        console.log('NCTR - handleConnectRequest:', 
                    flow.con, flow.srcPort, options.host, options.port);
        // open a TCP connection to the remote host
        var tcpConn = net.createConnection(options.port, options.host);
        tcpConn.on('connect', function() {
            console.log('   NCTR - connect OK for srcPort', flow.srcPort);
            // Construct HTTP Response
            let goodStatus = 'HTTP/1.1 200 Connection Established\r\n';
            //let badStatus = 'HTTP/1.1 500 Connection Failed\r\n';
            let genStatus = 'proxy-agent: nxt-connector\r\n' +
                            '\r\n';
            let body = Buffer.from(goodStatus + genStatus);

            // Bind the Websocket and TCP socket
            bindSockets(ws, tcpConn);

            // Store the tcpConn to be use by ws message processing
            let clientKey = clientMap.createKey(flow.srcPort, flow.srcIp);
            clientMap.insert(clientKey, tcpConn);

            // Reverse the flow before storing
            let dest = flow.dest;
            flow.dest = flow.con;
            flow.con = dest;

            // Set flow host to the ingress gateway for the connector
            flow.host = registrationInfo.host;

            // Store the flow object for usage in tcp data processing
            common.storeNxtFlowObject(tcpConn, flow);

            if (common.getArgs().new_multicluster) {
                common.sendNxtTunnel(ws, flow, body, true);
            } else {
                common.sendNxtTunnelInChunks(ws, flow, body, false);
            }
        });
    }
    catch (err) {
        console.error('NCTR - error in net.connect!');
        console.error(err.stack);
    }
}

function handleProxyRequest(ws, flow, options, body) {
    // console.log('NCTR - handleProxyRequest', options);
    // console.log(body.toString());

    try {
        var tcpConn = net.createConnection(options.port, options.host);
        tcpConn.on('connect', function() {
            console.log('NCTR - connect sucessful');
            // Bind the Websocket and TCP socket
            bindSockets(ws, tcpConn);

            // Store the tcpConn to be use by ws message processing
            let clientKey = clientMap.createKey(flow.srcPort, flow.srcIp);
            clientMap.insert(clientKey, tcpConn);

            // Reverse the flow before storing
            let dest = flow.dest;
            flow.dest = flow.con;
            flow.con = dest;

            // Set flow host to the ingress gateway for the connector
            console.log('NCTR - Registration Host', registrationInfo.host, options.host);
            flow.host = registrationInfo.host;

            // Store the flow object for usage in tcp data processing
            common.storeNxtFlowObject(tcpConn, flow);

            // Send body to destination
            console.log('NCTR - handleProxyRequest2', options);
            console.log(body.toString());
            tcpConn.write(body);
        });
    }
    catch (err) {
        console.error('NXT Agent error in net.connect (proxy)!');
        console.error(err.stack);
    }
}

// #########################################################################################

if (common.getArgs().local) {
    //
    // Direct connection - create websocket server
    // Only create it in Local Environment
    //
    // const wsServer = new WebSocket.Server( { server } );
    const wsServer = new WebSocket.Server( { server: secureServer } );
    console.log('NCTR - ws created for direct connected');

    wsServer.on('connection', (ws, req) => {
        console.log('NCTR - ws direct connected - connection event, req:', 
                    JSON.stringify(req.headers, true, 2));
        directWs = ws;
        ws.on('message', (message) => {
            console.log('NCTR - ws direct connected - message received');
            handleMultipleRequestMessages(directWs, message);
        });
        ws.on('close', (reason, description) => {
            console.log('NCTR - ws direct connected - close event');
            directWs = null;
        });
        ws.on('error', (reason, description) => {
            console.log('NCTR - ws direct connected - error event', reason);
            directWs.close();
        });
    });
} else if (common.getArgs().cluster || common.getArgs().multicluster || common.getArgs().new_multicluster) {
    // Cloud environment, need to create tunnel to gateway.sjc.nextensio.net (tom.com/candy.com cloud)
    registerAndCreateTunnel();
}

function requestRegistration() {
    if (common.getArgs().dynamic) {
        // Setting URL and headers for request
        var options = {
            // url: `${process.env.NXT_PORTAL_URL}/request_connector_reg_info`,
            url: `${process.env.NXT_PORTAL_URL}/request_connector_reg_info_demo`,
            headers: {
                'User-Agent': 'request'
            }
        };
        // Return new promise 
        return new Promise(function(resolve, reject) {
            // Do async job
            console.log('NCTR requesting registration info');
            request.get(options, function(err, resp, body) {
                if (err) {
                    console.log('Couldn\'t get registration info');
                    reject(err);
                } else {
                    resolve(resp.headers);
                    console.log('Promise resolved - Deployment');
                }
            })
        })
    } else {
        return new Promise(function(resolve, reject) {
            // Do async job
            resolve('default');
            console.log('Promise resolved - Cloud/Local');
        })
    }
}

function registerAndCreateTunnel() {
    var clientKey;
    var clientCrt;
    var clientCA;

    var regPromise = requestRegistration();

    console.log('NCTR reg promise', JSON.stringify(regPromise));

    regPromise.then(function(result) {
        if (common.getArgs().dynamic) {        
            console.log('NCTR obtained registration information from portal\n', result);

            registrationInfo.destService = result.destservice;
            registrationInfo.ingressGatewayAddr = result.ingressgatewayaddr;
            registrationInfo.accessToken = result.accesstoken;
            registrationInfo.sessionID = result.sessionid;
            registrationInfo.connectID = result.connectid;
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = result.codec;

            clientKey = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/private/gateway.ric.nextensio.net.key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/certs/gateway.ric.nextensio.net.cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/2_intermediate/certs/ca-chain.cert.pem');
        } else if (common.getArgs().cluster) {
            console.log('NCTR proceeding with tom.com/candy.com registration information');     
            
            var hostURL = urlParser.parse(common.NXTS_INGRESS_GW);

            registrationInfo.destService = common.NXT_CONNECTOR_SERVICE;
            registrationInfo.ingressGatewayAddr = common.NXTS_INGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = 'tom.com';
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/ingress_client_key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/ingress_client_cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/ingress_ca.pem');
        } else if (common.getArgs().multicluster) {        
            console.log('NCTR obtained multicloud registration information from portal\n', result);

            registrationInfo.destService = 'tom.com';
            registrationInfo.ingressGatewayAddr = common.NXTS_EGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = 'c362-video-aaa-com-80';
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/private/gateway.ric.nextensio.net.key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/certs/gateway.ric.nextensio.net.cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/2_intermediate/certs/ca-chain.cert.pem');
        } else if (common.getArgs().new_multicluster) {        
            console.log('NCTR obtained new multicloud registration information from portal\n', result);

            registrationInfo.destService = 'agent-1';
            registrationInfo.ingressGatewayAddr = common.NXTS_EGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = common.getArgs().service1;
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/private/gateway.ric.nextensio.net.key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/4_client/certs/gateway.ric.nextensio.net.cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/gateway.ric.nextensio.net/2_intermediate/certs/ca-chain.cert.pem');
        } 

        // update the host parameter for all modes
        var hostURL = urlParser.parse(registrationInfo.ingressGatewayAddr);
        registrationInfo.host = hostURL.hostname;

        console.log('NCTR - HOSTNAME:', registrationInfo.host);

        const extension = { 
            headers: { 
                'x-nextensio-codec' :  registrationInfo.codec,        
                'x-nextensio-connect' : registrationInfo.connectID,
                'Authorization' : 'Bearer ' + registrationInfo.accessToken 
            },
            key: clientKey,
            cert: clientCrt, 
            ca: clientCA,
            secureProtocol: 'TLSv1_2_method' 
        };

        dialoutWs = common.createNxtWsTunnel(dialoutWs, 
                                registrationInfo.ingressGatewayAddr, 
                                null, 
                                extension,
                                handleMultipleRequestMessages);
                                // handleRequestMessage);
        
        if (common.getArgs().cluster) {
            console.log('\nNXT Connector (NCTR) sending msg in 5 seconds');
            setTimeout(function () {
                dialoutWs.send('NCTR ' + registrationInfo.connectID);
            }, 5000);
        } else if (common.getArgs().dynamic) {
            console.log('\nNXT Connector (NCTR) sending msg in 10 seconds');
            setTimeout(function () {
                if (dialoutWs.readyState !== WebSocket.OPEN) {
                    console.log('NCTR - ERROR: websocket still is not open after 20 seconds');
                }
                else {
                    dialoutWs.send('NCTR ' + registrationInfo.connectID);
                }
            }, 10000);
        } else if (common.getArgs().multicluster) {
            console.log('\nNXT Connector (NCTR) sending msg in 10 seconds');
            setTimeout(function () {
                if (dialoutWs.readyState !== WebSocket.OPEN) {
                    console.log('NCTR - ERROR: websocket still is not open after 10 seconds');
                } else {
                    dialoutWs.send('NCTR ' + registrationInfo.connectID);
                }
            }, 10000);
        } else if (common.getArgs().new_multicluster) {
            console.log('\nNXT Connector (NCTR) sending msg in 10 seconds');
            setTimeout(function () {
                if (dialoutWs.readyState !== WebSocket.OPEN) {
                    console.log('NCTR - ERROR: websocket still is not open after 10 seconds');
                } else {
                    if (typeof common.getArgs().service2 !== 'undefined') {
                        dialoutWs.send('NCTR ' + common.getArgs().service1 + ' ' + common.getArgs().service2);
                    } else {
                        dialoutWs.send('NCTR ' + common.getArgs().service1);
                    }
                }
            }, 10000);
        } 
    }, function(err) {
        console.log('NCTR - promise rejected', err);
        console.log(err.stack);
    }).catch(function(ex) {
        console.log('NCTR - promise exception', ex);
    });
}
