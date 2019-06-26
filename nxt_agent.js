//
// NXT Proxy Agent
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
const httpProxy = require('http-proxy');
const httpParser = require('http-string-parser');
const urlParser = require('url');
const common = require('./nxt_common.js');
const bindSockets = require('./nxt_bind_sockets.js');
const clientSrcMap = require('./nxt_client_hash.js');
const httpsOpts = {
    key: fs.readFileSync('./server-key.pem'),
    cert: fs.readFileSync('./server-crt.pem'),
    ca: fs.readFileSync('./ca-crt.pem')
};
const express = require('express');
var request = require("request");

// Overwrite Console Log
//console.log = function(){};

//
// Global Variables
//
var nxtAccessToken = null;
var agtWs = null;
var previousFlow = null;

//
// Mesh Network
//
const NXT_LOCAL_INGRESS_MESH = 'ws://localhost:8082/';
const NXTS_LOCAL_INGRESS_MESH = 'wss://localhost:8084';
const NXT_MOVIE_MESH = 'ws://movie.kismis.org/bunny';

let registrationInfo = {
    destService : '',
    ingressGatewayAddr : '',
    host : '',
    accessToken : '',
    sessionID : '',
    connectID : '',
    uuid: '',
    codec : '',
    connectID : ''
};

//
// Process arguments
//
common.setArgs(minimist(process.argv.slice(2), {
    string: [ 'service', 'catchall' ],
    boolean: [ 'local', 'cluster', 'multicluster', 'dynamic', 'usages', 'new_multicluster' ],
    alias: { l: 'local', c: 'cluster', m: 'multicluster', d: 'dynamic', u: 'usages', n: 'new_multicluster' },
    default: { service: 'agent-1', catchall: 'connector-1' }
}));

if (common.getArgs().usages) {
    common.printUsages();
}

//
// Setup http proxy handle
//
var httpProxyHandle = new httpProxy.createProxyServer();

//
// HTTP Web Server
//
var httpServer = http.createServer(function (req, res) {
    console.log('\nNAGT - handling HTTP request callback (method,url,header)');
    // console.log(req.method, req.url, req.headers);

    let uri = urlParser.parse(req.url);
    if (uri.href === '/register') {
        if (common.getArgs().dynamic) {
            registerAndCreateTunnel();
        }
        res.writeHead(200);
        res.end();
    } else {
        if (nxtAccessToken != null) {
            httpProxyHandle.web(req, res, { target: req.url });
        } else {
            nxtProxySend(req, agtWs, res);
        }
    }
}).listen(8081);

console.log('NXT Agent HTTP Server listening to port 8081');

httpServer.on('connect', function(req, socket, head) {
    // directConnect(req, socket, head);
    nxtConnect(req, agtWs, socket, head);
});

function directConnect(req, socket, head) {
    var serverURL = urlParser.parse('https://' + req.url);
    console.log('NXT Agent connect event received (method,url,headers)');
    console.log(req.method, req.url, JSON.stringify(req.headers, true, 2));

    try {
        // open a TCP connection to the remote host
        var tcpConn = net.connect(serverURL.port, serverURL.hostname, function() {
            // respond to the client that the connection was made
            socket.write('HTTP/1.1 200 Connection Established\r\n' +
                            'Proxy-agent: Node-proxy\r\n' +
                            '\r\n');
            // create a tunnel between the two hosts
            tcpConn.pipe(socket);
            socket.pipe(tcpConn);

            socket.on('data', function(buff) {
                console.log('socket data type of', typeof buff);
                if (typeof buff === 'string') {
                    console.log(buff);
                } else {
                    console.log(buff.toString());
                }
            });

            socket.on('error', function(err) {
                console.log('NXT Agent TCP socket error', err.message);
            });
        });

        tcpConn.on('data', function(buff) {
            console.log('tcpConn data type of', typeof buff);
            if (typeof buff === 'string') {
                console.log(buff);
            } else {
                console.log(buff.toString());
            }
        });

        tcpConn.on('error', function(err) {
            console.log('NXT Agent TCP srvSocket error', err.message);
        });
    }
    catch (err) {
        console.error('NXT Agent error in net.connect!');
        console.error(err.stack);
    }
}

function nxtConnect(req, tunnelSocket, clientSocket, head) {

    // note: use proxy.pac to filter connect request!
    // if ((req.url === 'undefined.com:443') ||
    //     (req.url === 'gunicorn.com:443')) {
    // } else {
    //     return;
    // }

    if (tunnelSocket === null) {
        console.log('NAGT - tunnel socket is not created yet');
        return;
    }

    var serverURL = urlParser.parse('https://' + req.url);

    console.log('NXT Agent nxtConnect handler ------------------');
    console.log(req.method, req.url, JSON.stringify(req.headers, true, 2));
    // console.log(serverURL);

    try {
        // construct HTTP connect string from request
        var body = [];
        body.push(Buffer.from(`${req.method}` + ' ' + `${req.url}` + ' ' + 'HTTP/1.1' + '\r\n'));
        Object.keys(req.headers).forEach(function(key) {
            let val = req.headers[key];
            body.push(Buffer.from(`${key}` + ':' + ' ' + `${val}` + '\r\n'));
        });

        if (common.getArgs().new_multicluster) {
	    //
	    // Update 'destService' field per the destination filter
	    // The default gateway is specified using the 'catchall' field
	    //
            if (serverURL.hostname.includes(".kismis.org")) {
                registrationInfo.destService = serverURL.hostname;
            } else {
		registrationInfo.destService = common.getArgs().catchall;
	    }
	    console.log('x-nextensio-for will be changed to ', registrationInfo.destService);
        }

        // construct Nxt Flow Header
        var flow = common.createNxtFlowObject('CONNECT',
                                            registrationInfo.host,
                                            serverURL.path,
                                            registrationInfo.destService,
                                            registrationInfo.connectID,
                                            registrationInfo.uuid,
                                            clientSocket.remotePort,
                                            clientSocket.remoteAddress,
                                            registrationInfo.sessionID,
                                            registrationInfo.codec);

        // Socket Instance
        bindSockets(agtWs, clientSocket);

        // Store the client socket to be use during ws message processing
        var clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
        clientSrcMap.insert(clientKey, clientSocket);

        // Store the flow object to be use for tcp data processing
        common.storeNxtFlowObject(clientSocket, flow);

        // Send to NXT Tunnel
        common.sendNxtTunnelInChunks(tunnelSocket, flow, Buffer.concat(body), false);
    }
    catch (err) {
        console.error('NXT Agent error in create and sent to ws tunnel!');
        console.error(err.stack);
    }
}

function nxtProxySend(req, tunnelSocket, res) {
    console.log('NXT Agent nxtProxySend');

    if (tunnelSocket === null) {
        console.log('NAGT - tunnel socket is not created yet');
        return;
    }

    let uri = urlParser.parse(req.url);
    try {
        // construct HTTP request
        var body = [];
        // if path is not empty, use uri.path
        // if path is empty, use req.url
        if (uri.path.length > 1) {
            body.push(Buffer.from(`${req.method}` + ' ' + `${uri.path}` + ' ' + 'HTTP/1.1' + '\r\n'));
        } else {
            body.push(Buffer.from(`${req.method}` + ' ' + `${req.url}` + ' ' + 'HTTP/1.1' + '\r\n'));
        }
        Object.keys(req.headers).forEach(function(key) {
            let val = req.headers[key];
            body.push(Buffer.from(`${key}` + ':' + `${val}` + '\r\n'));
        });
        body.push(Buffer.from('\r\n'));

        // construct Nxt Flow Header
        var flow = common.createNxtFlowObject(req.method,
                                            uri.hostname,
                                            uri.path,
                                            registrationInfo.destService,
                                            registrationInfo.connectID,
                                            registrationInfo.uuid,
                                            req.connection.remotePort,
                                            req.connection.remoteAddress,
                                            registrationInfo.sessionID,
                                            registrationInfo.codec);

        // Store the client socket to be use during ws message processing
        var clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
        clientSrcMap.insert(clientKey, res); // insert response object into the client src map

        // Store the flow object to be use for tcp data processing
        common.storeNxtFlowObject(res, flow);

        // Send to NXT tunnel
        if (common.getArgs().new_multicluster) {
            common.sendNxtTunnel(tunnelSocket, flow, Buffer.concat(body), true);
        } else {
            common.sendNxtTunnelInChunks(tunnelSocket, flow, Buffer.concat(body), false);
        }
    }
    catch (err) {
        console.error('NXT Agent error in create and sent to ws tunnel!');
        console.error(err.stack);
    }
}

//
// HTTPS Web Server
//
var httpsServer = https.createServer(httpsOpts, function (req, res) {
    console.log('NXT Agent handling HTTPS request callback, url: ' + req.url);
    console.log(JSON.stringify(req.headers, true, 2));
    console.log('Response statusCode: ', res.statusCode);

    httpsProxy.web(req, res, { target: req.url });
}).listen(8083);

console.log('NXT Agent HTTPS started listening to port 8083');

function handleMultipleResponseMessages(ws, message) {
    // console.log('   NAGT - handle multiple response message (' + message.length + ') ------------------');

    var payloadArray = [];

    payloadArray = common.parseMultipleWsPayload(message);
    if (payloadArray[0].header === null) {
        console.log('   NAGT - multiple requests handler - received message without nxt header');
        handleResponseMessage(ws, message, true);
        return;
    }
    //console.log('NAGT - number of payloads', payloadArray.length);

    let msgIndex = 0;
    for (msgIndex = 0; msgIndex < payloadArray.length; msgIndex++) {
        let payload = payloadArray[msgIndex];
        handleResponseMessage(ws, payload, false);
    }
}

function handleResponseMessage(ws, payload, usePrevious) {
    // console.log('NAGT - handle response message');

    let flow;
    let clientKey;
    let clientSocket;

    // Case 1: Fragmented TCP packets, will arrive with no NXT Header. Payload is the message.
    //         In this case, use previous flow to send the data out. If previous flow is null, just print the message.
    if (usePrevious) {
        if (previousFlow !== null) {
            flow = previousFlow;
            clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
            clientSocket = clientSrcMap.get(clientKey);
            if (typeof clientSocket === 'undefined') {
               console.log('>> NAGT - usePrevious, client socket is not found, drop message!');
            } else {
               console.log('   NAGT - usePrevious, send message as-is');
               writeInChunks(clientSocket, payload);
            }
        } else {
            // console.log('NAGT - no previous flow recorded, print message');
            console.log(payload);
        }
        return;
    }

    // Case 2: payload has NXT header. Continue with normal processing.
    //
    let nxtReq = payload.header;
    flow = common.createNxtFlowObjectFromHeader(
                                common.getNxtFlowMsgType(nxtReq.headers),
                                nxtReq.uri,
                                nxtReq.headers);

    //console.log('Received', JSON.stringify(flow));

    let msgtype = common.getNxtFlowMsgType(nxtReq.headers);
    if (msgtype === 'CONNECT') {
        let res = httpParser.parseResponse(payload.data.toString());
        if (res.statusCode == 200)
            console.log('   HTTP CONNECT successful');
        else
            console.log('   HTTP CONNECT is NOT successful');

        clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
        clientSocket = clientSrcMap.get(clientKey);
        if (typeof clientSocket === 'undefined') {
            console.log('NAGT - client socket is not found');
        } else {
            // console.log('NAGT - client socket found, resp to browser');
            clientSocket.write(payload.data);
        }
    }
    else if (msgtype === 'TCP') {
        //console.log('   NAGT - processing TCP body');
        clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
        clientSocket = clientSrcMap.get(clientKey);
        if (typeof clientSocket === "undefined") {
            console.log('NAGT - client socket is not found, packet drop!');
        } else {
            // console.log('NAGT - client Socket found, sent payload to client');
            if (clientSocket instanceof Console) {
                // Console, used by test functions
                clientSocket.log('[' + payload.data.toString() + ']');
            } else if (clientSocket instanceof ServerResponse) {
                console.log('\nNAGT - TCP client is instanceof ServerResponse');
                handleServerResponse(clientSocket, payload.data);
            } else {
                // Handling HTTPS TCP Payload
                writeInChunks(clientSocket, payload.data);
            }
        }
    } else if (msgtype === 'GET') {
        console.log('NAGT - GET request, drop!');
    }

    // save the current flow
    previousFlow = flow;
}

function handleServerResponse(clientSocket, resBuf) {

    // Response Object Processing

    let httpHeader = httpParser.parseResponse(resBuf.toString());
    if (httpHeader.statusCode === undefined) {
        // no HTTP header detected. It must be transfer-encoding = chunked
        console.log('NAGT - no HTTP response header, write as-is');
        console.log(JSON.stringify(resBuf.toString()));

        //clientSocket.write(resBuf);

        let chunkEnd = resBuf.toString().endsWith('0\r\n\r\n');
        if (chunkEnd) {
            console.log('NAGT - chunked end');
            clientSocket.write(resBuf);
            clientSocket.end();
        } else {
            clientSocket.write(resBuf);
        }
    } else {
        // HTTP header detected. Parse the header to get the transfer-encoding.
        // strip off Body
        let emptyLineIndex = resBuf.indexOf('\r\n\r\n', 0)
        let httpBodyBuf = resBuf.slice(emptyLineIndex + 4);

        console.log('NAGT - writing statusCode and headers');
        console.log(JSON.stringify(httpHeader.headers));
        clientSocket.writeHead(httpHeader.statusCode, httpHeader.headers);

        console.log(JSON.stringify(httpBodyBuf.toString()));

        if (httpHeader.headers['Transfer-Encoding'] === 'chunked') {
            let chunkEnd = httpBodyBuf.toString().endsWith('0\r\n\r\n');
            if (chunkEnd) {
                console.log('NAGT -- chunked end');
                clientSocket.write(httpBodyBuf);
                clientSocket.end();
            } else {
                console.log('NAGT -- not chunked end');
                clientSocket.write(httpBodyBuf);
                // not end of chunk !
            }
        } else {
            clientSocket.write(httpBodyBuf);
            clientSocket.end();
        }
    }
}

function writeInChunks(s, data) {
    let len = data.length;
    let chunkSize = common.AGT_CHUNK_SIZE;

    if (len <= chunkSize) {
        s.write(data);
        // if (s.write(data) {
        // } else {
        //     console.log('>>>>>>>>>>>>>>>>>> tcp paused');
        //     clientSocket.pause();
        // }
        return;
    }

    let startChunk = 0;
    let endChunk = chunkSize;

    console.log('   NAGT - chks start', len, chunkSize);

    do {
        s.write(data.slice(startChunk, endChunk));
        //console.log('   NAGT - chks:', startChunk, endChunk - 1);
        common.sleep(1);
        startChunk = endChunk;
        endChunk += chunkSize;
    } while (endChunk < data.length);

    if (startChunk < len) {
       s.write(data.slice(startChunk));
       console.log('   NAGT - chks end:', startChunk, len - startChunk);
    }
}

// #########################################################################################

if (common.getArgs().local || 
    common.getArgs().cluster || 
    common.getArgs().multicluster || 
    common.getArgs().new_multicluster) {
    registerAndCreateTunnel();
}

function requestRegistration() {
    if (common.getArgs().dynamic) {
        // Setting URL and headers for request
        var options = {
            // url: `${process.env.NXT_PORTAL_URL}/request_agent_reg_info`,
            url: `${process.env.NXT_PORTAL_URL}/request_agent_reg_info_demo`,
            headers: { 'User-Agent': 'nxt-agent' }
        };
        // Return new promise
        return new Promise(function(resolve, reject) {
            // Do async job
            console.log('NAGT - request user info from nxt portal');
            request.get(options, function(err, resp, body) {
                if (err) {
                    reject(err);
                } else {
                    resolve(resp.headers);
                }
            })
        })
    } else {
        return new Promise(function(resolve, reject) {
            // Do async job
            resolve('no-op');
        })
    }
}

//
// Register and create Tunnel
//
function registerAndCreateTunnel() {
    var clientKey;
    var clientCrt;
    var clientCA;

    var regPromise = requestRegistration();
    regPromise.then(function(result) {
        if (common.getArgs().dynamic) {
            console.log('NAGT - user info received!\n', result);
            registrationInfo.destService = result.destservice;
            registrationInfo.ingressGatewayAddr = result.ingressgatewayaddr;
            registrationInfo.accessToken = result.accesstoken;
            registrationInfo.sessionID = result.sessionid;
            registrationInfo.connectID = result.connectid;
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = result.codec;

            clientKey = fs.readFileSync('../aws/istio_client/ingress_client_key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/ingress_client_cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/ingress_ca.pem');
        } else if (common.getArgs().cluster) {
            console.log('NXT Agent proceeding with tom.com/candy.com registration information');

            registrationInfo.destService = common.NXT_CONNECTOR_SERVICE;
            registrationInfo.ingressGatewayAddr = common.NXTS_INGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = 'candy.com';
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/ingress_client_key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/ingress_client_cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/ingress_ca.pem');
        } else if (common.getArgs().multicluster) {
            console.log('NXT Agent proceeding with multicloud registration information');

            registrationInfo.destService = 'c362-video-aaa-com-80';
            registrationInfo.ingressGatewayAddr = common.NXTS_INGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = 'tom.com';
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/ingress_client_key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/ingress_client_cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/ingress_ca.pem');
        } else if (common.getArgs().new_multicluster) {
            console.log('NXT Agent proceeding with new multicloud registration information');

            registrationInfo.destService = common.getArgs().catchall;
            registrationInfo.ingressGatewayAddr = common.NXTS_INGRESS_GW;
            registrationInfo.accessToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ';
            registrationInfo.sessionID = 'sid';
            registrationInfo.connectID = common.getArgs().service;
            registrationInfo.uuid = '1234578';
            registrationInfo.codec = common.BUFFER_ENCODING_HTTP;

            clientKey = fs.readFileSync('../aws/istio_client/ingress_client_key.pem');
            clientCrt = fs.readFileSync('../aws/istio_client/ingress_client_cert.pem');
            clientCA = fs.readFileSync('../aws/istio_client/ingress_ca.pem');
        } else {
            console.log('NXT Agent proceeding with local registration information');

            registrationInfo.connectID = 'local';
            registrationInfo.ingressGatewayAddr = NXTS_LOCAL_INGRESS_MESH;
            registrationInfo.codec = common.BUFFER_ENCODING_UNI;

            clientKey = fs.readFileSync('./client-key.pem');
            clientCrt = fs.readFileSync('./client-crt.pem');
            clientCA = fs.readFileSync('./ca-crt.pem');
        }

        var hostURL = urlParser.parse(registrationInfo.ingressGatewayAddr);
        registrationInfo.host = hostURL.hostname;

        const extension = {
            headers: {
                'x-nextensio-codec' : registrationInfo.codec,
                'x-nextensio-connect' : registrationInfo.connectID,
                'Authorization' : 'Bearer ' + registrationInfo.accessToken
            },
            key: clientKey,
            cert: clientCrt,
            ca: clientCA,
            secureProtocol: 'TLSv1_2_method'
        }

        // Create the tunnel
        agtWs = common.createNxtWsTunnel(agtWs,
                            registrationInfo.ingressGatewayAddr,
                            null,
                            extension,
                            handleMultipleResponseMessages);
                            // handleResponseMessage);
    }, function(err) {
        console.log('NXT Agent, promise rejected', err);
        console.log(err.stack);
    }).catch(function(ex) {
        console.log('NXT Agent, promise exception', ex);
    });

    if (common.getArgs().cluster) {
        console.log('\nNXT Agent (NAGT) sending msg in 5 seconds');
        setTimeout(function () {
            agtWs.send('NAGT ' + registrationInfo.connectID);
        }, 5000);
    } else if (common.getArgs().dynamic) {
        console.log('\nNXT Agent (NAGT) sending msg in 10 seconds');
        setTimeout(function () {
            if (agtWs.readyState !== WebSocket.OPEN) {
                console.log('NAGT - websocket still is not open after 10 seconds');
            } else {
                agtWs.send('NAGT ' + registrationInfo.connectID);
            }
        }, 10000);
    } else if (common.getArgs().multicluster) {
        console.log('\nNXT Agent (NAGT) sending msg in 10 seconds');
        setTimeout(function () {
            if (agtWs.readyState !== WebSocket.OPEN) {
                console.log('NAGT - websocket still is not open after 10 seconds');
            } else {
                agtWs.send('NAGT ' + registrationInfo.connectID);
            }
        }, 10000);
    } else if (common.getArgs().new_multicluster) {
        console.log('\nNXT Agent (NAGT) sending msg in 10 seconds');
        setTimeout(function () {
            if (agtWs.readyState !== WebSocket.OPEN) {
                console.log('NAGT - websocket still is not open after 10 seconds');
            } else {
                agtWs.send('NAGT ' + common.getArgs().service);
            }
        }, 10000);
    }
}

// setTimeout(function () {
//     testSendHTTPRequest(agtWs);
// }, 15000);

// function testSendHTTPRequest(ws) {
//     var lines;
//     let testURL = 'http://undefined.com/';
//     //let url = 'https://david-dm.org/apiaryio/http-string-parser/dev-status.png';
//     //let url = 'http://redirection20.directnic.com/assets/images/parked_header.png';

//     let uri = urlParser.parse(testURL);
//     let testHeaders = {
//         'Host': `${uri.hostname}`,
//         'Accept-Encoding': 'gzip, deflate',
//         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
//         'Content-Type': 'text/html; charset=UTF-8',
//         'Connection': 'keep-alive',
//         'User-Agent': 'nxt-agent'
//     };
//     let req = {
//         url: testURL,
//         host: `${uri.hostname}`,
//         path: `${uri.path}`,
//         method: 'GET',
//         port: 80,
//         headers: testHeaders,
//         connection: { remotePort: 4000, remoteAddress: '1.2.3.4' }
//     };
//     nxtProxySend(req, agtWs, new Console(process.stdout));
// }
