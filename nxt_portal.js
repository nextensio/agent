//
// NXT Web Portal
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const urlParser = require('url');
const session = require('express-session');
const { ExpressOIDC } = require('@okta/oidc-middleware');

//
// HTTPS Self-Sign Key and Certificates
//
const httpsOpts = {
    key: fs.readFileSync('./portal-key.pem', 'utf8'),
    cert: fs.readFileSync('./portal-cert.pem', 'utf8')
};

//
// PORTAL Listening Port
//
const NXT_PORTAL_PORT = 8080;

//
// Protected Route Modules / Paths
//
const protectedRouter = require('./nxt_auth');

const oidc = new ExpressOIDC({
    issuer: `${process.env.OKTA_ORG_URL}`,
    client_id: process.env.OKTA_CLIENT_ID,
    client_secret: process.env.OKTA_CLIENT_SECRET,
    redirect_uri: `${process.env.HOST_URL}/authorization-code/callback`,
    appBaseUrl: `${process.env.HOST_URL}`,
    scope: 'openid profile'
});

// 
// Express Instatiation 
//
var app = express();

app.use(session({
    secret: process.env.APP_SECRET,
    resave: true,
    saveUninitialized: false
}));

app.use(oidc.router);

//
// HTTP Server
// 
var server = http.Server(app);
//var server = https.Server(httpsOpts, app);

//
// WebPortal Listen Port
//
server.listen(NXT_PORTAL_PORT, function() {
   console.log('NXT Portal listening on port ' + `${NXT_PORTAL_PORT}`);
});

//
// Handle all HTTP routes
//
app.use(express.urlencoded({ extended: true }));

//
// Handle unprotected routes
//
app.get('/dashboard', (req, res) => {
    console.log("NXT Portal received dashboard request");
    res.writeHead(302,{Location: 'http://grafana.com'});
    res.end();
});

//
// Return proxy.pac
//
app.get('/proxy.pac', (req, res) => {
    console.log('Getting ' + __dirname + '/proxy.pac' + ' from disk');
    var file = fs.readFileSync(__dirname + '/proxy.pac', 'utf8');
    res.setHeader('Content-Length', file.length);
    res.write(file, 'utf8');
    res.end();
});

//
// Handle special case 'register' protected routes
//
app.get('/register', oidc.ensureAuthenticated(), (req, res) => {
    console.log('handling register (protected) route, userContext', req.userContext);
    // getSessionIdFromController();
    // res.end();
});

app.get('/request_agent_reg_info', (req, res) => {
    var req = handleAgentRequestRegInfo(req, res);
    req.then(function(message) {
        let serviceInfo = {
            destService: 'unknown',
            ingressGatewayAddr: 'unknown',
            accessToken: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ',
            sessionID: 'unknown',
            connectID: '0',
            codec: 'http'
        };
        let newServiceInfo = JSON.parse(message);

        let x = newServiceInfo['next_src_addr'].split('.');
        let deploymentName = 'a' + `${newServiceInfo['usid']}` + '-' + x[0] + '-' + x[1] + '-' + x[2] + '-' + x[3];

        serviceInfo.ingressGatewayAddr = constructSecureWebSocketStr(newServiceInfo['gateway_name']);
        serviceInfo.destService = 'c362-video-aaa-com-80'; // hardcode for now
        serviceInfo.sessionID = newServiceInfo['session_id'];
        serviceInfo.connectID = deploymentName;

        res.writeHeader(200, serviceInfo);
        res.end();
    }, function (err) {
        console.log(err);
        console.error(err.stack);
    }).catch(function(ex) {
        console.log('Promise then return an error:', ex.message);
        console.error(ex.stack);
    });
});

app.get('/request_agent_reg_info_demo', (req, res) => {
    console.log('NXT Portal return agent reg info (demo)');
    let serviceInfo = {
        destService: 'connector-1',
        ingressGatewayAddr: 'wss://gateway.sjc.nextensio.net:443',
        accessToken: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ',
        sessionID: 'sid',
        connectID: 'agent-1',
        codec: 'http'
    };
    res.writeHeader(200, serviceInfo);
    res.end();
});

app.get('/request_connector_reg_info_demo', (req, res) => {
    console.log('NXT Portal return connector reg info (demo)');
    let serviceInfo = {
        destService: 'agent-1',
        ingressGatewayAddr: 'wss://gateway.ric.nextensio.net:443',
        accessToken: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ',
        sessionID: 'sid',
        connectID: 'connector-1',
        codec: 'http'
    };
    res.writeHeader(200, serviceInfo);
    res.end();
});

function constructSecureWebSocketStr(urlStr) {
    return 'wss://' + urlStr + ':443';
}

function constructWebSocketStr(urlStr) {
    return 'ws://' + urlStr + ':80';
}

function handleAgentRequestRegInfo(req, res) {
    return new Promise (function (resolve, reject) {
        let controllerURIBody = '{' +
	        '\"ipaddr\":\"43.46.2.127\",' +
            '\"port\":\"40767\",' +
            '\"user\":\"mike.wilson@aaa.com\",' +
            '\"token\":\"nextensio\"' +
	    '}';
        createSessionInController(resolve, reject, controllerURIBody, true);
    });
}

app.get('/request_connector_reg_info', (req, res) => {
    var req = handleConnectorRequestRegInfo(req, res);
    req.then(function(message) {
        let serviceInfo = {
            destService: 'unknown',
            ingressGatewayAddr: 'unknown',
            accessToken: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ',
            sessionID: 'unknown',
            connectID: '0',
            codec: 'http'
        };
        let newServiceInfo = JSON.parse(message);

        let x = newServiceInfo['services'][0].split(':'); // only consider the first service
        let y = x[0].split(".");
        let deploymentName = 'c' + `${newServiceInfo['usid']}` + '-' + y[0] + '-' + y[1] + '-' + y[2] + '-' + x[1];

        serviceInfo.ingressGatewayAddr = constructSecureWebSocketStr(newServiceInfo['gateway_name']);
        serviceInfo.destService = 'a361-11-0-0-0'; // hardcode but will get overwriten later on....
        serviceInfo.sessionID = newServiceInfo['session_id'];
        serviceInfo.connectID = deploymentName;

        console.log('NXT Portal connector serviceInfo', JSON.stringify(serviceInfo));

        res.writeHeader(200, serviceInfo);
        res.end();
    }, function (err) {
        console.log(err);
        console.error(err.stack);
    }).catch(function(ex) {
        console.log('Promise then return an error:', ex.message);
        console.error(ex.stack);
    });
});

function handleConnectorRequestRegInfo(req, res) {
    console.log('NXT Portal entering handleConnectorRequestRegInfo');
    return new Promise (function (resolve, reject) {
        let controllerURIBody = '{' +
	        '\"ipaddr\":\"43.46.2.127\",' +
            '\"port\":\"40768\",' +
            '\"user\":\"tom.smith@aaa.com\",' +
            '\"token\":\"nextensio\"' +
	    '}';
        createSessionInController(resolve, reject, controllerURIBody, false);
    });
}

//
// Handle 'other' protected routes
//
app.use(oidc.ensureAuthenticated(), protectedRouter);

//
// Special functions
//
function createSessionInController(resolve, reject, controllerURIBody, agent) {
    console.log('NXT Portal entering createSessionInController');

    let controllerURI = urlParser.parse('https://iv5wtx5mb4.execute-api.us-west-2.amazonaws.com/api/v1/sessions');
    let controllerHeaders = { 
	    'Accept': 'application/json,/',
	    'Content-Type': 'application/json',
	    'User-Agent': 'nxt-portal',
	    'x-api-key': 'wBe1QeLMoZ7is2nE1ZECB7VidSRywGxDSvzQtJV5'
    };
    let options = {
        host: `${controllerURI.hostname}`,
        path: `${controllerURI.pathname}`,
        method: 'POST',
        headers: controllerHeaders
    };

    let req = https.request(options, (res) => {
	    var responseStr = '';

        console.log('NXT Portal response statusCode', res.statusCode);
        console.log('NXT Portal response headers\n', res.headers);

        if (res.statusCode === 200) {
            res.on('data', (data) => {
                responseStr += data;
            });

            res.on('end', () => {
                console.log('controller end, resp', responseStr);
                resolve(responseStr);
            });
        }
        else if (res.statusCode === 400) {
            var controllerData;
            if (agent) {
                controllerData = '{' +
                    '\"gateway_name\": \"gateway.ric.nextensio.net\",' +
                    '\"next_src_addr\": \"11.0.0.0\",' +
                    '\"usid\": \"361\",' +
                    '\"session_id\": \"0b2085152b9c49e8e74dd81eaea89a95\",' +
                    '\"services\": [],' +
                    '\"request_token\": \"nextensio\"' +
                '}';
            }
            else {
                controllerData = '{' +
                    '\"gateway_name\": \"gateway.ric.nextensio.net\",' +
                    '\"next_src_addr\": \"11.0.0.3\",' +
                    '\"usid\": \"362\",' +
                    '\"session_id\": \"ac63a34c4b9983230d3f1ef5cdd1e6e2\",' +
                    '\"services\": [ \"video.aaa.com:80\" ],' +
                    '\"request_token\": \"nextensio\"' +
                '}';
            }
            resolve(controllerData);
        }
        else {
            reject('nxt portal calls to nxt controller failed');
        }
    });

    console.log('NXT Portal request to create k8s sessions to controller\n', options);
    console.log('URIBody:', '[' + controllerURIBody + ']');
    
    req.write(controllerURIBody);
    req.end();
 
    req.on('error', (e) => {
	    console.log('controller error');
        console.error(e);
        reject(e);
    });
};



