//
// NXT App Rendering Application
//
require('dotenv').config();
const { ExpressOIDC } = require('@okta/oidc-middleware');

const express = require('express');
const request = require('request');
const minimist = require('minimist');
const session = require('express-session');

//
// Process arguments
//
let args = minimist(process.argv.slice(2), {
    boolean: [ 'agent', 'connector' ],
});

// App setup
const app = express();

var port;
var fileToRender;
var regURL;
var argRedirectURI;
var argAppBaseURI;

if (args.agent) {
    port = 3000;
    fileToRender = 'agent_index';
    argRedirectURI = `${process.env.HOST_URL}/authorization-code/callback`;
    argAppBaseURI = `${process.env.HOST_URL}`;
    regURL = 'http://localhost:8081/register';
}
else if (args.connector) {
    port = 4000;
    fileToRender = 'connector_index';
    argRedirectURI = `${process.env.CON_HOST_URL}/authorization-code/callback`;
    argAppBaseURI = `${process.env.CON_HOST_URL}`;
    regURL = 'http://localhost:8082/register';
}
else {
    console.log('Usage: node nxt_app.js [--agent | --connector]');
    process.exit(1);
}

const oidc = new ExpressOIDC({
    issuer: `${process.env.OKTA_ORG_URL}`,
    client_id: `${process.env.OKTA_CLIENT_ID}`,
    client_secret: `${process.env.OKTA_CLIENT_SECRET}`,
    redirect_uri: argRedirectURI,
    appBaseUrl: argAppBaseURI,
    scope: 'openid profile'
});

// Okta middleware integration
app.use(session({
    secret: process.env.APP_SECRET,
    resave: true,
    saveUninitialized: false
}));
app.use(oidc.router);

// setup ejs
app.set('view engine', 'ejs');

// Middleware: static files location
app.use('/', express.static('public'));

var server = app.listen(port, function() { 
    console.log('NXT App listening for requests on port ' + `${port}`);
});

// Handle Routes

app.use(function(error, req, res, next) {
    // Any request to this server will get here, and will send an HTTP
    // response with the error message 'woops'
    res.json({ message: error.message });
    console.log('error occur in middleware');
});

app.get('/', function(req, res) {
    // Let me in page
    res.render(fileToRender);
});

app.get('/register', oidc.ensureAuthenticated(), function(req, res) {
    console.log('NXT App login successful!');
    //console.log('request', JSON.stringify(req.headers));
    //console.log('statusCode', res.statusCode, res.statusMessage);

    var portal = registrationComplete(req);
    try {
        portal.then(function(result) {
            res.render('nxt_success');
            res.end();
        }, function(err) {
            res.render('nxt_failed');
            res.end();
        });
    }
    catch(error) {
        console.log('NXT App promise error:', error.message);
        console.err(error.stack);
        res.writeHead(400);
        res.end();
    }

});

function registrationComplete(req) {
    var options = {
        url: regURL,
        body: "",
        headers: {
            'User-Agent': 'nxt-app'
        }
    };

    const tokenSet = req.userContext.tokens;
    const userinfo = req.userContext.userinfo;

    console.log('NXT user-name:', userinfo['preferred_username']);
    console.log('NXT access_token:', tokenSet.access_token);
    console.log('NXT App allow tunnel creation for...', options);

    // Return new promise 
    return new Promise(function(resolve, reject) {
        // Do async job
        request.post(options, function(err, resp, body) {
            if (resp.statusCode === 200) {
                resolve('Registration OK');
            } 
            else {
                console.log('NXT App - registration failed');
                reject('Registration Failed', err);
            }
        });
    }); 
}