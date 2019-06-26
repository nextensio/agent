## Description
* NXT app, portal, agent and connector code in nodejs

## NXT Agent/Connector respository installation
* NPM and NODEJS installation
  * PC: Download NODEJS from https://nodejs.org/en/download/
  * Cloud VM: Use Ubuntu apt-get utility to download latest version of nodejs
    * Pick Ubuntu 18.04 LTS for your Cloud VM
* NXTS JS code installation
```
$ git clone clone https://github.com/rzulkarn/nxts
$ ls -ld nxts
drwxr-xr-x  34 rzulkarn  staff  1088 Jun  9 07:33 nxts
$ cd nxts
$ npm install concurrently @okta/oidc-middleware dotenv express express-session http-proxy http-string-parser jsonwebtoken path ws request ejs minimist
```
* Certificates installation
  * Get AWS CodeCommit GIT credential: https://docs.aws.amazon.com/codecommit/latest/userguide/setting-up-gc.html
```
$ mkdir aws
$ ls -ld nxts aws
drwxr-xr-x   5 rzulkarn  staff   160 Jun  4 21:30 aws
drwxr-xr-x  34 rzulkarn  staff  1088 Jun  9 07:33 nxts
$ cd aws 
$ git clone https://git-codecommit.us-west-2.amazonaws.com/v1/repos/istio_client
```

## Running NXT portal, agent and connector 
* HELP:
  * npm run help : show the available commands to run
```
> npm run help

Copyright (c) Nextensio 2019
NXT Agent and Connector usages -

Local Agent and Local Connector ---------
Local           : npm run agent           , npm run con
SingleCluster   : npm run agents (tom.com), npm run cons (candy.com) -- namespace default
MultiCluster    : npm run agentm (tom.com), npm run conm (ric c362a) -- namespace default
DynamicCluster  : npm run agentd (dynamic), npm run cond (dynamic)

Local Agent and Cloud Connector (AWS/GCP)
MultiCluster    : npm run agentm1 (tom.com)    , npm run conm (ric c362a) -- namespace default
MultiCluster2   : npm run agentnp (sjc agent-1), npm run conn1 (ric connector-1 bunny.kismis.org) -- namespace blue
MultiCluster3   : npm run agentn1 (sjc agent-1), npm run conn1 (ric connector-1 bunny.kismis.org), npm run conn5 (ric connector-5) -- namespace blue
MultiCluster4   : npm run agentn2 (sjc agent-2), npm run conn2 (ric connector-2) -- namespace aaa
MultiCluster5   : npm run agentn3 (sjc agent-3), npm run conn3 (ric connector-3) -- namespace bbb
MultiCluster6   : npm run agentn6 (sjc agent-6), npm run conn6 (ric connector-6) -- namespace blue
```
* MultiCluster2 additional information (Okta Login)
  * Agent need to login via Okta before WSS tunnel is created
  * Start URL: `http://localhost:3000`
  * Okta Login: `mike.wilson@aaa.com / demo2019N`
  * .env file: Modify `NXT_PORTAL_URL` to point to the PUBLIC IP of the Compute VM
    * NXT agents and connectors sign in to the NXT service through 'nx_portal' http server.
    * The environmental variable NXT_PORTAL_URL tells NXT agents and connectors where to find 'nxt_portal'.
    * The default setting is to launch 'nxt_portal' server on http://localhost:8080.
    * To launch 'nxt_portal' on a different machine, change 'localhost' to the public IP of the server.
  * Firewall: create a firewall rule to `ALLOW HTTP TCP:8080`

* Local         : Agent and Connector run in your PC
* SingleCluster : Agent and Connector connect to a single k8s cluster
* MultiCluster  : Agent and Connector connect to two k8s clusters
* DynamicCluster: Agent and Connector connect to two k8s clusters, OKTA login required to create the k8s cluster pods

## NXT Proxy.pac setup
* Configure system proxy to Automatic Proxy Configuration Web (PAC)
  * NXT portal running in local PC: 'http://127.0.0.1:8080/proxy.pac'
  * NXT portal running in Cloud VM: 'http://<VM Public IP>:8080/proxy.pac'
  * Usage of file:// is deprecated in MacOS Chrome 
* New Website URL
  * Add URL entry into proxy.pac, restart your browser
  * NXT portal need to be running for browser to read the new proxy.pac

## Fine Tunning Parameters
* nxt_common.js
  * FRAGMENTATION 1: WSS Tunnel chunks    : CHUNK_SIZE
  * FRAGMENTATION 2: AGT TO Browser chunks: AGT_CHUNK_SIZE
* nxt_common.js and nxt_agent.js
  * WSS Tunnel sleep     : common.sleep(..)
  * AGT to Browser sleep : this.sleep(...)  

## Known Issues
* MaxListenerExceeded -- multiple socket binding exceeded 11 listeners. Not functionality impacting.

## Node.js Instances
* NXT-Agent : a http and proxy agent that listen on port 8081
* NXT-Portal : a http server that listen on port 8080
* NXT-Connector : a websocket server listen on port 8082
* NXT-APP : application listen to port 3000 or 4000

## Key+Cert generation
```
## ROOT CA ##
openssl req -new -x509 -days 999 -keyout ca-key.pem -out ca-crt.pem

## SERVER - Important: use COMMON NAME: localhost ##
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server-csr.pem
openssl x509 -req -days 999 -in server-csr.pem -CA ca-crt.pem -CAkey ca-key.pem -CAcreateserial -out server-crt.pem

## CLIENT - Important: use COMMON NAME: AGENT ##
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client-csr.pem
openssl x509 -req -days 999 -in client-csr.pem -CA ca-crt.pem -CAkey ca-key.pem -CAcreateserial -out client-crt.pem

## Verify Certificate ##
openssl verify -CAfile ca-crt.pem client-crt.pem
```
