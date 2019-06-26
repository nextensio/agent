//
// NXT Common Code between Agent and Connector
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
const urlParser = require('url');
const WebSocket = require('ws');
const httpParser = require('http-string-parser');
const clientConMap = require('./nxt_client_hash.js');

const BUFFER_ENCODING_UNI = 'uni';
const BUFFER_ENCODING_HTTP = 'http';

const NXT_CONNECTOR_SERVICE = 'tom.com';
const NXTS_INGRESS_GW = 'wss://gateway.sjc.nextensio.net:443';
const NXTS_EGRESS_GW = 'wss://gateway.ric.nextensio.net:443';

const CHUNK_SIZE = 59392;
//const AGT_CHUNK_SIZE = 12288;
const AGT_CHUNK_SIZE = 10000;
var args;

var self = module.exports = {
  BUFFER_ENCODING_UNI,
  BUFFER_ENCODING_HTTP,
  NXT_CONNECTOR_SERVICE,
  NXTS_INGRESS_GW,
  NXTS_EGRESS_GW,
  AGT_CHUNK_SIZE,
  args,

  //
  // Export arguments
  //
  getArgs: function() {
     return args;
  },

  setArgs: function(argsN) {
     args = argsN;
  },

  printUsages: function() {
    console.log("Copyright (c) Nextensio 2019");
    console.log("NXT Agent and Connector usages -");
    console.log("");
    console.log("Local Agent and Connector ---------");
    console.log("Local           : npm run agent           , npm run con");
    console.log("SingleCluster   : npm run agents (tom.com), npm run cons (candy.com)");
    console.log("MultiCluster    : npm run agentm (tom.com), npm run conm (ric c362a)");
    console.log("DynamicCluster  : npm run agentd (dynamic), npm run cond (dynamic)");
    console.log("");
    console.log("Local Agent and Cloud Connector (AWS/GCP)");
    console.log("MultiCluster    : npm run agentm1 (tom.com)    , npm run conm (ric c362a)");
    console.log("MultiCluster2   : npm run agentn1 (sjc agent-1), npm run conn1 (ric connector-1 bunny.kismis.org)");
    console.log("New MultiCluster: npm run agentn  (sjc agent-1), npm run conn1 (ric connector-1 bunny.kismis.org), npm run conn2 (ric connector-5)");

    process.exit(0);
  },

  storeNxtFlowObject: function (key, flow) {
    return clientConMap.insert(key, flow);
  },

  getNxtFlowObject: function (key) {
    return clientConMap.get(key);
  },

  deleteNxtFlowObject: function (key) {
    return clientConMap.delete(key);
  },

  createNxtFlowObject: function (methodN, hostN, pathN, destN, connN, uuidN,
                                 srcPortN, srcIpN, sesId,
                                 codec) {
    return { 
      method: methodN, 
      host: hostN,
      path: pathN,
      dest: destN,
      con: connN,
      uuid: uuidN,
      srcPort: srcPortN,
      srcIp: srcIpN,
      sid: sesId,
      codec: codec
    };
  },

  getNxtFlowMsgType: function(reqHeaders) {
    return reqHeaders['x-nxts-msg'];
  },

  createNxtFlowObjectFromHeader: function (method, pathN, options) {
    return this.createNxtFlowObject(method, 
                          options['host'],
                          pathN, 
                          options['x-nextensio-for'],
                          options['x-nxts-con'],
                          options['x-nextensio-uuid'],
                          options['x-nxts-srcp'],
                          options['x-nxts-srcip'],
                          options['x-nextensio-sid'],
                          options['x-nxts-codec']);
  },

  createNxtHeader: function (method, hostN, pathN, destN, connN, uuidN,
                             srcPort, srcIp, sesId,
                             codec, len) {
    var lines;

    // NXT HEADER
    lines = 'GET' + ' ' + pathN + ' ' + 'HTTP/1.1' + '\r\n';
    lines += 'Host: ' + hostN + '\r\n';
    lines += 'x-nextensio-for:' + destN + '\r\n';
    lines += 'x-nextensio-uuid:' + uuidN + '\r\n';
    lines += 'x-nextensio-sid:' + sesId + '\r\n';
    lines += 'x-nxts-con:' + connN + '\r\n';
    lines += 'x-nxts-codec:' + codec + '\r\n';
    lines += 'x-nxts-srcp:' + `${srcPort}` + '\r\n';
    lines += 'x-nxts-srcip:' + srcIp + '\r\n';
    lines += 'x-nxts-msg:' + method + '\r\n';
    lines += 'content-length:' + `${len}` + '\r\n'; 
    lines += '\r\n';

    return lines;
  },

  parseMultipleWsPayload: function (message) {
    var packets = [];
    var emptyPacket = [];
    
    emptyPacket.push( { header: null, data: null } );
  
    if (message instanceof Buffer) {  
      var len = message.length;
      var index = 0;
      while (index < len) {
        let emptyLineIndex = message.indexOf('\r\n\r\n', index);
        let cl = (emptyLineIndex === -1) ? len : (len - emptyLineIndex - 4);
        // console.log('   COMM - emptyLineIndex: ' + emptyLineIndex + ' (LEN: ' + cl + ')');

        // received a packet without nxt headres
        if (emptyLineIndex == -1) {
          // packet with no NXT Headers, it could be tcp fragmented packets or just a hello string
          return emptyPacket; 
        }   

        // strip off NxtHeader
        let nxtHeader = message.slice(index, emptyLineIndex);

        // parse the header to get the content length
        let nxtHeaderObj = httpParser.parseRequest(nxtHeader.toString());  
        let contentLength = parseInt(nxtHeaderObj.headers['content-length']);
        let srcPort = nxtHeaderObj.headers['x-nxts-srcp'];
           
        // strip off Body
        let bodyStart = emptyLineIndex+4;
        let bodyEnd;
        let body;

        if (contentLength > len) {
          // In fragmented packets, content length is larger or equal to the length
          // in this case, the body slice should match the len
          bodyEnd = bodyStart + (len - bodyStart);
          body = message.slice(bodyStart, bodyEnd);
        } else {
          bodyEnd = bodyStart + contentLength;
          body = message.slice(bodyStart, bodyEnd);
        }
           
        packets.push( { header: nxtHeaderObj, data: body } );
           
        index += bodyEnd;
        console.log('   COMM - bS bE idx SP CL:', bodyStart, bodyEnd, index, srcPort, contentLength);
      }
    } else {
      console.log('   COMM - parseWsPayload is not type BUFFER');
      return emptyPacket;
    }
    return packets;
  },

  parseWsPayload: function (message) {
    //console.log('message instanceof buffer?', message instanceof Buffer);
    if (message instanceof Buffer) {
      let emptyLineIndex = message.indexOf('\n\r\n');

      // Received a packet without NXT Header! 
      if (emptyLineIndex === -1) {
        console.log('COMM - emptyLineIndex:', emptyLineIndex);
        return { header: "", data: "" };
      }

      // strip off NxtHeader
      let nxtHeader = message.slice(0, emptyLineIndex+2);

      // strip off Body
      let body = message.slice(emptyLineIndex+3);

      return { header: nxtHeader, data: body };
    }
    else {
      console.log('COMM - parseWsPayload is not type BUFFER');
      return { header: null, data: null };
    }
  },

  createWsSendPayload: function (flow, body, newline=true) {
    let bodyLen = body.length;
    let lines = [];
    lines[0] = Buffer.from(this.createNxtHeader(flow.method, 
                                            flow.host,
                                            flow.path,
                                            flow.dest,
                                            flow.con,
                                            flow.uuid,
                                            flow.srcPort,
                                            flow.srcIp, 
                                            flow.sid,
                                            flow.codec,
                                            bodyLen));
    lines[1] = Buffer.from(body);

    let payloadBuff = Buffer.concat(lines);
    if (newline == true) {
      console.log('');
    }
    console.log('WSS send SZ HD SP CL:', payloadBuff.length, lines[0].length, flow.srcPort, bodyLen);

    return payloadBuff;
  },

  createWsRecvPayload: function (headers, statusCode, statusMessage, bodyArray) {
    let lines = [];

    // client header
    lines.push(Buffer.from('HTTP/1.1' + ' ' + `${statusCode}` + ' ' + `${statusMessage}` + '\r\n'));
    Object.keys(headers).forEach(function(key) {
      let val = headers[key];
      lines.push(Buffer.from(`${key}` + ':' + ' ' + `${val}` + '\r\n'));
    });

    // client body
    if (bodyArray === undefined || bodyArray.length === 0) {
        // empty body!
        console.log('COMM - EmptyBody');
    } else {
      lines.push(Buffer.from('\r\n'));
      lines.push(Buffer.from(Buffer.concat(bodyArray)));
    }

    return Buffer.concat(lines);
  },

  sleep: function (ms) {
    var dt = new Date();
    dt.setTime(dt.getTime() + ms);
    while (new Date().getTime() < dt.getTime());
  },

  sendNxtTunnel: function (ws, flow, body, log, newline=true) {
    let payloadBuff = this.createWsSendPayload(flow, body, newline);
    // console.log('NXT common tunnel codec (' + flow.codec + ')');
    //if (log == true) {
      //console.log('\nSendToTunnel (SIZE: ' + payloadBuff.length + ')');
      //console.log('Flow', JSON.stringify(flow));
      //console.log(payloadBuff.toString('hex').match(/../g).join(' '));
      //console.log(JSON.stringify(payloadBuff.toString()));
      //console.log(payloadBuff);
    //}
    ws.send(payloadBuff);

    // this is done to avoid istio cloud of concatenating the packets!
    // need to handle this later.
    if (flow.codec === this.BUFFER_ENCODING_HTTP)
       this.sleep(25);
  },

  sendNxtTunnelInChunks: function (ws, flow, body, log) {
    let len = body.length;

    if (len <= CHUNK_SIZE) {
        this.sendNxtTunnel(ws, flow, body, log);
        return;
    }

    console.log('\nCOMM - chks start', len);

    let startChunk = 0;
    let endChunk = CHUNK_SIZE;

    do {
      this.sendNxtTunnel(ws, flow, body.slice(startChunk, endChunk), log, false);
      //console.log('COMM - cks', startChunk, endChunk-1, endChunk - startChunk);
      startChunk = endChunk;
      endChunk += CHUNK_SIZE;
    } while (endChunk < len);

    if (startChunk < len) {
      this.sendNxtTunnel(ws, flow, body.slice(startChunk), log, false);
      console.log('COMM - chks end', startChunk, len - startChunk);
    }
  },

  createWebSocket: function (uri, subp, extension) {
    return new WebSocket(uri, subp, extension);
  },

  //
  // Create NXT Tunnel Websocket
  //
  createNxtWsTunnel: function (ws, uri, subp, extension, cb) {
    if (!(ws !== undefined || ws !== null)) {
      console.log('WSS already created!');
      return ws;
    }

    console.log('WSS create ', uri, 
              JSON.stringify(extension.headers, true, 2));

    try {
      ws = this.createWebSocket(uri, subp, extension);

      ws.on('open', function() {
          console.log('WSS open ws communication to ' + uri);
      });
  
      ws.on('upgrade', function(res, socket, head) {
          //console.log('WSS upgrade event', JSON.stringify(res.headers, true, 2));
      });

      ws.on('message', function(buff) {
          console.log('\n>> WSS recv', buff.length);
          cb(ws, buff);
      });

      ws.on('close', function() {
          console.log('WSS close event received');
          ws = null;
          //
          // Create WebSocket Tunnel again!
          //
          setTimeout(() => {
              ws = self.createNxtWsTunnel(ws, uri, subp, extension, cb);
          }, 3000);
      });

      ws.on('error', function(err) {
          console.log('WSS error event received', err);
          console.error(err.stack);
      });
    } 
    catch (error) {
      console.log('WSS error in create ws!');
      console.error(error.stack);
      process.exit(1);
    }
    return ws;
  },

};
