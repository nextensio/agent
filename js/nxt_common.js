//
// NXT Common Code between Agent and Connector
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
'use strict'

// ############################## HUGE TODO ####################################
// The concept of "streams" is all kind of hand crafted here, it should be nicely
// tucked and hidden away under some library that handles creation of streams and
// sessions like the golang version does. Its a TODO to make that happen

const WebSocket = require('ws');
const AsyncTunnel = require('./nxt_async_tunnel.js');
const NxtHdrs = require('./nxt_hdr_pb.js');

const CHUNK_SIZE = 65536 + (1 * 1024);
const WSS_BUFFER_THRESHOLD = (64 * 1024 * 1024); // WSS buffer threshold is set to 64MB
const WSS_RETRY_FREQ = 10;                   // WSS send retry every 10 mseconds
const TUNNEL_RING_BUFFER_SIZE = 8;
const SOCKET_RING_BUFFER_SIZE = 32;

var args;
var tcpToFlow = new Map();
var flowToTcp = new Map();
var flowToStream = new Map();
var streamToFlow = new Map();

function varint(number) {
    let pack = [];
    do {
        if (number > 127) {
            pack.push(0x80 | (number & 0x7f))
        } else {
            pack.push(number & 0x7F)
        }
        number = number >> 7
    } while (number > 0);

    return pack;
}

function varintDecode(pack) {
    let number = 0;
    let shift = 0;
    var v;
    for (v of pack) {
        number = number | ((v & 0x7f) << 7 * shift)
        shift = shift + 1
    }
    return number
}

function packOnboard(isAgent, registrationInfo, services) {
    var hdr = new NxtHdrs.NxtHdr()
    var onboard = new NxtHdrs.NxtOnboard()
    onboard.setAgent(isAgent)
    onboard.setUserid(registrationInfo.userid)
    onboard.setUuid(registrationInfo.userid)
    onboard.setAccesstoken(registrationInfo.accessToken)
    onboard.setServicesList(services)
    hdr.setOnboard(onboard)
    var bytes = hdr.serializeBinary();
    var pack = varint(bytes.length)
    for (let i = 0; i < bytes.length; i++) {
        pack.push(bytes[i])
    }

    return pack
}

var self = module.exports = {
    SOCKET_RING_BUFFER_SIZE,
    TUNNEL_RING_BUFFER_SIZE,
    args,

    //
    // Export arguments
    //
    getArgs: function () {
        return args;
    },

    setArgs: function (argsN) {
        args = argsN;
    },

    printUsages: function () {
        console.log("Copyright (c) Nextensio 2019");
        console.log("NXT Agent and Connector usages -");
        console.log("");

        process.exit(0);
    },

    storeNxtTcpToFlow: function (tcp, flow) {
        return tcpToFlow.set(tcp, flow);
    },

    getNxtTcpToFlow: function (tcp) {
        return tcpToFlow.get(tcp);
    },

    deleteNxtTcpToFlow: function (tcp) {
        return tcpToFlow.delete(tcp);
    },

    clearNxtTcpToFlow: function () {
        tcpToFlow.clear()
    },

    storeNxtFlowToTcp: function (flow, tcp) {
        var key = flow.originAgent + ":" + flow.srcIp + ":" + flow.srcPort
        flowToStream.set(key, flow)
        if (flow.rxStreamid != -1) {
            streamToFlow.set(flow.rxStreamid, flow)
        }
        if (flow.txStreamid != -1) {
            streamToFlow.set(flow.txStreamid, flow)
        }
        return flowToTcp.set(key, tcp);
    },

    getNxtFlowToTcp: function (flow) {
        var key = flow.originAgent + ":" + flow.srcIp + ":" + flow.srcPort
        return flowToTcp.get(key);
    },

    deleteNxtFlowToTcp: function (flow) {
        var key = flow.originAgent + ":" + flow.srcIp + ":" + flow.srcPort
        flowToStream.delete(key)
        if (flow.rxStreamid != -1) {
            streamToFlow.delete(flow.rxStreamid)
        }
        if (flow.txStreamid != -1) {
            streamToFlow.delete(flow.txStreamid)
        }
        return flowToTcp.delete(key);
    },

    clearNxtFlowToTcp: function () {
        flowToTcp.clear()
        streamToFlow.clear()
        flowToStream.clear()
    },

    // The sourceAgent and destAgent can get swapped on the connector, the originAgent
    // continues to identify the agent that originated the flow. 
    createNxtFlow: function (methodN, destURL, destPort, destAgentN, srcIpN, srcPortN, sourceAgentN, originAgent, rxStreamid, txStreamid) {
        return {
            method: methodN,
            dest: destURL,
            destPort: destPort,
            destAgent: destAgentN,
            srcIp: srcIpN,
            srcPort: srcPortN,
            sourceAgent: sourceAgentN,
            originAgent: originAgent,
            rxStreamid: rxStreamid,
            txStreamid: txStreamid,
        };
    },

    getNxtFlowMsgType: function (NxtFlow) {
        if (NxtFlow.getType() == NxtHdrs.NxtFlow.FLOW_TYPE.L4) {
            return "L4"
        } else {
            return "L3"
        }
    },


    createNxtFlowFromHeader: function (NxtFlow, streamid) {
        return this.createNxtFlow(
            this.getNxtFlowMsgType(NxtFlow),
            NxtFlow.getDest(),
            NxtFlow.getDport(),
            NxtFlow.getDestagent(),
            NxtFlow.getSource(),
            NxtFlow.getSport(),
            NxtFlow.getSourceagent(),
            NxtFlow.getOriginagent(),
            streamid,
            -1);
    },

    closeNxtHeader: function (streamid) {
        var hdr = new NxtHdrs.NxtHdr()
        hdr.setStreamid(streamid)
        hdr.setStreamop(NxtHdrs.NxtHdr.STREAM_OP.CLOSE)
        var bytes = hdr.serializeBinary();
        var pack = varint(bytes.length)
        for (let i = 0; i < bytes.length; i++) {
            pack.push(bytes[i])
        }

        return pack;
    },

    createNxtHeader: function (method, dest, destPort, destAgent, srcIp, srcPort, sourceAgent, originAgent, streamid) {
        var hdr = new NxtHdrs.NxtHdr()
        var flow = new NxtHdrs.NxtFlow()
        flow.setSource(srcIp)
        flow.setSport(srcPort)
        // Only tcp at the moment
        flow.setProto(6)
        flow.setSourceagent(sourceAgent)
        flow.setDest(dest)
        flow.setDport(destPort)
        flow.setDestagent(destAgent)
        flow.setOriginagent(originAgent)
        if (method == 'L4') {
            flow.setType(NxtHdrs.NxtFlow.FLOW_TYPE.L4)
        } else {
            flow.setType(NxtHdrs.NxtFlow.FLOW_TYPE.L3)
        }
        hdr.setStreamid(streamid)
        hdr.setFlow(flow)
        var bytes = hdr.serializeBinary();
        var pack = varint(bytes.length)
        for (let i = 0; i < bytes.length; i++) {
            pack.push(bytes[i])
        }

        return pack;
    },

    parseWsPayload: function (nxtAsyncTunnel, message) {
        var index = 0;
        var packlen = [];
        // Parse the length of the nextensio headers
        while (index < message.length) {
            var v = message.readUInt8(index);
            packlen.push(v)
            index += 1
            if ((v & 0x80) == 0) {
                break
            }
        }
        var hdrlen = varintDecode(packlen)
        // Decode nextensio headers
        var hdr = NxtHdrs.NxtHdr.deserializeBinary(message.slice(index, index + hdrlen))
        var op = hdr.getStreamop()
        if (op == NxtHdrs.NxtHdr.STREAM_OP.NOOP) {
            var flow = hdr.getFlow()
            // Ignore anything other than a flow message (like onboarding)
            if (flow != null) {
                var f = this.createNxtFlowFromHeader(flow, hdr.getStreamid())
                var key = f.originAgent + ":" + f.srcIp + ":" + f.srcPort
                var s = flowToStream.get(key)
                if (typeof s !== 'undefined') {
                    s.rxStreamid = hdr.getStreamid()
                    streamToFlow.set(s.rxStreamid, s)
                }
                return [message.slice(index + hdrlen, message.length), f, this.getNxtFlowMsgType(flow)];
            }
        } else if (op == NxtHdrs.NxtHdr.STREAM_OP.CLOSE) {
            var s = streamToFlow.get(hdr.getStreamid())
            if (typeof s !== 'undefined') {
                var tcpconn = this.getNxtFlowToTcp(s)
                // This will ensure any queued up pkts from this session wont get sent after
                // this point. Also see comments in nxt_async_tunnel.js tcpconn.destroy()
                if (typeof tcpconn !== 'undefined') {
                    tcpconn.socket.destroy()
                    this.streamClose(nxtAsyncTunnel, s)
                    this.deleteNxtTcpToFlow(tcpconn);
                }
                this.deleteNxtFlowToTcp(s);
            }
            return null
        }

        return null;
    },

    streamClose: function (nxtAsyncTunnel, flow) {
        var key = flow.originAgent + ":" + flow.srcIp + ":" + flow.srcPort
        var s = flowToStream.get(key)
        if (typeof s === 'undefined') {
            return
        }
        try {
            if (s.rxStreamid != -1) {
                nxtAsyncTunnel.websocket.send(Buffer.from(this.closeNxtHeader(s.rxStreamid)));
            }
            if (s.txStreamid != -1) {
                nxtAsyncTunnel.websocket.send(Buffer.from(this.closeNxtHeader(s.txStreamid)));
            }
        } catch (error) {
            console.error(error);
        }
    },

    createWsSendPayload: function (flow, body) {
        let lines = [];
        lines[0] = Buffer.from(this.createNxtHeader(flow.method,
            flow.dest,
            flow.destPort,
            flow.destAgent,
            flow.srcIp,
            flow.srcPort,
            flow.sourceAgent,
            flow.originAgent,
            flow.txStreamid));
        lines[1] = Buffer.from(body);

        return Buffer.concat(lines);
    },

    sleep: function (ms) {
        var dt = new Date();
        dt.setTime(dt.getTime() + ms);
        while (new Date().getTime() < dt.getTime());
    },

    //
    // This function checks if Tunnel interface has exceeded the high water mark
    //
    checkNxtTunnelHighWaterMark: function (nxtAsyncTunnel) {
        return (nxtAsyncTunnel.websocket.bufferedAmount < WSS_BUFFER_THRESHOLD);
    },

    //
    // This function periodically drains the items that are buffered in the ring buffer. 
    //
    drainNxtTunnel: function (nxtAsyncTunnel) {
        nxtAsyncTunnel.drain();
        setTimeout(() => { this.drainNxtTunnel(nxtAsyncTunnel); }, WSS_RETRY_FREQ);
    },

    //
    // The wrapper function to send message frames over NXT tunnel
    // If the message size is larger than CHUNK_SIZE, chop the message into smaller frames
    //
    // NOTE:
    // (1) It is not guaranteed that an oversized message can always fit into the ring buffer,
    //     i.e., the ring buffer may wrap around. When ring overflow happens, tail drop is adopted.
    //     The caller should set the CHUNK_SIZE and ring buffer size carefully.
    // (2) A CHUNK_SIZE value that is too small can impact the throughput performance and risk the
    //     ring buffer overflow. The caller is advised to choose a larger CHUNK_SIZE
    //
    sendNxtTunnelInChunks: function (clientconn, nxtAsyncTunnel, flow, body, log) {
        let len = body.length;
        let payloadBuff;

        if (len <= CHUNK_SIZE) {
            payloadBuff = this.createWsSendPayload(flow, body);
            try {
                nxtAsyncTunnel.send(clientconn, payloadBuff);
            } catch (error) {
                console.error(error);
            }
            return;
        }

        let startChunk = 0;
        let endChunk = CHUNK_SIZE;

        try {
            do {
                payloadBuff = this.createWsSendPayload(flow, body.slice(startChunk, endChunk), log);
                nxtAsyncTunnel.send(clientconn, payloadBuff);
                startChunk = endChunk;
                endChunk += CHUNK_SIZE;
            } while (endChunk < len);

            payloadBuff = this.createWsSendPayload(flow, body.slice(startChunk), log);
            nxtAsyncTunnel.send(clientconn, payloadBuff);
        } catch (error) {
            console.error(error);
        }
    },

    //
    // Create NXT Tunnel Websocket
    //
    createNxtWsTunnel: function (uri, subp, extension, cb, registrationInfo, isAgent, services) {
        let ws;
        let tunnel;

        console.log('WSS create ', uri, JSON.stringify(extension.headers, true, 2));

        try {
            ws = new WebSocket(uri, subp, extension);

            tunnel = new AsyncTunnel(ws,
                TUNNEL_RING_BUFFER_SIZE,
                this.checkNxtTunnelHighWaterMark);
            ws.on('open', function () {
                var pack = packOnboard(isAgent, registrationInfo, services)
                ws.send(pack)
                self.drainNxtTunnel(tunnel);
                console.log('WSS open ws communication to ' + uri);
            });

            ws.on('message', function (buff) {
                cb(tunnel, buff);
            });

            ws.on('close', function () {
                // The periodic timer will watch for the socket state and reopen it
            });

            ws.on('error', function (err) {
                console.log('WSS error event received', err);
                console.error(err.stack);
            });
        }
        catch (error) {
            console.log('WSS error in create ws!');
            console.error(error.stack);
            process.exit(1);
        }
        return tunnel;
    },
};
