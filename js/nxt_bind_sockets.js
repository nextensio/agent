//
// Bind WS and TCP
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
'use strict'

const common = require('./nxt_common.js');

(function () {
    var bindSockets;

    module.exports = bindSockets = function (nxtAsyncTunnel, clientAsyncSocket) {

        var tcpconn = clientAsyncSocket.socket;

        tcpconn.on("drain", function () {
            console.log('>>>>> tcp drain occurred');
            clientAsyncSocket.drain();
        });

        tcpconn.on("data", function (buffer) {
            let flow = common.getNxtTcpToFlow(tcpconn);

            if (typeof flow !== 'undefined') {
                console.log('tcp data fow', flow)
                // Got the flow, sent it out to tunnel.
                // Overwrite the method (which might be CONNECT at the moment) to indicate TCP data
                flow.method = 'TCP';
                common.sendNxtTunnelInChunks(tcpconn, nxtAsyncTunnel, flow, buffer, true);
            } else {
                console.log('tcpconn data, flow not found. Drop!');
            }
        });

        tcpconn.on("error", function (err) {
            console.log(err.stack);
            return console.log('tcp Error ' + err);
        });

        tcpconn.on("end", function () {
            //
            // socket.peerAddress property is defined at connect event
            //
            // 
            // Received TCP FIN packet from remote socket.
            // Delete from flow hashmap
            // Note: By default (allowHalfOpen is false) the socket will send a FIN packet back and destroy its file 
            //       descriptor once it has written out its pending write queue.
            //       However, if allowHalfOpen is set to true, the socket will not automatically end() its writable side,
            //       allowing the user to write arbitrary amounts of data.
            //       The user must call end() explicitly to close the connection (i.e. sending a FIN packet back).
            //
            let flow = common.getNxtTcpToFlow(tcpconn);
            if (typeof flow !== 'undefined') {
                // Tell the cluster end that this stream has terminated. We dont want
                // any more packets from this session to be sent to the other end once
                // the stream is closed because in some cases like our own hand crafted
                // websocket streams (common gitlab repo transport/websocket), we dont really
                // track closed streams in any fin-wait state etc.., we just keep it simple
                // and expect the sender not to send more pkts on a closed stream.
                tcpconn.destroy()
                common.streamClose(nxtAsyncTunnel, flow)
                common.deleteNxtFlowToTcp(flow);
                common.deleteNxtTcpToFlow(tcpconn);
            }
        });

        tcpconn.on("close", function () {
            //
            // socket.peerAddress property is defined at connect event
            //
            delete tcpconn.peerAddress;

            // Delete from flow hashmap
            let flow = common.getNxtTcpToFlow(tcpconn);
            if (typeof flow !== 'undefined') {
                // Tell the cluster end that this stream has terminated. We dont want
                // any more packets from this session to be sent to the other end once
                // the stream is closed because in some cases like our own hand crafted
                // websocket streams (common gitlab repo transport/websocket), we dont really
                // track closed streams in any fin-wait state etc.., we just keep it simple
                // and expect the sender not to send more pkts on a closed stream.
                tcpconn.destroy()
                common.streamClose(nxtAsyncTunnel, flow)
                common.deleteNxtFlowToTcp(flow);
                common.deleteNxtTcpToFlow(tcpconn);
            }
            //
            // The socket 'close' event can be caused by normal exit or error conditions
            // Destroying the ocket connection forcefully without receiving the FIN packet
            //
            this.destroy();
        });

    };

}).call(this);

