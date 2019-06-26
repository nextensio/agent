//
// Bind WS and TCP
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
const common = require('./nxt_common.js');
const clientSrcMap = require('./nxt_client_hash.js');

(function() {
  var bindSockets;

  module.exports = bindSockets = function(wsconn, tcpconn) {

    wsconn.__paused = false;

    // wsconn.on('message', function(message) {
    //   if (message.type === 'utf8') {
    //     return console.log('Error, Not supposed to received message ');
    //   } else if (message.type === 'binary') {
    //     if (false === tcpconn.write(message.binaryData)) {
    //       wsconn.socket.pause();
    //       wsconn.__paused = true;
    //       return "";
    //     } else {
    //       if (true === wsconn.__paused) {
    //         wsconn.socket.resume();
    //         return wsconn.__paused = false;
    //       }
    //     }
    //   }
    // });
    
    wsconn.on("overflow", function() {
      console.log('>>>>>>>>>>>>>>>>>>> ws overflow occur');
      return tcpconn.pause();
    });
    
    wsconn.on("drain", function() {
      console.log('>>>>>>>>>>>>>>>>>>> ws drain occurred');
      return tcpconn.resume();
    });
    
    wsconn.on("close", function(reasonCode, description) {
      console.log("[SYSTEM] --> WS Peer " + wsconn.remoteAddress + ' disconnected - Reason: '+description);
      // TODO: need to destroy all tcpconn handles!
      // return tcpconn.destroy();
    });
    
    tcpconn.on("drain", function() {
      console.log('>>>>>>>>>>>>>>>>>> tcp drain occurred');
      tcpconn.resume();
      return wsconn.__paused = false;
    });
    
    tcpconn.on("data", function(buffer) {
      let flow = common.getNxtFlowObject(tcpconn);
      if (typeof flow !== 'undefined') {
        // Got the flow, sent it out to tunnel.
        // console.log("tcpconn data, flow found, sent to ws tunnel");
        // Overwrite the method to 'PUT' - to indicate TCP data
        flow.method = 'TCP';
        // console.log('data: flow.dest =>', flow.dest);
        if (common.getArgs().new_multicluster) {
            common.sendNxtTunnel(wsconn, flow, buffer, true);
	      } else {
            common.sendNxtTunnelInChunks(wsconn, flow, buffer, true);
	      }
      }
      else {
        console.log('tcpconn data, flow not found. Drop!');
      }
    });
    
    // tcpconn.on("end", function(data){
    //    console.log('>>>>>>>>>>>>>>>>>> Socket ended from other end!');
    // });

    tcpconn.on("error", function(err) {
      console.log(err.stack);
      return console.log('tcp Error ' + err);
    });
    
    tcpconn.on("close", function() {
      console.log("[SYSTEM] --> TCP connection close.");
      // Delete from flow hashmap
      let flow = common.getNxtFlowObject(tcpconn);
      if (typeof flow !== 'undefined') {
        // Delete from flow hashmap
        common.deleteNxtFlowObject(tcpconn);
        // Delete from client Src Map
        let clientKey = clientSrcMap.createKey(flow.srcPort, flow.srcIp);
        clientSrcMap.delete(clientKey);
      }
    });
    
  };

}).call(this);
