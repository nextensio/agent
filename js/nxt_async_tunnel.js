//
// NXT Asynchronus Tunnel Implementation
//
// Date: July 7th, 2019
//
'use strict'

module.exports = AsyncTunnel;

var RingBuffer = require('ringbufferjs');

// *************HUGE TODO*************************
// The code here happily drops packets without consequences. But we cant drop tcp
// data because its already acked to the client. So if we have to drop tcp data,
// the only choice is to close the client tcp conn/socket and also let the cluster 
// know that this stream is closed

//
// NXT Ring Buffer Implementation
// Allowing the ring buffer to overwrite the oldest entries if overfllow occurs.
//
function AsyncTunnel(myWebsocket, myRingSize, myCheckerCB) {

    this.rb = new RingBuffer(myRingSize);
    this.canSendMore = myCheckerCB;
    this.websocket = myWebsocket;
}

//
// Drain the ring buffer.
// Note: it is the caller's responsibility to check if the Writeable is ready to take on more
//
AsyncTunnel.prototype.drain = function () {

    while (this.rb.isEmpty() !== true && this.canSendMore(this) === true) {
        data = this.rb.deq();
        // If the client/app corresponding to this chunk is closed/doesnt exist anymore,
        // then dont send the data to the nxt cluster any more. This javascript version
        // of the agent is not coded with the session/stream design pattern. In that pattern,
        // there is a left side stream and right side stream, both being connected, and if
        // either one is closed then the other one should cease sending data too. Also see
        // nxt_bind_socket.js and nxt_common.js calls to tcpconn.destroy()
        if (data.conn.destroyed == false) {
            this.websocket.send(data.chunk);
        }
    }
}

//
// Send out one data chunk
//
AsyncTunnel.prototype.send = function (clientconn, chunk) {

    //
    // Defensive check to ensure the ring buffer is not full
    //
    if (this.rb.isFull()) {
        console.log('[AsyncTunnel.send() failed, ring buffer is full, send failed');
        return false;
    }

    if (this.canSendMore(this)) {
        if (this.rb.isEmpty()) {
            this.websocket.send(chunk);
        } else {
            //
            // ring buffer is non-empty. send the quequed item first
            //
            this.rb.enq({ conn: clientconn, chunk: chunk });
            this.drain();
        }
    } else {
        this.rb.enq({ conn: clientconn, chunk: chunk });
    }
    //
    // Inform the caller the ring buffer usage
    //
    return (this.rb.isFull() === false);
}

//
// Returns the capacity of the ring buffer.
//
AsyncTunnel.prototype.capacity = function () {
    return this.rb.capacity();
};

//
// Returns whether the ring buffer is empty or not.
//
AsyncTunnel.prototype.isEmpty = function () {
    return this.rb.isEmpty();
};

//
// Returns whether the ring buffer is full or not.
//
AsyncTunnel.prototype.isFull = function () {
    return this.rb.isFull();
};

//
// Returns the size of the queue.
//
AsyncTunnel.prototype.size = function () {
    return this.rb.size();
};
