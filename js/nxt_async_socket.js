//
// NXT Asynchronus Client Socket Implementation
//
// Date: June 15th, 2019
//
'use strict'

module.exports = AsyncSocket;

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
function AsyncSocket(mySocket, myRingSize) {
    this.rb = new RingBuffer(myRingSize);
    this.canSendMore = true;
    this.socket = mySocket;
}

//
// Drain the ring buffer.
// Note: it is the caller's responsibility to check if the Writeable is ready to take on more
//
AsyncSocket.prototype.drain = function () {
    var go = true;

    while (this.rb.isEmpty() !== true && go === true) {
        let chunk = this.rb.deq();
        go = this.socket.write(chunk);
    }

    this.canSendMore = go;
}

//
// Send out one data chunk
//
AsyncSocket.prototype.send = function (chunk) {

    //
    // Defensive check to ensure the ring buffer is not full
    //
    if (this.rb.isFull()) {
        return false;
    }

    if (this.canSendMore) {
        if (this.rb.isEmpty() === true) {
            // If this object is a socket
            this.canSendMore = this.socket.write(chunk);
        } else {
            //
            // ring buffer is non-empty. send the quequed item first
            //
            this.rb.enq(chunk);
            this.drain();
        }
    } else {
        this.rb.enq(chunk);
    }
    //
    // Inform the caller the ring buffer usage
    //
    return (this.rb.isFull() === false);
}

//
// Returns the capacity of the ring buffer.
//
AsyncSocket.prototype.capacity = function () {
    return this.rb.capacity();
};

//
// Returns whether the ring buffer is empty or not.
//
AsyncSocket.prototype.isEmpty = function () {
    return this.rb.isEmpty();
};

//
// Returns whether the ring buffer is full or not.
//
AsyncSocket.prototype.isFull = function () {
    return this.rb.isFull();
};

//
// Returns the size of the queue.
//
AsyncSocket.prototype.size = function () {
    return this.rb.size();
};


