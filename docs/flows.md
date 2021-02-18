# Flows in agents and connectors

A "flow" is a stanadard five tuple, a single flow has a seperate stream
to gateway and a seperate stream from gateway. And there are two goroutines
One for Rx and one for Tx. There obviously is only one bidirectional local
socket for the flow, that local socket is what talks to the application. So
there is one local socket and there are two gateway streams rx and tx.

The local socket to Gateway is calld appToGw in the code, and the gateway to
local socket is called gwToApp. Now if either direction closes any of the
sockets or apps, BOTH the directions have to close all the sockets and streams.
This is how we achieve it.

A. From appToGw direction, we set a CloseCascade saying that for whatever reason
   if gateway closes the stream (gwTx), then we should close the local socket also

B. We store informatoin regarding the gateway-rx (gwRx) stream such that its 
   available to the appToGw goroutine. So if the appToGw goroutine terminates,
   it will close the local socket, the gwTx socket AND the gwRx socket.

Now lets see the different termination cases

1. The local socket closes

   The appToGw is read-blocked on the local socket, so the goroutine will wake up
   and close the gwTx and the gwRx as explained before. Since gwRx is closed,
   the gwToApp goroutine wakes up and that also gets terminated

2. The gwTx stream closes

   Since we have set the close-cascade, a gwRx closure will also close the local-socket,
   and then step1 above happens

3. The gwRx stream closes

   This will wakeup the goroutine read-blocked on gwRx and it will close the
   local socket too, and then step1 above happens


Note that in the cluster also, if a stream on which we are read-blocked happens to close,
the goroutine will close the writer stream also. And we also set close-cascade such that
if the writer stream is closed, it closes the read-blocked stream and the goroutine 
unblocks and cleans up everythig.

So by this mechanism, we ensure that the close of a tcp socket is conveyed end to end,
from the application all the way to the connector opening socket to the final server.
Either application or the server end can terminate the socket and it will properly 
and immediately get conveyed to the other end
