package main

// Open two sessions:
// 1. An "underlay" session to rx/tx packets from the local system - it can be getting packets from
//    the applications on the phone via vpnService tunnel in android agent OR it can be getting
//    packets from the cloud via ethernet interface of a connector. The exact nature of ethernet Vs
//    vpnService etc.. is abstracted via the "Transport" interface in common/transport.go
//
// 2. A "overlay" session to rx/tx packets towards the nextensio clusters - it can also be different
//    kinds of transports like a DTLS tunnel or a TLS tunnel or IPSec etc.. The exact transport is again
//    abstracted using the "Transport" interface
//
// The main() function continuously monitors the overlay session for disconnects and reopens it if
// it gets disconnected
func main() {
}
