package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"
import (
	"fmt"
	"log"
	"net"
	"nextensio/agent/agent"
	"syscall"
)

type AndroidLogger struct {
	level C.int
}

func (l AndroidLogger) Write(p []byte) (int, error) {
	C.__android_log_write(l.level, C.CString("NxtGo"), C.CString(string(p)))
	return len(p), nil
}

//export nxtInit
func nxtInit(direct int) {
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("NxtGo"), C.CString("NxtInit"))
	l := AndroidLogger{level: C.ANDROID_LOG_ERROR}
	lg := log.New(&l, "", 0)
	agent.AgentInit(lg, direct)
}

//export nxtOn
func nxtOn(tunFd int32) {
	str := "NxtOn: " + fmt.Sprintf("%d", tunFd)
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("NxtGo"), C.CString(str))
	iface := agent.Iface{Fd: int(tunFd), IP: net.ParseIP("169.254.2.1")}
	l := AndroidLogger{level: C.ANDROID_LOG_ERROR}
	lg := log.New(&l, "", 0)
	agent.AgentIface(lg, &iface)
}

//export nxtOff
func nxtOff(tunFd int32) {
	str := "NxtOff: " + fmt.Sprintf("%d", tunFd)
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("NxtGo"), C.CString(str))
	syscall.Close(int(tunFd))
}

// Debug statistics collection APIs below. Its a TODO to somehow make this one API call
// and return a java class with all these fields in one shot

//export nxtHeap
func nxtHeap() uint64 {
	stats := agent.GetStats()
	return stats.Alloc
}

//export nxtMallocs
func nxtMallocs() uint64 {
	stats := agent.GetStats()
	return stats.Mallocs
}

//export nxtFrees
func nxtFrees() uint64 {
	stats := agent.GetStats()
	return stats.Frees
}

//export nxtPaused
func nxtPaused() uint64 {
	stats := agent.GetStats()
	return stats.PauseTotalNs
}

//export nxtGoroutines
func nxtGoroutines() int {
	stats := agent.GetStats()
	return stats.NumGoroutine
}

//export nxtTunDisco
func nxtTunDisco() int {
	stats := agent.GetStats()
	return stats.TunnelDisconnects
}

//export nxtTunConn
func nxtTunConn() int {
	stats := agent.GetStats()
	return stats.TunnelConnected
}

//export nxtTunDiscoSecs
func nxtTunDiscoSecs() int {
	stats := agent.GetStats()
	return stats.TunnelDiscoSecs
}

func main() {}
