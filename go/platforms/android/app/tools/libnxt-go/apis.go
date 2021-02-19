package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// struct goStats {
//      long long    heap;
//      long long    mallocs;
//      long long    frees;
//      long long    paused;
//      int         gc;
//      int         goroutines;
//      int         conn;
//      int         disco;
//      int         discoSecs;
//      int         numflows;
//      int         directflows;
// };
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

//export nxtStats
func nxtStats(s *C.struct_goStats) {
	stats := agent.GetStats()
	s.heap = C.longlong(stats.Alloc)
	s.mallocs = C.longlong(stats.Mallocs)
	s.frees = C.longlong(stats.Frees)
	s.paused = C.longlong(stats.PauseTotalNs)
	s.gc = C.int(stats.NumGC)
	s.goroutines = C.int(stats.NumGoroutine)
	s.conn = C.int(stats.TunnelConnected)
	s.disco = C.int(stats.TunnelDisconnects)
	s.discoSecs = C.int(stats.TunnelDiscoSecs)
    s.numflows = C.int(stats.NumFlows)
    s.directflows = C.int(stats.DirectFlows)
}

func main() {}
