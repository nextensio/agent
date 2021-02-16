package main

// #include <stdlib.h>
// #include <sys/types.h>
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
// };
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
//  ((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"
import (
    "errors"
	"fmt"
	"log"
	"net"
    "unsafe"
    "syscall"
	"nextensio/agent/agent"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger struct {
    level C.int
}

func (l *CLogger) Write(p []byte) (int, error) {
    if uintptr(loggerFunc) == 0 {
        return 0, errors.New("logger not initialized")
    }
    message := C.CString(string(p))
    C.callLogger(loggerFunc, loggerCtx, l.level, message)
    C.free(unsafe.Pointer(message))
    return len(p), nil
}

//export nxtInit
func nxtInit(direct int) {
	l := CLogger{level: 0}
	lg := log.New(&l, "", 0)
	agent.AgentInit(lg, direct)
}

//export nxtOn
func nxtOn(tunFd int32) {
	str := "NxtOn: " + fmt.Sprintf("%d", tunFd)
	iface := agent.Iface{Fd: int(tunFd), IP: net.ParseIP("169.254.2.1")}
	l := CLogger{level: 0}
        l.Write([]byte(str))
	lg := log.New(&l, "", 0)
	agent.AgentIface(lg, &iface)
}

//export nxtLogger
func nxtLogger(context, loggerFn uintptr) {
    loggerCtx = unsafe.Pointer(context)
    loggerFunc = unsafe.Pointer(loggerFn)
}

//export nxtOff
func nxtOff(tunFd int32) {
    str := "NxtOff: " + fmt.Sprintf("%d", tunFd)
    l := CLogger{level: 0}
    l.Write([]byte(str))
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
}

func main() {}
