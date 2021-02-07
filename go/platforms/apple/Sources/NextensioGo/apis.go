package main

// #include <stdlib.h>
// #include <sys/types.h>
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
	lg := log.New(&l, "", 0)
	agent.AgentIface(lg, &iface)
}

//export nxtLogger
func nxtLogger(context, loggerFn uintptr) {
    loggerCtx = unsafe.Pointer(context)
    loggerFunc = unsafe.Pointer(loggerFn)
}

func main() {}
