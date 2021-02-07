package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"
import (
	"fmt"
	"log"
	"net"
	"nextensio/agent/agent"
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

func main() {}
