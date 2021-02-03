package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"
import "fmt"

type AndroidLogger struct {
	level C.int
}

func (l AndroidLogger) Write(p []byte) (int, error) {
	C.__android_log_write(l.level, C.CString("NxtGo/"), C.CString(string(p)))
	return len(p), nil
}

func init() {
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("NxtGo"), C.CString("Init Called"))
}

//export nxtOn
func nxtOn(tunFd int32) int {
	str := "NxtOn: " + fmt.Sprintf("%d", tunFd)
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("NxtGo"), C.CString(str))
	return 0
}

func main() {}
