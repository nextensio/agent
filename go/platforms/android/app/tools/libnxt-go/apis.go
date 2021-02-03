package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"

type AndroidLogger struct {
	level         C.int
}

func (l AndroidLogger) Write(p []byte) (int, error) {
	C.__android_log_write(l.level, C.CString("Nextensio/Go/"), C.CString(string(p)))
	return len(p), nil
}

func init() {
	C.__android_log_write(C.ANDROID_LOG_ERROR, C.CString("Nextensio/Go/"), C.CString("Init Called"))
}

//export nxtOn
func nxtOn(tunFd int32) int {
    return 0
}

func main() {}
