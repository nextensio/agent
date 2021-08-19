/*
 * Nextensio.io - Windows Agent
 */

package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS:  -L . -lnextensio -lWs2_32 -ladvapi32 -luserenv -lcrypt32 -lsecurity -lncrypt -lntdll -static
#include "nxt-api.h"
*/
import "C"
import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	winio "github.com/Microsoft/go-winio"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var pipe net.Conn
var vpnTun tun.Device

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var nxtTokens *accessIdTokens

var (
	nxtIPAddresToAdd = net.IPNet{
		IP:   net.IP{100, 64, 1, 1},
		Mask: net.IPMask{255, 224, 0, 0},
	}
	nxtRouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{0, 0, 0, 0},
			Mask: net.IPMask{0, 0, 0, 0},
		},
		NextHop: net.IP{100, 64, 1, 2},
		Metric:  0,
	}
)

func idpVerify() *accessIdTokens {
	nxtTokens = authenticate("https://dev-635657.okta.com", "0oaz5lndczD0DSUeh4x6",
		"rudy@nextensio.net", "LetMeIn123")

	return nxtTokens
}

func pipeToVpn() {
	var buf [4096]byte

	for {
		r, e := pipe.Read(buf[:])
		if e != nil {
			log.Println("Pipe Read error", e)
			vpnTun.Close()
			return
		}
		log.Println("Pipe Read bytes ", r)
		w, e := vpnTun.Write(buf[0:r], 0)
		if e != nil || w != r {
			log.Println("vpn write failed ", e)
			vpnTun.Close()
			return
		}
	}
}

func vpnToPipe() {
	var buf [2048]byte
	for {
		r, e := vpnTun.Read(buf[:], 0)
		if e != nil {
			log.Println("vpn Read error", e)
			vpnTun.Close()
			break
		}
		log.Println("vpn Read bytes ", r)
		if pipe != nil {
			n, e := pipe.Write(buf[:r])
			if e != nil || n != r {
				log.Println("Pipe write error", e)
				vpnTun.Close()
				break
			}
		}
	}
}

func agentInit() {
	C.agent_init(2 /*windows*/, 1, 1500, 1500, 1)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: .\nxt-windows.exe nxt0")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting nxt-windows version %s", "1.0.0")

	watcher, err := watchInterface()
	if err != nil {
		log.Println("Watcher error ", err)
		return
	}

	err = elevate.DoAsSystem(func() error {
		var terr error
		vpnTun, terr = tun.CreateTUN(interfaceName, 0)
		return terr
	})
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	realInterfaceName, _ := vpnTun.Name()
	interfaceName = realInterfaceName

	defer vpnTun.Close()
	nativeTunDevice := vpnTun.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())

	logger.Verbosef("TunIf created %s, %d", realInterfaceName, luid)

	err = luid.SetIPAddresses([]net.IPNet{nxtIPAddresToAdd})
	if err != nil {
		logger.Errorf("Failed to create IP Addr: %v", err)
		os.Exit(ExitSetupFailed)
	}
	err = luid.SetRoutes([]*winipcfg.RouteData{&nxtRouteIPv4ToAdd})
	if err != nil {
		logger.Errorf("Failed to create RouteData: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(vpnTun, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	logger.Verbosef("Device started")

	term := make(chan os.Signal, 1)

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	// This will create the server part of the pipe
	go agentInit()

	// Once pipe server is created, we try to connect to it as client
	var e error
	for {
		pipe, e = winio.DialPipe(`\\.\pipe\nextensio`, nil)
		if e == nil {
			break
		}
		time.Sleep(time.Second)
	}
	logger.Verbosef("Pipe client created")

	watcher.Configure(luid)
	go monitorDefaultIP(windows.AF_INET)

	// There is no point sending traffic to agent till we have told it which
	// interface to send it out of, doing that might even cause a loop. So
	// wait till we figure out an interface to use
	for {
		if defaultIP == 0 {
			log.Println("Wait for default IP")
			time.Sleep(time.Second)
			continue
		}
		break
	}
	go pipeToVpn()
	go vpnToPipe()

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up
	watcher.Destroy()
	device.Close()

	logger.Verbosef("Shutting down")
}
