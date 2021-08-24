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
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var fromAgent net.PacketConn
var toAgent net.Addr
var vpnTun tun.Device
var agentHandshake bool
var logger *device.Logger

const RXMTU = 1500
const TXMTU = 1500

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var nxtTokens *accessIdTokens

// Use a CGNAT address that doesnt clash with anything else
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
	dnsesToSet = []net.IP{
		net.IPv4(8, 8, 8, 8),
		net.IPv4(8, 8, 4, 4),
	}
)

func idpVerify() *accessIdTokens {
	nxtTokens = authenticate("https://dev-635657.okta.com", "0oaz5lndczD0DSUeh4x6",
		"rudy@nextensio.net", "LetMeIn123")

	return nxtTokens
}

func agentToVpn() {
	var buf [TXMTU]byte

	for {
		r, a, e := fromAgent.ReadFrom(buf[:])
		if e != nil {
			logger.Verbosef("Pipe Read error %s", e)
			vpnTun.Close()
			return
		}
		// Agent sends a dummy handshake message as the first packet
		if !agentHandshake {
			logger.Verbosef("Got handshake size %d, from %s, message %s", r, a, string(buf[:r]))
			toAgent = a
			agentHandshake = true
			continue
		}
		w, e := vpnTun.Write(buf[0:r], 0)
		if e != nil || w != r {
			logger.Verbosef("vpn write failed error %s, w %d, r %d", e, w, r)
			vpnTun.Close()
			return
		}
	}
}

func vpnToAgent() {
	var buf [RXMTU]byte
	for {
		r, e := vpnTun.Read(buf[:], 0)
		if e != nil {
			logger.Verbosef("vpn Read error %s", e)
			vpnTun.Close()
			break
		}
		if agentHandshake {
			n, e := fromAgent.WriteTo(buf[:r], toAgent)
			if e != nil || n != r {
				logger.Verbosef("Pipe write error %s, n %d, r %d", e, n, r)
				vpnTun.Close()
				break
			}
		}
	}
}

func agentInit(port int) {
	C.agent_init(2 /*windows*/, 1, RXMTU, TXMTU, 1, C.uint32_t(port))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: .\nxt-windows.exe nxt0")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	logger = device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting nxt-windows version %s", "1.0.0")

	watcher, err := watchInterface()
	if err != nil {
		logger.Verbosef("Watcher error %s", err)
		return
	}

	err = elevate.DoAsSystem(func() error {
		var terr error
		vpnTun, terr = tun.CreateTUN(interfaceName, TXMTU)
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
	err = luid.SetDNS(windows.AF_INET, dnsesToSet, nil)
	if err != nil {
		logger.Errorf("Failed to create DNS: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(vpnTun, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	iface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		logger.Errorf("Failed to get iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}
	iface.NLMTU = TXMTU
	err = iface.Set()
	if err != nil {
		logger.Errorf("Failed to set iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}

	firewall.EnableFirewall(uint64(luid), true, nil)
	logger.Verbosef("Device started")

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	fromAgent, err = net.ListenPacket("udp", ":0")
	if err != nil {
		panic(err)
	}
	udpServer := fromAgent.LocalAddr().(*net.UDPAddr).Port

	logger.Verbosef("UDP server at %u", udpServer)
	// This will create the server part of the pipe
	go agentInit(udpServer)

	watcher.Configure(luid)
	go monitorDefaultIP(windows.AF_INET)

	// There is no point sending traffic to agent till we have told it which
	// interface to send it out of, doing that might even cause a loop. So
	// wait till we figure out an interface to use
	for {
		if defaultIP == 0 {
			logger.Verbosef("Wait for default IP")
			time.Sleep(time.Second)
			continue
		}
		break
	}
	go agentToVpn()
	go vpnToAgent()

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up
	watcher.Destroy()
	device.Close()

	logger.Verbosef("Shutting down")
}
