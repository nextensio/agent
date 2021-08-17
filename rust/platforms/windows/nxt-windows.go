/*
 * Nextensio.io - Windows Agent
 */

package main

/*
#include "nxt-api.h"
*/
import "C"
import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	winio "github.com/Microsoft/go-winio"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var nxtTokens *accessIdTokens

func runningElevated() bool {
	var process windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &process)
	if err != nil {
		return false
	}
	defer process.Close()
	return process.IsElevated()
}

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a net.IPNet) bool {
		// TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ip := addr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := addr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if includedInAddresses(ipnet) {
				fmt.Fprintf(os.Stderr, "Cleaning up stale address %s from interface %s\n", ipnet.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

// TODO: Add IPv6 tests.
var (
	nxtIPAddresToAdd = net.IPNet{
		IP:   net.IP{10, 82, 31, 5},
		Mask: net.IPMask{255, 255, 255, 0},
	}
	nxtRouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{0, 0, 0, 0},
			Mask: net.IPMask{0, 0, 0, 0},
		},
		NextHop: net.IP{10, 82, 31, 4},
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

func createPipe(name string) net.Listener {
	l, err := winio.ListenPipe(name, nil)
	if err != nil {
		return nil
	}
	return l
}

func pipeReader(l net.Conn) {
	var buf [2048]byte

	for {
		r, e := l.Read(buf[:])
		if e != nil {
			fmt.Println("Pipe Read error", e)
			return
		}
		fmt.Println("Pipe Read bytes ", r)
	}
}

func pipeListener() {
	p := createPipe(`\\.\pipe\nextensio`)

	for {
		l, err := p.Accept()
		if err != nil {
			fmt.Println("listen error", err)
		} else {
			go pipeReader(l)
		}
	}
}

func pipeWriter() net.Conn {
	p, e := winio.DialPipe(`\\.\pipe\nextensio`, nil)
	if e != nil {
		fmt.Println("Pipe write error", e)
		return nil
	}
	return p
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: .\nxt-windows.exec nxt0")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting nxt-windows version %s", "1.0.0")

	var t tun.Device
	err := elevate.DoAsSystem(func() error {
		var terr error
		t, terr = tun.CreateTUN(interfaceName, 0)
		return terr
	})
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	realInterfaceName, _ := t.Name()
	interfaceName = realInterfaceName

	defer t.Close()
	nativeTunDevice := t.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())

	logger.Verbosef("TunIf created %s, %d", realInterfaceName, luid)
	// logger.Verbosef("Adaptor %d", t.wt)

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

	device := device.NewDevice(t, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	logger.Verbosef("Device started")

	// errs := make(chan error)
	term := make(chan os.Signal, 1)

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, syscall.SIGTERM)

	//go pipeListener()
	//time.Sleep(time.Second)
	p := pipeWriter()
	go pipeReader(p)

	var buf [2048]byte
	for {
		r, e := t.Read(buf[:], 0)
		if e != nil {
			fmt.Println("Tunnel error", e)
			t.Close()
			break
		}
		fmt.Println("Read wintun bytes", r)
		n, e := p.Write(buf[:r])
		if e != nil || n != r {
			fmt.Println("Pipe write error", e)
		}
	}
	select {
	case <-term:
	// case <-errs:
	case <-device.Wait():
	}

	// clean up

	// uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
