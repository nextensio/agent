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
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	websock "gitlab.com/nextensio/common/go/transport/websocket"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var fromAgent net.PacketConn
var toAgent net.Addr
var vpnTun *tun.Device
var agentHandshake bool
var logger *device.Logger
var writeLock sync.Mutex
var lg *log.Logger
var onboarded bool
var uniqueId string
var controller string
var regInfo RegistrationInfo
var regInfoLock sync.RWMutex
var unique uuid.UUID
var username string
var password string
var idp string
var clientid string

const MTU = 1500

// TODO: This can be a problem if someone else is using this port already,
// we should ideally be able to use "any" port, ie start the websocket server
// on a port of choice of the OS (we should be able to give a 127.0.0.0:0 as the address)
// and then figure out what port OS allocated, and pass that to agent_init()
const PKTTCPPORT = 8282

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

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

func agentToVpn(tcpTun *common.Transport) {
	handshaked := false
	for {
		_, bufs, e := (*tcpTun).Read()
		if e != nil {
			logger.Verbosef("Pipe Read error %s", e)
			(*vpnTun).Close()
			return
		}
		if !handshaked {
			logger.Verbosef("Got handshake %s", string(bufs[0]))
			handshaked = true
		} else {
			writeLock.Lock()
			w, err := (*vpnTun).Write(bufs[0], 0)
			writeLock.Unlock()
			if err != nil || w != len(bufs[0]) {
				logger.Verbosef("vpn write failed error %s, w %d, r %d", e, w, len(bufs[0]))
				(*vpnTun).Close()
				return
			}
		}
	}
}

// Respond to icmp requests to ourselves, a quick and easy test
// to see if the wintun layer is working fine
func handleICMP(buf []byte) bool {
	packet := gopacket.NewPacket(buf[0:], layers.LayerTypeIPv4, gopacket.Default)
	if packet == nil {
		return false
	}
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	if iplayer == nil {
		return false
	}
	ip, _ := iplayer.(*layers.IPv4)
	self := ip.DstIP.To4()
	if self[0] != 100 || self[1] != 64 || self[2] != 1 || self[3] != 2 {
		return false
	}
	// swap src, dst
	src := ip.SrcIP
	dst := ip.DstIP
	ip.SrcIP = dst
	ip.DstIP = src
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return false
	}
	icmp, _ := icmpLayer.(*layers.ICMPv4)
	icmp.TypeCode = layers.ICMPv4TypeEchoReply

	// now send response
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	newBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(newBuffer, options, packet)
	if err != nil {
		return false
	}

	writeLock.Lock()
	(*vpnTun).Write(newBuffer.Bytes(), 0)
	writeLock.Unlock()

	return true
}

func vpnToAgent(tcpTun *common.Transport) {
	for {
		buf := make([]byte, MTU)
		r, e := (*vpnTun).Read(buf[0:MTU], 0)
		if e != nil {
			logger.Verbosef("vpn Read error %s", e)
			(*vpnTun).Close()
			return
		}
		if handleICMP(buf[0:r]) {
			continue
		}
		hdr := &nxthdr.NxtHdr{}
		flow := nxthdr.NxtFlow{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
		err := (*tcpTun).Write(hdr, net.Buffers{buf[0:r]})
		if err != nil {
			logger.Verbosef("Pipe write error %s,  r %d", e, r)
			(*vpnTun).Close()
			return
		}
	}
}

func agentInit(port int) {
	C.agent_init(2 /*windows*/, 1, MTU, 1, C.uint32_t(port))
}

func agentConnection(tchan chan common.NxtStream) {
	for {
		select {
		case client := <-tchan:
			logger.Verbosef("Got connection from agent")
			go agentToVpn(&client.Stream)
			go vpnToAgent(&client.Stream)
		}
	}
}

func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Nextensio Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Nextensio Password: ")
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func monitorController(lg *log.Logger) {
	var keepalive uint = 30
	force_onboard := false
	var tokens *accessIdTokens

	for {
		tokens = authenticate(idp, clientid, username, password)
		if tokens != nil {
			break
		}
		lg.Println("Unable to authenticate connector with the IDP")
		time.Sleep(10 * time.Second)
	}
	refresh := time.Now()
	last_keepalive := time.Now()
	for {
		if onboarded {
			if uint(time.Since(last_keepalive).Seconds()) >= keepalive {
				force_onboard = ControllerKeepalive(lg, controller, tokens.AccessToken, regInfo.Version, uniqueId)
				last_keepalive = time.Now()
			}
		}
		// Okta is configured with one hour as the access token lifetime,
		// refresh at 45 minutes
		if time.Since(refresh).Minutes() >= 45 {
			tokens = refreshTokens(idp, clientid, tokens.Refresh)
			if tokens != nil {
				refresh = time.Now()
				// Send the new tokens to the gateway
				force_onboard = true
			} else {
				lg.Println("Token refresh failed, will try again in 30 seconds")
			}
		}
		if !onboarded || force_onboard {
			if ControllerOnboard(lg, controller, tokens.AccessToken) {
				onboarded = true
				force_onboard = false
				if regInfo.Keepalive == 0 {
					keepalive = 5 * 60
				} else {
					keepalive = regInfo.Keepalive
				}
			}
		}
		time.Sleep(30 * time.Second)
	}
}

func args() {
	flag.Parse()
	idp = "https://dev-24743301.okta.com"
	clientid = "0oav0q3hn65I4Zkmr5d6"
	controller = "server.nextensio.net:8080"
	username, password = credentials()
}

func initOnboard() {
	common.MAXBUF = (64 * 1024)
	unique = uuid.New()
	args()
	uniqueId = unique.String()
	go monitorController(lg)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: .\nxt-windows.exe nxt0")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]
	lg = log.New(os.Stdout, "Nextensio\n", 0)
	initOnboard()

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

	logger.Verbosef("Starting tunnel", tun.WintunPool)
	err = elevate.DoAsSystem(func() error {
		t, terr := tun.CreateTUN(interfaceName, MTU)
		vpnTun = &t
		return terr
	})
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	realInterfaceName, _ := (*vpnTun).Name()
	interfaceName = realInterfaceName

	defer (*vpnTun).Close()
	nativeTunDevice := (*vpnTun).(*tun.NativeTun)
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
	/* Windows has a "smart dns" resolver, if you google for it there is plenty
	 * of details. Basically windows will send a dns request out of every interface
	 * that advertises a dns server - it will send it out "directly" on that interface
	 * bypassing all vpns (by binding to that interface). And whichever interface will
	 * respond first will be the dns answer taken. So we dont really need to advertise
	 * any public dns servers, that will be resolved via the ethernet/wi-fi interface.
	 * But if someone turns OFF smart dns, then we are in trouble because then windows
	 * will try to resolve dns servers of the interface with the lowest metric - now
	 * what if the lowest metric interface doesnt advertise dns (like us), will windows
	 * fall back to the next higher metric interface ? I hope so, not sure.
	err = luid.SetDNS(windows.AF_INET, dnsesToSet, nil)
	if err != nil {
		logger.Errorf("Failed to create DNS: %v", err)
		os.Exit(ExitSetupFailed)
	}
	*/

	iface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		logger.Errorf("Failed to get iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}
	iface.NLMTU = MTU
	err = iface.Set()
	if err != nil {
		logger.Errorf("Failed to set iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}

	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		logger.Errorf("Failed to get iface for metric: %v", err)
		os.Exit(ExitSetupFailed)
	}
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	err = ipif.Set()
	if err != nil {
		logger.Errorf("Failed to set iface for metric: %v", err)
		os.Exit(ExitSetupFailed)
	}
	firewall.EnableFirewall(uint64(luid), true, nil)
	logger.Verbosef("Device started")

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	pktserver := websock.NewListener(context.TODO(), lg, nil, nil, PKTTCPPORT, 0, 0)
	tchan := make(chan common.NxtStream)
	go pktserver.Listen(tchan)
	go agentConnection(tchan)

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

	agentInit(PKTTCPPORT)
	logger.Verbosef("Agent started")

	select {
	case <-term:
	}

	// clean up
	watcher.Destroy()

	logger.Verbosef("Shutting down")
}
