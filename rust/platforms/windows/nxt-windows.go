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
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/windows"

	fyne "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
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
var luid *winipcfg.LUID
var loginStatus *widget.Button
var watcher *interfaceWatcher
var myApp fyne.App
var pool common.NxtPool

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

// Use a CGNAT address that doesnt clash with anything else.
// See comments against vpnRoutes() for more details on all the circus done here
var (
	nxtIPAddresToAdd = net.IPNet{
		IP:   net.IP{100, 64, 1, 1},
		Mask: net.IPMask{255, 192, 0, 0},
	}
	nxtSpecificRouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{100, 64, 0, 0},
			Mask: net.IPMask{255, 192, 0, 0},
		},
		NextHop: net.IP{100, 64, 1, 2},
		Metric:  0,
	}
	nxtDefaultRouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{0, 0, 0, 0},
			Mask: net.IPMask{0, 0, 0, 0},
		},
		NextHop: net.IP{100, 64, 1, 2},
		Metric:  0,
	}
	nxtDNS1RouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{8, 8, 8, 8},
			Mask: net.IPMask{255, 255, 255, 255},
		},
		NextHop: net.IP{100, 64, 1, 2},
		Metric:  0,
	}
	nxtDNS2RouteIPv4ToAdd = winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   net.IP{8, 8, 4, 4},
			Mask: net.IPMask{255, 255, 255, 255},
		},
		NextHop: net.IP{100, 64, 1, 2},
		Metric:  0,
	}
	dnsDefaultToSet = []net.IP{
		net.IPv4(8, 8, 8, 8),
		net.IPv4(8, 8, 4, 4),
	}
)

func agentToVpn(tcpTun *common.Transport) {
	handshaked := false
	for {
		_, bufs, e := (*tcpTun).Read()
		if e != nil {
			lg.Printf("Pipe Read error %s", e)
			(*vpnTun).Close()
			return
		}
		if !handshaked {
			handshaked = true
		} else {
			writeLock.Lock()
			w, err := (*vpnTun).Write(bufs.Slices[0], 0)
			writeLock.Unlock()
			if err != nil || w != len(bufs.Slices[0]) {
				lg.Printf("vpn write failed error %s, w %d, r %d", e, w, len(bufs.Slices[0]))
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
		b := common.GetBuf(pool)
		buf := b.Buf
		r, e := (*vpnTun).Read(buf[0:MTU], 0)
		if e != nil {
			lg.Printf("vpn Read error %s", e)
			(*vpnTun).Close()
			return
		}
		if handleICMP(buf[0:r]) {
			continue
		}
		hdr := &nxthdr.NxtHdr{}
		flow := nxthdr.NxtFlow{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
		err := (*tcpTun).Write(hdr, &common.NxtBufs{Slices: net.Buffers{buf[0:r]}, Bufs: []*common.NxtBuf{b}})
		if err != nil {
			lg.Printf("Pipe write error %s,  r %d", e, r)
			(*vpnTun).Close()
			return
		}
	}
}

func agentInit(port int) {
	C.agent_init(2 /*windows*/, 0, MTU, 2, C.uint32_t(port))
}

func agentConnection(tchan chan common.NxtStream) {
	for {
		select {
		case client := <-tchan:
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
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
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
				regInfoLock.Lock()
				regInfo.AccessToken = tokens.AccessToken
				regInfoLock.Unlock()
			} else {
				lg.Println("Token refresh failed, will try again in 30 seconds")
			}
		}
		if !onboarded || force_onboard {
			fmt.Println("Forcing onboard")
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

func agentOnboard() {
	l := len(regInfo.Domains)
	domains := C.malloc(C.size_t(l) * C.size_t(unsafe.Sizeof(uintptr(0))))
	Cdomains := (*[1 << 28]*C.char)(domains)

	for i, d := range regInfo.Domains {
		Cdomains[i] = C.CString(d.Name)
	}

	l = len(regInfo.CACert)
	ca_cert := C.malloc(C.size_t(l) * C.size_t(unsafe.Sizeof(C.uint8_t(0))))
	Cca_cert := (*[1 << 28]C.uint8_t)(ca_cert)
	for i, c := range regInfo.CACert {
		Cca_cert[i] = C.uint8_t(c)
	}

	l = len(regInfo.Services)
	services := C.malloc(C.size_t(l) * C.size_t(unsafe.Sizeof(uintptr(0))))
	Cservices := (*[1 << 28]*C.char)(services)
	for i, s := range regInfo.Services {
		Cservices[i] = C.CString(s)
	}

	creg := C.CRegistrationInfo{
		gateway:      C.CString(regInfo.Gateway),
		access_token: C.CString(regInfo.AccessToken),
		connect_id:   C.CString(regInfo.ConnectID),
		cluster:      C.CString(regInfo.Cluster),
		domains:      (**C.char)(domains),
		num_domains:  C.int(len(regInfo.Domains)),
		ca_cert:      (*C.char)(ca_cert),
		num_cacert:   C.int(len(regInfo.CACert)),
		userid:       C.CString(regInfo.Userid),
		uuid:         C.CString(uniqueId),
		services:     (**C.char)(services),
		num_services: C.int(len(regInfo.Services)),
		hostname:     C.CString("localhost"),
		model:        C.CString("unknown"),
		os_type:      C.CString("windows"),
		os_name:      C.CString("unknown"),
		os_patch:     0,
		os_major:     0,
		os_minor:     0,
	}

	C.onboard(creg)

	for i, _ := range regInfo.Domains {
		C.free(unsafe.Pointer(Cdomains[i]))
	}
	C.free(unsafe.Pointer(domains))

	C.free(ca_cert)

	for i, _ := range regInfo.Services {
		C.free(unsafe.Pointer(Cservices[i]))
	}
	C.free(unsafe.Pointer(services))

	C.free(unsafe.Pointer(creg.gateway))
	C.free(unsafe.Pointer(creg.access_token))
	C.free(unsafe.Pointer(creg.connect_id))
	C.free(unsafe.Pointer(creg.cluster))
	C.free(unsafe.Pointer(creg.userid))
	C.free(unsafe.Pointer(creg.uuid))
	C.free(unsafe.Pointer(creg.hostname))
	C.free(unsafe.Pointer(creg.model))
	C.free(unsafe.Pointer(creg.os_type))
	C.free(unsafe.Pointer(creg.os_name))

	// See if the routes need to change from catch-all to specific or vice versa
	vpnRoutes()
}

func extraRoutes() []*winipcfg.RouteData {
	routes := []*winipcfg.RouteData{}
	for _, a := range regInfo.Domains {
		_, ipmask, err := net.ParseCIDR(a.Name)
		if err == nil {
			toAdd := winipcfg.RouteData{
				Destination: *ipmask,
				NextHop:     net.IP{100, 64, 1, 2},
				Metric:      0,
			}
			routes = append(routes, &toAdd)
		}
	}
	return routes
}

// By default, windows enables "smart dns" - ie it broadcasts the dns
// request parallely on all interfaces that advertise a dns server -
// which means even the private domain names dns requests will be broadcast
// on the public interface (yikes), but thats what it does. The "smart"
// part is that windows accepts the first dns response that comes from any
// interface. But smart dns can be turned off in which case windows will just
// send the dns request on the interface with the lowest metric, and the answer
// from that will be chosen as the dns response. Turning off smart dns needs
// editing registry etc.., so "normal" users for sure wont do it, maybe enterprise
// users might have security stuff install on the laptop that does that.
// So Lets consider four cases below. Note that the nextensio tunnel will always
// have the lowest metric (0) of all interfaces
//
// Case 1: Smart DNS ON, Nextensio attracting ALL traffic public and private (catch-all route)
// In this case windows will send dns on both Wi-Fi and the nxt0 tunnel. The nxt0
// tunnel of course relays that over Wi-Fi anyways, so there is effectively double
// dns requests sent. Whichever response comes first will be taken. The nxt0 interface
// does have to advertise a dns server because we want to DNS respond to private domain
// requests (which will fail over public). (The "Whichever response comes first will be taken"
// statement is dubious/behaviour is doubtful because if we drop dns requests on nxt0,
// then we can clearly see dns resolution overall getting delayed)
//
// Case 2: Smart DNS ON, Nextensio attracting only private traffic (no catch-all route)
// In this case also, DNS behaves same as before. TODO: We "can" make this behaviour
// different if we can somehow tell windows to send DNS requests to a server only on
// matching some domains, like NEDNSSettings.matchDomains in apple. Not sure if such
// a thing exists in windows, need to find out. If it exists, then we can ensure that
// only private domain dns requests come to nxt0.
//
// Case 3: Smart DNS OFF, Nextensio attracting ALL traffic (catch-all route)
// Here, nxt0 will be the only interface getting dns request because we are the lowest
// metric interface. And we have to ensure that we respond to both public and private
// DNS.
//
// Case 4: Smart DNS OFF, Nextensio attracting only private traffic (no catch-all route)
// Here again, since nxt0 is the lowest metric, we will be the only one getting all the
// dns requests and hence we will have to respond to both.
//
// NOTE1: We can play some more tricks with interface metric - we can say that in catch-all
// mode we have metric 0 and in the private-only mode we have a large metric. But then in the
// private only mode with smart DNS OFF, we will never get our private dns requests ! What
// windows really needs is a mac/ios style capability to differentiate dns servers based on
// the match-domains, rather than this wierd interface metric based mechanism.
//
// NOTE2: Down below, we wierdly add 8.8.8.8/32 and 8.8.4.4/32 to the route table, the
// reason for that is as follows - like we mentioned earlier, windows will end up broadcasting
// public requests on dns servers of Wi-Fi AND nxt0. For private requests alone, we can give
// some dummy DNS server IP like 100.64.1.3 for example, it doesnt matter since we respond
// ourselves. If we do that, for public DNS also, windows will send the DNS packet with the
// dest-IP of 100.64.1.3 and then we have to translate that to some legitimate public DNS server
// IP and send it out and get the response back. If we dont get the response back, windows
// claims to be "smart" and waiting only for the first response (Wi-fi in this case) etc.., but
// I have seen that if we dont respond over nxt0, there is some kind of additional delay introduced
// in dns resolution, so we better respond with a proper response for public DNS also on nxt0.
// As of today the rust agent is very simple - if a request comes to some dest IP, it just opens
// a socket to that dest IP and sends the request across, there is no logic to "map" from a dummy
// IP to a legit IP etc.., so we just ensure that the DNS IP we give here is a legit one, and of
// course we also need to ensure that legit IP comes via nxt0 so we get the request and can
// respond to it.
func vpnRoutes() {
	if luid == nil {
		return
	}

	extra := extraRoutes()

	// NOTE: This decides if we will act as a full tunnel and suck in all traffic or we
	// will suck in only traffic to specific routes
	attractAll := !regInfo.SplitTunnel

	for _, d := range regInfo.Domains {
		if d.Name == "nextensio-default-internet" {
			attractAll = true
		}
	}

	count := 0
	for {
		count += 1
		if attractAll {
			routes := []*winipcfg.RouteData{&nxtDefaultRouteIPv4ToAdd, &nxtDNS1RouteIPv4ToAdd, &nxtDNS2RouteIPv4ToAdd}
			err := (*luid).SetRoutes(routes)
			if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				lg.Printf("Failed to create default RouteData: %v (%d)", err, count)
				time.Sleep(1 * time.Second)
				continue
			}
			err = (*luid).SetDNS(windows.AF_INET, dnsDefaultToSet, nil)
			if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				lg.Printf("Failed to create DNS: %v (%d)", err, count)
				time.Sleep(1 * time.Second)
				continue
			}
		} else {
			base := []*winipcfg.RouteData{&nxtSpecificRouteIPv4ToAdd, &nxtDNS1RouteIPv4ToAdd, &nxtDNS2RouteIPv4ToAdd}
			routes := append(extra, base...)
			err := (*luid).SetRoutes(routes)
			if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				lg.Printf("Failed to create specific RouteData: %v (%d)", err, count)
				time.Sleep(1 * time.Second)
				continue
			}
			err = (*luid).SetDNS(windows.AF_INET, dnsDefaultToSet, nil)
			if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				lg.Printf("Failed to create DNS: %v (%d)", err, count)
				time.Sleep(1 * time.Second)
				continue
			}
		}
		break
	}
}

func UIEventLoop() {
	myApp = app.New()
	w := myApp.NewWindow("Login")
	w.Resize(fyne.NewSize(300, 100))
	w.SetOnClosed(func() {
	})

	u := widget.NewEntry()
	p := widget.NewPasswordEntry()
	loginStatus = widget.NewButton("Login", func() {
		username = u.Text
		password = p.Text
		loginStatus.Text = "Logging user in"
		tokens := authenticate(idp, clientid, username, password)
		if tokens != nil {
			loginStatus.Text = "Logged in"
			loginStatus.Disable()
			go monitorController(lg)
		} else {
			loginStatus.Text = "Login failed, please try again"
		}
	})

	w.SetContent(container.NewVBox(
		u,
		p,
		loginStatus,
	))

	w.ShowAndRun()
}

func postLogin() {
	interfaceName := "nxt0"
	for {
		if !onboarded {
			time.Sleep(time.Second)
			continue
		}
		break
	}

	var err error
	watcher, err = watchInterface()
	if err != nil {
		lg.Printf("Watcher error %s", err)
		return
	}

	err = elevate.DoAsSystem(func() error {
		t, terr := tun.CreateTUN(interfaceName, MTU)
		vpnTun = &t
		return terr
	})
	if err != nil {
		lg.Printf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	realInterfaceName, _ := (*vpnTun).Name()
	interfaceName = realInterfaceName

	defer (*vpnTun).Close()
	nativeTunDevice := (*vpnTun).(*tun.NativeTun)
	luidVal := winipcfg.LUID(nativeTunDevice.LUID())
	luid = &luidVal

	err = (*luid).SetIPAddresses([]net.IPNet{nxtIPAddresToAdd})
	if err != nil {
		lg.Printf("Failed to create IP Addr: %v", err)
		os.Exit(ExitSetupFailed)
	}

	iface, err := (*luid).IPInterface(windows.AF_INET)
	if err != nil {
		lg.Printf("Failed to get iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}
	iface.NLMTU = MTU
	err = iface.Set()
	if err != nil {
		lg.Printf("Failed to set iface for mtu: %v", err)
		os.Exit(ExitSetupFailed)
	}

	ipif, err := (*luid).IPInterface(windows.AF_INET)
	if err != nil {
		lg.Printf("Failed to get iface for metric: %v", err)
		os.Exit(ExitSetupFailed)
	}
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	err = ipif.Set()
	if err != nil {
		lg.Printf("Failed to set iface for metric: %v", err)
		os.Exit(ExitSetupFailed)
	}
	firewall.EnableFirewall(uint64(*luid), true, nil)

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	pool = common.NewPool(MTU)
	pktserver := websock.NewListener(context.TODO(), lg, pool, nil, nil, PKTTCPPORT, 0, 0, 0)
	tchan := make(chan common.NxtStream)
	go pktserver.Listen(tchan)
	go agentConnection(tchan)

	watcher.Configure(*luid)
	go monitorDefaultIP(windows.AF_INET)

	// There is no point sending traffic to agent till we have told it which
	// interface to send it out of, doing that might even cause a loop. So
	// wait till we figure out an interface to use
	for {
		if defaultIP == 0 {
			lg.Printf("Wait for default IP")
			time.Sleep(time.Second)
			continue
		}
		break
	}

	agentInit(PKTTCPPORT)

	regInfoLock.Lock()
	vpnRoutes()
	regInfoLock.Unlock()

	select {
	case <-term:
	}
	myApp.Quit()
}

func main() {
	lg = log.New(os.Stdout, "Nextensio: ", 0)
	unique = uuid.New()
	uniqueId = unique.String()
	idp = "https://login.nextensio.net"
	clientid = "0oav0q3hn65I4Zkmr5d6"
	controller = "server.nextensio.net:8080"
	go postLogin()
	UIEventLoop()
	lg.Printf("Shutting down")
	if watcher != nil {
		watcher.Destroy()
	}
}
