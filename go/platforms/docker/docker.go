package main

import (
	"fmt"
	"log"

	"net"
	"nextensio/agent/agent"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A docker container just has one eth0. So we create a tun interface tun0
// and add iptable magic rules such that everything thats forwarded will be
// re-routed to the tun0 interface. Everytihng thats destined to the eth0
// IP will still go to the linux networking stack and come to us via socket/http
// So this enables us to use the docker agent both as a http proxy where the
// docker eth0 IP is the proxy address (at port 8080) and also if someone sets
// the docker eth0 IP as a default route and pumps IP packets, then we capture it
// via the tun interface and try to terminate the tcp/udp there and forward it.
// Note that the http proxy and the agent-terminating-tcp/udp co-exists at the
// same time!
//
//NOTE: For the above described tun0 mechanism to work, we need the host linux
// to turn off RPF using the commands below BEFORE creating the kind/docker
// testbed
// sudo sysctl -w net.ipv4.conf.all.rp_filter=0
// sudo sysctl net.ipv4.default.all.rp_filter=0
//
// To get some idea of what the iptable magic is, refer to the link below
// https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.netfilter.html

func configTun() {
	_, err := exec.Command("bash", "-c", "ifconfig tun0 up").Output()
	if err != nil {
		panic(err)
	}
	_, err = exec.Command("bash", "-c", "ifconfig tun0 169.254.2.1 netmask 255.255.255.0").Output()
	if err != nil {
		panic(err)
	}
	_, err = exec.Command("bash", "-c", "iptables -A PREROUTING -i eth0 -t mangle -j MARK --set-mark 1").Output()
	if err != nil {
		panic(err)
	}
	_, err = exec.Command("bash", "-c", "echo 201 nxt >> /etc/iproute2/rt_tables").Output()
	if err != nil {
		panic(err)
	}
	_, err = exec.Command("bash", "-c", "ip rule add fwmark 1 table nxt").Output()
	if err != nil {
		panic(err)
	}
	_, err = exec.Command("bash", "-c", "ip route add default via 169.254.2.1 dev tun0 table nxt").Output()
	if err != nil {
		panic(err)
	}
}

func createTun() int {
	nfd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	old, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFL, 0)
	if err != nil {
		panic(err)
	}
	_, err = unix.FcntlInt(uintptr(nfd), unix.F_SETFL, old & ^unix.O_NONBLOCK)
	if err != nil {
		panic(err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI
	name := []byte("tun0")
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	fmt.Println(string(ifr[:unix.IFNAMSIZ]))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(nfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		panic(fmt.Errorf("ioctl errno: %d", errno))
	}

	return nfd
}

func main() {
	iface := agent.Iface{Fd: createTun(), IP: net.ParseIP("169.254.2.1")}
	configTun()
	lg := log.New(os.Stdout, "AGT", 0)
	agent.AgentInit(lg, 0, 0)
	agent.AgentIface(lg, &iface)
	for {
		time.Sleep(100000 * time.Hour)
	}
}
