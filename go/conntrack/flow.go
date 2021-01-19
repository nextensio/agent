package conntrack

import (
	"errors"
	"time"

	"gitlab.com/nextensio/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// One hour in seconds, timeout for established tcp sessions
	TCP_EST_AGE float64 = (1 * 60 * 60)
	// 5 minutes in seconds, timeout for half open tcp sessions
	TCP_HALF_OPEN_AGE float64 = (5 * 60)
)

type Flow interface {
	SnatGet() (uint16, []byte)
	SnatSet(port uint16, ip []byte)
	SrcGet() (uint16, []byte)
	DstGet() (uint16, []byte)
	Protocol() uint16
}

// A "flow" is a 5 tuple of src ip, src port, dst ip, dst port and protocol
type FlowV4 struct {
	FlowV4Key
	NatSport uint16
	NatSip   [4]byte
	lastSeen time.Time
	tcpState int
}

type FlowV4Key struct {
	Sport uint16
	Dport uint16
	Sip   [4]byte
	Dip   [4]byte
	Proto uint16
}

type FlowV4Table struct {
	nat   NatTable
	flows map[FlowV4Key]*FlowV4
}

func NewFlowV4Table(nat NatTable) FlowV4Table {
	return FlowV4Table{nat: nat, flows: make(map[FlowV4Key]*FlowV4)}
}

// Extract the flow 5-tuple for each L4 protocol type
func FlowV4Keys(pkt *gopacket.Packet) (error, FlowV4Key, *layers.TCP) {
	var proto uint16
	var sport uint16
	var dport uint16
	var sip [4]byte
	var dip [4]byte

	ipLayer := (*pkt).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return errors.New("Not an ipv4 packet"), FlowV4Key{}, nil
	}
	ip := ipLayer.(*layers.IPv4)
	copy(sip[0:], []byte(ip.SrcIP.To4()))
	copy(dip[0:], []byte(ip.DstIP.To4()))

	var tcpState *layers.TCP
	if tcpLayer := (*pkt).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		proto = common.TCP
		sport = uint16(tcp.SrcPort)
		dport = uint16(tcp.DstPort)
		tcpState = tcp
	} else if udpLayer := (*pkt).Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		proto = common.UDP
		sport = uint16(udp.SrcPort)
		dport = uint16(udp.DstPort)
	} else if icmpLayer := (*pkt).Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		proto = common.ICMP
		sport = icmp.Id
		dport = 0
	} else {
		return errors.New("Unsupported protocol"), FlowV4Key{}, nil
	}

	return nil, FlowV4Key{Proto: proto, Sport: sport, Dport: dport, Sip: sip, Dip: dip}, tcpState
}

// If flow exists, return that. If flow does not exist, create one
func (f *FlowV4Table) Create(pkt *gopacket.Packet) *FlowV4 {
	err, key, tcp := FlowV4Keys(pkt)
	if err != nil {
		return nil
	}
	if flow, ok := f.flows[key]; ok {
		if tcp != nil {
			flow.tcpFsm(tcp)
		}
		return flow
	} else {
		flow = &FlowV4{FlowV4Key: key, NatSport: 0, tcpState: common.TCP_INIT}
		f.flows[key] = flow
		if tcp != nil {
			flow.tcpFsm(tcp)
		}
		return flow
	}

	return nil
}

// If flow exists, return that. If flow does not exist, return nil
func (f *FlowV4Table) Fetch(pkt *gopacket.Packet) *FlowV4 {
	err, key, tcp := FlowV4Keys(pkt)
	if err != nil {
		return nil
	}
	if flow, ok := f.flows[key]; ok {
		if tcp != nil {
			flow.tcpFsm(tcp)
		}
		return flow
	}

	return nil
}

// Delete the forward and reverse flows
func (f *FlowV4Table) Del(flow *FlowV4) error {
	key := FlowV4Key{Sip: flow.Sip, Dip: flow.Dip, Sport: flow.Sport, Dport: flow.Sport, Proto: flow.Proto}
	delete(f.flows, key)
	key = FlowV4Key{Dip: flow.NatSip, Sip: flow.Dip, Sport: flow.Sport, Dport: flow.NatSport, Proto: flow.Proto}
	delete(f.flows, key)

	if flow.NatSport != 0 {
		return f.nat.Put(flow.Proto, flow.Dip[0:], flow.NatSport)
	}
	return nil
}

// Source NAT a packet, creating flows and NAT entries etc.. as required
func (f *FlowV4Table) Snat(pkt *gopacket.Packet) error {
	flow := f.Create(pkt)
	if flow == nil {
		return errors.New("Snat failed")
	}

	hasNat := (flow.NatSport != 0)
	err := f.nat.Snat(pkt, flow)
	if err != nil {
		f.Del(flow)
		return err
	}

	// If the flow got NATed, add the reverse flow also to the flow table
	if !hasNat && flow.NatSport != 0 {
		var key FlowV4Key
		if flow.Proto != common.ICMP {
			key = FlowV4Key{Sport: flow.Sport, Dport: flow.NatSport, Sip: flow.Dip, Dip: flow.NatSip, Proto: flow.Proto}
		} else {
			key = FlowV4Key{Sport: flow.NatSport, Dport: 0, Sip: flow.Dip, Dip: flow.NatSip, Proto: flow.Proto}
		}
		f.flows[key] = flow
	}

	return nil
}

// Reverse S-NAT (D-NAT) the packet, the S-NAT entries should exist already or else
// the reverse S-NAT will just fail
func (f *FlowV4Table) Dnat(pkt *gopacket.Packet) error {
	flow := f.Fetch(pkt)
	if flow == nil {
		return errors.New("Dnat failed")
	}

	err := f.nat.Dnat(pkt, flow)
	if err != nil {
		return err
	}

	return nil
}

// Track the tcp states of the flow
func (flow *FlowV4) tcpFsm(tcp *layers.TCP) {
	flow.lastSeen = time.Now()
	if tcp.FIN || tcp.RST {
		flow.tcpState = common.TCP_CLOSED
		return
	}
	switch flow.tcpState {
	case common.TCP_INIT:
		if tcp.SYN && !tcp.ACK {
			flow.tcpState = common.TCP_SYN
		}
	case common.TCP_SYN:
		// TODO: well, we need to check syn-ack from the proper direction
		if tcp.SYN && tcp.ACK {
			flow.tcpState = common.TCP_SYN_ACK
		}
	case common.TCP_SYN_ACK:
		// TODO: again, we need to check ack from the proper direction
		if tcp.ACK && !tcp.SYN {
			flow.tcpState = common.TCP_ACK
		}
	case common.TCP_ACK:
		if tcp.FIN || tcp.RST {
			flow.tcpState = common.TCP_CLOSED
		}
	case common.TCP_CLOSED:
		// nothing can move the flow out of closed state
	}
}

func (flow *FlowV4) TimedOut() bool {
	elapsed := time.Since(flow.lastSeen).Seconds()

	if flow.tcpState == common.TCP_ACK {
		if elapsed > TCP_EST_AGE {
			return true
		}
	} else {
		if elapsed > TCP_HALF_OPEN_AGE {
			return true
		}
	}

	return false
}

func (flow *FlowV4) SnatGet() (uint16, []byte) {
	return flow.NatSport, flow.NatSip[0:]
}

func (flow *FlowV4) SrcGet() (uint16, []byte) {
	return flow.Sport, flow.Sip[0:]
}

func (flow *FlowV4) DstGet() (uint16, []byte) {
	return flow.Sport, flow.Dip[0:]
}

func (flow *FlowV4) Protocol() uint16 {
	return flow.Proto
}

func (flow *FlowV4) SnatSet(port uint16, ip []byte) {
	flow.NatSport = port
	copy(flow.NatSip[0:], ip)
}
