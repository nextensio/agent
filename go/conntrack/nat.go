package conntrack

import (
	"container/list"
	"errors"
	"net"

	"gitlab.com/nextensio/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NatTable interface {
	Get(uint16, []byte) uint16
	Put(uint16, []byte, uint16) error
	Snat(*gopacket.Packet, Flow) error
	Dnat(*gopacket.Packet, Flow) error
}

var (
	PSTART uint16 = 20000
	PEND   uint16 = 64000
)

type SNatV4 struct {
	start uint16
	end   uint16
	free  *list.List
}

type NatV4Key struct {
	proto uint16
	dest  [4]byte
}

type NatV4Table struct {
	source [4]byte
	dest   map[NatV4Key]*SNatV4
}

func NewNatV4Table(source net.IP) *NatV4Table {
	dest := make(map[NatV4Key]*SNatV4)
	var sip [4]byte
	copy(sip[0:], []byte(source.To4()))
	return &NatV4Table{source: sip, dest: dest}
}

func rewriteSrcV4(pkt *gopacket.Packet, sip []byte, sport uint16) error {
	var offset = 0
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	ipLayer := (*pkt).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return errors.New("Not an ipv4 packet")
	}
	ip := ipLayer.(*layers.IPv4)
	ip.SrcIP = net.IP([]byte{sip[0], sip[1], sip[2], sip[3]})
	offset += len(ip.Contents)
	serialize = append(serialize, ip)

	if tcpLayer := (*pkt).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		tcp.SrcPort = layers.TCPPort(sport)
		tcp.SetNetworkLayerForChecksum(ip)
		offset += len(tcp.Contents)
		serialize = append(serialize, tcp)
	} else if udpLayer := (*pkt).Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		udp.SrcPort = layers.UDPPort(sport)
		udp.SetNetworkLayerForChecksum(ip)
		offset += len(udp.Contents)
		serialize = append(serialize, udp)
	} else if icmpLayer := (*pkt).Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		icmp.Id = sport
		offset += len(icmp.Contents)
		serialize = append(serialize, icmp)
	} else {
		return errors.New("Unsupported protocol")
	}

	// Overwrite the original packet with the new headers, we are not changing any header
	// lengths, so there should be no extra/less data compared to before
	buf := common.NewInplaceSerializeBuffer((*pkt).Data(), offset)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return err
	}

	return nil
}

func rewriteDstV4(pkt *gopacket.Packet, dip []byte, dport uint16) error {
	var offset = 0
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	ipLayer := (*pkt).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return errors.New("Not an ipv4 packet")
	}
	ip := ipLayer.(*layers.IPv4)
	ip.DstIP = net.IP([]byte{dip[0], dip[1], dip[2], dip[3]})
	offset += len(ip.Contents)
	serialize = append(serialize, ip)

	if tcpLayer := (*pkt).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		tcp.DstPort = layers.TCPPort(dport)
		tcp.SetNetworkLayerForChecksum(ip)
		offset += len(tcp.Contents)
		serialize = append(serialize, tcp)
	} else if udpLayer := (*pkt).Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		udp.DstPort = layers.UDPPort(dport)
		udp.SetNetworkLayerForChecksum(ip)
		offset += len(udp.Contents)
		serialize = append(serialize, udp)
	} else if icmpLayer := (*pkt).Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		icmp.Id = dport
		offset += len(icmp.Contents)
		serialize = append(serialize, icmp)
	} else {
		return errors.New("Unsupported protocol")
	}

	// Overwrite the original packet with the new headers, we are not changing any header
	// lengths, so there should be no extra/less data compared to before
	buf := common.NewInplaceSerializeBuffer((*pkt).Data(), offset)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return err
	}

	return nil
}

func (n *NatV4Table) Get(proto uint16, ip []byte) uint16 {
	key := NatV4Key{proto: proto}
	copy(key.dest[0:], ip)
	if d, ok := n.dest[key]; ok {
		if d.start <= d.end {
			port := d.start
			d.start++
			return port
		} else if d.free != nil {
			port := d.free.Front()
			if port != nil {
				d.free.Remove(port)
				return port.Value.(uint16)
			}
		}
	} else {
		n.dest[key] = &SNatV4{start: PSTART + 1, end: PEND, free: nil}
		return PSTART
	}
	return 0
}

func (n *NatV4Table) Put(proto uint16, ip []byte, port uint16) error {
	key := NatV4Key{proto: proto}
	copy(key.dest[0:], ip)
	if d, ok := n.dest[key]; ok {
		if d.free == nil {
			d.free = list.New()
		}
		d.free.PushFront(port)
	} else {
		return errors.New("Cannot find port mapping")
	}

	return nil
}

func (n *NatV4Table) Snat(pkt *gopacket.Packet, flow Flow) error {

	natSport, natSip := flow.SnatGet()
	_, dip := flow.DstGet()
	proto := flow.Protocol()
	if natSport == 0 {
		nport := n.Get(proto, dip)
		if nport == 0 {
			return errors.New("Out of ports")
		}
		flow.SnatSet(nport, n.source[0:])
	}
	return rewriteSrcV4(pkt, natSip, natSport)
}

func (n *NatV4Table) Dnat(pkt *gopacket.Packet, flow Flow) error {
	natSport, _ := flow.SnatGet()
	sport, sip := flow.SrcGet()
	if natSport == 0 {
		return errors.New("Unknown return flow")
	} else {
		return rewriteDstV4(pkt, sip, sport)
	}
}
