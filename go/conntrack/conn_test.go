package conntrack

import (
	"bytes"
	"net"
	"nextensio/agent/common"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var testSrcip = "192.0.2.1"
var testDstip = "198.51.100.1"
var testNATSrcip = "54.1.1.1"
var testNATDstip = "54.1.1.1"
var testSrcport uint16 = 12345
var testDstport uint16 = 9999
var testNATSrcport uint16 = 8888
var testNATDstport uint16 = 8888

func createIPv4ChecksumTestLayer() *layers.IPv4 {
	ip4 := &layers.IPv4{}
	ip4.Version = 4
	ip4.TTL = 64
	ip4.SrcIP = net.ParseIP(testSrcip)
	ip4.DstIP = net.ParseIP(testDstip)

	return ip4
}

func createUDPChecksumTestLayer(sport uint16, dport uint16) *layers.UDP {
	udp := &layers.UDP{}
	udp.SrcPort = layers.UDPPort(sport)
	udp.DstPort = layers.UDPPort(dport)

	return udp
}

func createUDPPacket(sport uint16, dport uint16) *gopacket.Packet {
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip4 := createIPv4ChecksumTestLayer()
	ip4.Protocol = layers.IPProtocolUDP
	serialize = append(serialize, ip4)

	udp := createUDPChecksumTestLayer(sport, dport)
	udp.SetNetworkLayerForChecksum(ip4)
	serialize = append(serialize, udp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return nil
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}

	return &p
}

func createTCPChecksumTestLayer(sport uint16, dport uint16, syn bool, ack bool, rst bool, fin bool) *layers.TCP {
	tcp := &layers.TCP{}
	tcp.SrcPort = layers.TCPPort(sport)
	tcp.DstPort = layers.TCPPort(dport)
	if syn {
		tcp.SYN = true
	}
	if ack {
		tcp.ACK = true
	}
	if rst {
		tcp.RST = true
	}
	if fin {
		tcp.FIN = true
	}
	return tcp
}

func createTCPPacketFlags(sport uint16, dport uint16, syn bool, ack bool, rst bool, fin bool) *gopacket.Packet {
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip4 := createIPv4ChecksumTestLayer()
	ip4.Protocol = layers.IPProtocolTCP
	serialize = append(serialize, ip4)

	tcp := createTCPChecksumTestLayer(sport, dport, syn, ack, rst, fin)
	tcp.SetNetworkLayerForChecksum(ip4)
	serialize = append(serialize, tcp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return nil
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}

	return &p
}

func createTCPPacket(sport uint16, dport uint16) *gopacket.Packet {
	return createTCPPacketFlags(sport, dport, true, false, false, false)
}

func TestUDPCreateDelete(t *testing.T) {
	p := createUDPPacket(testSrcport, testDstport)

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)
	flow := flowv4Table.Create(p)
	if len(flowv4Table.flows) != 1 {
		t.Fatalf("Flow table empty")
	}

	if !bytes.Equal(flow.sip[0:], net.ParseIP(testSrcip).To4()) {
		t.Fatalf("Flow SIP incorrect")
	}
	if !bytes.Equal(flow.dip[0:], net.ParseIP(testDstip).To4()) {
		t.Fatalf("Flow DIP incorrect")
	}
	if flow.sport != testSrcport {
		t.Fatalf("Flow SPort incorrect")
	}
	if flow.dport != testDstport {
		t.Fatalf("Flow DPort incorrect")
	}
	if flow.proto != common.UDP {
		t.Fatalf("Flow protocol incorrect")
	}
	if flow.natSport != 0 {
		t.Fatalf("NAT port should be zero")
	}

	flowv4Table.Del(flow)
	if len(flowv4Table.flows) != 0 {
		t.Fatalf("Flow table not empty")
	}
}

func TestUDPNatCreateDelete(t *testing.T) {
	PSTART = 1
	PEND = 5

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))

	var dest [4]byte
	copy(dest[0:], net.ParseIP(testDstip).To4())

	for i := PSTART; i <= PEND; i++ {
		port := natv4Table.Get(common.UDP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d", port)
		}
	}
	port := natv4Table.Get(common.UDP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}
	for i := PEND; i >= PSTART; i-- {
		err := natv4Table.Put(common.UDP, dest[0:], i)
		if err != nil {
			t.Fatalf("NAT port not expected: %d", err)
		}
	}
	for i := PSTART; i <= PEND; i++ {
		port := natv4Table.Get(common.UDP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d / %d", i, port)
		}
	}
	port = natv4Table.Get(common.UDP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}

	for i := PSTART; i <= PEND; i++ {
		err := natv4Table.Put(common.UDP, dest[0:], i)
		if err != nil {
			t.Fatalf("NAT port not expected: %d", err)
		}
	}
	for i := PEND; i >= PSTART; i-- {
		port := natv4Table.Get(common.UDP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d / %d", i, port)
		}
	}
	port = natv4Table.Get(common.UDP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}
}

func TestUDPSrcNatPkt(t *testing.T) {
	p := createUDPPacket(testSrcport, testDstport)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testNATSrcip).To4())
	// In place modify the packet
	rewriteSrcV4(p, sip[0:], testNATSrcport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	udpLayer := n.Layer(layers.LayerTypeUDP)
	udp, _ := udpLayer.(*layers.UDP)

	if !bytes.Equal(ip.SrcIP, net.ParseIP(testNATSrcip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if uint16(udp.SrcPort) != testNATSrcport {
		t.Fatalf("Port has not been NATed")
	}
}

func TestUDPDstNatPkt(t *testing.T) {
	p := createUDPPacket(testSrcport, testDstport)

	var dip [4]byte
	copy(dip[0:], net.ParseIP(testNATDstip).To4())
	// In place modify the packet
	rewriteDstV4(p, dip[0:], testNATDstport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	udpLayer := n.Layer(layers.LayerTypeUDP)
	udp, _ := udpLayer.(*layers.UDP)

	if !bytes.Equal(ip.DstIP, net.ParseIP(testNATDstip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if uint16(udp.DstPort) != testNATDstport {
		t.Fatalf("Port has not been NATed")
	}
}

func TestTCPCreateDelete(t *testing.T) {
	p := createTCPPacket(testSrcport, testDstport)

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)
	flow := flowv4Table.Create(p)
	if len(flowv4Table.flows) != 1 {
		t.Fatalf("Flow table empty")
	}

	if !bytes.Equal(flow.sip[0:], net.ParseIP(testSrcip).To4()) {
		t.Fatalf("Flow SIP incorrect")
	}
	if !bytes.Equal(flow.dip[0:], net.ParseIP(testDstip).To4()) {
		t.Fatalf("Flow DIP incorrect")
	}
	if flow.sport != testSrcport {
		t.Fatalf("Flow SPort incorrect")
	}
	if flow.dport != testDstport {
		t.Fatalf("Flow DPort incorrect")
	}
	if flow.proto != common.TCP {
		t.Fatalf("Flow protocol incorrect")
	}
	if flow.natSport != 0 {
		t.Fatalf("NAT port should be zero")
	}

	flowv4Table.Del(flow)
	if len(flowv4Table.flows) != 0 {
		t.Fatalf("Flow table not empty")
	}
}

func TestTCPNatCreateDelete(t *testing.T) {
	PSTART = 1
	PEND = 5

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))

	var dest [4]byte
	copy(dest[0:], net.ParseIP(testDstip).To4())

	for i := PSTART; i <= PEND; i++ {
		port := natv4Table.Get(common.TCP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d", port)
		}
	}
	port := natv4Table.Get(common.TCP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}
	for i := PEND; i >= PSTART; i-- {
		err := natv4Table.Put(common.TCP, dest[0:], i)
		if err != nil {
			t.Fatalf("NAT port not expected: %d", err)
		}
	}
	for i := PSTART; i <= PEND; i++ {
		port := natv4Table.Get(common.TCP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d / %d", i, port)
		}
	}
	port = natv4Table.Get(common.TCP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}

	for i := PSTART; i <= PEND; i++ {
		err := natv4Table.Put(common.TCP, dest[0:], i)
		if err != nil {
			t.Fatalf("NAT port not expected: %d", err)
		}
	}
	for i := PEND; i >= PSTART; i-- {
		port := natv4Table.Get(common.TCP, dest[0:])
		if port != i {
			t.Fatalf("NAT port not expected: %d / %d", i, port)
		}
	}
	port = natv4Table.Get(common.TCP, dest[0:])
	if port != 0 {
		t.Fatalf("Expecting out of port, got %d", port)
	}
}

func TestTCPSrcNatPkt(t *testing.T) {
	p := createTCPPacket(testSrcport, testDstport)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testNATSrcip).To4())
	// In place modify the packet
	rewriteSrcV4(p, sip[0:], testNATSrcport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	tcpLayer := n.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	if !bytes.Equal(ip.SrcIP, net.ParseIP(testNATSrcip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if uint16(tcp.SrcPort) != testNATSrcport {
		t.Fatalf("Port has not been NATed")
	}
}

func TestTCPDstNatPkt(t *testing.T) {
	p := createTCPPacket(testSrcport, testDstport)

	var dip [4]byte
	copy(dip[0:], net.ParseIP(testNATDstip).To4())
	// In place modify the packet
	rewriteDstV4(p, dip[0:], testNATDstport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	tcpLayer := n.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	if !bytes.Equal(ip.DstIP, net.ParseIP(testNATDstip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if uint16(tcp.DstPort) != testNATDstport {
		t.Fatalf("Port has not been NATed")
	}
}

func TestTCPUDPNatCreateDelete(t *testing.T) {
	PSTART = 1
	PEND = 5

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))

	var dest [4]byte
	copy(dest[0:], net.ParseIP(testDstip).To4())

	tport := natv4Table.Get(common.TCP, dest[0:])
	if tport != 1 {
		t.Fatalf("NAT port not the expected one")
	}
	uport := natv4Table.Get(common.UDP, dest[0:])
	if uport != 1 {
		t.Fatalf("NAT port not the expected one")
	}
	if len(natv4Table.dest) != 2 {
		t.Fatalf("Expected two NAT destinations")
	}
	natv4Table.Put(common.TCP, dest[0:], tport)
	natv4Table.Put(common.TCP, dest[0:], uport)
	if len(natv4Table.dest) != 2 {
		t.Fatalf("Expected two NAT destinations")
	}
}

func createUDPflows(t *testing.T, flowv4Table *FlowV4Table) {
	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	for i := PSTART; i <= PEND; i++ {
		sport := testSrcport + i
		p := createUDPPacket(sport, testDstport)
		err := flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key := FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.UDP}
		flow := flowv4Table.flows[key]
		if flow.natSport != i {
			t.Fatalf("Wrong NAT port for flow %d", flow.natSport)
		}
		key = FlowV4Key{sport: testDstport, dport: flow.natSport, sip: dip, dip: nat, proto: common.UDP}
		reverse := flowv4Table.flows[key]
		if reverse != flow {
			t.Fatalf("Reverse flow not found")
		}

		// Try a second packet, it should hit the same flow
		p = createUDPPacket(sport, testDstport)
		err = flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key = FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.UDP}
		flow2 := flowv4Table.flows[key]
		if flow2 != flow {
			t.Fatalf("Flows difer??!!")
		}
	}
}
func TestSNATUDPFlow(t *testing.T) {
	PSTART = 1
	PEND = 2

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	createUDPflows(t, &flowv4Table)

	// No more nat ports free, now a new flow should fail
	sport := PEND + 1
	p := createUDPPacket(sport, testDstport)
	err := flowv4Table.Snat(p)
	if err == nil {
		t.Fatalf("NAT failed")
	}

	// Now delete all flows
	for i := PEND; i >= PSTART; i-- {
		sport := testSrcport + i
		key := FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.UDP}
		flow := flowv4Table.flows[key]
		if flow == nil {
			t.Fatalf("Flow not found")
		}
		flowv4Table.Del(flow)

		key = FlowV4Key{sport: testDstport, dport: flow.natSport, sip: dip, dip: nat, proto: common.UDP}
		reverse := flowv4Table.flows[key]
		if reverse != nil {
			t.Fatalf("Reverse flow should have been deleted!")
		}
	}
	if len(flowv4Table.flows) != 0 {
		t.Fatalf("Expect flow table to be empty now %d", len(flowv4Table.flows))
	}

	// Create should succeed again
	createUDPflows(t, &flowv4Table)
	if len(flowv4Table.flows) != 2*int(PEND-PSTART+1) {
		t.Fatalf("Number of flows not matching expectation")
	}
}

func createTCPflows(t *testing.T, flowv4Table *FlowV4Table) {
	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	for i := PSTART; i <= PEND; i++ {
		sport := testSrcport + i
		p := createTCPPacket(sport, testDstport)
		err := flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key := FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.TCP}
		flow := flowv4Table.flows[key]
		if flow.natSport != i {
			t.Fatalf("Wrong NAT port for flow %d", flow.natSport)
		}
		key = FlowV4Key{sport: testDstport, dport: flow.natSport, sip: dip, dip: nat, proto: common.TCP}
		reverse := flowv4Table.flows[key]
		if reverse != flow {
			t.Fatalf("Reverse flow not found")
		}

		// Try a second packet, it should hit the same flow
		p = createTCPPacket(sport, testDstport)
		err = flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key = FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.TCP}
		flow2 := flowv4Table.flows[key]
		if flow2 != flow {
			t.Fatalf("Flows difer??!!")
		}
	}
}

func TestSNATTCPFlow(t *testing.T) {
	PSTART = 1
	PEND = 2

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	createTCPflows(t, &flowv4Table)

	// No more nat ports free, now a new flow should fail
	sport := PEND + 1
	p := createTCPPacket(sport, testDstport)
	err := flowv4Table.Snat(p)
	if err == nil {
		t.Fatalf("NAT failed")
	}

	// Now delete all flows
	for i := PEND; i >= PSTART; i-- {
		sport := testSrcport + i
		key := FlowV4Key{sport: sport, dport: testDstport, sip: sip, dip: dip, proto: common.TCP}
		flow := flowv4Table.flows[key]
		if flow == nil {
			t.Fatalf("Flow not found")
		}
		flowv4Table.Del(flow)

		key = FlowV4Key{sport: testDstport, dport: flow.natSport, sip: dip, dip: nat, proto: common.TCP}
		reverse := flowv4Table.flows[key]
		if reverse != nil {
			t.Fatalf("Reverse flow should have been deleted!")
		}
	}
	if len(flowv4Table.flows) != 0 {
		t.Fatalf("Expect flow table to be empty now %d", len(flowv4Table.flows))
	}

	// Create should succeed again
	createTCPflows(t, &flowv4Table)
	if len(flowv4Table.flows) != 2*int(PEND-PSTART+1) {
		t.Fatalf("Number of flows not matching expectation")
	}
}

// TODO: The tcp state checking should check for the proper direction of syn,syn-ack,ack
// which it doesnt today. The test case should be modified once that check is added
func testTcpStates(t *testing.T, rst bool, fin bool) {

	// send tcp SYN
	p := createTCPPacketFlags(testSrcport, testDstport, true, false, false, false)
	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)
	flowv4Table.Snat(p)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	key := FlowV4Key{sport: testSrcport, dport: testDstport, sip: sip, dip: dip, proto: common.TCP}
	flow := flowv4Table.flows[key]
	if flow.tcpState != common.TCP_SYN {
		t.Fatalf("TCP state not SYN")
	}
	// one more packet with just no flags
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN {
		t.Fatalf("TCP state not SYN")
	}
	// one more with SYN
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN {
		t.Fatalf("TCP state not SYN")
	}

	// Send syn-ack
	p = createTCPPacketFlags(testSrcport, testDstport, true, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN_ACK {
		t.Fatalf("TCP state not SYN-ACK")
	}
	// one more packet with just no flags
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN_ACK {
		t.Fatalf("TCP state not SYN-ACK")
	}
	// one more with SYN
	p = createTCPPacketFlags(testSrcport, testDstport, true, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN_ACK {
		t.Fatalf("TCP state not SYN-ACK")
	}
	// one more syn-ack
	p = createTCPPacketFlags(testSrcport, testDstport, true, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_SYN_ACK {
		t.Fatalf("TCP state not SYN-ACK")
	}

	// Send ack
	p = createTCPPacketFlags(testSrcport, testDstport, false, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_ACK {
		t.Fatalf("TCP state not ACK")
	}
	// no flags
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_ACK {
		t.Fatalf("TCP state not ACK")
	}
	// SYN
	p = createTCPPacketFlags(testSrcport, testDstport, true, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_ACK {
		t.Fatalf("TCP state not ACK")
	}
	// SYN-ACK
	p = createTCPPacketFlags(testSrcport, testDstport, true, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_ACK {
		t.Fatalf("TCP state not ACK")
	}
	// ACK
	p = createTCPPacketFlags(testSrcport, testDstport, false, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_ACK {
		t.Fatalf("TCP state not ACK")
	}

	// Now close the session
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, rst, fin)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_CLOSED {
		t.Fatalf("TCP state not closed")
	}
	// no flags
	p = createTCPPacketFlags(testSrcport, testDstport, false, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_CLOSED {
		t.Fatalf("TCP state not ACK")
	}
	// SYN
	p = createTCPPacketFlags(testSrcport, testDstport, true, false, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_CLOSED {
		t.Fatalf("TCP state not ACK")
	}
	// SYN-ACK
	p = createTCPPacketFlags(testSrcport, testDstport, true, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_CLOSED {
		t.Fatalf("TCP state not ACK")
	}
	// ACK
	p = createTCPPacketFlags(testSrcport, testDstport, false, true, false, false)
	flowv4Table.Snat(p)
	if flow.tcpState != common.TCP_CLOSED {
		t.Fatalf("TCP state not ACK")
	}
}

func TestTcpStatesFIN(t *testing.T) {
	testTcpStates(t, false, true)
}

func TestTcpStatesRST(t *testing.T) {
	testTcpStates(t, true, false)
}

func TestTcpStatesFINRST(t *testing.T) {
	testTcpStates(t, true, true)
}

func createICMPTestLayer(id uint16, seq uint16) *layers.ICMPv4 {
	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	icmp.Id = id
	icmp.Seq = seq

	return icmp
}

func createICMPPacket(id uint16, seq uint16) *gopacket.Packet {
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip4 := createIPv4ChecksumTestLayer()
	ip4.Protocol = layers.IPProtocolICMPv4
	serialize = append(serialize, ip4)

	icmp := createICMPTestLayer(id, seq)
	serialize = append(serialize, icmp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return nil
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}

	return &p
}

func TestICMPSrcNatPkt(t *testing.T) {
	p := createICMPPacket(testSrcport, 1234)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testNATSrcip).To4())
	// In place modify the packet
	rewriteSrcV4(p, sip[0:], testNATSrcport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	icmpLayer := n.Layer(layers.LayerTypeICMPv4)
	icmp, _ := icmpLayer.(*layers.ICMPv4)

	if !bytes.Equal(ip.SrcIP, net.ParseIP(testNATSrcip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if icmp.Id != testNATSrcport {
		t.Fatalf("Port has not been NATed %d", icmp)
	}
}

func TestICMPDstNatPkt(t *testing.T) {
	p := createICMPPacket(testDstport, 1234)

	var dip [4]byte
	copy(dip[0:], net.ParseIP(testNATDstip).To4())
	// In place modify the packet
	rewriteDstV4(p, dip[0:], testNATDstport)

	// Parse the same packet again, use the old packet's data buffer and create
	// a new packet and parse it again. Not sure if gopacket has an option to just
	// "reparse" an existing packet
	n := gopacket.NewPacket((*p).Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer := n.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	icmpLayer := n.Layer(layers.LayerTypeICMPv4)
	icmp, _ := icmpLayer.(*layers.ICMPv4)

	if !bytes.Equal(ip.DstIP, net.ParseIP(testNATDstip).To4()) {
		t.Fatalf("IP has not been NATed")
	}
	if icmp.Id != testNATDstport {
		t.Fatalf("Port has not been NATed")
	}
}

func createICMPflows(t *testing.T, flowv4Table *FlowV4Table) {
	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	for i := PSTART; i <= PEND; i++ {
		sport := testSrcport + i
		p := createICMPPacket(sport, 1234)
		err := flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key := FlowV4Key{Sport: sport, Dport: 0, Sip: sip, Dip: dip, Proto: common.ICMP}
		flow := flowv4Table.flows[key]
		if flow.natSport != i {
			t.Fatalf("Wrong NAT port for flow %d", flow.natSport)
		}
		key = FlowV4Key{Sport: 0, Dport: flow.natSport, Sip: dip, Dip: nat, Proto: common.ICMP}
		reverse := flowv4Table.flows[key]
		if reverse != flow {
			t.Fatalf("Reverse flow not found")
		}

		// Try a second packet, it should hit the same flow
		p = createICMPPacket(sport, 1234)
		err = flowv4Table.Snat(p)
		if err != nil {
			t.Fatalf("NAT failed")
		}
		key = FlowV4Key{Sport: sport, Dport: 0, Sip: sip, Dip: dip, Proto: common.ICMP}
		flow2 := flowv4Table.flows[key]
		if flow2 != flow {
			t.Fatalf("Flows difer??!!")
		}
	}
}

func TestSNATICMPFlow(t *testing.T) {
	PSTART = 1
	PEND = 2

	natv4Table := NewNatV4Table(net.ParseIP(testNATSrcip))
	flowv4Table := NewFlowV4Table(natv4Table)

	var sip [4]byte
	copy(sip[0:], net.ParseIP(testSrcip).To4())
	var dip [4]byte
	copy(dip[0:], net.ParseIP(testDstip).To4())
	var nat [4]byte
	copy(nat[0:], net.ParseIP(testNATSrcip).To4())

	createICMPflows(t, &flowv4Table)

	// No more nat ports free, now a new flow should fail
	sport := PEND + 1
	p := createICMPPacket(sport, 1234)
	err := flowv4Table.Snat(p)
	if err == nil {
		t.Fatalf("NAT failed")
	}

	// Now delete all flows
	for i := PEND; i >= PSTART; i-- {
		sport := testSrcport + i
		key := FlowV4Key{Sport: sport, Dport: 0, Sip: sip, Dip: dip, Proto: common.ICMP}
		flow := flowv4Table.flows[key]
		if flow == nil {
			t.Fatalf("Flow not found")
		}
		flowv4Table.Del(flow)

		key = FlowV4Key{Sport: 0, Dport: flow.natSport, Sip: dip, Dip: nat, Proto: common.ICMP}
		reverse := flowv4Table.flows[key]
		if reverse != nil {
			t.Fatalf("Reverse flow should have been deleted!")
		}
	}
	if len(flowv4Table.flows) != 0 {
		t.Fatalf("Expect flow table to be empty now %d", len(flowv4Table.flows))
	}

	// Create should succeed again
	createICMPflows(t, &flowv4Table)
	if len(flowv4Table.flows) != 2*int(PEND-PSTART+1) {
		t.Fatalf("Number of flows not matching expectation")
	}
}
