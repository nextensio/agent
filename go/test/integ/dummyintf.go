package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
	"net/http"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

var testSrcip = "192.0.2.1"
var testDstip = "198.51.100.1"
var testNATSrcip = "54.1.1.1"

type DummySource struct {
	EchoId       uint16
	SeqId        uint16
	ExpectSeq    uint16
	InSequence   int
	OutOfSeq     int
	listening    bool
	closed       bool
	testComplete *bool
}

func createIPv4ChecksumTestLayer() *layers.IPv4 {
	ip4 := &layers.IPv4{}
	ip4.Version = 4
	ip4.TTL = 64
	ip4.SrcIP = net.ParseIP(testSrcip)
	ip4.DstIP = net.ParseIP(testDstip)

	return ip4
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

func (d *DummySource) Listen(c chan common.NxtStream) {
	for {
		for d.listening {
			time.Sleep(time.Second)
		}
		d.listening = true
		c <- common.NxtStream{Parent: uuid.New(), Stream: d}
	}
}

func (d *DummySource) Dial(sChan chan common.NxtStream) *common.NxtError {
	return nil
}

func (d *DummySource) Close() *common.NxtError {
	d.closed = true
	d.listening = false
	return nil
}

func (d *DummySource) IsClosed() bool {
	return d.closed
}

func (d *DummySource) NewStream(hdr http.Header) common.Transport {
	return d
}

func (d *DummySource) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	p := gopacket.NewPacket(buf[0], layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return common.Err(common.GENERAL_ERR, nil)
	}

	ipLayer := p.Layer(layers.LayerTypeIPv4)
	ip := ipLayer.(*layers.IPv4)
	var sip [4]byte
	var dip [4]byte
	copy(sip[0:], []byte(ip.SrcIP.To4()))
	copy(dip[0:], []byte(ip.DstIP.To4()))

	n := gopacket.NewPacket(p.Data(), layers.LinkTypeRaw, common.LazyNoCopy)
	ipLayer = n.Layer(layers.LayerTypeIPv4)
	ip = ipLayer.(*layers.IPv4)
	icmpLayer := n.Layer(layers.LayerTypeICMPv4)
	icmp, _ := icmpLayer.(*layers.ICMPv4)

	if !bytes.Equal(ip.SrcIP, net.ParseIP(testDstip).To4()) {
		return common.Err(common.GENERAL_ERR, nil)
	}
	if d.EchoId != icmp.Id {
		return common.Err(common.GENERAL_ERR, nil)
	}
	if d.ExpectSeq != icmp.Seq {
		d.ExpectSeq = icmp.Seq + 1
		d.InSequence = 0
		d.OutOfSeq++
	} else {
		d.ExpectSeq++
		d.InSequence++
	}
	return nil
}

func (d *DummySource) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	buf := make([]byte, common.MAXBUF)
	hdr := &nxthdr.NxtHdr{}

	if d.InSequence >= 100 {
		// Well, we are testing by sending UDP/DTLS packets here, so there might be occassional
		// packet drops especially since we are blasting pkts in a while loop. With 100 pkts, we
		// should not see OutOfSeq any value other than the expected value 1, but with larger number
		// of InSequence count like 1000, we can expect pkt drops and OutofSeq to go up
		fmt.Println("Test Complete, got 100 packets in sequeuce ", d.OutOfSeq)
		*d.testComplete = true
		return hdr, net.Buffers{buf}, nil
	}
	p := createICMPPacket(d.EchoId, d.SeqId)
	d.SeqId++
	copy(buf[0:], (*p).Data())
	hdr.Hdr = &nxthdr.NxtHdr_Flow{}
	return hdr, net.Buffers{buf[0:len((*p).Data())]}, nil
}

func (d *DummySource) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}

func CreateDummySource(testComplete *bool) DummySource {
	return DummySource{testComplete: testComplete}
}

type Pkt struct {
	data []byte
}
type DummySink struct {
	listening bool
	closed    bool
	queue     []Pkt
	qLock     sync.Mutex
}

func (d *DummySink) Listen(c chan common.NxtStream) {
	for {
		for d.listening {
			time.Sleep(time.Second)
		}
		d.queue = make([]Pkt, 0)
		d.listening = true
		c <- common.NxtStream{Parent: uuid.New(), Stream: d}
	}
}

func (d *DummySink) Dial(sChan chan common.NxtStream) *common.NxtError {
	return nil
}

func (d *DummySink) Close() *common.NxtError {
	d.closed = true
	d.listening = false
	return nil
}

func (d *DummySink) IsClosed() bool {
	return d.closed
}

func (d *DummySink) NewStream(hdr http.Header) common.Transport {
	return d
}

func (d *DummySink) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	data := make([]byte, len(buf[0]))
	copy(data[0:], buf[0])
	d.qLock.Lock()
	d.queue = append(d.queue, Pkt{data: data})
	d.qLock.Unlock()
	return nil
}

func (d *DummySink) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {

	buf := make([]byte, common.MAXBUF)
	hdr := &nxthdr.NxtHdr{}

	for len(d.queue) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	d.qLock.Lock()
	pkt := d.queue[0]
	d.queue = d.queue[1:]
	d.qLock.Unlock()

	var serialize = make([]gopacket.SerializableLayer, 0, 1)
	p := gopacket.NewPacket(pkt.data[0:], layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil, nil, common.Err(common.GENERAL_ERR, nil)
	}
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil, common.Err(common.GENERAL_ERR, nil)
	}
	ip := ipLayer.(*layers.IPv4)
	tmpIP := make([]byte, len(ip.SrcIP))
	copy(tmpIP[0:], ip.SrcIP[0:])
	copy(ip.SrcIP[0:], ip.DstIP[0:])
	copy(ip.DstIP[0:], tmpIP[0:])
	serialize = append(serialize, ip)

	// Overwrite the original packet with the new headers, we are not changing any header
	// lengths, so there should be no extra/less data compared to before
	ser := common.NewInplaceSerializeBuffer(p.Data(), len(ip.Contents))
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(ser, opts, serialize...)
	if err != nil {
		return nil, nil, common.Err(common.GENERAL_ERR, err)
	}

	copy(buf[0:], pkt.data[0:])
	hdr.Hdr = &nxthdr.NxtHdr_Flow{}

	return hdr, net.Buffers{buf[0:len(pkt.data)]}, nil
}

func (d *DummySink) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}
