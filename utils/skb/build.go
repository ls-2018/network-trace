package skb

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type Pkt struct {
	Saddr    [4]byte
	Daddr    [4]byte
	Sport    [2]byte
	Dport    [2]byte
	Protocol uint8
	IcmpType uint8
	IcmpCode uint8
	IsSynack uint8
}

func _ntohs(n [2]byte) uint16 {
	return binary.BigEndian.Uint16(n[:])
}

func BuildSkbData() ([]byte, error) {
	pkt := &Pkt{
		Saddr:    [4]byte{192, 168, 1, 1},
		Daddr:    [4]byte{192, 168, 1, 2},
		Sport:    [2]byte{0x30, 0x39},
		Dport:    [2]byte{0x30, 0x39},
		Protocol: 6,
	}

	// Create a new Ethernet frame
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create a new IPv4 packet
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP(pkt.Saddr[:]),
		DstIP:    net.IP(pkt.Daddr[:]),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		IHL:      5,
	}

	var l4layer gopacket.SerializableLayer
	switch pkt.Protocol {
	case 6: // TCP
		ipLayer.Protocol = layers.IPProtocolTCP
		l4layer = &layers.TCP{
			SrcPort: layers.TCPPort(_ntohs(pkt.Sport)),
			DstPort: layers.TCPPort(_ntohs(pkt.Dport)),
		}

		if pkt.IsSynack == 1 {
			l4layer.(*layers.TCP).SYN = true
			l4layer.(*layers.TCP).ACK = true
		}

	case 17: // UDP
		ipLayer.Protocol = layers.IPProtocolUDP
		l4layer = &layers.UDP{
			SrcPort: layers.UDPPort(_ntohs(pkt.Sport)),
			DstPort: layers.UDPPort(_ntohs(pkt.Dport)),
		}

	case 1: // ICMP
		ipLayer.Protocol = layers.IPProtocolICMPv4
		l4layer = &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(pkt.IcmpType, pkt.IcmpCode),
		}
	}

	// Create the encapsulated payload (in this case, a simple payload)
	payload := []byte("Hello, Packet!")

	// Serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethLayer,
		ipLayer,
		l4layer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to gen packet: %w", err)
	}

	return buffer.Bytes(), nil
}
