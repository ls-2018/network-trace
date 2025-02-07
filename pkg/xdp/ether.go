package xdp

import (
	"fmt"
	"net"
)

type Mac [6]byte

func (m *Mac) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type IpHdr struct {
	IHL      uint8  `json:"ihl"`
	Version  uint8  `json:"version"`
	TOS      uint8  `json:"tos"`      // 数据包的优先级和延迟要求
	TotLen   uint16 `json:"tot_len"`  // 是整个数据包的长度（包括 IP 头部和数据部分），单位是字节。它是一个 16 位字段，采用网络字节序（大端序），
	ID       uint16 `json:"id"`       // 是数据包的标识符，通常用于数据包的分片
	FragOff  uint16 `json:"frag_off"` // 用于表示数据包是否被分片以及分片的位置
	TTL      uint8  `json:"ttl"`
	Protocol uint8  `json:"protocol"`
	Check    uint16 `json:"check"`
	SAddr    uint32 `json:"saddr"`
	DAddr    uint32 `json:"daddr"`
}

func IntToIP(ipInt uint32) net.IP {
	return net.IPv4(byte(ipInt&0xFF), byte(ipInt>>8&0xFF), byte(ipInt>>16&0xFF), byte(ipInt>>24))
}
