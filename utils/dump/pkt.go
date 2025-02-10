package dump

import "syscall"

func PutPktType(pktType uint8) string {

	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PacketUser   = 6
		PacketKernel = 7
	)
	pktTypes := map[uint8]string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PacketUser:               "USER",
		PacketKernel:             "KERNEL",
	}
	if s, ok := pktTypes[pktType]; ok {
		return s
	}
	return ""
}
