package dump

import (
	"encoding/binary"
	"fmt"
	"github.com/tklauser/ps"
	"io"
	"net/netip"
)

func PrintMeta(w io.Writer, meta *Meta) {
	saddr := netip.AddrFrom4([4]byte(meta.Addrs[4:]))
	daddr := netip.AddrFrom4([4]byte(meta.Addrs[:4]))
	dport := binary.BigEndian.Uint16(meta.Dport[:])
	sport := meta.PortNum
	family := addressFamily(meta.Family)

	var protocol string
	switch family {
	case AF_INET, AF_INET6:
		protocol = ipProto(meta.Protocol).String()
	case AF_NETLINK:
		protocol = netlinkProto(meta.Protocol).String()
	default:
		protocol = fmt.Sprintf("%d", meta.Protocol)
	}

	fmt.Fprintf(w, " %s:%d -> %s:%d netns=%d family=%s protocol=%s", saddr, sport, daddr, dport, meta.Netns, family, protocol)
}

func nullString(s []byte) string {
	for i, b := range s {
		if b == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

func getProcess(ev *Event) string {
	pid := ev.Pid
	p, err := ps.FindProcess(int(pid))
	if err != nil {
		return fmt.Sprintf("%d(%s)", pid, nullString(ev.Comm[:]))
	}

	return fmt.Sprintf("%d(%s)", pid, p.Command())
}
