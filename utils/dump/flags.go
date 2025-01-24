package dump

import "net/netip"

type Flags struct {
	Netns string
	netns uint32
	Pid   uint
	Mark  uint

	FilterProtocol string
	protocol       uint16
	FilterAddr     string
	addr           netip.Addr
	FilterPort     uint16
	FilterFuncs    string

	OutputSockCommon bool
	OutputSockInfo   bool
	OutputSocketInfo bool
	OutputStack      bool

	OutputFile string

	OutputLimitLines uint

	KprobeWay string

	ListFuncs string
}
