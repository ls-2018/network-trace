package dump

import (
	"golang.org/x/exp/slices"
	"reflect"
	"unsafe"
)

const (
	MaxStackDepth = 50
)

type sockType uint16

const (
	SOCK_STREAM    sockType = 1
	SOCK_DGRAM     sockType = 2
	SOCK_RAW       sockType = 3
	SOCK_RDM       sockType = 4
	SOCK_SEQPACKET sockType = 5
	SOCK_DCCP      sockType = 6
	SOCK_PACKET    sockType = 10
)

func (s sockType) String() string {
	switch s {
	case SOCK_STREAM:
		return "SOCK_STREAM"
	case SOCK_DGRAM:
		return "SOCK_DGRAM"
	case SOCK_RAW:
		return "SOCK_RAW"
	case SOCK_RDM:
		return "SOCK_RDM"
	case SOCK_SEQPACKET:
		return "SOCK_SEQPACKET"
	case SOCK_DCCP:
		return "SOCK_DCCP"
	case SOCK_PACKET:
		return "SOCK_PACKET"
	default:
		return ""
	}
}

type SocketState uint16

const (
	socketStateFree SocketState = iota
	socketStateUnconnected
	socketStateConnecting
	socketStateConnected
	socketStateDisconnecting
)

func (s SocketState) String() string {
	switch s {
	case socketStateFree:
		return "FREE"
	case socketStateUnconnected:
		return "UNCONNECTED"
	case socketStateConnecting:
		return "CONNECTING"
	case socketStateConnected:
		return "CONNECTED"
	case socketStateDisconnecting:
		return "DISCONNECTING"
	default:
		return ""
	}
}

type AddressFamily uint16

const (
	AF_UNSPEC     AddressFamily = 0
	AF_UNIX       AddressFamily = 1  /* Unix domain sockets 		*/
	AF_LOCAL      AddressFamily = 1  /* POSIX name for AF_UNIX	*/
	AF_INET       AddressFamily = 2  /* Internet IP Protocol 	*/
	AF_AX25       AddressFamily = 3  /* Amateur Radio AX.25 		*/
	AF_IPX        AddressFamily = 4  /* Novell IPX 			*/
	AF_APPLETALK  AddressFamily = 5  /* AppleTalk DDP 		*/
	AF_NETROM     AddressFamily = 6  /* Amateur Radio NET/ROM 	*/
	AF_BRIDGE     AddressFamily = 7  /* Multiprotocol bridge 	*/
	AF_ATMPVC     AddressFamily = 8  /* ATM PVCs			*/
	AF_X25        AddressFamily = 9  /* Reserved for X.25 project 	*/
	AF_INET6      AddressFamily = 10 /* IP version 6			*/
	AF_ROSE       AddressFamily = 11 /* Amateur Radio X.25 PLP	*/
	AF_DECnet     AddressFamily = 12 /* Reserved for DECnet project	*/
	AF_NETBEUI    AddressFamily = 13 /* Reserved for 802.2LLC project*/
	AF_SECURITY   AddressFamily = 14 /* Security callback pseudo AF */
	AF_KEY        AddressFamily = 15 /* PF_KEY key management API */
	AF_NETLINK    AddressFamily = 16
	AF_ROUTE      AddressFamily = AF_NETLINK /* Alias to emulate 4.4BSD */
	AF_PACKET     AddressFamily = 17         /* Packet family		*/
	AF_ASH        AddressFamily = 18         /* Ash				*/
	AF_ECONET     AddressFamily = 19         /* Acorn Econet			*/
	AF_ATMSVC     AddressFamily = 20         /* ATM SVCs			*/
	AF_RDS        AddressFamily = 21         /* RDS sockets 			*/
	AF_SNA        AddressFamily = 22         /* Linux SNA Project (nutters!) */
	AF_IRDA       AddressFamily = 23         /* IRDA sockets			*/
	AF_PPPOX      AddressFamily = 24         /* PPPoX sockets		*/
	AF_WANPIPE    AddressFamily = 25         /* Wanpipe API Sockets */
	AF_LLC        AddressFamily = 26         /* Linux LLC			*/
	AF_IB         AddressFamily = 27         /* Native InfiniBand address	*/
	AF_MPLS       AddressFamily = 28         /* MPLS */
	AF_CAN        AddressFamily = 29         /* Controller Area Network      */
	AF_TIPC       AddressFamily = 30         /* TIPC sockets			*/
	AF_BLUETOOTH  AddressFamily = 31         /* Bluetooth sockets 		*/
	AF_IUCV       AddressFamily = 32         /* IUCV sockets			*/
	AF_RXRPC      AddressFamily = 33         /* RxRPC sockets 		*/
	AF_ISDN       AddressFamily = 34         /* mISDN sockets 		*/
	AF_PHONET     AddressFamily = 35         /* Phonet sockets		*/
	AF_IEEE802154 AddressFamily = 36         /* IEEE802154 sockets		*/
	AF_CAIF       AddressFamily = 37         /* CAIF sockets			*/
	AF_ALG        AddressFamily = 38         /* Algorithm sockets		*/
	AF_NFC        AddressFamily = 39         /* NFC sockets			*/
	AF_VSOCK      AddressFamily = 40         /* vSockets			*/
	AF_KCM        AddressFamily = 41         /* Kernel Connection Multiplexor*/
	AF_QIPCRTR    AddressFamily = 42         /* Qualcomm IPC Router          */
	AF_SMC        AddressFamily = 43         /* smc sockets: reserve number for
	 * PF_SMC protocol family that
	 * reuses AF_INET address family
	 */
	AF_XDP  AddressFamily = 44 /* XDP sockets			*/
	AF_MCTP AddressFamily = 45 /* Management component
	 * transport protocol
	 */
)

func (a AddressFamily) String() string {
	switch a {
	case AF_UNSPEC:
		return "AF_UNSPEC"
	case AF_UNIX:
		return "AF_UNIX"
	case AF_INET:
		return "AF_INET"
	case AF_AX25:
		return "AF_AX25"
	case AF_IPX:
		return "AF_IPX"
	case AF_APPLETALK:
		return "AF_APPLETALK"
	case AF_NETROM:
		return "AF_NETROM"
	case AF_BRIDGE:
		return "AF_BRIDGE"
	case AF_ATMPVC:
		return "AF_ATMPVC"
	case AF_X25:
		return "AF_X25"
	case AF_INET6:
		return "AF_INET6"
	case AF_ROSE:
		return "AF_ROSE"
	case AF_DECnet:
		return "AF_DECnet"
	case AF_NETBEUI:
		return "AF_NETBEUI"
	case AF_SECURITY:
		return "AF_SECURITY"
	case AF_KEY:
		return "AF_KEY"
	case AF_NETLINK:
		return "AF_NETLINK"
	case AF_PACKET:
		return "AF_PACKET"
	case AF_ASH:
		return "AF_ASH"
	case AF_ECONET:
		return "AF_ECONET"
	case AF_ATMSVC:
		return "AF_ATMSVC"
	case AF_RDS:
		return "AF_RDS"
	case AF_SNA:
		return "AF_SNA"
	case AF_IRDA:
		return "AF_IRDA"
	case AF_PPPOX:
		return "AF_PPPOX"
	case AF_WANPIPE:
		return "AF_WANPIPE"
	case AF_LLC:
		return "AF_LLC"
	case AF_IB:
		return "AF_IB"
	case AF_MPLS:
		return "AF_MPLS"
	case AF_CAN:
		return "AF_CAN"
	case AF_TIPC:
		return "AF_TIPC"
	case AF_BLUETOOTH:
		return "AF_BLUETOOTH"
	case AF_IUCV:
		return "AF_IUCV"
	case AF_RXRPC:
		return "AF_RXRPC"
	case AF_ISDN:
		return "AF_ISDN"
	case AF_PHONET:
		return "AF_PHONET"
	case AF_IEEE802154:
		return "AF_IEEE802154"
	case AF_CAIF:
		return "AF_CAIF"
	case AF_ALG:
		return "AF_ALG"
	case AF_NFC:
		return "AF_NFC"
	case AF_VSOCK:
		return "AF_VSOCK"
	case AF_KCM:
		return "AF_KCM"
	case AF_QIPCRTR:
		return "AF_QIPCRTR"
	case AF_SMC:
		return "AF_SMC"
	case AF_XDP:
		return "AF_XDP"
	case AF_MCTP:
		return "AF_MCTP"
	default:
		return ""
	}
}

type IpProto uint16

const (
	IPPROTO_IP       IpProto = 0   /* Dummy protocol for TCP		*/
	IPPROTO_ICMP     IpProto = 1   /* Internet Control Message Protocol	*/
	IPPROTO_IGMP     IpProto = 2   /* Internet Group Management Protocol	*/
	IPPROTO_IPIP     IpProto = 4   /* IPIP tunnels (older KA9Q tunnels use 94) */
	IPPROTO_TCP      IpProto = 6   /* Transmission Control Protocol	*/
	IPPROTO_EGP      IpProto = 8   /* Exterior Gateway Protocol		*/
	IPPROTO_PUP      IpProto = 12  /* PUP protocol				*/
	IPPROTO_UDP      IpProto = 17  /* User Datagram Protocol		*/
	IPPROTO_IDP      IpProto = 22  /* XNS IDP protocol			*/
	IPPROTO_TP       IpProto = 29  /* SO Transport Protocol Class 4	*/
	IPPROTO_DCCP     IpProto = 33  /* Datagram Congestion Control Protocol */
	IPPROTO_IPV6     IpProto = 41  /* IPv6-in-IPv4 tunnelling		*/
	IPPROTO_RSVP     IpProto = 46  /* RSVP Protocol			*/
	IPPROTO_GRE      IpProto = 47  /* Cisco GRE tunnels (rfc 1701,1702)	*/
	IPPROTO_ESP      IpProto = 50  /* Encapsulation Security Payload protocol */
	IPPROTO_AH       IpProto = 51  /* Authentication Header protocol	*/
	IPPROTO_MTP      IpProto = 92  /* Multicast Transport Protocol		*/
	IPPROTO_BEETPH   IpProto = 94  /* IP option pseudo header for BEET	*/
	IPPROTO_ENCAP    IpProto = 98  /* Encapsulation Header			*/
	IPPROTO_PIM      IpProto = 103 /* Protocol Independent Multicast	*/
	IPPROTO_COMP     IpProto = 108 /* Compression Header Protocol		*/
	IPPROTO_L2TP     IpProto = 115 /* Layer 2 Tunnelling Protocol		*/
	IPPROTO_SCTP     IpProto = 132 /* Stream Control Transport Protocol	*/
	IPPROTO_UDPLITE  IpProto = 136 /* UDP-Lite (RFC 3828)			*/
	IPPROTO_MPLS     IpProto = 137 /* MPLS in IP (RFC 4023)		*/
	IPPROTO_ETHERNET IpProto = 143 /* Ethernet-within-IPv6 Encapsulation	*/
	IPPROTO_RAW      IpProto = 255 /* Raw IP packets			*/
	IPPROTO_MPTCP    IpProto = 262 /* Multipath TCP connection		*/
)

func (i IpProto) String() string {
	switch i {
	case IPPROTO_IP:
		return "IPPROTO_IP"
	case IPPROTO_ICMP:
		return "IPPROTO_ICMP"
	case IPPROTO_IGMP:
		return "IPPROTO_IGMP"
	case IPPROTO_IPIP:
		return "IPPROTO_IPIP"
	case IPPROTO_TCP:
		return "IPPROTO_TCP"
	case IPPROTO_EGP:
		return "IPPROTO_EGP"
	case IPPROTO_PUP:
		return "IPPROTO_PUP"
	case IPPROTO_UDP:
		return "IPPROTO_UDP"
	case IPPROTO_IDP:
		return "IPPROTO_IDP"
	case IPPROTO_TP:
		return "IPPROTO_TP"
	case IPPROTO_DCCP:
		return "IPPROTO_DCCP"
	case IPPROTO_IPV6:
		return "IPPROTO_IPV6"
	case IPPROTO_RSVP:
		return "IPPROTO_RSVP"
	case IPPROTO_GRE:
		return "IPPROTO_GRE"
	case IPPROTO_ESP:
		return "IPPROTO_ESP"
	case IPPROTO_AH:
		return "IPPROTO_AH"
	case IPPROTO_MTP:
		return "IPPROTO_MTP"
	case IPPROTO_BEETPH:
		return "IPPROTO_BEETPH"
	case IPPROTO_ENCAP:
		return "IPPROTO_ENCAP"
	case IPPROTO_PIM:
		return "IPPROTO_PIM"
	case IPPROTO_COMP:
		return "IPPROTO_COMP"
	case IPPROTO_L2TP:
		return "IPPROTO_L2TP"
	case IPPROTO_SCTP:
		return "IPPROTO_SCTP"
	case IPPROTO_UDPLITE:
		return "IPPROTO_UDPLITE"
	case IPPROTO_MPLS:
		return "IPPROTO_MPLS"
	case IPPROTO_ETHERNET:
		return "IPPROTO_ETHERNET"
	case IPPROTO_RAW:
		return "IPPROTO_RAW"
	case IPPROTO_MPTCP:
		return "IPPROTO_MPTCP"
	default:
		return ""
	}
}

type netlinkProto uint16

const (
	NETLINK_ROUTE          netlinkProto = 0 /* Routing/device hook				*/
	NETLINK_UNUSED         netlinkProto = 1 /* Unused number				*/
	NETLINK_USERSOCK       netlinkProto = 2 /* Reserved for user mode socket protocols 	*/
	NETLINK_FIREWALL       netlinkProto = 3 /* Unused number, formerly ip_queue		*/
	NETLINK_SOCK_DIAG      netlinkProto = 4 /* socket monitoring				*/
	NETLINK_NFLOG          netlinkProto = 5 /* netfilter/iptables ULOG */
	NETLINK_XFRM           netlinkProto = 6 /* ipsec */
	NETLINK_SELINUX        netlinkProto = 7 /* SELinux event notifications */
	NETLINK_ISCSI          netlinkProto = 8 /* Open-iSCSI */
	NETLINK_AUDIT          netlinkProto = 9 /* auditing */
	NETLINK_FIB_LOOKUP     netlinkProto = 10
	NETLINK_CONNECTOR      netlinkProto = 11
	NETLINK_NETFILTER      netlinkProto = 12 /* netfilter subsystem */
	NETLINK_IP6_FW         netlinkProto = 13
	NETLINK_DNRTMSG        netlinkProto = 14 /* DECnet routing messages (obsolete) */
	NETLINK_KOBJECT_UEVENT netlinkProto = 15 /* Kernel messages to userspace */
	NETLINK_GENERIC        netlinkProto = 16
	/* leave room for NETLINK_DM (DM Events) */
	NETLINK_SCSITRANSPORT netlinkProto = 18 /* SCSI Transports */
	NETLINK_ECRYPTFS      netlinkProto = 19
	NETLINK_RDMA          netlinkProto = 20
	NETLINK_CRYPTO        netlinkProto = 21 /* Crypto layer */
	NETLINK_SMC           netlinkProto = 22 /* SMC monitoring */
)

func (n netlinkProto) String() string {
	switch n {
	case NETLINK_ROUTE:
		return "NETLINK_ROUTE"
	case NETLINK_UNUSED:
		return "NETLINK_UNUSED"
	case NETLINK_USERSOCK:
		return "NETLINK_USERSOCK"
	case NETLINK_FIREWALL:
		return "NETLINK_FIREWALL"
	case NETLINK_SOCK_DIAG:
		return "NETLINK_SOCK_DIAG"
	case NETLINK_NFLOG:
		return "NETLINK_NFLOG"
	case NETLINK_XFRM:
		return "NETLINK_XFRM"
	case NETLINK_SELINUX:
		return "NETLINK_SELINUX"
	case NETLINK_ISCSI:
		return "NETLINK_ISCSI"
	case NETLINK_AUDIT:
		return "NETLINK_AUDIT"
	case NETLINK_FIB_LOOKUP:
		return "NETLINK_FIB_LOOKUP"
	case NETLINK_CONNECTOR:
		return "NETLINK_CONNECTOR"
	case NETLINK_NETFILTER:
		return "NETLINK_NETFILTER"
	case NETLINK_IP6_FW:
		return "NETLINK_IP6_FW"
	case NETLINK_DNRTMSG:
		return "NETLINK_DNRTMSG"
	case NETLINK_KOBJECT_UEVENT:
		return "NETLINK_KOBJECT_UEVENT"
	case NETLINK_GENERIC:
		return "NETLINK_GENERIC"
	case NETLINK_SCSITRANSPORT:
		return "NETLINK_SCSITRANSPORT"
	case NETLINK_ECRYPTFS:
		return "NETLINK_ECRYPTFS"
	case NETLINK_RDMA:
		return "NETLINK_RDMA"
	case NETLINK_CRYPTO:
		return "NETLINK_CRYPTO"
	case NETLINK_SMC:
		return "NETLINK_SMC"
	default:
		return ""
	}
}

type SockState uint8

const (
	TCP_ESTABLISHED SockState = 1 + iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING /* Now a valid state */
	TCP_NEW_SYN_RECV
	TCP_BOUND_INACTIVE /* Pseudo-state for inet_diag */
)

func (t SockState) String() string {
	switch t {
	case TCP_ESTABLISHED:
		return "ESTABLISHED"
	case TCP_SYN_SENT:
		return "SYN_SENT"
	case TCP_SYN_RECV:
		return "SYN_RECV"
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1"
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2"
	case TCP_TIME_WAIT:
		return "TIME_WAIT"
	case TCP_CLOSE:
		return "CLOSE"
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case TCP_LAST_ACK:
		return "LAST_ACK"
	case TCP_LISTEN:
		return "LISTEN"
	case TCP_CLOSING:
		return "CLOSING"
	case TCP_NEW_SYN_RECV:
		return "NEW_SYN_RECV"
	case TCP_BOUND_INACTIVE:
		return "BOUND_INACTIVE"
	default:
		return ""
	}
}

type Meta struct {
	Addrs    [8]byte
	Dport    [2]byte
	PortNum  uint16
	Netns    uint32
	Family   uint16
	Protocol uint16
}

type SockCommon struct {
	State        uint8
	ReusePort    uint8
	Pad          [2]uint8
	BoundIfindex uint32
}

type SockInfo struct {
	RxDstIfindex uint32
	BacklogLen   uint32
	RcvBuff      uint32
	SndBuff      uint32
	Priority     uint32
	Mark         uint32
	Type         uint16
	Pad          uint16
}

type SocketInfo struct {
	State     uint16
	Type      uint16
	Pad       uint32
	FileInode uint64
	Flags     uint64
}

type StackData struct {
	IPs [MaxStackDepth]uint64
}

type Event struct {
	Pid  uint32
	Comm [16]byte
	CPU  uint32
	Addr uint64
	Meta
	SockCommon
	SockInfo
	SocketInfo
	StackID int64
}

const (
	SizeofEvent = int(unsafe.Sizeof(Event{}))
)

type Config struct {
	Pid      uint32
	NetNs    uint32
	Mark     uint32
	Addr     [4]byte
	PortLE   uint16
	PortBE   uint16
	Protocol uint16

	OutputSockCommon uint8
	OutputSockInfo   uint8
	OutputSocketInfo uint8
	OutputStack      uint8
	IsSet            uint8
	Pad              uint8
}

func ProcessNameString(p []int8) string {
	// 使用 reflect.StringHeader 获取底层数据的指针
	sh := reflect.StringHeader{
		Data: uintptr(unsafe.Pointer(&p[0])),
		Len:  slices.Index(p, 0),
	}
	// 将 reflect.StringHeader 转换为 string
	return *(*string)(unsafe.Pointer(&sh))
}
