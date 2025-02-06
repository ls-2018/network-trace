package xdp

import (
	"context"
	"ebpf-nftrace/utils/assert"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"os"
)

var (
	iFaceName string
	mode      int
	logger    *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "xdp", log.Ltime|log.Lshortfile)
	flag.StringVar(&iFaceName, "iface", "eth1", "eth interface name")
	flag.IntVar(&mode, "xdpMode", 2, fmt.Sprintf("xdp attach mode: generic:%d,driver:%d,offload:%d", link.XDPGenericMode, link.XDPDriverMode, link.XDPOffloadMode))
}

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types xdptrace ./../../ebpf/xdp-trace.c -- -D__TARGET_ARCH_x86 -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function
func Run(ctx context.Context) {
	ifi, err := net.InterfaceByName(iFaceName)
	if err != nil {
		logger.Fatalf("network iface lookup for %q: %s", iFaceName, err)
	}

	obj := xdptraceObjects{}
	err = loadXdptraceObjects(&obj, nil)
	assert.NoVerifierErr(err, "loadXdptraceObjects")
	opt := link.XDPOptions{
		Program:   obj.TracePackets,
		Interface: ifi.Index,
		Flags:     link.XDPGenericMode,
	}
	xdp, err := link.AttachXDP(opt)
	if err != nil {
		logger.Fatalln(err)
	}
	defer xdp.Close()
	<-ctx.Done()
}
