package nftables

import (
	"context"
	"ebpf-nftrace/pkg/nftrace"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"unsafe"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang -type trace_info nftabletrace ./../../ebpf/nftrace_perf.c -- -D__TARGET_ARCH_x86 -I./../../ebpf/headers -Wall -Wall -Wno-unused-variable

func Run(ctx context.Context) {
	for _, module := range nftrace.RequiredKernelModules {
		ok, err := nftrace.IsKernelModuleLoaded(module)
		if err != nil {
			log.Fatalf("failed to determine if kernel module %s is loaded: %v", module, err)
		}
		if !ok {
			log.Fatalf("kernel module '%s' is not loaded", module)
		}
	}

	objs := nftabletraceObjects{}
	if err := loadNftabletraceObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	kp, err := link.Kprobe("__nft_trace_packet", objs.KprobeNftTracePacket, nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Printf("hook __nft_trace_packet: %v\n", kp)
	defer kp.Close()

	go func() {
		reader, err := ringbuf.NewReader(objs.nftabletraceMaps.Events)
		if err != nil {
			log.Fatalf("failed to create nftrace reader: %v", err)
		}
		i := uint64(0)
		cnt := uint64(0)
		for {
			record, err := reader.Read()
			if err != nil {
				log.Fatalf("failed to read nftrace record: %v", err)
			}
			if len(record.RawSample) == 0 {
				log.Println("Empty RawSample received")
				continue
			}
			event := *(*nftabletraceTraceInfo)(unsafe.Pointer(&record.RawSample[0]))
			i += 1
			log.Printf(
				"i: %d, sum: %d, id: %d, type: %s, family: %s, tbl name: %s tbl handle: %d, chain name: %s, chain handle: %d, rule handle: %d, verdict: %s, "+
					"jt: %s, nfproto: %d, policy: %s, makr: %d, iif: %d, iif_type: %d, iif_name: %s, oif: %d, oif_type: %d, oif_name: %s, "+
					"src=%s:%d, dst=%s:%d, proto=%s, mac-src: %s, mac-dst: %s, len=%d, counter=%d, ts=%d ns\n",
				i,
				cnt,
				event.Id,
				nftrace.TraceType(event.Type),
				nftrace.FamilyTable(event.Family),
				unix.ByteSliceToString(event.TableName[:]),
				event.TableHandle,
				unix.ByteSliceToString(event.ChainName[:]),
				event.ChainHandle,
				event.RuleHandle,
				nftrace.Verdict(event.Verdict),
				unix.ByteSliceToString(event.JumpTarget[:]),
				event.Nfproto,
				nftrace.Verdict(event.Policy),
				event.Mark,
				event.Iif,
				event.IifType,
				unix.ByteSliceToString(event.IifName[:]),
				event.Oif,
				event.OifType,
				unix.ByteSliceToString(event.OifName[:]),
				nftrace.Ip2String(event.Family == unix.NFPROTO_IPV6, event.SrcIp, event.SrcIp6.In6U.U6Addr8[:]),
				event.SrcPort,
				nftrace.Ip2String(event.Family == unix.NFPROTO_IPV6, event.DstIp, event.DstIp6.In6U.U6Addr8[:]),
				event.DstPort,
				nftrace.IpProto(event.IpProto),
				net.HardwareAddr(event.SrcMac[:]),
				net.HardwareAddr(event.DstMac[:]),
				event.Len,
				event.Counter,
				event.Time,
			)
		}
	}()
	<-ctx.Done()
}
