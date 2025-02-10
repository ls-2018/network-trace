package nftables

import (
	"context"
	"ebpf-nftrace/pkg/nftrace"
	"ebpf-nftrace/pkg/options"
	"ebpf-nftrace/utils/dump"
	"ebpf-nftrace/utils/errx"
	"ebpf-nftrace/utils/nft"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"unsafe"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type trace_info nftabletrace ./../../ebpf/nftrace-trace.c -- -D__TARGET_ARCH_x86 -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

func Run(ctx context.Context, opt options.Options) {
	nft.Add()
	defer nft.Remove()
	for _, module := range nftrace.RequiredKernelModules {
		ok, err := nftrace.IsKernelModuleLoaded(module)
		if err != nil {
			log.Fatalf("failed to determine if kernel module %s is loaded: %v", module, err)
		}
		if !ok {
			log.Fatalf("kernel module '%s' is not loaded", module)
		}
	}
	spec, err := loadNftabletrace()
	for _, _spec := range opt.Specs {
		_spec(spec)
	}
	co := ebpf.CollectionOptions{}
	for _, _co := range opt.CollectionOptions {
		_co(&co)
	}
	errx.Check(err, "loadNfTableTrace")
	obj, err := ebpf.NewCollectionWithOptions(spec, co)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	for _, _obj := range opt.Objs {
		_obj(obj)
	}
	kp, err := link.Kprobe("__nft_trace_packet", obj.Programs["kprobe_nft_trace_packet"], nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Printf("hook __nft_trace_packet: %v\n", kp)
	defer kp.Close()

	go func() {
		reader, err := ringbuf.NewReader(obj.Maps["events"])
		if err != nil {
			log.Fatalf("failed to create nftrace reader: %v", err)
		}
		for {
			record, err := reader.Read()
			if err != nil {
				log.Fatalf("failed to read nftrace record: %v", err)
			}
			if len(record.RawSample) == 0 {
				log.Println("Empty RawSample received")
				continue
			}
			ev := *(*nftabletraceTraceInfo)(unsafe.Pointer(&record.RawSample[0]))

			log.Printf(
				"process:%-20s pid:%-6d skId:%d id:%-10d, type:%s, family:%s, tbl name:%-6s tbl_handle:%d, chain_name:%s, chain_handle:%d, rule_handle:%-5d, verdict:%-8s, "+
					"jt:%-20s, nfproto:%d, policy:%s, makr:%-5d, iif:%d, iif_type:%d, iif_name:%s, oif:%d, oif_type:%d, oif_name:%s, "+
					"src=%-22s, dst=%-22s, proto=%s, mac-src:%s, mac-dst:%s, len=%-5d, counter=%-20d, ts=%d ns\n",
				dump.ProcessNameString(ev.ProcessInfo.Name[:]),
				ev.ProcessInfo.Pid,
				ev.SkId,
				ev.Id,
				nftrace.TraceType(ev.NftInfo.Type),
				nftrace.FamilyTable(ev.Family),
				unix.ByteSliceToString(ev.NftInfo.TableName[:]),
				ev.NftInfo.TableHandle,
				unix.ByteSliceToString(ev.NftInfo.ChainName[:]),
				ev.NftInfo.ChainHandle,
				ev.NftInfo.RuleHandle,
				nftrace.Verdict(ev.NftInfo.Verdict),
				unix.ByteSliceToString(ev.NftInfo.JumpTarget[:]),
				ev.NftInfo.NfProto,
				nftrace.Verdict(ev.NftInfo.Policy),
				ev.NftInfo.Mark,
				ev.Iif,
				ev.IifType,
				unix.ByteSliceToString(ev.IifName[:]),
				ev.Oif,
				ev.OifType,
				unix.ByteSliceToString(ev.OifName[:]),
				fmt.Sprintf(
					"%s:%v",
					nftrace.Ip2String(ev.Family == unix.NFPROTO_IPV6, ev.ConnInfo.C_ip, ev.ConnInfo.C_ip6.In6U.U6Addr8[:]),
					ev.ConnInfo.C_port,
				),
				fmt.Sprintf(
					"%s:%v",
					nftrace.Ip2String(ev.Family == unix.NFPROTO_IPV6, ev.ConnInfo.S_ip, ev.ConnInfo.S_ip6.In6U.U6Addr8[:]),
					ev.ConnInfo.S_port,
				),
				nftrace.IpProto(ev.ConnInfo.Protocol),
				net.HardwareAddr(ev.ConnInfo.C_mac[:]),
				net.HardwareAddr(ev.ConnInfo.D_mac[:]),
				ev.NftInfo.Len,
				ev.Counter,
				ev.Time,
			)
		}
	}()
	<-ctx.Done()
}
