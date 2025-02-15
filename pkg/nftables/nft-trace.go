package nftables

import (
	"context"
	"ebpf-nftrace/pkg/nftrace"
	"ebpf-nftrace/pkg/options"
	"ebpf-nftrace/utils/attach"
	"ebpf-nftrace/utils/errx"
	"ebpf-nftrace/utils/nft"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/dropbox/goebpf"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"unsafe"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type trace_info nftabletrace ./../../ebpf/nftrace-trace.c -- -D${TARGET_ARCH} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

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

	defer attach.AttachAll(spec, obj)()

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
			if ev.NftInfo.RuleHandle == 0 {
				continue
			}

			s := nftrace.Ip2String(ev.ConnInfo.Family == unix.NFPROTO_IPV6, ev.ConnInfo.SrcIp, ev.ConnInfo.SrcIp6.In6U.U6Addr8[:])
			d := nftrace.Ip2String(ev.ConnInfo.Family == unix.NFPROTO_IPV6, ev.ConnInfo.DestIp, ev.ConnInfo.DestIp6.In6U.U6Addr8[:])
			log.Printf(
				//"process:%-20s pid:%-6d skId:%d id:%-10d, type:%s, family:%s, tbl_name:%-6s tbl_handle:%d, chain_name:%s, chain_handle:%d, rule_handle:%-5d, verdict:%-8s, "+
				//	"jt:%-20s, nfproto:%d, policy:%s, makr:%-5d, iif:%d, iif_type:%d, iif_name:%s, oif:%d, oif_type:%d, oif_name:%s, "+
				//	"src=%-22s, dst=%-22s, proto=%s, mac-src:%s, mac-dst:%s, len=%-5d, counter=%-20d, ts=%d ns %s\n",
				"process:%s pid:%d sockId:%d type:%s, family:%s, tbl_name:%s tbl_handle:%d, "+
					"chain_name:%s, chain_handle:%d, rule_handle:%d, verdict:%-8s, "+
					"jt:%s, nfproto:%s, policy:%s, makr:%d, iif:%d, iif_type:%d, "+
					"iif_name:%s, oif:%d, oif_type:%d, oif_name:%s, "+
					"src=%s, dst=%s, proto=%s, mac-src:%s, mac-dst:%s, len=%d, %s\n",
				goebpf.NullTerminatedStringToString(ev.ProcessInfo.Name[:]),
				ev.ProcessInfo.Pid,
				ev.SkInfo.SockId,
				nftrace.TraceType(ev.NftInfo.Type),
				nftrace.NfFamily(ev.NftInfo.BaseChainFamily).String(),
				unix.ByteSliceToString(ev.NftInfo.TableName[:]),
				ev.NftInfo.TableHandle,
				unix.ByteSliceToString(ev.NftInfo.ChainName[:]),
				ev.NftInfo.ChainHandle,
				ev.NftInfo.RuleHandle,
				nftrace.Verdict(ev.NftInfo.Verdict),
				unix.ByteSliceToString(ev.NftInfo.JumpTarget[:]),
				nftrace.NfFamily(ev.NftInfo.NfProto).String(),
				nftrace.Verdict(ev.NftInfo.Policy),
				ev.NftInfo.Mark,
				ev.DevInfo.Iif,
				ev.DevInfo.IifType,
				unix.ByteSliceToString(ev.DevInfo.IifName[:]),
				ev.DevInfo.Oif,
				ev.DevInfo.OifType,
				unix.ByteSliceToString(ev.DevInfo.OifName[:]),
				fmt.Sprintf("%s:%v", s, ev.ConnInfo.SrcPort),
				fmt.Sprintf("%s:%v", d, ev.ConnInfo.DestPort),
				nftrace.IpProto(ev.ConnInfo.Protocol).String(),
				net.HardwareAddr(ev.ConnInfo.SrcMac[:]),
				net.HardwareAddr(ev.ConnInfo.DestMac[:]),
				ev.NftInfo.Len,
				fmt.Sprintf("%d", ev.ConnInfo.SkProtocol),
			)
		}
	}()
	<-ctx.Done()
}
