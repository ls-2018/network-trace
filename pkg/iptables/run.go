package iptables

import (
	"context"
	"ebpf-nftrace/pkg/ipttrace"
	"ebpf-nftrace/utils/assert"
	"errors"
	"flag"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"log"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types iptablestrace ./../../ebpf/iptables-trace.c -- -D${TARGET_ARCH} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function
var ko string

func init() {
	flag.StringVar(&ko, "ko", "", "iptables ko file path")
}

func Run(ctx context.Context) {
	if ko == "" {
		log.Fatal("ko file path is required")
	}
	btfSpec, err := btf.LoadKernelSpec()
	assert.NoErr(err, "Failed to load kernel btf spec: %v")

	kernelModules := map[string]*btf.Spec{}
	iptBtfSpec, _ := btf.LoadKernelModuleSpec("ip_tables")
	if iptBtfSpec != nil {
		kernelModules["ip_tables"] = iptBtfSpec
	}
	nftBtfSpec, _ := btf.LoadKernelModuleSpec("nf_tables")
	if nftBtfSpec != nil {
		kernelModules["nf_tables"] = nftBtfSpec
	}

	bpfSpec, err := loadIptablestrace()
	if err != nil {
		log.Printf("Failed to load bpf spec: %v", err)
		return
	}
	err = bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": getBpfConfig(),
	})
	//err = bpfSpec.Variables["CFG"].Set(getBpfConfig())
	assert.NoErr(err, "Failed to set bpf config: %v")

	var bpfObj iptablestraceObjects
	err = bpfSpec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes:       btfSpec,
			KernelModuleTypes: kernelModules,
		},
	})
	assert.NoVerifierErr(err, "Failed to load and assign bpf objects: %v")
	defer bpfObj.Close()

	kprobeNft, err := link.Kprobe("nft_do_chain", bpfObj.K_nftDoChain, nil)
	assert.NoErr(err, "Failed to attach kprobe nft_do_chain: %v")
	defer kprobeNft.Close()

	kretprobeNft, err := link.Kretprobe("nft_do_chain", bpfObj.KrNftDoChain, nil)
	assert.NoErr(err, "Failed to attach kretprobe nft_do_chain: %v")
	defer kretprobeNft.Close()

	isHighVersion, err := ipttrace.IsIptDoTableNew(btfSpec)
	if err != nil && errors.Is(err, ipttrace.ErrNotFound) {
		log.Fatalln("ipt_do_table not found in kernel btf spec")
	}
	assert.NoErr(err, "Failed to check ipt_do_table btf spec: %v")

	if err := insmod(ko, isHighVersion, bpfObj.K_iptDoTable, bpfObj.KrIptDoTable, bpfObj.K_nfLogTrace); err != nil {
		log.Printf("Failed to insmod: %v", err)
		return
	}
	defer func() {
		unpinAll(bpfObj.K_iptDoTable, bpfObj.KrIptDoTable, bpfObj.K_nfLogTrace)

		select {
		case <-ctx.Done():
		default:
			if err := rmmod(); err != nil {
				log.Printf("Failed to rmmod iptables-trace: %v\nPlease run `sudo rmmod iptables-trace` by hand!", err)
			}
		}
	}()
	<-ctx.Done()
}

type BpfConfig struct {
	NetNS  uint32
	Pid    uint32
	IP     uint32
	Port   uint16
	IcmpID uint16
	Proto  uint8
	Pad    [3]uint8
}

func getBpfConfig() BpfConfig {
	return BpfConfig{}
}
