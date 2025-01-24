package insn

import (
	"ebpf-nftrace/pkg/errx"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/davecgh/go-spew/spew"
)

func Print(prog *ebpf.Program) {
	info, err := prog.Info()
	errx.Check(err, "Failed to get xdp prog info")
	insns, err := info.Instructions()
	errx.Check(err, "Failed to get xdp prog instructions")
	for i := range insns {
		insn := insns[i]
		fmt.Printf("%d: %+v\n", i, insn)
		spew.Dump(insn)
	}
	fmt.Println()
}
