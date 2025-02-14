package attach

import (
	"ebpf-nftrace/utils/errx"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"strings"
)

type Func struct {
	SectionName    string
	KernelFuncName string
	ProgramName    string
	Category       string
}

func AttachAll(spec *ebpf.CollectionSpec, obj *ebpf.Collection) func() {
	var deferClose []func()

	var fExitEntryFunc []Func
	var kProbeRetProbeFunc []Func
	var tracePoIntFunc []Func // category, kernel func name , prog name
	var rawTracePoIntFunc []Func
	var xdpFunc []Func

	for name, prog := range spec.Programs {
		ss := strings.Split(prog.SectionName, "/")
		switch ss[0] {
		case "kprobe", "kretprobe":
			kProbeRetProbeFunc = append(kProbeRetProbeFunc, Func{
				SectionName:    prog.SectionName,
				KernelFuncName: ss[1],
				ProgramName:    name,
			})
		case "fentry", "fexit":
			fExitEntryFunc = append(fExitEntryFunc, Func{
				SectionName:    prog.SectionName,
				KernelFuncName: ss[1],
				ProgramName:    name,
			})
		case "xdp":
			xdpFunc = append(xdpFunc, Func{
				SectionName:    prog.SectionName,
				KernelFuncName: ss[1],
				ProgramName:    name,
			})
		case "raw_tracepoint":
			rawTracePoIntFunc = append(rawTracePoIntFunc, Func{
				SectionName:    prog.SectionName,
				KernelFuncName: ss[1],
				ProgramName:    name,
			})
		case "tracepoint":
			tracePoIntFunc = append(tracePoIntFunc, Func{
				SectionName:    prog.SectionName,
				Category:       ss[1],
				KernelFuncName: ss[2],
				ProgramName:    name,
			})
        default:
            log.Printf("unknown sec %s", prog.SectionName)
		}
	}

	for _, info := range fExitEntryFunc {
		prog, _ := obj.Programs[info.ProgramName]
		l, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		log.Printf("attach tracing %s %v", info.KernelFuncName, l)
		errx.Check(err, "Failed to attach tracing(%s):", info.KernelFuncName)
		deferClose = append(deferClose, func() {
			l.Close()
		})
	}

	for _, info := range kProbeRetProbeFunc {
		prog, _ := obj.Programs[info.ProgramName]
		kprobe, err := link.Kprobe(info.KernelFuncName, prog, nil)
		errx.Check(err, "Failed to kprobe(%s): %v", info.KernelFuncName)
		log.Printf("kprobe %s %v", info.KernelFuncName, kprobe)
		deferClose = append(deferClose, func() {
			kprobe.Close()
		})
	}
	for _, info := range tracePoIntFunc {
		prog, _ := obj.Programs[info.ProgramName]
		tp, err := link.Tracepoint(info.Category, info.KernelFuncName, prog, nil)
		errx.Check(err, "Failed to Tracepoint(%s)", info.KernelFuncName)
		log.Printf("tracepoint %s %v", info.KernelFuncName, tp)
		deferClose = append(deferClose, func() {
			tp.Close()
		})
	}
	for _, info := range rawTracePoIntFunc {
		rawTracePoint, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    info.KernelFuncName,
			Program: obj.Programs[info.ProgramName],
		})
		errx.Check(err, "Failed to rawtracepoint(%s): %v", info.KernelFuncName)
		log.Printf("rawtracepoint %s %v", info.KernelFuncName, rawTracePoint)
		deferClose = append(deferClose, func() {
			rawTracePoint.Close()
		})
	}
	return func() {
		for _, f := range deferClose {
			fmt.Println("close")
			f()
		}
	}
}
