package tcp

import (
	"bytes"
	"context"
	"ebpf-nftrace/utils/dump"
	"ebpf-nftrace/utils/errx"
	"ebpf-nftrace/utils/ether"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type event_t tcpconn ./../../ebpf/tcp-connecting.c -- -D__TARGET_ARCH_x86 ${CUSTOM_DEFINE} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

type Func struct {
	SectionName    string
	KernelFuncName string
	ProgramName    string
	Category       string
}

func Run(ctx context.Context) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcpconn()
	errx.Check(err, "load tcp conn")
	obj, err := ebpf.NewCollection(spec)
	errx.CheckVerifierErr(err, "Failed to load bpf obj: %v")

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
		}
	}

	defer obj.Close()
	go handlePerfEvent(ctx, obj.Maps["events"])

	for _, info := range fExitEntryFunc {
		prog, _ := obj.Programs[info.ProgramName]
		l, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		log.Printf("attach tracing %s %v", info.KernelFuncName, l)
		errx.Check(err, "Failed to attach tracing(%s):", info.KernelFuncName)
		defer l.Close()
	}

	for _, info := range kProbeRetProbeFunc {
		prog, _ := obj.Programs[info.ProgramName]
		kprobe, err := link.Kprobe(info.KernelFuncName, prog, nil)
		errx.Check(err, "Failed to kprobe(%s): %v", info.KernelFuncName)
		log.Printf("kprobe %s %v", info.KernelFuncName, kprobe)
		defer kprobe.Close()
	}
	for _, info := range tracePoIntFunc {
		prog, _ := obj.Programs[info.ProgramName]
		tp, err := link.Tracepoint(info.Category, info.KernelFuncName, prog, nil)
		errx.Check(err, "Failed to Tracepoint(%s)", info.KernelFuncName)
		log.Printf("tracepoint %s %v", info.KernelFuncName, tp)
		defer tp.Close()
	}
	for _, info := range rawTracePoIntFunc {
		rawTracePoint, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    info.KernelFuncName,
			Program: obj.Programs[info.ProgramName],
		})
		errx.Check(err, "Failed to rawtracepoint(%s): %v", info.KernelFuncName)
		log.Printf("rawtracepoint %s %v", info.KernelFuncName, rawTracePoint)
		defer rawTracePoint.Close()
	}
	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := ringbuf.NewReader(events)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading perf-event: %v", err)
		}
		ev := tcpconnEventT{}

		//if event.Remaining != 0 {
		//	log.Printf("Remaining %d events", event.Remaining/int(unsafe.Sizeof(ev)))
		//}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		//s := fmt.Sprintf("%s", net.IP(ether.ReverseBytes(ev.C_ip[:])))
		//d := fmt.Sprintf("%s", net.IP(ether.ReverseBytes(ev.S_ip[:])))
		var s, d string

		if dump.AddressFamily(ev.Family) == dump.AF_INET6 {
			s = fmt.Sprintf("%s", net.IP(ev.C_ip6[:]).String())
			d = fmt.Sprintf("%s", net.IP(ev.S_ip6[:]).String())
		} else {
			s = fmt.Sprintf("%s", net.IP(ether.ReverseBytes((*[4]byte)(unsafe.Pointer(&ev.C_ip))[:])))
			d = fmt.Sprintf("%s", net.IP(ether.ReverseBytes((*[4]byte)(unsafe.Pointer(&ev.S_ip))[:])))
		}
		if s == "127.0.0.1" && d == "127.0.0.1" {
			continue
		}
		log.Printf(
			"skId:%-20d %-22s -> %-22s state: %-14s -> %-14s family:%-8s proto:%s ns:%d role:%-6s Seq:%d",
			ev.SkId,
			fmt.Sprintf("%s:%d", s, ev.C_port),
			fmt.Sprintf("%s:%d", d, ev.S_port),
			dump.SockState(ev.OldState).String(),
			dump.SockState(ev.NewState).String(),
			dump.AddressFamily(ev.Family).String(),
			dump.IpProto(ev.Protocol).String(),
			ev.NetNs,
			dump.Agent(ev.Type).String(),
			ev.Seq,
		)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
