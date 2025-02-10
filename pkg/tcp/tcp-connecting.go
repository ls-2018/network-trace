package tcp

import (
	"bytes"
	"context"
	"ebpf-nftrace/pkg/options"
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
	"github.com/dropbox/goebpf"
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

func Run(ctx context.Context, opt options.Options) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcpconn()
	for _, _spec := range opt.Specs {
		_spec(spec)
	}
	errx.Check(err, "load tcp conn")

	obj, err := ebpf.NewCollection(spec)

	errx.CheckVerifierErr(err, "Failed to load bpf obj: %v")

	for _, _obj := range opt.Objs {
		_obj(obj)
	}

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
		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)
		var s, d string

		if dump.AddressFamily(ev.ConnInfo.Family) == dump.AF_INET6 {
			s = fmt.Sprintf("%s", net.IP(ev.ConnInfo.C_ip6.In6U.U6Addr8[:]).String())
			d = fmt.Sprintf("%s", net.IP(ev.ConnInfo.S_ip6.In6U.U6Addr8[:]).String())
		} else {
			s = fmt.Sprintf("%s", net.IP(ether.ReverseBytes((*[4]byte)(unsafe.Pointer(&ev.ConnInfo.C_ip))[:])))
			d = fmt.Sprintf("%s", net.IP(ether.ReverseBytes((*[4]byte)(unsafe.Pointer(&ev.ConnInfo.S_ip))[:])))
		}
		if s == "127.0.0.1" && d == "127.0.0.1" {
			continue
		}
		var direct = "<---->"
		switch dump.Agent(ev.Type) {
		case dump.LinkRoleUnknown:
		case dump.LinkRoleServer:
			direct = "    ->"
		case dump.LinkRoleClient:
			direct = "->    "
		}
		log.Printf(
			"process❓:%-20s pid❓:%-6d skId❓:%-20d socketId❓:%-20d %-22s%s%-22s state: %-14s -> %-14s family:%-8s proto:%s ns:%d role:%-6s Seq:%d",
			goebpf.NullTerminatedStringToString(ev.Process.Name[:]), // 不准
			ev.Process.Pid, // 不准
			ev.SkId,        // 不准
			ev.SocketId,
			fmt.Sprintf("%s:%d", s, ev.ConnInfo.C_port),
			direct,
			fmt.Sprintf("%s:%d", d, ev.ConnInfo.S_port),
			dump.SockState(ev.ConnInfo.OldState).String(),
			dump.SockState(ev.ConnInfo.NewState).String(),
			dump.AddressFamily(ev.ConnInfo.Family).String(),
			dump.IpProto(ev.ConnInfo.Protocol).String(),
			ev.ConnInfo.NetNs,
			dump.Agent(ev.Type).String(),
			ev.ConnInfo.Seq,
		)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
