package tcp

import (
	"bytes"
	"context"
	"ebpf-nftrace/pkg/xdp"
	"ebpf-nftrace/utils/dump"
	"ebpf-nftrace/utils/errx"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type event_t tcpconn ./../../ebpf/tcp-connecting.c -- -D__TARGET_ARCH_x86 ${CUSTOM_DEFINE} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

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

	var fExitEntryFunc []string
	var kprobeFunc []string
	var tracePoIntFunc []string
	for name, _ := range spec.Programs {
		if strings.HasPrefix(name, "f") {
			fExitEntryFunc = append(fExitEntryFunc, name)
		}
		if strings.HasPrefix(name, "k") {
			kprobeFunc = append(kprobeFunc, name)
		}
		if strings.HasPrefix(name, "tp") {
			tracePoIntFunc = append(tracePoIntFunc, name)
		}
	}

	defer obj.Close()
	go handlePerfEvent(ctx, obj.Maps["events"])

	for _, name := range fExitEntryFunc {
		prog, ok := obj.Programs[name]
		if !ok {
			log.Fatalf("failed to get program: %s", err)
		}
		l, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		log.Printf("attach tracing %s %v", name, l)
		errx.Check(err, "Failed to attach tracing(%s):", name)
		defer l.Close()
	}

	for _, name := range kprobeFunc {
		prog, ok := obj.Programs[name]
		if !ok {
			log.Fatalf("failed to get program: %s", err)
		}
		errx.Check(err, "create prog %s", name)
		kName := strings.TrimLeft(name, "k_")
		kprobe, err := link.Kprobe(kName, prog, nil)
		errx.Check(err, "Failed to kprobe(%s): %v", kName)
		log.Printf("kprobe %s %v", name, kprobe)
		defer kprobe.Close()
	}
	for _, rawName := range tracePoIntFunc {
		prog, ok := obj.Programs[rawName]
		traceGroup := strings.SplitN(spec.Programs[rawName].SectionName, "/", 3)
		if len(traceGroup) != 3 {
			log.Fatalf("/ size is not 3 : %s", rawName)
		}
		category := traceGroup[1]
		name := traceGroup[2]
		if !ok {
			log.Fatalf("failed to get program: %s", err)
		}
		tp, err := link.Tracepoint(category, name, prog, nil)
		errx.Check(err, "Failed to Tracepoint(%s)", rawName)
		log.Printf("Tracepoint %s %v", spec.Programs[rawName].SectionName, tp)
		defer tp.Close()
	}

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := ringbuf.NewReader(events)
	//eventReader, err := perf.NewReader(events, 4096)
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

		if event.Remaining != 0 {
			//log.Printf("Remaining %d events", event.Remaining/int(unsafe.Sizeof(ev)))
		}
		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)
		s := fmt.Sprintf("%s", xdp.IntToIP(binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&ev.Saddr))[:])))
		d := fmt.Sprintf("%s", xdp.IntToIP(binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&ev.Daddr))[:])))
		direction := ""
		if ev.Type < 0 {
			direction = "<-"
		} else if ev.Type > 0 {
			direction = "->"
		} else {
			direction = "<--->"
		}
		if s == "127.0.0.1" && d == "127.0.0.1" {
			continue
		}

		log.Printf(
			"new tcp connection: %s:%d %s %s:%d state: %s->%s %s family:%s proto:%s ns:%d type:%d",
			s, ev.Sport,
			direction,
			d, ev.Dport,
			dump.SockState(ev.Oldstate).String(),
			dump.SockState(ev.Newstate).String(),
			dump.SockState(ev.State).String(),
			dump.AddressFamily(ev.Family).String(),
			dump.IpProto(ev.Protocol).String(),
			ev.Netns,
			ev.Type,
		)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
