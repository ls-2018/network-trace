package tcp

import (
	"bytes"
	"context"
	"ebpf-nftrace/pkg/errx"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -cflags="-Wunused-variable" -no-global-types tcpconn ./../../ebpf/tcp-connecting.c -- -D__TARGET_ARCH_x86 -I./../../ebpf/headers -Wall -Wno-unused-variable

func Run() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj tcpconnObjects
	errx.Check(loadTcpconnObjects(&obj, nil), "Failed to load bpf obj: %v")

	defer obj.Close()

	if kp, err := link.Kprobe("tcp_connect", obj.K_tcpConnect, nil); err != nil {
		log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(tcp_connect)")
	}

	if kp, err := link.Kprobe("inet_csk_complete_hashdance", obj.K_icskCompleteHashdance, nil); err != nil {
		log.Printf("Failed to attach kprobe(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(inet_csk_complete_hashdance)")
	}

	go handlePerfEvent(ctx, obj.Events)

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Saddr, Daddr [4]byte
		Sport, Dport uint16
		Type         uint16
	}
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)
		TypeMsg := ``
		if ev.Type == 1 {
			TypeMsg = "inet_csk_complete_hashdance"
		}
		if ev.Type == 2 {
			TypeMsg = "tcp_connect"
		}
		log.Printf("new tcp connection: %s:%d -> %s:%d TypeMsg:%s",
			netip.AddrFrom4(ev.Saddr), ev.Sport,
			netip.AddrFrom4(ev.Daddr), ev.Dport, TypeMsg)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// 	for name, prog := range coll.Programs {
//		if name == "tp_inet_sock_set_state" {
//			continue
//		}
//
//		l, err := link.AttachTracing(link.TracingOptions{
//			Program: prog,
//		})
//		errx.Check(err, "Failed to attach tracing(%s): %v", name)
//		defer l.Close()
//	}
//
//	tp, err := link.Tracepoint("sock", "inet_sock_set_state",
//		coll.Programs["tp_inet_sock_set_state"], &link.TracepointOptions{}
//	)
//	errx.Check(err, "Failed to attach tracepoint(inet_sock_set_state): %v")
//	defer tp.Close()
