package tcp

import (
	"bytes"
	"context"
	"ebpf-nftrace/pkg/nftrace"
	"ebpf-nftrace/pkg/options"
	"ebpf-nftrace/utils/attach"
	"ebpf-nftrace/utils/dump"
	"ebpf-nftrace/utils/errx"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dropbox/goebpf"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type event_t tcpconn ./../../ebpf/tcp-trace.c -- -D__TARGET_ARCH_x86 ${CUSTOM_DEFINE} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

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

	defer obj.Close()

	errx.CheckVerifierErr(err, "Failed to load bpf obj: %v")

	for _, _obj := range opt.Objs {
		_obj(obj)
	}
	defer attach.AttachAll(spec, obj)()
	go handlePerfEvent(ctx, obj.Maps["events"])

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
		d := nftrace.Ip2String(dump.AddressFamily(ev.ConnInfo.Family) == dump.AF_INET6, ev.ConnInfo.S_ip, ev.ConnInfo.S_ip6.In6U.U6Addr8[:])
		s := nftrace.Ip2String(dump.AddressFamily(ev.ConnInfo.Family) == dump.AF_INET6, ev.ConnInfo.C_ip, ev.ConnInfo.C_ip6.In6U.U6Addr8[:])
		if s == "127.0.0.1" && d == "127.0.0.1" {
			continue
		}
		var direct = "<---->"
		switch dump.Agent(ev.ConnInfo.Role) {
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
			ev.SkInfo.SkId, // 不准
			ev.SocketInfo.SocketId,
			fmt.Sprintf("%s:%v", s, ev.ConnInfo.C_port),
			direct,
			fmt.Sprintf("%s:%v", d, ev.ConnInfo.S_port),
			dump.SockState(ev.ConnInfo.OldState).String(),
			dump.SockState(ev.ConnInfo.NewState).String(),
			dump.AddressFamily(ev.ConnInfo.Family).String(),
			dump.IpProto(ev.ConnInfo.Protocol).String(),
			ev.ConnInfo.NetNs,
			dump.Agent(ev.ConnInfo.Role).String(),
			ev.ConnInfo.Seq,
		)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
