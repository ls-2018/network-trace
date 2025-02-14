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
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dropbox/goebpf"
)

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type event_t tcpconn ./../../ebpf/tcp-link-trace.c -- -D${TARGET_ARCH} ${CUSTOM_DEFINE} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

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
		SrcIp := nftrace.Ip2String(dump.AddressFamily(ev.ConnInfo.Family) == dump.AF_INET6, ev.ConnInfo.SrcIp, ev.ConnInfo.SrcIp6.In6U.U6Addr8[:])
		DestIp := nftrace.Ip2String(dump.AddressFamily(ev.ConnInfo.Family) == dump.AF_INET6, ev.ConnInfo.DestIp, ev.ConnInfo.DestIp6.In6U.U6Addr8[:])
		if SrcIp == "127.0.0.1" && DestIp == "127.0.0.1" {
			continue
		}
		SrcPort := ev.ConnInfo.SrcPort
		DestPort := ev.ConnInfo.DestPort
		var direct = "<---->"
		switch dump.Agent(ev.ConnInfo.Role) {
		case dump.LinkRoleUnknown:
		case dump.LinkRoleServer:
			direct = "    <-"
			SrcIp, DestIp = DestIp, SrcIp
			SrcPort, DestPort = DestPort, SrcPort
		case dump.LinkRoleClient:
			direct = "->    "
			SrcIp, DestIp = SrcIp, DestIp
			SrcPort, DestPort = SrcPort, DestPort
		}

		log.Printf(
			"process:%-20s pid:%-6d sockId:%-20d %-22s%s%-22s state: %-14s -> %-14s family:%-8s proto:%s ns:%d role:%-6s loc:%d",
			goebpf.NullTerminatedStringToString(ev.Process.Name[:]), // 不准
			ev.Process.Pid, // 不准
			ev.SkInfo.SockId, // 不准
			fmt.Sprintf("%s:%v", SrcIp, SrcPort),
			direct,
			fmt.Sprintf("%s:%v", DestIp, DestPort),
			dump.SockState(ev.ConnInfo.OldState).String(),
			dump.SockState(ev.ConnInfo.NewState).String(),
			dump.AddressFamily(ev.ConnInfo.Family).String(),
			dump.IpProto(ev.ConnInfo.Protocol).String(),
			ev.ConnInfo.NetNs,
			dump.Agent(ev.ConnInfo.Role).String(),
			ev.ConnInfo.Loc,
		)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

//2025/02/13 23:47:31 process:ssh                  pid:131621 skId:18446462602095124224 192.168.33.13:0       ->    192.168.33.13:22       state: CLOSE          -> SYN_SENT       family:AF_INET  proto:IPPROTO_IP ns:4026531840 role:CLIENT loc:7
//2025/02/13 23:47:31 process:ssh                  pid:131621 skId:18446462602095124224 192.168.33.13:35538   ->    192.168.33.13:22       state: SYN_SENT       -> ESTABLISHED    family:AF_INET  proto:IPPROTO_IP ns:4026531840 role:CLIENT loc:5
//2025/02/13 23:47:31 process:ssh                  pid:131621 skId:18446462600950226432 192.168.33.13:35538       <-192.168.33.13:22       state: SYN_RECV       -> ESTABLISHED    family:AF_INET6 proto:IPPROTO_IP ns:4026531840 role:SERVER loc:6
//2025/02/13 23:47:32 process:sshd                 pid:131628 skId:18446462600950226432 192.168.33.13:35538       <-192.168.33.13:22       state: ESTABLISHED    -> CLOSE_WAIT     family:AF_INET6 proto:IPPROTO_IP ns:4026531840 role:SERVER loc:7
