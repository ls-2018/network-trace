- bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET)
-
- bpf_map_lookup_or_try_init(&tcp_timers, &key, &init_timer)
- bpf_timer_init
- bpf_timer_set_callback
- bpf_timer_start
- bpf_cancel_timer
- bpf_probe_read_kernel_str
- BPF_CORE_READ_INTO
-
- bpf_skc_to_tcp_sock                       # Dynamically cast a *sk* pointer to a *tcp_sock* pointer.
- bpf_skc_to_tcp_timewait_sock              # Dynamically cast a *sk* pointer to a *tcp_timewait_sock* pointer.
- bpf_skc_to_tcp_request_sock               # Dynamically cast a *sk* pointer to a *tcp_request_sock* pointer.
- bpf_jiffies64
- bpf_seq_printf
- bpf_printk
-
- bpf_htons
- bpf_ntohs
- bpf_ntohl(大端)
- &sk->__sk_common.skc_daddr
- bpf_tail_call_static(ctx, &progs, 0);   // static tailcall
- bpf_tail_call(ctx, &progs, idx);        // dynamic tailcall
- bpf_loop (上限次数,long 回调(__u32, struct delay_ctx *),上下文,继续执行的结果)
- bpf_for_each_map_elem
-
- binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)
- bpffs.IsMountedAt(bpffsPath)
- link.LoadPinnedLink
- netlink.LinkByName
- xdp.NewSocket
- bpf.LoadWithSpec(spec, &dataObjs)





``` tcx
SEC("tc/ingress")
int dummy(struct __sk_buff *skb)
{
    return TCX_NEXT;
}

l, err := link.AttachTCX(link.TCXOptions{
    Interface: ifi.Attrs().Index,
    Program:   obj.Dummy,
    Attach:    ebpf.AttachTCXIngress,
})



SEC("tc")
int tc_metadata(struct __sk_buff *skb) // TC_ACT_OK

tc qdisc add dev eth1 ingress
tc filter add dev eth1 ingress pref 10 protocol all bpf da obj ./tcmd_bpfel.o sec tc

```


```timer
bpf_map_lookup_or_try_init(&tcp_timers, &key, &init_timer)
bpf_timer_init(&timer->timer, &tcp_timers, CLOCK_BOOTTIME);
bpf_timer_set_callback(&timer->timer, timer_cb);
bpf_timer_start(&timer->timer, 100, 0);
```



``` const
const volatile delay_cidrs_t delay_cidrs;
const volatile __u32 delay_cidrs_len = 0;

err = spec.RewriteConstants(map[string]interface{}{
    "delay_cidrs":     cidrs,
    "delay_cidrs_len": uint32(cidrNum),
})

```


```xdp

link.AttachXDP(link.XDPOptions{
    Program:   obj.XdpFn,
    Interface: ifi.Attrs().Index,
    Flags:     link.XDPGenericMode,
})
```


```metadata

__u32 *val;
const int siz = sizeof(*val);

if (bpf_xdp_adjust_meta(ctx, -siz) != 0)
    return XDP_PASS;

data = ctx_ptr(ctx, data); // required to re-obtain data pointer
void *data_meta = ctx_ptr(ctx, data_meta);

val = (typeof(val))data_meta;
if ((void *)(val + 1) > data)
    return XDP_PASS;

*val = LATENCY_MS;
```




- https://lishiwen4.github.io/network/sk_buff


## variable

```
#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tc.h"

char _license[] SEC("license") = "GPL";

__u32 target_addr = 0xFEDCBA98;

#define target_addr_method_2 0xFEDCBA97


SEC("egress")
int filter_out(void *skb) {
    struct iphdr iph;

    if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET) < 0)
        return TC_ACT_OK;

    if (iph.protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    bpf_printk("from ebpf inject-global-var, 0x%08X -> 0x%08X, target 0x%08X   0x%08x\n", iph.saddr, iph.daddr, target_addr,target_addr_method_2);

    if (iph.daddr == target_addr)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
```
-----
```
package main

import (
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

//go:embed ebpf-inject-global-var.elf
var bpfElf []byte

func mustDo(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func must[T any](t T, err error) T {
	if err != nil {
		log.Fatalln(err)
	}
	return t
}

type entry struct {
	off uint64
	val interface{}
}

func (e *entry) get(data []byte, size uint64, bo binary.ByteOrder) {
	switch size {
	case 1:
		e.val = data[0]
	case 2:
		e.val = bo.Uint16(data[:2])
	case 4:
		e.val = bo.Uint32(data[:4])
	case 8:
		e.val = bo.Uint64(data[:8])
	default:
		e.val = int(-1)
	}
}

func (e *entry) put(data []byte, val uint32, bo binary.ByteOrder) {
	data = data[e.off:]
	switch e.val.(type) {
	case uint8:
		data[0] = byte(val)
	case uint16:
		bo.PutUint16(data[:2], uint16(val))
	case uint32:
		bo.PutUint32(data[:4], val)
	case uint64:
		bo.PutUint64(data[:8], uint64(val))
	}
}

func getEntry(f *elf.File, name string) (*entry, error) {
	syms := must(f.Symbols())
	for _, s := range syms {
		if s.Name == name {
			sect := f.Sections[s.Section]
			bs, _ := sect.Data()
			varOff := s.Value - sect.Addr

			var e entry
			e.off = sect.Offset + varOff
			e.get(bs[varOff:], s.Size, f.ByteOrder)
			return &e, nil
		}
	}
	return nil, fmt.Errorf("can't find symbol '%s'", name)
}

func attachTcEgress(ifindex int, bpfProgFd int) error {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Replace(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %d: %v\n", ifindex, err)
		return err
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	fd := uint32(bpfProgFd)
	flags := uint32(0x1)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	if err := tcnl.Filter().Replace(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()

	return nil
}

func attachBpfProg(ifindex int, data []byte) error {
	var bpfObj struct {
		Prog *ebpf.Program `ebpf:"filter_out"`
	}

	bpfSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}

	for _, prog := range bpfSpec.Programs {
		prog.Type = ebpf.SchedCLS
	}
	for _, prog := range bpfSpec.Programs {
		for i := range prog.Instructions {
			if prog.Instructions[i].Constant == 0xFEDCBA97 {
				prog.Instructions[i].Constant = int64(targetAddr)
			}
		}
	}
	if err := bpfSpec.LoadAndAssign(&bpfObj, nil); err != nil {
		return err
	}

	return attachTcEgress(ifindex, bpfObj.Prog.FD())
}

func updateElf(ip uint32) ([]byte, error) {
	elfFile, err := elf.NewFile(bytes.NewReader(bpfElf))
	if err != nil {
		return nil, err
	}

	entry, err := getEntry(elfFile, "target_addr")
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(bpfElf))
	copy(data, bpfElf)
	entry.put(data, ip, elfFile.ByteOrder)
	return data, nil
}

var targetAddr uint32 = 0

//go:generate clang -I../../../headers -O2 -g -target bpf -c inject_global_var.c -o ebpf-inject-global-var.elf
func main() {
	var targetIP, targetDev string
	flag.StringVar(&targetIP, "ip", "192.168.33.12", "target IP address")
	flag.StringVar(&targetDev, "dev", "eth1", "target device")
	flag.Parse()

	netIP := net.ParseIP(targetIP).To4()
	if netIP == nil {
		log.Fatal("invalid IP address")
	}

	ifi := must(net.InterfaceByName(targetDev))

	netNum := *(*uint32)(unsafe.Pointer(&netIP[0]))
	targetAddr = 15
	data, _ := updateElf(netNum)
	_ = attachBpfProg(ifi.Index, data)
}

```


## freplace

```
var tcObj tcpconnObjects
_ = loadTcpconnObjects(&tcObj, nil)
defer tcObj.Close()

frSpec, _ := loadFreplace()
replaceName := ``
replaceName = "stub_handler" //replaceName = "stub_handler_static"
frSpec.Programs["freplace_handler"].AttachTarget = tcObj.K_icskCompleteHashdance
frSpec.Programs["freplace_handler"].AttachTo = replaceName

var frObj freplaceObjects
_ = frSpec.LoadAndAssign(&frObj,  &ebpf.CollectionOptions{
    MapReplacements: map[string]*ebpf.Map{
        // "events": tcObj.Events,
    },
})
defer frObj.Close()

link.AttachFreplace(tcObj.K_icskCompleteHashdance, replaceName, frObj.FreplaceHandler)
link.Kprobe("inet_csk_complete_hashdance", tcObj.K_icskCompleteHashdance, nil)

------------------------------------------------------
# tcp-connecting.c
__noinline int stub_handler_static() {
    bpf_printk("freplace, stub handler static\n");
    return 0;
}

__noinline int stub_handler() {
    bpf_printk("freplace, stub handler\n");
    return 0;
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx) {
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);
    stub_handler_static();
    return stub_handler();
}

------------------------------------------------------
# freplace.c
SEC("freplace/stub_handler")
int freplace_handler() {
    bpf_printk("freplace, replaced handler\n");
    return 0;
}

```




## trace
- tc
    ```
    SEC("fexit/tc")
    int BPF_PROG(fexit_tc, struct sk_buff *skb, int verdict) {
        return 0;
    }
	
	rtnl, _ := tc.Open(&tc.Config{})
	defer rtnl.Close()
    # ----------
	rtnl.SetOption(nl.ExtendedAcknowledge, true)
	tcQdiscObj := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(ifi.Attrs().Index),
			Parent:  tc.HandleIngress,
			Info:    0,
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
		},
		Attribute: tc.Attribute{
			Kind: "ingress",   # clsact
		},
	}
	rtnl.Qdisc().Replace(&tcQdiscObj)  # tcnl.Qdisc().Add(&qdisc)
	defer rtnl.Qdisc().Delete(&tcQdiscObj)
	
	progFD := uint32(tcProg.FD())
	annotation := "dummy"
	tcFlags := uint32(tc.BpfActDirect)
	
	tcFilterObj := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(ifi.Attrs().Index),
			Handle:  0xFFFFFFF1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    10<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &progFD,
				Name:  &annotation,
				Flags: &tcFlags,
			},
		},
	}
	rtnl.Filter().Replace(&tcFilterObj)
	defer rtnl.Filter().Delete(&tcFilterObj)



- 容器ns 宿主机 ns veth 的流转
- ipvs
- host route
- host <-> host