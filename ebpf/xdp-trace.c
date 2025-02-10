#include "bpf_all.h"
#include "lib_xdp_tc.h"
#include "define/if_ether.h"
#include "define/icmp.h"

#define MAGIC 0xFEDCBA98
#define MAX_MAP_ENTRIES 100

struct conn_track {
    u64 s_ip;
    u64 d_ip;
    u32 s_port;
    u32 d_port;
};

struct flow_count {
    struct bpf_spin_lock lock;
    u64 pkt_cnt;
    u64 pkt_byte;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_track);
    __type(value, struct flow_count);
    __uint(max_entries, MAX_MAP_ENTRIES);
} xdp_stats_map SEC(".maps");

static __always_inline void parse_ipv4_src_addr(struct xdp_md *ctx)
{
    __u32 *val;
    const int siz = sizeof(*val);

    if (bpf_xdp_adjust_meta(ctx, -siz) != 0)
        return;

    void *data = ctx_ptr(ctx, data); // required to re-obtain data pointer
    void *data_meta = ctx_ptr(ctx, data_meta);

    val = (typeof(val))data_meta;
    if ((void *)(val + 1) > data)
        return;

    *val = MAGIC;
}

SEC("xdp")
int trace_packets(struct xdp_md *ctx)
{

    struct ethhdr *eth = (struct ethhdr *)ctx_ptr(ctx, data);
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    // struct icmphdr *icmph = (struct icmphdr *)(iph + 1); //icmp、tcp、udp
    struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);
    struct udphdr *udp = (void *)iph + sizeof(struct iphdr);

    struct conn_track ct;

    if ((void *)(__u64)(eth + 1) > ctx_ptr(ctx, data_end)) {
        return XDP_PASS;
    }

    if ((void *)(__u64)(iph + 1) > ctx_ptr(ctx, data_end)) {
        return XDP_PASS;
    } else {
        u16 src_port;
        u16 dest_port;
        switch (iph->protocol) {
            case IPPROTO_TCP:
                if ((void *)(tcp + 1) > ctx_ptr(ctx, data_end)) {
                    return XDP_PASS;
                }
                src_port = tcp->source;
                dest_port = tcp->dest;
                break;
            case IPPROTO_UDP:
                if ((void *)(udp + 1) > ctx_ptr(ctx, data_end)) {
                    return XDP_PASS;
                }
                src_port = udp->source;
                dest_port = udp->dest;
                break;
            default:
                return XDP_PASS;
                break;
        }

        ct.s_ip = bpf_ntohl(iph->saddr);
        ct.d_ip = bpf_ntohl(iph->daddr);
        ct.s_port = bpf_ntohs(src_port);
        ct.d_port = bpf_ntohs(dest_port);
    };
    //    bpf_debug_printk("eth proto : %d ", bpf_ntohs(eth->h_proto)); // ETH_P_IP
    //    bpf_debug_printk("iphdr      tos: %d", iph->tos);
    //    bpf_debug_printk("iphdr  tot_len: %d", bpf_ntohs(iph->tot_len));
    //    bpf_debug_printk("iphdr       id: %d", bpf_ntohs(iph->id));
    //    bpf_debug_printk("iphdr frag_off: %d", bpf_ntohs(iph->frag_off));
    //    bpf_debug_printk("iphdr      ttl: %d", iph->ttl);

    //    struct flow_count *stat = bpf_map_lookup_elem(&xdp_stats_map, &ct);
    //    if (stat) {
    //        guard_spinlock(&stat->lock);
    //        stat->pkt_byte += (u64)(ctx->data_end - ctx->data);
    //        __sync_fetch_and_add(&stat->pkt_cnt, 1);
    //    }
    return XDP_PASS;
}

__noinline int stub_handler(struct xdp_md *ctx)
{
    volatile int retval = XDP_ABORTED; // 入栈
    // bpf_tail_call_static(ctx, &prog_array, 0); // 结果放入当前栈
    return retval; // 读栈,放入r0
}

SEC("xdp")
int xdp_f2(struct xdp_md *ctx)
{
    __u32 *val;
    // Note: do not bpf_xdp_adjust_meta again.
    void *data_meta = ctx_ptr(ctx, data_meta);
    void *data = ctx_ptr(ctx, data);

    val = (typeof(val))data_meta;
    if ((void *)(val + 1) > data)
        return XDP_PASS;

    if (*val == MAGIC)
        bpf_debug_printk("xdp tailcall \n");

    return XDP_PASS;
}

static __always_inline void handle_xdp(void *ctx, struct xdp_buff *xdp, int verdict, bool is_fexit)
{
    struct ethhdr *eth = (void *)(long)BPF_CORE_READ(xdp, data);
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > (void *)(long)BPF_CORE_READ(xdp, data_end))
        return;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return;

    __handle_packet(ctx, iph, is_fexit ? PROBE_TYPE_FEXIT : PROBE_TYPE_FENTRY, verdict);
}

// SEC("fentry/xdp")
// int BPF_PROG(fentry_xdp, struct xdp_buff *xdp)
//{
//     handle_xdp(ctx, xdp, 0, false);
//     return 0;
// }
//
// SEC("fexit/xdp")
// int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int verdict)
//{
//     handle_xdp(ctx, xdp, verdict, true);
//     return 0;
// }

// bpf_tail_call_static(ctx, &xdp_progs, 0);
// bpf_xdp_adjust_tail
// bpf_xdp_adjust_head
// bpf_redirect_map(&xdp_sockets, 0, 0);
// bpf_loop
// __builtin_memcpy