
#include "bpf_all.h"
#include "lib_xdp_tc.h"
#include "define/if_ether.h"
#include "define/icmp.h"

#define MAGIC 0xFEDCBA98

volatile const __u32 MY_ADDR = 0;

struct xdp_stat_item {
    u64 pkt_cnt;
    u64 pkt_byte;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct xdp_stat_item);
    __uint(max_entries, 1);
} stats SEC(".maps");

static __always_inline int trim_payload(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, __u64 *icmp_payload)
{
    int pkt_len = ctx->data_end - ctx->data;
    int trim_size;
    int payload_len, iph_len = sizeof(*iph);
    struct icmphdr *icmph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    bool move_hdr = iph->ihl != 5;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            payload_len = iph_len + sizeof(struct tcphdr);

            if (move_hdr) {
                tcph = (struct tcphdr *)((void *)iph + (iph->ihl << 2));
                if ((void *)(__u64)(tcph + 1) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;
                if ((void *)(__u64)(iph + 1) + sizeof(*tcph) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;

                __builtin_memcpy(iph + 1, tcph, sizeof(*tcph));
            }
            break;

        case IPPROTO_UDP:
            payload_len = iph_len + sizeof(struct udphdr);

            if (move_hdr) {
                udph = (struct udphdr *)((void *)iph + (iph->ihl << 2));
                if ((void *)(__u64)(udph + 1) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;
                if ((void *)(__u64)(iph + 1) + sizeof(*udph) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;

                __builtin_memcpy(iph + 1, udph, sizeof(*udph));
            }
            break;

        case IPPROTO_ICMP:
            payload_len = iph_len + sizeof(struct icmphdr);

            if (move_hdr) {
                icmph = (struct icmphdr *)((void *)iph + (iph->ihl << 2));
                if ((void *)(__u64)(icmph + 1) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;
                if ((void *)(__u64)(iph + 1) + sizeof(*icmph) > ctx_ptr(ctx, data_end))
                    return XDP_PASS;

                __builtin_memcpy(iph + 1, icmph, sizeof(*icmph));
            }
            break;

        default:
            return XDP_PASS;
    }

    *icmp_payload = payload_len;
    trim_size = pkt_len - sizeof(*eth) - payload_len;
    if (trim_size < 0)
        return XDP_PASS;

    if (trim_size > 0 && bpf_xdp_adjust_tail(ctx, -trim_size))
        return XDP_PASS;

    return 0;
}

static __always_inline int expand_icmp_headroom(struct xdp_md *ctx)
{
    const int siz = (sizeof(struct iphdr) + sizeof(struct icmphdr));

    return bpf_xdp_adjust_head(ctx, -siz);
}

static __always_inline int encode_icmp_packet(struct xdp_md *ctx, struct ethhdr *org_eth, __u64 icmp_payload, __u32 sip, __u16 id)
{
    struct ethhdr *eth = (struct ethhdr *)ctx_ptr(ctx, data);
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

    if ((void *)(__u64)(icmph + 1) + icmp_payload > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    __builtin_memcpy(eth->h_dest, org_eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, org_eth->h_dest, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0x2b; // Custom TOS to identify the packet.
    iph->tot_len = bpf_htons(sizeof(*iph) + sizeof(*icmph) + icmp_payload);
    iph->id = id;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = MY_ADDR;
    iph->daddr = sip;
    __update_ip_checksum(iph);

    icmph->type = ICMP_TIME_EXCEEDED;
    icmph->code = ICMP_EXC_TTL;
    icmph->un.gateway = 0;
    __update_icmp_checksum(icmph, sizeof(*icmph) + icmp_payload);

    return XDP_TX;
}

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
    return;
}

SEC("xdp")
int trace_xdp_packets(struct xdp_md *ctx)
{
    struct ethhdr *eth = ctx_ptr(ctx, data);
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct xdp_stat_item *stat;
    u32 key = 0;
    __u64 icmp_payload;
    parse_ipv4_src_addr(ctx);

    stat = (typeof(stat))bpf_map_lookup_elem(&stats, &key);
    if (stat) {
        guard_spinlock(&stat->lock);
        stat->pkt_cnt++;
        stat->pkt_byte += (u64)(ctx->data_end - ctx->data);
    }

    bpf_printk("proto %d", bpf_htons(ETH_P_IP));
    struct ethhdr *copied;
    __builtin_memcpy(&copied, eth, sizeof(copied));
    if (trim_payload(ctx, eth, iph, &icmp_payload))
        return XDP_PASS;

    if (expand_icmp_headroom(ctx))
        return XDP_PASS;

    return encode_icmp_packet(ctx, &copied, icmp_payload, iph->saddr, iph->id);
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
        bpf_printk("xdp tailcall \n");

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

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp)
{
    handle_xdp(ctx, xdp, 0, false);
    return 0;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int verdict)
{
    handle_xdp(ctx, xdp, verdict, true);
    return 0;
}

// bpf_tail_call_static(ctx, &xdp_progs, 0);
// bpf_xdp_adjust_tail
// bpf_xdp_adjust_head
// bpf_redirect_map(&xdp_sockets, 0, 0);
// bpf_loop