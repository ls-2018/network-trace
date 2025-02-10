#include "trace.h"
#include "counters.h"

struct trace_info {
    u32 id;
    u64 sk_id;
    int family;
    u32 iif;
    u32 oif;
    u16 iif_type;
    u16 oif_type;
    u8 iif_name[16];
    u8 oif_name[16];
    struct trace_nft_info nft_info;
    struct trace_conn_info conn_info;
    u64 time;
    u64 counter;
    struct trace_process_info process_info;
};

const struct trace_info *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

static __always_inline int skb_mac_header_was_set(const struct sk_buff *skb) { return BPF_CORE_READ(skb, mac_header) != (typeof(BPF_CORE_READ(skb, mac_header)))~0U; }

static __always_inline unsigned char *skb_mac_header(const struct sk_buff *skb) { return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, mac_header); }

static __always_inline unsigned char *skb_network_header(const struct sk_buff *skb) { return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header); }

static __always_inline void fill_trace_pkt_info(struct trace_info *trace, const struct sk_buff *skb)
{
    void *head = BPF_CORE_READ(skb, head);
    void *end = head + BPF_CORE_READ(skb, end);
    if (!head || !end || head >= end)
        return;

    if (skb_mac_header_was_set(skb)) {
        struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
        if ((void *)eth + sizeof(*eth) > end)
            return;
        bpf_probe_read_kernel(trace->conn_info.c_mac, sizeof(trace->conn_info.c_mac), BPF_CORE_READ(eth, h_source));
        bpf_probe_read_kernel(trace->conn_info.d_mac, sizeof(trace->conn_info.d_mac), BPF_CORE_READ(eth, h_dest));
    }

    if (trace->family == NFPROTO_IPV4) {
        struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
        if ((void *)iph + sizeof(*iph) > end)
            return;

        trace->conn_info.protocol = BPF_CORE_READ(iph, protocol);
        trace->conn_info.c_ip = bpf_ntohl(BPF_CORE_READ(iph, saddr));
        trace->conn_info.s_ip = bpf_ntohl(BPF_CORE_READ(iph, daddr));
        trace->nft_info.len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));

        if (trace->conn_info.protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)((void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4));
            if ((void *)tcph + sizeof(*tcph) > end)
                return;

            trace->conn_info.c_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
            trace->conn_info.s_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
        } else if (trace->conn_info.protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)((void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4));
            if ((void *)udph + sizeof(*udph) > end)
                return;

            trace->conn_info.c_port = bpf_ntohs(BPF_CORE_READ(udph, source));
            trace->conn_info.s_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
        }

    } else if (trace->family == NFPROTO_IPV6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)skb_network_header(skb);
        if ((void *)ip6h + sizeof(*ip6h) > end)
            return;

        trace->conn_info.protocol = BPF_CORE_READ(ip6h, nexthdr);
        trace->conn_info.c_ip6 = BPF_CORE_READ(ip6h, saddr);
        trace->conn_info.s_ip6 = BPF_CORE_READ(ip6h, daddr);
        trace->nft_info.len = bpf_ntohs(BPF_CORE_READ(ip6h, payload_len));

        if (trace->conn_info.protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)((void *)ip6h + sizeof(*ip6h));
            if ((void *)tcph + sizeof(*tcph) > end)
                return;

            trace->conn_info.c_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
            trace->conn_info.s_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
        } else if (trace->conn_info.protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)((void *)ip6h + sizeof(*ip6h));
            if ((void *)udph + sizeof(*udph) > end)
                return;

            trace->conn_info.c_port = bpf_ntohs(BPF_CORE_READ(udph, source));
            trace->conn_info.s_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
        }
    }
}

#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
static __always_inline void fill_trace(struct trace_info *trace, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule *rule, struct nft_traceinfo *info)
#else
static __always_inline void fill_trace(struct trace_info *trace, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule_dp *rule, struct nft_traceinfo *info)
#endif

{

    struct trace_process_info *p = &trace->process_info;
    fill_process_info(p);
    struct sock *sk = BPF_CORE_READ(pkt, skb, sk);
    trace->sk_id = (u64)sk;
    trace->id = BPF_CORE_READ(pkt, skb, hash); // get_trace_id(BPF_CORE_READ(pkt, skb));
    trace->nft_info.type = BPF_CORE_READ_BITFIELD_PROBED(info, type);
    trace->family = BPF_CORE_READ(info, basechain, type, family);
    bpf_probe_read_kernel_str(trace->nft_info.table_name, sizeof(trace->nft_info.table_name), BPF_CORE_READ(info, basechain, chain.table, name));
    trace->nft_info.table_handle = BPF_CORE_READ(info, basechain, chain.table, handle);
    bpf_probe_read_kernel_str(trace->nft_info.chain_name, sizeof(trace->nft_info.chain_name), BPF_CORE_READ(info, basechain, chain.name));
    trace->nft_info.chain_handle = BPF_CORE_READ(info, basechain, chain.handle);
    trace->nft_info.rule_handle = BPF_CORE_READ_BITFIELD_PROBED(rule, handle);
    trace->nft_info.nf_proto = BPF_CORE_READ(pkt, state, pf);
    trace->nft_info.verdict = BPF_CORE_READ(verdict, code);
    bpf_probe_read_kernel_str(trace->nft_info.jump_target, sizeof(trace->nft_info.jump_target), BPF_CORE_READ(verdict, chain, name));
    trace->nft_info.policy = BPF_CORE_READ(info, basechain, policy);
    trace->nft_info.mark = BPF_CORE_READ(pkt, skb, mark);
    trace->iif = BPF_CORE_READ(pkt, state, in, ifindex);
    trace->iif_type = BPF_CORE_READ(pkt, state, in, type);
    bpf_probe_read_kernel_str(trace->iif_name, sizeof(trace->iif_name), BPF_CORE_READ(pkt, state, in, name));
    trace->oif = BPF_CORE_READ(pkt, state, out, ifindex);
    trace->oif_type = BPF_CORE_READ(pkt, state, out, type);
    bpf_probe_read_kernel_str(trace->oif_name, sizeof(trace->oif_name), BPF_CORE_READ(pkt, state, out, name));
    fill_trace_pkt_info(trace, BPF_CORE_READ(pkt, skb));
    __sync_fetch_and_add(&trace->counter, 1);
}

SEC("kprobe/__nft_trace_packet")
#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
int BPF_KPROBE(kprobe_nft_trace_packet, struct nft_traceinfo *info)
#else
int BPF_KPROBE(kprobe_nft_trace_packet, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule_dp *rule, struct nft_traceinfo *info)
#endif
{
    char comm[60];
    bpf_get_current_comm(&comm, sizeof(comm));

    u32 sample_rate_key = 0;
    u64 *sample_rate_val;

    u32 pkt_cnt = PKT_COUNTER_INC();

    sample_rate_val = bpf_map_lookup_elem(&sample_rate, &sample_rate_key);

    if (sample_rate_val) {
        u64 safe_sample_rate_val = __sync_fetch_and_add(sample_rate_val, 0);
        if (safe_sample_rate_val > 0) {
            if (pkt_cnt % safe_sample_rate_val) {
                return 0;
            }
        }
    }

    struct trace_info *trace;
    int _err = CLEAN_ERR_INIT;
    int *err = &_err;
    guard_ring_buf(&events, trace, err);
    if (!trace) {
        return BPF_OK;
    }

#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    fill_trace(trace, BPF_CORE_READ(info, pkt), BPF_CORE_READ(info, verdict), BPF_CORE_READ(info, rule), info);
#else
    fill_trace(trace, pkt, verdict, rule, info);
#endif
    _err = CLEAN_ERR_SUCCESS;
    return 0;
}