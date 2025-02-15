#include "nftrace.h"
#include "define/if_ether.h"
#include "common.h"
#include <define/netfiler.h>

struct trace_info {
    u32 skb_hash;
    struct trace_sk_info sk_info;
    struct trace_dev_info dev_info;
    struct trace_nft_info nft_info;
    struct trace_conn_info conn_info;
    struct trace_process_info process_info;
};

const struct trace_info *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct trace_conn_key);
    __type(value, struct trace_conn_value);
    __uint(max_entries, 10000000);
} conn_ctx_map SEC(".maps");

static __always_inline int skb_mac_header_was_set(const struct sk_buff *skb) { return BPF_CORE_READ(skb, mac_header) != (typeof(BPF_CORE_READ(skb, mac_header)))~0U; }

static __always_inline unsigned char *skb_mac_header(const struct sk_buff *skb) { return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, mac_header); }

static __always_inline unsigned char *skb_network_header(const struct sk_buff *skb) { return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header); }

static __always_inline void handle_nft_ipv4(int *err, struct trace_info *trace, const struct sk_buff *skb)
{
    void *head = BPF_CORE_READ(skb, head);
    void *end = head + BPF_CORE_READ(skb, end);
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    if ((void *)iph + sizeof(*iph) > end) {
        *err = CLEAN_ERR_FAILED;
        return;
    }

    trace->conn_info.protocol = BPF_CORE_READ(iph, protocol);
    trace->conn_info.src_ip = bpf_ntohl(BPF_CORE_READ(iph, saddr));
    trace->conn_info.dest_ip = bpf_ntohl(BPF_CORE_READ(iph, daddr));
    trace->nft_info.len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));

    switch (trace->conn_info.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcph = (void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4);
            if ((void *)tcph + sizeof(*tcph) > end) {
                *err = CLEAN_ERR_FAILED;
                return;
            }
            trace->conn_info.src_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
            trace->conn_info.dest_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udph = (void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4);
            if ((void *)udph + sizeof(*udph) > end) {
                *err = CLEAN_ERR_FAILED;
                return;
            }
            trace->conn_info.src_port = bpf_ntohs(BPF_CORE_READ(udph, source));
            trace->conn_info.dest_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *ich = (void *)iph + sizeof(*iph);
            if ((void *)ich + sizeof(*ich) > end) {
                *err = CLEAN_ERR_FAILED;
                return;
            }
            trace->conn_info.icmp_info.code = bpf_ntohs(BPF_CORE_READ(ich, code));
            trace->conn_info.icmp_info.type = bpf_ntohs(BPF_CORE_READ(ich, type));
            break;
        }
        default: {
            *err = CLEAN_ERR_FAILED;
        }
    }
}

static __always_inline void handle_nft_ipv6(int *err, struct trace_info *trace, const struct sk_buff *skb)
{
    void *head = BPF_CORE_READ(skb, head);
    void *end = head + BPF_CORE_READ(skb, end);
    struct ipv6hdr *ip6h = (struct ipv6hdr *)skb_network_header(skb);
    if ((void *)ip6h + sizeof(*ip6h) > end) {
        *err = CLEAN_ERR_FAILED;
        return;
    }

    trace->conn_info.protocol = BPF_CORE_READ(ip6h, nexthdr);
    trace->conn_info.src_ip6 = BPF_CORE_READ(ip6h, saddr);
    trace->conn_info.dest_ip6 = BPF_CORE_READ(ip6h, daddr);
    trace->nft_info.len = bpf_ntohs(BPF_CORE_READ(ip6h, payload_len));

    if (trace->conn_info.protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)((void *)ip6h + sizeof(*ip6h));
        if ((void *)tcph + sizeof(*tcph) > end) {
            *err = CLEAN_ERR_FAILED;
            return;
        }
        trace->conn_info.src_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
        trace->conn_info.dest_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
    } else if (trace->conn_info.protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)((void *)ip6h + sizeof(*ip6h));
        if ((void *)udph + sizeof(*udph) > end) {
            *err = CLEAN_ERR_FAILED;
            return;
        }

        trace->conn_info.src_port = bpf_ntohs(BPF_CORE_READ(udph, source));
        trace->conn_info.dest_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
    } else if (trace->conn_info.protocol == IPPROTO_ICMPV6) {
        struct icmp6hdr *ic6h = (void *)((void *)ip6h + sizeof(*ip6h));
        if ((void *)ic6h + sizeof(*ic6h) > end) {
            *err = CLEAN_ERR_FAILED;
            return;
        }
        trace->conn_info.icmp_info.code = bpf_ntohs(BPF_CORE_READ(ic6h, icmp6_code));
        trace->conn_info.icmp_info.type = bpf_ntohs(BPF_CORE_READ(ic6h, icmp6_type));
    } else {
        *err = CLEAN_ERR_FAILED;
    }
}

static __always_inline void fill_trace_pkt_info(int *err, struct trace_info *trace, const struct nft_pktinfo *pkt)
{
    struct sk_buff *skb = BPF_CORE_READ(pkt, skb);
    struct sock *sk = BPF_CORE_READ(pkt, skb, sk, sk_socket, sk);

    void *head = BPF_CORE_READ(skb, head);
    void *end = head + BPF_CORE_READ(skb, end);
    if (!head || !end || head >= end) {
        *err = CLEAN_ERR_FAILED;
        return;
    }
    struct ethhdr *eth;
    if (skb_mac_header_was_set(skb)) {
        eth = (struct ethhdr *)skb_mac_header(skb);
        if ((void *)eth + sizeof(*eth) > end) {
            *err = CLEAN_ERR_FAILED;
            return;
        }
    } else {
        *err = CLEAN_ERR_FAILED;
        return;
    }
    switch (_ntohs(BPF_CORE_READ(eth, h_proto))) {
        case ETH_P_IPV6:
            break;
        case ETH_P_IP:
            break;
        default:
            return;
    }
    const u32 dest_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    const u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (dest_ip <= 0 || src_ip <= 0) {
        *err = CLEAN_ERR_FAILED;
        return;
    }
    const struct trace_conn_key key = get_conn_key(sk);
    const struct trace_conn_value *val = bpf_map_lookup_elem(&conn_ctx_map, &key);
    if (val) {
        print_conn_info(sk, "ok");
        // const struct state_info state = { .role = val->role };
        // set_conn_info(sk, &trace->conn_info, &state, err);
    } else {
        print_conn_info(sk, "not ok");
        // *err = CLEAN_ERR_FAILED;
        // return;
    }
    bpf_probe_read_kernel(trace->conn_info.src_mac, sizeof(trace->conn_info.src_mac), BPF_CORE_READ(eth, h_source));
    bpf_probe_read_kernel(trace->conn_info.dest_mac, sizeof(trace->conn_info.dest_mac), BPF_CORE_READ(eth, h_dest));

    switch (BPF_CORE_READ(pkt, state, pf)) {
        case NFPROTO_IPV4:
            print_conn_info(sk, "print_conn_info_v4");
            handle_nft_ipv4(err, trace, skb);
            break;
        case NFPROTO_IPV6:
            print_conn_info_v6(sk, "print_conn_info_v6");
            handle_nft_ipv6(err, trace, skb);
            break;
        default:
            bpf_printk("asdxxxx");
            return;
    }
}

#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
static __always_inline void fill_trace(int *err, struct trace_info *trace, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule *rule, struct nft_traceinfo *info)
#else
static __always_inline void fill_trace(int *err, struct trace_info *trace, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule_dp *rule, struct nft_traceinfo *info)
#endif
{
    struct trace_process_info *p = &trace->process_info;
    fill_process_info(p);
    // pkt->state->sk
    struct sock *sk = BPF_CORE_READ(pkt, state, sk);
    set_sk_info(sk, &trace->sk_info);
    set_dev_info(&trace->dev_info, pkt);
    set_nft_info(&trace->nft_info, pkt, verdict, rule, info);
    fill_trace_pkt_info(err, trace, pkt);
}

SEC("kprobe/__nft_trace_packet")
#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
int BPF_KPROBE(kprobe_nft_trace_packet, struct nft_traceinfo *info)
#else
int BPF_KPROBE(kprobe_nft_trace_packet, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict, const struct nft_rule_dp *rule, struct nft_traceinfo *info)
#endif
{
    struct trace_info *trace;
    int _err = CLEAN_ERR_INIT;
    int *err = &_err;
    guard_ring_buf(&events, trace, err);
    if (!trace) {
        return BPF_OK;
    }
    __builtin_memset(trace, 0, sizeof(*trace));

#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    fill_trace(err, trace, BPF_CORE_READ(info, pkt), BPF_CORE_READ(info, verdict), BPF_CORE_READ(info, rule), info);
#else
    fill_trace(err, trace, pkt, verdict, rule, info);
#endif

    if (*err == CLEAN_ERR_INIT) {
        *err = CLEAN_ERR_SUCCESS;
    }
    return 0;
}

SEC("fentry/nft_do_chain")
int BPF_PROG(fentry_nft_do_chain) { return 0; }

/*
 * nft_do_chain
 *     nft_trace_packet
 *         __nft_trace_packet
 *     nft_trace_verdict
 *         __nft_trace_verdict
 *             __nft_trace_packet
 *     nft_trace_packet
 *         __nft_trace_packet
 */
// root@vm2404:~# bpftrace -l |grep -E 'nft_do_chain|nf_route_table'
// fentry:nf_tables:nf_route_table_hook4        // 会调用 nft_do_chain
// fentry:nf_tables:nf_route_table_hook6        // 会调用 nft_do_chain
// fentry:nf_tables:nf_route_table_inet         // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain
// fentry:nf_tables:nft_do_chain_arp            // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_bridge         // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_inet           // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_inet_ingress   // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_ipv4           // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_ipv6           // 会调用 nft_do_chain
// fentry:nf_tables:nft_do_chain_netdev         // 会调用 nft_do_chain
// kprobe:nf_route_table_hook4
// kprobe:nf_route_table_hook6
// kprobe:nf_route_table_inet
// kprobe:nft_do_chain
// kprobe:nft_do_chain_arp
// kprobe:nft_do_chain_bridge
// kprobe:nft_do_chain_inet
// kprobe:nft_do_chain_inet_ingress
// kprobe:nft_do_chain_ipv4
// kprobe:nft_do_chain_ipv6
// kprobe:nft_do_chain_netdev