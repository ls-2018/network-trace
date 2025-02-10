#ifndef __SKB_HELPERS_H__
#define __SKB_HELPERS_H__

#include "bpf_all.h"
#include "string.h"
#include "nftrace.h"
#define IFNAMSIZ 16
#define ADDRSIZE 16
#define MAC_HEADER_SIZE 14
#define FUNCNAME_MAX_LEN 32
#define XT_TABLE_MAXNAMELEN 32
#define MAX_STACKDEPTH 50

union addr {
    u32 v4addr;

    struct {
        u64 pre;
        u64 post;
    } v6addr;

    u64 pad[2];
} __attribute__((packed));

struct l2_info_t {
    u8 dest_mac[6];
    u16 l3_proto;
    u8 pad[4];
};

struct l3_info_t {
    union addr saddr;
    union addr daddr;
    u16 tot_len;
    u8 ip_version;
    u8 l4_proto;
    u8 pad[4];
} __attribute__((packed));

struct l4_info_t {
    u16 sport;
    u16 dport;
    u16 tcpflags;
    u8 pad[2];
} __attribute__((packed));

struct icmp_info_t {
    u16 icmpid;
    u16 icmpseq;
    u8 icmptype;
    u8 pad[3];
} __attribute__((packed));

struct iptables_info_t {
    char tablename[XT_TABLE_MAXNAMELEN];
    u32 hook;
    u32 verdict;
    u64 delay;
    u8 pf;
    u8 pad[7];
} __attribute__((packed));

struct iptables_trace_t {
    char in[IFNAMSIZ];
    char out[IFNAMSIZ];
    char tablename[XT_TABLE_MAXNAMELEN];
    char chainname[XT_TABLE_MAXNAMELEN];
    u32 rulenum;
    u32 hooknum;
    u8 pf;
    u8 pad[3];
} __attribute__((packed));

struct nft_trace_t {
    char tablename[XT_TABLE_MAXNAMELEN];
    char chainname[XT_TABLE_MAXNAMELEN];
    u64 delay;
    u32 verdict;
} __attribute__((packed));

struct pkt_info_t {
    char ifname[IFNAMSIZ];
    u32 len;
    u32 cpu;
    u32 pid;
    u32 netns;
    u8 pkt_type; // skb->pkt_type
    u8 pad[7];
} __attribute__((packed));

struct event_t {
    char func_name[FUNCNAME_MAX_LEN];
    u64 skb;
    u64 start_ns;
    __s32 kernel_stack_id;
    u8 flags;
    u8 pad[7];
    struct pkt_info_t pkt_info;
    struct l2_info_t l2_info;
    struct l3_info_t l3_info;
    struct l4_info_t l4_info;
    struct icmp_info_t icmp_info;

    union {
        struct iptables_info_t ipt_info;
        struct iptables_trace_t trace_info;
        struct nft_trace_t nft_info;
    };
} ;
union ___skb_pkt_type {
    u8 value;

    struct {
        u8 __pkt_type_offset[0];
        u8 pkt_type : 3;
        u8 pfmemalloc : 1;
        u8 ignore_df : 1;

        u8 nf_trace : 1;
        u8 ip_summed : 2;
    };
};
#define SKBTRACER_EVENT_IF 0x01
#define SKBTRACER_EVENT_IPTABLE 0x02
#define SKBTRACER_EVENT_DROP 0x04
#define SKBTRACER_EVENT_NEW 0x10

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __type(value, u64[]); // MAX_STACKDEPTH
    __uint(max_entries, 256);
} skbtracer_stack SEC(".maps");

static __always_inline u32 get_netns_skb(struct sk_buff *skb)
{
    u32 netns;

    // Get netns inode. The code below is equivalent to: netns =
    // skb->dev->nd_net.net->ns.inum
    netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

    // maybe the skb->dev is not init, for this situation, we can get netns inode by
    // skb->sk->__sk_common.skc_net.net->ns.inum
    if (netns == 0) {
        struct sock *sk = BPF_CORE_READ(skb, sk);
        if (sk != NULL)
            netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    }

    return netns;
}

static __always_inline u8 get_pkt_type(struct sk_buff *skb)
{
    union ___skb_pkt_type type = {};
    bpf_probe_read(&type.value, 1, &skb->__pkt_type_offset);
    // return BPF_CORE_READ_BITFIELD(skb, pkt_type); // Failed
    return type.pkt_type;
}

static __always_inline u8 get_ip_version(void *hdr)
{
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte >> 4) & 0x0f;
}

static __always_inline u8 get_ipv4_header_len(void *hdr)
{
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte & 0x0f) * 4;
}

static __always_inline unsigned char *get_l2_header(struct sk_buff *skb)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    return head + mac_header;
}

static __always_inline unsigned char *get_l3_header(struct sk_buff *skb)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    if (network_header == 0)
        network_header = mac_header + MAC_HEADER_SIZE;
    return head + network_header;
}

static __always_inline unsigned char *get_l4_header(struct sk_buff *skb)
{
    u16 transport_size = 0;
    unsigned char *l3_header = get_l3_header(skb);
    u8 ip_version = get_ip_version(l3_header);
    if (ip_version == 6)
        transport_size = sizeof(struct ipv6hdr);
    else
        transport_size = get_ipv4_header_len(l3_header);
    return l3_header + transport_size;
}

static __always_inline void set_event_info(struct sk_buff *skb, struct event_t *ev)
{
    ev->skb = (u64)skb;
    ev->start_ns = bpf_ktime_get_ns();
}

static __always_inline void set_callstack(struct event_t *event, struct pt_regs *ctx)
{
    event->kernel_stack_id = bpf_get_stackid(ctx, &skbtracer_stack, 0);
    return;
}

static __always_inline void read_dev_name(char *dst, const struct net_device *dev)
{
    dst[0] = 0;
    if (dev)
        bpf_probe_read_kernel_str(dst, IFNAMSIZ, &dev->name);
}

static __always_inline void set_pkt_info(struct sk_buff *skb, struct pkt_info_t *pkt_info)
{
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    pkt_info->len = BPF_CORE_READ(skb, len);
    pkt_info->cpu = bpf_get_smp_processor_id();
    pkt_info->pid = bpf_get_current_pid_tgid() & 0xffff;
    pkt_info->netns = get_netns_skb(skb);
    pkt_info->pkt_type = get_pkt_type(skb);
    read_dev_name((char *)&pkt_info->ifname, dev);

    //    pkt_info->ifname[0] = 0;
    //    bpf_probe_read(&pkt_info->ifname, IFNAMSIZ, &dev->name);
    //    if (pkt_info->ifname[0] == 0)
    //        bpf_strncpy(pkt_info->ifname, "nil", IFNAMSIZ);
}

static __always_inline void set_ether_info(struct sk_buff *skb, struct l2_info_t *l2_info)
{
    unsigned char *l2_header = get_l2_header(skb);
    bpf_probe_read(&l2_info->dest_mac, 6, l2_header);
}

static __always_inline void set_ipv4_info(struct sk_buff *skb, struct l3_info_t *l3_info)
{
    struct iphdr *iph = (struct iphdr *)get_l3_header(skb);
    l3_info->saddr.v4addr = BPF_CORE_READ(iph, saddr);
    l3_info->daddr.v4addr = BPF_CORE_READ(iph, daddr);
    l3_info->tot_len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));
    l3_info->l4_proto = BPF_CORE_READ(iph, protocol);
    l3_info->ip_version = get_ip_version(iph);
}

static __always_inline void set_ipv6_info(struct sk_buff *skb, struct l3_info_t *l3_info)
{
    struct ipv6hdr *iph = (struct ipv6hdr *)get_l3_header(skb);
    bpf_probe_read(&l3_info->saddr.v6addr, ADDRSIZE, &iph->saddr);
    bpf_probe_read(&l3_info->daddr.v6addr, ADDRSIZE, &iph->daddr);
    l3_info->tot_len = BPF_CORE_READ(iph, payload_len);
    l3_info->l4_proto = BPF_CORE_READ(iph, nexthdr);
    l3_info->ip_version = get_ip_version(iph);
}

static __always_inline void set_tcp_info(struct sk_buff *skb, struct l4_info_t *l4_info)
{
    struct tcphdr *tcph = (struct tcphdr *)get_l4_header(skb);
    l4_info->sport = bpf_ntohs(BPF_CORE_READ(tcph, source));
    l4_info->dport = bpf_ntohs(BPF_CORE_READ(tcph, dest));
    bpf_probe_read(&l4_info->tcpflags, 2, (char *)tcph + 12);
}

static __always_inline void set_udp_info(struct sk_buff *skb, struct l4_info_t *l4_info)
{
    struct udphdr *uh = (struct udphdr *)get_l4_header(skb);
    l4_info->sport = bpf_ntohs(BPF_CORE_READ(uh, source));
    l4_info->dport = bpf_ntohs(BPF_CORE_READ(uh, dest));
}

static __always_inline void set_icmp_info(struct sk_buff *skb, struct icmp_info_t *icmp_info)
{
    struct icmphdr ih;
    unsigned char *l4_header = get_l4_header(skb);
    bpf_probe_read(&ih, sizeof(ih), l4_header);

    icmp_info->icmptype = ih.type;
    icmp_info->icmpid = bpf_ntohs(ih.un.echo.id);
    icmp_info->icmpseq = bpf_ntohs(ih.un.echo.sequence);
}

static __always_inline void set_iptables_info(struct xt_table *table, const struct nf_hook_state *state, u32 verdict, u64 delay, struct iptables_info_t *ipt_info)
{
    // BPF_CORE_READ_STR_INTO(&ipt_info->tablename, table, name); /* failed of bad CO-RE relocation */
    bpf_probe_read(&ipt_info->tablename, XT_TABLE_MAXNAMELEN, &table->name);
    ipt_info->hook = BPF_CORE_READ(state, hook);
    ipt_info->verdict = verdict;
    ipt_info->delay = delay;
    ipt_info->pf = BPF_CORE_READ(state, pf);
}

#endif // __SKB_HELPERS_H__
