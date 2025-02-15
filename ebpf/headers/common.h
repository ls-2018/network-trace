#ifndef COMMON_H_
#define COMMON_H_
#include "bpf_all.h"
#include "nftrace.h"
#include "define/socket.h"

#ifndef MAX_PROCESS_NAME
#define MAX_PROCESS_NAME 64
#endif
#define MAX_STACK_DEPTH 50
#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT 2
#define TCP_EVENT_TYPE_CLOSE 3
#define TCP_EVENT_TYPE_FD_INSTALL 4
#define IP6_LEN 16

enum link_role { LINK_ROLE_UNKNOWN = 0, LINK_ROLE_CLIENT = 1, LINK_ROLE_SERVER = 2 };

struct trace_icmp
{
    __u8 type;
    __u8 code;
};

// dynamic information about the state of a connection.
struct connection_throughput_stats
{
    u64 bytes_sent;
    u64 bytes_received;
    u64 is_active; // u64 because it will be padded anyway. should change whether
    // new members are added
};

struct trace_conn_key
{
    u16 src_port;
    u16 dest_port;
    __u32 src_ip;
    __u32 dest_ip;
    struct in6_addr src_ip6;
    struct in6_addr dest_ip6;
    __u8 family;
};

struct trace_conn_value
{
    u16 id;
    enum link_role role;
};

static __always_inline struct trace_conn_key get_conn_key(const struct sock* sk)
{
    struct trace_conn_key key;
    const __u8 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    key.family = family;

    key.dest_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (family == AF_INET)
    {
        key.dest_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    else
    {
        BPF_CORE_READ_INTO(&key.src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.dest_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    return key;
}

struct trace_conn_info
{
    __u8 src_mac[6];
    __u8 dest_mac[6];
    u16 src_port;
    u16 dest_port;
    __u32 src_ip;
    __u32 dest_ip;
    struct in6_addr src_ip6;
    struct in6_addr dest_ip6;
    __u32 net_ns;
    __u8 family;
    __u8 protocol;
    u16 sk_protocol;
    u16 loc;
    __u8 old_state;
    __u8 new_state;
    struct trace_icmp icmp_info;
    enum link_role role;
    struct connection_throughput_stats throughput;
};

struct sk_common
{
    u8 state;
    u8 reuse_port;
    u8 pad[2];
    u32 bound_ifindex;
} __attribute__((packed));

struct trace_sk_info
{
    u64 sock_id;
    u32 rx_dst_ifindex;
    u32 backlog_len;
    u32 rcv_buff;
    u32 snd_buff;
    u32 priority;
    u32 mark;
    u16 type;
    u16 pad;
} __attribute__((packed));

struct trace_socket_info
{
    u16 state;
    u16 type;
    u32 pad;
    u64 file_inode;
    u64 flags;
} __attribute__((packed));

struct trace_dev_info
{
    u8 iif_name[16];
    u8 oif_name[16];
    u32 iif;
    u32 oif;
    u16 iif_type;
    u16 oif_type;
    u16 pad[2];
};

struct trace_nft_info
{
    enum nft_trace_types type;
    u32 verdict;
    u8 table_name[64];
    u64 table_handle;
    u8 chain_name[64];
    u64 chain_handle;
    u64 rule_handle;
    u8 jump_target[64];
    u8 nf_proto;
    u8 policy;
    u16 len;
    u32 mark;
    u32 base_chain_family;
};

struct trace_process_info
{
    u8 name[MAX_PROCESS_NAME];
    __u64 pid;
    __u64 tgid;
};

void print_mac_info(const struct trace_conn_info* info)
{
    bpf_printk("mac:  %d:%d:%d:%d:%d:%d %d:%d:%d:%d:%d:%d",
               info->src_mac[0], info->src_mac[1], info->src_mac[2], info->src_mac[3], info->src_mac[4],
               info->src_mac[5],
               info->dest_mac[0], info->dest_mac[1], info->dest_mac[2], info->dest_mac[3], info->dest_mac[4],
               info->dest_mac[5]
    );
}

#define print_conn_info(sk, info)                                                                                                                                                                                                              \
    ({                                                                                                                                                                                                                                         \
        bpf_printk("connect lport=%d rport=%d laddr=%pI4 raddr=%pI4 %s",  BPF_CORE_READ(sk, __sk_common.skc_num), bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), &sk->__sk_common.skc_rcv_saddr, &sk->__sk_common.skc_daddr,  \
                   info);                                                                                                                                                                                                                      \
    })

#define print_conn_info_v6(sk, info)                                                                                                                                                                                                           \
    ({                                                                                                                                                                                                                                         \
        bpf_printk("connect lport=%d rport=%d laddr=%pI6 raddr=%pI6 %s", BPF_CORE_READ(sk, __sk_common.skc_num), bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32,                       \
                   &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, info);                                                                                                                                                                       \
    })

static __always_inline void fill_process_info(struct trace_process_info* p)
{
    bpf_get_current_comm(&p->name, sizeof(p->name));
    p->pid = bpf_get_current_pid_tgid() >> 32;
    p->tgid = bpf_get_current_pid_tgid() << 32;
}

static __always_inline void set_sock_info(struct sock* sk, struct trace_socket_info* sock_info)
{
    struct socket* sock = BPF_CORE_READ(sk, sk_socket);
    sock_info->state = BPF_CORE_READ(sock, state);
    sock_info->type = BPF_CORE_READ(sock, type);
    sock_info->flags = BPF_CORE_READ(sock, flags);
    sock_info->file_inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
}

static __always_inline void set_nft_info(struct trace_nft_info* nft, const struct nft_pktinfo* pkt,
                                         const struct nft_verdict* verdict, const struct nft_rule_dp* rule,
                                         struct nft_traceinfo* info)
{
    nft->type = BPF_CORE_READ_BITFIELD_PROBED(info, type);
    nft->base_chain_family = BPF_CORE_READ(info, basechain, type, family);
    nft->nf_proto = BPF_CORE_READ(pkt, state, pf);
    bpf_probe_read_kernel_str(nft->table_name, sizeof(nft->table_name),
                              BPF_CORE_READ(info, basechain, chain.table, name));
    nft->table_handle = BPF_CORE_READ(info, basechain, chain.table, handle);
    bpf_probe_read_kernel_str(nft->chain_name, sizeof(nft->chain_name), BPF_CORE_READ(info, basechain, chain.name));
    nft->chain_handle = BPF_CORE_READ(info, basechain, chain.handle);
    nft->rule_handle = BPF_CORE_READ_BITFIELD_PROBED(rule, handle);
    nft->verdict = BPF_CORE_READ(verdict, code);
    bpf_probe_read_kernel_str(nft->jump_target, sizeof(nft->jump_target), BPF_CORE_READ(verdict, chain, name));
    nft->policy = BPF_CORE_READ(info, basechain, policy);
    nft->mark = BPF_CORE_READ(pkt, skb, mark);
}

static __always_inline void set_dev_info(struct trace_dev_info* dev_info, const struct nft_pktinfo* pkt)
{
    dev_info->iif = BPF_CORE_READ(pkt, state, in, ifindex);
    dev_info->iif_type = BPF_CORE_READ(pkt, state, in, type);
    bpf_probe_read_kernel_str(dev_info->iif_name, sizeof(dev_info->iif_name), BPF_CORE_READ(pkt, state, in, name));
    dev_info->oif = BPF_CORE_READ(pkt, state, out, ifindex);
    dev_info->oif_type = BPF_CORE_READ(pkt, state, out, type);
    bpf_probe_read_kernel_str(dev_info->oif_name, sizeof(dev_info->oif_name), BPF_CORE_READ(pkt, state, out, name));
}

static __always_inline void set_sk_info(struct sock* sk, struct trace_sk_info* sk_info)
{
    sk_info->sock_id = (u64)sk;
    sk_info->rx_dst_ifindex = BPF_CORE_READ(sk, sk_rx_dst_ifindex);
    sk_info->backlog_len = BPF_CORE_READ(sk, sk_backlog.len);
    sk_info->rcv_buff = BPF_CORE_READ(sk, sk_rcvbuf);
    sk_info->snd_buff = BPF_CORE_READ(sk, sk_sndbuf);
    sk_info->priority = BPF_CORE_READ(sk, sk_priority);
    sk_info->mark = BPF_CORE_READ(sk, sk_mark);
    sk_info->type = BPF_CORE_READ(sk, sk_type);
}

static __always_inline void set_sk_common(struct sock* sk, struct sk_common* skc)
{
    skc->state = BPF_CORE_READ(sk, __sk_common.skc_state);
    skc->reuse_port = BPF_CORE_READ_BITFIELD_PROBED(sk, __sk_common.skc_reuseport);
    skc->bound_ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
}

#define inet_sport inet_sport
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_num sk.__sk_common.skc_num

struct state_info
{
    __u8 old_state;
    __u8 new_state;
    __u32 loc;
    enum link_role role;
};

static __always_inline void set_conn_info(struct sock* sk, struct trace_conn_info* conn_info,
                                          const struct state_info* states, int* err)
{
    conn_info->role = states->role;
    conn_info->loc = states->loc;
    conn_info->old_state = states->old_state;
    conn_info->new_state = states->new_state;
    // struct sock wraps struct tcp_sock and struct inet_sock as its first member
    struct tcp_sock* tcp = (struct tcp_sock*)sk;
    struct inet_sock* inet = (struct inet_sock*)sk;

    const __u8 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
    {
        *err = CLEAN_ERR_FAILED;
        return;
    }

    const u16 sk_protocol = BPF_CORE_READ(sk, sk_protocol);
    switch (sk_protocol)
    {
    case IPPROTO_TCP:
        conn_info->throughput.bytes_received = BPF_CORE_READ(tcp, bytes_received);
        conn_info->throughput.bytes_sent = BPF_CORE_READ(tcp, bytes_sent);
        break;
    case IPPROTO_UDP: // todo
        break;
    case IPPROTO_ICMP: // todo
        break;
    default:
        *err = CLEAN_ERR_FAILED;
        return;
    }
    conn_info->family = family;
    conn_info->sk_protocol = sk_protocol;
    conn_info->net_ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    conn_info->dest_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    conn_info->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (conn_info->family == AF_INET)
    {
        conn_info->dest_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        conn_info->src_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
        if (conn_info->dest_ip <= 0 || conn_info->src_ip <= 0)
        {
            *err = CLEAN_ERR_FAILED;
            return;
        }
    }
    else
    {
        BPF_CORE_READ_INTO(&conn_info->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&conn_info->dest_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
}

static inline u32 get_unique_id()
{
    return bpf_ktime_get_ns() % __UINT32_MAX__; // no reason to use 64 bit for this
}
#endif
