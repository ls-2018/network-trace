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

enum { LINK_ROLE_UNKNOWN = 0, LINK_ROLE_CLIENT = 1, LINK_ROLE_SERVER = 2 };

struct trace_conn_info {
    __u8 c_mac[6];
    __u8 d_mac[6];

    u16 c_port;
    u16 s_port;

    __u32 c_ip;
    __u32 s_ip;
    struct in6_addr c_ip6;
    struct in6_addr s_ip6;
    __u32 net_ns;
    u16 family;
    u16 protocol;
    u16 seq;
    __u8 old_state;
    __u8 new_state;
    __u8 role;
};

struct sk_meta {
    __be64 addrs;
    __be16 dport;
    u16 port_num;
    u32 netns;
    u16 family;
    u16 protocol;
} __attribute__((packed));

struct sk_common {
    u8 state;
    u8 reuse_port;
    u8 pad[2];
    u32 bound_ifindex;
} __attribute__((packed));

struct trace_sk_info {
    u64 sk_id;
    u32 rx_dst_ifindex;
    u32 backlog_len;
    u32 rcv_buff;
    u32 snd_buff;
    u32 priority;
    u32 mark;
    u16 type;
    u16 pad;
} __attribute__((packed));

struct trace_socket_info {
    u64 socket_id;
    u16 state;
    u16 type;
    u32 pad;
    u64 file_inode;
    u64 flags;
} __attribute__((packed));

struct trace_nft_info {
    enum nft_trace_types type;
    u8 table_name[64];
    u64 table_handle;
    u8 chain_name[64];
    u64 chain_handle;
    u64 rule_handle;
    u8 jump_target[64];
    u32 verdict;
    u8 nf_proto;
    u8 policy;
    u16 len;
    u32 mark;
};

struct trace_process_info {
    u8 name[MAX_PROCESS_NAME];
    __u64 pid;
    __u64 tgid;
} ;

static __always_inline void fill_process_info(struct trace_process_info *p)
{
    bpf_get_current_comm(&p->name, sizeof(p->name));
    p->pid = bpf_get_current_pid_tgid() >> 32;
    p->tgid = bpf_get_current_pid_tgid() << 32;
}

static __always_inline void set_sock_info(struct sock *sk, struct trace_socket_info *sock_info)
{
    struct socket *sock = BPF_CORE_READ(sk, sk_socket);
    if (!sock)
        return;
    sock_info->socket_id = (u64)sock;
    sock_info->state = BPF_CORE_READ(sock, state);
    sock_info->type = BPF_CORE_READ(sock, type);
    sock_info->flags = BPF_CORE_READ(sock, flags);
    sock_info->file_inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
}

static __always_inline void set_sk_info(struct sock *sk, struct trace_sk_info *sk_info)
{
    sk_info->sk_id = (u64)sk;
    sk_info->rx_dst_ifindex = BPF_CORE_READ(sk, sk_rx_dst_ifindex);
    sk_info->backlog_len = BPF_CORE_READ(sk, sk_backlog.len);
    sk_info->rcv_buff = BPF_CORE_READ(sk, sk_rcvbuf);
    sk_info->snd_buff = BPF_CORE_READ(sk, sk_sndbuf);
    sk_info->priority = BPF_CORE_READ(sk, sk_priority);
    sk_info->mark = BPF_CORE_READ(sk, sk_mark);
    sk_info->type = BPF_CORE_READ(sk, sk_type);
}

static __always_inline void set_meta(struct sock *sk, struct sk_meta *meta)
{
    meta->addrs = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
    meta->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    meta->port_num = BPF_CORE_READ(sk, __sk_common.skc_num);
    meta->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    ;
    meta->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    meta->protocol = BPF_CORE_READ(sk, sk_protocol);
}

static __always_inline void set_sk_common(struct sock *sk, struct sk_common *skc)
{
    skc->state = BPF_CORE_READ(sk, __sk_common.skc_state);
    skc->reuse_port = BPF_CORE_READ_BITFIELD_PROBED(sk, __sk_common.skc_reuseport);
    skc->bound_ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
}

static __always_inline void set_conn_info(struct sock *sk, struct trace_conn_info *conn_info, const __u8 type, int *err)
{
    const __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return;
    }

    const u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP) {
        return;
    }

    conn_info->family = family;
    conn_info->protocol = protocol;
    conn_info->net_ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

    __u32 skc_rcv_s_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    if (bpf_ntohl(skc_rcv_s_addr) <= 0) {
        *err = CLEAN_ERR_FAILED;
        return;
    }

    __u32 skc_d_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u32 skc_s_port = BPF_CORE_READ(sk, __sk_common.skc_num);

    switch (type) {
        case LINK_ROLE_SERVER:
            conn_info->s_port = skc_s_port;
            conn_info->c_port = bpf_ntohs(skc_d_port);
            bpf_probe_read_kernel(&conn_info->s_ip, sizeof(conn_info->s_ip), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&conn_info->c_ip, sizeof(conn_info->c_ip), &sk->__sk_common.skc_daddr);

            /* family == AF_INET6 */
            bpf_probe_read_kernel(&conn_info->s_ip6, sizeof(conn_info->s_ip6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&conn_info->c_ip6, sizeof(conn_info->c_ip6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;

        case LINK_ROLE_UNKNOWN:
        case LINK_ROLE_CLIENT:
            conn_info->c_port = skc_s_port;
            conn_info->s_port = bpf_ntohs(skc_d_port);
            bpf_probe_read_kernel(&conn_info->c_ip, sizeof(conn_info->c_ip), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&conn_info->s_ip, sizeof(conn_info->s_ip), &sk->__sk_common.skc_daddr);
            /* family == AF_INET6 */
            bpf_probe_read_kernel(&conn_info->c_ip6, sizeof(conn_info->c_ip6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&conn_info->s_ip6, sizeof(conn_info->s_ip6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;
        default:
            break;
    }

    conn_info->s_ip = bpf_ntohl(conn_info->s_ip);
    conn_info->c_ip = bpf_ntohl(conn_info->c_ip);
}

#endif
