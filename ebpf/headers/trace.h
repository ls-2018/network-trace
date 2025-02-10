#ifndef __COMMON_H__
#define __COMMON_H__
#include "bpf_all.h"
#include "nftrace.h"

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
};

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

#ifndef MAX_PROCESS_NAME
#define MAX_PROCESS_NAME 64
#endif

struct trace_process_info {
    char name[MAX_PROCESS_NAME];
    __u64 pid;
    __u64 tgid;
} __attribute__((packed));

// struct process_info *
#define fill_process_info(p)                         \
    bpf_get_current_comm(&p->name, sizeof(p->name)); \
    p->pid = bpf_get_current_pid_tgid() >> 32;       \
    p->tgid = bpf_get_current_pid_tgid() << 32;

#endif

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT 2
#define TCP_EVENT_TYPE_CLOSE 3
#define TCP_EVENT_TYPE_FD_INSTALL 4

#define IP6_LEN 16

enum {
    LINK_ROLE_UNKNOWN = 0,
    LINK_ROLE_CLIENT = 1,
    LINK_ROLE_SERVER = 2
};
