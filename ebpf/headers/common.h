#ifndef __COMMON_H__
#define __COMMON_H__

struct ip_tuple {
    u16 src_port;
    u16 dst_port;
    u32 src_ip4;
    u32 dst_ip4;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
    u8 src_mac[6];
    u8 dst_mac[6];

    u8 ip_proto;
};
#define MAX_PROCESS_NAME 64

struct process_info {
    char name[MAX_PROCESS_NAME];
    u32 pid;
} __attribute__((packed));

// struct process_info *
#define fill_process_info(p)                                                                                           \
    bpf_get_current_comm(&p->name, sizeof(p->name));                                                                   \
    p->pid = bpf_get_current_pid_tgid() >> 32;

#endif

//     struct process_info *p = &pkt->process;
//       fill_process_info(p);