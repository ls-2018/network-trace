#ifndef DNS
#define DNS
#include "vmlinux.h"

// dns
struct dns_header {
    __be16 id;    // 事务ID
    __be16 flags; // 标志字段     0x8000
    u16 qdcount;  // 问题部分计数
    u16 ancount;  // 应答记录计数
    u16 nscount;  // 授权记录计数
    u16 arcount;  // 附加记录计数
};

struct dns_query {
    struct dns_header header; // DNS头部
    char data[64];            // 可变长度数据（域名+类型+类）
};

#define MAX_COMM 16
struct dns_information {
    u32 pid;
    char comm[MAX_COMM];
    u16 id;
    u32 saddr;
    u32 daddr;
    u32 start_us;
    u32 end_us;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
    char data[64];
    u16 rcode; // 返回标志  flags&0x000F
};

#endif
