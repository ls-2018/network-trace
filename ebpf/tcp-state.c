#include "common.h"
#include "dns.h"

// 丢包检查
SEC("tracepoint/skb/kfree_skb")
int tp_free_skb(struct trace_event_raw_kfree_skb *ctx)
{
    if (bpf_core_field_exists(ctx->reason)) { } // enum skb_drop_reason { 丢包原因

    if (bpf_core_field_exists(ctx->location)) { } // address 可以从 /proc/kallsyms 获取函数名
    return 0;
}

// 发起连接
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk) { return 0; }

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret)
{
    // 0 成功
    return 0;
}

// 发送 reset 报文
SEC("tracepoint/tcp/tcp_send_reset")
int handle_send_reset(struct trace_event_raw_tcp_send_reset *ctx) { return 0; }
// 全连接、半连接个数
SEC("kprobe/tcp_v4_conn_request")
int BPF_KPROBE(tcp_v4_conn_request, struct sock *sk)
{
    // u32 sk_ack_backlog = BPF_CORE_READ(sk, sk_ack_backlog); // 当前全连接队列的大小
    // u32 sk_max_ack_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);// 当前半连接队列的大小
    return 0;
}

// dns
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb)
{
    // if ((sport != 53) && (dport != 53)) {
    // return 0;
    // }
    const u32 dns_offset = BPF_CORE_READ(skb, transport_header) + sizeof(struct udphdr);
    struct dns_query query;
    // dns头部位置
    bpf_probe_read_kernel(&query.header, sizeof(query.header), BPF_CORE_READ(skb, head) + dns_offset);
    struct dns_information message = { 0 };
    bpf_probe_read_kernel(message.data, sizeof(message.data), BPF_CORE_READ(skb, head) + dns_offset + sizeof(struct dns_header));

    return 0;
}

SEC("kprobe/udp_rcv")
int BPF_KPROBE(udp_rcv, struct sk_buff *skb) { return 0; }