#include "bpf_all.h"
#include "skbtracer.h"
#include "define/if_ether.h"
#include "define/netfiler.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} skbtracer_event SEC(".maps");

struct ipt_do_table_args {
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    struct nft_chain *chain;
    u64 start_ns;
} __attribute__((packed)) /* __attribute__((preserve_access_index)) */;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct ipt_do_table_args);
    __uint(max_entries, 1024);
} skbtracer_ipt SEC(".maps");

static __always_inline bool do_trace_skb(struct event_t *event, struct config *cfg, struct pt_regs *ctx, struct sk_buff *skb)
{
    unsigned char *l3_header;
    u8 ip_version, l4_proto;

    if (filter_pid(cfg) || filter_netns(cfg, skb) || filter_l3_and_l4_info(cfg, skb))
        return false;

    event->flags |= SKBTRACER_EVENT_IF;
    set_event_info(skb, event);
    set_pkt_info(skb, &event->pkt_info);
    set_ether_info(skb, &event->l2_info);

    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        event->l2_info.l3_proto = ETH_P_IP;
        set_ipv4_info(skb, &event->l3_info);
    } else if (ip_version == 6) {
        event->l2_info.l3_proto = ETH_P_IPV6;
        set_ipv6_info(skb, &event->l3_info);
    } else {
        return false;
    }

    l4_proto = event->l3_info.l4_proto;
    if (l4_proto == IPPROTO_TCP) {
        set_tcp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_UDP) {
        set_udp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        set_icmp_info(skb, &event->icmp_info);
    } else {
        return false;
    }

    return true;
}

static __always_inline int do_trace(struct pt_regs *ctx, struct sk_buff *skb, const char *func_name)
{
    GET_CFG();
    GET_EVENT_BUF();

    if (!do_trace_skb(event, cfg, ctx, skb))
        return 0;

    if (!filter_callstack(cfg))
        set_callstack(event, ctx);

    bpf_strncpy(event->func_name, func_name, FUNCNAME_MAX_LEN);
    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event, sizeof(struct event_t));

    return 0;
}

// netif_rx 函数的主要工作就是把接收到的数据包添加到待处理队列中，并且启动网络中断下半部处理
// (软中断部分)
SEC("kprobe/netif_rx")
int k_netif_rx(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "netif_rx");
}

// (软中断部分):netif_receive_skb
//   |-- netif_receive_skb_internal
//      |-- 没开启RPS __netif_receive_skb
//      |--   开启RPS 交给对应CPU队列
SEC("kprobe/__netif_receive_skb")
int k_nif_rcv_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "__netif_receive_skb");
}

// 根据当前缓冲区的空间,决定使用tpacket_rcv、packet_rcv  替换数据报文解析函数
SEC("kprobe/tpacket_rcv")
int k_tpacket_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "tpacket_rcv");
}

SEC("kprobe/packet_rcv")
int k_packet_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "packet_rcv");
}

// ethtool -k eth0 | grep generic-receive-offload
// ethtool -K eth0 gro on
// 处理GRO（如果系统启用了GRO）的网络数据，并将数据发送到协议层。
SEC("kprobe/napi_gro_receive")
int k_napi_gro_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "napi_gro_receive");
}

// 将skb发送出去
SEC("kprobe/__dev_queue_xmit")
int k_dev_q_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *sb_dev)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "__dev_queue_xmit");
}

/*
 * br process hook:
 * 1) rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
 * 2) int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) unsigned int br_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
 * 4) int br_nf_pre_routing_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int br_pass_frame_up(struct sk_buff *skb)
 * 6) int br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 7) void br_forward(const struct net_bridge_port *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
 * 8) int br_forward_finish(struct net *net, * struct sock *sk, struct sk_buff *skb)
 * 9) unsigned int br_nf_forward_ip(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 10)int br_nf_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 11)unsigned int br_nf_post_routing(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 12)int br_nf_dev_queue_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
 */
// 决策将不同类别的数据包做不同的分发路径  组播、单播、广播
SEC("kprobe/br_handle_frame_finish")
int k_br_handle_ff(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_handle_frame_finish");
}

// 配置的IPv4或IPv6协议相关规则。这些规则可能包括DNAT（目的网络地址转换）等操作，用于改变数据包的目的IP地址或进行其他网络处
SEC("kprobe/br_nf_pre_routing")
int k_br_nf_prero(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "br_nf_pre_routing");
}

// br_nf_pre_routing 正常操作完，会调用
SEC("kprobe/br_nf_pre_routing_finish")
int k_brnf_prero_f(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_nf_pre_routing_finish");
}
// 将数据包送往本机上层处理
SEC("kprobe/br_pass_frame_up")
int k_br_pass_f_up(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "br_pass_frame_up");
}
// 根据包类型，出发对应的处理函数
SEC("kprobe/br_netif_receive_skb")
int k_br_nif_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_netif_receive_skb");
}

// https://blog.csdn.net/wangquan1992/article/details/112328918
// 指定端口转发数据
SEC("kprobe/br_forward")
int k_br_forward(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "br_forward");
}
// 转发函数
SEC("kprobe/__br_forward")
int k___br_fwd(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "__br_forward");
}
// 公共转发接口
SEC("kprobe/br_forward_finish")
int k_br_fwd_f(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_forward_finish");
}

SEC("kprobe/br_nf_forward_ip")
int k_br_nf_fwd_ip(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "br_nf_forward_ip");
}

SEC("kprobe/br_nf_forward_finish")
int k_br_nf_fwd_fin(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_nf_forward_finish");
}

SEC("kprobe/br_nf_post_routing")
int k_br_nf_post_ro(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "br_nf_post_routing");
}

SEC("kprobe/br_nf_dev_queue_xmit")
int k_br_nf_q_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "br_nf_dev_queue_xmit");
}

/*
 * ip layer:
 * 1) int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 * 2) int ip_rcv_finish(struct net *net, * struct sock *sk, struct sk_buff *skb)
 * 3) int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 4) int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 6) ...
 */

SEC("kprobe/ip_rcv")
int k_ip_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "ip_rcv");
}

SEC("kprobe/ip_rcv_finish")
int k_ip_rcv_finish(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "ip_rcv_finish");
}

SEC("kprobe/ip_output")
int k_ip_output(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "ip_output");
}

SEC("kprobe/ip_finish_output")
int k_ip_finish_out(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "ip_finish_output");
}

static __always_inline int __ipt_do_table_out(struct pt_regs *ctx, struct sk_buff *skb)
{
    u32 pid;
    u32 verdict;
    u64 ipt_delay;
    struct ipt_do_table_args *args;

    pid = bpf_get_current_pid_tgid();
    args = bpf_map_lookup_elem(&skbtracer_ipt, &pid);
    if (args == NULL)
        return 0;
    bpf_map_delete_elem(&skbtracer_ipt, &pid);

    GET_CFG();
    GET_EVENT_BUF();

    if (!do_trace_skb(event, cfg, ctx, args->skb))
        return 0;

    event->flags |= SKBTRACER_EVENT_IPTABLE;

    verdict = PT_REGS_RC(ctx);
    ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    set_iptables_info(args->table, args->state, verdict, ipt_delay, &event->ipt_info);

    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event, sizeof(struct event_t));

    return 0;
}

SEC("kprobe/__kfree_skb")
int k___kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    GET_CFG();
    GET_EVENT_BUF();

    if (!do_trace_skb(event, cfg, ctx, skb))
        return 0;

    if (!filter_dropstack(cfg))
        set_callstack(event, ctx);

    event->flags |= SKBTRACER_EVENT_DROP;
    event->start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event->func_name, "__kfree_skb", FUNCNAME_MAX_LEN);
    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event, sizeof(struct event_t));
    return 0;
}