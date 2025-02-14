// netif_rx 函数的主要工作就是把接收到的数据包添加到待处理队列中，并且启动网络中断下半部处理
// (软中断部分)
// SEC("kprobe/netif_rx")int k_netif_rx(struct pt_regs *ctx)

// (软中断部分):netif_receive_skb
//   |-- netif_receive_skb_internal
//      |-- 没开启RPS __netif_receive_skb
//      |--   开启RPS 交给对应CPU队列
// SEC("kprobe/__netif_receive_skb") int k_nif_rcv_skb(struct pt_regs *ctx)


// 根据当前缓冲区的空间,决定使用tpacket_rcv、packet_rcv  替换数据报文解析函数
// SEC("kprobe/tpacket_rcv") int k_tpacket_rcv(struct pt_regs *ctx)


// SEC("kprobe/packet_rcv") int k_packet_rcv(struct pt_regs *ctx)
// ethtool -k eth0 | grep generic-receive-offload
// ethtool -K eth0 gro on
// 处理GRO（如果系统启用了GRO）的网络数据，并将数据发送到协议层。
// SEC("kprobe/napi_gro_receive") int k_napi_gro_rcv(struct pt_regs *ctx)


// 将skb发送出去
// SEC("kprobe/__dev_queue_xmit") int k_dev_q_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *sb_dev)

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
// SEC("kprobe/br_handle_frame_finish")
// 配置的IPv4或IPv6协议相关规则。这些规则可能包括DNAT（目的网络地址转换）等操作，用于改变数据包的目的IP地址或进行其他网络处
// SEC("kprobe/br_nf_pre_routing")
// int k_br_nf_prero(struct pt_regs *ctx)

// br_nf_pre_routing 正常操作完，会调用
// SEC("kprobe/br_nf_pre_routing_finish")
// int k_brnf_prero_f(struct pt_regs *ctx)

// 将数据包送往本机上层处理
// SEC("kprobe/br_pass_frame_up")

// 根据包类型，出发对应的处理函数
// SEC("kprobe/br_netif_receive_skb")

// // https://blog.csdn.net/wangquan1992/article/details/112328918
// // 指定端口转发数据
// SEC("kprobe/br_forward")
// // 转发函数
// SEC("kprobe/__br_forward")
// // 公共转发接口
// SEC("kprobe/br_forward_finish")
// SEC("kprobe/br_nf_forward_ip")
// SEC("kprobe/br_nf_forward_finish")
// SEC("kprobe/br_nf_post_routing")
// SEC("kprobe/br_nf_dev_queue_xmit")


/*
 * ip layer:
 * 1) int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 * 2) int ip_rcv_finish(struct net *net, * struct sock *sk, struct sk_buff *skb)
 * 3) int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 4) int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 6) ...
 */

// SEC("kprobe/ip_rcv")
// SEC("kprobe/ip_rcv_finish")
// SEC("kprobe/ip_output")
// SEC("kprobe/ip_finish_output")
// SEC("kprobe/__kfree_skb")



// 将struct sock类型的指针转化为struct tcp_sock类型的指针
static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) { return (struct tcp_sock *)sk; }

// 将struct sk_buff类型的指针转化为struct udphdr类型的指针
static __always_inline struct udphdr *skb_to_udphdr(const struct sk_buff *skb)
{
    return (struct udphdr *)((BPF_CORE_READ(skb, head) +              // 报文头部偏移
                              BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}

// 将struct sk_buff类型的指针转化为struct tcphdr类型的指针
static __always_inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)((BPF_CORE_READ(skb, head) +              // 报文头部偏移
                              BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}

// 将struct sk_buff类型的指针转化为struct iphdr类型的指针
static __always_inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) { return (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header)); }

// 将struct sk_buff类型的指针转化为struct ipv6hdr类型的指针
static __always_inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb) { return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header)); }




#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);         // 数据包信息
    u32 start_seq = BPF_CORE_READ(tcb, seq);          // 开始序列号
    u32 end_seq = BPF_CORE_READ(tcb, end_seq);        // 结束序列号
    struct tcp_sock *tp = tcp_sk(sk);                 // 套接字信息
    u32 rcv_wup = BPF_CORE_READ(tp, rcv_wup);         // 接收方已经确认并准备接收的数据最后一个字节的序列号
    u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);         // 期望发送发下次发送的数据字节序列号
    u32 rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);         // tcp接收窗口大小
    u32 receive_window = rcv_wup + rcv_nxt - rcv_wnd; // 当前可用的接收窗口
    receive_window = 0;

    if (end_seq >= rcv_wup && rcv_nxt + receive_window >= start_seq) {
        // bpf_printk("error_identify: tcp seq validated. \n");
        return 0;
        // 检查数据包序列号是否在接收窗口内
    }


struct tcphdr *tcp = skb_to_tcphdr(skb);
int doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff); // 得用bitfield_probed
// 读取tcp头部中的数据偏移字段
u8 *user_data = (u8 *)((u8 *)tcp + (doff * 4));
// 计算tcp的负载开始位置就是tcp头部之后的数据，将tcp指针指向tcp头部位置将其转换成unsigned
// char类型
// doff *
// 4数据偏移值(tcp的头部长度20个字节)乘以4计算tcp头部实际字节长度，32位为单位就是4字节
bpf_probe_read_str(packet->data, sizeof(packet->data), user_data); // 将tcp负载数据读取到packet->data


```
out_ipv4:
    kprobe/tcp_sendmsg
    kprobe/ip_queue_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

out_ipv6:
    kprobe/tcp_sendmsg
    kprobe/inet6_csk_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit


in_ipv4:
    kprobe/eth_type_trans
    kprobe/ip_rcv_core.isra.0
    kprobe/tcp_v4_rcv
    kprobe/tcp_v4_do_rcv
    kprobe/skb_copy_datagram_iter

in_ipv6:
    kprobe/eth_type_trans
    kprobe/ip6_rcv_core.isra.0
    kprobe/tcp_v6_rcv
    kprobe/tcp_v6_do_rcv
    kprobe/skb_copy_datagram_iter
```