#include "bpf_all.h"
#include "define/socket.h"

enum {
    LINK_ROLE_UNKNOWN = 0,
    LINK_ROLE_CLIENT = 1,
    LINK_ROLE_SERVER = 2
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uid_t);
    __type(value, u8);
    __uint(max_entries, 10000000);
} sock_link_type SEC(".maps");

struct proto_accept_arg {
    int flags;
    int err;
    int is_empty;
    bool kern;
};

struct state_info {
    u8 old_state;
    u8 new_state;
    u32 seq;
    u64 sk_id;
    u8 role;
};

struct event_t {
    __u16 c_port;
    __u16 s_port;
    __u16 family;
    __u16 protocol;
    u16 type;
    u16 seq;
    u8 old_state;
    u8 new_state;
    u64 sk_id;
    u32 c_ip;
    u32 s_ip;
  unsigned  __int128 c_ip6;
  unsigned  __int128 s_ip6;
    __u32 net_ns;
} __attribute__((packed));

enum {
    ERR_SUCCESS = 0,
    ERR_INIT = 1,
    ERR_FAILED = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

static __always_inline u32 get_netns(struct sk_buff *skb)
{
    u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

    // if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
    if (netns == 0) {
        struct sock *sk = BPF_CORE_READ(skb, sk);
        if (sk != NULL) {
            netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
        }
    }

    return netns;
}

// static inline __attribute__((always_inline)) unsigned __int128 bpf_swab128(unsigned __int128 x)
// {
//     uint64_t high = x >> 64;               // 获取高 64 位
//     uint64_t low = x & 0xFFFFFFFFFFFFFFFF; // 获取低 64 位
//
//     // 交换每个 64 位部分的字节顺序
//     high = __builtin_bswap64(high);
//     low = __builtin_bswap64(low);
//
//     // 将低 64 位放到高 64 位，反之亦然
//     return ((unsigned __int128)low << 64) | high;
// }

static __noinline void copy_event_from_sk(struct sock *sk, struct event_t *event, u16 type, int *err)
{
    __u32 skc_rcv_s_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 skc_rcv_d_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (bpf_ntohl(skc_rcv_s_addr) <= 0) {
        *err = ERR_FAILED;
        return;
    }

    __u32 skc_d_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u32 skc_s_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->type = type;
    switch (type) {

        case LINK_ROLE_SERVER:
            event->s_port = skc_s_port;
            event->c_port = bpf_ntohs(skc_d_port);
                bpf_probe_read_kernel(&event->s_ip, sizeof(event->s_ip), &sk->__sk_common.skc_rcv_saddr);
                bpf_probe_read_kernel(&event->c_ip, sizeof(event->c_ip), &sk->__sk_common.skc_daddr);

        /* family == AF_INET6 */
            bpf_probe_read_kernel(&event->s_ip6, sizeof(event->s_ip6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&event->c_ip6, sizeof(event->c_ip6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;

        case LINK_ROLE_UNKNOWN:
        case LINK_ROLE_CLIENT:
            event->c_port = skc_s_port;
            event->s_port = bpf_ntohs(skc_d_port);
            bpf_probe_read_kernel(&event->c_ip, sizeof(event->c_ip), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&event->s_ip, sizeof(event->s_ip), &sk->__sk_common.skc_daddr);
        /* family == AF_INET6 */
            bpf_probe_read_kernel(&event->c_ip6, sizeof(event->c_ip6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&event->s_ip6, sizeof(event->s_ip6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;
        default:
            break;
    }

    event->s_ip = bpf_ntohl(event->s_ip);
    event->c_ip = bpf_ntohl(event->c_ip);
}

static __noinline void handle_new_connection(void *ctx, struct sock *sk, const struct state_info *states)
{
    struct event_t *event;
    int _err = ERR_INIT;
    int *err = &_err;
    guard_ring_buf(&events, event, err);
    if (!event) {
        return;
    }

    if (sk) {
        const __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family != AF_INET && family != AF_INET6) {
            return;
        }

        const u16 protocol = BPF_CORE_READ(sk, sk_protocol);
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP) {
            return;
        }
        event->sk_id = states->sk_id;
        event->family = family;
        event->protocol = protocol;
        event->net_ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
        event->seq = states->seq;
        event->old_state = states->old_state;
        event->new_state = states->new_state;

        copy_event_from_sk(sk, event, states->role, err);
    } else {
        return;
    }
    if (*err == ERR_INIT) {
        *err = ERR_SUCCESS;
    }
}

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

struct tcp_fd_info {
    __u64 file;
    __u64 new_file;
    u8 cur_state;
    u8 role;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct tcp_fd_info);
    __uint(max_entries, 1024);
} fd_info_map SEC(".maps");

static __always_inline __u64 get_stack_id(void)
{
    __u64 fp;

    asm volatile("%[fp] = r10" : [fp] "+r"(fp) :);           /* FP of current tracer */
    fp = bpf_probe_read_kernel(&fp, sizeof(fp), (void *)fp); /* FP of trampoline */
    fp = bpf_probe_read_kernel(&fp, sizeof(fp), (void *)fp); /* FP of tracee's caller */
    return fp;
}

static __always_inline struct tcp_fd_info *find_fd_info(void)
{
    struct tcp_fd_info *fd_info;
    __u64 stack_id;

    stack_id = get_stack_id();

    for (int i = 0; i < 3; i++) {
        if ((fd_info = bpf_map_lookup_elem(&fd_info_map, &stack_id)))
            return fd_info;

        stack_id = bpf_probe_read_kernel(&stack_id, sizeof(stack_id), (void *)stack_id);
    }

    return NULL;
}

static __always_inline struct sock *sock_from_file(__u64 ptr)
{
    struct file *file = (void *)ptr;
    struct socket *sock = BPF_CORE_READ(file, private_data);
    return BPF_CORE_READ(sock, sk);
}

SEC("fentry/__sys_connect")
int BPF_PROG(fentry___sys_connect, int fd)
{
    struct tcp_fd_info fd_info = {};
    __u64 stack_id;

    stack_id = get_stack_id();
    bpf_map_update_elem(&fd_info_map, &stack_id, &fd_info, BPF_ANY);

    return BPF_OK;
}

SEC("fentry/__sys_connect_file")
int BPF_PROG(fentry___sys_connect_file, struct file *file)
{

    struct tcp_fd_info *fd_info = find_fd_info();
    if (!fd_info)
        return BPF_OK;

    fd_info->file = (__u64)(void *)file;
    struct sock *sk = sock_from_file(fd_info->file);
    fd_info->cur_state = BPF_CORE_READ(sk, __sk_common.skc_state);

    return BPF_OK;
}

SEC("fexit/__sys_connect")
int BPF_PROG(fexit___sys_connect, int fd, struct sockaddr *uservaddr, int addrlen, int retval)
{
    __u64 stack_id;
    stack_id = get_stack_id();

    struct tcp_fd_info *fd_info = bpf_map_lookup_and_delete(&fd_info_map, &stack_id);
    if (!fd_info)
        return BPF_OK;

    struct sock *sk = sock_from_file(fd_info->file);
    const u8 c = LINK_ROLE_CLIENT;
    const u64 id = (u64)(void *)sk;
    bpf_map_lookup_or_try_init(&sock_link_type, &id, &c);

    return BPF_OK;
}

SEC("fentry/__sys_accept4")
int BPF_PROG(fentry___sys_accept4, int fd)
{
    struct tcp_fd_info fd_info = {};
    __u64 stack_id;

    stack_id = get_stack_id();
    bpf_map_update_elem(&fd_info_map, &stack_id, &fd_info, BPF_ANY);

    return BPF_OK;
}

// 从已经建立的监听套接字队列中获取一个待处理的连接，并返回一个新的套接字描述符
SEC("fexit/do_accept")
int BPF_PROG(fexit_do_accept, struct file *file, struct proto_accept_arg *arg, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags, struct file *newfile)
{
    struct tcp_fd_info *fd_info = find_fd_info();
    if (!fd_info)
        return BPF_OK;

    fd_info->file = (__u64)(void *)file;
    if (!IS_ERR_VALUE(newfile)) {
        fd_info->new_file = (__u64)(void *)newfile;
    }

    return BPF_OK;
}

SEC("fexit/__sys_accept4")
int BPF_PROG(fexit___sys_accept4, int fd, struct sockaddr *uservaddr, int addrlen, int newfd)
{
    __u64 stack_id;

    stack_id = get_stack_id();

    struct tcp_fd_info *fd_info = bpf_map_lookup_and_delete(&fd_info_map, &stack_id);
    if (!fd_info)
        return BPF_OK;

    if (newfd < 0)
        return BPF_OK;

    return BPF_OK;
}

//__sys_accept4 和 do_accept 都是 Linux 内核中用于处理套接字连接的函数，但它们所处的层次和角色有所不同。
// 简单来说，__sys_accept4 是系统调用的实现
// 而 do_accept 是内部处理接收连接逻辑的函数。

// __sys_connect -> __sys_connect_file
// __sys_accept4 -> __sys_accept4_file -> do_accept

SEC("fentry/tcp_v4_connect") // client
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    const u64 id = (u64)(void *)sk;
    const u8 un = LINK_ROLE_CLIENT;
    bpf_map_lookup_or_try_init(&sock_link_type, &id, &un);
    return BPF_OK;
}

SEC("fentry/tcp_v6_connect") // client
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    const u64 id = (u64)(void *)sk;
    const u8 un = LINK_ROLE_CLIENT;
    bpf_map_lookup_or_try_init(&sock_link_type, &id, &un);
    return BPF_OK;
}

SEC("fentry/inet_csk_accept") // server
int BPF_PROG(fexit_inet_csk_accept, struct sock *sk, struct proto_accept_arg *arg)
{
    const u64 id = (u64)(void *)sk;
    const u8 un = LINK_ROLE_SERVER;
    bpf_map_lookup_or_try_init(&sock_link_type, &id, &un);
    return BPF_OK;
}

// SEC("kprobe/tcp_connect")   int k_tcp_connect(struct pt_regs *ctx)
// SEC("fexit/tcp_v4_do_rcv")  int BPF_PROG(fexit_tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb, int retval)
// SEC("fentry/tcp_set_state") int BPF_PROG(fentry_tcp_set_state, struct sock *sk, int state)
// SEC("fexit/tcp_set_state")  int BPF_PROG(fexit_tcp_set_state , struct sock *sk, int state)

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(k_set_state, struct sock *sk, int new_state)
{
    const u8 old_state = BPF_CORE_READ(sk, sk_state);
    // const u64 id = BPF_CORE_READ(sk, sk_uid.val); // 全是0
    const u64 id = (u64)(void *)sk;

    struct state_info info = {
        .old_state = old_state,
        .new_state = new_state,
        .sk_id = id,
    };
    if (old_state == TCP_SYN_SENT && new_state == TCP_ESTABLISHED) {
        info.seq = 5;
        info.role = LINK_ROLE_CLIENT;
        bpf_map_update_elem(&sock_link_type, &id, &info.role, BPF_ANY);
        handle_new_connection(NULL, sk, &info);
        goto exit;
    }

    if (old_state == TCP_SYN_RECV && new_state == TCP_ESTABLISHED) {
        info.seq = 6;
        info.role = LINK_ROLE_SERVER;
        bpf_map_update_elem(&sock_link_type, &id, &info.role, BPF_ANY);
        handle_new_connection(NULL, sk, &info);
        goto exit;
    }

    const u8 *val = bpf_map_lookup_elem(&sock_link_type, &id);
    if (val) {
        info.seq = 7;
        info.role = *val;
        handle_new_connection(NULL, sk, &info);
    }
exit:
    return 0;
}

// struct tcp_ipv4_event_t {
//     __u64 timestamp;
//     __u64 cpu;
//     __u32 type;
//     __u32 pid;
//     char comm[TASK_COMM_LEN];
//     __u32 saddr;
//     __u32 daddr;
//     __u16 sport;
//     __u16 dport;
//     __u32 netns;
//     __u32 fd;
//     __u32 dummy;
// };
//
// struct
//{
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __type(key, int);
//     __type(value, __u32);
//     __uint(max_entries, 1024 * 1024);
// } fdinstall_ret SEC(".maps");
//
// struct
//{
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __type(key, int);
//     __type(value, __u32);
//     __uint(max_entries, 1024 * 1024);
// } tcp_event_ipv4 SEC(".maps");
//
//
// SEC("kprobe/fd_install")
// int kprobe__fd_install(  struct pt_regs *ctx)
//{
//     u64 pid = bpf_get_current_pid_tgid();
//     unsigned long fd = PT_REGS_PARM1(ctx);
//     bpf_map_update_elem(&fdinstall_ret, &pid, &fd, BPF_ANY);
//     return 0;
// }
//
// SEC("kretprobe/fd_install")
// int kretprobe__fd_install(struct pt_regs *ctx)
//{
//     u64 pid = bpf_get_current_pid_tgid();
//     unsigned long *fd;
//     fd = bpf_map_lookup_elem(&fdinstall_ret, &pid);
//     if (fd == NULL)
//     {
//         return 0; // missed entry
//     }
//     bpf_map_delete_elem(&fdinstall_ret, &pid);
//
//     u32 cpu = bpf_get_smp_processor_id();
//     struct tcp_ipv4_event_t evt = {
//         .timestamp = bpf_ktime_get_ns(),
//         .cpu = cpu,
//         .type = TCP_EVENT_TYPE_FD_INSTALL,
//     };
//     evt.pid = pid >> 32;
//     evt.fd = *(__u32 *)fd;
//     bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
//     bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt));
//     return 0;
// }
//
SEC("kprobe/tcp_v4_destroy_sock")
int BPF_KPROBE(k_tcp_v4_destroy_sock, struct sock *sk)
{
    const u64 id = (u64)(void *)sk;
    bpf_map_delete_elem(&sock_link_type, &id);
    return 0;
}

SEC("raw_tracepoint/tcp_destroy_sock")
int rtp_tcp_destroy_sock(struct bpf_raw_tracepoint_args *ctx)
{
    struct sock *sk = (struct sock *)ctx->args[0];
    if (!sk) {
        return 0;
    }

    const u64 id = (u64)(void *)sk;
    bpf_map_delete_elem(&sock_link_type, &id);
    return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int tp_destroy_sock_func(struct trace_event_raw_tcp_event_sk *ctx)
{
    const struct sock *sk = ctx->skaddr;
    if (!sk) {
        return 0; // 如果没有有效的 sock 指针，返回
    }

    const u64 id = (u64)(void *)sk;
    bpf_map_delete_elem(&sock_link_type, &id);
    return 0;
}