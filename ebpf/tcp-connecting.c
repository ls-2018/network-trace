#include "bpf_all.h"
#include "define/socket.h"

struct proto_accept_arg {
    int flags;
    int err;
    int is_empty;
    bool kern;
};

struct five_key {
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct five_key);
    __type(value, int);
    __uint(max_entries, 1024);
} ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct five_key);
    __type(value, int);
    __uint(max_entries, 1024);
} egress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 1);
} progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

struct inet_sock_set_state_args {
    __u64 unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u32 saddr;
    __u32 daddr;
};

struct event_t {
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u32 saddr;
    __u32 daddr;
    s16 type;
    __u32 netns;

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

static __noinline void copy_event_from_args(struct inet_sock_set_state_args *args, struct event_t *event, int *err)
{
    if (!args) {
        return;
    }
    event->oldstate = args->oldstate;
    event->newstate = args->newstate;
    event->sport = args->sport;
    event->dport = args->dport;
    event->family = args->family;
    __builtin_memcpy(&event->saddr, &args->saddr, sizeof(event->saddr));
    __builtin_memcpy(&event->daddr, &args->daddr, sizeof(event->daddr));
    event->saddr = bpf_ntohl(event->saddr);
    event->daddr = bpf_ntohl(event->daddr);
}

static __noinline void copy_event_from_sk(struct sock *sk, struct event_t *event, int *err)
{
    if (!sk) {
        *err = ERR_FAILED;
        return;
    }
    event->saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    if (event->saddr <= 0) {
        *err = ERR_FAILED;
        return;
    }
    event->daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __noinline void handle_new_connection(void *ctx, struct sock *sk, s16 type, struct inet_sock_set_state_args *args)
{
    struct event_t *event;
    int _err = ERR_INIT;
    int *err = &_err;
    guard_ring_buf(&events, event, err);
    if (!event) {
        return;
    }

    copy_event_from_args(args, event, err);

    if (sk) {
        __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family != AF_INET && family != AF_INET6) {
            return;
        }

        u16 protocol = BPF_CORE_READ(sk, sk_protocol);
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP) {
            return;
        }

        u32 netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

        event->family = family;
        event->protocol = protocol;
        event->netns = netns;
        event->type = type;
        copy_event_from_sk(sk, event, err);
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
    __u64 newfile;
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

// SEC("fentry/__sys_connect_file")
// int BPF_PROG(fentry___sys_connect_file, struct file *file)
//{
//
//     struct tcp_fd_info *fd_info = find_fd_info();
//     if (!fd_info)
//         return BPF_OK;
//
//     fd_info->file = (__u64)(void *)file;
//
//     return BPF_OK;
// }

SEC("fexit/__sys_connect")
int BPF_PROG(fexit___sys_connect, int fd, struct sockaddr *uservaddr, int addrlen, int retval)
{
    __u64 stack_id;

    stack_id = get_stack_id();

    struct tcp_fd_info *fd_info = bpf_map_lookup_and_delete(&fd_info_map, &stack_id);
    if (!fd_info)
        return BPF_OK;

    struct sock *sk = sock_from_file(fd_info->file);

    handle_new_connection(NULL, sk, 5, NULL);

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
    if (!IS_ERR_VALUE(newfile))
        fd_info->newfile = (__u64)(void *)newfile;

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

    struct sock *sk = sock_from_file(fd_info->newfile);
    short unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return BPF_OK;

    handle_new_connection(NULL, sk, -4, NULL);
    return BPF_OK;
}

// 开始建立连接,构建好包
SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (typeof(sk))PT_REGS_PARM1(ctx);
    handle_new_connection(ctx, sk, 3, NULL);
    return 0;
}

// 接收到客户端的第三个握手ACK报文之后，在函数tcp_check_req中
// 如果一切检查正常的话，使用回调syn_recv_sock处理创建子套接口，
// 之后由函数inet_csk_complete_hashdance将子套接口添加到ACCEPT队列中。
SEC("tp/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct inet_sock_set_state_args *args)
{
    struct sock *sk = (struct sock *)(__u64)args->skaddr;

    if (args->family != AF_INET && args->family != AF_INET6)
        return BPF_OK;

    handle_new_connection(NULL, sk, 0, args);

    // if (args->newstate == TCP_CLOSE) {
    //     struct five_key key = { .sport = BPF_CORE_READ(sk, __sk_common.skc_num), .dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), .saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr)), .daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr)), .family = BPF_CORE_READ(sk, __sk_common.skc_family) };
    //     bpf_map_delete_elem(&egress, &key);
    //     bpf_map_delete_elem(&ingress, &key);
    // }
    return BPF_OK;
}

//__sys_accept4 和 do_accept 都是 Linux 内核中用于处理套接字连接的函数，但它们所处的层次和角色有所不同。
// 简单来说，__sys_accept4 是系统调用的实现
// 而 do_accept 是内部处理接收连接逻辑的函数。

// __sys_connect -> __sys_connect_file
// __sys_accept4 -> __sys_accept4_file -> do_accept

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct five_key key = { .sport = BPF_CORE_READ(sk, __sk_common.skc_num), .dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), .saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr)), .daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr)), .family = BPF_CORE_READ(sk, __sk_common.skc_family) };
    int state = TCP_CLOSE;
    bpf_map_lookup_or_try_init(&egress, &key, &state);
    handle_new_connection(NULL, sk, 2, NULL);

    return BPF_OK;
}

// SEC("fexit/tcp_v4_do_rcv")
// int BPF_PROG(fexit_tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb, int retval)
// {
//     handle_new_connection(NULL, sk, -5, NULL);
//     return BPF_OK;
// }