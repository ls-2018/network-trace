#include "bpf_all.h"
#include "define/socket.h"

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

typedef struct event {
    __be32 saddr, daddr;
    __be16 sport, dport;
    __be16 type;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __noinline void handle_new_connection(void *ctx, struct sock *sk, __be16 type)
{
    event_t ev = {};
    ev.type = type;
    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

// 开始建立连接,构建好包
SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    handle_new_connection(ctx, sk, 2);

    return 0;
}

// 接收到客户端的第三个握手ACK报文之后，在函数tcp_check_req中
// 如果一切检查正常的话，使用回调syn_recv_sock处理创建子套接口，
// 之后由函数inet_csk_complete_hashdance将子套接口添加到ACCEPT队列中。
SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    handle_new_connection(ctx, sk, 1);

    return 0;
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
    struct socket *sock;
    struct file *file;

    file = (struct file *)(void *)ptr;
    sock = BPF_CORE_READ(file, private_data);
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
    struct tcp_fd_info *fd_info;

    fd_info = find_fd_info();
    if (!fd_info)
        return BPF_OK;

    fd_info->file = (__u64)(void *)file;

    return BPF_OK;
}

SEC("fexit/__sys_connect")
int BPF_PROG(fexit___sys_connect, int fd, struct sockaddr *uservaddr, int addrlen, int retval)
{
    struct tcp_fd_info *fd_info;
    __u64 stack_id;

    stack_id = get_stack_id();

    fd_info = bpf_map_lookup_and_delete(&fd_info_map, &stack_id);
    if (!fd_info)
        return BPF_OK;

    struct sock *sk = sock_from_file(fd_info->file);
    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET) {
        bpf_printk("fd-socket: connect fd=%d sock=0x%016llx retval=%d\n", fd, (__u64)sock_from_file(fd_info->file), retval);
        bpf_printk("fd-socket: connect lport=%d rport=%d laddr=%pI4 raddr=%pI4\n", BPF_CORE_READ(sk, __sk_common.skc_num), bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), &sk->__sk_common.skc_rcv_saddr, &sk->__sk_common.skc_daddr);
    }

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

//SEC("fexit/do_accept")
//int BPF_PROG(fexit_do_accept, struct file *file, struct proto_accept_arg *arg, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags, struct file *newfile)
//{
//    struct tcp_fd_info *fd_info;
//
//    fd_info = find_fd_info();
//    if (!fd_info)
//        return BPF_OK;
//
//    fd_info->file = (__u64)(void *)file;
//    if (!IS_ERR_VALUE(newfile))
//        fd_info->newfile = (__u64)(void *)newfile;
//
//    return BPF_OK;
//}

SEC("fexit/__sys_accept4")
int BPF_PROG(fexit___sys_accept4, int fd, struct sockaddr *uservaddr, int addrlen, int newfd)
{
    struct tcp_fd_info *fd_info;
    __u64 stack_id;

    stack_id = get_stack_id();

    fd_info = bpf_map_lookup_and_delete(&fd_info_map, &stack_id);
    if (!fd_info)
        return BPF_OK;

    bpf_printk("fd-socket: accept fd=%d sock=0x%016llx retval=%d\n", fd, (__u64)sock_from_file(fd_info->file), newfd);
    if (newfd < 0)
        return BPF_OK;

    struct sock *sk = sock_from_file(fd_info->newfile);
    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET) {
        bpf_printk("fd-socket: accept newfd=%d sock=0x%016llx\n", newfd, (__u64)sk);
        bpf_printk("fd-socket: accept lport=%d rport=%d laddr=%pI4 raddr=%pI4\n", BPF_CORE_READ(sk, __sk_common.skc_num), bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), &sk->__sk_common.skc_rcv_saddr, &sk->__sk_common.skc_daddr);
    }
    return BPF_OK;
}

struct inet_sock_set_state_args {
    __u64 unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tp/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct inet_sock_set_state_args *args)
{
    struct sock *sk = (struct sock *)(__u64)args->skaddr;
    __u16 lport, rport;

    if (args->family != AF_INET && args->family != AF_INET6)
        return BPF_OK;
    if (args->newstate != TCP_ESTABLISHED)
        return BPF_OK;

    lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (args->family == AF_INET)
        bpf_printk("fd-socket: established sock=0x%016llx lport=%d rport=%d laddr=%pI4 raddr=%pI4\n", (__u64)args->skaddr, lport, rport, &sk->__sk_common.skc_rcv_saddr, &sk->__sk_common.skc_daddr);
    else
        bpf_printk("fd-socket: established sock=0x%016llx lport=%d rport=%d saddr=%pI6c daddr=%pI6c\n", (__u64)args->skaddr, lport, rport, &sk->__sk_common.skc_v6_rcv_saddr, &sk->__sk_common.skc_v6_daddr);

    return BPF_OK;
}
