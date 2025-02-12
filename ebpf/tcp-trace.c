#include "common.h"

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
    __u8 old_state;
    __u8 new_state;
    __u32 seq;
    __u8 role;
};

struct event_t {
    __u64 cur_time;
    struct sk_common skc;
    struct trace_sk_info sk_info;
    struct trace_socket_info socket_info;
    struct trace_conn_info conn_info;
    struct trace_process_info process;
};

const struct event_t *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

static __noinline void handle_new_connection(void *ctx, struct sock *sk, const struct state_info *states)
{
    struct event_t *event;
    int _err = CLEAN_ERR_INIT;
    int *err = &_err;
    guard_ring_buf(&events, event, err);
    if (!event) {
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    fill_process_info(&event->process);
    set_sock_info(sk, &event->socket_info);
    set_sk_info(sk, &event->sk_info);
    //    todo
    //    event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
    event->cur_time = bpf_ktime_get_ns();
    do {
        set_conn_info(sk, &event->conn_info, states->role, err);
        event->conn_info.role = states->role;
        event->conn_info.seq = states->seq;
        event->conn_info.old_state = states->old_state;
        event->conn_info.new_state = states->new_state;
    } while (false);

    if (*err == CLEAN_ERR_INIT) {
        *err = CLEAN_ERR_SUCCESS;
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
//     char comm[MAX_PROCESS_NAME];
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

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close_entry, struct sock *sk, long timeout)
{
    const u64 id = (u64)(void *)sk;
    bpf_map_delete_elem(&sock_link_type, &id);
    return 0;
}

// probing the tcp_data_queue kernel function, and adding the connection
// observed to the map.
SEC("kprobe/tcp_data_queue")
  int handle_tcp_data_queue(struct pt_regs *ctx) // 维护链接状态,role,throughput
{
    // first argument to tcp_data_queue is a struct sock*
    struct sock *sock = (struct sock *)PT_REGS_PARM1(ctx);
}