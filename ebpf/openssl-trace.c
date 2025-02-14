#include "bpf_all.h"

// #include "openssl.h"
// write/read
enum ssl_event_type { kSSLRead = 0, kSSLWrite };
// MAX_DATA_SIZE_OPENSSL：OpenSSL 数据的最大大小，设置为 4KB。
#define MAX_DATA_SIZE_OPENSSL 1024 * 4

SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs *ctx)
{
    // 从 pt_regs 结构体中获取 SSL_write 函数的第二个参数（si），这是 SSL_write 函数中的缓冲区指针 buf
    // const char *buf = (const char *)(ctx)->si;
    // 将 buf 的地址存储到 active_ssl_write_args_map BPF map 中。
    return 0;
}

// 用于在 SSL_write 函数返回时执行
SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs *ctx) { return 0; }

SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs *ctx)
{
    // const char *buf = (const char *)(ctx)->si;
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs *ctx)
{
    // 获取读取 地址
    // 使用 bpf_probe_read 从用户空间缓冲区 buf 中读取数据，并存储到事件结构体的 data 字段中
    // bpf_probe_read_user(event->data, event->data_len, buf);// 0没读完  buf_filled
    return 0;
}
