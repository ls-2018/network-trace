volatile const __u32 DEBUG = 0;

#define bpf_debug_printk(fmt, ...)                                                                                     \
    do {                                                                                                               \
        if (XDPACL_DEBUG)                                                                                              \
            bpf_printk(fmt, ##__VA_ARGS__);                                                                            \
    } while (0)