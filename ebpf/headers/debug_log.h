const __u32 DEBUG = 1;

#define bpf_debug_printk(fmt, ...)                                                                                                                                                                                                             \
    do {                                                                                                                                                                                                                                       \
        if (DEBUG)                                                                                                                                                                                                                             \
            bpf_printk(fmt, ##__VA_ARGS__);                                                                                                                                                                                                    \
    } while (0)