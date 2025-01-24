extern int LINUX_KERNEL_VERSION __kconfig;

static __always_inline bool __is_kernel_ge_6_0_0(void) { return LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0); }

static __always_inline bool __is_str_prefix(const char *str, const char *prefix, int siz)
{
    for (int i = 0; i < siz && prefix[i]; i++)
        if (str[i] != prefix[i])
            return false;

    return true;
}