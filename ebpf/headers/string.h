#include "bpf/bpf_helpers.h"

static __always_inline int strcmp(unsigned char a[16], unsigned char b[16])
{
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i]) {
            return 1;
        }
        if (a[i++] == '\0' && b[i] == '\0') {
            break;
        }
    }
    return 0;
}
static __always_inline void bpf_strncpy(char *dst, const char *src, int n)
{
    int i = 0, j;
#define CPY(n)                                                                                                                                                                                                                                 \
    do {                                                                                                                                                                                                                                       \
        for (; i < n; i++) {                                                                                                                                                                                                                   \
            if (src[i] == 0)                                                                                                                                                                                                                   \
                return;                                                                                                                                                                                                                        \
            dst[i] = src[i];                                                                                                                                                                                                                   \
        }                                                                                                                                                                                                                                      \
    } while (0)

    for (j = 10; j < 64; j += 10)
        CPY(j);
    CPY(64);
#undef CPY
}