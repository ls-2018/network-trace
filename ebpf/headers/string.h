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