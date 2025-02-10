#ifndef BPF_ALL_H_
#define BPF_ALL_H_

#include "vmlinux.h"

#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tc.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_tracing_net.h"
#include "bpf/bpf_csum.h"
#include "bpf/map_helpers.h"
#include "bpf/bpf_kprobe_args.h"
#include "bpf/bpf_cleanup.h"
#include "bpf/bpf_compiler.h"
#include "debug_log.h"

#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem

char __license[] SEC("license") = "GPL";

#endif // BPF_ALL_H_