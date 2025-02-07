#include "bpf_all.h"
#include "fill_trace.h"
#include "counters.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

SEC("kprobe/__nft_trace_packet")
#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
int BPF_KPROBE(kprobe_nft_trace_packet, struct nft_traceinfo *info)
#else
int BPF_KPROBE(kprobe_nft_trace_packet, const struct nft_pktinfo *pkt, const struct nft_verdict *verdict,
    const struct nft_rule_dp *rule, struct nft_traceinfo *info)
#endif
{
    char comm[60];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 's') {
        return 0;
    } else {
        bpf_printk("%s", comm);
    }

    u32 sample_rate_key = 0;
    u64 *sample_rate_val;

    u32 pkt_cnt = PKT_COUNTER_INC();

    sample_rate_val = bpf_map_lookup_elem(&sample_rate, &sample_rate_key);

    if (sample_rate_val) {
        u64 safe_sample_rate_val = __sync_fetch_and_add(sample_rate_val, 0);
        if (safe_sample_rate_val > 0) {
            if (pkt_cnt % safe_sample_rate_val) {
                return 0;
            }
        }
    }

    struct trace_info *trace;
    int _err = 0;
    int *err = &_err;
    guard_ringbuf(&events, trace, err);
    if (!trace) {
        return BPF_OK;
    }

#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    fill_trace(trace, BPF_CORE_READ(info, pkt), BPF_CORE_READ(info, verdict), BPF_CORE_READ(info, rule), info);
#else
    fill_trace(trace, pkt, verdict, rule, info);
#endif

    bpf_ringbuf_submit(trace, 0);

    return 0;
}