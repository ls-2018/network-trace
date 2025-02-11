#ifndef __COUNTERS_H__
#define __COUNTERS_H__
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_rate SEC(".maps");

static __always_inline u64 upd_counter_in_map(void *map)
{
    const u32 key = 0;
    const u64 init_val = 0;

    u64 *val = bpf_map_lookup_elem(map, &key);
    if (val) {
        return __sync_fetch_and_add(val, 1);
    }

    bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);

    return init_val;
}

#define PKT_COUNTER_INC() upd_counter_in_map(&pkt_counter)

static __always_inline bool grab_data()
{
    const u32 sample_rate_key = 0;
    const u32 pkt_cnt = PKT_COUNTER_INC();

    u64 *sample_rate_val = bpf_map_lookup_elem(&sample_rate, &sample_rate_key);

    if (sample_rate_val) {
        const u64 safe_sample_rate_val = __sync_fetch_and_add(sample_rate_val, 0);
        if (safe_sample_rate_val > 0) {
            if (pkt_cnt % 100 > safe_sample_rate_val) {
                return 0;
            }
        }
    }
    return 1;
}

#endif