
#ifndef __BPF_CLEANUP_H_
#define __BPF_CLEANUP_H_

#include "bpf_helpers.h"

#ifndef __cleanup
#define __cleanup(fn) __attribute__((cleanup(fn)))
#endif

struct guard_spinlock_t {
    struct bpf_spin_lock *lock;
};

static __noinline void guard_spinlock_destructor(struct guard_spinlock_t *guard) { bpf_spin_unlock(guard->lock); }

#define guard_spinlock_constructor(lock)          \
    ({                                            \
        struct guard_spinlock_t guard = { lock }; \
        bpf_spin_lock(lock);                      \
        guard;                                    \
    })

#define guard_spinlock(lock) struct guard_spinlock_t var __cleanup(guard_spinlock_destructor) = guard_spinlock_constructor(lock)

struct guard_ringbuf {
    void *data;
    int *err;
};

static __noinline void guard_ring_buf_destructor(struct guard_ringbuf *guard)
{

    if (!guard->data) {
        return;
    }
    if (*guard->err > 0) {
        bpf_ringbuf_discard(guard->data, 0);
    } else {
        bpf_ringbuf_submit(guard->data, 0);
    }
}

#define guard_ring_buf_constructor(ringbuf, size, err)      \
    ({                                                      \
        struct guard_ringbuf guard = {};                    \
        guard.err = err;                                    \
        guard.data = bpf_ringbuf_reserve(ringbuf, size, 0); \
        guard;                                              \
    })

#define guard_ring_buf(_ring_buf, _data, err)                                                                                  \
    struct guard_ringbuf _g __cleanup(guard_ring_buf_destructor) = guard_ring_buf_constructor(_ring_buf, sizeof(*_data), err); \
    _data = (typeof(_data))_g.data;

#endif // __BPF_CLEANUP_H_