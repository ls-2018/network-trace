#ifndef ROLE
#define ROLE
#include "bpf_all.h"

enum connection_role {
    CONNECTION_ROLE_UNKNOWN = 0,
    CONNECTION_ROLE_CLIENT,
    CONNECTION_ROLE_SERVER,
};

static inline enum connection_role get_sock_role(struct sock *sock)
{
    // the max_ack_backlog holds the limit for the accept queue
    // if it is a server, it will not be 0
    int max_ack_backlog = 0;
    if (0 != bpf_core_read(&max_ack_backlog, sizeof(max_ack_backlog), &sock->sk_max_ack_backlog)) {
        return CONNECTION_ROLE_UNKNOWN;
    }

    return max_ack_backlog == 0 ? CONNECTION_ROLE_CLIENT : CONNECTION_ROLE_SERVER;
}

static inline u32 get_unique_id()
{
    return bpf_ktime_get_ns() % __UINT32_MAX__; // no reason to use 64 bit for this
}

#endif