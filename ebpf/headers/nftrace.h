#ifndef __NFTRACE_H__
#define __NFTRACE_H__

#include "version.h"

struct nft_rule {
    //    struct list_head list;
    u64 handle : 42, genmask : 2, dlen : 12, udata : 1;
    //    unsigned char data[0];
} __attribute__((preserve_access_index));

struct nft_rule_dp {
    u64 is_last : 1, dlen : 12, handle : 42; /* for tracing */
    //    long : 0;
    //    unsigned char data[0];
} __attribute__((preserve_access_index));

struct nft_table {
    // struct list_head list;
    // struct rhltable chains_ht;
    // struct list_head chains;
    // struct list_head sets;
    // struct list_head objects;
    // struct list_head flowtables;
    // u64 hgenerator;
    u64 handle;
    //    u32 use;
    u16 family : 6, flags : 8, genmask : 2;
    u32 nlpid;
    char *name;
    //     u16 udlen;
    //     u8 *udata;
    // #if COMPILE_LINUX_VERSION_CODE > KERNEL_VERSION(6, 3, 13)
    //     u8 validate_state;
    // #endif
} __attribute__((preserve_access_index));

struct nft_chain {
    // struct nft_rule *rules_gen_0;
    // struct nft_rule *rules_gen_1;
    // struct list_head rules;
    // struct list_head list;
    // struct rhlist_head rhlhead;
    struct nft_table *table;
    u64 handle;
    // u32 use;
    // u8 flags : 5,
    //     bound : 1,
    //     genmask : 2;
    char *name;
    // u16 udlen;
    // u8 *udata;

    // /* Only used during control plane commit phase: */
    // struct nft_rule **rules_next;
} __attribute__((preserve_access_index));

struct nft_verdict {
    u32 code;
    struct nft_chain *chain;
} __attribute__((preserve_access_index));

struct nft_pktinfo {
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    //    u8 flags;
    //    u8 tprot;
    //    u16 fragoff;
    //    u16 thoff;
    //    u16 inneroff;

} __attribute__((preserve_access_index));

enum nft_chain_types { NFT_CHAIN_T_DEFAULT = 0, NFT_CHAIN_T_ROUTE, NFT_CHAIN_T_NAT, NFT_CHAIN_T_MAX };

struct nft_chain_type {
    const char *name;
    enum nft_chain_types type;
    int family;
    // struct module *owner;
    // unsigned int hook_mask;
    // nf_hookfn *hooks[6];
    // int (*ops_register)(struct net *net, const struct nf_hook_ops *ops);
    // void (*ops_unregister)(struct net *net, const struct nf_hook_ops *ops);
} __attribute__((preserve_access_index));

struct nft_base_chain {
    //    struct nf_hook_ops ops;
    //    struct list_head hook_list;
    const struct nft_chain_type *type;
    u8 policy;
    //    u8 flags;
    //    struct nft_stats *stats;
    struct nft_chain chain;
    //    struct flow_block flow_block;
} __attribute__((preserve_access_index));

struct nft_traceinfo {
#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
    const struct nft_pktinfo *pkt;
    const struct nft_base_chain *basechain;
    const struct nft_chain *chain;
    const struct nft_rule *rule;
    const struct nft_verdict *verdict;
    enum nft_trace_types type;
    //   bool packet_dumped;
    //    bool trace;
#else
#if COMPILE_LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    bool trace;
    bool nf_trace;
    bool packet_dumped;
    enum nft_trace_types type : 8;
    u32 skbid;
    const struct nft_pktinfo *pkt;
    const struct nft_base_chain *basechain;
    const struct nft_chain *chain;
    const struct nft_rule_dp *rule;
    const struct nft_verdict *verdict;
#else
    bool trace;
    bool nf_trace;
    bool packet_dumped;
    enum nft_trace_types type : 8;
    u32 skbid;
    const struct nft_base_chain *basechain;
#endif
#endif
} __attribute__((preserve_access_index));

struct trace_info {
    u32 id;
    enum nft_trace_types type;
    u8 table_name[64];
    u64 table_handle;
    u8 chain_name[64];
    u64 chain_handle;
    u64 rule_handle;
    u8 jump_target[64];
    u32 verdict;
    int family;
    u8 nfproto;
    u8 policy;
    u16 len;
    u32 mark;
    u32 iif;
    u32 oif;
    u16 iif_type;
    u16 oif_type;
    u8 iif_name[16];
    u8 oif_name[16];

    struct ip_tuple ip_info;

    u64 time;
    u64 counter;

    struct process_info process;
};

const struct trace_info *unused __attribute__((unused));
#define XT_TABLE_MAXNAMELEN 32

struct xt_table_info {
    unsigned int size;
    unsigned int number;
    unsigned int initial_entries;
    unsigned int hook_entry[5];
    unsigned int underflow[5];
    unsigned int stacksize;
    void ***jumpstack;
    unsigned char entries[0];
};

struct xt_table {
    struct list_head list;
    unsigned int valid_hooks;
    struct xt_table_info *private;
    struct module *me;
    u_int8_t af;
    int priority;
    int (*table_init)(struct net *);
    const char name[32];
};

#endif