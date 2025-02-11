# include/uapi/linux/netfilter.h
enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_INET   =  1,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_NETDEV =  5,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_NUMPROTO,
};

static const struct nft_chain_type nft_chain_filter_ipv4 = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_IPV4,
	.hook_mask	= (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_LOCAL_IN]	= nft_do_chain_ipv4,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_ipv4,
		[NF_INET_FORWARD]	= nft_do_chain_ipv4,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_ipv4,
		[NF_INET_POST_ROUTING]	= nft_do_chain_ipv4,
	},
};

static const struct nft_chain_type nft_chain_filter_arp = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_ARP,
	.owner		= THIS_MODULE,
	.hook_mask	= (1 << NF_ARP_IN) |
			  (1 << NF_ARP_OUT),
	.hooks		= {
		[NF_ARP_IN]		= nft_do_chain_arp,
		[NF_ARP_OUT]		= nft_do_chain_arp,
	},
};

static const struct nft_chain_type nft_chain_filter_ipv6 = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_IPV6,
	.hook_mask	= (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_LOCAL_IN]	= nft_do_chain_ipv6,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_ipv6,
		[NF_INET_FORWARD]	= nft_do_chain_ipv6,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_ipv6,
		[NF_INET_POST_ROUTING]	= nft_do_chain_ipv6,
	},
};

static const struct nft_chain_type nft_chain_filter_inet = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_INET,
	.hook_mask	= (1 << NF_INET_INGRESS) |
			  (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_INGRESS]	= nft_do_chain_inet_ingress,
		[NF_INET_LOCAL_IN]	= nft_do_chain_inet,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_inet,
		[NF_INET_FORWARD]	= nft_do_chain_inet,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_inet,
		[NF_INET_POST_ROUTING]	= nft_do_chain_inet,
        },
};

static const struct nft_chain_type nft_chain_filter_bridge = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_BRIDGE,
	.hook_mask	= (1 << NF_BR_PRE_ROUTING) |
			  (1 << NF_BR_LOCAL_IN) |
			  (1 << NF_BR_FORWARD) |
			  (1 << NF_BR_LOCAL_OUT) |
			  (1 << NF_BR_POST_ROUTING),
	.hooks		= {
		[NF_BR_PRE_ROUTING]	= nft_do_chain_bridge,
		[NF_BR_LOCAL_IN]	= nft_do_chain_bridge,
		[NF_BR_FORWARD]		= nft_do_chain_bridge,
		[NF_BR_LOCAL_OUT]	= nft_do_chain_bridge,
		[NF_BR_POST_ROUTING]	= nft_do_chain_bridge,
	},
};

static const struct nft_chain_type nft_chain_filter_netdev = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_NETDEV,
	.hook_mask	= (1 << NF_NETDEV_INGRESS) |
			  (1 << NF_NETDEV_EGRESS),
	.hooks		= {
		[NF_NETDEV_INGRESS]	= nft_do_chain_netdev,
		[NF_NETDEV_EGRESS]	= nft_do_chain_netdev,
	},
};

static const struct nft_chain_type nft_chain_nat_ipv4 = {
	.name		= "nat",
	.type		= NFT_CHAIN_T_NAT,
	.family		= NFPROTO_IPV4,
	.owner		= THIS_MODULE,
	.hook_mask	= (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_LOCAL_IN),
	.hooks		= {
		[NF_INET_PRE_ROUTING]	= nft_nat_do_chain,
		[NF_INET_POST_ROUTING]	= nft_nat_do_chain,
		[NF_INET_LOCAL_OUT]	= nft_nat_do_chain,
		[NF_INET_LOCAL_IN]	= nft_nat_do_chain,
	},
	.ops_register = nf_nat_ipv4_register_fn,
	.ops_unregister = nf_nat_ipv4_unregister_fn,
};

static const struct nft_chain_type nft_chain_nat_ipv6 = {
	.name		= "nat",
	.type		= NFT_CHAIN_T_NAT,
	.family		= NFPROTO_IPV6,
	.owner		= THIS_MODULE,
	.hook_mask	= (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_LOCAL_IN),
	.hooks		= {
		[NF_INET_PRE_ROUTING]	= nft_nat_do_chain,
		[NF_INET_POST_ROUTING]	= nft_nat_do_chain,
		[NF_INET_LOCAL_OUT]	= nft_nat_do_chain,
		[NF_INET_LOCAL_IN]	= nft_nat_do_chain,
	},
	.ops_register		= nf_nat_ipv6_register_fn,
	.ops_unregister		= nf_nat_ipv6_unregister_fn,
};

static const struct nft_chain_type nft_chain_nat_inet = {
	.name		= "nat",
	.type		= NFT_CHAIN_T_NAT,
	.family		= NFPROTO_INET,
	.owner		= THIS_MODULE,
	.hook_mask	= (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_PRE_ROUTING]	= nft_nat_do_chain,
		[NF_INET_LOCAL_IN]	= nft_nat_do_chain,
		[NF_INET_LOCAL_OUT]	= nft_nat_do_chain,
		[NF_INET_POST_ROUTING]	= nft_nat_do_chain,
	},
	.ops_register		= nft_nat_inet_reg,
	.ops_unregister		= nft_nat_inet_unreg,
};

static const struct nft_chain_type nft_chain_route_ipv4 = {
	.name		= "route",
	.type		= NFT_CHAIN_T_ROUTE,
	.family		= NFPROTO_IPV4,
	.hook_mask	= (1 << NF_INET_LOCAL_OUT),
	.hooks		= {
		[NF_INET_LOCAL_OUT]	= nf_route_table_hook4,
	},
};

static const struct nft_chain_type nft_chain_route_ipv6 = {
	.name		= "route",
	.type		= NFT_CHAIN_T_ROUTE,
	.family		= NFPROTO_IPV6,
	.hook_mask	= (1 << NF_INET_LOCAL_OUT),
	.hooks		= {
		[NF_INET_LOCAL_OUT]	= nf_route_table_hook6,
	},
};

static const struct nft_chain_type nft_chain_route_inet = {
	.name		= "route",
	.type		= NFT_CHAIN_T_ROUTE,
	.family		= NFPROTO_INET,
	.hook_mask	= (1 << NF_INET_LOCAL_OUT),
	.hooks		= {
		[NF_INET_LOCAL_OUT]	= nf_route_table_inet,
	},
};