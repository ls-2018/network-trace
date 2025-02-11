nft flush ruleset

sudo nft add table ip filter
sudo nft add chain ip filter input { type filter hook input priority 0 \; }
sudo nft add rule ip filter input icmp type echo-request drop

sudo nft add table ip6 filter
sudo nft add chain ip6 filter input { type filter hook input priority 0 \; }
sudo nft add rule  ip6 filter input icmpv6 type echo-request drop


在宿主机
ping vm2404
ping fe80::20c:29ff:feaa:eae0



