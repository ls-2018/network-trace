验证nft 规则下采集到的是否正确
nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }


sudo nft add rule inet filter input tcp dport 8080 drop

<!-- sudo nft add rule inet filter output tcp sport 8080 drop -->
<!-- sudo nft add rule inet filter input tcp dport 8080 tcp flags syn drop -->

nft -a list ruleset
