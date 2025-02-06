docker rm if-test --force
ip link delete veth_host
docker run -d --name if-test --network none registry.cn-hangzhou.aliyuncs.com/acejilam/centos:8 sleep 36000
docker exec -it if-test ip addr

pid=$(ps -ef | grep "sleep 36000" | grep -v grep | awk '{print $2}')
echo $pid
mkdir -p /var/run/netns
ln -s /proc/$pid/ns/net /var/run/netns/$pid

# Create a pair of veth interfaces
ip link add name veth_host type veth peer name veth_container
# Put one of them in the new net ns
ip link set veth_container netns $pid

# In the container, setup veth_container
ip netns exec $pid ip link set veth_container name eth0
ip netns exec $pid ip addr add 172.17.1.2/16 dev eth0
ip netns exec $pid ip link set eth0 up
ip netns exec $pid ip route add default via 172.17.0.1

# In the host, set veth_host up
ip link set veth_host up

ip addr add 172.17.1.1/16 dev veth_host

# 让子网通过宿主机上 eth0 去访问外网的话
docker exec -it if-test ping -c1 172.17.1.1

# ip addr delete 172.17.1.1/16 dev veth_host
ip link set veth_host master docker0

iptables -P FORWARD ACCEPT # 数据包 会从 ns->veth_host->docker0
#iptables -L -t nat
#ip netns exec $pid tcpdump -i eth0 host 39.106.233.176 -nn
#tcpdump -i veth_host host 39.106.233.176 -nn
#tcpdump -i docker0 host 39.106.233.176 -nn
echo 1 > /proc/sys/net/ipv4/ip_forward
# 数据包 会从 docker0->eth0
#tcpdump -i eth0 host 39.106.233.176 -nn