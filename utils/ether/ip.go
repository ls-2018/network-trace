package ether

import (
	"fmt"
	"log"
	"net"
)

func Parse() {
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	// 遍历每个网络接口
	for _, iface := range interfaces {
		fmt.Printf("Interface: %s\n", iface.Name)

		// 获取该接口的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Error getting addresses for interface %s: %v", iface.Name, err)
			continue
		}

		// 遍历地址并分别检查 IPv4 和 IPv6 地址
		for _, addr := range addrs {
			// 将地址转换为 IP 类型
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// 检查是否是 IPv4 地址
			if ipNet.IP.To4() != nil {
				fmt.Printf("  IPv4: %s\n", ipNet.IP.String())
			}

			// 检查是否是 IPv6 地址
			if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
				fmt.Printf("  IPv6: %s\n", ipNet.IP.String())
			}
		}
	}
}
