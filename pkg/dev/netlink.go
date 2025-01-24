package dev

import (
	"github.com/vishvananda/netlink"
	"log"
)

func getDevices() map[int]string {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to list links: %v", err)
	}

	m := make(map[int]string)
	for _, l := range links {
		ifindex, ifname := l.Attrs().Index, l.Attrs().Name
		m[ifindex] = ifname
	}

	return m
}
