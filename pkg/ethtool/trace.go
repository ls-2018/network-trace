package ethtool

//go:generate go run -mod=readonly github.com/cilium/ebpf/cmd/bpf2go -no-global-types ethtool ./../../ebpf/ethtool-trace.c -- -D${TARGET_ARCH} -I./../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function
