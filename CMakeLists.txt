cmake_minimum_required(VERSION 3.30)
project(ebpf-nftrace C)

set(CMAKE_C_STANDARD 11)
include_directories("./ebpf/headers")

add_library(ebpf-nftrace
        ./ebpf/ethtool-trace.c
        ./ebpf/iptables-trace.c
        ./ebpf/nftrace-trace.c
        ./ebpf/tcp-trace.c
        ./ebpf/unix-sock-trace.c
        ./ebpf/xdp-trace.c
        ./ebpf/headers/counters.h
        ./ebpf/headers/lib_kprobe.h
        ./ebpf/headers/lib_tp_msg.h
        ./ebpf/headers/lib_xdp_tc.h
)