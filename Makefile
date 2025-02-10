KERNEL_VERSION := $(shell uname -r)
KERNEL_MAJOR := $(shell echo $(KERNEL_VERSION) | cut -d. -f1)
KERNEL_MINOR := $(shell echo $(KERNEL_VERSION) | cut -d. -f2)
KERNEL_PATCH := $(shell echo $(KERNEL_VERSION) | cut -d. -f3 | cut -d- -f1)

JSON_CONTENT := $(shell cat ./hack/add.json | jq -c .)
JSON_DELETE :=  $(shell cat ./hack/delete.json | jq -c .)
SRC_FILES := $(shell find ./ebpf -maxdepth 1 -type f -name "*.c" -exec readlink -f {} \;)

all:
	#bpftool btf dump file /sys/kernel/btf/vmlinux   format c > ./ebpf/headers/vmlinux.h
	#bpftool btf dump file /sys/kernel/btf/nf_tables format c > ./ebpf/headers/btf/nf_tables.h
	echo "#define COMPILE_LINUX_VERSION_CODE KERNEL_VERSION(${KERNEL_MAJOR}, ${KERNEL_MINOR}, ${KERNEL_PATCH})" > ebpf/headers/version.h
	#nft flush ruleset
	#iptables -F
	#iptables -A OUTPUT -d 8.8.8.8 -p icmp -j DROP
	CUSTOM_DEFINE='-DUSE_RING_BUF ' go generate ./...
	go run ./cmd/ebpf -ko ./bin/src/iptables-trace.ko
	#go run ./cmd/ebpf -ko ./bin/src/iptables-trace.ko > ./logs/trace.log 2>&1

build_kernel:
	cd kernel && \
	mkdir -p tmp && \
	cp iptables-trace.c ./tmp && \
	cp Makefile ./tmp && \
	cd tmp && make && cd - && \
	cp ./tmp/iptables-trace.ko ../bin/src && \
	rm -rf ./tmp


build: clean tidy build_kernel
	#bpftool btf dump file /sys/kernel/btf/vmlinux   format c > ./ebpf/headers/vmlinux.h
	#bpftool btf dump file /sys/kernel/btf/nf_tables format c > ./ebpf/headers/btf/nf_tables.h

	echo "#define COMPILE_LINUX_VERSION_CODE KERNEL_VERSION(5,16,0)" > ebpf/headers/version.h
	go generate ./...
	go build -o ./bin/tmp/5.16.0 ./cmd/ebpf

	echo "#define COMPILE_LINUX_VERSION_CODE KERNEL_VERSION(5,19,0)" > ebpf/headers/version.h
	go generate ./...
	go build -o ./bin/tmp/5.19.0 ./cmd/ebpf

	echo "#define COMPILE_LINUX_VERSION_CODE KERNEL_VERSION(6,4,0)" > ebpf/headers/version.h
	go generate ./...
	go build -o ./bin/tmp/6.4.0 ./cmd/ebpf

	find ./bin/tmp -type f ! -name "*.gz" | xargs -I F gzip -k F
	mv ./bin/tmp/*.gz ./bin/src/
	go build -o bin/entry .

clean:
	rm -rf bin
	@bash -c 'mkdir -p bin/{tmp,src}'
	find . -type f -name "*.o" | xargs -I F rm F

tidy:
	go mod tidy
	go mod vendor

#trace-cmd record -p function_graph -O funcgraph-proc -g nft_do_chain
#trace-cmd report

#trace-cmd record -p function_graph -O funcgraph-proc ping -w 1 8.8.8.8
#trace-cmd report > a.txt