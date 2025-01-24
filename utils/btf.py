#!/usr/bin/env python3
import subprocess,os

PROJECT_PATH = subprocess.getoutput("git rev-parse --show-toplevel")
BTF_PATH = f"{PROJECT_PATH}/internal/app/nftrace/ebpf/btf"
try:
    os.makedirs(BTF_PATH)
except Exception:
    pass


ms = subprocess.getoutput("ls /sys/kernel/btf")
for module in ms.split("\n"):
    if module and 'nf_table' in module:
        module=module.strip()
        print(module)
        os.system(f"bpftool btf dump file /sys/kernel/btf/{module} format c  > {BTF_PATH}/{module}.h")