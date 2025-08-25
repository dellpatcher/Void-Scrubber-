# 🔸 XDP/eBPF loader and builder
import tempfile
import os
from .config import INTERFACE
from .utils import run

BPF_PROGRAM = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_spoof(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = __bpf_ntohl(ip->saddr);

    // Drop RFC1918 spoofed IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ((src_ip >> 24) == 10 ||
        (src_ip >> 20) == 0xac1 ||
        (src_ip >> 16) == 0xc0a8) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

def build_bpf_program():
    with tempfile.TemporaryDirectory() as tmpdir:
        c_file = os.path.join(tmpdir, "drop_spoof.c")
        obj_file = os.path.join(tmpdir, "drop_spoof.o")
        with open(c_file, "w") as f:
            f.write(BPF_PROGRAM)
        cmd = f"clang -O2 -target bpf -c {c_file} -o {obj_file}"
        success, output = run(cmd)
        if not success:
            return False, output
        return True, obj_file

def load_xdp():
    success, obj_file = build_bpf_program()
    if not success:
        return False, obj_file
    return run(f"ip link set dev {INTERFACE} xdp obj {obj_file} sec xdp")

def unload_xdp():
    return run(f"ip link set dev {INTERFACE} xdp off")