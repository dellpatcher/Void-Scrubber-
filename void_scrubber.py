#!/usr/bin/env python3
import subprocess
import sys
import os
import tempfile
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

NFT_RULES = """
flush ruleset

table inet void_scrubber {
    sets {
        trusted_ips {
            type ipv4_addr
            flags interval
        }
        blacklist {
            type ipv4_addr
            timeout 10m
        }
    }

    chains {
        input {
            type filter hook input priority 0; policy drop;

            ct state established,related accept
            ip saddr @trusted_ips accept
            ip saddr @blacklist drop

            tcp dport {22, 80, 443} ct state new limit rate 100/second burst 200 packets accept

            log prefix "VOID_DROP: " flags all counter
            drop
        }

        forward {
            type filter hook forward priority 0; policy drop;
        }

        output {
            type filter hook output priority 0; policy accept;
        }
    }
}
"""

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

INTERFACE = "eth0"  # Change this for your network interface
NFT_PATH = "/etc/nftables.d/void_scrubber.nft"

def run(cmd):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return proc.returncode == 0, proc.stdout + proc.stderr
    except Exception as e:
        return False, str(e)

def write_nft_rules():
    try:
        os.makedirs(os.path.dirname(NFT_PATH), exist_ok=True)
        with open(NFT_PATH, "w") as f:
            f.write(NFT_RULES)
        return True, f"NFTables rules written to {NFT_PATH}"
    except Exception as e:
        return False, f"Error writing nftables rules: {e}"

def init_nft():
    success, msg = write_nft_rules()
    if not success:
        return False, msg
    return run(f"nft -f {NFT_PATH}")

def add_trusted(ip):
    return run(f"nft add element inet void_scrubber trusted_ips {{ {ip} }}")

def remove_trusted(ip):
    return run(f"nft delete element inet void_scrubber trusted_ips {{ {ip} }}")

def block_ip(ip):
    return run(f"nft add element inet void_scrubber blacklist {{ {ip} }}")

def unblock_ip(ip):
    return run(f"nft delete element inet void_scrubber blacklist {{ {ip} }}")

def status():
    return run("nft list ruleset")

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

def preconfig():
    # Initialize nft, load xdp, add local subnet trusted IP (change subnet accordingly)
    success, msg = init_nft()
    if not success:
        return False, f"Init nftables failed: {msg}"
    success, msg = load_xdp()
    if not success:
        return False, f"Load XDP failed: {msg}"
    # Example: trust local subnet 192.168.1.0/24 (modify as needed)
    success, msg = add_trusted("192.168.1.0-192.168.1.255")
    if not success:
        return False, f"Add trusted subnet failed: {msg}"
    return True, "Preconfiguration complete"

# ---------- GUI ----------

class VoidScrubberGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Void Scrubber Firewall Control")

        # Frame for buttons
        frame = tk.Frame(root)
        frame.pack(pady=10)

        tk.Button(frame, text="Initialize Firewall (nftables)", command=self.threaded(self.do_init)).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame, text="Load XDP eBPF", command=self.threaded(self.do_xdp_load)).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(frame, text="Unload XDP", command=self.threaded(self.do_xdp_unload)).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(frame, text="One-Click Preconfig", command=self.threaded(self.do_preconfig)).grid(row=0, column=3, padx=5, pady=5)

        # Trusted IP management
        trusted_frame = tk.LabelFrame(root, text="Manage Trusted IPs")
        trusted_frame.pack(padx=10, pady=5, fill='x')

        tk.Label(trusted_frame, text="IP or range:").grid(row=0, column=0, padx=5, pady=5)
        self.trusted_ip_entry = tk.Entry(trusted_frame, width=30)
        self.trusted_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(trusted_frame, text="Add", command=self.threaded(self.do_add_trusted)).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(trusted_frame, text="Remove", command=self.threaded(self.do_remove_trusted)).grid(row=0, column=3, padx=5, pady=5)

        # Blacklist management
        blacklist_frame = tk.LabelFrame(root, text="Manage Blacklist")
        blacklist_frame.pack(padx=10, pady=5, fill='x')

        tk.Label(blacklist_frame, text="IP or range:").grid(row=0, column=0, padx=5, pady=5)
        self.blacklist_ip_entry = tk.Entry(blacklist_frame, width=30)
        self.blacklist_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(blacklist_frame, text="Add", command=self.threaded(self.do_add_blacklist)).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(blacklist_frame, text="Remove", command=self.threaded(self.do_remove_blacklist)).grid(row=0, column=3, padx=5, pady=5)

        # Status output
        status_frame = tk.LabelFrame(root, text="Firewall Status / Logs")
        status_frame.pack(padx=10, pady=10, fill='both', expand=True)

        self.output_text = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=20, bg="#222", fg="#eee")
        self.output_text.pack(fill='both', expand=True)

        tk.Button(root, text="Show nftables Ruleset", command=self.threaded(self.do_status)).pack(pady=5)

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def threaded(self, func):
        def wrapper():
            threading.Thread(target=func).start()
        return wrapper

    def do_init(self):
        self.log("Initializing nftables...")
        success, output = init_nft()
        self.log(output)
        self._msgbox(success, "Initialize nftables")

    def do_xdp_load(self):
        self.log("Loading XDP eBPF program...")
        success, output = load_xdp()
        self.log(output)
        self._msgbox(success, "Load XDP")

    def do_xdp_unload(self):
        self.log("Unloading XDP program...")
        success, output = unload_xdp()
        self.log(output)
        self._msgbox(success, "Unload XDP")

    def do_preconfig(self):
        self.log("Running preconfiguration...")
        success, output = preconfig()
        self.log(output)
        self._msgbox(success, "Preconfiguration")

    def do_add_trusted(self):
        ip = self.trusted_ip_entry.get().strip()
        if not ip:
            self._msgbox(False, "Please enter an IP or range to add to trusted IPs.")
            return
        self.log(f"Adding trusted IP: {ip}")
        success, output = add_trusted(ip)
        self.log(output)
        self._msgbox(success, f"Add Trusted IP {ip}")

    def do_remove_trusted(self):
        ip = self.trusted_ip_entry.get().strip()
        if not ip:
            self._msgbox(False, "Please enter an IP or range to remove from trusted IPs.")
            return
        self.log(f"Removing trusted IP: {ip}")
        success, output = remove_trusted(ip)
        self.log(output)
        self._msgbox(success, f"Remove Trusted IP {ip}")

    def do_add_blacklist(self):
        ip = self.blacklist_ip_entry.get().strip()
        if not ip:
            self._msgbox(False, "Please enter an IP or range to add to blacklist.")
            return
        self.log(f"Adding to blacklist: {ip}")
        success, output = block_ip(ip)
        self.log(output)
        self._msgbox(success, f"Add Blacklist {ip}")

    def do_remove_blacklist(self):
        ip = self.blacklist_ip_entry.get().strip()
        if not ip:
            self._msgbox(False, "Please enter an IP or range to remove from blacklist.")
            return
        self.log(f"Removing from blacklist: {ip}")
        success, output = unblock_ip(ip)
        self.log(output)
        self._msgbox(success, f"Remove Blacklist {ip}")

    def do_status(self):
        self.log("Fetching nftables ruleset...")
        success, output = status()
        if success:
            self.log(output)
        else:
            self.log(f"Error: {output}")
        self._msgbox(success, "Status")

    def _msgbox(self, success, title):
        if success:
            messagebox.showinfo(title, "Operation completed successfully.")
        else:
            messagebox.showerror(title, "Operation failed. See logs.")

def main():
    root = tk.Tk()
    app = VoidScrubberGUI(root)
    root.geometry("900x700")
    root.mainloop()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: It's recommended to run this program as root for full functionality.")
    main()
