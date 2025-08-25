# 🔹 GUI logic using tkinter
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from .nft_manager import (
    init_nft, add_trusted, remove_trusted,
    block_ip, unblock_ip, status,
    add_allowed_dns
)
from .xdp_manager import load_xdp, unload_xdp

def preconfig():
    # Initialize nft, load xdp, add local subnet trusted IP (change subnet accordingly)
    success, msg = init_nft()
    if not success:
        return False, f"Init nftables failed: {msg}"
    success, msg = load_xdp()
    if not success:
        return False, f"Load XDP failed: {msg}"
    # Trust local subnets
    add_trusted("192.168.1.0-192.168.1.255")
    add_trusted("10.0.0.0-10.255.255.255")
    # Allow common DNS servers (Google, Cloudflare, local)
    add_allowed_dns("8.8.8.8")
    add_allowed_dns("8.8.4.4")
    add_allowed_dns("1.1.1.1")
    add_allowed_dns("192.168.1.1")
    return True, "Preconfiguration complete"

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