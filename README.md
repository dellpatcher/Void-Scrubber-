# NetScrubber

**NetScrubber** is a Python-based advanced firewall and packet filtering tool that combines the power of **nftables** and **XDP eBPF** for high-performance, low-latency network protection.

Designed for home, office, and small business environments, NetScrubber provides a modern GUI, real-time packet scrubbing, and simple management of trusted and blacklisted IPs.


## Features

### Firewall Management
- Uses a powerful `nftables` ruleset
- Supports IPv6, rate limiting, anti-spoofing
- Dynamic management of trusted and blacklisted IPs

### XDP + eBPF Scrubbing
- Drops spoofed, malformed, or DDoS-related packets
- Filters traffic at the kernel level using XDP
- Compiles eBPF code using `clang` for maximum performance

### GUI Interface
- Intuitive Tkinter-based GUI
- Real-time management of:
  - Trusted IPs
  - Blacklisted IPs
  - Ruleset viewing
  - XDP activation

### Multithreaded Design
- UI stays responsive during firewall operations
- All commands run in background threads

### Modular Codebase
- Separated into:
  - GUI logic
  - nftables manager
  - XDP manager
  - Configuration
  - Utilities
  - eBPF source code



## Disclaimer

NetScrubber is currently in **alpha development**.

> Use with caution in production environments.

### Known limitations:
- Some features may still be unstable or incomplete
- Only tested on Linux systems with:
  - `nftables`
  - `clang`
  - `iproute2`
- Not intended for enterprise use — yet!

---

## Requirements

- Linux (Debian-based recommended)
- Python 3.6+
- `nftables`, `iproute2`, `clang`
- `tkinter` (usually comes with Python)
- Root privileges



# Run with root privileges
sudo python3 main.py
