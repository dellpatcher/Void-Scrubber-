# NetScrubber

**NetScrubber** is a Python-based firewall and packet filtering tool using nftables and XDP eBPF. It helps with managing trusted/blacklisted IPs and blocking spoofed traffic on your network.

## Features
- **Firewall**: Control incoming/outgoing traffic via nftables.
- **XDP eBPF**: Drop spoofed IPs using XDP.
- **GUI**: Intuitive Tkinter-based interface for managing the firewall.
- **Multithreaded**: Non-blocking interface for smooth user experience

- 
**NetScrubber** is currently in its **alpha testing** phase. While the core functionality is operational, the tool may still have some bugs, incomplete features, or other issues that could affect its performance. We encourage testers to try out the tool, but please be aware that it is not yet ready for production environments.

### Known Limitations:
- **Potential Bugs**: Some features might not work as expected.
- **Compatibility**: Only tested on Linux systems with `nftables`, `clang`, and `iproute2` installed.
- **No Guarantee of Stability**: Please use this tool with caution, especially on production systems.

By participating in alpha testing, you help us improve the tool, so we appreciate any feedback or bug reports. 

Thank you for helping us improve **NetScrubber**!
