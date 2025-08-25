# 🔸 nftables logic (rules, sets, status)
import os
from .config import NFT_PATH, NFT_RULES
from .utils import run

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

def add_allowed_dns(ip):
    return run(f"nft add element inet void_scrubber allowed_dns {{ {ip} }}")

def remove_allowed_dns(ip):
    return run(f"nft delete element inet void_scrubber allowed_dns {{ {ip} }}")

def status():
    return run("nft list ruleset")