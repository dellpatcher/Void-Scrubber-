# ⚙️ Constants (interface name, nft rules, paths)

INTERFACE = "eth0"  # Change this for your network interface
NFT_PATH = "/etc/nftables.d/void_scrubber.nft"

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
        allowed_dns {
            type ipv4_addr
        }
    }

    chains {
        input {
            type filter hook input priority 0; policy drop;

            ct state established,related accept
            ip saddr @trusted_ips accept
            ip saddr @blacklist drop

            # Allow DNS from trusted servers only
            udp dport 53 ip saddr @allowed_dns accept

            # Allow DHCP
            udp sport 67 udp dport 68 accept

            # Allow ICMP echo-request (ping) from trusted only
            ip protocol icmp icmp type echo-request ip saddr @trusted_ips accept

            # Limit SSH, HTTP, HTTPS
            tcp dport {22, 80, 443} ct state new limit rate 50/second burst 100 packets accept

            # Drop invalid packets
            ct state invalid drop

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