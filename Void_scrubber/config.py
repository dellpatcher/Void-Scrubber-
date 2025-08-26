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
        allowed_ntp {
            type ipv4_addr
        }
    }

    chains {
        input {
            type filter hook input priority 0; policy drop;

            # Accept established/related
            ct state established,related accept

            # Anti-spoofing: drop packets from reserved/bogon sources
            ip saddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } drop
            ip6 saddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } drop

            # Drop blacklisted IPs
            ip saddr @blacklist drop

            # Allow trusted IPs
            ip saddr @trusted_ips accept

            # Allow DNS from trusted servers only
            udp dport 53 ip saddr @allowed_dns accept

            # Allow NTP from trusted servers only
            udp dport 123 ip saddr @allowed_ntp accept

            # Allow DHCP
            udp sport 67 udp dport 68 accept
            udp sport 547 udp dport 546 accept

            # Allow ICMP echo-request (ping) from trusted only
            ip protocol icmp icmp type echo-request ip saddr @trusted_ips accept
            ip6 nexthdr icmpv6 icmpv6 type { 128 } ip6 saddr @trusted_ips accept

            # Allow essential ICMPv6 (ND, RA, etc.)
            ip6 nexthdr icmpv6 icmpv6 type { 133, 134, 135, 136, 137 } accept

            # Limit SSH, HTTP, HTTPS (new connections)
            tcp dport {22, 80, 443} ct state new limit rate 30/second burst 60 packets accept

            # Drop invalid packets
            ct state invalid drop

            # Log and drop everything else
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