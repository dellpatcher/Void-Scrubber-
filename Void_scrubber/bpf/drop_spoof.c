#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_scrub(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // L2: Only allow IPv4
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_DROP;

    // L3: IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_DROP;

    __u32 src_ip = __bpf_ntohl(ip->saddr);

    // Drop RFC1918, loopback, invalid, multicast, reserved
    if ((src_ip >> 24) == 10 ||                // 10.0.0.0/8
        (src_ip >> 20) == 0xac1 ||             // 172.16.0.0/12
        (src_ip >> 16) == 0xc0a8 ||            // 192.168.0.0/16
        (src_ip >> 24) == 127 ||               // 127.0.0.0/8
        (src_ip >> 24) == 0 ||                 // 0.0.0.0/8
        (src_ip >> 28) == 0xE ||               // 224.0.0.0/4 (multicast)
        (src_ip >> 28) == 0xF) {               // 240.0.0.0/4 (reserved)
        return XDP_DROP;
    }

    // Drop fragments (offset != 0)
    if (ip->frag_off & __bpf_htons(0x1FFF))
        return XDP_DROP;

    // Drop malformed packets (short length)
    if ((void*)ip + (ip->ihl * 4) > data_end)
        return XDP_DROP;

    // Drop short IP packets (less than header size)
    if (__bpf_ntohs(ip->tot_len) < (ip->ihl * 4))
        return XDP_DROP;

    // L4: TCP/UDP/ICMP DDoS basic stateless filtering
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + (ip->ihl * 4);
        if ((void*)(tcp + 1) > data_end)
            return XDP_DROP;

        // Drop XMAS scan: FIN, PSH, URG all set
        if (tcp->fin && tcp->psh && tcp->urg)
            return XDP_DROP;

        // Drop NULL scan: no flags set
        if (!(tcp->fin || tcp->syn || tcp->rst || tcp->psh || tcp->ack || tcp->urg))
            return XDP_DROP;

        // Drop FIN scan: only FIN set
        if (tcp->fin && !(tcp->syn || tcp->rst || tcp->psh || tcp->ack || tcp->urg))
            return XDP_DROP;

        // Drop SYN floods (stateless: drop if only SYN, no ACK, no payload)
        if (tcp->syn && !tcp->ack && ((void*)(tcp + 1) == data_end))
            return XDP_DROP;

        // Drop ACK floods (only ACK, no payload)
        if (tcp->ack && !(tcp->syn || tcp->fin || tcp->rst || tcp->psh || tcp->urg) && ((void*)(tcp + 1) == data_end))
            return XDP_DROP;

        // Drop RST floods (only RST, no payload)
        if (tcp->rst && !(tcp->syn || tcp->fin || tcp->ack || tcp->psh || tcp->urg) && ((void*)(tcp + 1) == data_end))
            return XDP_DROP;

        // Drop PSH+ACK floods (only PSH+ACK, no payload)
        if (tcp->psh && tcp->ack && !(tcp->syn || tcp->fin || tcp->rst || tcp->urg) && ((void*)(tcp + 1) == data_end))
            return XDP_DROP;

        // Block Mirai/QBot common ports (telnet, web, TR-069, etc.)
        __u16 dport = __bpf_ntohs(tcp->dest);
        if (dport == 23   || dport == 2323  || // Telnet
            dport == 80   || dport == 81    || dport == 82   || dport == 8080 || // Web
            dport == 7547 || dport == 5555  || dport == 37215) // TR-069, Mirai, QBot
            return XDP_DROP;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + (ip->ihl * 4);
        if ((void*)(udp + 1) > data_end)
            return XDP_DROP;

        // Drop UDP packets with length < 8 (invalid)
        if (__bpf_ntohs(udp->len) < 8)
            return XDP_DROP;

        // Drop UDP floods to common amplification ports (NTP, DNS, SSDP, Memcached, Chargen, TFTP)
        __u16 dport = __bpf_ntohs(udp->dest);
        if (dport == 53 || dport == 123 || dport == 1900 || dport == 11211 || dport == 19 || dport == 69)
            return XDP_DROP;

        // Block Mirai/QBot common ports (telnet, web, TR-069, etc.)
        if (dport == 23   || dport == 2323  ||
            dport == 80   || dport == 81    || dport == 82   || dport == 8080 ||
            dport == 7547 || dport == 5555  || dport == 37215)
            return XDP_DROP;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void*)ip + (ip->ihl * 4);
        if ((void*)(icmp + 1) > data_end)
            return XDP_DROP;

        // Drop ICMP echo-request floods (type 8)
        if (icmp->type == 8)
            return XDP_DROP;
    } else if (ip->protocol == 47) { // GRE (Generic Routing Encapsulation)
        // Mirai/QBot sometimes use GRE floods
        return XDP_DROP;
    } else if (ip->protocol == 41) { // IPv6-in-IPv4 tunneling
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";