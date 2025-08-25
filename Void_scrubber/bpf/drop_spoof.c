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

    // L4: TCP/UDP/ICMP DDoS basic stateless filtering
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + (ip->ihl * 4);
        if ((void*)(tcp + 1) > data_end)
            return XDP_DROP;

        // Drop XMAS, NULL, and other malformed TCP packets
        if ((tcp->fin && tcp->urg && tcp->psh) || 
            (tcp->syn == 0 && tcp->ack == 0 && tcp->fin == 0 && tcp->rst == 0 && tcp->psh == 0 && tcp->urg == 0))
            return XDP_DROP;

        // Drop SYN floods (stateless: drop if only SYN, no ACK, no payload)
        if (tcp->syn && !tcp->ack && ((void*)(tcp + 1) == data_end))
            return XDP_DROP;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + (ip->ihl * 4);
        if ((void*)(udp + 1) > data_end)
            return XDP_DROP;

        // Drop UDP packets with length < 8 (invalid)
        if (__bpf_ntohs(udp->len) < 8)
            return XDP_DROP;

        // Drop UDP floods to common amplification ports (NTP, DNS, SSDP, Memcached)
        __u16 dport = __bpf_ntohs(udp->dest);
        if (dport == 53 || dport == 123 || dport == 1900 || dport == 11211)
            return XDP_DROP;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void*)ip + (ip->ihl * 4);
        if ((void*)(icmp + 1) > data_end)
            return XDP_DROP;

        // Drop ICMP echo-request floods (type 8)
        if (icmp->type == 8)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";