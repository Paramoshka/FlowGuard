#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>


struct forwarding_rule {
    __u32 source_ip;
    __u16 source_port;
    __u32 destination_ip;
    __u16 destination_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);  // source_ip + source_port
    __type(value, struct forwarding_rule);
} forwarding_map SEC(".maps");


SEC("tcx/egress")  // Новый формат секции
int forward_traffic(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_SHOT;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end) {
        return TC_ACT_SHOT;
    }

    __u64 key = ((__u64)ip->saddr << 16) | ((__u64)ip->id);
    struct forwarding_rule *rule = bpf_map_lookup_elem(&forwarding_map, &key);
    if (!rule) {
        return TC_ACT_OK;
    }

    ip->daddr = rule->destination_ip;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_SHOT;
        }
        tcp->dest = rule->destination_port;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(struct iphdr);
        if ((void *)udp + sizeof(struct udphdr) > data_end) {
            return TC_ACT_SHOT;
        }
        udp->dest = rule->destination_port;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
