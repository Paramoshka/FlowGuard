#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>


struct forwarding_rule {
    __u32 src_ip;   // Исходный IP-адрес (в формате network byte order)
    __u32 src_mask; // Маска подсети источника
    __u16 src_port; // Исходный порт
    __u32 dst_ip;   // Адрес назначения
    __u16 dst_port; // Порт назначения
};


//mask + ip
struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} forwarding_map SEC(".maps");


SEC("tcx/egress")  // Новый формат секции
int forward_traffic(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr,
    };
    

    __u32 action = bpf_map_lookup_elem(&forwarding_map, &key);
    if (action) {
        //todo
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
