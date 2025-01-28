#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// eBPF map for allow/deny rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IPv4 address
    __type(value, __u8); // 1 for allow, 0 for deny
} ip_rules SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only process IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if the source IP is in the map
    __u8 *rule_action = bpf_map_lookup_elem(&ip_rules, &ip->saddr);
    if (rule_action) {
        if (*rule_action == 0) {
            // Deny the packet
            return XDP_DROP;
        }
        // Allow the packet
        return XDP_PASS;
    }

    // Default action: pass if no rule is matched
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
