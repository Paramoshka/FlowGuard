
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "stats.h"

// Карта для хранения статистики
struct bpf_map_def SEC("maps") stats_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_key_t),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

// Основная eBPF программа
SEC("xdp")
int collect_stats(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Проверяем, что это IP-пакет
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    // Парсим IP-заголовок
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Парсим TCP/UDP-заголовок
    struct ip_key_t key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        key.dst_port = udp->dest;
    } else {
        return XDP_PASS;  // Не поддерживаемый протокол
    }

    // Обновляем статистику
    __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&stats_map, &key, &init_val, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
