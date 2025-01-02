#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Карта для разрешённых IP-адресов
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IP-адрес
    __type(value, __u8); // Флаг (1 — разрешён)
} allowed_ips SEC(".maps");

// Карта для запрещённых IP-адресов
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IP-адрес
    __type(value, __u8); // Флаг (1 — запрещён)
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_filter_ip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Проверяем, что это IP-пакет
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Проверяем, есть ли IP в списке запрещённых
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked == 1) {
        // Блокируем пакет
        bpf_printk("Blocked IP: %s", src_ip);
        return XDP_DROP;
    }

    // Проверяем, есть ли IP в списке разрешённых
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (allowed && *allowed == 1) {
        // Разрешаем пакет
        return XDP_PASS;
    }

    // Если IP нет ни в одном списке, блокируем по умолчанию
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";