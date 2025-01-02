#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

// Структура для правил пересылки
struct forwarding_rule {
    __u32 forward_ip;   // IP-адрес для пересылки
    __u16 forward_port; // Порт для пересылки
};

// Структура для отслеживания соединений (для обратного трафика)
struct conn_track {
    __u32 orig_src_ip;   // Исходный IP клиента
    __u16 orig_src_port; // Исходный порт клиента
    __u32 orig_dst_ip;   // Исходный IP назначения (до пересылки)
    __u16 orig_dst_port; // Исходный порт назначения (до пересылки)
};

// Первая карта - поиск по source IP (LPM Trie)
struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);  // Флаг существования правила
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} src_lookup_map SEC(".maps");

// Вторая карта - правила пересылки
struct forwarding_key {
    __u32 src_ip;    // Исходный IP
    __u16 dst_port;  // Порт назначения
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct forwarding_key);
    __type(value, struct forwarding_rule);
    __uint(max_entries, 255);
} forwarding_rules SEC(".maps");

// Третья карта - отслеживание соединений (для обратного трафика)
struct conn_key {
    __u32 src_ip;    // IP сервера (forward_ip)
    __u16 src_port;  // Порт сервера (forward_port)
    __u32 dst_ip;    // IP клиента
    __u16 dst_port;  // Порт клиента
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_track);
    __uint(max_entries, 1024);
} conn_track_map SEC(".maps");

// Программа для исходящего трафика (egress)
SEC("tcx/egress")
int forward_traffic_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Проверка минимального размера для Ethernet-заголовка
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Проверка минимального размера для IP-заголовка
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct ipv4_lpm_key src_key = {
        .prefixlen = 32,
        .addr = ip->saddr,
    };

    __u32 *rule_exists = bpf_map_lookup_elem(&src_lookup_map, &src_key);
    if (!rule_exists)
        return XDP_PASS;

    __u16 dst_port = 0;
    __u16 src_port = 0;

    // Проверка размера пакета для транспортного заголовка
    void *transport_hdr = (void *)ip + (ip->ihl * 4);
    if (transport_hdr + sizeof(struct tcphdr) > data_end)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_hdr;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_hdr;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    struct forwarding_key fwd_key = {
        .src_ip = ip->saddr,
        .dst_port = dst_port,
    };

    struct forwarding_rule *rule = bpf_map_lookup_elem(&forwarding_rules, &fwd_key);
    if (rule) {
        // Сохраняем информацию о соединении для обратного трафика
        struct conn_key ck = {
            .src_ip = rule->forward_ip,
            .src_port = rule->forward_port,
            .dst_ip = ip->saddr,
            .dst_port = src_port,
        };
        struct conn_track ct = {
            .orig_src_ip = ip->saddr,
            .orig_src_port = src_port,
            .orig_dst_ip = ip->daddr,
            .orig_dst_port = dst_port,
        };
        bpf_map_update_elem(&conn_track_map, &ck, &ct, BPF_ANY);

        // Модифицируем пакет
        ip->daddr = rule->forward_ip;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transport_hdr;
            tcp->dest = bpf_htons(rule->forward_port);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = transport_hdr;
            udp->dest = bpf_htons(rule->forward_port);
        }
        ip->check = 0; // TODO: Пересчет контрольной суммы IP
    }

    return XDP_PASS;
}

// Программа для входящего трафика (ingress)
SEC("tcx/ingress")
int forward_traffic_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Проверка минимального размера для Ethernet-заголовка
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Проверка минимального размера для IP-заголовка
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Проверка размера пакета для транспортного заголовка
    void *transport_hdr = (void *)ip + (ip->ihl * 4);
    if (transport_hdr + sizeof(struct tcphdr) > data_end)
        return XDP_DROP;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_hdr;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_hdr;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    // Проверяем, есть ли запись о соединении
    struct conn_key ck = {
        .src_ip = ip->saddr,
        .src_port = src_port,
        .dst_ip = ip->daddr,
        .dst_port = dst_port,
    };

    struct conn_track *ct = bpf_map_lookup_elem(&conn_track_map, &ck);
    if (ct) {
        // Подменяем IP и порт источника на те, что ожидает клиент
        ip->saddr = ct->orig_dst_ip;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transport_hdr;
            tcp->source = bpf_htons(ct->orig_dst_port);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = transport_hdr;
            udp->source = bpf_htons(ct->orig_dst_port);
        }
        ip->check = 0; // TODO: Пересчет контрольной суммы IP
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";