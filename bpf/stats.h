//
// Created by ivan on 02.01.2025.
//

#ifndef STATS_H
#define STATS_H
//

#include <linux/bpf.h>


struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

// Структура ключа
struct ip_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
};

#endif //STATS_H
