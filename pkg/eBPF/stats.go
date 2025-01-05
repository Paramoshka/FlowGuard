package eBPF

import (
	"fmt"
	"github.com/cilium/ebpf"
)

// StatsValue представляет значение карты (статистика)
type StatsValue struct {
	Packets uint64
	Bytes   uint64
}

// ShowStats читает и отображает статистику из eBPF карты
func ShowStats(coll *ebpf.Collection) error {
	// Открываем eBPF-карту статистики
	fmt.Println(*coll.Maps["stats_map"])
	return nil
}
