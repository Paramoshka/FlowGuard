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

// IPPortKey представляет ключ карты (IP + порт)
type IPPortKey struct {
	srcIp   uint32
	dstIp   uint32
	dstPort uint16
}

// ShowStats читает и отображает статистику из eBPF карты
func ShowStats(coll *ebpf.Collection) error {
	// Открываем eBPF-карту статистики
	statsMap := *coll.Maps["stats_map"]
	//var value uint64
	//var nextKey IPPortKey
	fmt.Println(statsMap.String())
	//for {
	//	// Читаем значение по ключу
	//	if err := statsMap.Lookup(&nextKey, &value); err != nil {
	//		return fmt.Errorf("failed to lookup value: %w", err)
	//	}
	//
	//}

	return nil
}
