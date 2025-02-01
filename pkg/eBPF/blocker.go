package eBPF

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type BlockedIps struct {
}

func (bl *BlockedIps) init() {
	// Убедимся, что у нас достаточно прав для работы с eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Загружаем eBPF-программу
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Загружаем программу в ядро
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer objs.Close()

	// Прикрепляем программу к сетевому интерфейсу (например, eth0)
	iface := "eth0" // Укажите ваш интерфейс
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterIp,
		Interface: iface,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	log.Printf("eBPF program attached to %s\n", iface)

	// Добавляем IP-адреса в карты
	addIPToMap(objs.AllowedIps, "192.168.1.100") // Разрешённый IP
	addIPToMap(objs.BlockedIps, "10.0.0.1")      // Запрещённый IP

	log.Println("IP addresses added to maps")

	// Ожидаем сигнала для завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Detaching eBPF program and exiting...")
}

// addIPToMap добавляет IP-адрес в карту
func addIPToMap(m *ebpf.Map, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		log.Fatalf("Only IPv4 addresses are supported: %s", ipStr)
	}

	key := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	value := uint8(1) // Флаг (1 — разрешён/запрещён)

	if err := m.Put(key, value); err != nil {
		log.Fatalf("Failed to update map: %v", err)
	}
}
