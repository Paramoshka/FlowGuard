package eBPF

import (
	"fmt"
	"log"
	"os"
)

import (
	"github.com/cilium/ebpf"
	_ "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func Loader() {
	// Укажите путь к вашему скомпилированному eBPF ELF-файлу
	const bpfProgPath = "build/stats.o"
	const ifaceName = "eth0" // Укажите интерфейс, к которому хотите привязать программу

	// Открываем скомпилированный eBPF ELF-файл
	spec, err := ebpf.LoadCollectionSpec(bpfProgPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	// Создаем коллекцию для карты и программы
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Достаём программу XDP
	prog := coll.Programs["collect_stats"]
	if prog == nil {
		log.Fatalf("Program 'collect_stats' not found in ELF")
	}

	// Находим интерфейс
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find network interface: %v", err)
	}

	// Привязываем программу к интерфейсу с помощью XDP
	xdpLink, err := link.AttachXDP(link.(*netlink.LinkAttrs), prog.FD(), ebpf.XDP_FLAGS_SKB_MODE)
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("XDP program attached to %s\n", ifaceName)

	// Завершаем программу, но программа XDP останется активной, пока она не будет отвязана.
	fmt.Println("Press Ctrl+C to exit...")
	<-make(chan os.Signal, 1)
}
