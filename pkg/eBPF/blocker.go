package eBPF

import (
	"FlowGuard/pkg/config"
	"fmt"
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
	coll       *ebpf.Collection
	iface      link.Link
	cfg        *config.Config
	stopChan   chan os.Signal
	allowedIPs *ebpf.Map
	blockedIPs *ebpf.Map
}

func New(cfg *config.Config) (*BlockedIps, error) {
	// // Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Create collections
	collections, err := ebpf.LoadCollection("/app/blocker.o")
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}

	// Load eBPF program in kernel
	prog := collections.Programs["xdp_filter_ip"]
	if prog == nil {
		log.Fatalf("failed to find eBPF program")
	}

	allowedIPs := collections.Maps["allowed_ips"]
	if allowedIPs == nil {
		return nil, fmt.Errorf("eBPF map 'allowed_ips' not found")
	}

	blockedIPs := collections.Maps["blocked_ips"]
	if blockedIPs == nil {
		return nil, fmt.Errorf("eBPF map 'blocked_ips' not found")
	}

	// get index interface by name
	iface_idx, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", cfg.Interface, err))
	}

	// attach to interface
	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface_idx.Index,
	}

	//attach to interface
	link, err := link.AttachXDP(opts)
	if err != nil {
		panic(fmt.Sprintf("Failed to attach to interface %s: %v\n", cfg.Interface, err))
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	return &BlockedIps{
		coll:       collections,
		cfg:        cfg,
		iface:      link,
		stopChan:   stopChan,
		allowedIPs: allowedIPs,
		blockedIPs: blockedIPs,
	}, nil
}

func (bl *BlockedIps) ServeTraffic() error {
	log.Println("Serving traffic Blocker...")

	// load blocked IPs
	for _, addr := range bl.cfg.Allow {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Printf("Invalid IP address: %s", addr)
			continue
		}
		if err := bl.AddBlockedIP(ip); err != nil {
			log.Printf("Failed to add blocked IP %s: %v", addr, err)
		}
	}

	// load allow IPs
	for _, addr := range bl.cfg.Deny {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Printf("Invalid IP address: %s", addr)
			continue
		}
		if err := bl.AddAllowedIP(ip); err != nil {
			log.Printf("Failed to add allowed IP %s: %v", addr, err)
		}
	}

	// wait OS signal
	<-bl.stopChan
	log.Println("Stopping ServeTraffic...")
	return nil
}

func (bl *BlockedIps) Close() {
	log.Println("Closing eBPF program...")

	if bl.iface != nil {
		bl.iface.Close()
	}

	if bl.coll != nil {
		bl.coll.Close()
	}

	log.Println("eBPF program closed.")
}

// AddAllowedIP
func (bpf *BlockedIps) AddAllowedIP(ip net.IP) error {
	key := IpToUint32(ip)
	value := uint8(1) // Флаг "разрешён"
	return bpf.allowedIPs.Put(key, value)
}

// AddBlockedIP
func (bpf *BlockedIps) AddBlockedIP(ip net.IP) error {
	key := IpToUint32(ip)
	value := uint8(1) // Флаг "запрещён"
	return bpf.blockedIPs.Put(key, value)
}
