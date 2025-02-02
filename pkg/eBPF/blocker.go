package eBPF

import (
	"FlowGuard/pkg/config"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type BlockedIps struct {
	prog     *ebpf.Program
	link     *link.Link
	linkOpts *link.XDPOptions
	cfg      *config.Config
}

func New(cfg *config.Config) BlockedIps, error {
	// // Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Create collections
	collections, err := ebpf.LoadCollection("./build/blocker.o")
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}
	defer collections.Close()

	// Load eBPF program in kernel
	prog := collections.Programs["xdp_filter_ip"]
	if prog == nil {
		log.Fatalf("failed to find eBPF program")
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

	return BlockedIps{
		prog:     prog,
		linkOpts: &opts,
		cfg:      cfg,
	}
}

func (bl *BlockedIps) ServeTraffic() error {
	link, err := link.AttachXDP(*bl.linkOpts)
	if err != nil {
		panic(fmt.Sprintf("Failed to attach to interface %s: %v\n", bl.cfg.Interface, err))
	}

	defer link.Close()
	return nil
}

func (bl *BlockedIps) Close() error {
	bl.prog.Close()
	return nil
}
