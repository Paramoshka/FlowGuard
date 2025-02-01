package eBPF

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type BlockedIps struct {
}

func (bl *BlockedIps) init() {
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
}
