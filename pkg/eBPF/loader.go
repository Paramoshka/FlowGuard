package eBPF

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
	"os"
)

func LoadStats(iface string) (*ebpf.Collection, *ebpf.Program, error) {

	spec, err := ebpf.LoadCollectionSpec("build/stats.o")
	if err != nil {
		return nil, nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	prog := coll.Programs["collect_stats"]
	if prog == nil {
		panic("No program named 'collect_stats' found in collection")
	}

	if iface == "" {
		iface = os.Getenv("INTERFACE")
	}

	if iface == "" {
		panic("No interface specified. Please set the INTERFACE environment variable to the name of the interface to be use")
	}

	iface_idx, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", iface, err))
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface_idx.Index,
		// Flags — одно из значений XDPAttachFlags (необязательно).
	}
	lnk, err := link.AttachXDP(opts)
	if err != nil {
		return nil, nil, err
	}
	defer lnk.Close()

	info, err := prog.Info()
	if err != nil {
		return nil, nil, err
	}
	id, _ := info.ID()

	fmt.Printf("Successfully loaded program id %d:  and attached BPF program.", id)

	return coll, prog, nil
}
