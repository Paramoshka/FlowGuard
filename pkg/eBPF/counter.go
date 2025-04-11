package eBPF

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

func ShowPackets() {

	spec, err := ebpf.LoadCollectionSpec("/app/counter.o")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	prog := coll.Programs["count_packets"]
	if prog == nil {
		panic("No program named 'collect_stats' found in collection")
	}

	var iface = "wlo1"

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
		panic(err)
	}
	defer lnk.Close()

	PktCount := coll.Maps["pkt_count"]

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var count uint64
			err := PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}

	fmt.Printf("Successfully loaded program:  and attached BPF program.")

}
