package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel ebpf_interface bpf/ebpf_interface.bpf.c

const defaultInterface = "upfgtp"

func main() {
	ifaceName := flag.String("iface", defaultInterface, "network interface to attach XDP program")
	interval := flag.Duration("interval", time.Second, "refresh interval for stats display")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := ebpf_interfaceObjects{}
	if err := loadEbpf_interfaceObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("lookup interface %s: %v", *ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCount,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attach XDP to %s: %v", *ifaceName, err)
	}
	defer xdpLink.Close()

	fmt.Printf("Starting packet counter on interface %s\n", *ifaceName)
	fmt.Println("Press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	key := uint32(0)
	var value uint64

	for {
		select {
		case <-ticker.C:
			if err := objs.PacketCount.Lookup(&key, &value); err != nil {
				log.Printf("lookup packet count: %v", err)
				continue
			}
			printStats(*ifaceName, value)
		case <-sig:
			fmt.Println("Stopping packet counter")
			return
		}
	}
}

func printStats(iface string, packets uint64) {
	fmt.Println("+----------------------------+")
	fmt.Printf("| Interface: %-12s |\n", iface)
	fmt.Println("+----------------------------+")
	fmt.Printf("| %-10s | %12d |\n", "Packets", packets)
	fmt.Println("+----------------------------+")
}
