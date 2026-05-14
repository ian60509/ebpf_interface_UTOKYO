package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-interface/pkg"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type packet_stats -target bpfel ebpf_interface bpf/ebpf_interface.bpf.c

const defaultInterface = "upfgtp"

func main() {
	ifaceName := flag.String("iface", defaultInterface, "network interface to attach TC BPF program")
	interval := flag.Duration("interval", 2*time.Second, "refresh interval for stats display")
	includeDebug := flag.Bool("debug", false, "print debug counters")
	flag.Parse()

	// Load eBPF objects
	objs := ebpf_interfaceObjects{}
	if err := loadEbpf_interfaceObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Initialize eBPF manager with flow stats and unknown count maps
	var debugCounters *ebpf.Map
	if *includeDebug {
		debugCounters = objs.DebugCounters
	}
	ebpfMgr, err := pkg.NewEBPFManager(objs.FlowStats, objs.UnknownCount, debugCounters)
	if err != nil {
		log.Fatalf("create eBPF manager: %v", err)
	}
	defer ebpfMgr.Close()

	// Attach TC BPF program to interface
	if err := ebpfMgr.AttachXDP(*ifaceName, objs.XdpGtpParse); err != nil {
		log.Fatalf("attach XDP BPF program: %v", err)
	}

	display := pkg.NewStatisticsDisplay(*ifaceName)
	display.PrintHeader()
	display.PrintColumnHeaders()

	// Setup signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Create ticker for periodic updates
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	fmt.Println("Starting GTP packet capture. Press Ctrl+C to stop")
	time.Sleep(500 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			stats, err := ebpfMgr.GetFlowStats()
			if err != nil {
				log.Printf("get flow stats: %v", err)
				continue
			}

			destinationStats, err := ebpfMgr.GetDestinationStats()
			if err != nil {
				log.Printf("get destination stats: %v", err)
				continue
			}

			unknown, err := ebpfMgr.GetUnknownCount()
			if err != nil {
				log.Printf("get unknown count: %v", err)
				unknown = 0
			}

			display.PrintStats(stats, unknown)
			display.PrintDestinationStats(destinationStats)
			display.PrintSummary(stats, unknown)
			if *includeDebug && ebpfMgr.HasDebugCounters() {
				totalSeen, _ := ebpfMgr.GetDebugCounter(0)
				canReadEth, _ := ebpfMgr.GetDebugCounter(1)
				ethIPv4, _ := ebpfMgr.GetDebugCounter(2)
				canReadIP, _ := ebpfMgr.GetDebugCounter(3)
				isIPv4, _ := ebpfMgr.GetDebugCounter(4)
				notIPv4, _ := ebpfMgr.GetDebugCounter(5)
				udpProto, _ := ebpfMgr.GetDebugCounter(6)
				gtpPort, _ := ebpfMgr.GetDebugCounter(7)
				gtpMsg0xff, _ := ebpfMgr.GetDebugCounter(8)
				sucStats, _ := ebpfMgr.GetDebugCounter(9)

				fmt.Printf("| [DEBUG] Total: %d | CanReadEth: %d | EthIPv4: %d | CanReadIP: %d | IsIPv4: %d | NotIPv4: %d |\n",
					totalSeen, canReadEth, ethIPv4, canReadIP, isIPv4, notIPv4)
				fmt.Printf("| [DEBUG] UDP: %d | GTPPort: %d | GTPMsg0xFf: %d | SucStats: %d |\n",
					udpProto, gtpPort, gtpMsg0xff, sucStats)
			}
			fmt.Println()

		case <-sig:
			fmt.Println("\nStopping GTP packet capture")
			return
		}
	}
}
