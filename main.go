package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-interface/pkg"

	"math/rand"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type packet_stats -target bpfel ebpf_interface bpf/ebpf_interface.bpf.c

const defaultInterface = "upfgtp"

func main() {
	ifaceName := flag.String("iface", defaultInterface, "network interface to attach TC BPF program")
	interval := flag.Duration("interval", 2*time.Second, "refresh interval for stats display")
	includeDebug := flag.Bool("debug", false, "print debug counters")
	uiOnly := flag.Bool("ui-only", false, "run UI with simulated data (no eBPF); for testing only")
	flag.Parse()

	// If ui-only, skip eBPF and run simulated updates for UI debugging
	if *uiOnly {
		display := pkg.NewStatisticsDisplay(*ifaceName)
		display.PrintHeader()
		display.PrintColumnHeaders()

		// simulate some flows
		randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))
		// create 5 simulated flows with different innerDst IPs
		simStats := make(map[uint64]pkg.PacketStats)
		for i := 0; i < 5; i++ {
			innerDst := uint32(0x0a000100 + uint32(i)) // 10.0.1.0 + i
			innerSrc := uint32(0x0a000200 + uint32(i))
			key := (uint64(innerSrc) << 32) | uint64(innerDst)
			simStats[key] = pkg.PacketStats{
				SrcIP:       0x0a000001,
				DstIP:       0x0a000002,
				InnerSrcIP:  innerSrc,
				InnerDstIP:  innerDst,
				TEID:        uint32(i + 1),
				PacketCount: 0,
			}
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(*interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// increment packets randomly and build destination stats
				dest := make(map[uint32]uint64)
				for k, v := range simStats {
					inc := uint64(randSrc.Intn(200))
					v.PacketCount += inc
					simStats[k] = v
					dest[v.InnerDstIP] += inc
				}

				// call display in same order as production use (destination then flows)
				display.PrintDestinationStats(dest)
				display.PrintStats(simStats, 0)
				display.PrintSummary(simStats, 0)

			case <-sig:
				display.Close()
				return
			}
		}
	}

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
	ebpfMgr, err := pkg.NewEBPFManager(objs.FlowStats, objs.UnknownCount, debugCounters, objs.IpBlacklist, objs.DestBlacklist)
	if err != nil {
		log.Fatalf("create eBPF manager: %v", err)
	}
	defer ebpfMgr.Close()

	// Start API server for blacklist management (in goroutine)
	apiServer := pkg.NewAPIServer(ebpfMgr, "8080")
	go func() {
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()
	log.Println("Blacklist API available at http://localhost:8080/api/*")

	// Attach TC BPF program to interface
	if err := ebpfMgr.AttachXDP(*ifaceName, objs.XdpGtpParse); err != nil {
		log.Fatalf("attach XDP BPF program: %v", err)
	}

	display := pkg.NewStatisticsDisplay(*ifaceName)
	defer display.Close()
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

			// compute destination rates using previous snapshot first, then update flows
			display.PrintDestinationStats(destinationStats)
			display.PrintStats(stats, unknown)
			display.PrintSummary(stats, unknown)

			// update UI with current blacklist contents
			if bl, err := ebpfMgr.GetBlacklist(); err == nil {
				display.UpdateBlacklist(bl)
			}
			if dbl, err := ebpfMgr.GetDestBlacklist(); err == nil {
				display.UpdateDestBlacklist(dbl)
			}
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
