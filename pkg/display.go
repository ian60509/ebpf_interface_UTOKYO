package pkg

import (
	"fmt"
	"sort"
)

const (
	BorderChar    = "+"
	HorizontalRow = "-"
	VerticalChar  = "|"
)

type StatisticsDisplay struct {
	interfaceName string
}

func NewStatisticsDisplay(ifaceName string) *StatisticsDisplay {
	return &StatisticsDisplay{
		interfaceName: ifaceName,
	}
}

func (sd *StatisticsDisplay) PrintHeader() {
	fmt.Println()
	sd.printDivider()
	fmt.Printf("| GTP Flow Statistics - Interface: %-20s |\n", sd.interfaceName)
	sd.printDivider()
}

func (sd *StatisticsDisplay) printDivider() {
	fmt.Println("+------+---------------+---------------+---------------+---------------+----------+------------+")
}

func (sd *StatisticsDisplay) printDestinationDivider() {
	fmt.Println("+------+---------------------+------------+")
}

func (sd *StatisticsDisplay) PrintColumnHeaders() {
	fmt.Printf("| %-4s | %-13s | %-13s | %-13s | %-13s | %-8s | %-10s |\n",
		"Seq", "Outer Src IP", "Outer Dst IP", "Inner Src IP", "Inner Dst IP", "TEID", "Packets")
	sd.printDivider()
}

func (sd *StatisticsDisplay) PrintStats(stats map[uint64]PacketStats, unknownCount uint64) {
	if len(stats) == 0 {
		fmt.Printf("| No parsed GTP flows detected. Unknown packets: %-10d                           |\n", unknownCount)
		sd.printDivider()
		return
	}

	// Sort by outer src IP and dst IP for consistent display
	var sortedStats []PacketStats
	for _, stat := range stats {
		sortedStats = append(sortedStats, stat)
	}

	sort.Slice(sortedStats, func(i, j int) bool {
		if sortedStats[i].SrcIP != sortedStats[j].SrcIP {
			return sortedStats[i].SrcIP < sortedStats[j].SrcIP
		}
		return sortedStats[i].DstIP < sortedStats[j].DstIP
	})

	for seq, stat := range sortedStats {
		fmt.Printf("| %-4d | %-13s | %-13s | %-13s | %-13s | %8s | %10d |\n",
			seq+1,
			stat.SrcIPString(),
			stat.DstIPString(),
			stat.InnerSrcIPString(),
			stat.InnerDstIPString(),
			stat.TEIDString(),
			stat.PacketCount)
	}

	sd.printDivider()
}

func (sd *StatisticsDisplay) PrintDestinationStats(stats map[uint32]uint64) {
	fmt.Println("| Destination IP Statistics                                                    |")
	sd.printDestinationDivider()
	fmt.Printf("| %-4s | %-19s | %-10s |\n", "Seq", "Destination IP", "Packets")
	sd.printDestinationDivider()

	if len(stats) == 0 {
		fmt.Printf("| %-4s | %-19s | %-10d |\n", "-", "No destination stats", 0)
		sd.printDestinationDivider()
		return
	}

	keys := make([]uint32, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for seq, key := range keys {
		fmt.Printf("| %-4d | %-19s | %-10d |\n", seq+1, ipToString(key), stats[key])
	}

	sd.printDestinationDivider()
}

func (sd *StatisticsDisplay) PrintSummary(stats map[uint64]PacketStats, unknownCount uint64) {
	var totalPackets uint64
	for _, stat := range stats {
		totalPackets += stat.PacketCount
	}

	fmt.Printf("| Total Flows: %-6d | Parsed Packets: %-12d | Unknown Packets: %-10d |\n", len(stats), totalPackets, unknownCount)
	sd.printDivider()
	fmt.Println()
}
