package pkg

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	termbox "github.com/nsf/termbox-go"
)

// StatisticsDisplay implements a terminal UI using termui.
type StatisticsDisplay struct {
	interfaceName string

	mu        sync.RWMutex
	closeOnce sync.Once

	// latest data
	flows   map[uint64]PacketStats
	unknown uint64

	// UI widgets
	header       *widgets.Paragraph
	legend       *widgets.Paragraph
	trafficPanel *widgets.SparklineGroup
	ueTable      *widgets.Table
	destBar      *widgets.BarChart
	footer       *widgets.Paragraph
	fallback     *widgets.Paragraph

	// blacklist snapshot for UI
	blacklist     []string
	destBlacklist []string

	selectedIndex int

	quitCh    chan struct{}
	uiEnabled bool
	hasPanic  bool

	// history buffers (Mbps)
	totalSeries    []float64
	selectedSeries []float64
	destRates      map[uint32]float64 // Mbps

	// previous snapshot for rate calc
	prevFlows    map[uint64]PacketStats
	prevFlowTime time.Time
	prevDest     map[uint32]uint64
	prevDestTime time.Time

	// current per-flow rates (Mbps)
	flowRates map[uint64]float64

	limitMbps float64
}

func NewStatisticsDisplay(ifaceName string) *StatisticsDisplay {
	sd := &StatisticsDisplay{
		interfaceName: ifaceName,
		flows:         make(map[uint64]PacketStats),
		quitCh:        make(chan struct{}),
		prevFlows:     make(map[uint64]PacketStats),
		flowRates:     make(map[uint64]float64),
		prevDest:      make(map[uint32]uint64),
		destRates:     make(map[uint32]float64),
		limitMbps:     100,
	}

	if err := ui.Init(); err != nil {
		// fall back to plain printing if UI init fails
		fmt.Printf("termui init failed: %v\n", err)
		sd.uiEnabled = false
		return sd
	}

	sd.uiEnabled = true
	// Enable mouse mode only while UI is alive. We always call Close() on shutdown.
	termbox.SetInputMode(termbox.InputEsc | termbox.InputMouse)
	sd.initWidgets()

	go sd.uiEventLoop()
	go sd.uiRenderLoop()

	return sd
}

func (sd *StatisticsDisplay) initWidgets() {
	sd.header = widgets.NewParagraph()
	sd.header.Title = "5G eBPF UPF Rate-Limiter Dashboard"
	sd.header.Text = "Initializing..."
	sd.header.SetRect(0, 0, 120, 3)

	totalSpark := widgets.NewSparkline()
	totalSpark.Title = "Total"
	totalSpark.LineColor = ui.ColorWhite
	selectedSpark := widgets.NewSparkline()
	selectedSpark.Title = "Selected"
	selectedSpark.LineColor = ui.ColorCyan

	sd.trafficPanel = widgets.NewSparklineGroup(totalSpark, selectedSpark)
	sd.trafficPanel.Title = "Real-time Traffic Analytics (Last 60s)"
	sd.trafficPanel.SetRect(0, 3, 80, 15)

	sd.fallback = widgets.NewParagraph()
	sd.fallback.Title = "Render Fallback"
	sd.fallback.SetRect(0, 3, 80, 15)

	sd.legend = widgets.NewParagraph()
	sd.legend.Title = "Legend"
	sd.legend.Text = "Total=White  Selected=Cyan\nY ticks shown as text"
	sd.legend.SetRect(80, 3, 120, 7)

	sd.ueTable = widgets.NewTable()
	sd.ueTable.Title = "User Equipment (UE) List"
	sd.ueTable.RowSeparator = false
	sd.ueTable.SetRect(0, 15, 60, 30)

	sd.destBar = widgets.NewBarChart()
	sd.destBar.Title = "Top Destinations (Mbps)"
	sd.destBar.SetRect(60, 15, 120, 30)
	sd.destBar.BarWidth = 8
	sd.destBar.Labels = []string{}
	sd.destBar.Data = []float64{}
	sd.destBar.NumFormatter = func(v float64) string {
		return fmt.Sprintf("%.2f", v)
	}

	sd.selectedIndex = 0

	sd.footer = widgets.NewParagraph()
	sd.footer.Title = "Controls"
	sd.footer.Text = "[q] Quit  [↑/↓] Select UE"
	sd.footer.SetRect(0, 30, 120, 33)
}

func (sd *StatisticsDisplay) uiEventLoop() {
	if !sd.uiEnabled {
		return
	}
	uiEvents := ui.PollEvents()
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "Q":
				sd.Close()
				return
			case "j", "J", "<Down>":
				sd.moveSelection(1)
			case "k", "K", "<Up>":
				sd.moveSelection(-1)
			case "<MouseLeft>":
				// Consume mouse events, no action.
			}
		case <-sd.quitCh:
			return
		}
	}
}

func (sd *StatisticsDisplay) uiRenderLoop() {
	if !sd.uiEnabled {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						sd.mu.Lock()
						sd.hasPanic = true
						sd.mu.Unlock()
					}
				}()
				sd.render()
			}()
		case <-sd.quitCh:
			return
		}
	}
}

func (sd *StatisticsDisplay) moveSelection(delta int) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	// count flows to bound selection
	n := len(sd.flows)
	if n == 0 {
		sd.selectedIndex = 0
		return
	}
	sd.selectedIndex = (sd.selectedIndex + delta + n) % n
	// append current selected rate to selectedSeries for immediate visual feedback
	keys := make([]uint64, 0, len(sd.flows))
	for k := range sd.flows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(keys) > 0 {
		selIdx := sd.selectedIndex % len(keys)
		selKey := keys[selIdx]
		selRate := sd.flowRates[selKey]
		const historyLen = 60
		sd.selectedSeries = append(sd.selectedSeries, selRate)
		if len(sd.selectedSeries) > historyLen {
			sd.selectedSeries = sd.selectedSeries[len(sd.selectedSeries)-historyLen:]
		}
	}
}

func (sd *StatisticsDisplay) render() {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	// header
	totalUEs := len(sd.flows)
	globalMbps := lastOrZero(sd.totalSeries)
	sd.header.Text = fmt.Sprintf("Total Flows: %d    Engine: eBPF XDP    Global: %.2f Mbps    [Last Updated: %s]", totalUEs, globalMbps, time.Now().Format("15:04:05"))

	// build UE table rows (show rate in Mbps)
	rows := [][]string{{"ID", "Inner Src IP", "Inner Dst IP", "TEID", "Curr Rate (Mbps)"}}
	keys := make([]uint64, 0, len(sd.flows))
	for k := range sd.flows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for i, k := range keys {
		ps := sd.flows[k]
		marker := " "
		if i == sd.selectedIndex {
			marker = "➔"
		}
		rate := sd.flowRates[k]
		rows = append(rows, []string{
			fmt.Sprintf("%s %02d", marker, i+1),
			ps.InnerSrcIPString(),
			ps.InnerDstIPString(),
			ps.TEIDString(),
			fmt.Sprintf("%.2f", rate),
		})
	}
	sd.ueTable.Rows = rows

	// destination bar chart (Mbps)
	destKeys := make([]uint32, 0, len(sd.destRates))
	for k := range sd.destRates {
		destKeys = append(destKeys, k)
	}
	sort.Slice(destKeys, func(i, j int) bool { return sd.destRates[destKeys[i]] > sd.destRates[destKeys[j]] })
	labels := []string{}
	data := []float64{}

	for i, k := range destKeys {
		if i >= 5 {
			break
		}
		labels = append(labels, ipToString(k))
		data = append(data, clampNonNegative(sd.destRates[k]))
	}
	sd.destBar.Labels = labels
	sd.destBar.Data = data

	// middle panel using sparklines for stability.
	const targetLen = 60
	totalP := padToLen(sd.totalSeries, targetLen)
	selectedP := padToLen(sd.selectedSeries, targetLen)

	totalData := make([]float64, 0, len(totalP))
	selectedData := make([]float64, 0, len(selectedP))
	for i := 0; i < targetLen; i++ {
		totalData = append(totalData, toSparkValue(totalP[i]))
		selectedData = append(selectedData, toSparkValue(selectedP[i]))
	}

	sd.trafficPanel.Sparklines[0].Data = totalData
	sd.trafficPanel.Sparklines[1].Data = selectedData

	// Y-axis max for Total/Selected shown next to labels.
	yMax := 0.0
	for _, v := range totalP {
		if v > yMax {
			yMax = v
		}
	}
	for _, v := range selectedP {
		if v > yMax {
			yMax = v
		}
	}
	if yMax < 1.0 {
		yMax = 1.0
	}
	yMid := yMax / 2
	sd.trafficPanel.Sparklines[0].Title = fmt.Sprintf("Total (Y max %.2f Mbps)", yMax)
	sd.trafficPanel.Sparklines[1].Title = fmt.Sprintf("Selected (Y max %.2f Mbps)", yMax)
	// build legend including blacklist summary
	blSummary := "none"
	if len(sd.blacklist) > 0 {
		// show up to 3 entries
		maxShow := 3
		if len(sd.blacklist) < maxShow {
			maxShow = len(sd.blacklist)
		}
		blSummary = sd.blacklist[0]
		for i := 1; i < maxShow; i++ {
			blSummary += ", " + sd.blacklist[i]
		}
		if len(sd.blacklist) > maxShow {
			blSummary += ", ..."
		}
	}

	// build dest blacklist summary
	dblSummary := "none"
	if len(sd.destBlacklist) > 0 {
		// show up to 3 entries
		maxShow := 3
		if len(sd.destBlacklist) < maxShow {
			maxShow = len(sd.destBlacklist)
		}
		dblSummary = sd.destBlacklist[0]
		for i := 1; i < maxShow; i++ {
			dblSummary += ", " + sd.destBlacklist[i]
		}
		if len(sd.destBlacklist) > maxShow {
			dblSummary += ", ..."
		}
	}

	sd.legend.Text = fmt.Sprintf("Total=White  Selected=Cyan\nY ticks: %.2f | %.2f | 0.00 Mbps\nLimit: %.2f Mbps\nIP Blacklist: %s\nDest Blacklist: %s", yMax, yMid, sd.limitMbps, blSummary, dblSummary)

	currentTotal := lastOrZero(sd.totalSeries)
	currentSelected := lastOrZero(sd.selectedSeries)
	sd.trafficPanel.Title = fmt.Sprintf("Real-time Traffic (60s)  T=%.2f  S=%.2f Mbps", currentTotal, currentSelected)

	if sd.hasPanic {
		sd.fallback.Text = fmt.Sprintf("Previous render panic detected.\nTotal: %.2f Mbps\nSelected: %.2f Mbps\nLimit: %.2f Mbps", currentTotal, currentSelected, sd.limitMbps)
		ui.Render(sd.header, sd.fallback, sd.legend, sd.ueTable, sd.destBar, sd.footer)
		return
	}

	ui.Render(sd.header, sd.trafficPanel, sd.legend, sd.ueTable, sd.destBar, sd.footer)
}

// PrintHeader kept for compatibility; initial UI is handled in NewStatisticsDisplay
func (sd *StatisticsDisplay) PrintHeader() {
	// no-op (header rendered by UI)
}

func (sd *StatisticsDisplay) PrintColumnHeaders() {
	// no-op (table title handles headers)
}

func (sd *StatisticsDisplay) PrintStats(stats map[uint64]PacketStats, unknownCount uint64) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	now := time.Now()
	// compute total packets delta and per-flow rates (assume avg packet size 1500 bytes -> Mbps)
	var totalDelta uint64
	for k, v := range stats {
		prev := sd.prevFlows[k]
		if prev.PacketCount == 0 || sd.prevFlowTime.IsZero() {
			// if no prev, treat rate as 0
			sd.flowRates[k] = 0
		} else {
			deltaPackets := uint64(0)
			if v.PacketCount >= prev.PacketCount {
				deltaPackets = v.PacketCount - prev.PacketCount
			}
			secs := now.Sub(sd.prevFlowTime).Seconds()
			if secs <= 0 {
				sd.flowRates[k] = 0
			} else {
				pps := float64(deltaPackets) / secs
				// convert to Mbps assuming 1500 bytes/packet
				mbps := clampNonNegative(pps * 1500 * 8 / 1e6)
				sd.flowRates[k] = mbps
			}
			totalDelta += deltaPackets
		}
		sd.flows[k] = v
	}
	// total rate
	totalRate := 0.0
	if !sd.prevFlowTime.IsZero() {
		secs := now.Sub(sd.prevFlowTime).Seconds()
		if secs > 0 {
			pps := float64(totalDelta) / secs
			totalRate = clampNonNegative(pps * 1500 * 8 / 1e6)
		}
	}
	// append to history (keep last 60)
	const historyLen = 60
	sd.totalSeries = append(sd.totalSeries, totalRate)
	if len(sd.totalSeries) > historyLen {
		sd.totalSeries = sd.totalSeries[len(sd.totalSeries)-historyLen:]
	}

	// selected series value
	selRate := 0.0
	keys := make([]uint64, 0, len(sd.flows))
	for k := range sd.flows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(keys) > 0 {
		selIdx := sd.selectedIndex % len(keys)
		selKey := keys[selIdx]
		selRate = sd.flowRates[selKey]
	}
	sd.selectedSeries = append(sd.selectedSeries, selRate)
	if len(sd.selectedSeries) > historyLen {
		sd.selectedSeries = sd.selectedSeries[len(sd.selectedSeries)-historyLen:]
	}

	sd.prevFlowTime = now
	// copy current stats to prevFlows
	sd.prevFlows = make(map[uint64]PacketStats, len(stats))
	for k, v := range stats {
		sd.prevFlows[k] = v
	}
	sd.unknown = unknownCount
}

func (sd *StatisticsDisplay) PrintDestinationStats(stats map[uint32]uint64) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	now := time.Now()
	// compute destination rates from previous snapshot (Mbps)
	dt := now.Sub(sd.prevDestTime).Seconds()
	for k, v := range stats {
		prev := sd.prevDest[k]
		var mbps float64
		if prev == 0 || sd.prevDestTime.IsZero() || dt <= 0 {
			mbps = 0
		} else {
			deltaPackets := uint64(0)
			if v >= prev {
				deltaPackets = v - prev
			}
			pps := float64(deltaPackets) / dt
			mbps = clampNonNegative(pps * 1500 * 8 / 1e6)
		}
		sd.destRates[k] = mbps
	}
	// update previous destination snapshot
	sd.prevDest = make(map[uint32]uint64, len(stats))
	for k, v := range stats {
		sd.prevDest[k] = v
	}
	sd.prevDestTime = now
}

func (sd *StatisticsDisplay) PrintSummary(stats map[uint64]PacketStats, unknownCount uint64) {
	// we already update unknown in PrintStats; keep for compatibility
	sd.mu.Lock()
	sd.unknown = unknownCount
	sd.mu.Unlock()
}

// UpdateBlacklist sets the current blacklist entries for UI display.
func (sd *StatisticsDisplay) UpdateBlacklist(entries []string) {
	sd.mu.Lock()
	sd.blacklist = entries
	sd.mu.Unlock()
}

// UpdateDestBlacklist sets the current destination blacklist entries for UI display.
func (sd *StatisticsDisplay) UpdateDestBlacklist(entries []string) {
	sd.mu.Lock()
	sd.destBlacklist = entries
	sd.mu.Unlock()
}

// Close UI when done
func (sd *StatisticsDisplay) Close() {
	sd.closeOnce.Do(func() {
		close(sd.quitCh)
		if sd.uiEnabled {
			ui.Close()
		}
	})
}

func clampNonNegative(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}

func lastOrZero(series []float64) float64 {
	if len(series) == 0 {
		return 0
	}
	return series[len(series)-1]
}

func padToLen(src []float64, n int) []float64 {
	if n <= 0 {
		return []float64{}
	}
	if len(src) >= n {
		return src[len(src)-n:]
	}
	out := make([]float64, n)
	if len(src) == 0 {
		return out
	}
	copy(out[n-len(src):], src)
	return out
}

func toSparkValue(mbps float64) float64 {
	v := clampNonNegative(mbps)
	// keep two decimals of precision for tiny values
	return v * 100
}
