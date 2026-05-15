package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// Hardcoded SUPI -> IP mapping (controller shows SUPI but API uses IP)
var ueMap = []struct {
	Supi string
	IP   string
}{
	{"imsi-208930000000001", "10.60.100.1"},
	{"imsi-208930000000002", "10.60.100.2"},
	{"imsi-208930000000003", "10.60.100.3"},
	{"imsi-208930000000004", "10.60.100.4"},
	{"imsi-208930000000005", "10.60.100.5"},
}

var dests = []string{"1.1.1.1", "8.8.8.8"}

const apiBase = "http://localhost:8080/api"

type blacklistResp struct {
	Type    string   `json:"type"`
	Entries []string `json:"entries"`
}

func addIP(ip string) error {
	url := apiBase + "/ip-blacklist/add"
	body := map[string]string{"ip": ip}
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(data))
	}
	return nil
}

func removeIP(ip string) error {
	url := apiBase + "/ip-blacklist/remove"
	body := map[string]string{"ip": ip}
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(data))
	}
	return nil
}

func addDest(ip string) error {
	url := apiBase + "/dest-blacklist/add"
	body := map[string]string{"ip": ip}
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(data))
	}
	return nil
}

func removeDest(ip string) error {
	url := apiBase + "/dest-blacklist/remove"
	body := map[string]string{"ip": ip}
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(data))
	}
	return nil
}

func limitUE2HalfMbps() error {
	url := apiBase + "/ue-rate-limit/preset/ue2-half-mbps"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(data))
	}
	return nil
}

func listIP() ([]string, error) {
	url := apiBase + "/ip-blacklist/list"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var br blacklistResp
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	return br.Entries, nil
}

func listDest() ([]string, error) {
	url := apiBase + "/dest-blacklist/list"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var br blacklistResp
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	return br.Entries, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func main() {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to init termui: %v", err)
	}
	defer ui.Close()

	list := widgets.NewList()
	list.Title = "Controller - select entry and press Space to toggle block/unblock, L to cap UE2 at 0.5 Mbps (q to quit)"
	list.SetRect(0, 0, 80, 20)
	list.TextStyle = ui.NewStyle(ui.ColorWhite)
	list.WrapText = false
	// make selection visible (black text on cyan background)
	list.SelectedRowStyle = ui.NewStyle(ui.ColorBlack, ui.ColorCyan)

	footer := widgets.NewParagraph()
	footer.Text = "[Space] toggle  [L] cap UE2 to 0.5 Mbps  [↑/↓] navigate  [q] quit"
	footer.SetRect(0, 20, 80, 23)

	status := widgets.NewParagraph()
	status.Title = "Status"
	status.SetRect(0, 23, 80, 28)

	// build rows initially
	selected := 1
	rows := buildRows([]string{}, []string{}, selected)
	list.Rows = rows
	// start selection on first UE
	list.SelectedRow = selected

	ui.Render(list, footer, status)
	// ticker to refresh blacklist from API
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// event loop
	events := ui.PollEvents()
	for {
		select {
		case e := <-events:
			switch e.ID {
			case "q", "Q":
				return
			case "<Down>":
				if selected < len(list.Rows)-1 {
					selected++
				}
				list.SelectedRow = selected
				list.ScrollDown()
			case "<Up>":
				if selected > 0 {
					selected--
				}
				list.SelectedRow = selected
				list.ScrollUp()
			case " ", "<Space>", "<Enter>":
				// toggle
				ip, kind := resolveSelection(selected)
				if ip == "" {
					break
				}
				if kind == "ue" {
					ips, err := listIP()
					if err != nil {
						status.Text = fmt.Sprintf("List IP error: %v", err)
						// refresh rows immediately after toggling
						ips2, err1 := listIP()
						ds2, err2 := listDest()
						if err1 == nil && err2 == nil {
							list.Rows = buildRows(ips2, ds2, selected)
							if selected >= len(list.Rows) {
								selected = len(list.Rows) - 1
							}
							list.SelectedRow = selected
						}
						ui.Render(list, footer, status)
						break
					}
					if contains(ips, ip) {
						if err := removeIP(ip); err != nil {
							status.Text = fmt.Sprintf("Remove IP error: %v", err)
						} else {
							status.Text = fmt.Sprintf("Removed %s", ip)
						}
					} else {
						if err := addIP(ip); err != nil {
							status.Text = fmt.Sprintf("Add IP error: %v", err)
						} else {
							status.Text = fmt.Sprintf("Added %s", ip)
						}
					}
					// refresh rows immediately after toggling
					ui.Render(list, footer, status)
					// refresh rows immediately after toggling
					ips2, err1 := listIP()
					ds2, err2 := listDest()
					if err1 == nil && err2 == nil {
						list.Rows = buildRows(ips2, ds2, selected)
						if selected >= len(list.Rows) {
							selected = len(list.Rows) - 1
						}
						list.SelectedRow = selected
					}
				} else if kind == "dest" {
					destsList, err := listDest()
					if err != nil {
						status.Text = fmt.Sprintf("List dest error: %v", err)
						ui.Render(status)
						break
					}
					if contains(destsList, ip) {
						if err := removeDest(ip); err != nil {
							status.Text = fmt.Sprintf("Remove dest error: %v", err)
						} else {
							status.Text = fmt.Sprintf("Removed dest %s", ip)
						}
					} else {
						if err := addDest(ip); err != nil {
							status.Text = fmt.Sprintf("Add dest error: %v", err)
						} else {
							status.Text = fmt.Sprintf("Added dest %s", ip)
						}
					}
					// refresh rows immediately after toggling dest
					ips2, err1 := listIP()
					ds2, err2 := listDest()
					if err1 == nil && err2 == nil {
						list.Rows = buildRows(ips2, ds2, selected)
						if selected >= len(list.Rows) {
							selected = len(list.Rows) - 1
						}
						list.SelectedRow = selected
					}
				}

				ui.Render(status)
			case "l", "L":
				if err := limitUE2HalfMbps(); err != nil {
					status.Text = fmt.Sprintf("Limit UE2 error: %v", err)
				} else {
					status.Text = "Limited UE2 to 0.5 Mbps preset"
				}
				ui.Render(status)
			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				list.SetRect(0, 0, payload.Width, payload.Height-5)
				footer.SetRect(0, payload.Height-5, payload.Width, payload.Height-2)
				status.SetRect(0, payload.Height-2, payload.Width, payload.Height)
			}
		case <-ticker.C:
			// refresh blacklists from API
			ips, ipErr := listIP()
			ds, dstErr := listDest()
			if ipErr != nil {
				status.Text = fmt.Sprintf("List IP error: %v", ipErr)
			} else if dstErr != nil {
				status.Text = fmt.Sprintf("List Dest error: %v", dstErr)
			} else {
				rows = buildRows(ips, ds, selected)
				list.Rows = rows
				// keep selection in range
				if selected >= len(rows) {
					selected = len(rows) - 1
				}
				list.SelectedRow = selected
				ui.Render(list, footer, status)
			}
		}
	}
}

// buildRows composes visual rows with blocked markings
func buildRows(blockedIPs []string, blockedDests []string, selected int) []string {
	rows := []string{"-- UEs --"}
	// rows indices: header(0), UEs 1..N, header, dests
	idx := 1
	for _, u := range ueMap {
		marker := "  "
		if idx == selected {
			marker = "➔ "
		}
		line := fmt.Sprintf("%s%s -> %s", marker, u.Supi, u.IP)
		if contains(blockedIPs, u.IP) {
			line = fmt.Sprintf("%s  [BLOCKED](fg:red)", line)
		}
		rows = append(rows, line)
		idx++
	}
	rows = append(rows, "-- Destinations --")
	idx++ // destination header index
	for _, d := range dests {
		marker := "  "
		if idx == selected {
			marker = "➔ "
		}
		line := fmt.Sprintf("%s%s", marker, d)
		if contains(blockedDests, d) {
			line = fmt.Sprintf("%s  [BLOCKED](fg:red)", line)
		}
		rows = append(rows, line)
		idx++
	}
	return rows
}

// resolveSelection returns (ip, kind) where kind is "ue" or "dest" or "" if non-selectable
func resolveSelection(sel int) (string, string) {
	// rows layout: 0 header, 1..len(ueMap) UEs, next header, then dests
	if sel <= 0 {
		return "", ""
	}
	if sel >= 1 && sel <= len(ueMap) {
		idx := sel - 1
		return ueMap[idx].IP, "ue"
	}
	if sel == 1+len(ueMap) {
		return "", ""
	} // dest header
	idx := sel - (2 + len(ueMap))
	if idx >= 0 && idx < len(dests) {
		return dests[idx], "dest"
	}
	return "", ""
}
