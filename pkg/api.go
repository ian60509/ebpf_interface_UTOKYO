package pkg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

// BlacklistRequest represent an IP to add or remove from blacklist
type BlacklistRequest struct {
	IP string `json:"ip"`
}

// RateLimitRequest represents a UE rate-limit update request.
type RateLimitRequest struct {
	UEIP     string `json:"ue_ip"`
	RateMbps int    `json:"rate_mbps"`
	BurstMB  int    `json:"burst_mb"`
}

// BlacklistResponse shows current blacklist entries
type BlacklistResponse struct {
	Type    string   `json:"type"`
	Entries []string `json:"entries"`
}

// APIServer wraps the EBPF manager to serve blacklist management endpoints
type APIServer struct {
	ebpfMgr *EBPFManager
	port    string
}

// NewAPIServer creates and returns a new API server
func NewAPIServer(ebpfMgr *EBPFManager, port string) *APIServer {
	return &APIServer{
		ebpfMgr: ebpfMgr,
		port:    port,
	}
}

// Start launches the HTTP server
func (as *APIServer) Start() error {
	http.HandleFunc("/api/ip-blacklist/add", as.addIPBlacklist)
	http.HandleFunc("/api/ip-blacklist/remove", as.removeIPBlacklist)
	http.HandleFunc("/api/ip-blacklist/list", as.listIPBlacklist)
	http.HandleFunc("/api/dest-blacklist/add", as.addDestBlacklist)
	http.HandleFunc("/api/dest-blacklist/remove", as.removeDestBlacklist)
	http.HandleFunc("/api/dest-blacklist/list", as.listDestBlacklist)
	http.HandleFunc("/api/ue-rate-limit/update", as.updateUERateLimit)
	http.HandleFunc("/api/ue-rate-limit/preset/ue2-half-mbps", as.limitUE2HalfMbps)

	log.Printf("Starting API server on port %s", as.port)
	return http.ListenAndServe(":"+as.port, nil)
}

func (as *APIServer) addIPBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := as.ebpfMgr.AddIPBlacklist(req.IP); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": fmt.Sprintf("Added %s to IP blacklist", req.IP)})
}

func (as *APIServer) removeIPBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := as.ebpfMgr.RemoveIPBlacklist(req.IP); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": fmt.Sprintf("Removed %s from IP blacklist", req.IP)})
}

func (as *APIServer) listIPBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := as.ebpfMgr.GetBlacklist()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BlacklistResponse{Type: "ip", Entries: entries})
}

func (as *APIServer) addDestBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := as.ebpfMgr.AddDestBlacklist(req.IP); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": fmt.Sprintf("Added %s to dest blacklist", req.IP)})
}

func (as *APIServer) removeDestBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := as.ebpfMgr.RemoveDestBlacklist(req.IP); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": fmt.Sprintf("Removed %s from dest blacklist", req.IP)})
}

func (as *APIServer) listDestBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := as.ebpfMgr.GetDestBlacklist()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BlacklistResponse{Type: "dest", Entries: entries})
}

func (as *APIServer) updateUERateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RateLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := as.ebpfMgr.UpdateUERateLimit(req.UEIP, req.RateMbps, req.BurstMB); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": fmt.Sprintf("Updated rate limit for %s", req.UEIP)})
}

func (as *APIServer) limitUE2HalfMbps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := as.ebpfMgr.updateUERateLimitBytes("10.60.100.2", 62500, 62500); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Limited UE2 to 0.5 Mbps preset"})
}

// ipToKey converts IP string to little-endian uint32 key for map storage
func ipToKey(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IP: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

// keyToIP converts little-endian uint32 key back to IP string
func keyToIP(key uint32) string {
	b := []byte{byte(key & 0xff), byte((key >> 8) & 0xff), byte((key >> 16) & 0xff), byte((key >> 24) & 0xff)}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}
