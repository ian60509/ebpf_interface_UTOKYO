package pkg

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type EBPFManager struct {
	xdpLink       link.Link
	flowStats     *ebpf.Map
	unknownCount  *ebpf.Map
	debugCounters *ebpf.Map
	ipBlacklist   *ebpf.Map
	destBlacklist *ebpf.Map
}

func NewEBPFManager(flowStatsMap, unknownCountMap, debugCountersMap, ipBlacklistMap, destBlacklistMap *ebpf.Map) (*EBPFManager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	if flowStatsMap == nil {
		return nil, fmt.Errorf("flow_stats map is nil")
	}
	if unknownCountMap == nil {
		return nil, fmt.Errorf("unknown_count map is nil")
	}

	return &EBPFManager{
		flowStats:     flowStatsMap,
		unknownCount:  unknownCountMap,
		debugCounters: debugCountersMap,
		ipBlacklist:   ipBlacklistMap,
		destBlacklist: destBlacklistMap,
	}, nil
}

func (em *EBPFManager) HasDebugCounters() bool {
	return em.debugCounters != nil
}

func (em *EBPFManager) AttachXDP(ifaceName string, prog *ebpf.Program) error {
	if prog == nil {
		return fmt.Errorf("program is nil")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}

	em.xdpLink = xdpLink
	log.Printf("Attached XDP program to %s", ifaceName)
	return nil
}

func (em *EBPFManager) GetFlowStats() (map[uint64]PacketStats, error) {
	result := make(map[uint64]PacketStats)

	iter := em.flowStats.Iterate()
	var key uint64
	var value PacketStats

	for iter.Next(&key, &value) {
		result[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate flow_stats: %w", err)
	}

	return result, nil
}

func (em *EBPFManager) GetDestinationStats() (map[uint32]uint64, error) {
	result := make(map[uint32]uint64)

	iter := em.flowStats.Iterate()
	var key uint64
	var value PacketStats

	for iter.Next(&key, &value) {
		result[value.InnerDstIP] += value.PacketCount
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate flow_stats for destination stats: %w", err)
	}

	return result, nil
}

func (em *EBPFManager) GetUnknownCount() (uint64, error) {
	var key uint32
	var value uint64

	if err := em.unknownCount.Lookup(&key, &value); err != nil {
		return 0, fmt.Errorf("lookup unknown_count: %w", err)
	}

	return value, nil
}

func (em *EBPFManager) GetDebugCounter(index uint32) (uint64, error) {
	if em.debugCounters == nil {
		return 0, fmt.Errorf("debug counters are disabled")
	}

	var value uint64

	if err := em.debugCounters.Lookup(&index, &value); err != nil {
		return 0, fmt.Errorf("lookup debug_counters[%d]: %w", index, err)
	}

	return value, nil
}

func (em *EBPFManager) Close() error {
	if em.xdpLink != nil {
		if err := em.xdpLink.Close(); err != nil {
			log.Printf("close XDP link: %v", err)
		}
	}

	return nil
}

// GetBlacklist returns a list of IP strings currently present in the ip_blacklist map.
func (em *EBPFManager) GetBlacklist() ([]string, error) {
	if em.ipBlacklist == nil {
		return nil, fmt.Errorf("ip_blacklist map is not available")
	}

	result := []string{}
	iter := em.ipBlacklist.Iterate()
	var key uint32
	var value uint8
	for iter.Next(&key, &value) {
		// The key stored in the map uses the raw IP bytes. On little-endian
		// hosts the uint32 value will have the IP in little-endian order in
		// memory, so reconstruct bytes accordingly.
		b := []byte{byte(key & 0xff), byte((key >> 8) & 0xff), byte((key >> 16) & 0xff), byte((key >> 24) & 0xff)}
		ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
		if value != 0 {
			result = append(result, ip)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate ip_blacklist: %w", err)
	}
	return result, nil
}

// GetDestBlacklist returns a list of destination IP strings currently present in the dest_blacklist map.
func (em *EBPFManager) GetDestBlacklist() ([]string, error) {
	if em.destBlacklist == nil {
		return nil, fmt.Errorf("dest_blacklist map is not available")
	}

	result := []string{}
	iter := em.destBlacklist.Iterate()
	var key uint32
	var value uint8
	for iter.Next(&key, &value) {
		// The key stored in the map uses the raw IP bytes. On little-endian
		// hosts the uint32 value will have the IP in little-endian order in
		// memory, so reconstruct bytes accordingly.
		b := []byte{byte(key & 0xff), byte((key >> 8) & 0xff), byte((key >> 16) & 0xff), byte((key >> 24) & 0xff)}
		ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
		if value != 0 {
			result = append(result, ip)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate dest_blacklist: %w", err)
	}
	return result, nil
}

// AddIPBlacklist adds an IP to the ip_blacklist map
func (em *EBPFManager) AddIPBlacklist(ipStr string) error {
	if em.ipBlacklist == nil {
		return fmt.Errorf("ip_blacklist map is not available")
	}

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	key := binary.LittleEndian.Uint32(ip)
	var val uint8 = 1

	if err := em.ipBlacklist.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update ip_blacklist: %w", err)
	}
	return nil
}

// RemoveIPBlacklist removes an IP from the ip_blacklist map
func (em *EBPFManager) RemoveIPBlacklist(ipStr string) error {
	if em.ipBlacklist == nil {
		return fmt.Errorf("ip_blacklist map is not available")
	}

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	key := binary.LittleEndian.Uint32(ip)

	if err := em.ipBlacklist.Delete(&key); err != nil {
		return fmt.Errorf("delete from ip_blacklist: %w", err)
	}
	return nil
}

// AddDestBlacklist adds an IP to the dest_blacklist map
func (em *EBPFManager) AddDestBlacklist(ipStr string) error {
	if em.destBlacklist == nil {
		return fmt.Errorf("dest_blacklist map is not available")
	}

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	key := binary.LittleEndian.Uint32(ip)
	var val uint8 = 1

	if err := em.destBlacklist.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update dest_blacklist: %w", err)
	}
	return nil
}

// RemoveDestBlacklist removes an IP from the dest_blacklist map
func (em *EBPFManager) RemoveDestBlacklist(ipStr string) error {
	if em.destBlacklist == nil {
		return fmt.Errorf("dest_blacklist map is not available")
	}

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	key := binary.LittleEndian.Uint32(ip)

	if err := em.destBlacklist.Delete(&key); err != nil {
		return fmt.Errorf("delete from dest_blacklist: %w", err)
	}
	return nil
}
