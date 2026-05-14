package pkg

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// PopulateHardcodedBlacklist inserts a hard-coded blocked IP (10.60.0.1)
// into the provided eBPF map. Keys are IPv4 in network byte order.
func PopulateHardcodedBlacklist(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("ip_blacklist map is nil")
	}

	ip := net.ParseIP("10.60.100.1").To4()
	if ip == nil {
		return fmt.Errorf("invalid IP")
	}

	// Store key so its in-memory byte layout equals the IP bytes (network order).
	// On little-endian hosts we must interpret the bytes as little-endian uint32
	// so that the map key's raw bytes match inner_ip->saddr in the kernel.
	key := binary.LittleEndian.Uint32(ip)
	var val uint8 = 1

	if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update ip_blacklist: %w", err)
	}

	return nil
}
