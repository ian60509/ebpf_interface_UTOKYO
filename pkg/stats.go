package pkg

import (
	"fmt"
	"net"
)

type PacketStats struct {
	SrcIP       uint32
	DstIP       uint32
	InnerSrcIP  uint32
	InnerDstIP  uint32
	TEID        uint32
	_           [4]byte
	PacketCount uint64
}

func (ps *PacketStats) SrcIPString() string {
	return ipToString(ps.SrcIP)
}

func (ps *PacketStats) DstIPString() string {
	return ipToString(ps.DstIP)
}

func (ps *PacketStats) InnerSrcIPString() string {
	return ipToString(ps.InnerSrcIP)
}

func (ps *PacketStats) InnerDstIPString() string {
	return ipToString(ps.InnerDstIP)
}

func (ps *PacketStats) TEIDString() string {
	return fmt.Sprintf("0x%08x", ps.TEID)
}

func ipToString(ip uint32) string {
	// Stored value comes from BPF as little-endian on this platform; reverse bytes
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}
