#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Destination IP blacklist map
 * Keys are IPv4 addresses in network byte order (__u32)
 * Values are a single byte where non-zero means blocked
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} dest_blacklist SEC(".maps");

static __always_inline int is_dest_blacklisted(__u32 ip_be) {
    __u8 *v = bpf_map_lookup_elem(&dest_blacklist, &ip_be);
    return v ? 1 : 0;
}
