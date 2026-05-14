#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "blacklist.bpf.c"
#include "dest_blacklist.bpf.c"

#define GTP_U_V1_PORT 2152
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

struct ethhdr {
    __u8   h_dest[6];
    __u8   h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8    ihl:4;
    __u8    version:4;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __be16  check;
    __be32  saddr;
    __be32  daddr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

struct packet_stats {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u32 teid;
    __u64 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct packet_stats);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} unknown_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline void debug_inc(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline void increment_unknown(void) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&unknown_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static __always_inline struct packet_stats* lookup_or_create_stats(
    __u32 src_ip, __u32 dst_ip, __u32 inner_src_ip, __u32 inner_dst_ip, __u32 teid) {
    // Use both inner source and destination IP as the map key to track each flow independently
    __u64 key = ((__u64)inner_src_ip << 32) | inner_dst_ip;
    struct packet_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
    if (!stats) {
        struct packet_stats new_stats = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .inner_src_ip = inner_src_ip,
            .inner_dst_ip = inner_dst_ip,
            .teid = teid,
            .packet_count = 0,
        };
        bpf_map_update_elem(&flow_stats, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&flow_stats, &key);
    }
    return stats;
}

SEC("xdp")
int xdp_gtp_parse(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    debug_inc(0);  // Counter 0: total packets
    
    // Try Ethernet first
    struct ethhdr *eth = data;
    struct iphdr *iph = NULL;
    if ((void *)(eth + 1) <= data_end) {
        debug_inc(1);  // Counter 1: can read Ethernet
        __be16 eth_proto = eth->h_proto;
        if (eth_proto == (__be16)__builtin_bswap16(ETH_P_IP)) {
            struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
            if ((void *)(outer_ip + 1) <= data_end && outer_ip->version == 4) {
                debug_inc(2);  // Counter 2: Ethernet + IPv4 valid
                /* set iph to point to the outer IP header for processing */
                iph = outer_ip;
                goto process_gtp;
            }
        }
    }
    
    // Fallback: Raw IP (L3) for upfgtp
    iph = data;
    if ((void *)(iph + 1) <= data_end) {
        debug_inc(3);  // Counter 3: can read IP header
        if (iph->version == 4) {
            debug_inc(4);  // Counter 4: is IPv4
            goto process_gtp;
        } else {
            debug_inc(5);  // Counter 5: not IPv4
        }
    }
    
    increment_unknown();
    return XDP_PASS;

process_gtp:
    {
        if (iph->protocol != IPPROTO_UDP) {
            increment_unknown();
            return XDP_PASS;
        }
        
        debug_inc(6);  // Counter 6: UDP protocol
        
        __u32 iph_len = iph->ihl * 4;
        struct udphdr *udp = (struct udphdr *)((void *)iph + iph_len);
        
        if ((void *)(udp + 1) > data_end) {
            increment_unknown();
            return XDP_PASS;
        }
        
        if (udp->dest != (__be16)__builtin_bswap16(GTP_U_V1_PORT)) {
            increment_unknown();
            return XDP_PASS;
        }
        
        debug_inc(7);  // Counter 7: GTP-U port 2152
        
        void *gtp = (void *)(udp + 1);
        if (gtp + 8 > data_end) {
            increment_unknown();
            return XDP_PASS;
        }
        
        __u8 gtp_flags = *((__u8 *)gtp);
        __u8 gtp_msg_type = *((__u8 *)gtp + 1);
        
        if (gtp_msg_type != 0xff) {
            increment_unknown();
            return XDP_PASS;
        }
        
        debug_inc(8);  // Counter 8: GTP-U data packet (msg_type 0xff)
        
        __u32 gtp_teid = ((__u32)*((__u8 *)gtp + 4) << 24) |
                         ((__u32)*((__u8 *)gtp + 5) << 16) |
                         ((__u32)*((__u8 *)gtp + 6) << 8) |
                         ((__u32)*((__u8 *)gtp + 7));
        
        void *inner = gtp + 8;
        if ((gtp_flags & 0x07) != 0) {
            inner = gtp + 12;
            if (inner > data_end) {
                increment_unknown();
                return XDP_PASS;
            }
            
            if (gtp_flags & 0x04) {
                __u8 nexthdr = *((__u8 *)gtp + 11);
                #pragma unroll 16
                for (int i = 0; i < 16; i++) {
                    if (nexthdr == 0) break;
                    if (inner + 1 > data_end) {
                        increment_unknown();
                        return XDP_PASS;
                    }
                    __u32 ext_len = ((__u32)(*((__u8 *)inner))) * 4;
                    if (ext_len < 4 || inner + ext_len > data_end) {
                        increment_unknown();
                        return XDP_PASS;
                    }
                    nexthdr = *((__u8 *)inner + ext_len - 1);
                    inner = inner + ext_len;
                }
            }
        }
        
        struct iphdr *inner_ip = inner;
        if ((void *)(inner_ip + 1) > data_end || inner_ip->version != 4) {
            increment_unknown();
            return XDP_PASS;
        }

        debug_inc(10);  // Counter 10: Valid inner IPv4

        /* Check blacklist for inner packet IPs (keys are in network byte order) */
        if (is_blacklisted(inner_ip->saddr) || is_blacklisted(inner_ip->daddr)) {
            debug_inc(11);  // Counter 11: blocked by source/dest ip blacklist
            return XDP_DROP;
        }

        /* Check destination IP blacklist */
        if (is_dest_blacklisted(inner_ip->daddr)) {
            debug_inc(12);  // Counter 12: blocked by dest blacklist
            return XDP_DROP;
        }

        struct packet_stats *stats = lookup_or_create_stats(
            iph->saddr, iph->daddr,
            inner_ip->saddr, inner_ip->daddr,
            gtp_teid
        );
        
        if (stats) {
            __sync_fetch_and_add(&stats->packet_count, 1);
            debug_inc(9);  // Counter 9: Stats recorded
        }
        
        return XDP_PASS;
    }
}
