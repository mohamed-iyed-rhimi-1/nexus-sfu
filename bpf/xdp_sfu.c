// SPDX-License-Identifier: GPL-2.0
// XDP program for Nexus SFU kernel-bypass packet forwarding.
//
// This program runs at the NIC driver level and classifies incoming UDP packets:
// - RTP packets: Forwarded in kernel space via BPF map lookup (hot path, ~90%)
// - RTCP/DTLS/STUN: Passed to user space via AF_XDP (cold path, ~10%)
//
// Requirements: 19.1, 19.2, 19.3, 19.8
// TigerStyle: Fixed bounds, explicit types, comprehensive comments

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ============================================================================
// Constants
// ============================================================================

// Maximum entries in forward table (fits in L2 cache at ~1.3MB)
#define MAX_FORWARD_ENTRIES 65536

// Statistics array indices
#define STATS_RTP_FORWARDED    0
#define STATS_RTP_PASSED       1
#define STATS_RTCP_PASSED      2
#define STATS_DTLS_PASSED      3
#define STATS_STUN_PASSED      4
#define STATS_UNKNOWN_PASSED   5
#define STATS_PARSE_ERRORS     6
#define STATS_MAP_MISSES       7
#define STATS_MAX              8

// STUN magic cookie (RFC 5389)
#define STUN_MAGIC_COOKIE 0x2112A442

// RTP payload type ranges for common codecs
// Dynamic payload types: 96-127 (most WebRTC codecs)
// Static audio: 0-23, Static video: 24-34
#define RTP_PT_MIN_DYNAMIC 96
#define RTP_PT_MAX_DYNAMIC 127
#define RTP_PT_MAX_STATIC  34

// RTCP packet types (RFC 3550)
#define RTCP_PT_SR   200  // Sender Report
#define RTCP_PT_RR   201  // Receiver Report
#define RTCP_PT_SDES 202  // Source Description
#define RTCP_PT_BYE  203  // Goodbye
#define RTCP_PT_APP  204  // Application-Defined
#define RTCP_PT_RTPFB 205 // Transport Layer Feedback
#define RTCP_PT_PSFB  206 // Payload-Specific Feedback

// DTLS content types (RFC 5246)
#define DTLS_CONTENT_CHANGE_CIPHER 20
#define DTLS_CONTENT_ALERT         21
#define DTLS_CONTENT_HANDSHAKE     22
#define DTLS_CONTENT_APPLICATION   23
#define DTLS_CONTENT_HEARTBEAT     24
#define DTLS_CONTENT_MAX           25

// Minimum packet sizes
#define MIN_RTP_HEADER_SIZE  12
#define MIN_RTCP_HEADER_SIZE 8
#define MIN_STUN_HEADER_SIZE 20
#define MIN_DTLS_HEADER_SIZE 13

// ============================================================================
// Data Structures
// ============================================================================

// Forward table entry: destination for RTP packet forwarding
// Size: 20 bytes per entry
// Total map size: 65536 * 20 = ~1.3MB (fits in L2 cache)
struct forward_entry {
    __u8  dst_mac[6];    // Destination MAC address
    __u16 _pad;          // Alignment padding
    __u32 dst_ip;        // Destination IP (network byte order)
    __u16 dst_port;      // Destination UDP port (network byte order)
    __u16 _pad2;         // Alignment padding
    __u32 ifindex;       // Output interface index for redirect
};

// ============================================================================
// BPF Maps
// ============================================================================

// Forward table: SSRC -> destination mapping
// Used for kernel-space RTP forwarding (hot path)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FORWARD_ENTRIES);
    __type(key, __u32);                    // SSRC (32-bit)
    __type(value, struct forward_entry);   // Destination info
} forward_table SEC(".maps");

// Per-CPU statistics counters
// Using PERCPU_ARRAY avoids lock contention on stats updates
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// AF_XDP socket map for cold path packets
// Packets that need user-space processing are redirected here
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);  // Max 64 queues
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Increment a statistics counter (lock-free via PERCPU)
static __always_inline void stats_inc(__u32 idx) {
    __u64 *counter = bpf_map_lookup_elem(&stats_map, &idx);
    if (counter) {
        (*counter)++;
    }
}

// Check if payload type is a valid RTP payload type
// Returns 1 if RTP, 0 otherwise
static __always_inline int is_rtp_payload_type(__u8 pt) {
    // Mask off marker bit (bit 7)
    __u8 payload_type = pt & 0x7F;
    
    // Dynamic payload types (96-127) - most WebRTC codecs
    if (payload_type >= RTP_PT_MIN_DYNAMIC && payload_type <= RTP_PT_MAX_DYNAMIC) {
        return 1;
    }
    
    // Static payload types (0-34) - legacy codecs
    if (payload_type <= RTP_PT_MAX_STATIC) {
        return 1;
    }
    
    return 0;
}

// Check if payload type is RTCP (200-206)
static __always_inline int is_rtcp_payload_type(__u8 pt) {
    return (pt >= RTCP_PT_SR && pt <= RTCP_PT_PSFB);
}

// Check if packet is DTLS based on content type byte
static __always_inline int is_dtls_content_type(__u8 content_type) {
    return (content_type >= DTLS_CONTENT_CHANGE_CIPHER && 
            content_type <= DTLS_CONTENT_MAX);
}

// Compute IP header checksum (RFC 1071)
// WHY: After rewriting IP addresses, we must recalculate the checksum
static __always_inline __u16 ip_checksum(struct iphdr *iph) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;
    int len = iph->ihl * 4;
    
    // Clear existing checksum
    iph->check = 0;
    
    // Sum all 16-bit words (bounded loop for verifier)
    #pragma unroll
    for (int i = 0; i < 10; i++) {  // Max 20 bytes = 10 words
        if (i * 2 >= len) break;
        sum += ptr[i];
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// Compute UDP checksum incrementally after header rewrite
// WHY: Full UDP checksum recalculation is expensive; use incremental update
static __always_inline __u16 udp_checksum_update(
    __u16 old_check,
    __u32 old_ip, __u32 new_ip,
    __u16 old_port, __u16 new_port
) {
    __u32 sum;
    
    // If checksum was 0 (disabled), keep it disabled
    if (old_check == 0) {
        return 0;
    }
    
    // RFC 1624: Incremental checksum update
    // ~new_check = ~old_check + ~old_value + new_value
    sum = ~old_check & 0xFFFF;
    
    // Update for IP address change (2 x 16-bit words)
    sum += ~(old_ip & 0xFFFF) & 0xFFFF;
    sum += ~(old_ip >> 16) & 0xFFFF;
    sum += (new_ip & 0xFFFF);
    sum += (new_ip >> 16);
    
    // Update for port change
    sum += ~old_port & 0xFFFF;
    sum += new_port;
    
    // Fold and complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// ============================================================================
// Packet Classification
// ============================================================================

// Packet type classification result
enum pkt_type {
    PKT_RTP,
    PKT_RTCP,
    PKT_DTLS,
    PKT_STUN,
    PKT_UNKNOWN
};

// Classify UDP payload as RTP, RTCP, DTLS, or STUN
// WHY: Different packet types require different processing paths
// - RTP: Forward in kernel (hot path)
// - Others: Pass to user space (cold path)
static __always_inline enum pkt_type classify_packet(
    void *data, void *data_end, int payload_offset
) {
    __u8 *payload = data + payload_offset;
    
    // Bounds check: need at least 1 byte to classify
    if (payload + 1 > (__u8 *)data_end) {
        return PKT_UNKNOWN;
    }
    
    __u8 first_byte = payload[0];
    
    // DTLS check: content type 20-25 in first byte
    // WHY: DTLS has distinctive content type values
    if (is_dtls_content_type(first_byte)) {
        // Verify DTLS header length
        if (payload + MIN_DTLS_HEADER_SIZE > (__u8 *)data_end) {
            return PKT_UNKNOWN;
        }
        return PKT_DTLS;
    }
    
    // STUN check: magic cookie at bytes 4-7
    // WHY: STUN has a fixed magic cookie for identification
    if (payload + MIN_STUN_HEADER_SIZE <= (__u8 *)data_end) {
        __u32 *magic = (__u32 *)(payload + 4);
        if (bpf_ntohl(*magic) == STUN_MAGIC_COOKIE) {
            return PKT_STUN;
        }
    }
    
    // RTP/RTCP check: version must be 2 (bits 6-7 of first byte)
    __u8 version = (first_byte >> 6) & 0x03;
    if (version != 2) {
        return PKT_UNKNOWN;
    }
    
    // Need second byte for payload type
    if (payload + 2 > (__u8 *)data_end) {
        return PKT_UNKNOWN;
    }
    
    __u8 second_byte = payload[1];
    
    // RTCP check: payload type 200-206
    // WHY: RTCP uses specific payload type values
    if (is_rtcp_payload_type(second_byte)) {
        if (payload + MIN_RTCP_HEADER_SIZE > (__u8 *)data_end) {
            return PKT_UNKNOWN;
        }
        return PKT_RTCP;
    }
    
    // RTP check: valid payload type
    // WHY: RTP uses payload types 0-34 (static) or 96-127 (dynamic)
    if (is_rtp_payload_type(second_byte)) {
        if (payload + MIN_RTP_HEADER_SIZE > (__u8 *)data_end) {
            return PKT_UNKNOWN;
        }
        return PKT_RTP;
    }
    
    return PKT_UNKNOWN;
}

// ============================================================================
// Main XDP Program
// ============================================================================

SEC("xdp")
int xdp_sfu_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // ========================================================================
    // Parse Ethernet Header
    // ========================================================================
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stats_inc(STATS_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // ========================================================================
    // Parse IP Header
    // ========================================================================
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        stats_inc(STATS_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // Validate IP header length (minimum 20 bytes, IHL field is in 4-byte units)
    if (iph->ihl < 5) {
        stats_inc(STATS_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // Only process UDP packets
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // Calculate IP header length
    int ip_hdr_len = iph->ihl * 4;
    
    // ========================================================================
    // Parse UDP Header
    // ========================================================================
    struct udphdr *udph = (void *)iph + ip_hdr_len;
    if ((void *)(udph + 1) > data_end) {
        stats_inc(STATS_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // Calculate payload offset
    int payload_offset = sizeof(*eth) + ip_hdr_len + sizeof(*udph);
    
    // ========================================================================
    // Classify Packet
    // ========================================================================
    enum pkt_type ptype = classify_packet(data, data_end, payload_offset);
    
    // ========================================================================
    // Handle Non-RTP Packets (Cold Path -> AF_XDP)
    // ========================================================================
    if (ptype != PKT_RTP) {
        // Update statistics based on packet type
        switch (ptype) {
            case PKT_RTCP:
                stats_inc(STATS_RTCP_PASSED);
                break;
            case PKT_DTLS:
                stats_inc(STATS_DTLS_PASSED);
                break;
            case PKT_STUN:
                stats_inc(STATS_STUN_PASSED);
                break;
            default:
                stats_inc(STATS_UNKNOWN_PASSED);
                break;
        }
        
        // Redirect to AF_XDP socket for user-space processing
        // WHY: RTCP, DTLS, STUN require complex state machines in user space
        __u32 queue_id = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
            return bpf_redirect_map(&xsks_map, queue_id, XDP_PASS);
        }
        
        // No AF_XDP socket bound, pass to kernel stack
        return XDP_PASS;
    }
    
    // ========================================================================
    // Handle RTP Packets (Hot Path -> Kernel Forwarding)
    // ========================================================================
    
    // Extract SSRC from RTP header (bytes 8-11 of RTP header)
    __u8 *rtp_hdr = data + payload_offset;
    if (rtp_hdr + MIN_RTP_HEADER_SIZE > (__u8 *)data_end) {
        stats_inc(STATS_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // SSRC is at offset 8 in RTP header (network byte order)
    __u32 ssrc = *(__u32 *)(rtp_hdr + 8);
    
    // Lookup destination in forward table
    struct forward_entry *entry = bpf_map_lookup_elem(&forward_table, &ssrc);
    if (!entry) {
        // No forwarding entry - pass to user space for new track setup
        stats_inc(STATS_MAP_MISSES);
        stats_inc(STATS_RTP_PASSED);
        
        // Try AF_XDP redirect
        __u32 queue_id = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
            return bpf_redirect_map(&xsks_map, queue_id, XDP_PASS);
        }
        return XDP_PASS;
    }
    
    // ========================================================================
    // Rewrite Headers for Forwarding
    // ========================================================================
    
    // Save old values for checksum update
    __u32 old_daddr = iph->daddr;
    __u16 old_dport = udph->dest;
    
    // Rewrite destination MAC
    __builtin_memcpy(eth->h_dest, entry->dst_mac, 6);
    
    // Rewrite destination IP
    iph->daddr = entry->dst_ip;
    
    // Rewrite destination port
    udph->dest = entry->dst_port;
    
    // ========================================================================
    // Recalculate Checksums
    // ========================================================================
    
    // Recalculate IP checksum (required after IP header modification)
    iph->check = ip_checksum(iph);
    
    // Update UDP checksum incrementally
    udph->check = udp_checksum_update(
        udph->check,
        old_daddr, entry->dst_ip,
        old_dport, entry->dst_port
    );
    
    // ========================================================================
    // Redirect to Output Interface
    // ========================================================================
    stats_inc(STATS_RTP_FORWARDED);
    
    // Redirect packet to the specified interface
    // WHY: XDP_REDIRECT is faster than returning to kernel stack
    return bpf_redirect(entry->ifindex, 0);
}

// License declaration required for BPF programs
char _license[] SEC("license") = "GPL";
