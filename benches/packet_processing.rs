//! Packet Processing Benchmarks for Nexus SFU
//!
//! Benchmarks RTCP parsing and packet demux classification.
//! Complements benches/forwarding.rs which covers RTP parsing.
//!
//! Run with: cargo bench --bench packet_processing
//!
//! # Benchmarks
//!
//! - RTCP parsing: Sender Reports, Receiver Reports, PLI, NACK
//! - Packet demux: Classification of RTP vs RTCP vs STUN vs DTLS
//!
//! # Performance Targets
//!
//! - RTCP SR parsing: ~30-50ns per packet
//! - RTCP RR block parsing: ~20-30ns per block
//! - Packet demux: ~5-10ns per packet

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use nexus_webrtc::webrtc::{PacketType, quick_classify};

// Re-export RTCP types from nexus-media
use nexus_media::rtcp::{SenderReport, ReceiverReportBlock, PliPacket, NackPacket};

// =============================================================================
// RTCP Packet Generators
// =============================================================================

/// Create a valid RTCP Sender Report packet (28 bytes).
fn create_sender_report() -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    // Header: V=2, P=0, RC=0, PT=200 (SR), length=6 words
    packet[0] = 0x80; // V=2, P=0, RC=0
    packet[1] = 200;  // PT=200 (Sender Report)
    packet[2] = 0x00;
    packet[3] = 0x06; // Length = 6 words (28 bytes / 4 - 1)
    
    // SSRC of sender (bytes 4-7)
    packet[4..8].copy_from_slice(&0xDEADBEEF_u32.to_be_bytes());
    
    // NTP timestamp (bytes 8-15)
    packet[8..16].copy_from_slice(&0x1234567890ABCDEF_u64.to_be_bytes());
    
    // RTP timestamp (bytes 16-19)
    packet[16..20].copy_from_slice(&0x12345678_u32.to_be_bytes());
    
    // Sender's packet count (bytes 20-23)
    packet[20..24].copy_from_slice(&1000_u32.to_be_bytes());
    
    // Sender's octet count (bytes 24-27)
    packet[24..28].copy_from_slice(&150000_u32.to_be_bytes());
    
    packet
}

/// Create a valid RTCP Receiver Report block (24 bytes).
fn create_receiver_report_block() -> Vec<u8> {
    let mut block = vec![0u8; 24];
    
    // SSRC of source (bytes 0-3)
    block[0..4].copy_from_slice(&0xCAFEBABE_u32.to_be_bytes());
    
    // Fraction lost (byte 4) - 5% loss = 12/256
    block[4] = 12;
    
    // Cumulative lost (bytes 5-7) - 24-bit signed
    block[5] = 0x00;
    block[6] = 0x00;
    block[7] = 0x64; // 100 packets lost
    
    // Extended highest sequence number (bytes 8-11)
    block[8..12].copy_from_slice(&0x0001FFFF_u32.to_be_bytes());
    
    // Interarrival jitter (bytes 12-15)
    block[12..16].copy_from_slice(&500_u32.to_be_bytes());
    
    // Last SR timestamp (bytes 16-19)
    block[16..20].copy_from_slice(&0x12345678_u32.to_be_bytes());
    
    // Delay since last SR (bytes 20-23)
    block[20..24].copy_from_slice(&0x0000FFFF_u32.to_be_bytes());
    
    block
}

/// Create a valid RTCP PLI packet (12 bytes).
fn create_pli_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    // Header: V=2, P=0, FMT=1, PT=206 (Payload Feedback), length=2
    packet[0] = 0x81; // V=2, P=0, FMT=1
    packet[1] = 206;  // PT=206 (Payload Feedback)
    packet[2] = 0x00;
    packet[3] = 0x02; // Length = 2 words
    
    // SSRC of packet sender (bytes 4-7)
    packet[4..8].copy_from_slice(&0x11111111_u32.to_be_bytes());
    
    // SSRC of media source (bytes 8-11)
    packet[8..12].copy_from_slice(&0x22222222_u32.to_be_bytes());
    
    packet
}

/// Create a valid RTCP NACK packet with multiple lost packets.
fn create_nack_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 16];
    // Header: V=2, P=0, FMT=1, PT=205 (Transport Feedback), length=3
    packet[0] = 0x81; // V=2, P=0, FMT=1
    packet[1] = 205;  // PT=205 (Transport Feedback)
    packet[2] = 0x00;
    packet[3] = 0x03; // Length = 3 words
    
    // SSRC of packet sender (bytes 4-7)
    packet[4..8].copy_from_slice(&0x11111111_u32.to_be_bytes());
    
    // SSRC of media source (bytes 8-11)
    packet[8..12].copy_from_slice(&0x22222222_u32.to_be_bytes());
    
    // FCI: PID=1000, BLP=0x000F (packets 1001-1004 also lost)
    packet[12..14].copy_from_slice(&1000_u16.to_be_bytes());
    packet[14..16].copy_from_slice(&0x000F_u16.to_be_bytes());
    
    packet
}

// =============================================================================
// Demux Packet Generators
// =============================================================================

/// Create a minimal STUN binding request packet.
fn create_stun_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    // STUN header
    packet[0] = 0x00; // Message type high byte
    packet[1] = 0x01; // Binding Request
    packet[2] = 0x00; // Message length high byte
    packet[3] = 0x00; // Message length low byte (no attributes)
    // Magic cookie
    packet[4..8].copy_from_slice(&0x2112A442_u32.to_be_bytes());
    // Transaction ID (12 bytes)
    for i in 8..20 {
        packet[i] = (i - 8) as u8;
    }
    packet
}

/// Create a minimal DTLS handshake packet.
fn create_dtls_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 13];
    packet[0] = 22;   // Content type: Handshake
    packet[1] = 0xFE; // Version high byte (DTLS 1.2)
    packet[2] = 0xFD; // Version low byte
    // Epoch (2 bytes)
    packet[3] = 0x00;
    packet[4] = 0x00;
    // Sequence number (6 bytes)
    packet[5..11].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // Length (2 bytes) - 0 for minimal packet
    packet[11] = 0x00;
    packet[12] = 0x00;
    packet
}

/// Create a minimal RTP packet.
fn create_rtp_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&1234_u16.to_be_bytes());
    packet[4..8].copy_from_slice(&5678_u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0xDEADBEEF_u32.to_be_bytes());
    packet
}

/// Create a minimal RTCP packet.
fn create_rtcp_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 8];
    packet[0] = 0x80; // V=2, P=0, RC=0
    packet[1] = 200;  // PT=200 (SR) - maps to payload type 72 in demux
    packet[2] = 0x00;
    packet[3] = 0x01; // Length = 1 word
    packet[4..8].copy_from_slice(&0xDEADBEEF_u32.to_be_bytes());
    packet
}

/// Create a batch of mixed packets for realistic demux benchmarking.
fn create_mixed_packet_batch() -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(64);
    
    // 70% RTP (typical media-heavy workload)
    for _ in 0..45 {
        packets.push(create_rtp_packet());
    }
    
    // 15% RTCP
    for _ in 0..10 {
        packets.push(create_rtcp_packet());
    }
    
    // 10% STUN (ICE keepalives)
    for _ in 0..6 {
        packets.push(create_stun_packet());
    }
    
    // 5% DTLS
    for _ in 0..3 {
        packets.push(create_dtls_packet());
    }
    
    packets
}

// =============================================================================
// RTCP Parsing Benchmarks
// =============================================================================

/// Benchmark RTCP Sender Report parsing.
///
/// Target: ~30-50ns per packet
fn bench_rtcp_sender_report_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtcp_parse");
    group.throughput(Throughput::Elements(1));
    
    let sr_packet = create_sender_report();
    
    group.bench_function("sender_report", |b| {
        b.iter(|| {
            let result = SenderReport::parse(black_box(&sr_packet));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark RTCP Receiver Report block parsing.
///
/// Target: ~20-30ns per block
fn bench_rtcp_receiver_report_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtcp_parse");
    group.throughput(Throughput::Elements(1));
    
    let rr_block = create_receiver_report_block();
    
    group.bench_function("receiver_report_block", |b| {
        b.iter(|| {
            let result = ReceiverReportBlock::parse(black_box(&rr_block));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark RTCP PLI packet parsing.
fn bench_rtcp_pli_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtcp_parse");
    group.throughput(Throughput::Elements(1));
    
    let pli_packet = create_pli_packet();
    
    group.bench_function("pli", |b| {
        b.iter(|| {
            let result = PliPacket::parse(black_box(&pli_packet));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark RTCP NACK packet parsing.
fn bench_rtcp_nack_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtcp_parse");
    group.throughput(Throughput::Elements(1));
    
    let nack_packet = create_nack_packet();
    
    group.bench_function("nack", |b| {
        b.iter(|| {
            let result = NackPacket::parse(black_box(&nack_packet));
            black_box(result)
        });
    });
    
    group.finish();
}

// =============================================================================
// Packet Demux Benchmarks
// =============================================================================

/// Benchmark packet type classification for individual packet types.
///
/// Target: ~5-10ns per packet
fn bench_demux_classify_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("demux_classify");
    group.throughput(Throughput::Elements(1));
    
    let stun = create_stun_packet();
    let dtls = create_dtls_packet();
    let rtp = create_rtp_packet();
    let rtcp = create_rtcp_packet();
    
    group.bench_function("stun", |b| {
        b.iter(|| {
            let result = quick_classify(black_box(&stun));
            black_box(result)
        });
    });
    
    group.bench_function("dtls", |b| {
        b.iter(|| {
            let result = quick_classify(black_box(&dtls));
            black_box(result)
        });
    });
    
    group.bench_function("rtp", |b| {
        b.iter(|| {
            let result = quick_classify(black_box(&rtp));
            black_box(result)
        });
    });
    
    group.bench_function("rtcp", |b| {
        b.iter(|| {
            let result = quick_classify(black_box(&rtcp));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark batch packet classification with realistic distribution.
///
/// Simulates actual SFU workload: 70% RTP, 15% RTCP, 10% STUN, 5% DTLS
fn bench_demux_classify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("demux_classify_batch");
    group.throughput(Throughput::Elements(64));
    
    let batch = create_mixed_packet_batch();
    let packet_refs: Vec<&[u8]> = batch.iter().map(|p| p.as_slice()).collect();
    
    group.bench_function("64_mixed_packets", |b| {
        b.iter(|| {
            let mut results = [PacketType::Unknown; 64];
            for (i, packet) in packet_refs.iter().enumerate() {
                results[i] = quick_classify(black_box(packet));
            }
            black_box(results)
        });
    });
    
    group.finish();
}

/// Benchmark demux throughput with pure RTP stream.
fn bench_demux_rtp_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("demux_rtp_only");
    group.throughput(Throughput::Elements(64));
    
    let packets: Vec<Vec<u8>> = (0..64).map(|_| create_rtp_packet()).collect();
    let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();
    
    group.bench_function("64_rtp_packets", |b| {
        b.iter(|| {
            let mut results = [PacketType::Unknown; 64];
            for (i, packet) in packet_refs.iter().enumerate() {
                results[i] = quick_classify(black_box(packet));
            }
            black_box(results)
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_rtcp_sender_report_parse,
    bench_rtcp_receiver_report_parse,
    bench_rtcp_pli_parse,
    bench_rtcp_nack_parse,
    bench_demux_classify_individual,
    bench_demux_classify_batch,
    bench_demux_rtp_only,
);

criterion_main!(benches);
