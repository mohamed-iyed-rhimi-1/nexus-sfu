//! RTCP parsing benchmarks (`nexus-media`): Sender Reports, Receiver Report
//! blocks, PLI, NACK.
//!
//! The shard parses SRs and PLIs with these functions; RR and NACK parse into
//! `Vec`s and are not used on the shard (it counts and ignores them). The old
//! demux classification groups were removed with the old path (Phase 1, C2):
//! the shard's classifier is a first-byte range check whose cost is part of
//! `real_path`'s `ingress` numbers.
//!
//! Run with: cargo bench --bench packet_processing
//!
//! # Performance Targets
//!
//! - RTCP SR parsing: ~30-50ns per packet
//! - RTCP RR block parsing: ~20-30ns per block

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

// RTCP types from nexus-media
use nexus_media::rtcp::{NackPacket, PliPacket, ReceiverReportBlock, SenderReport};

// =============================================================================
// RTCP Packet Generators
// =============================================================================

/// Create a valid RTCP Sender Report packet (28 bytes).
fn create_sender_report() -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    // Header: V=2, P=0, RC=0, PT=200 (SR), length=6 words
    packet[0] = 0x80; // V=2, P=0, RC=0
    packet[1] = 200; // PT=200 (Sender Report)
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
    packet[1] = 206; // PT=206 (Payload Feedback)
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
    packet[1] = 205; // PT=205 (Transport Feedback)
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

criterion_group!(
    benches,
    bench_rtcp_sender_report_parse,
    bench_rtcp_receiver_report_parse,
    bench_rtcp_pli_parse,
    bench_rtcp_nack_parse,
);

criterion_main!(benches);
