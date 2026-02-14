//! Forwarding Benchmarks for Nexus SFU MVP
//!
//! Benchmarks packet forwarding performance to verify the 500K+ packets/sec/core target.
//!
//! Run with: cargo bench --bench forwarding

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use nexus_sfu::{
    arena::PacketArena,
    forward::{SsrcRouter, Subscriber, SubscriberList},
    media::rtp::RtpHeader,
    ring_buffer::RingBuffer,
    transport::BatchSender,
};

// =============================================================================
// RTP Parsing Benchmark Helpers
// =============================================================================
//
// Performance Targets:
// - Standard parsing: ~50-80ns per packet (baseline)
// - SIMD parsing: ~10-15ns per packet (4-5x faster)
// - Batch parsing: ~10-15ns per packet (SIMD + prefetch optimization)
//
// Platform-specific optimizations:
// - x86_64 SSE4.1: 128-bit SIMD loads and extracts
// - aarch64 NEON: 128-bit NEON intrinsics
// - AVX2 batch: 8-packet chunks with prefetch
// - AVX-512 batch: 16-packet chunks with prefetch
//
// Run specific benchmarks:
//   cargo bench --bench forwarding -- rtp_parse
//
// Interpret results:
// - Compare "standard" vs "simd" to verify 4-5x speedup
// - Compare batch implementations to find optimal for your CPU
// - Target: >1M packets/second/core for realistic workload
// =============================================================================

/// Create a minimal 12-byte RTP packet (version 2, no CSRC, no extension).
fn create_rtp_packet_minimal() -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&1234u16.to_be_bytes()); // Sequence number
    packet[4..8].copy_from_slice(&5678u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // SSRC
    packet
}

/// Create an RTP packet with specified CSRC count (12 + count*4 bytes).
fn create_rtp_packet_with_csrc(count: u8) -> Vec<u8> {
    let csrc_size = (count as usize) * 4;
    let mut packet = vec![0u8; 12 + csrc_size];
    packet[0] = 0x80 | count; // V=2, P=0, X=0, CC=count
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&1234u16.to_be_bytes()); // Sequence number
    packet[4..8].copy_from_slice(&5678u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // SSRC
    // Fill CSRC entries
    for i in 0..count as usize {
        let csrc = (0x11111111u32).wrapping_mul((i + 1) as u32);
        let offset = 12 + i * 4;
        packet[offset..offset + 4].copy_from_slice(&csrc.to_be_bytes());
    }
    packet
}

/// Create an RTP packet with extension header (12 + 4 + extension_data bytes).
fn create_rtp_packet_with_extension() -> Vec<u8> {
    let ext_words = 2u16; // 8 bytes of extension data
    let ext_data_size = (ext_words as usize) * 4;
    let mut packet = vec![0u8; 12 + 4 + ext_data_size];
    packet[0] = 0x90; // V=2, P=0, X=1, CC=0
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&1234u16.to_be_bytes()); // Sequence number
    packet[4..8].copy_from_slice(&5678u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // SSRC
    // Extension header
    packet[12..14].copy_from_slice(&[0xBE, 0xDE]); // Profile-specific (RFC 5285)
    packet[14..16].copy_from_slice(&ext_words.to_be_bytes()); // Length in words
    // Extension data (filled with pattern)
    for i in 0..ext_data_size {
        packet[16 + i] = (i % 256) as u8;
    }
    packet
}

/// Create a realistic 1200-byte RTP packet with payload.
fn create_rtp_packet_large() -> Vec<u8> {
    let payload_size = 1188; // 1200 - 12 = 1188 bytes payload
    let mut packet = vec![0u8; 12 + payload_size];
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0xE0; // M=1, PT=96 (marker set for video keyframe)
    packet[2..4].copy_from_slice(&1234u16.to_be_bytes()); // Sequence number
    packet[4..8].copy_from_slice(&5678u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // SSRC
    // Fill payload with pattern
    for i in 0..payload_size {
        packet[12 + i] = (i % 256) as u8;
    }
    packet
}

/// Create a batch of 64 packets with realistic distribution.
/// - 80% minimal (no CSRC, no extension) - typical audio/video
/// - 15% with CSRC (2 CSRCs) - conferencing with mixers
/// - 5% with extension - advanced features like abs-send-time
fn create_rtp_batch_64() -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(64);
    
    // 80% minimal (51 packets)
    for _ in 0..51 {
        packets.push(create_rtp_packet_minimal());
    }
    
    // 15% with CSRC (10 packets)
    for _ in 0..10 {
        packets.push(create_rtp_packet_with_csrc(2));
    }
    
    // 5% with extension (3 packets)
    for _ in 0..3 {
        packets.push(create_rtp_packet_with_extension());
    }
    
    packets
}

/// Create a test packet slot with RTP-like data
fn create_test_packet(arena: &PacketArena, seq: u16) -> nexus_sfu::PacketSlot {
    let mut slot = arena.alloc().expect("Failed to allocate packet slot");
    
    // Create a minimal RTP header (12 bytes) + payload
    let data = slot.data_mut();
    data[0] = 0x80; // V=2, P=0, X=0, CC=0
    data[1] = 0x60; // M=0, PT=96
    data[2] = (seq >> 8) as u8;
    data[3] = seq as u8;
    // Timestamp (4 bytes)
    data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // SSRC (4 bytes)
    data[8..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    // Payload (160 bytes for audio-like packet)
    for i in 12..172 {
        data[i] = (i % 256) as u8;
    }
    
    slot.set_len(172);
    slot
}

/// Benchmark packet arena allocation and deallocation
fn bench_arena_alloc(c: &mut Criterion) {
    let arena = PacketArena::new(64).expect("Failed to create arena");
    
    c.bench_function("arena_alloc_dealloc", |b| {
        b.iter(|| {
            let slot = arena.alloc().expect("Failed to allocate");
            black_box(slot);
            // Slot is automatically deallocated on drop
        });
    });
}

/// Benchmark ring buffer push operations
fn bench_ring_buffer_push(c: &mut Criterion) {
    let arena = PacketArena::new(64).expect("Failed to create arena");
    let ring_buffer: RingBuffer<2048> = RingBuffer::new();
    
    c.bench_function("ring_buffer_push", |b| {
        let mut seq = 0u16;
        b.iter(|| {
            let packet = create_test_packet(&arena, seq);
            let result = ring_buffer.push(packet);
            black_box(result);
            seq = seq.wrapping_add(1);
        });
    });
}

/// Benchmark SSRC router lookup
fn bench_ssrc_lookup(c: &mut Criterion) {
    let router = SsrcRouter::new();
    
    // Register 1000 SSRCs
    for i in 1..=1000u32 {
        router.register(i, i as u64, i % 8).expect("Failed to register SSRC");
    }
    
    c.bench_function("ssrc_lookup", |b| {
        let mut ssrc = 1u32;
        b.iter(|| {
            let result = router.lookup(ssrc);
            black_box(result);
            ssrc = (ssrc % 1000) + 1;
        });
    });
}

/// Benchmark batch sender queue operation
fn bench_batch_sender_queue(c: &mut Criterion) {
    let arena = PacketArena::new(64).expect("Failed to create arena");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
    let socket_fd = socket.as_raw_fd();
    
    let mut sender = BatchSender::new(socket_fd, 64, 1000);
    let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    
    c.bench_function("batch_sender_queue", |b| {
        let mut seq = 0u16;
        b.iter(|| {
            let packet = create_test_packet(&arena, seq);
            sender.queue(dest, packet);
            seq = seq.wrapping_add(1);
            
            // Flush periodically to avoid memory buildup
            if sender.pending_count() >= 64 {
                let _ = sender.flush();
            }
        });
    });
}

/// Benchmark subscriber list iteration (hot path)
fn bench_subscriber_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("subscriber_iteration");
    
    for subscriber_count in [100, 500, 1000].iter() {
        let mut list = SubscriberList::new(5_000_000_000);
        
        // Add subscribers
        for i in 1..=*subscriber_count {
            let addr: SocketAddr = format!("192.168.{}.{}:5000", i / 256, i % 256).parse().unwrap();
            let subscriber = Subscriber::new(i as u32, i as u64, addr);
            list.add(subscriber);
        }
        
        group.throughput(Throughput::Elements(*subscriber_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subscriber_count),
            subscriber_count,
            |b, _| {
                b.iter(|| {
                    let mut count = 0;
                    for subscriber in list.iter_hot() {
                        black_box(subscriber.dest_addr());
                        count += 1;
                    }
                    black_box(count);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark packet forwarding to multiple subscribers
fn bench_packet_forwarding(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_forwarding");
    
    for subscriber_count in [100, 500, 1000].iter() {
        let arena = PacketArena::new(64).expect("Failed to create arena");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
        let socket_fd = socket.as_raw_fd();
        
        // Create subscriber list
        let mut subscribers: Vec<SocketAddr> = Vec::with_capacity(*subscriber_count);
        for i in 1..=*subscriber_count {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10000 + i).parse().unwrap();
            subscribers.push(addr);
        }
        
        group.throughput(Throughput::Elements(*subscriber_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subscriber_count),
            subscriber_count,
            |b, _| {
                let mut sender = BatchSender::new(socket_fd, 64, 1000);
                let mut seq = 0u16;
                
                b.iter(|| {
                    // Create a packet
                    let packet = create_test_packet(&arena, seq);
                    seq = seq.wrapping_add(1);
                    
                    // Forward to all subscribers (simulating track forwarding)
                    for dest in &subscribers {
                        let packet_clone = packet.clone_shallow();
                        sender.queue(*dest, packet_clone);
                    }
                    
                    // Flush the batch
                    let (sent, _failed) = sender.flush();
                    black_box(sent);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark batch sender throughput (packets per second)
fn bench_batch_sender_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_sender_throughput");
    group.throughput(Throughput::Elements(64)); // 64 packets per batch
    
    let arena = PacketArena::new(64).expect("Failed to create arena");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
    let socket_fd = socket.as_raw_fd();
    
    group.bench_function("batch_64_packets", |b| {
        let mut sender = BatchSender::new(socket_fd, 64, 1000);
        let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut seq = 0u16;
        
        b.iter(|| {
            // Queue 64 packets
            for _ in 0..64 {
                let packet = create_test_packet(&arena, seq);
                sender.queue(dest, packet);
                seq = seq.wrapping_add(1);
            }
            
            // Flush
            let (sent, _failed) = sender.flush();
            black_box(sent);
        });
    });
    
    group.finish();
}

/// Benchmark shallow clone performance (zero-copy forwarding)
fn bench_shallow_clone(c: &mut Criterion) {
    let arena = PacketArena::new(64).expect("Failed to create arena");
    let packet = create_test_packet(&arena, 0);
    
    c.bench_function("packet_shallow_clone", |b| {
        b.iter(|| {
            let cloned = packet.clone_shallow();
            black_box(cloned);
        });
    });
}

/// Benchmark end-to-end forwarding pipeline
fn bench_forwarding_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("forwarding_pipeline");
    
    // Target: 500K packets/sec/core
    // This benchmark measures the complete forwarding path:
    // 1. Allocate packet from arena
    // 2. Parse SSRC and lookup route
    // 3. Store in ring buffer
    // 4. Clone and queue to batch sender for each subscriber
    // 5. Flush batch
    
    for subscriber_count in [100, 500, 1000].iter() {
        let arena = PacketArena::new(64).expect("Failed to create arena");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
        let socket_fd = socket.as_raw_fd();
        
        // Setup SSRC router
        let router = SsrcRouter::new();
        let ssrc = 0xDEADBEEF_u32;
        let track_id = 1u64;
        let worker_id = 0u32;
        router.register(ssrc, track_id, worker_id).expect("Failed to register SSRC");
        
        // Setup ring buffer
        let ring_buffer: RingBuffer<2048> = RingBuffer::new();
        
        // Setup subscribers
        let mut subscribers: Vec<SocketAddr> = Vec::with_capacity(*subscriber_count);
        for i in 1..=*subscriber_count {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10000 + i).parse().unwrap();
            subscribers.push(addr);
        }
        
        group.throughput(Throughput::Elements(1)); // 1 packet through pipeline
        group.bench_with_input(
            BenchmarkId::new("subscribers", subscriber_count),
            subscriber_count,
            |b, _| {
                let mut sender = BatchSender::new(socket_fd, 64, 1000);
                let mut seq = 0u16;
                
                b.iter(|| {
                    // 1. Allocate packet
                    let packet = create_test_packet(&arena, seq);
                    seq = seq.wrapping_add(1);
                    
                    // 2. Lookup SSRC route
                    let route = router.lookup(ssrc);
                    black_box(route);
                    
                    // 3. Store in ring buffer
                    let ring_seq = ring_buffer.push(packet.clone_shallow());
                    black_box(ring_seq);
                    
                    // 4. Forward to subscribers
                    for dest in &subscribers {
                        let packet_clone = packet.clone_shallow();
                        sender.queue(*dest, packet_clone);
                    }
                    
                    // 5. Flush batch
                    let (sent, _failed) = sender.flush();
                    black_box(sent);
                });
            },
        );
    }
    
    group.finish();
}

// =============================================================================
// RTP Parsing Benchmarks
// =============================================================================
//
// These benchmarks validate the claimed 4-5x SIMD performance improvement:
//
// | Method          | Expected Performance | Notes                    |
// |-----------------|---------------------|--------------------------|
// | parse()         | 50-80ns/packet      | Baseline scalar parsing  |
// | parse_simd()    | 10-15ns/packet      | SSE4.1/NEON accelerated  |
// | parse_batch_*() | 10-15ns/packet      | SIMD + prefetch          |
//
// Run with: cargo bench --bench forwarding -- rtp_parse
// =============================================================================

/// Benchmark standard RTP parsing (baseline).
///
/// Tests `RtpHeader::parse()` across different packet types to establish
/// the baseline performance (~50-80ns per packet expected).
fn bench_rtp_parse_standard(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtp_parse_standard");
    group.throughput(Throughput::Elements(1));

    // Minimal packet (12 bytes)
    let minimal = create_rtp_packet_minimal();
    group.bench_function("minimal_12b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse(black_box(&minimal));
            black_box(result)
        });
    });

    // Packet with 2 CSRCs (20 bytes)
    let with_csrc = create_rtp_packet_with_csrc(2);
    group.bench_function("with_csrc_20b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse(black_box(&with_csrc));
            black_box(result)
        });
    });

    // Packet with extension (24 bytes)
    let with_ext = create_rtp_packet_with_extension();
    group.bench_function("with_extension_24b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse(black_box(&with_ext));
            black_box(result)
        });
    });

    // Large packet (1200 bytes)
    let large = create_rtp_packet_large();
    group.bench_function("large_1200b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse(black_box(&large));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark SIMD-accelerated RTP parsing.
///
/// Tests `RtpHeader::parse_simd()` across different packet types to verify
/// the 4-5x speedup over standard parsing (~10-15ns per packet expected).
fn bench_rtp_parse_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtp_parse_simd");
    group.throughput(Throughput::Elements(1));

    // Minimal packet (12 bytes)
    let minimal = create_rtp_packet_minimal();
    group.bench_function("minimal_12b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse_simd(black_box(&minimal));
            black_box(result)
        });
    });

    // Packet with 2 CSRCs (20 bytes)
    let with_csrc = create_rtp_packet_with_csrc(2);
    group.bench_function("with_csrc_20b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse_simd(black_box(&with_csrc));
            black_box(result)
        });
    });

    // Packet with extension (24 bytes)
    let with_ext = create_rtp_packet_with_extension();
    group.bench_function("with_extension_24b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse_simd(black_box(&with_ext));
            black_box(result)
        });
    });

    // Large packet (1200 bytes)
    let large = create_rtp_packet_large();
    group.bench_function("large_1200b", |b| {
        b.iter(|| {
            let result = RtpHeader::parse_simd(black_box(&large));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark batch parsing with 64-packet I/O batches.
///
/// Compares different batch parsing implementations:
/// - scalar_prefetch: Scalar parsing with prefetch optimization
/// - avx2: AVX2-optimized 8-packet chunks (x86_64 only, skipped if not supported)
/// - avx512: AVX-512-optimized 16-packet chunks (x86_64 only, skipped if not supported)
/// - optimal: Auto-dispatched to best available implementation
fn bench_rtp_parse_batch_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtp_parse_batch_64");
    group.throughput(Throughput::Elements(64)); // 64 packets per batch

    // Generate realistic 64-packet batch
    let batch = create_rtp_batch_64();
    let packet_refs: Vec<&[u8]> = batch.iter().map(|p| p.as_slice()).collect();

    // Scalar with prefetch (always available)
    group.bench_with_input(
        BenchmarkId::new("scalar_prefetch", "64_packets"),
        &packet_refs,
        |b, packets| {
            b.iter(|| {
                let results = RtpHeader::parse_batch_scalar(black_box(packets));
                black_box(results)
            });
        },
    );

    // AVX2 benchmark (x86_64 only, with runtime feature detection)
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            group.bench_with_input(
                BenchmarkId::new("avx2", "64_packets"),
                &packet_refs,
                |b, packets| {
                    b.iter(|| {
                        let results = RtpHeader::parse_batch_avx2(black_box(packets));
                        black_box(results)
                    });
                },
            );
        }
    }

    // AVX-512 benchmark (x86_64 only, with runtime feature detection)
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            group.bench_with_input(
                BenchmarkId::new("avx512", "64_packets"),
                &packet_refs,
                |b, packets| {
                    b.iter(|| {
                        let results = RtpHeader::parse_batch_avx512(black_box(packets));
                        black_box(results)
                    });
                },
            );
        }
    }

    // Optimal (auto-dispatch) - always available
    group.bench_with_input(
        BenchmarkId::new("optimal", "64_packets"),
        &packet_refs,
        |b, packets| {
            b.iter(|| {
                let results = RtpHeader::parse_batch_optimal(black_box(packets));
                black_box(results)
            });
        },
    );

    group.finish();
}

/// Benchmark comparing standard vs SIMD parsing side-by-side.
///
/// Provides direct comparison for each packet type to verify
/// the expected 4-5x speedup from SIMD acceleration.
fn bench_rtp_parse_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtp_parse_comparison");
    group.throughput(Throughput::Elements(1));

    // Test each packet type with both methods
    let packet_types: Vec<(&str, Vec<u8>)> = vec![
        ("minimal", create_rtp_packet_minimal()),
        ("with_csrc", create_rtp_packet_with_csrc(2)),
        ("with_extension", create_rtp_packet_with_extension()),
        ("large", create_rtp_packet_large()),
    ];

    for (name, packet) in packet_types.iter() {
        // Standard parsing
        group.bench_with_input(
            BenchmarkId::new("standard", *name),
            packet,
            |b, p| {
                b.iter(|| {
                    let result = RtpHeader::parse(black_box(p));
                    black_box(result)
                });
            },
        );

        // SIMD parsing
        group.bench_with_input(
            BenchmarkId::new("simd", *name),
            packet,
            |b, p| {
                b.iter(|| {
                    let result = RtpHeader::parse_simd(black_box(p));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark realistic SFU workload: 64-packet batches.
///
/// Simulates actual SFU packet processing by parsing complete 64-packet
/// I/O batches with realistic packet distribution. Uses the optimal
/// batch parsing method for maximum performance.
///
/// Target: >1M packets/second/core
/// - 64 packets at 15-20ns each = ~1-1.3μs per batch
/// - 1 batch at 1μs = 1M packets/second with 64 batches/second
fn bench_rtp_parse_realistic_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtp_parse_realistic");
    group.throughput(Throughput::Elements(64)); // 64 packets per iteration

    // Pre-generate multiple batches for variety
    let batches: Vec<Vec<Vec<u8>>> = (0..16).map(|_| create_rtp_batch_64()).collect();
    let batch_refs: Vec<Vec<&[u8]>> = batches
        .iter()
        .map(|batch| batch.iter().map(|p| p.as_slice()).collect())
        .collect();

    let mut batch_idx = 0usize;

    group.bench_function("64_packet_batch", |b| {
        b.iter(|| {
            let packets = &batch_refs[batch_idx % batch_refs.len()];
            let results = RtpHeader::parse_batch_optimal(black_box(packets));
            batch_idx = batch_idx.wrapping_add(1);
            black_box(results)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_arena_alloc,
    bench_ring_buffer_push,
    bench_ssrc_lookup,
    bench_batch_sender_queue,
    bench_subscriber_iteration,
    bench_packet_forwarding,
    bench_batch_sender_throughput,
    bench_shallow_clone,
    bench_forwarding_pipeline,
    bench_rtp_parse_standard,
    bench_rtp_parse_simd,
    bench_rtp_parse_batch_64,
    bench_rtp_parse_comparison,
    bench_rtp_parse_realistic_workload,
);

criterion_main!(benches);
