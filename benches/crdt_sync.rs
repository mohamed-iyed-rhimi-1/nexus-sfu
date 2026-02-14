//! CRDT Synchronization Benchmarks for Nexus SFU
//!
//! Benchmarks CRDT operations and gossip protocol encoding.
//!
//! Run with: cargo bench --bench crdt_sync
//!
//! # Benchmarks
//!
//! - GCounter: increment() and value()
//! - Orswot: add() and remove()
//! - CRDT merge: varying entry counts (10, 100, 1000)
//! - Gossip: broadcast encoding and fanout
//!
//! # Performance Targets
//!
//! - GCounter increment: ~5-10ns per operation
//! - Orswot add/remove: ~100-200ns per operation
//! - CRDT merge: O(n), ~1μs for 100 entries
//! - Gossip broadcast: ~10μs per broadcast to 3 peers

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use nexus_state::crdt::{GCounter, Orswot};
use nexus_state::types::{Dot, MAX_ACTORS};
use nexus_state::gossip::types::{StateUpdate, GossipMessage, TrackInfo};

// =============================================================================
// GCounter Benchmarks
// =============================================================================

/// Benchmark GCounter::increment() operation.
///
/// Target: ~5-10ns per increment
fn bench_gcounter_increment(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcounter");
    group.throughput(Throughput::Elements(1));
    
    let counter = GCounter::new();
    let mut actor_id = 0u64;
    
    group.bench_function("increment", |b| {
        b.iter(|| {
            let result = counter.increment(black_box(actor_id), black_box(1));
            actor_id = (actor_id + 1) % (MAX_ACTORS as u64);
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark GCounter::value() operation.
///
/// This sums all actor counters, so it's O(MAX_ACTORS).
fn bench_gcounter_value(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcounter");
    group.throughput(Throughput::Elements(1));
    
    let counter = GCounter::new();
    // Pre-populate with some values
    for i in 0..10 {
        counter.increment(i, 100);
    }
    
    group.bench_function("value", |b| {
        b.iter(|| {
            let result = counter.value();
            black_box(result)
        });
    });
    
    group.finish();
}

// =============================================================================
// Orswot Benchmarks
// =============================================================================

/// Benchmark Orswot::add() operation.
///
/// Target: ~100-200ns per add
fn bench_orswot_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));
    
    let mut set: Orswot<u32> = Orswot::new();
    let mut element = 0u32;
    let mut clock = 1u64;
    
    group.bench_function("add", |b| {
        b.iter(|| {
            let dot = Dot::new(0, clock);
            let result = set.add(black_box(element), black_box(dot));
            element = element.wrapping_add(1);
            clock += 1;
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark Orswot::remove() operation.
///
/// Target: ~100-200ns per remove
fn bench_orswot_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));
    
    // Pre-populate with elements
    let mut set: Orswot<u32> = Orswot::new();
    for i in 0..1000u32 {
        let _ = set.add(i, Dot::new(0, i as u64 + 1));
    }
    
    let mut element = 0u32;
    let mut clock = 2000u64;
    
    group.bench_function("remove", |b| {
        b.iter(|| {
            let dot = Dot::new(0, clock);
            let result = set.remove(black_box(&element), black_box(dot));
            element = (element + 1) % 1000;
            clock += 1;
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark Orswot::contains() operation.
fn bench_orswot_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));
    
    // Pre-populate with elements
    let mut set: Orswot<u32> = Orswot::new();
    for i in 0..500u32 {
        let _ = set.add(i, Dot::new(0, i as u64 + 1));
    }
    
    let mut element = 0u32;
    
    group.bench_function("contains", |b| {
        b.iter(|| {
            let result = set.contains(black_box(&element));
            element = (element + 1) % 1000; // Half will be found, half won't
            black_box(result)
        });
    });
    
    group.finish();
}

// =============================================================================
// CRDT Merge Benchmarks
// =============================================================================

/// Benchmark GCounter merge with varying entry counts.
///
/// Target: O(MAX_ACTORS), ~1μs for merge
fn bench_gcounter_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt_merge");
    
    for entry_count in [10, 100, 256].iter() {
        // Create two counters with different values
        let counter_a = GCounter::new();
        let counter_b = GCounter::new();
        
        // Populate counter_a
        for i in 0..*entry_count {
            let actor = (i % MAX_ACTORS) as u64;
            counter_a.increment(actor, 10);
        }
        
        // Populate counter_b with different values
        for i in 0..*entry_count {
            let actor = (i % MAX_ACTORS) as u64;
            counter_b.increment(actor, 5);
        }
        
        group.throughput(Throughput::Elements(*entry_count as u64));
        group.bench_with_input(
            BenchmarkId::new("gcounter", entry_count),
            entry_count,
            |b, _| {
                b.iter(|| {
                    counter_a.merge(black_box(&counter_b));
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark Orswot merge with varying entry counts.
///
/// Target: O(n), ~1μs for 100 entries
fn bench_orswot_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt_merge");
    
    for entry_count in [10, 100, 1000].iter() {
        // Create two sets with different elements
        let mut set_a: Orswot<u32> = Orswot::new();
        let mut set_b: Orswot<u32> = Orswot::new();
        
        // Populate set_a with elements 0..entry_count
        for i in 0..*entry_count as u32 {
            let _ = set_a.add(i, Dot::new(0, i as u64 + 1));
        }
        
        // Populate set_b with elements entry_count..2*entry_count
        for i in 0..*entry_count as u32 {
            let elem = i + *entry_count as u32;
            let _ = set_b.add(elem, Dot::new(1, i as u64 + 1));
        }
        
        group.throughput(Throughput::Elements(*entry_count as u64));
        group.bench_with_input(
            BenchmarkId::new("orswot", entry_count),
            entry_count,
            |b, _| {
                // Clone set_a for each iteration since merge modifies it
                let mut set_a_clone: Orswot<u32> = Orswot::new();
                for i in 0..*entry_count as u32 {
                    let _ = set_a_clone.add(i, Dot::new(0, i as u64 + 1));
                }
                
                b.iter(|| {
                    let _ = set_a_clone.merge(black_box(&set_b));
                });
            },
        );
    }
    
    group.finish();
}

// =============================================================================
// Gossip Broadcast Benchmarks
// =============================================================================

/// Create a sample StateUpdate for benchmarking.
fn create_state_update(i: u32) -> StateUpdate {
    StateUpdate::ParticipantAdded {
        room_id: i,
        participant_id: i * 2,
        dot: Dot::new(0, i as u64 + 1),
    }
}

/// Benchmark StateUpdate encoding.
fn bench_state_update_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");
    group.throughput(Throughput::Elements(1));
    
    let update = create_state_update(42);
    let mut buffer = [0u8; 64];
    
    group.bench_function("state_update_encode", |b| {
        b.iter(|| {
            let len = update.encode(black_box(&mut buffer));
            black_box(len)
        });
    });
    
    group.finish();
}

/// Benchmark StateUpdate decoding.
fn bench_state_update_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");
    group.throughput(Throughput::Elements(1));
    
    let update = create_state_update(42);
    let mut buffer = [0u8; 64];
    let len = update.encode(&mut buffer);
    let encoded = &buffer[..len];
    
    group.bench_function("state_update_decode", |b| {
        b.iter(|| {
            let result = StateUpdate::decode(black_box(encoded));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark GossipMessage::Ping encoding with piggyback updates.
///
/// Target: ~10μs per broadcast encoding
fn bench_gossip_ping_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");
    group.throughput(Throughput::Elements(1));
    
    // Create a Ping message with piggyback updates
    let piggyback: Vec<StateUpdate> = (0..8)
        .map(|i| create_state_update(i))
        .collect();
    
    let msg = GossipMessage::Ping {
        from: 1,
        incarnation: 100,
        piggyback,
    };
    
    group.bench_function("ping_encode", |b| {
        b.iter(|| {
            let encoded = msg.encode();
            black_box(encoded)
        });
    });
    
    group.finish();
}

/// Benchmark gossip broadcast encoding with fanout.
///
/// Simulates encoding a message for 3 peers (typical fanout).
fn bench_gossip_broadcast_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");
    group.throughput(Throughput::Elements(3)); // 3 peers
    
    // Create a Ping message with piggyback updates
    let piggyback: Vec<StateUpdate> = (0..4)
        .map(|i| create_state_update(i))
        .collect();
    
    let msg = GossipMessage::Ping {
        from: 1,
        incarnation: 100,
        piggyback,
    };
    
    group.bench_function("broadcast_fanout_3", |b| {
        b.iter(|| {
            // Encode for 3 peers (typical fanout)
            let encoded1 = msg.encode();
            let encoded2 = msg.encode();
            let encoded3 = msg.encode();
            black_box((encoded1, encoded2, encoded3))
        });
    });
    
    group.finish();
}

/// Benchmark TrackInfo encoding/decoding.
fn bench_track_info_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");
    group.throughput(Throughput::Elements(1));
    
    let info = TrackInfo {
        track_type: 1, // video
        codec: 96,     // VP8
        bitrate_kbps: 2500,
    };
    let mut buffer = [0u8; 16];
    
    group.bench_function("track_info_encode", |b| {
        b.iter(|| {
            let len = info.encode(black_box(&mut buffer));
            black_box(len)
        });
    });
    
    let len = info.encode(&mut buffer);
    let encoded = &buffer[..len];
    
    group.bench_function("track_info_decode", |b| {
        b.iter(|| {
            let result = TrackInfo::decode(black_box(encoded));
            black_box(result)
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_gcounter_increment,
    bench_gcounter_value,
    bench_orswot_add,
    bench_orswot_remove,
    bench_orswot_contains,
    bench_gcounter_merge,
    bench_orswot_merge,
    bench_state_update_encode,
    bench_state_update_decode,
    bench_gossip_ping_encode,
    bench_gossip_broadcast_fanout,
    bench_track_info_encode_decode,
);

criterion_main!(benches);
