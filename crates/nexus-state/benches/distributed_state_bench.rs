//! Benchmarks for DistributedState operations
//!
//! Run with: cargo bench --bench distributed_state_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

use nexus_state::{DistributedState, DistributedStateConfig, Dot};
use nexus_state::gossip::types::{StateUpdate, TrackInfo};

/// Benchmark adding participants to a room
fn bench_add_participant(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);
    state.create_room(1, "Benchmark Room".to_string(), 10000).unwrap();

    let mut participant_id = 1u32;

    c.bench_function("add_participant", |b| {
        b.iter(|| {
            participant_id += 1;
            let _ = black_box(state.add_participant(1, participant_id));
        })
    });
}

/// Benchmark removing participants from a room
fn bench_remove_participant(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);
    state.create_room(1, "Benchmark Room".to_string(), 10000).unwrap();

    // Pre-populate with participants
    for i in 1..=1000 {
        let _ = state.add_participant(1, i);
    }

    let mut participant_id = 1u32;

    c.bench_function("remove_participant", |b| {
        b.iter(|| {
            participant_id = (participant_id % 1000) + 1;
            let _ = black_box(state.remove_participant(1, participant_id));
            // Re-add for next iteration
            let _ = state.add_participant(1, participant_id);
        })
    });
}

/// Benchmark querying participants
fn bench_get_participants(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_participants");

    for size in [10, 100, 500, 1000].iter() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);
        state.create_room(1, "Benchmark Room".to_string(), 10000).unwrap();

        // Pre-populate with participants
        for i in 1..=*size {
            let _ = state.add_participant(1, i);
        }

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(state.get_participants(1))
            })
        });
    }

    group.finish();
}

/// Benchmark adding tracks
fn bench_add_track(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let mut track_id = 1u32;
    let info = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2500,
    };

    c.bench_function("add_track", |b| {
        b.iter(|| {
            track_id += 1;
            let _ = black_box(state.add_track(track_id, info));
        })
    });
}

/// Benchmark updating tracks
fn bench_update_track(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Pre-create track
    let info = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2500,
    };
    state.add_track(1, info).unwrap();

    let mut bitrate = 1000u32;

    c.bench_function("update_track", |b| {
        b.iter(|| {
            bitrate = (bitrate % 10000) + 100;
            let new_info = TrackInfo {
                track_type: 1,
                codec: 100,
                bitrate_kbps: bitrate,
            };
            let _ = black_box(state.update_track(1, new_info));
        })
    });
}

/// Benchmark getting track info
fn bench_get_track(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Pre-create tracks
    for i in 1..=100 {
        let info = TrackInfo {
            track_type: (i % 2) as u8,
            codec: 100,
            bitrate_kbps: 2500,
        };
        state.add_track(i, info).unwrap();
    }

    let mut track_id = 1u32;

    c.bench_function("get_track", |b| {
        b.iter(|| {
            track_id = (track_id % 100) + 1;
            black_box(state.get_track(track_id))
        })
    });
}

/// Benchmark adding subscriptions
fn bench_add_subscription(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let mut track_id = 1u32;
    let mut participant_id = 1u32;

    c.bench_function("add_subscription", |b| {
        b.iter(|| {
            track_id += 1;
            participant_id = (participant_id % 100) + 1;
            let _ = black_box(state.add_subscription(track_id, participant_id));
        })
    });
}

/// Benchmark querying subscriptions for a track
fn bench_get_subscriptions_for_track(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_subscriptions_for_track");

    for size in [10, 100, 500, 1000].iter() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        // Pre-populate subscriptions (all for track 1)
        for i in 1..=*size {
            let _ = state.add_subscription(1, i);
        }

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(state.get_subscriptions_for_track(1))
            })
        });
    }

    group.finish();
}

/// Benchmark querying subscriptions for a participant
fn bench_get_subscriptions_for_participant(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_subscriptions_for_participant");

    for size in [10, 100, 500, 1000].iter() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        // Pre-populate subscriptions (all for participant 1)
        for i in 1..=*size {
            let _ = state.add_subscription(i, 1);
        }

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(state.get_subscriptions_for_participant(1))
            })
        });
    }

    group.finish();
}

/// Benchmark merging a single delta
fn bench_merge_delta(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);
    state.create_room(1, "Benchmark".to_string(), 10000).unwrap();

    let mut clock = 1u64;

    c.bench_function("merge_delta_participant_added", |b| {
        b.iter(|| {
            clock += 1;
            let delta = StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: (clock % 1000) as u32 + 1,
                dot: Dot::new(2, clock),
            };
            let _ = black_box(state.merge_delta(delta));
        })
    });
}

/// Benchmark merging track updates
fn bench_merge_delta_track_updated(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let mut clock = 1u64;

    c.bench_function("merge_delta_track_updated", |b| {
        b.iter(|| {
            clock += 1;
            let delta = StateUpdate::TrackUpdated {
                track_id: 1,
                info: TrackInfo {
                    track_type: 1,
                    codec: 100,
                    bitrate_kbps: (clock % 10000) as u32,
                },
                timestamp: clock,
                actor: 2,
            };
            let _ = black_box(state.merge_delta(delta));
        })
    });
}

/// Benchmark merging subscription deltas
fn bench_merge_delta_subscription_added(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let mut clock = 1u64;

    c.bench_function("merge_delta_subscription_added", |b| {
        b.iter(|| {
            clock += 1;
            let delta = StateUpdate::SubscriptionAdded {
                track_id: (clock % 1000) as u32 + 1,
                participant_id: (clock % 100) as u32 + 1,
                dot: Dot::new(2, clock),
            };
            let _ = black_box(state.merge_delta(delta));
        })
    });
}

/// Benchmark batch delta merging
fn bench_merge_deltas_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge_deltas_batch");

    for batch_size in [1, 4, 8, 16].iter() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);
        state.create_room(1, "Benchmark".to_string(), 10000).unwrap();

        let mut clock = 1u64;

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), batch_size, |b, &size| {
            b.iter(|| {
                let mut updates = Vec::with_capacity(size);
                for _ in 0..size {
                    clock += 1;
                    updates.push(StateUpdate::ParticipantAdded {
                        room_id: 1,
                        participant_id: (clock % 1000) as u32 + 1,
                        dot: Dot::new(2, clock),
                    });
                }
                let _ = black_box(state.merge_deltas(updates));
            })
        });
    }

    group.finish();
}

/// Benchmark creating rooms
fn bench_create_room(c: &mut Criterion) {
    let config = DistributedStateConfig::with_limits(1, 50000, 100, 100);
    let state = DistributedState::new(config);

    let mut room_id = 1u32;

    c.bench_function("create_room", |b| {
        b.iter(|| {
            room_id += 1;
            let _ = black_box(state.create_room(room_id, format!("Room {}", room_id), 100));
        })
    });
}

/// Benchmark room existence check
fn bench_room_exists(c: &mut Criterion) {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Pre-create rooms
    for i in 1..=1000 {
        let _ = state.create_room(i, format!("Room {}", i), 100);
    }

    let mut room_id = 1u32;

    c.bench_function("room_exists", |b| {
        b.iter(|| {
            room_id = (room_id % 1000) + 1;
            black_box(state.room_exists(room_id))
        })
    });
}

/// Benchmark concurrent operations throughput
fn bench_concurrent_throughput(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let config = DistributedStateConfig::new(1);
    let state = Arc::new(DistributedState::new(config));
    state.create_room(1, "Concurrent".to_string(), 10000).unwrap();

    c.bench_function("concurrent_add_participant_4_threads", |b| {
        b.iter(|| {
            let mut handles = vec![];

            for thread_id in 0..4 {
                let state_clone = Arc::clone(&state);
                let handle = thread::spawn(move || {
                    for i in 0..100 {
                        let participant_id = thread_id * 1000 + i + 1;
                        let _ = state_clone.add_participant(1, participant_id);
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.join();
            }
        })
    });
}

/// Benchmark delta generation
fn bench_generate_deltas(c: &mut Criterion) {
    let dot = Dot::new(1, 100);
    let info = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2500,
    };

    c.bench_function("generate_participant_added_delta", |b| {
        b.iter(|| {
            black_box(DistributedState::generate_participant_added_delta(42, dot))
        })
    });

    c.bench_function("generate_track_updated_delta", |b| {
        b.iter(|| {
            black_box(DistributedState::generate_track_updated_delta(1, info, 100, 1))
        })
    });

    c.bench_function("generate_subscription_added_delta", |b| {
        b.iter(|| {
            black_box(DistributedState::generate_subscription_added_delta(1, 42, dot))
        })
    });
}

criterion_group!(
    benches,
    // Participant operations
    bench_add_participant,
    bench_remove_participant,
    bench_get_participants,
    // Track operations
    bench_add_track,
    bench_update_track,
    bench_get_track,
    // Subscription operations
    bench_add_subscription,
    bench_get_subscriptions_for_track,
    bench_get_subscriptions_for_participant,
    // Delta operations
    bench_merge_delta,
    bench_merge_delta_track_updated,
    bench_merge_delta_subscription_added,
    bench_merge_deltas_batch,
    // Room operations
    bench_create_room,
    bench_room_exists,
    // Concurrent operations
    bench_concurrent_throughput,
    // Delta generation
    bench_generate_deltas,
);

criterion_main!(benches);
