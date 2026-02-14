//! Benchmarks for SWIM gossip protocol.
//!
//! Target performance:
//! - Message encode/decode: < 1μs per message
//! - Membership update: < 100ns
//! - Batch send (64 messages): < 500μs
//! - Protocol cycle: < 2ms (including network RTT)

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::net::SocketAddr;

use nexus_state::gossip::{
    GossipConfig, GossipMessage, GossipTransport, MembershipList,
    StateUpdate, SwimProtocol, MAX_PIGGYBACK_UPDATES,
};
use nexus_state::types::Dot;

// =============================================================================
// Message Encode/Decode Benchmarks
// =============================================================================

fn bench_message_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encode");

    // Ping without piggyback
    group.bench_function("ping_empty", |b| {
        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 100,
            piggyback: vec![],
        };
        b.iter(|| black_box(msg.encode()))
    });

    // Ping with max piggyback
    group.bench_function("ping_max_piggyback", |b| {
        let mut piggyback = Vec::with_capacity(MAX_PIGGYBACK_UPDATES);
        for i in 0..MAX_PIGGYBACK_UPDATES {
            let dot = Dot::new(1, (i + 1) as u64);
            piggyback.push(StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: i as u32,
                dot,
            });
        }
        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 100,
            piggyback,
        };
        b.iter(|| black_box(msg.encode()))
    });

    // Ack
    group.bench_function("ack", |b| {
        let msg = GossipMessage::Ack {
            from: 2,
            incarnation: 200,
            piggyback: vec![],
        };
        b.iter(|| black_box(msg.encode()))
    });

    // PingReq
    group.bench_function("ping_req", |b| {
        let msg = GossipMessage::PingReq {
            from: 1,
            target: 5,
            target_addr: "192.168.1.1:7946".parse().unwrap(),
        };
        b.iter(|| black_box(msg.encode()))
    });

    // Suspect
    group.bench_function("suspect", |b| {
        let msg = GossipMessage::Suspect {
            actor_id: 5,
            incarnation: 50,
        };
        b.iter(|| black_box(msg.encode()))
    });

    // Dead
    group.bench_function("dead", |b| {
        let msg = GossipMessage::Dead { actor_id: 7 };
        b.iter(|| black_box(msg.encode()))
    });

    group.finish();
}

fn bench_message_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_decode");

    // Pre-encode messages
    let ping_empty = GossipMessage::Ping {
        from: 1,
        incarnation: 100,
        piggyback: vec![],
    }
    .encode();

    let mut piggyback = Vec::with_capacity(MAX_PIGGYBACK_UPDATES);
    for i in 0..MAX_PIGGYBACK_UPDATES {
        let dot = Dot::new(1, (i + 1) as u64);
        piggyback.push(StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: i as u32,
            dot,
        });
    }
    let ping_full = GossipMessage::Ping {
        from: 1,
        incarnation: 100,
        piggyback,
    }
    .encode();

    let dead = GossipMessage::Dead { actor_id: 7 }.encode();

    group.bench_function("ping_empty", |b| {
        b.iter(|| black_box(GossipMessage::decode(&ping_empty).unwrap()))
    });

    group.bench_function("ping_max_piggyback", |b| {
        b.iter(|| black_box(GossipMessage::decode(&ping_full).unwrap()))
    });

    group.bench_function("dead", |b| {
        b.iter(|| black_box(GossipMessage::decode(&dead).unwrap()))
    });

    group.finish();
}

fn bench_message_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_roundtrip");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ping_empty", |b| {
        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 100,
            piggyback: vec![],
        };
        b.iter(|| {
            let encoded = msg.encode();
            black_box(GossipMessage::decode(&encoded).unwrap())
        })
    });

    group.finish();
}

// =============================================================================
// Membership List Benchmarks
// =============================================================================

fn bench_membership_add_peer(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership");

    group.bench_function("add_peer", |b| {
        b.iter_batched(
            || MembershipList::new(0),
            |mut list| {
                let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();
                black_box(list.add_peer(1, addr).unwrap())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("add_100_peers", |b| {
        b.iter_batched(
            || MembershipList::new(0),
            |mut list| {
                for i in 1..=100u64 {
                    let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
                    list.add_peer(i, addr).unwrap();
                }
                black_box(list.peer_count())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_membership_find_peer(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership");

    // Setup: create list with 100 peers
    let mut list = MembershipList::new(0);
    for i in 1..=100u64 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
        list.add_peer(i, addr).unwrap();
    }

    group.bench_function("find_peer_first", |b| {
        b.iter(|| black_box(list.find_peer(1)))
    });

    group.bench_function("find_peer_middle", |b| {
        b.iter(|| black_box(list.find_peer(50)))
    });

    group.bench_function("find_peer_last", |b| {
        b.iter(|| black_box(list.find_peer(100)))
    });

    group.bench_function("find_peer_missing", |b| {
        b.iter(|| black_box(list.find_peer(200)))
    });

    group.finish();
}

fn bench_membership_update_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership");

    group.bench_function("update_state", |b| {
        b.iter_batched(
            || {
                let mut list = MembershipList::new(0);
                let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();
                list.add_peer(1, addr).unwrap();
                list
            },
            |mut list| {
                list.mark_suspect(1, 0).unwrap();
                black_box(list.find_peer(1).unwrap().state())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_membership_get_random_peer(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership");

    // Setup: create list with 100 peers
    let mut list = MembershipList::new(0);
    for i in 1..=100u64 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
        list.add_peer(i, addr).unwrap();
    }

    group.bench_function("get_random_alive_peer", |b| {
        b.iter(|| black_box(list.get_random_alive_peer()))
    });

    group.bench_function("get_random_alive_peers_3", |b| {
        b.iter(|| black_box(list.get_random_alive_peers(3, 0)))
    });

    group.bench_function("get_alive_peers", |b| {
        b.iter(|| black_box(list.get_alive_peers()))
    });

    group.finish();
}

fn bench_membership_check_timeouts(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership");

    group.bench_function("check_timeouts_100_peers", |b| {
        b.iter_batched(
            || {
                let mut list = MembershipList::new(0);
                for i in 1..=100u64 {
                    let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
                    list.add_peer(i, addr).unwrap();
                    // Mark half as suspect
                    if i % 2 == 0 {
                        list.mark_suspect(i, 0).unwrap();
                    }
                }
                list
            },
            |mut list| {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                black_box(list.check_timeouts(now_ns))
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// State Update Benchmarks
// =============================================================================

fn bench_state_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_update");

    let dot = Dot::new(1, 100);
    let update = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 42,
        dot,
    };

    group.bench_function("encode", |b| {
        let mut buffer = [0u8; 64];
        b.iter(|| black_box(update.encode(&mut buffer)))
    });

    group.bench_function("decode", |b| {
        let mut buffer = [0u8; 64];
        let len = update.encode(&mut buffer);
        b.iter(|| black_box(StateUpdate::decode(&buffer[..len]).unwrap()))
    });

    group.finish();
}

// =============================================================================
// Protocol Benchmarks
// =============================================================================

fn bench_protocol_probe_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol");

    group.bench_function("probe_cycle_empty", |b| {
        b.iter_batched(
            || {
                let config = GossipConfig::for_testing();
                SwimProtocol::new(1, "127.0.0.1:0".parse().unwrap(), config).unwrap()
            },
            |mut protocol| black_box(protocol.run_probe_cycle().unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("probe_cycle_with_peers", |b| {
        b.iter_batched(
            || {
                let config = GossipConfig::for_testing();
                let mut protocol =
                    SwimProtocol::new(1, "127.0.0.1:0".parse().unwrap(), config).unwrap();

                // Add some fake peers (won't actually respond)
                for i in 2..10u64 {
                    let addr: SocketAddr = format!("127.0.0.1:{}", 50000 + i).parse().unwrap();
                    protocol.membership_mut().add_peer(i, addr).unwrap();
                }

                protocol
            },
            |mut protocol| black_box(protocol.run_probe_cycle().unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_protocol_broadcast_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol");

    let config = GossipConfig::for_testing();
    let mut protocol = SwimProtocol::new(1, "127.0.0.1:0".parse().unwrap(), config).unwrap();

    let dot = Dot::new(1, 1);
    let update = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 42,
        dot,
    };

    group.bench_function("broadcast_state_update", |b| {
        b.iter(|| {
            protocol.broadcast_state_update(update.clone());
            black_box(())
        })
    });

    group.finish();
}

// =============================================================================
// Transport Benchmarks (localhost only)
// =============================================================================

fn bench_transport_send(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport");

    let mut transport = GossipTransport::new("127.0.0.1:0".parse().unwrap()).unwrap();
    let dest: SocketAddr = "127.0.0.1:59999".parse().unwrap(); // Won't be received

    let msg = GossipMessage::Ping {
        from: 1,
        incarnation: 100,
        piggyback: vec![],
    };

    group.bench_function("send_single", |b| {
        b.iter(|| {
            // Ignore errors (destination doesn't exist)
            let _ = transport.send(&msg, dest);
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    message_benches,
    bench_message_encode,
    bench_message_decode,
    bench_message_roundtrip,
);

criterion_group!(
    membership_benches,
    bench_membership_add_peer,
    bench_membership_find_peer,
    bench_membership_update_state,
    bench_membership_get_random_peer,
    bench_membership_check_timeouts,
);

criterion_group!(state_update_benches, bench_state_update,);

criterion_group!(
    protocol_benches,
    bench_protocol_probe_cycle,
    bench_protocol_broadcast_update,
);

criterion_group!(transport_benches, bench_transport_send,);

criterion_main!(
    message_benches,
    membership_benches,
    state_update_benches,
    protocol_benches,
    transport_benches,
);
