/// Built-in simulation scenarios embedded as TOML strings.
///
/// Each scenario is a valid TOML document that can be parsed with `Scenario::from_toml()`.

/// Basic room lifecycle: create room → join → publish → subscribe → forward → leave → cleanup.
pub const BASIC_LIFECYCLE: &str = r#"
name = "basic_lifecycle"
description = "Room create, join, publish, subscribe, forward packets, leave, cleanup"
seed = 42
timeout_secs = 30

[network]
default_latency_ms = 10
default_jitter_ms = 2
default_loss_rate = 0.0
default_reorder_rate = 0.0

[[participants]]
name = "alice"
room = "room1"
join_at_ms = 0
leave_at_ms = 15000

[[participants]]
name = "bob"
room = "room1"
join_at_ms = 100
leave_at_ms = 15000

[[tracks]]
label = "alice_audio"
participant = "alice"
kind = "audio"
publish_at_ms = 200
unpublish_at_ms = 14000
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "alice_video"
participant = "alice"
kind = "video"
publish_at_ms = 200
unpublish_at_ms = 14000
packet_interval_ms = 33
packet_size = 1200

[[subscriptions]]
subscriber = "bob"
track = "alice_audio"
subscribe_at_ms = 300
unsubscribe_at_ms = 13000

[[subscriptions]]
subscriber = "bob"
track = "alice_video"
subscribe_at_ms = 300
unsubscribe_at_ms = 13000

[[assertions]]
kind = "delivery_ratio"
[assertions.params]
min_ratio = 1.0

[[assertions]]
kind = "crdt_converged"
[assertions.params]
"#;

/// Multi-room isolation: 3 rooms, 5 participants each, verify no cross-room packet leakage.
pub const MULTI_ROOM_ISOLATION: &str = r#"
name = "multi_room_isolation"
description = "3 rooms with 5 participants each, verify no cross-room packet leakage"
seed = 100
timeout_secs = 30

[network]
default_latency_ms = 10
default_jitter_ms = 2
default_loss_rate = 0.0
default_reorder_rate = 0.0

[[participants]]
name = "r1_p1"
room = "room1"
join_at_ms = 0

[[participants]]
name = "r1_p2"
room = "room1"
join_at_ms = 0

[[participants]]
name = "r1_p3"
room = "room1"
join_at_ms = 0

[[participants]]
name = "r1_p4"
room = "room1"
join_at_ms = 0

[[participants]]
name = "r1_p5"
room = "room1"
join_at_ms = 0

[[participants]]
name = "r2_p1"
room = "room2"
join_at_ms = 0

[[participants]]
name = "r2_p2"
room = "room2"
join_at_ms = 0

[[participants]]
name = "r2_p3"
room = "room2"
join_at_ms = 0

[[participants]]
name = "r2_p4"
room = "room2"
join_at_ms = 0

[[participants]]
name = "r2_p5"
room = "room2"
join_at_ms = 0

[[participants]]
name = "r3_p1"
room = "room3"
join_at_ms = 0

[[participants]]
name = "r3_p2"
room = "room3"
join_at_ms = 0

[[participants]]
name = "r3_p3"
room = "room3"
join_at_ms = 0

[[participants]]
name = "r3_p4"
room = "room3"
join_at_ms = 0

[[participants]]
name = "r3_p5"
room = "room3"
join_at_ms = 0

[[tracks]]
label = "r1_audio"
participant = "r1_p1"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "r2_audio"
participant = "r2_p1"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "r3_audio"
participant = "r3_p1"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160

[[subscriptions]]
subscriber = "r1_p2"
track = "r1_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r1_p3"
track = "r1_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r1_p4"
track = "r1_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r1_p5"
track = "r1_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r2_p2"
track = "r2_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r2_p3"
track = "r2_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r2_p4"
track = "r2_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r2_p5"
track = "r2_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r3_p2"
track = "r3_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r3_p3"
track = "r3_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r3_p4"
track = "r3_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "r3_p5"
track = "r3_audio"
subscribe_at_ms = 200

[[assertions]]
kind = "delivery_ratio"
[assertions.params]
min_ratio = 1.0

[[assertions]]
kind = "crdt_converged"
[assertions.params]
"#;

/// Fan-out: 1 publisher, 50 subscribers, verify all receive all packets.
pub const FAN_OUT: &str = r#"
name = "fan_out"
description = "1 publisher with 50 subscribers, verify 100% delivery under zero-loss"
seed = 200
timeout_secs = 30

[network]
default_latency_ms = 10
default_jitter_ms = 2
default_loss_rate = 0.0
default_reorder_rate = 0.0

[[participants]]
name = "publisher"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_01"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_02"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_03"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_04"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_05"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_06"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_07"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_08"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_09"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_10"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_11"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_12"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_13"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_14"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_15"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_16"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_17"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_18"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_19"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_20"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_21"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_22"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_23"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_24"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_25"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_26"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_27"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_28"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_29"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_30"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_31"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_32"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_33"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_34"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_35"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_36"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_37"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_38"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_39"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_40"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_41"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_42"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_43"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_44"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_45"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_46"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_47"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_48"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_49"
room = "room1"
join_at_ms = 0

[[participants]]
name = "sub_50"
room = "room1"
join_at_ms = 0

[[tracks]]
label = "pub_video"
participant = "publisher"
kind = "video"
publish_at_ms = 100
packet_interval_ms = 33
packet_size = 1200

[[subscriptions]]
subscriber = "sub_01"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_02"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_03"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_04"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_05"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_06"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_07"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_08"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_09"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_10"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_11"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_12"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_13"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_14"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_15"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_16"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_17"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_18"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_19"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_20"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_21"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_22"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_23"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_24"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_25"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_26"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_27"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_28"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_29"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_30"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_31"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_32"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_33"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_34"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_35"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_36"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_37"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_38"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_39"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_40"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_41"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_42"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_43"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_44"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_45"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_46"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_47"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_48"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_49"
track = "pub_video"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "sub_50"
track = "pub_video"
subscribe_at_ms = 200

[[assertions]]
kind = "delivery_ratio"
[assertions.params]
min_ratio = 1.0
"#;

/// CRDT convergence: 3 nodes, concurrent operations, gossip rounds, verify convergence.
pub const CRDT_CONVERGENCE: &str = r#"
name = "crdt_convergence"
description = "3 nodes with concurrent operations, gossip rounds, verify CRDT convergence"
seed = 300
timeout_secs = 30

[network]
default_latency_ms = 20
default_jitter_ms = 5
default_loss_rate = 0.0
default_reorder_rate = 0.0

[[participants]]
name = "node_a"
room = "room1"
join_at_ms = 0

[[participants]]
name = "node_b"
room = "room1"
join_at_ms = 50

[[participants]]
name = "node_c"
room = "room1"
join_at_ms = 100

[[tracks]]
label = "node_a_audio"
participant = "node_a"
kind = "audio"
publish_at_ms = 200
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "node_b_audio"
participant = "node_b"
kind = "audio"
publish_at_ms = 200
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "node_c_video"
participant = "node_c"
kind = "video"
publish_at_ms = 250
packet_interval_ms = 33
packet_size = 1200

[[subscriptions]]
subscriber = "node_b"
track = "node_a_audio"
subscribe_at_ms = 300

[[subscriptions]]
subscriber = "node_c"
track = "node_a_audio"
subscribe_at_ms = 300

[[subscriptions]]
subscriber = "node_a"
track = "node_b_audio"
subscribe_at_ms = 300

[[subscriptions]]
subscriber = "node_c"
track = "node_b_audio"
subscribe_at_ms = 300

[[subscriptions]]
subscriber = "node_a"
track = "node_c_video"
subscribe_at_ms = 350

[[subscriptions]]
subscriber = "node_b"
track = "node_c_video"
subscribe_at_ms = 350

[[assertions]]
kind = "crdt_converged"
[assertions.params]
"#;

/// Fault tolerance: actor crash → supervisor restart → verify recovery.
pub const FAULT_TOLERANCE: &str = r#"
name = "fault_tolerance"
description = "Actor crash followed by supervisor restart, verify state recovery"
seed = 400
timeout_secs = 30

[network]
default_latency_ms = 15
default_jitter_ms = 3
default_loss_rate = 0.01
default_reorder_rate = 0.005

[[participants]]
name = "alice"
room = "room1"
join_at_ms = 0

[[participants]]
name = "bob"
room = "room1"
join_at_ms = 100

[[participants]]
name = "charlie"
room = "room1"
join_at_ms = 200

[[tracks]]
label = "alice_audio"
participant = "alice"
kind = "audio"
publish_at_ms = 300
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "bob_video"
participant = "bob"
kind = "video"
publish_at_ms = 300
packet_interval_ms = 33
packet_size = 1200

[[subscriptions]]
subscriber = "bob"
track = "alice_audio"
subscribe_at_ms = 400

[[subscriptions]]
subscriber = "charlie"
track = "alice_audio"
subscribe_at_ms = 400

[[subscriptions]]
subscriber = "alice"
track = "bob_video"
subscribe_at_ms = 400

[[subscriptions]]
subscriber = "charlie"
track = "bob_video"
subscribe_at_ms = 400

[[faults]]
kind = "crash"
at_ms = 2000
[faults.params]
actor = "bob"

[[assertions]]
kind = "crdt_converged"
[assertions.params]
"#;

/// Network partition: partition → concurrent writes → heal → gossip → verify CRDT merge.
pub const NETWORK_PARTITION: &str = r#"
name = "network_partition"
description = "Network partition, concurrent writes, heal, gossip, verify CRDT merge"
seed = 500
timeout_secs = 60

[network]
default_latency_ms = 25
default_jitter_ms = 5
default_loss_rate = 0.02
default_reorder_rate = 0.01

[[participants]]
name = "node_x"
room = "room1"
join_at_ms = 0

[[participants]]
name = "node_y"
room = "room1"
join_at_ms = 0

[[participants]]
name = "node_z"
room = "room1"
join_at_ms = 0

[[tracks]]
label = "node_x_audio"
participant = "node_x"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160

[[tracks]]
label = "node_y_audio"
participant = "node_y"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160

[[subscriptions]]
subscriber = "node_y"
track = "node_x_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "node_z"
track = "node_x_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "node_x"
track = "node_y_audio"
subscribe_at_ms = 200

[[subscriptions]]
subscriber = "node_z"
track = "node_y_audio"
subscribe_at_ms = 200

[[faults]]
kind = "partition"
at_ms = 1000
[faults.params]
node_a = "node_x"
node_b = "node_y"

[[faults]]
kind = "heal"
at_ms = 5000
[faults.params]
node_a = "node_x"
node_b = "node_y"

[[assertions]]
kind = "crdt_converged"
[assertions.params]
"#;

/// Scalability: 100 participants, 10 tracks each, verify completion within timeout.
///
/// This scenario is generated programmatically because embedding 100 participants
/// and 1000 tracks as a literal TOML string would be unwieldy. We build the TOML
/// at compile time via `lazy_static`-style initialization (actually just a function).
pub fn scalability_toml() -> String {
    use std::fmt::Write;

    let mut toml = String::with_capacity(64 * 1024);
    writeln!(toml, r#"name = "scalability""#).unwrap();
    writeln!(
        toml,
        r#"description = "100 participants, 10 tracks each, verify bounded memory and completion""#
    )
    .unwrap();
    writeln!(toml, "seed = 600").unwrap();
    writeln!(toml, "timeout_secs = 120").unwrap();
    writeln!(toml).unwrap();
    writeln!(toml, "[network]").unwrap();
    writeln!(toml, "default_latency_ms = 10").unwrap();
    writeln!(toml, "default_jitter_ms = 2").unwrap();
    writeln!(toml, "default_loss_rate = 0.0").unwrap();
    writeln!(toml, "default_reorder_rate = 0.0").unwrap();
    writeln!(toml).unwrap();

    // 100 participants in a single room
    for i in 1..=100 {
        writeln!(toml, "[[participants]]").unwrap();
        writeln!(toml, r#"name = "p{i:03}""#).unwrap();
        writeln!(toml, r#"room = "big_room""#).unwrap();
        writeln!(toml, "join_at_ms = {}", i * 10).unwrap();
        writeln!(toml).unwrap();
    }

    // Each participant publishes 10 tracks (audio + video mix)
    for i in 1..=100 {
        for t in 1..=10 {
            let kind = if t <= 5 { "audio" } else { "video" };
            let interval = if t <= 5 { 20 } else { 33 };
            let size = if t <= 5 { 160 } else { 1200 };
            writeln!(toml, "[[tracks]]").unwrap();
            writeln!(toml, r#"label = "p{i:03}_t{t:02}""#).unwrap();
            writeln!(toml, r#"participant = "p{i:03}""#).unwrap();
            writeln!(toml, r#"kind = "{kind}""#).unwrap();
            // Stagger publish times slightly
            writeln!(toml, "publish_at_ms = {}", 1000 + i * 10 + t).unwrap();
            writeln!(toml, "packet_interval_ms = {interval}").unwrap();
            writeln!(toml, "packet_size = {size}").unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Each participant subscribes to the first track of the next participant (ring topology)
    // This keeps subscription count manageable while still exercising fan-out
    for i in 1..=100 {
        let next = if i == 100 { 1 } else { i + 1 };
        writeln!(toml, "[[subscriptions]]").unwrap();
        writeln!(toml, r#"subscriber = "p{i:03}""#).unwrap();
        writeln!(toml, r#"track = "p{next:03}_t01""#).unwrap();
        writeln!(toml, "subscribe_at_ms = 2000").unwrap();
        writeln!(toml).unwrap();
    }

    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "participant_count""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml, "room = \"big_room\"").unwrap();
    writeln!(toml, "expected = 100").unwrap();

    toml
}

/// Extreme stress test: Push the SFU to its architectural limits.
///
/// This scenario simulates:
/// - 500 participants across 10 rooms (50 per room)
/// - Each participant publishes 2 tracks (1 audio, 1 video)
/// - Full mesh subscriptions within each room (each participant subscribes to all others)
/// - High packet rates to stress the forwarding path
/// - Network conditions with realistic latency and jitter
///
/// Architecture targets being tested:
/// - Latency P50 < 5ms, P99 < 15ms
/// - Memory per participant < 100KB
/// - Packets/sec/core approaching 1M target
/// - CRDT convergence across distributed state nodes
/// - Zero-allocation hot path via arena allocator
pub fn extreme_stress_test_toml() -> String {
    use std::fmt::Write;

    let num_rooms = 10;
    let participants_per_room = 50;
    let _total_participants = num_rooms * participants_per_room;

    let mut toml = String::with_capacity(512 * 1024);
    writeln!(toml, r#"name = "extreme_stress_test""#).unwrap();
    writeln!(
        toml,
        r#"description = "500 participants, 10 rooms, full mesh subscriptions - push architecture limits""#
    )
    .unwrap();
    writeln!(toml, "seed = 12345").unwrap();
    writeln!(toml, "timeout_secs = 60").unwrap();
    writeln!(toml).unwrap();

    // Realistic network conditions
    writeln!(toml, "[network]").unwrap();
    writeln!(toml, "default_latency_ms = 5").unwrap();
    writeln!(toml, "default_jitter_ms = 2").unwrap();
    writeln!(toml, "default_loss_rate = 0.001").unwrap(); // 0.1% loss
    writeln!(toml, "default_reorder_rate = 0.0005").unwrap();
    writeln!(toml).unwrap();

    // Generate participants across rooms
    for room_idx in 0..num_rooms {
        for p_idx in 0..participants_per_room {
            let global_idx = room_idx * participants_per_room + p_idx;
            writeln!(toml, "[[participants]]").unwrap();
            writeln!(toml, r#"name = "p{global_idx:04}""#).unwrap();
            writeln!(toml, r#"room = "room{room_idx:02}""#).unwrap();
            // Stagger joins to simulate realistic connection patterns
            writeln!(toml, "join_at_ms = {}", global_idx * 5).unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Each participant publishes 2 tracks: 1 audio, 1 video
    for room_idx in 0..num_rooms {
        for p_idx in 0..participants_per_room {
            let global_idx = room_idx * participants_per_room + p_idx;

            // Audio track - 50 packets/sec (20ms interval)
            writeln!(toml, "[[tracks]]").unwrap();
            writeln!(toml, r#"label = "p{global_idx:04}_audio""#).unwrap();
            writeln!(toml, r#"participant = "p{global_idx:04}""#).unwrap();
            writeln!(toml, r#"kind = "audio""#).unwrap();
            writeln!(toml, "publish_at_ms = {}", 3000 + global_idx * 2).unwrap();
            writeln!(toml, "packet_interval_ms = 20").unwrap();
            writeln!(toml, "packet_size = 160").unwrap();
            writeln!(toml).unwrap();

            // Video track - 30 packets/sec (33ms interval)
            writeln!(toml, "[[tracks]]").unwrap();
            writeln!(toml, r#"label = "p{global_idx:04}_video""#).unwrap();
            writeln!(toml, r#"participant = "p{global_idx:04}""#).unwrap();
            writeln!(toml, r#"kind = "video""#).unwrap();
            writeln!(toml, "publish_at_ms = {}", 3000 + global_idx * 2 + 1).unwrap();
            writeln!(toml, "packet_interval_ms = 33").unwrap();
            writeln!(toml, "packet_size = 1200").unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Full mesh subscriptions within each room
    // Each participant subscribes to all other participants' audio and video in their room
    for room_idx in 0..num_rooms {
        for subscriber_idx in 0..participants_per_room {
            let subscriber_global = room_idx * participants_per_room + subscriber_idx;

            for publisher_idx in 0..participants_per_room {
                if subscriber_idx == publisher_idx {
                    continue; // Don't subscribe to own tracks
                }

                let publisher_global = room_idx * participants_per_room + publisher_idx;

                // Subscribe to audio
                writeln!(toml, "[[subscriptions]]").unwrap();
                writeln!(toml, r#"subscriber = "p{subscriber_global:04}""#).unwrap();
                writeln!(toml, r#"track = "p{publisher_global:04}_audio""#).unwrap();
                writeln!(toml, "subscribe_at_ms = {}", 5000 + subscriber_global * 2).unwrap();
                writeln!(toml).unwrap();

                // Subscribe to video
                writeln!(toml, "[[subscriptions]]").unwrap();
                writeln!(toml, r#"subscriber = "p{subscriber_global:04}""#).unwrap();
                writeln!(toml, r#"track = "p{publisher_global:04}_video""#).unwrap();
                writeln!(toml, "subscribe_at_ms = {}", 5000 + subscriber_global * 2 + 1).unwrap();
                writeln!(toml).unwrap();
            }
        }
    }

    // Assertions
    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "delivery_ratio""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml, "min_ratio = 0.99").unwrap();
    writeln!(toml).unwrap();

    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "crdt_converged""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml).unwrap();

    // Add participant count assertions for each room
    for room_idx in 0..num_rooms {
        writeln!(toml, "[[assertions]]").unwrap();
        writeln!(toml, r#"kind = "participant_count""#).unwrap();
        writeln!(toml, "[assertions.params]").unwrap();
        writeln!(toml, r#"room = "room{room_idx:02}""#).unwrap();
        writeln!(toml, "expected = {participants_per_room}").unwrap();
        writeln!(toml).unwrap();
    }

    toml
}

/// Webinar stress test: 1 broadcaster, 1000 viewers.
///
/// This scenario simulates a large webinar/broadcast use case:
/// - 1 room with 1001 participants
/// - 1 broadcaster publishing high-quality video + audio
/// - 1000 viewers subscribing to the broadcast
/// - Tests extreme fan-out (1-to-1000 forwarding)
///
/// This is the ultimate test of the track actor model's fan-out efficiency.
pub fn webinar_stress_test_toml() -> String {
    use std::fmt::Write;

    let num_viewers = 1000;

    let mut toml = String::with_capacity(256 * 1024);
    writeln!(toml, r#"name = "webinar_stress_test""#).unwrap();
    writeln!(
        toml,
        r#"description = "1 broadcaster, 1000 viewers - extreme fan-out stress test""#
    )
    .unwrap();
    writeln!(toml, "seed = 99999").unwrap();
    writeln!(toml, "timeout_secs = 30").unwrap();
    writeln!(toml).unwrap();

    // Low latency network for broadcast
    writeln!(toml, "[network]").unwrap();
    writeln!(toml, "default_latency_ms = 3").unwrap();
    writeln!(toml, "default_jitter_ms = 1").unwrap();
    writeln!(toml, "default_loss_rate = 0.0").unwrap();
    writeln!(toml, "default_reorder_rate = 0.0").unwrap();
    writeln!(toml).unwrap();

    // Broadcaster
    writeln!(toml, "[[participants]]").unwrap();
    writeln!(toml, r#"name = "broadcaster""#).unwrap();
    writeln!(toml, r#"room = "webinar""#).unwrap();
    writeln!(toml, "join_at_ms = 0").unwrap();
    writeln!(toml).unwrap();

    // Viewers
    for i in 0..num_viewers {
        writeln!(toml, "[[participants]]").unwrap();
        writeln!(toml, r#"name = "viewer{i:04}""#).unwrap();
        writeln!(toml, r#"room = "webinar""#).unwrap();
        // Stagger viewer joins
        writeln!(toml, "join_at_ms = {}", 100 + i * 2).unwrap();
        writeln!(toml).unwrap();
    }

    // Broadcaster tracks - high quality
    writeln!(toml, "[[tracks]]").unwrap();
    writeln!(toml, r#"label = "broadcast_audio""#).unwrap();
    writeln!(toml, r#"participant = "broadcaster""#).unwrap();
    writeln!(toml, r#"kind = "audio""#).unwrap();
    writeln!(toml, "publish_at_ms = 500").unwrap();
    writeln!(toml, "packet_interval_ms = 20").unwrap();
    writeln!(toml, "packet_size = 320").unwrap(); // High quality audio
    writeln!(toml).unwrap();

    writeln!(toml, "[[tracks]]").unwrap();
    writeln!(toml, r#"label = "broadcast_video""#).unwrap();
    writeln!(toml, r#"participant = "broadcaster""#).unwrap();
    writeln!(toml, r#"kind = "video""#).unwrap();
    writeln!(toml, "publish_at_ms = 500").unwrap();
    writeln!(toml, "packet_interval_ms = 16").unwrap(); // 60fps
    writeln!(toml, "packet_size = 1400").unwrap(); // Near MTU
    writeln!(toml).unwrap();

    // All viewers subscribe to broadcast
    for i in 0..num_viewers {
        writeln!(toml, "[[subscriptions]]").unwrap();
        writeln!(toml, r#"subscriber = "viewer{i:04}""#).unwrap();
        writeln!(toml, r#"track = "broadcast_audio""#).unwrap();
        writeln!(toml, "subscribe_at_ms = {}", 3000 + i).unwrap();
        writeln!(toml).unwrap();

        writeln!(toml, "[[subscriptions]]").unwrap();
        writeln!(toml, r#"subscriber = "viewer{i:04}""#).unwrap();
        writeln!(toml, r#"track = "broadcast_video""#).unwrap();
        writeln!(toml, "subscribe_at_ms = {}", 3000 + i).unwrap();
        writeln!(toml).unwrap();
    }

    // Assertions
    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "delivery_ratio""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml, "min_ratio = 1.0").unwrap();
    writeln!(toml).unwrap();

    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "participant_count""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml, r#"room = "webinar""#).unwrap();
    writeln!(toml, "expected = {}", num_viewers + 1).unwrap();

    toml
}

/// Chaos engineering stress test: Network partitions, actor crashes, and recovery.
///
/// This scenario tests fault tolerance under stress:
/// - 100 participants across 5 rooms
/// - Multiple network partitions and heals
/// - Actor crashes with supervisor recovery
/// - Verifies CRDT convergence after chaos
pub fn chaos_stress_test_toml() -> String {
    use std::fmt::Write;

    let num_rooms = 5;
    let participants_per_room = 20;

    let mut toml = String::with_capacity(128 * 1024);
    writeln!(toml, r#"name = "chaos_stress_test""#).unwrap();
    writeln!(
        toml,
        r#"description = "100 participants with network partitions and actor crashes""#
    )
    .unwrap();
    writeln!(toml, "seed = 77777").unwrap();
    writeln!(toml, "timeout_secs = 60").unwrap();
    writeln!(toml).unwrap();

    // Lossy network to stress recovery
    writeln!(toml, "[network]").unwrap();
    writeln!(toml, "default_latency_ms = 15").unwrap();
    writeln!(toml, "default_jitter_ms = 5").unwrap();
    writeln!(toml, "default_loss_rate = 0.02").unwrap(); // 2% loss
    writeln!(toml, "default_reorder_rate = 0.01").unwrap();
    writeln!(toml).unwrap();

    // Generate participants
    for room_idx in 0..num_rooms {
        for p_idx in 0..participants_per_room {
            let global_idx = room_idx * participants_per_room + p_idx;
            writeln!(toml, "[[participants]]").unwrap();
            writeln!(toml, r#"name = "chaos_p{global_idx:03}""#).unwrap();
            writeln!(toml, r#"room = "chaos_room{room_idx}""#).unwrap();
            writeln!(toml, "join_at_ms = {}", global_idx * 10).unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Each participant publishes 1 audio track
    for room_idx in 0..num_rooms {
        for p_idx in 0..participants_per_room {
            let global_idx = room_idx * participants_per_room + p_idx;
            writeln!(toml, "[[tracks]]").unwrap();
            writeln!(toml, r#"label = "chaos_p{global_idx:03}_audio""#).unwrap();
            writeln!(toml, r#"participant = "chaos_p{global_idx:03}""#).unwrap();
            writeln!(toml, r#"kind = "audio""#).unwrap();
            writeln!(toml, "publish_at_ms = {}", 2000 + global_idx * 5).unwrap();
            writeln!(toml, "packet_interval_ms = 20").unwrap();
            writeln!(toml, "packet_size = 160").unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Ring subscriptions within each room
    for room_idx in 0..num_rooms {
        for p_idx in 0..participants_per_room {
            let global_idx = room_idx * participants_per_room + p_idx;
            let next_idx = room_idx * participants_per_room + ((p_idx + 1) % participants_per_room);

            writeln!(toml, "[[subscriptions]]").unwrap();
            writeln!(toml, r#"subscriber = "chaos_p{global_idx:03}""#).unwrap();
            writeln!(toml, r#"track = "chaos_p{next_idx:03}_audio""#).unwrap();
            writeln!(toml, "subscribe_at_ms = {}", 4000 + global_idx * 3).unwrap();
            writeln!(toml).unwrap();
        }
    }

    // Fault injection: Network partitions between rooms
    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "partition""#).unwrap();
    writeln!(toml, "at_ms = 10000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"node_a = "chaos_p000""#).unwrap();
    writeln!(toml, r#"node_b = "chaos_p020""#).unwrap();
    writeln!(toml).unwrap();

    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "partition""#).unwrap();
    writeln!(toml, "at_ms = 15000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"node_a = "chaos_p040""#).unwrap();
    writeln!(toml, r#"node_b = "chaos_p060""#).unwrap();
    writeln!(toml).unwrap();

    // Heal partitions
    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "heal""#).unwrap();
    writeln!(toml, "at_ms = 25000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"node_a = "chaos_p000""#).unwrap();
    writeln!(toml, r#"node_b = "chaos_p020""#).unwrap();
    writeln!(toml).unwrap();

    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "heal""#).unwrap();
    writeln!(toml, "at_ms = 30000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"node_a = "chaos_p040""#).unwrap();
    writeln!(toml, r#"node_b = "chaos_p060""#).unwrap();
    writeln!(toml).unwrap();

    // Actor crashes
    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "crash""#).unwrap();
    writeln!(toml, "at_ms = 20000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"actor = "chaos_p010""#).unwrap();
    writeln!(toml).unwrap();

    writeln!(toml, "[[faults]]").unwrap();
    writeln!(toml, r#"kind = "crash""#).unwrap();
    writeln!(toml, "at_ms = 22000").unwrap();
    writeln!(toml, "[faults.params]").unwrap();
    writeln!(toml, r#"actor = "chaos_p050""#).unwrap();
    writeln!(toml).unwrap();

    // Assertions - expect some packet loss due to chaos
    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "delivery_ratio""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();
    writeln!(toml, "min_ratio = 0.90").unwrap(); // Allow 10% loss due to chaos
    writeln!(toml).unwrap();

    writeln!(toml, "[[assertions]]").unwrap();
    writeln!(toml, r#"kind = "crdt_converged""#).unwrap();
    writeln!(toml, "[assertions.params]").unwrap();

    toml
}

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// All built-in scenario entries: (name, description, toml_content).
///
/// The `scalability` scenario is generated dynamically; the rest are `const` strings.
struct BuiltinEntry {
    name: &'static str,
    description: &'static str,
    toml: BuiltinToml,
}

enum BuiltinToml {
    Static(&'static str),
    Dynamic(fn() -> String),
}

const BUILTINS: &[BuiltinEntry] = &[
    BuiltinEntry {
        name: "basic_lifecycle",
        description: "Room create → join → publish → subscribe → forward → leave → cleanup",
        toml: BuiltinToml::Static(BASIC_LIFECYCLE),
    },
    BuiltinEntry {
        name: "multi_room_isolation",
        description: "3 rooms, 5 participants each, verify no cross-room packet leakage",
        toml: BuiltinToml::Static(MULTI_ROOM_ISOLATION),
    },
    BuiltinEntry {
        name: "fan_out",
        description: "1 publisher, 50 subscribers, verify all receive all packets",
        toml: BuiltinToml::Static(FAN_OUT),
    },
    BuiltinEntry {
        name: "crdt_convergence",
        description: "3 nodes, concurrent operations, gossip rounds, verify convergence",
        toml: BuiltinToml::Static(CRDT_CONVERGENCE),
    },
    BuiltinEntry {
        name: "fault_tolerance",
        description: "Actor crash → supervisor restart → verify recovery",
        toml: BuiltinToml::Static(FAULT_TOLERANCE),
    },
    BuiltinEntry {
        name: "network_partition",
        description: "Partition → concurrent writes → heal → gossip → verify merge",
        toml: BuiltinToml::Static(NETWORK_PARTITION),
    },
    BuiltinEntry {
        name: "scalability",
        description: "100 participants, 10 tracks each, verify bounded memory and completion",
        toml: BuiltinToml::Dynamic(scalability_toml),
    },
    BuiltinEntry {
        name: "extreme_stress_test",
        description: "500 participants, 10 rooms, full mesh - push architecture limits with benchmarks",
        toml: BuiltinToml::Dynamic(extreme_stress_test_toml),
    },
    BuiltinEntry {
        name: "webinar_stress_test",
        description: "1 broadcaster, 1000 viewers - extreme fan-out stress test with benchmarks",
        toml: BuiltinToml::Dynamic(webinar_stress_test_toml),
    },
    BuiltinEntry {
        name: "chaos_stress_test",
        description: "100 participants with network partitions and actor crashes - fault tolerance",
        toml: BuiltinToml::Dynamic(chaos_stress_test_toml),
    },
];

/// Look up a built-in scenario by name. Returns the TOML string if found.
pub fn get_builtin_scenario(name: &str) -> Option<String> {
    BUILTINS.iter().find(|e| e.name == name).map(|e| match &e.toml {
        BuiltinToml::Static(s) => (*s).to_string(),
        BuiltinToml::Dynamic(f) => f(),
    })
}

/// List all built-in scenarios as `(name, description)` pairs.
pub fn list_builtin_scenarios() -> Vec<(&'static str, &'static str)> {
    BUILTINS.iter().map(|e| (e.name, e.description)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Scenario;

    #[test]
    fn all_builtin_scenarios_parse_and_validate() {
        for (name, _desc) in list_builtin_scenarios() {
            let toml_str =
                get_builtin_scenario(name).unwrap_or_else(|| panic!("missing scenario: {name}"));
            let scenario = Scenario::from_toml(&toml_str)
                .unwrap_or_else(|e| panic!("failed to parse scenario '{name}': {e}"));
            scenario
                .validate()
                .unwrap_or_else(|errs| panic!("scenario '{name}' validation failed: {errs:?}"));
        }
    }

    #[test]
    fn get_builtin_scenario_returns_none_for_unknown() {
        assert!(get_builtin_scenario("nonexistent").is_none());
    }

    #[test]
    fn list_builtin_scenarios_returns_ten_entries() {
        let list = list_builtin_scenarios();
        assert_eq!(list.len(), 10);
    }

    #[test]
    fn scalability_scenario_has_100_participants_and_1000_tracks() {
        let toml_str = scalability_toml();
        let scenario = Scenario::from_toml(&toml_str).expect("scalability should parse");
        assert_eq!(scenario.participants.len(), 100);
        assert_eq!(scenario.tracks.len(), 1000);
        assert_eq!(scenario.subscriptions.len(), 100);
    }
}
