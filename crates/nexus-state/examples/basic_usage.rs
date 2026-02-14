//! Basic usage examples for nexus-state CRDTs
//!
//! This example demonstrates:
//! - Creating each CRDT type
//! - Performing operations (add, remove, increment, set)
//! - Merging states from multiple nodes
//! - Handling capacity errors
//! - Verifying CRDT properties

use nexus_state::crdt::{GCounter, LWWReg, Orswot};
use nexus_state::error::CrdtError;
use nexus_state::types::Dot;

fn main() {
    println!("=== nexus-state CRDT Examples ===\n");

    gcounter_example();
    lwwreg_example();
    orswot_example();
    distributed_scenario();
}

/// Demonstrates GCounter usage for distributed counting
fn gcounter_example() {
    println!("--- GCounter Example ---\n");

    // Create a new counter
    let counter = GCounter::new();
    println!("Initial value: {}", counter.value());

    // Increment from different actors (nodes)
    counter.increment(0, 5);
    println!("After actor 0 increments by 5: {}", counter.value());

    counter.increment(1, 3);
    println!("After actor 1 increments by 3: {}", counter.value());

    counter.increment(0, 2);
    println!("After actor 0 increments by 2 more: {}", counter.value());

    // Check individual actor values
    println!("\nPer-actor breakdown:");
    println!("  Actor 0: {}", counter.actor_value(0));
    println!("  Actor 1: {}", counter.actor_value(1));

    // Demonstrate merge
    let counter2 = GCounter::new();
    counter2.increment(2, 100);
    counter2.increment(0, 10); // Overlaps with counter's actor 0

    println!("\nBefore merge with counter2: {}", counter.value());
    counter.merge(&counter2);
    println!("After merge: {}", counter.value());
    println!("  Actor 0 after merge: {} (max of 7 and 10)", counter.actor_value(0));

    // Verify properties
    println!("\nVerifying CRDT properties:");
    let c1 = GCounter::new();
    c1.increment(0, 5);
    let c2 = GCounter::new();
    c2.increment(1, 3);

    let mut merged1 = GCounter::new();
    merged1.merge(&c1);
    merged1.merge(&c2);

    let mut merged2 = GCounter::new();
    merged2.merge(&c2);
    merged2.merge(&c1);

    println!("  Commutativity: merge(c1,c2) == merge(c2,c1)? {}", 
             merged1.snapshot() == merged2.snapshot());

    println!();
}

/// Demonstrates LWWReg usage for distributed metadata
fn lwwreg_example() {
    println!("--- LWWReg Example ---\n");

    // Create a register with initial value
    let mut reg = LWWReg::new(0u32, 0);
    println!("Initial value: {}", reg.get());

    // Update with timestamp
    reg.set(42, 100, 0);
    println!("After set(42, ts=100): {}", reg.get());

    // Older timestamp is rejected
    let updated = reg.set(99, 50, 1);
    println!("Tried set(99, ts=50): updated={}, value={}", updated, reg.get());

    // Newer timestamp wins
    let updated = reg.set(123, 200, 1);
    println!("Tried set(123, ts=200): updated={}, value={}", updated, reg.get());

    // Demonstrate tie-breaking by actor ID
    println!("\nTie-breaking by actor ID:");
    let mut reg1 = LWWReg::with_timestamp(10u32, 100, 1);
    let reg2 = LWWReg::with_timestamp(20u32, 100, 5); // Same ts, higher actor

    println!("  reg1: value={}, ts={}, actor={}", reg1.get(), reg1.timestamp(), reg1.writer());
    println!("  reg2: value={}, ts={}, actor={}", reg2.get(), reg2.timestamp(), reg2.writer());

    reg1.merge(&reg2);
    println!("  After merge: value={} (actor {} wins)", reg1.get(), reg1.writer());

    // Using with structs
    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Config {
        max_bitrate: u32,
        audio_enabled: bool,
    }

    let mut config_reg = LWWReg::new(
        Config {
            max_bitrate: 1_000_000,
            audio_enabled: true,
        },
        0,
    );

    config_reg.set(
        Config {
            max_bitrate: 2_000_000,
            audio_enabled: false,
        },
        100,
        0,
    );

    println!("\nStruct in register: {:?}", config_reg.get());

    println!();
}

/// Demonstrates Orswot usage for distributed sets
fn orswot_example() {
    println!("--- Orswot Example ---\n");

    // Create a new set
    let mut set: Orswot<u32> = Orswot::new();
    println!("Initial size: {}", set.len());

    // Add elements
    set.add(42, Dot::new(0, 1)).unwrap();
    set.add(99, Dot::new(0, 2)).unwrap();
    set.add(7, Dot::new(0, 3)).unwrap();

    println!("After adding 42, 99, 7:");
    println!("  Size: {}", set.len());
    println!("  Contains 42? {}", set.contains(&42));
    println!("  Contains 100? {}", set.contains(&100));

    // Iterate over elements
    print!("  Elements: ");
    for elem in set.iter() {
        print!("{} ", elem);
    }
    println!();

    // Remove element
    set.remove(&99, Dot::new(0, 4)).unwrap();
    println!("\nAfter removing 99:");
    println!("  Size: {}", set.len());
    println!("  Contains 99? {}", set.contains(&99));
    println!("  Tombstone count: {}", set.tombstone_count());

    // Demonstrate idempotence
    let added1 = set.add(42, Dot::new(0, 1)).unwrap();
    println!("\nAdding 42 again with same dot: added={} (idempotent)", added1);

    // Demonstrate tombstone preventing resurrection
    let added2 = set.add(99, Dot::new(0, 2)).unwrap();
    println!("Re-adding 99 with old dot: added={} (tombstoned)", added2);

    // Can add with newer dot
    let added3 = set.add(99, Dot::new(0, 5)).unwrap();
    println!("Re-adding 99 with new dot: added={}", added3);

    // Demonstrate merge
    println!("\nMerge example:");
    let mut set_a: Orswot<u32> = Orswot::new();
    set_a.add(1, Dot::new(0, 1)).unwrap();
    set_a.add(2, Dot::new(0, 2)).unwrap();

    let mut set_b: Orswot<u32> = Orswot::new();
    set_b.add(3, Dot::new(1, 1)).unwrap();
    set_b.add(4, Dot::new(1, 2)).unwrap();

    println!("  Set A before merge: {:?}", set_a.iter().collect::<Vec<_>>());
    println!("  Set B: {:?}", set_b.iter().collect::<Vec<_>>());

    set_a.merge(&set_b).unwrap();
    println!("  Set A after merge: {:?}", set_a.iter().collect::<Vec<_>>());

    // Handle capacity error
    println!("\nCapacity handling:");
    let small_demo: Orswot<u32> = Orswot::new();
    // In real usage, would fill to MAX_ELEMENTS to see error
    println!("  Max elements: {}", nexus_state::MAX_ELEMENTS);
    println!("  Max tombstones: {}", nexus_state::MAX_TOMBSTONES);

    // Demonstrate error handling
    let mut err_set: Orswot<u32> = Orswot::new();
    match err_set.add(1, Dot::new_unchecked(1000, 1)) { // Invalid actor ID
        Ok(_) => println!("  Add succeeded"),
        Err(CrdtError::InvalidDot { actor_id, .. }) => {
            println!("  Got expected error: InvalidDot(actor_id={})", actor_id);
        }
        Err(e) => println!("  Unexpected error: {}", e),
    }

    println!();
}

/// Demonstrates a complete distributed scenario with multiple nodes
fn distributed_scenario() {
    println!("--- Distributed Scenario ---\n");

    // Simulate a WebRTC room with 3 SFU nodes
    println!("Scenario: 3 SFU nodes managing participant state\n");

    // Node 0 state
    let mut node0_participants: Orswot<u64> = Orswot::new();
    let node0_packets = GCounter::new();
    let mut node0_bitrate = LWWReg::new(1_000_000u32, 0);

    // Node 1 state
    let mut node1_participants: Orswot<u64> = Orswot::new();
    let node1_packets = GCounter::new();
    let mut node1_bitrate = LWWReg::new(1_000_000u32, 1);

    // Node 2 state
    let mut node2_participants: Orswot<u64> = Orswot::new();
    let node2_packets = GCounter::new();
    let mut node2_bitrate = LWWReg::new(1_000_000u32, 2);

    println!("Phase 1: Independent operations");
    
    // Node 0: Participant 100 joins, sends packets
    node0_participants.add(100, Dot::new(0, 1)).unwrap();
    node0_packets.increment(0, 1000);
    node0_bitrate.set(2_000_000, 100, 0);
    println!("  Node 0: Added participant 100, 1000 packets, bitrate=2Mbps");

    // Node 1: Participant 200 joins, sends packets
    node1_participants.add(200, Dot::new(1, 1)).unwrap();
    node1_packets.increment(1, 2000);
    node1_bitrate.set(3_000_000, 200, 1);
    println!("  Node 1: Added participant 200, 2000 packets, bitrate=3Mbps");

    // Node 2: Participant 300 joins
    node2_participants.add(300, Dot::new(2, 1)).unwrap();
    node2_packets.increment(2, 500);
    println!("  Node 2: Added participant 300, 500 packets");

    println!("\nPhase 2: State synchronization");

    // Sync participants
    node0_participants.merge(&node1_participants).unwrap();
    node0_participants.merge(&node2_participants).unwrap();
    
    node1_participants.merge(&node0_participants).unwrap();
    node1_participants.merge(&node2_participants).unwrap();
    
    node2_participants.merge(&node0_participants).unwrap();
    node2_participants.merge(&node1_participants).unwrap();

    // Sync packet counters
    node0_packets.merge(&node1_packets);
    node0_packets.merge(&node2_packets);

    // Sync bitrate (last writer wins)
    node0_bitrate.merge(&node1_bitrate);
    node0_bitrate.merge(&node2_bitrate);

    println!("  All nodes synced");

    println!("\nPhase 3: Verify convergence");
    
    let participants: Vec<_> = node0_participants.iter().copied().collect();
    println!("  Participants (all nodes): {:?}", participants);
    println!("  Total packets: {}", node0_packets.value());
    println!("  Current bitrate: {} (set by node {} at ts={})", 
             node0_bitrate.get(), 
             node0_bitrate.writer(),
             node0_bitrate.timestamp());

    // Verify all nodes have same participant set
    let converged = node0_participants.snapshot() == node1_participants.snapshot()
        && node1_participants.snapshot() == node2_participants.snapshot();
    println!("  Participant sets converged: {}", converged);

    println!("\nPhase 4: Participant leaves (handled by one node)");
    
    node1_participants.remove(&200, Dot::new(1, 2)).unwrap();
    println!("  Node 1: Removed participant 200");
    println!("  Node 1 participants: {:?}", node1_participants.iter().copied().collect::<Vec<_>>());

    // Sync the removal
    node0_participants.merge(&node1_participants).unwrap();
    node2_participants.merge(&node1_participants).unwrap();

    println!("  After sync - Node 0 participants: {:?}", 
             node0_participants.iter().copied().collect::<Vec<_>>());
    println!("  Removal propagated: {}", !node0_participants.contains(&200));

    println!("\n=== Example Complete ===");
}
