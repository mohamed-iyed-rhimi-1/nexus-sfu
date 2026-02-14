//! Integration tests for nexus-state CRDTs
//!
//! These tests simulate real-world distributed scenarios with multiple
//! nodes performing concurrent operations and merging state.

use nexus_state::crdt::{GCounter, LWWReg, Orswot};
use nexus_state::types::Dot;

/// Simulates a participant ID (u64)
type ParticipantId = u64;

/// Simulates track information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackInfo {
    bitrate: u32,
    codec_id: u8,
    active: bool,
}

impl Default for TrackInfo {
    fn default() -> Self {
        Self {
            bitrate: 0,
            codec_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// Participant Set Tests (Orswot)
// ============================================================================

#[test]
fn test_participant_set_with_orswot() {
    // Simulate 3 nodes managing a participant set
    let mut node0: Orswot<ParticipantId> = Orswot::new();
    let mut node1: Orswot<ParticipantId> = Orswot::new();
    let mut node2: Orswot<ParticipantId> = Orswot::new();

    // Node 0 adds participants 100, 101
    node0.add(100, Dot::new(0, 1)).unwrap();
    node0.add(101, Dot::new(0, 2)).unwrap();

    // Node 1 adds participants 200, 201
    node1.add(200, Dot::new(1, 1)).unwrap();
    node1.add(201, Dot::new(1, 2)).unwrap();

    // Node 2 adds participant 300, removes 100 (concurrent with node0's add)
    node2.add(300, Dot::new(2, 1)).unwrap();

    // Merge all states into node0
    node0.merge(&node1).unwrap();
    node0.merge(&node2).unwrap();

    // Verify convergence
    assert!(node0.contains(&100));
    assert!(node0.contains(&101));
    assert!(node0.contains(&200));
    assert!(node0.contains(&201));
    assert!(node0.contains(&300));
    assert_eq!(node0.len(), 5);

    // Merge into node1 and verify same state
    node1.merge(&node0).unwrap();
    node1.merge(&node2).unwrap();

    assert_eq!(node0.snapshot(), node1.snapshot());

    // Merge into node2 and verify same state
    node2.merge(&node0).unwrap();
    node2.merge(&node1).unwrap();

    assert_eq!(node0.snapshot(), node2.snapshot());
}

#[test]
fn test_participant_removal_propagation() {
    let mut node0: Orswot<ParticipantId> = Orswot::new();
    let mut node1: Orswot<ParticipantId> = Orswot::new();

    // Both nodes know about participant 100
    node0.add(100, Dot::new(0, 1)).unwrap();
    node1.add(100, Dot::new(0, 1)).unwrap();

    // Node 0 removes participant 100
    node0.remove(&100, Dot::new(0, 2)).unwrap();
    assert!(!node0.contains(&100));

    // Node 1 still sees participant 100
    assert!(node1.contains(&100));

    // After merge, node1 should also not see participant 100
    node1.merge(&node0).unwrap();
    assert!(!node1.contains(&100));
}

#[test]
fn test_concurrent_add_remove_participant() {
    let mut node0: Orswot<ParticipantId> = Orswot::new();
    let mut node1: Orswot<ParticipantId> = Orswot::new();

    // Node 0 adds participant with dot (0, 1)
    node0.add(100, Dot::new(0, 1)).unwrap();

    // Node 1 also has the participant (replicated state)
    node1.add(100, Dot::new(0, 1)).unwrap();

    // Concurrent operations:
    // - Node 0 updates participant with newer dot (0, 5)
    // - Node 1 removes participant with dot (0, 2)
    node0.add(100, Dot::new(0, 5)).unwrap();
    node1.remove(&100, Dot::new(0, 2)).unwrap();

    // After merge, the add with newer dot should win
    node0.merge(&node1).unwrap();
    assert!(node0.contains(&100), "Add with newer dot should win");

    node1.merge(&node0).unwrap();
    assert!(node1.contains(&100), "States should converge");
}

// ============================================================================
// Track Metadata Tests (LWWReg)
// ============================================================================

#[test]
fn test_track_metadata_with_lwwreg() {
    // Simulate track metadata being updated by different nodes
    let mut node0 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 1000,
            codec_id: 1,
            active: true,
        },
        100,
        0,
    );

    let mut node1 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 2000,
            codec_id: 2,
            active: true,
        },
        200,
        1,
    );

    // Node 0 has older timestamp, so node1's value should win
    node0.merge(&node1);

    assert_eq!(node0.get().bitrate, 2000);
    assert_eq!(node0.get().codec_id, 2);
    assert_eq!(node0.timestamp(), 200);
}

#[test]
fn test_track_metadata_concurrent_updates() {
    // Same timestamp, different actors
    let mut node0 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 1000,
            codec_id: 1,
            active: true,
        },
        100,
        0,
    );

    let node1 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 2000,
            codec_id: 2,
            active: true,
        },
        100, // Same timestamp
        5,   // Higher actor ID - wins tie
    );

    node0.merge(&node1);

    // Higher actor ID wins on tie
    assert_eq!(node0.get().bitrate, 2000);
    assert_eq!(node0.writer(), 5);
}

#[test]
fn test_track_metadata_convergence() {
    let node0 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 1000,
            codec_id: 1,
            active: true,
        },
        100,
        0,
    );

    let node1 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 2000,
            codec_id: 2,
            active: false,
        },
        200,
        1,
    );

    let node2 = LWWReg::with_timestamp(
        TrackInfo {
            bitrate: 3000,
            codec_id: 3,
            active: true,
        },
        150,
        2,
    );

    // Merge all into each node
    let mut final0 = node0.clone();
    final0.merge(&node1);
    final0.merge(&node2);

    let mut final1 = node1.clone();
    final1.merge(&node0);
    final1.merge(&node2);

    let mut final2 = node2.clone();
    final2.merge(&node0);
    final2.merge(&node1);

    // All should converge to the same value (highest timestamp = 200)
    assert_eq!(final0.snapshot(), final1.snapshot());
    assert_eq!(final1.snapshot(), final2.snapshot());
    assert_eq!(final0.get().bitrate, 2000);
}

// ============================================================================
// Subscription Graph Tests (Orswot with tuples)
// ============================================================================

/// A subscription: (subscriber_id, track_id)
type Subscription = (u64, u64);

#[test]
fn test_subscription_graph_with_orswot() {
    let mut node0: Orswot<Subscription> = Orswot::new();
    let mut node1: Orswot<Subscription> = Orswot::new();

    // Node 0: Participant 100 subscribes to tracks 1, 2
    node0.add((100, 1), Dot::new(0, 1)).unwrap();
    node0.add((100, 2), Dot::new(0, 2)).unwrap();

    // Node 1: Participant 200 subscribes to tracks 1, 3
    node1.add((200, 1), Dot::new(1, 1)).unwrap();
    node1.add((200, 3), Dot::new(1, 2)).unwrap();

    // Merge
    node0.merge(&node1).unwrap();

    // Verify all subscriptions present
    assert!(node0.contains(&(100, 1)));
    assert!(node0.contains(&(100, 2)));
    assert!(node0.contains(&(200, 1)));
    assert!(node0.contains(&(200, 3)));
    assert_eq!(node0.len(), 4);

    // No phantom subscriptions
    assert!(!node0.contains(&(100, 3)));
    assert!(!node0.contains(&(200, 2)));
}

#[test]
fn test_subscription_unsubscribe() {
    let mut node0: Orswot<Subscription> = Orswot::new();
    let mut node1: Orswot<Subscription> = Orswot::new();

    // Both nodes have subscription (100, 1)
    node0.add((100, 1), Dot::new(0, 1)).unwrap();
    node1.add((100, 1), Dot::new(0, 1)).unwrap();

    // Node 1 unsubscribes
    node1.remove(&(100, 1), Dot::new(0, 2)).unwrap();

    // After merge, subscription should be gone
    node0.merge(&node1).unwrap();
    assert!(!node0.contains(&(100, 1)));
}

// ============================================================================
// Statistics Tests (GCounter)
// ============================================================================

#[test]
fn test_statistics_with_gcounter() {
    // Simulate packet counting across multiple workers
    let worker0 = GCounter::new();
    let worker1 = GCounter::new();
    let worker2 = GCounter::new();

    // Each worker counts packets
    worker0.increment(0, 1000);
    worker1.increment(1, 2000);
    worker2.increment(2, 3000);

    // Merge all into a central counter
    let central = GCounter::new();
    central.merge(&worker0);
    central.merge(&worker1);
    central.merge(&worker2);

    // Total should be sum of all increments
    assert_eq!(central.value(), 6000);

    // Verify monotonicity: subsequent merges don't decrease
    central.merge(&worker0);
    assert_eq!(central.value(), 6000);
}

#[test]
fn test_statistics_concurrent_workers() {
    let counter = GCounter::new();

    // Simulate concurrent increments from multiple actors
    for actor in 0..10u64 {
        counter.increment(actor, 100);
    }

    assert_eq!(counter.value(), 1000);

    // Each actor's contribution is tracked separately
    for actor in 0..10u64 {
        assert_eq!(counter.actor_value(actor), 100);
    }
}

#[test]
fn test_statistics_merge_convergence() {
    let node0 = GCounter::new();
    let node1 = GCounter::new();
    let node2 = GCounter::new();

    // Different nodes increment different actors
    node0.increment(0, 100);
    node0.increment(1, 50);

    node1.increment(1, 75); // Overlaps with node0's actor 1
    node1.increment(2, 200);

    node2.increment(0, 150); // Overlaps with node0's actor 0
    node2.increment(3, 300);

    // Merge all ways
    let merged0 = GCounter::new();
    merged0.merge(&node0);
    merged0.merge(&node1);
    merged0.merge(&node2);

    let merged1 = GCounter::new();
    merged1.merge(&node1);
    merged1.merge(&node2);
    merged1.merge(&node0);

    let merged2 = GCounter::new();
    merged2.merge(&node2);
    merged2.merge(&node0);
    merged2.merge(&node1);

    // All should have same value
    assert_eq!(merged0.snapshot(), merged1.snapshot());
    assert_eq!(merged1.snapshot(), merged2.snapshot());

    // Value should be max of each actor
    // Actor 0: max(100, 150) = 150
    // Actor 1: max(50, 75) = 75
    // Actor 2: max(0, 200) = 200
    // Actor 3: max(0, 300) = 300
    // Total: 150 + 75 + 200 + 300 = 725
    assert_eq!(merged0.value(), 725);
}

// ============================================================================
// Complex Scenario Tests
// ============================================================================

#[test]
fn test_room_state_simulation() {
    // Simulate a complete room with participants, tracks, and subscriptions
    
    // Participant set
    let mut participants: Orswot<ParticipantId> = Orswot::new();
    
    // Track metadata (one register per track - simulated with a simple approach)
    let mut track_bitrate = LWWReg::new(0u32, 0);
    
    // Subscription graph
    let mut subscriptions: Orswot<Subscription> = Orswot::new();
    
    // Packet counter
    let packet_counter = GCounter::new();

    // Add participants
    participants.add(100, Dot::new(0, 1)).unwrap();
    participants.add(200, Dot::new(1, 1)).unwrap();

    // Update track metadata
    track_bitrate.set(1_000_000, 100, 0);

    // Add subscriptions
    subscriptions.add((100, 1), Dot::new(0, 2)).unwrap();
    subscriptions.add((200, 1), Dot::new(1, 2)).unwrap();

    // Count packets
    packet_counter.increment(0, 1000);
    packet_counter.increment(1, 2000);

    // Verify state
    assert_eq!(participants.len(), 2);
    assert_eq!(track_bitrate.get(), 1_000_000);
    assert_eq!(subscriptions.len(), 2);
    assert_eq!(packet_counter.value(), 3000);

    // Simulate participant leaving
    participants.remove(&100, Dot::new(0, 3)).unwrap();
    subscriptions.remove(&(100, 1), Dot::new(0, 3)).unwrap();

    assert_eq!(participants.len(), 1);
    assert_eq!(subscriptions.len(), 1);
    assert!(!participants.contains(&100));
    assert!(participants.contains(&200));
}

#[test]
fn test_multi_node_sync_scenario() {
    // Simulate 3 nodes with network partitions and eventual sync

    // Initial state on all nodes
    let mut node0: Orswot<ParticipantId> = Orswot::new();
    let mut node1: Orswot<ParticipantId> = Orswot::new();
    let mut node2: Orswot<ParticipantId> = Orswot::new();

    // Phase 1: All nodes add same initial participant
    let initial_dot = Dot::new(0, 1);
    node0.add(100, initial_dot).unwrap();
    node1.add(100, initial_dot).unwrap();
    node2.add(100, initial_dot).unwrap();

    // Phase 2: Network partition - each node operates independently
    node0.add(101, Dot::new(0, 2)).unwrap();
    node1.add(102, Dot::new(1, 1)).unwrap();
    node1.remove(&100, Dot::new(1, 2)).unwrap();
    node2.add(103, Dot::new(2, 1)).unwrap();

    // Phase 3: Network heals - merge all states
    // First sync node0 and node1
    node0.merge(&node1).unwrap();
    node1.merge(&node0).unwrap();

    // Then sync with node2
    node0.merge(&node2).unwrap();
    node1.merge(&node2).unwrap();
    node2.merge(&node0).unwrap();

    // All nodes should converge to same state
    assert_eq!(node0.snapshot(), node1.snapshot());
    assert_eq!(node1.snapshot(), node2.snapshot());

    // Verify final state
    // - 100 was removed by node1
    // - 101, 102, 103 were added by different nodes
    assert!(!node0.contains(&100), "Removed participant should not be present");
    assert!(node0.contains(&101));
    assert!(node0.contains(&102));
    assert!(node0.contains(&103));
    assert_eq!(node0.len(), 3);
}
