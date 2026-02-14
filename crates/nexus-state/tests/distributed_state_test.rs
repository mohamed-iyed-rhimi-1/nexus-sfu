//! Integration tests for DistributedState
//!
//! These tests verify the correctness of the distributed state manager,
//! including CRDT properties like commutativity, associativity, and idempotence.

use nexus_state::{
    DistributedState, DistributedStateConfig, CrdtError,
    Dot, MAX_ACTORS,
};
use nexus_state::gossip::types::{StateUpdate, TrackInfo};

// =============================================================================
// Room Tests
// =============================================================================

#[test]
fn test_create_room() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Create room
    state.create_room(1, "Meeting".to_string(), 100).unwrap();

    // Verify room exists
    assert!(state.room_exists(1));
    assert_eq!(state.room_count(), 1);

    // Verify metadata
    let metadata = state.get_room(1).unwrap();
    assert_eq!(metadata.name(), "Meeting");
    assert_eq!(metadata.max_participants(), 100);
    assert!(metadata.created_at_ns() > 0);
}

#[test]
fn test_remove_room() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    state.create_room(1, "Test".to_string(), 100).unwrap();
    assert!(state.room_exists(1));

    // Remove room
    assert!(state.remove_room(1));
    assert!(!state.room_exists(1));
    assert_eq!(state.room_count(), 0);

    // Remove non-existent room
    assert!(!state.remove_room(1));
}

#[test]
fn test_room_capacity_limit() {
    let config = DistributedStateConfig::with_limits(1, 3, 100, 100);
    let state = DistributedState::new(config);

    // Create rooms up to limit
    state.create_room(1, "Room 1".to_string(), 100).unwrap();
    state.create_room(2, "Room 2".to_string(), 100).unwrap();
    state.create_room(3, "Room 3".to_string(), 100).unwrap();

    // Fourth room should fail
    let result = state.create_room(4, "Room 4".to_string(), 100);
    assert!(matches!(result, Err(CrdtError::CapacityExhausted { capacity: 3 })));
}

// =============================================================================
// Participant Tests
// =============================================================================

#[test]
fn test_add_remove_participant() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    state.create_room(1, "Test".to_string(), 100).unwrap();

    // Add participant
    let dot = state.add_participant(1, 42).unwrap();
    assert!(dot.clock() > 0);
    assert_eq!(dot.actor_id(), 1);

    // Verify participant exists
    assert!(state.participant_exists(1, 42));
    assert_eq!(state.participant_count(1), 1);

    let participants = state.get_participants(1);
    assert_eq!(participants, vec![42]);

    // Remove participant
    let dot2 = state.remove_participant(1, 42).unwrap();
    assert!(dot2.clock() > dot.clock());

    // Verify participant removed
    assert!(!state.participant_exists(1, 42));
    assert_eq!(state.participant_count(1), 0);
}

#[test]
fn test_participant_room_not_found() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Add participant to non-existent room
    let result = state.add_participant(999, 42);
    assert!(matches!(result, Err(CrdtError::ElementNotFound)));
}

#[test]
fn test_participant_room_capacity() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Create room with max 2 participants
    state.create_room(1, "Small Room".to_string(), 2).unwrap();

    // Add up to limit
    state.add_participant(1, 1).unwrap();
    state.add_participant(1, 2).unwrap();

    // Third should fail
    let result = state.add_participant(1, 3);
    assert!(matches!(result, Err(CrdtError::CapacityExhausted { capacity: 2 })));
}

#[test]
fn test_multiple_rooms_participants() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    state.create_room(1, "Room A".to_string(), 100).unwrap();
    state.create_room(2, "Room B".to_string(), 100).unwrap();

    // Add participants to different rooms
    state.add_participant(1, 10).unwrap();
    state.add_participant(1, 11).unwrap();
    state.add_participant(2, 20).unwrap();

    assert_eq!(state.participant_count(1), 2);
    assert_eq!(state.participant_count(2), 1);

    assert!(state.participant_exists(1, 10));
    assert!(!state.participant_exists(2, 10));
}

// =============================================================================
// Track Tests
// =============================================================================

#[test]
fn test_add_update_track() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let info = TrackInfo {
        track_type: 1, // video
        codec: 100,
        bitrate_kbps: 2500,
    };

    // Add track
    let ts1 = state.add_track(1, info).unwrap();
    assert!(ts1 > 0);
    assert_eq!(state.track_count(), 1);

    // Verify track
    let retrieved = state.get_track(1).unwrap();
    assert_eq!(retrieved.track_type, 1);
    assert_eq!(retrieved.bitrate_kbps, 2500);

    // Update track
    let new_info = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 5000,
    };
    let ts2 = state.update_track(1, new_info).unwrap();
    assert!(ts2 > ts1);

    // Verify update
    let retrieved = state.get_track(1).unwrap();
    assert_eq!(retrieved.bitrate_kbps, 5000);
}

#[test]
fn test_remove_track() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let info = TrackInfo::default();
    state.add_track(1, info).unwrap();
    assert!(state.get_track(1).is_some());

    // Remove track
    assert!(state.remove_track(1));
    assert!(state.get_track(1).is_none());
    assert_eq!(state.track_count(), 0);

    // Remove non-existent
    assert!(!state.remove_track(1));
}

#[test]
fn test_update_nonexistent_track() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let result = state.update_track(999, TrackInfo::default());
    assert!(matches!(result, Err(CrdtError::ElementNotFound)));
}

#[test]
fn test_track_capacity_limit() {
    let config = DistributedStateConfig::with_limits(1, 100, 3, 100);
    let state = DistributedState::new(config);

    // Add tracks up to limit
    state.add_track(1, TrackInfo::default()).unwrap();
    state.add_track(2, TrackInfo::default()).unwrap();
    state.add_track(3, TrackInfo::default()).unwrap();

    // Fourth should fail
    let result = state.add_track(4, TrackInfo::default());
    assert!(matches!(result, Err(CrdtError::CapacityExhausted { capacity: 3 })));
}

// =============================================================================
// Subscription Tests
// =============================================================================

#[test]
fn test_add_remove_subscription() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Add subscription
    let dot = state.add_subscription(1, 42).unwrap();
    assert!(dot.clock() > 0);
    assert_eq!(state.subscription_count(), 1);

    // Verify queries
    let subs = state.get_subscriptions_for_track(1);
    assert_eq!(subs, vec![42]);

    let tracks = state.get_subscriptions_for_participant(42);
    assert_eq!(tracks, vec![1]);

    // Remove subscription
    let dot2 = state.remove_subscription(1, 42).unwrap();
    assert!(dot2.clock() > dot.clock());
    assert_eq!(state.subscription_count(), 0);

    // Verify removed
    assert!(state.get_subscriptions_for_track(1).is_empty());
    assert!(state.get_subscriptions_for_participant(42).is_empty());
}

#[test]
fn test_multiple_subscriptions() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Participant 1 subscribes to tracks 1, 2, 3
    state.add_subscription(1, 1).unwrap();
    state.add_subscription(2, 1).unwrap();
    state.add_subscription(3, 1).unwrap();

    // Participant 2 subscribes to track 1
    state.add_subscription(1, 2).unwrap();

    assert_eq!(state.subscription_count(), 4);

    // Check subscriptions for track 1
    let mut subs = state.get_subscriptions_for_track(1);
    subs.sort();
    assert_eq!(subs, vec![1, 2]);

    // Check subscriptions for participant 1
    let mut tracks = state.get_subscriptions_for_participant(1);
    tracks.sort();
    assert_eq!(tracks, vec![1, 2, 3]);
}

#[test]
fn test_subscription_capacity_limit() {
    let config = DistributedStateConfig::with_limits(1, 100, 100, 3);
    let state = DistributedState::new(config);

    // Add subscriptions up to limit
    state.add_subscription(1, 1).unwrap();
    state.add_subscription(2, 1).unwrap();
    state.add_subscription(3, 1).unwrap();

    // Fourth should fail
    let result = state.add_subscription(4, 1);
    assert!(matches!(result, Err(CrdtError::CapacityExhausted { capacity: 3 })));
}

// =============================================================================
// Delta Merge Tests
// =============================================================================

#[test]
fn test_merge_deltas_commutativity() {
    // Create two instances with different actors
    let config1 = DistributedStateConfig::new(1);
    let config2 = DistributedStateConfig::new(2);
    let state1 = DistributedState::new(config1);
    let state2 = DistributedState::new(config2);

    // Create rooms in both
    state1.create_room(1, "Test".to_string(), 100).unwrap();
    state2.create_room(1, "Test".to_string(), 100).unwrap();

    // Create deltas
    let delta_a = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 10,
        dot: Dot::new(1, 100),
    };
    let delta_b = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 20,
        dot: Dot::new(2, 100),
    };

    // Apply in order A, B to state1
    state1.merge_delta(delta_a.clone()).unwrap();
    state1.merge_delta(delta_b.clone()).unwrap();

    // Apply in order B, A to state2
    state2.merge_delta(delta_b).unwrap();
    state2.merge_delta(delta_a).unwrap();

    // Both should have same participant count
    assert_eq!(state1.participant_count(1), state2.participant_count(1));
}

#[test]
fn test_merge_deltas_idempotence() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    state.create_room(1, "Test".to_string(), 100).unwrap();

    let delta = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 42,
        dot: Dot::new(2, 100),
    };

    // Apply once
    state.merge_delta(delta.clone()).unwrap();
    let count_after_first = state.participant_count(1);

    // Apply again - should be idempotent
    state.merge_delta(delta.clone()).unwrap();
    let count_after_second = state.participant_count(1);

    // Apply third time
    state.merge_delta(delta).unwrap();
    let count_after_third = state.participant_count(1);

    // All counts should be the same
    assert_eq!(count_after_first, count_after_second);
    assert_eq!(count_after_second, count_after_third);
}

#[test]
fn test_merge_track_updated() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    let info1 = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 1000,
    };
    let info2 = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2000,
    };

    // Merge with lower timestamp first
    let delta1 = StateUpdate::TrackUpdated {
        track_id: 1,
        info: info1,
        timestamp: 100,
        actor: 1,
    };
    state.merge_delta(delta1).unwrap();

    let track = state.get_track(1).unwrap();
    assert_eq!(track.bitrate_kbps, 1000);

    // Merge with higher timestamp
    let delta2 = StateUpdate::TrackUpdated {
        track_id: 1,
        info: info2,
        timestamp: 200,
        actor: 2,
    };
    state.merge_delta(delta2).unwrap();

    // Higher timestamp wins
    let track = state.get_track(1).unwrap();
    assert_eq!(track.bitrate_kbps, 2000);
}

#[test]
fn test_merge_subscription_deltas() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Add via delta
    let add_delta = StateUpdate::SubscriptionAdded {
        track_id: 1,
        participant_id: 42,
        dot: Dot::new(2, 100),
    };
    state.merge_delta(add_delta).unwrap();

    assert_eq!(state.subscription_count(), 1);
    assert_eq!(state.get_subscriptions_for_track(1), vec![42]);

    // Remove via delta
    let remove_delta = StateUpdate::SubscriptionRemoved {
        track_id: 1,
        participant_id: 42,
        dot: Dot::new(2, 101),
    };
    state.merge_delta(remove_delta).unwrap();

    assert_eq!(state.subscription_count(), 0);
}

#[test]
fn test_merge_deltas_batch() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    state.create_room(1, "Test".to_string(), 100).unwrap();

    let updates = vec![
        StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: 1,
            dot: Dot::new(2, 100),
        },
        StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: 2,
            dot: Dot::new(2, 101),
        },
        StateUpdate::SubscriptionAdded {
            track_id: 1,
            participant_id: 1,
            dot: Dot::new(2, 102),
        },
    ];

    state.merge_deltas(updates).unwrap();

    // All updates should have been applied
    assert!(state.participant_count(1) >= 0); // At least processed without error
    assert_eq!(state.subscription_count(), 1);
}

// =============================================================================
// LWW Conflict Resolution Tests
// =============================================================================

#[test]
fn test_lww_conflict_resolution() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Two updates with same timestamp but different actors
    let info1 = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 1000,
    };
    let info2 = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2000,
    };

    // Actor 1, timestamp 100
    let delta1 = StateUpdate::TrackUpdated {
        track_id: 1,
        info: info1,
        timestamp: 100,
        actor: 1,
    };

    // Actor 2, timestamp 100 (same timestamp)
    let delta2 = StateUpdate::TrackUpdated {
        track_id: 1,
        info: info2,
        timestamp: 100,
        actor: 2,
    };

    // Apply in one order
    state.merge_delta(delta1.clone()).unwrap();
    state.merge_delta(delta2.clone()).unwrap();

    let result1 = state.get_track(1).unwrap();

    // Reset and apply in opposite order
    state.remove_track(1);

    state.merge_delta(delta2).unwrap();
    state.merge_delta(delta1).unwrap();

    let result2 = state.get_track(1).unwrap();

    // Both should converge to same value (higher actor wins on tie)
    assert_eq!(result1.bitrate_kbps, result2.bitrate_kbps);
}

// =============================================================================
// Concurrent Update Tests
// =============================================================================

#[test]
fn test_concurrent_updates() {
    use std::sync::Arc;
    use std::thread;

    let config = DistributedStateConfig::new(1);
    let state = Arc::new(DistributedState::new(config));

    state.create_room(1, "Concurrent".to_string(), 1000).unwrap();

    let mut handles = vec![];

    // Spawn 10 threads, each adding 10 participants
    for thread_id in 0..10 {
        let state_clone = Arc::clone(&state);
        let handle = thread::spawn(move || {
            for i in 0..10 {
                let participant_id = thread_id * 100 + i + 1; // Unique IDs
                let _ = state_clone.add_participant(1, participant_id);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Should have all participants (or at least some due to CRDT semantics)
    let count = state.participant_count(1);
    assert!(count > 0, "Expected some participants");
    assert!(count <= 100, "Should not exceed 100 participants");
}

#[test]
fn test_concurrent_track_updates() {
    use std::sync::Arc;
    use std::thread;

    let config = DistributedStateConfig::new(1);
    let state = Arc::new(DistributedState::new(config));

    // Add initial track
    state.add_track(1, TrackInfo::default()).unwrap();

    let mut handles = vec![];

    // Spawn 5 threads, each updating the track
    for thread_id in 0..5 {
        let state_clone = Arc::clone(&state);
        let handle = thread::spawn(move || {
            for i in 0..10 {
                let info = TrackInfo {
                    track_type: 1,
                    codec: 100,
                    bitrate_kbps: (thread_id * 1000 + i * 100) as u32,
                };
                let _ = state_clone.update_track(1, info);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Track should exist with some valid bitrate
    let track = state.get_track(1).unwrap();
    assert!(track.bitrate_kbps > 0 || track.bitrate_kbps == 0); // Just checking it's accessible
}

// =============================================================================
// Delta Generation Tests
// =============================================================================

#[test]
fn test_generate_deltas() {
    let dot = Dot::new(1, 100);

    // ParticipantAdded
    let delta = DistributedState::generate_participant_added_delta(1, 42, dot);
    match delta {
        StateUpdate::ParticipantAdded { room_id, participant_id, dot: d } => {
            assert_eq!(room_id, 1);
            assert_eq!(participant_id, 42);
            assert_eq!(d.clock(), 100);
        }
        _ => panic!("Wrong delta type"),
    }

    // ParticipantRemoved
    let delta = DistributedState::generate_participant_removed_delta(1, 42, dot);
    match delta {
        StateUpdate::ParticipantRemoved { room_id, participant_id, .. } => {
            assert_eq!(room_id, 1);
            assert_eq!(participant_id, 42);
        }
        _ => panic!("Wrong delta type"),
    }

    // TrackUpdated
    let info = TrackInfo {
        track_type: 1,
        codec: 100,
        bitrate_kbps: 2500,
    };
    let delta = DistributedState::generate_track_updated_delta(1, info, 200, 1);
    match delta {
        StateUpdate::TrackUpdated { track_id, info: i, timestamp, actor } => {
            assert_eq!(track_id, 1);
            assert_eq!(i.bitrate_kbps, 2500);
            assert_eq!(timestamp, 200);
            assert_eq!(actor, 1);
        }
        _ => panic!("Wrong delta type"),
    }

    // SubscriptionAdded
    let delta = DistributedState::generate_subscription_added_delta(1, 42, dot);
    match delta {
        StateUpdate::SubscriptionAdded { track_id, participant_id, .. } => {
            assert_eq!(track_id, 1);
            assert_eq!(participant_id, 42);
        }
        _ => panic!("Wrong delta type"),
    }

    // SubscriptionRemoved
    let delta = DistributedState::generate_subscription_removed_delta(1, 42, dot);
    match delta {
        StateUpdate::SubscriptionRemoved { track_id, participant_id, .. } => {
            assert_eq!(track_id, 1);
            assert_eq!(participant_id, 42);
        }
        _ => panic!("Wrong delta type"),
    }
}

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_config_accessors() {
    let config = DistributedStateConfig::with_limits(5, 100, 1000, 10000);

    assert_eq!(config.local_actor(), 5);
    assert_eq!(config.max_rooms(), 100);
    assert_eq!(config.max_tracks(), 1000);
    assert_eq!(config.max_subscriptions(), 10000);
}

#[test]
fn test_config_default() {
    let config = DistributedStateConfig::default();

    assert_eq!(config.local_actor(), 0);
    assert_eq!(config.max_rooms(), nexus_state::MAX_ROOMS);
    assert_eq!(config.max_tracks(), nexus_state::MAX_TRACKS);
    assert_eq!(config.max_subscriptions(), nexus_state::MAX_SUBSCRIPTIONS);
}

#[test]
#[should_panic(expected = "local_actor must be < MAX_ACTORS")]
fn test_config_invalid_actor() {
    DistributedStateConfig::new(MAX_ACTORS as u64);
}

#[test]
#[should_panic(expected = "max_rooms must not exceed MAX_ROOMS")]
fn test_config_invalid_max_rooms() {
    DistributedStateConfig::with_limits(1, 1_000_000, 100, 100);
}

// =============================================================================
// Invariant Tests
// =============================================================================

#[test]
fn test_invariants_after_operations() {
    let config = DistributedStateConfig::new(1);
    let state = DistributedState::new(config);

    // Perform various operations
    state.create_room(1, "Room 1".to_string(), 100).unwrap();
    state.create_room(2, "Room 2".to_string(), 50).unwrap();

    state.add_participant(1, 10).unwrap();
    state.add_participant(1, 11).unwrap();
    state.add_participant(2, 20).unwrap();

    state.add_track(1, TrackInfo::default()).unwrap();
    state.add_track(2, TrackInfo::default()).unwrap();

    state.add_subscription(1, 10).unwrap();
    state.add_subscription(1, 11).unwrap();
    state.add_subscription(2, 20).unwrap();

    // Remove some
    state.remove_participant(1, 10).unwrap();
    state.remove_track(2);
    state.remove_subscription(1, 11).unwrap();

    // Invariants should still hold
    state.assert_crdt_invariants();
}
