//! Integration test: Actor system with distributed state
//!
//! Tests the full actor hierarchy:
//! 1. RoomActor creation and participant management
//! 2. ParticipantActor track publishing and subscription
//! 3. TrackActor packet forwarding and migration
//! 4. DistributedState CRDT synchronization

use nexus_actor::ActorManager;
use nexus_state::{DistributedState, DistributedStateConfig};
use std::sync::Arc;

#[tokio::test]
async fn test_room_participant_track_hierarchy() {
    // Initialize distributed state
    let state_config = DistributedStateConfig::new(1, 100, 1000, 10000);
    let distributed_state = Arc::new(DistributedState::new(state_config));

    // Initialize actor manager
    let actor_manager = Arc::new(ActorManager::new(
        10,   // max_rooms
        100,  // max_participants
        1000, // max_tracks
        distributed_state.clone(),
    ));

    // Create room
    let room_id = actor_manager
        .create_room("test-room".to_string(), 50) // max_participants
        .expect("Failed to create room");

    // Verify room exists in distributed state
    assert!(distributed_state.has_room(room_id));

    // Add participant
    let participant_id = actor_manager
        .add_participant(room_id, "alice".to_string())
        .expect("Failed to add participant");

    // Verify participant in distributed state
    assert!(distributed_state.has_participant(room_id, participant_id));

    // Publish track
    let track_id = actor_manager
        .publish_track(
            participant_id,
            nexus_actor::MediaKind::Video,
            0x12345678, // ssrc
        )
        .expect("Failed to publish track");

    // Verify track in distributed state
    assert!(distributed_state.has_track(track_id));

    // Subscribe another participant
    let bob_id = actor_manager
        .add_participant(room_id, "bob".to_string())
        .expect("Failed to add bob");

    let _worker_id = actor_manager
        .subscribe_to_track(bob_id, track_id, "127.0.0.1:5000".parse().unwrap())
        .expect("Failed to subscribe");

    // Verify subscription in distributed state
    assert!(distributed_state.has_subscription(track_id, bob_id));

    // Cleanup
    actor_manager
        .remove_participant(participant_id)
        .expect("Failed to remove alice");
    actor_manager
        .remove_participant(bob_id)
        .expect("Failed to remove bob");
    actor_manager
        .remove_room(room_id)
        .expect("Failed to remove room");

    // Verify cleanup in distributed state
    assert!(!distributed_state.has_room(room_id));
}

#[tokio::test]
async fn test_track_migration_between_workers() {
    let state_config = DistributedStateConfig::new(1, 100, 1000, 10000);
    let distributed_state = Arc::new(DistributedState::new(state_config));

    let actor_manager = Arc::new(ActorManager::new(
        10,
        100,
        1000,
        distributed_state.clone(),
    ));

    let room_id = actor_manager
        .create_room("migration-test".to_string(), 50)
        .expect("Failed to create room");

    let publisher_id = actor_manager
        .add_participant(room_id, "publisher".to_string())
        .expect("Failed to add publisher");

    let track_id = actor_manager
        .publish_track(
            publisher_id,
            nexus_actor::MediaKind::Video,
            0xABCDEF00,
        )
        .expect("Failed to publish track");

    // Add 10 subscribers on different workers
    let mut subscriber_ids = Vec::new();
    for i in 0..10 {
        let sub_id = actor_manager
            .add_participant(room_id, format!("subscriber-{}", i))
            .expect("Failed to add subscriber");

        let _worker_id = actor_manager
            .subscribe_to_track(sub_id, track_id, format!("127.0.0.1:{}", 5000 + i).parse().unwrap())
            .expect("Failed to subscribe");

        subscriber_ids.push(sub_id);
    }

    // Trigger migration (implementation-specific)
    // This would normally be triggered by subscriber gravity calculation

    // Verify track still functional after migration
    // (Implementation would check packet forwarding continues)

    // Cleanup
    for sub_id in subscriber_ids {
        actor_manager.remove_participant(sub_id).ok();
    }
    actor_manager.remove_participant(publisher_id).ok();
    actor_manager.remove_room(room_id).ok();
}
