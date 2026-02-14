//! Hierarchy invariant tests
//!
//! Tests that verify the actor hierarchy relationships:
//! - Participant belongs to Room
//! - Track belongs to Participant
//! - Capacity enforcement
//! - Hierarchy integrity

use nexus_actor::{
    ActorManager, MediaKind, ParticipantActor, ParticipantActorMessage, RoomActor,
    RoomActorMessage, TrackActor,
};
use std::sync::Arc;

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn create_test_distributed_state() -> Arc<nexus_state::DistributedState> {
    let config = nexus_state::DistributedStateConfig::new(1);
    Arc::new(nexus_state::DistributedState::new(config))
}

#[test]
fn test_participant_belongs_to_room() {
    let state = create_test_distributed_state();
    
    // Spawn room
    let (room, _room_tx) = RoomActor::spawn(1, "Test Room".to_string(), 100, 0, now_ns(), state.clone());

    // Spawn participant
    let (participant, _participant_tx) =
        ParticipantActor::spawn(10, 1, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Assert participant.room_id == room.id
    assert_eq!(participant.room_id(), room.id());
}

#[test]
fn test_track_belongs_to_participant() {
    let state = create_test_distributed_state();
    
    // Spawn participant
    let (participant, _participant_tx) =
        ParticipantActor::spawn(10, 1, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Spawn track
    let (track, _track_tx) = TrackActor::spawn(100, 10, 12345, MediaKind::Video, 0);

    // Assert track.participant_id == participant.id
    assert_eq!(track.participant_id(), participant.id());
}

#[test]
fn test_room_capacity_enforcement() {
    let state = create_test_distributed_state();
    let (mut room, room_tx) = RoomActor::spawn(1, "Test".to_string(), 2, 0, now_ns(), state);

    // Add 2 participants (should succeed)
    room_tx
        .send(RoomActorMessage::AddParticipant {
            participant_id: 1,
            name: "Alice".to_string(),
            connection_id: 100,
        })
        .unwrap();

    room_tx
        .send(RoomActorMessage::AddParticipant {
            participant_id: 2,
            name: "Bob".to_string(),
            connection_id: 101,
        })
        .unwrap();

    room.process_messages();
    assert!(room.is_full());
    assert_eq!(room.participant_count(), 2);

    // Third participant should be rejected
    room_tx
        .send(RoomActorMessage::AddParticipant {
            participant_id: 3,
            name: "Charlie".to_string(),
            connection_id: 102,
        })
        .unwrap();

    room.process_messages();

    // Assert participant count still 2
    assert_eq!(room.participant_count(), 2);
}

#[test]
fn test_participant_track_capacity() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(10, 1, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Publish multiple tracks
    for i in 0..5 {
        tx.send(ParticipantActorMessage::PublishTrack {
            track_id: 1000 + i,
            ssrc: 12345 + i as u32,
            kind: MediaKind::Video,
        })
        .unwrap();
    }

    participant.process_messages();

    let tracks = participant.published_tracks();
    assert_eq!(tracks.len(), 5);
}

#[test]
fn test_room_track_announcement() {
    let state = create_test_distributed_state();
    let (mut room, room_tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant first
    room_tx
        .send(RoomActorMessage::AddParticipant {
            participant_id: 10,
            name: "Alice".to_string(),
            connection_id: 1000,
        })
        .unwrap();

    room.process_messages();

    // Announce track
    room_tx
        .send(RoomActorMessage::AnnounceTrack {
            track_id: 1000,
            participant_id: 10,
            kind: MediaKind::Video,
        })
        .unwrap();

    room.process_messages();

    assert_eq!(room.track_count(), 1);
    let tracks = room.tracks();
    assert_eq!(tracks.get(&1000), Some(&10));
}

#[test]
#[should_panic(expected = "participant 99 not in room 1")]
fn test_track_announcement_requires_participant() {
    let state = create_test_distributed_state();
    let (mut room, room_tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Try to announce track without adding participant first
    room_tx
        .send(RoomActorMessage::AnnounceTrack {
            track_id: 1000,
            participant_id: 99,
            kind: MediaKind::Video,
        })
        .unwrap();

    room.process_messages();
}

#[test]
fn test_actor_manager_hierarchy() {
    let state = create_test_distributed_state();
    let manager = ActorManager::new(10, 100, 1000, state);

    // Spawn room
    manager
        .spawn_room(1, "Test Room".to_string(), 100, 0)
        .unwrap();

    // Spawn participant
    manager
        .spawn_participant(10, 1, "Alice".to_string(), 1000, 0)
        .unwrap();

    // Spawn track
    manager
        .spawn_track(100, 10, 12345, MediaKind::Video, 0)
        .unwrap();

    // Verify registry
    let registry = manager.registry();
    assert_eq!(registry.lookup_room(1), Some(0));
    assert_eq!(registry.lookup_participant(10), Some(0));
    assert_eq!(registry.lookup_track(100), Some(0));
}

#[test]
fn test_actor_manager_capacity() {
    let state = create_test_distributed_state();
    let manager = ActorManager::new(2, 5, 10, state);

    // Fill room capacity
    manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
    manager.spawn_room(2, "Room2".to_string(), 100, 0).unwrap();

    // Should fail
    let result = manager.spawn_room(3, "Room3".to_string(), 100, 0);
    assert!(result.is_err());

    // Fill participant capacity
    for i in 0..5 {
        manager
            .spawn_participant(10 + i, 1, format!("User{}", i), 1000 + i, 0)
            .unwrap();
    }

    // Should fail
    let result = manager.spawn_participant(99, 1, "Extra".to_string(), 9999, 0);
    assert!(result.is_err());
}

#[test]
fn test_remove_participant_removes_tracks() {
    let state = create_test_distributed_state();
    let (mut room, room_tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant
    room_tx
        .send(RoomActorMessage::AddParticipant {
            participant_id: 10,
            name: "Alice".to_string(),
            connection_id: 1000,
        })
        .unwrap();

    room.process_messages();

    // Announce multiple tracks
    for i in 0..3 {
        room_tx
            .send(RoomActorMessage::AnnounceTrack {
                track_id: 1000 + i,
                participant_id: 10,
                kind: MediaKind::Video,
            })
            .unwrap();
    }

    room.process_messages();
    assert_eq!(room.track_count(), 3);

    // Remove participant
    room_tx
        .send(RoomActorMessage::RemoveParticipant { participant_id: 10 })
        .unwrap();

    room.process_messages();

    // All tracks should be removed
    assert_eq!(room.participant_count(), 0);
    assert_eq!(room.track_count(), 0);
}

#[test]
fn test_participant_subscription_management() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(10, 1, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Subscribe to multiple tracks
    for i in 0..5 {
        tx.send(ParticipantActorMessage::SubscribeToTrack {
            track_id: 2000 + i,
            target_layer: 2,
        })
        .unwrap();
    }

    participant.process_messages();

    let subs = participant.subscriptions();
    assert_eq!(subs.len(), 5);

    // Unsubscribe from one
    tx.send(ParticipantActorMessage::UnsubscribeFromTrack { track_id: 2002 })
        .unwrap();

    participant.process_messages();

    let subs = participant.subscriptions();
    assert_eq!(subs.len(), 4);
    assert!(!subs.contains(&2002));
}
