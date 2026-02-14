//! RoomActor unit tests

use crossbeam_channel::bounded;
use nexus_actor::{ActorState, MediaKind, RoomActor, RoomActorMessage, RoomStats};
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
fn test_spawn_room() {
    let state = create_test_distributed_state();
    let (room, _tx) = RoomActor::spawn(1, "Test Room".to_string(), 100, 0, now_ns(), state);

    assert_eq!(room.id(), 1);
    assert_eq!(room.name(), "Test Room");
    assert_eq!(room.max_participants(), 100);
    assert_eq!(room.participant_count(), 0);
    assert_eq!(room.track_count(), 0);
    assert_eq!(room.state(), ActorState::Active);
    assert_eq!(room.worker_id(), 0);
}

#[test]
#[should_panic(expected = "room id must not be 0")]
fn test_spawn_zero_id() {
    let state = create_test_distributed_state();
    let _ = RoomActor::spawn(0, "Test".to_string(), 100, 0, now_ns(), state);
}

#[test]
#[should_panic(expected = "name too long")]
fn test_spawn_long_name() {
    let state = create_test_distributed_state();
    let long_name = "a".repeat(257);
    let _ = RoomActor::spawn(1, long_name, 100, 0, now_ns(), state);
}

#[test]
#[should_panic(expected = "max_participants")]
fn test_spawn_zero_max_participants() {
    let state = create_test_distributed_state();
    let _ = RoomActor::spawn(1, "Test".to_string(), 0, 0, now_ns(), state);
}

#[test]
fn test_add_participant() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();

    assert_eq!(room.participant_count(), 1);
    let participants = room.participants();
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0], 10);
}

#[test]
fn test_add_multiple_participants() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    for i in 0..5 {
        tx.send(RoomActorMessage::AddParticipant {
            participant_id: 10 + i,
            name: format!("User{}", i),
            connection_id: 1000 + i,
        })
        .unwrap();
    }

    room.process_messages();

    assert_eq!(room.participant_count(), 5);
}

#[test]
fn test_remove_participant() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();
    assert_eq!(room.participant_count(), 1);

    // Remove participant
    tx.send(RoomActorMessage::RemoveParticipant { participant_id: 10 })
        .unwrap();

    room.process_messages();
    assert_eq!(room.participant_count(), 0);
}

#[test]
fn test_room_capacity_enforcement() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 2, 0, now_ns(), state);

    // Add 2 participants (should succeed)
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 1,
        name: "Alice".to_string(),
        connection_id: 100,
    })
    .unwrap();

    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 2,
        name: "Bob".to_string(),
        connection_id: 101,
    })
    .unwrap();

    room.process_messages();
    assert_eq!(room.participant_count(), 2);
    assert!(room.is_full());
    assert!(!room.can_add_participant());

    // Third participant should be rejected
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 3,
        name: "Charlie".to_string(),
        connection_id: 102,
    })
    .unwrap();

    room.process_messages();
    assert_eq!(room.participant_count(), 2);
}

#[test]
fn test_announce_track() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant first
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();

    // Announce track
    tx.send(RoomActorMessage::AnnounceTrack {
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
fn test_remove_track_announcement() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();

    // Announce track
    tx.send(RoomActorMessage::AnnounceTrack {
        track_id: 1000,
        participant_id: 10,
        kind: MediaKind::Video,
    })
    .unwrap();

    room.process_messages();
    assert_eq!(room.track_count(), 1);

    // Remove track announcement
    tx.send(RoomActorMessage::RemoveTrackAnnouncement { track_id: 1000 })
        .unwrap();

    room.process_messages();
    assert_eq!(room.track_count(), 0);
}

#[test]
fn test_remove_participant_removes_tracks() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add participant
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();

    // Announce multiple tracks
    for i in 0..3 {
        tx.send(RoomActorMessage::AnnounceTrack {
            track_id: 1000 + i,
            participant_id: 10,
            kind: MediaKind::Video,
        })
        .unwrap();
    }

    room.process_messages();
    assert_eq!(room.track_count(), 3);

    // Remove participant
    tx.send(RoomActorMessage::RemoveParticipant { participant_id: 10 })
        .unwrap();

    room.process_messages();

    // All tracks should be removed
    assert_eq!(room.participant_count(), 0);
    assert_eq!(room.track_count(), 0);
}

#[test]
fn test_terminate() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    tx.send(RoomActorMessage::Terminate).unwrap();

    let should_continue = room.process_messages();
    assert!(!should_continue);
    assert_eq!(room.state(), ActorState::Terminated);
}

#[test]
fn test_health_check() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    tx.send(RoomActorMessage::HealthCheck).unwrap();

    room.process_messages();
    assert_eq!(room.state(), ActorState::Active);
}

#[test]
fn test_get_stats() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add a participant and track to have non-zero stats
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();

    tx.send(RoomActorMessage::AnnounceTrack {
        track_id: 1000,
        participant_id: 10,
        kind: MediaKind::Video,
    })
    .unwrap();

    room.process_messages();

    // Create response channel and request stats
    let (response_tx, response_rx) = bounded::<RoomStats>(1);
    tx.send(RoomActorMessage::GetStats { response_tx }).unwrap();

    room.process_messages();

    // Verify stats received via response channel
    let stats = response_rx.recv().unwrap();
    assert_eq!(stats.participant_count, 1);
    assert_eq!(stats.track_count, 1);
    assert!(stats.uptime_ns > 0);
    assert!(stats.messages_processed > 0);
}

#[test]
fn test_message_processing_bounded() {
    let state = create_test_distributed_state();
    // Use max_participants of 100 (the limit) and test with health checks
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Send more than MAX_MESSAGES_PER_ITERATION (100) health check messages
    for _ in 0..150 {
        tx.send(RoomActorMessage::HealthCheck).unwrap();
    }

    // First call processes up to 100 messages
    room.process_messages();

    // Second call processes remaining messages
    room.process_messages();
    
    // Verify room is still active
    assert_eq!(room.state(), ActorState::Active);
}

#[test]
#[should_panic(expected = "participant_id must not be 0")]
fn test_add_participant_zero_id() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 0,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    room.process_messages();
}

#[test]
fn test_add_duplicate_participant() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Add same participant twice
    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice".to_string(),
        connection_id: 1000,
    })
    .unwrap();

    tx.send(RoomActorMessage::AddParticipant {
        participant_id: 10,
        name: "Alice2".to_string(),
        connection_id: 1001,
    })
    .unwrap();

    room.process_messages();

    // Should only have one participant
    assert_eq!(room.participant_count(), 1);
}

#[test]
#[should_panic(expected = "not in room")]
fn test_announce_track_without_participant() {
    let state = create_test_distributed_state();
    let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), state);

    // Try to announce track without adding participant
    tx.send(RoomActorMessage::AnnounceTrack {
        track_id: 1000,
        participant_id: 99,
        kind: MediaKind::Video,
    })
    .unwrap();

    room.process_messages();
}
