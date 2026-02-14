//! ParticipantActor unit tests

use nexus_actor::{
    ActorState, ConnectionState, MediaKind, ParticipantActor, ParticipantActorMessage,
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
fn test_spawn_participant() {
    let state = create_test_distributed_state();
    let (participant, _tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    assert_eq!(participant.id(), 1);
    assert_eq!(participant.room_id(), 100);
    assert_eq!(participant.name(), "Alice");
    assert_eq!(participant.connection_id(), 1000);
    assert_eq!(participant.state(), ActorState::Active);
    assert_eq!(participant.connection_state(), ConnectionState::Connecting);
    assert_eq!(participant.worker_id(), 0);
}

#[test]
#[should_panic(expected = "participant id must not be 0")]
fn test_spawn_zero_id() {
    let state = create_test_distributed_state();
    let _ = ParticipantActor::spawn(0, 100, "Alice".to_string(), 1000, 0, now_ns(), state);
}

#[test]
#[should_panic(expected = "room id must not be 0")]
fn test_spawn_zero_room_id() {
    let state = create_test_distributed_state();
    let _ = ParticipantActor::spawn(1, 0, "Alice".to_string(), 1000, 0, now_ns(), state);
}

#[test]
#[should_panic(expected = "connection id must not be 0")]
fn test_spawn_zero_connection_id() {
    let state = create_test_distributed_state();
    let _ = ParticipantActor::spawn(1, 100, "Alice".to_string(), 0, 0, now_ns(), state);
}

#[test]
#[should_panic(expected = "name too long")]
fn test_spawn_long_name() {
    let state = create_test_distributed_state();
    let long_name = "a".repeat(257);
    let _ = ParticipantActor::spawn(1, 100, long_name, 1000, 0, now_ns(), state);
}

#[test]
fn test_publish_track() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::PublishTrack {
        track_id: 1000,
        ssrc: 12345,
        kind: MediaKind::Video,
    })
    .unwrap();

    participant.process_messages();

    let tracks = participant.published_tracks();
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0], 1000);
}

#[test]
fn test_publish_multiple_tracks() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

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
fn test_unpublish_track() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Publish track
    tx.send(ParticipantActorMessage::PublishTrack {
        track_id: 1000,
        ssrc: 12345,
        kind: MediaKind::Video,
    })
    .unwrap();

    participant.process_messages();
    assert_eq!(participant.published_tracks().len(), 1);

    // Unpublish track
    tx.send(ParticipantActorMessage::UnpublishTrack { track_id: 1000 })
        .unwrap();

    participant.process_messages();
    assert_eq!(participant.published_tracks().len(), 0);
}

#[test]
fn test_subscribe_to_track() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::SubscribeToTrack {
        track_id: 2000,
        target_layer: 2,
    })
    .unwrap();

    participant.process_messages();

    let subs = participant.subscriptions();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0], 2000);
}

#[test]
fn test_unsubscribe_from_track() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Subscribe
    tx.send(ParticipantActorMessage::SubscribeToTrack {
        track_id: 2000,
        target_layer: 2,
    })
    .unwrap();

    participant.process_messages();
    assert_eq!(participant.subscriptions().len(), 1);

    // Unsubscribe
    tx.send(ParticipantActorMessage::UnsubscribeFromTrack { track_id: 2000 })
        .unwrap();

    participant.process_messages();
    assert_eq!(participant.subscriptions().len(), 0);
}

#[test]
fn test_update_connection_state() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::UpdateConnectionState {
        session_id: 5000,
        state: ConnectionState::Connected,
    })
    .unwrap();

    participant.process_messages();

    assert_eq!(participant.connection_state(), ConnectionState::Connected);
    assert_eq!(participant.session_id(), 5000);
}

#[test]
fn test_update_metadata() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::UpdateMetadata {
        name: "Alice Updated".to_string(),
    })
    .unwrap();

    participant.process_messages();

    assert_eq!(participant.name(), "Alice Updated");
}

#[test]
fn test_terminate() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::Terminate).unwrap();

    let should_continue = participant.process_messages();
    assert!(!should_continue);
    assert_eq!(participant.state(), ActorState::Terminated);
}

#[test]
fn test_health_check() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::HealthCheck).unwrap();

    participant.process_messages();
    // Health check should not change state
    assert_eq!(participant.state(), ActorState::Active);
}

#[test]
fn test_message_processing_bounded() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Send more than MAX_MESSAGES_PER_ITERATION (100) health check messages
    // Health checks don't have capacity limits
    for _ in 0..150 {
        tx.send(ParticipantActorMessage::HealthCheck).unwrap();
    }

    // First call processes up to 100 messages
    let should_continue = participant.process_messages();
    assert!(should_continue);

    // Second call processes remaining messages
    let should_continue = participant.process_messages();
    assert!(should_continue);
    
    // Verify actor is still active
    assert_eq!(participant.state(), ActorState::Active);
}

#[test]
#[should_panic(expected = "track_id must not be 0")]
fn test_publish_zero_track_id() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    tx.send(ParticipantActorMessage::PublishTrack {
        track_id: 0,
        ssrc: 12345,
        kind: MediaKind::Video,
    })
    .unwrap();

    participant.process_messages();
}

#[test]
#[should_panic(expected = "already published")]
fn test_publish_duplicate_track() {
    let state = create_test_distributed_state();
    let (mut participant, tx) =
        ParticipantActor::spawn(1, 100, "Alice".to_string(), 1000, 0, now_ns(), state);

    // Publish same track twice
    tx.send(ParticipantActorMessage::PublishTrack {
        track_id: 1000,
        ssrc: 12345,
        kind: MediaKind::Video,
    })
    .unwrap();

    tx.send(ParticipantActorMessage::PublishTrack {
        track_id: 1000,
        ssrc: 12345,
        kind: MediaKind::Video,
    })
    .unwrap();

    participant.process_messages();
}
