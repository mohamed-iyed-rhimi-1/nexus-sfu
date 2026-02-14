//! Comprehensive tests for the TrackActor system
//!
//! Tests cover:
//! - Actor spawning and initialization
//! - State machine transitions
//! - Message handling
//! - Subscriber management
//! - Registry operations
//! - Supervisor policies

use std::net::SocketAddr;

use nexus_actor::*;

// ============================================================================
// TrackActor Spawn Tests
// ============================================================================

#[test]
fn test_track_actor_spawn() {
    let (actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    assert_eq!(actor.id(), 1);
    assert_eq!(actor.participant_id(), 100);
    assert_eq!(actor.ssrc(), 12345);
    assert_eq!(actor.kind(), MediaKind::Video);
    assert_eq!(actor.worker_id(), 0);
    assert_eq!(actor.state(), ActorState::Active);
    assert_eq!(actor.health(), ActorHealth::Healthy);

    // Sender should be valid
    assert!(!sender.is_full());
}

#[test]
fn test_track_actor_spawn_audio() {
    let (actor, _) = TrackActor::spawn(2, 200, 54321, MediaKind::Audio, 5);

    assert_eq!(actor.id(), 2);
    assert_eq!(actor.kind(), MediaKind::Audio);
    assert_eq!(actor.worker_id(), 5);
}

#[test]
#[should_panic(expected = "track id must not be 0")]
fn test_track_actor_spawn_zero_id() {
    let _ = TrackActor::spawn(0, 100, 12345, MediaKind::Video, 0);
}

#[test]
#[should_panic(expected = "participant_id must not be 0")]
fn test_track_actor_spawn_zero_participant() {
    let _ = TrackActor::spawn(1, 0, 12345, MediaKind::Video, 0);
}

#[test]
#[should_panic(expected = "ssrc must not be 0")]
fn test_track_actor_spawn_zero_ssrc() {
    let _ = TrackActor::spawn(1, 100, 0, MediaKind::Video, 0);
}

#[test]
#[should_panic(expected = "worker_id must be < MAX_WORKERS")]
fn test_track_actor_spawn_invalid_worker() {
    let _ = TrackActor::spawn(1, 100, 12345, MediaKind::Video, MAX_WORKERS);
}

// ============================================================================
// State Transition Tests
// ============================================================================

#[test]
fn test_track_actor_state_transitions() {
    let (actor, _) = TrackActor::spawn(1, 100, 12345, MediaKind::Audio, 0);

    // Active -> Migrating
    actor.transition_state(ActorState::Active, ActorState::Migrating);
    assert_eq!(actor.state(), ActorState::Migrating);

    // Migrating -> Active
    actor.transition_state(ActorState::Migrating, ActorState::Active);
    assert_eq!(actor.state(), ActorState::Active);

    // Active -> Terminated
    actor.transition_state(ActorState::Active, ActorState::Terminated);
    assert_eq!(actor.state(), ActorState::Terminated);
}

#[test]
#[should_panic(expected = "invalid state transition")]
fn test_track_actor_invalid_transition_active_to_init() {
    let (actor, _) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    // Cannot go from Active to Initializing
    actor.transition_state(ActorState::Active, ActorState::Initializing);
}

#[test]
#[should_panic(expected = "invalid state transition")]
fn test_track_actor_invalid_transition_terminated_to_active() {
    let (actor, _) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    // Terminate first
    actor.transition_state(ActorState::Active, ActorState::Terminated);

    // Cannot go from Terminated to Active
    actor.transition_state(ActorState::Terminated, ActorState::Active);
}

// ============================================================================
// Message Handling Tests
// ============================================================================

#[test]
fn test_track_actor_subscribe_message() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Send subscribe message
    sender
        .send(TrackActorMessage::Subscribe {
            subscriber_id: 1,
            participant_id: 200,
            dest_addr: addr,
        })
        .unwrap();

    // Process messages
    assert!(actor.process_messages());
    assert_eq!(actor.subscriber_count(), 1);
    assert_eq!(actor.messages_processed(), 1);
}

#[test]
fn test_track_actor_unsubscribe_message() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Subscribe first
    sender
        .send(TrackActorMessage::Subscribe {
            subscriber_id: 1,
            participant_id: 200,
            dest_addr: addr,
        })
        .unwrap();
    actor.process_messages();
    assert_eq!(actor.subscriber_count(), 1);

    // Now unsubscribe
    sender
        .send(TrackActorMessage::Unsubscribe { subscriber_id: 1 })
        .unwrap();
    actor.process_messages();
    assert_eq!(actor.subscriber_count(), 0);
}

#[test]
fn test_track_actor_process_packet_message() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Add a subscriber first
    sender
        .send(TrackActorMessage::Subscribe {
            subscriber_id: 1,
            participant_id: 200,
            dest_addr: addr,
        })
        .unwrap();
    actor.process_messages();

    // Send packet
    let packet = PacketSlot::new(&[1, 2, 3, 4, 5]);
    sender
        .send(TrackActorMessage::ProcessPacket { packet })
        .unwrap();
    actor.process_messages();

    assert_eq!(actor.packets_received(), 1);
    assert_eq!(actor.packets_forwarded(), 1);
    assert_eq!(actor.packets_dropped(), 0);
}

#[test]
fn test_track_actor_packet_dropped_no_subscribers() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    // Send packet without subscribers
    let packet = PacketSlot::new(&[1, 2, 3, 4, 5]);
    sender
        .send(TrackActorMessage::ProcessPacket { packet })
        .unwrap();
    actor.process_messages();

    assert_eq!(actor.packets_received(), 1);
    assert_eq!(actor.packets_forwarded(), 0);
    assert_eq!(actor.packets_dropped(), 1);
}

#[test]
fn test_track_actor_terminate_message() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    // Send terminate
    sender.send(TrackActorMessage::Terminate).unwrap();

    // Process should return false
    assert!(!actor.process_messages());
    assert_eq!(actor.state(), ActorState::Terminated);
}

#[test]
fn test_track_actor_migration_messages() {
    let (mut actor, sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

    // Begin migration
    sender
        .send(TrackActorMessage::BeginMigration { target_worker_id: 5 })
        .unwrap();
    actor.process_messages();
    assert_eq!(actor.state(), ActorState::Migrating);

    // Complete migration
    sender.send(TrackActorMessage::CompleteMigration).unwrap();
    actor.process_messages();
    assert_eq!(actor.state(), ActorState::Active);
}

// ============================================================================
// Registry Tests
// ============================================================================

#[test]
fn test_actor_registry() {
    let registry = ActorRegistry::new();

    registry.register(1, 0);
    registry.register(2, 1);

    assert_eq!(registry.lookup(1), Some(0));
    assert_eq!(registry.lookup(2), Some(1));
    assert_eq!(registry.lookup(999), None);

    assert_eq!(registry.count(), 2);

    registry.unregister(1);
    assert_eq!(registry.lookup(1), None);
    assert_eq!(registry.count(), 1);
}

#[test]
fn test_actor_registry_update_location() {
    let registry = ActorRegistry::new();

    registry.register(1, 0);
    assert_eq!(registry.lookup(1), Some(0));

    assert!(registry.update_location(1, 5));
    assert_eq!(registry.lookup(1), Some(5));

    assert!(!registry.update_location(999, 0));
}

#[test]
fn test_actor_registry_tracks_on_worker() {
    let registry = ActorRegistry::new();

    registry.register(1, 0);
    registry.register(2, 1);
    registry.register(3, 0);

    let tracks = registry.tracks_on_worker(0);
    assert_eq!(tracks.len(), 2);
    assert!(tracks.contains(&1));
    assert!(tracks.contains(&3));
}

// ============================================================================
// Supervisor Tests
// ============================================================================

#[test]
fn test_actor_supervisor() {
    use nexus_actor::registry::ActorId;
    let actor_id = ActorId::track(1);
    let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Limited(3), 0);

    // Initially should allow restarts
    assert!(supervisor.should_restart(0));
}

#[test]
fn test_supervisor_restart_policy_never() {
    use nexus_actor::registry::ActorId;
    let actor_id = ActorId::track(1);
    let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Never, 0);

    assert!(!supervisor.should_restart(0));
}

#[test]
fn test_supervisor_restart_policy_limited() {
    use nexus_actor::registry::ActorId;
    let actor_id = ActorId::track(1);
    let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Limited(2), 0);

    // First two restarts allowed
    assert!(supervisor.should_restart(0));
    assert!(supervisor.should_restart(1));

    // Third restart not allowed
    assert!(!supervisor.should_restart(2));
}

// ============================================================================
// Subscriber List Tests
// ============================================================================

#[test]
fn test_subscriber_list_hot_cold() {
    let mut list = SubscriberList::new();
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Add 100 hot subscribers (max)
    for i in 1..=100 {
        list.add(Subscriber::new(i, 100 + i as u64, addr));
    }
    assert_eq!(list.hot.len(), 100);
    assert_eq!(list.cold.len(), 0);

    // Add one more, should go to cold
    list.add(Subscriber::new(101, 201, addr));
    assert_eq!(list.hot.len(), 100);
    assert_eq!(list.cold.len(), 1);
}

#[test]
fn test_subscriber_list_promote_demote() {
    let mut list = SubscriberList::new();
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    list.add(Subscriber::new(1, 100, addr));
    list.add(Subscriber::new(2, 101, addr));

    // Demote subscriber 1
    assert!(list.demote(1));
    assert_eq!(list.hot.len(), 1);
    assert_eq!(list.cold.len(), 1);

    // Promote subscriber 1
    assert!(list.promote(1));
    assert_eq!(list.hot.len(), 2);
    assert_eq!(list.cold.len(), 0);
}

// ============================================================================
// PacketSlot Tests
// ============================================================================

#[test]
fn test_packet_slot_shallow_clone() {
    let data = vec![1u8, 2, 3, 4, 5];
    let slot1 = PacketSlot::new(&data);
    let slot2 = slot1.clone_shallow();

    assert_eq!(slot1.len(), slot2.len());
    assert_eq!(slot1.as_slice(), slot2.as_slice());
}

#[test]
fn test_packet_slot_properties() {
    let data = vec![1u8, 2, 3, 4, 5];
    let slot = PacketSlot::new(&data);

    assert_eq!(slot.len(), 5);
    assert!(!slot.is_empty());
    assert_eq!(slot.as_slice(), &[1, 2, 3, 4, 5]);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_workflow() {
    // Create registry
    let registry = ActorRegistry::new();

    // Spawn actors
    let (mut actor1, sender1) = TrackActor::spawn(1, 100, 11111, MediaKind::Video, 0);
    let (mut actor2, sender2) = TrackActor::spawn(2, 101, 22222, MediaKind::Audio, 1);

    // Register in registry
    registry.register(actor1.id(), actor1.worker_id());
    registry.register(actor2.id(), actor2.worker_id());

    // Verify registry
    assert_eq!(registry.lookup(1), Some(0));
    assert_eq!(registry.lookup(2), Some(1));

    // Add subscribers
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    sender1
        .send(TrackActorMessage::Subscribe {
            subscriber_id: 1,
            participant_id: 200,
            dest_addr: addr,
        })
        .unwrap();
    sender2
        .send(TrackActorMessage::Subscribe {
            subscriber_id: 2,
            participant_id: 201,
            dest_addr: addr,
        })
        .unwrap();

    // Process messages
    actor1.process_messages();
    actor2.process_messages();

    // Send packets
    sender1
        .send(TrackActorMessage::ProcessPacket {
            packet: PacketSlot::new(&[1, 2, 3]),
        })
        .unwrap();
    sender2
        .send(TrackActorMessage::ProcessPacket {
            packet: PacketSlot::new(&[4, 5, 6]),
        })
        .unwrap();

    actor1.process_messages();
    actor2.process_messages();

    // Verify stats
    assert_eq!(actor1.packets_received(), 1);
    assert_eq!(actor2.packets_received(), 1);

    // Terminate actors
    sender1.send(TrackActorMessage::Terminate).unwrap();
    sender2.send(TrackActorMessage::Terminate).unwrap();

    actor1.process_messages();
    actor2.process_messages();

    assert_eq!(actor1.state(), ActorState::Terminated);
    assert_eq!(actor2.state(), ActorState::Terminated);

    // Unregister from registry
    registry.unregister(1);
    registry.unregister(2);

    assert_eq!(registry.count(), 0);
}
