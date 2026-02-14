//! Integration tests for SWIM gossip protocol.
//!
//! These tests verify the protocol behavior across multiple nodes,
//! including cluster formation, failure detection, and state propagation.

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use nexus_state::gossip::{
    GossipConfig, GossipMessage, MembershipList, PeerState,
    StateUpdate, SwimProtocol, MAX_PEERS, MAX_PIGGYBACK_UPDATES,
};
use nexus_state::types::Dot;
use nexus_state::GossipError;

/// Helper to create a localhost address with port 0 (auto-assign)
fn localhost_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Helper to wait for a condition with timeout
#[allow(dead_code)]
fn wait_for<F>(mut condition: F, timeout_ms: u64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }

    false
}

// =============================================================================
// Two-Node Cluster Tests
// =============================================================================

#[test]
fn test_two_node_cluster_formation() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();

    // Node1 adds Node2 as seed peer
    node1.add_seed_peer(2, node2_addr).unwrap();

    // Run a few cycles
    for _ in 0..5 {
        node1.run_probe_cycle().unwrap();
        node1.recv_loop_iteration().unwrap();

        node2.run_probe_cycle().unwrap();
        node2.recv_loop_iteration().unwrap();

        thread::sleep(Duration::from_millis(10));
    }

    // Both nodes should know about each other
    assert!(node1.membership().find_peer(2).is_some());
    assert!(node2.membership().find_peer(1).is_some());
}

#[test]
fn test_two_node_ping_ack() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();

    // Node1 sends initial ping to Node2
    node1.add_seed_peer(2, node2_addr).unwrap();

    // Wait for ping to arrive
    thread::sleep(Duration::from_millis(10));

    // Node2 receives ping and sends ack
    node2.recv_loop_iteration().unwrap();

    // Wait for ack to arrive
    thread::sleep(Duration::from_millis(10));

    // Node1 receives ack
    node1.recv_loop_iteration().unwrap();

    // Verify stats
    let stats1 = node1.stats().snapshot();
    assert_eq!(stats1.pings_sent, 1);
    assert_eq!(stats1.acks_received, 1);
}

// =============================================================================
// Three-Node Cluster Tests
// =============================================================================

#[test]
fn test_three_node_cluster_formation() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config.clone()).unwrap();
    let mut node3 = SwimProtocol::new(3, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();
    let node3_addr = node3.local_addr();

    // Node1 is the seed, Node2 and Node3 connect to it
    node1.add_seed_peer(2, node2_addr).unwrap();
    node1.add_seed_peer(3, node3_addr).unwrap();

    // Run protocol for all nodes
    for _ in 0..10 {
        node1.run_probe_cycle().unwrap();
        for _ in 0..3 {
            node1.recv_loop_iteration().unwrap();
        }

        node2.run_probe_cycle().unwrap();
        for _ in 0..3 {
            node2.recv_loop_iteration().unwrap();
        }

        node3.run_probe_cycle().unwrap();
        for _ in 0..3 {
            node3.recv_loop_iteration().unwrap();
        }

        thread::sleep(Duration::from_millis(10));
    }

    // Node1 should know about both Node2 and Node3
    assert!(node1.membership().find_peer(2).is_some());
    assert!(node1.membership().find_peer(3).is_some());
}

// =============================================================================
// State Propagation Tests
// =============================================================================

#[test]
fn test_state_update_piggyback() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();

    // Node1 broadcasts a state update
    let dot = Dot::new(1, 1);
    let update = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 42,
        dot,
    };
    node1.broadcast_state_update(update);

    // Node1 adds Node2 (this will piggyback the update)
    node1.add_seed_peer(2, node2_addr).unwrap();

    // Wait for message
    thread::sleep(Duration::from_millis(10));

    // Node2 receives the ping with piggybacked update
    node2.recv_loop_iteration().unwrap();

    // Check Node2 received the update
    let stats2 = node2.stats().snapshot();
    assert!(stats2.state_updates_received >= 1);
}

#[test]
fn test_multiple_state_updates() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();

    // Broadcast multiple updates
    for i in 0..5 {
        let dot = Dot::new(1, (i + 1) as u64);
        let update = StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: i as u64,
            dot,
        };
        node1.broadcast_state_update(update);
    }

    // Connect nodes
    node1.add_seed_peer(2, node2_addr).unwrap();

    // Run communication
    for _ in 0..5 {
        node1.run_probe_cycle().unwrap();
        node1.recv_loop_iteration().unwrap();

        node2.run_probe_cycle().unwrap();
        node2.recv_loop_iteration().unwrap();

        thread::sleep(Duration::from_millis(10));
    }

    // Node2 should have received updates
    let stats2 = node2.stats().snapshot();
    assert!(stats2.state_updates_received > 0);
}

// =============================================================================
// Failure Detection Tests
// =============================================================================

#[test]
fn test_suspicion_on_timeout() {
    // Use very short timeouts for testing
    let config = GossipConfig::new()
        .with_probe_interval(10)
        .with_ping_timeout(20)
        .with_suspect_timeout(50);

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config).unwrap();

    // Add a fake peer that won't respond
    let fake_addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();
    node1.membership_mut().add_peer(99, fake_addr).unwrap();

    // Run probe cycles until timeout (needs at least 2 ping timeout cycles)
    // - First timeout: indirect probes are requested
    // - Second timeout: peer is marked suspect
    // Give it plenty of cycles to handle timing variability
    for _ in 0..50 {
        node1.run_probe_cycle().unwrap();
        node1.recv_loop_iteration().unwrap();
        thread::sleep(Duration::from_millis(15));
    }

    // Peer should eventually be marked as suspect or dead
    if let Some(peer) = node1.membership().find_peer(99) {
        assert!(
            peer.state() == PeerState::Suspect || peer.state() == PeerState::Dead,
            "Peer should be suspect or dead, got {:?}",
            peer.state()
        );
    }
}

#[test]
fn test_refutation_increments_incarnation() {
    let config = GossipConfig::for_testing();
    let mut node1 = SwimProtocol::new(1, localhost_addr(), config).unwrap();

    let initial_incarnation = node1.membership().local_incarnation();

    // Simulate receiving a suspect message about self
    let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let msg = GossipMessage::Suspect {
        actor_id: 1, // Self
        incarnation: initial_incarnation,
    };

    node1.handle_message(msg, source).unwrap();

    // Incarnation should have been incremented
    let new_incarnation = node1.membership().local_incarnation();
    assert!(
        new_incarnation > initial_incarnation,
        "Incarnation should have increased"
    );
}

// =============================================================================
// Message Encoding/Decoding Tests
// =============================================================================

#[test]
fn test_message_roundtrip_all_types() {
    let messages = vec![
        GossipMessage::Ping {
            from: 1,
            incarnation: 100,
            piggyback: vec![],
        },
        GossipMessage::Ack {
            from: 2,
            incarnation: 200,
            piggyback: vec![],
        },
        GossipMessage::PingReq {
            from: 1,
            target: 3,
            target_addr: "192.168.1.1:7946".parse().unwrap(),
            requester_addr: "192.168.1.2:7946".parse().unwrap(),
        },
        GossipMessage::Suspect {
            actor_id: 5,
            incarnation: 50,
        },
        GossipMessage::Alive {
            actor_id: 6,
            incarnation: 60,
        },
        GossipMessage::Dead { actor_id: 7 },
    ];

    for msg in messages {
        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg, "Message roundtrip failed");
    }
}

#[test]
fn test_message_with_max_piggyback() {
    let mut piggyback = Vec::with_capacity(MAX_PIGGYBACK_UPDATES);
    for i in 0..MAX_PIGGYBACK_UPDATES {
        let dot = Dot::new(1, (i + 1) as u64);
        piggyback.push(StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: i as u64,
            dot,
        });
    }

    let msg = GossipMessage::Ping {
        from: 1,
        incarnation: 1,
        piggyback,
    };

    let encoded = msg.encode();
    let decoded = GossipMessage::decode(&encoded).unwrap();

    if let GossipMessage::Ping {
        piggyback: decoded_pb,
        ..
    } = decoded
    {
        assert_eq!(decoded_pb.len(), MAX_PIGGYBACK_UPDATES);
    } else {
        panic!("Expected Ping message");
    }
}

// =============================================================================
// MembershipList Tests
// =============================================================================

#[test]
fn test_membership_capacity() {
    let mut list = MembershipList::new(0);

    // Fill to capacity
    for i in 1..=MAX_PEERS {
        let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
        if i < MAX_PEERS {
            list.add_peer(i as u64, addr).unwrap();
        }
    }

    assert_eq!(list.peer_count() as usize, MAX_PEERS - 1);
}

#[test]
fn test_membership_state_transitions() {
    let mut list = MembershipList::new(0);
    let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();

    // Add peer
    list.add_peer(1, addr).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Alive);

    // Alive → Suspect
    list.mark_suspect(1, 0).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Suspect);

    // Suspect → Dead
    list.mark_dead(1).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Dead);

    // Dead → Alive (resurrection with higher incarnation)
    list.update_state(1, PeerState::Alive, u64::MAX).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Alive);
}

#[test]
fn test_membership_refutation() {
    let mut list = MembershipList::new(0);
    let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();

    list.add_peer(1, addr).unwrap();

    // Mark as suspect with incarnation 5
    list.mark_suspect(1, 5).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Suspect);

    // Try to refute with same incarnation (should fail)
    let result = list.update_state(1, PeerState::Alive, 5);
    assert!(result.is_err());
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Suspect);

    // Refute with higher incarnation (should succeed)
    list.update_state(1, PeerState::Alive, 6).unwrap();
    assert_eq!(list.find_peer(1).unwrap().state(), PeerState::Alive);
    assert_eq!(list.find_peer(1).unwrap().incarnation(), 6);
}

// =============================================================================
// Protocol Stats Tests
// =============================================================================

#[test]
fn test_protocol_stats_tracking() {
    let config = GossipConfig::for_testing();

    let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
    let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

    let node2_addr = node2.local_addr();

    // Initial state
    let stats1 = node1.stats().snapshot();
    assert_eq!(stats1.pings_sent, 0);
    assert_eq!(stats1.acks_received, 0);

    // Add peer (sends ping)
    node1.add_seed_peer(2, node2_addr).unwrap();

    let stats1 = node1.stats().snapshot();
    assert_eq!(stats1.pings_sent, 1);

    // Process on node2 and back
    thread::sleep(Duration::from_millis(10));
    node2.recv_loop_iteration().unwrap();
    thread::sleep(Duration::from_millis(10));
    node1.recv_loop_iteration().unwrap();

    let stats1 = node1.stats().snapshot();
    assert_eq!(stats1.acks_received, 1);
}

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_config_validation() {
    // Valid configs
    assert!(GossipConfig::default().validate().is_ok());
    assert!(GossipConfig::for_lan().validate().is_ok());
    assert!(GossipConfig::for_wan().validate().is_ok());
    assert!(GossipConfig::for_testing().validate().is_ok());

    // Invalid: zero probe interval
    let mut config = GossipConfig::default();
    config.probe_interval_ms = 0;
    assert!(config.validate().is_err());

    // Invalid: suspect timeout not greater than ping timeout
    let mut config = GossipConfig::default();
    config.suspect_timeout_ms = config.ping_timeout_ms;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_builder() {
    let config = GossipConfig::new()
        .with_probe_interval(500)
        .with_ping_timeout(100)
        .with_suspect_timeout(2000)
        .with_fanout(5)
        .with_max_piggyback_updates(8);

    assert_eq!(config.probe_interval_ms, 500);
    assert_eq!(config.ping_timeout_ms, 100);
    assert_eq!(config.suspect_timeout_ms, 2000);
    assert_eq!(config.fanout, 5);
    assert_eq!(config.max_piggyback_updates, 8);

    assert!(config.validate().is_ok());
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_error_peer_not_found() {
    let mut list = MembershipList::new(0);

    let result = list.remove_peer(99);
    assert!(matches!(result, Err(GossipError::PeerNotFound { actor_id: 99 })));
}

#[test]
fn test_error_invalid_state_transition() {
    let mut list = MembershipList::new(0);
    let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();

    list.add_peer(1, addr).unwrap();
    list.mark_suspect(1, 5).unwrap();

    // Cannot go back to Alive without higher incarnation
    let result = list.update_state(1, PeerState::Alive, 4);
    assert!(matches!(
        result,
        Err(GossipError::InvalidStateTransition { .. })
    ));
}
