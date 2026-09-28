//! Robustness of the gossip receive path against untrusted datagrams.
//!
//! Release builds abort on panic, and the SWIM socket accepts datagrams from
//! anyone, so no received bytes may reach an assert. Each test sends crafted
//! bytes either to a live node's socket (then runs the receive loop and a probe
//! cycle) or straight into `SwimProtocol::handle_datagram`, the function the
//! receive loop calls, with a `DistributedState` attached so the apply paths run.

use std::cell::RefCell;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use nexus_state::gossip::types::MAX_MESSAGE_SIZE;
use nexus_state::gossip::{GossipConfig, SwimProtocol};
use nexus_state::{DistributedState, DistributedStateConfig, MAX_ACTORS};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};

const LOCAL_ACTOR: u64 = 1;
const PEER_ACTOR: u64 = 2;
const ROOM: u32 = 7;

// Message and update tags (wire format of `gossip::types`).
const MSG_PING: u8 = 0;
const MSG_ACK: u8 = 1;
const MSG_PING_REQ: u8 = 2;
const MSG_SUSPECT: u8 = 3;
const MSG_ALIVE: u8 = 4;
const MSG_DEAD: u8 = 5;
const MSG_STATE_SNAPSHOT: u8 = 7;
const UPDATE_PARTICIPANT_ADDED: u8 = 0;
const UPDATE_TRACK_UPDATED: u8 = 2;
const UPDATE_SUBSCRIPTION_ADDED: u8 = 3;
const UPDATE_RELAY_SUBSCRIBE: u8 = 5;

/// A node under test: protocol, attached state, and a peer socket that
/// receives the node's responses (so sends succeed and go somewhere).
struct Node {
    swim: SwimProtocol,
    state: Arc<DistributedState>,
    peer: UdpSocket,
}

impl Node {
    fn new() -> Self {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut swim = SwimProtocol::new(LOCAL_ACTOR, bind, GossipConfig::for_testing()).unwrap();
        let config = DistributedStateConfig::with_limits(LOCAL_ACTOR, 16, 64, 1024);
        let state = Arc::new(DistributedState::new(config));
        state.create_room(ROOM, "room".to_string(), 100).unwrap();
        swim.set_distributed_state(state.clone());
        swim.set_anti_entropy_interval(1);
        let peer = UdpSocket::bind(bind).unwrap();
        peer.set_nonblocking(true).unwrap();
        Self { swim, state, peer }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer.local_addr().unwrap()
    }

    /// Feed bytes through the receive path's decode + handle step.
    fn feed(&mut self, bytes: &[u8]) {
        let from = self.peer_addr();
        let _ = self.swim.handle_datagram(bytes, from);
    }

    /// Send bytes to the node's socket, then run its receive loop and a probe cycle.
    fn send(&mut self, bytes: &[u8]) {
        self.peer.send_to(bytes, self.swim.local_addr()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let _ = self.swim.recv_loop_iteration();
        let _ = self.swim.run_probe_cycle();
    }

    fn dropped(&self) -> u64 {
        self.swim.stats().snapshot().messages_dropped
    }

    /// Nothing from the network landed in the CRDT state.
    fn assert_state_untouched(&self) {
        assert_eq!(self.state.participant_count(ROOM), 0);
        assert_eq!(self.state.track_count(), 0);
        assert_eq!(self.state.subscription_count(), 0);
        assert_eq!(self.state.room_count(), 1);
        self.state.assert_crdt_invariants();
    }
}

// -----------------------------------------------------------------------------
// Byte builders (written by hand so any field can be made invalid)
// -----------------------------------------------------------------------------

fn header(tag: u8, from: u64, incarnation: u64) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&from.to_be_bytes());
    bytes.extend_from_slice(&incarnation.to_be_bytes());
    bytes
}

/// A ping from `PEER_ACTOR` carrying the given raw updates.
fn ping_with(updates: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header(MSG_PING, PEER_ACTOR, 1);
    bytes.extend_from_slice(&(updates.len() as u16).to_be_bytes());
    for update in updates {
        bytes.extend_from_slice(&(update.len() as u16).to_be_bytes());
        bytes.extend_from_slice(update);
    }
    bytes
}

fn participant_added(room: u32, participant: u64, dot_actor: u64, clock: u64) -> Vec<u8> {
    let mut bytes = vec![UPDATE_PARTICIPANT_ADDED];
    bytes.extend_from_slice(&room.to_be_bytes());
    bytes.extend_from_slice(&participant.to_be_bytes());
    bytes.extend_from_slice(&dot_actor.to_be_bytes());
    bytes.extend_from_slice(&clock.to_be_bytes());
    bytes
}

fn track_updated(track: u64, timestamp: u64, actor: u64) -> Vec<u8> {
    let mut bytes = vec![UPDATE_TRACK_UPDATED];
    bytes.extend_from_slice(&track.to_be_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 96, 0, 0, 1, 0]); // type, content, codec, kbps
    bytes.extend_from_slice(&PEER_ACTOR.to_be_bytes()); // owner_node
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&actor.to_be_bytes());
    bytes
}

fn subscription_added(track: u64, participant: u64, dot_actor: u64, clock: u64) -> Vec<u8> {
    let mut bytes = vec![UPDATE_SUBSCRIPTION_ADDED];
    bytes.extend_from_slice(&track.to_be_bytes());
    bytes.extend_from_slice(&participant.to_be_bytes());
    bytes.extend_from_slice(&dot_actor.to_be_bytes());
    bytes.extend_from_slice(&clock.to_be_bytes());
    bytes
}

fn relay_subscribe(track: u64, requester: u64) -> Vec<u8> {
    let mut bytes = vec![UPDATE_RELAY_SUBSCRIBE];
    bytes.extend_from_slice(&track.to_be_bytes());
    bytes.extend_from_slice(&requester.to_be_bytes());
    bytes
}

fn ipv4(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else {
        panic!("test addresses are IPv4")
    };
    let mut bytes = vec![0];
    bytes.extend_from_slice(&v4.ip().octets());
    bytes.extend_from_slice(&v4.port().to_be_bytes());
    bytes
}

// -----------------------------------------------------------------------------
// Transport
// -----------------------------------------------------------------------------

#[test]
fn empty_datagram_is_dropped() {
    let mut node = Node::new();
    node.send(&[]);
    assert_eq!(node.swim.transport().stats().snapshot().recv_errors, 1);
    // The node still works: a valid ping afterwards is handled
    node.send(&ping_with(&[]));
    assert!(node.swim.membership().find_peer(PEER_ACTOR).is_some());
    node.feed(&[]);
    assert_eq!(node.dropped(), 1);
}

#[test]
fn oversized_datagram_is_dropped() {
    let mut node = Node::new();
    let mut bytes = ping_with(&[]);
    bytes.resize(MAX_MESSAGE_SIZE + 100, 0xAB);
    node.send(&bytes); // kernel truncates to the buffer; still valid framing
    node.feed(&bytes);
    assert_eq!(node.dropped(), 1);
}

// -----------------------------------------------------------------------------
// Piggybacked state updates with fields that used to assert
// -----------------------------------------------------------------------------

#[test]
fn invalid_participant_updates_are_ignored() {
    let mut node = Node::new();
    let updates = [
        participant_added(0, 5, PEER_ACTOR, 1),        // room 0
        participant_added(u32::MAX, 5, PEER_ACTOR, 1), // room > u32::MAX / 2
        participant_added(u32::MAX / 2 + 1, 5, PEER_ACTOR, 1), // just above the bound
        participant_added(ROOM, 0, PEER_ACTOR, 1),     // participant 0
        participant_added(ROOM, 5, MAX_ACTORS as u64, 1), // dot actor out of range
        participant_added(ROOM, 5, u64::MAX, 1),       // dot actor far out of range
        participant_added(ROOM, 5, PEER_ACTOR, 0),     // dot clock 0
    ];
    for update in &updates {
        node.send(&ping_with(std::slice::from_ref(update)));
        node.feed(&ping_with(std::slice::from_ref(update)));
    }
    node.feed(&ping_with(&updates));
    node.assert_state_untouched();
    // The pings themselves were valid: the sender is a peer now
    assert!(node.swim.membership().find_peer(PEER_ACTOR).is_some());
}

#[test]
fn invalid_track_updates_are_ignored() {
    let mut node = Node::new();
    let updates = [
        track_updated(0, 5, PEER_ACTOR),                // track 0
        track_updated(u64::MAX, 5, PEER_ACTOR),         // track > u64::MAX / 2
        track_updated(u64::MAX / 2 + 1, 5, PEER_ACTOR), // just above the bound
        track_updated(9, 0, PEER_ACTOR),                // timestamp 0 (LWWReg)
        track_updated(9, 5, MAX_ACTORS as u64),         // actor out of range
    ];
    for update in &updates {
        node.send(&ping_with(std::slice::from_ref(update)));
        node.feed(&ping_with(std::slice::from_ref(update)));
    }
    node.assert_state_untouched();
}

#[test]
fn invalid_subscription_updates_are_ignored() {
    let mut node = Node::new();
    let updates = [
        subscription_added(0, 5, PEER_ACTOR, 1),        // track 0
        subscription_added(9, 0, PEER_ACTOR, 1),        // participant 0
        subscription_added(u64::MAX, 5, PEER_ACTOR, 1), // track out of range
        subscription_added(9, 5, MAX_ACTORS as u64, 1), // dot actor out of range
        subscription_added(9, 5, PEER_ACTOR, 0),        // dot clock 0
    ];
    for update in &updates {
        node.send(&ping_with(std::slice::from_ref(update)));
        node.feed(&ping_with(std::slice::from_ref(update)));
    }
    node.assert_state_untouched();
}

#[test]
fn valid_subscription_update_round_trips() {
    // The subscription decoder reads the layout the encoder writes
    let mut node = Node::new();
    node.feed(&ping_with(&[subscription_added(9, 5, PEER_ACTOR, 3)]));
    assert!(node.state.has_subscription(9, 5));
}

#[test]
fn invalid_relay_updates_are_ignored() {
    let mut node = Node::new();
    for update in [relay_subscribe(0, 3), relay_subscribe(9, 0)] {
        node.send(&ping_with(std::slice::from_ref(&update)));
        node.feed(&ping_with(std::slice::from_ref(&update)));
    }
    assert!(node.swim.drain_relay_events().is_empty());
    node.feed(&ping_with(&[relay_subscribe(9, 3)]));
    assert_eq!(node.swim.drain_relay_events().len(), 1);
}

#[test]
fn unknown_update_tag_is_skipped() {
    let mut node = Node::new();
    node.feed(&ping_with(&[vec![7; 29], vec![255; 43]]));
    node.assert_state_untouched();
    assert!(node.swim.membership().find_peer(PEER_ACTOR).is_some());
}

// -----------------------------------------------------------------------------
// Framing: tags, lengths, counts
// -----------------------------------------------------------------------------

#[test]
fn malformed_framing_is_dropped() {
    let mut node = Node::new();
    let mut truncated_update = header(MSG_PING, PEER_ACTOR, 1);
    truncated_update.extend_from_slice(&1u16.to_be_bytes());
    truncated_update.extend_from_slice(&1000u16.to_be_bytes()); // length past the end
    truncated_update.extend_from_slice(&participant_added(ROOM, 5, PEER_ACTOR, 1));

    let mut huge_count = header(MSG_PING, PEER_ACTOR, 1);
    huge_count.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut snapshot_huge = header(MSG_STATE_SNAPSHOT, PEER_ACTOR, 1);
    snapshot_huge.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut snapshot_truncated = header(MSG_STATE_SNAPSHOT, PEER_ACTOR, 1);
    snapshot_truncated.extend_from_slice(&3u16.to_be_bytes());
    snapshot_truncated.extend_from_slice(&[0; 20]);

    let cases: [Vec<u8>; 9] = [
        vec![8],                        // unknown message tag
        vec![255; 64],                  // unknown message tag
        vec![MSG_PING],                 // header truncated
        header(MSG_ACK, PEER_ACTOR, 1), // count missing
        truncated_update,
        huge_count,
        snapshot_huge,
        snapshot_truncated,
        vec![
            MSG_PING_REQ,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            9,
        ], // bad addr tag
    ];
    for bytes in &cases {
        node.send(bytes);
        node.feed(bytes);
    }
    // Each case went through the socket and through handle_datagram
    assert_eq!(node.dropped(), 2 * cases.len() as u64);
    node.assert_state_untouched();
    assert_eq!(node.swim.membership().peer_count(), 0);
}

// -----------------------------------------------------------------------------
// Membership: sender-supplied actor ids and incarnations
// -----------------------------------------------------------------------------

#[test]
fn actor_ids_out_of_range_are_dropped() {
    let mut node = Node::new();
    let out = MAX_ACTORS as u64;
    let mut cases = vec![
        ping_from(out),
        header(MSG_SUSPECT, out, 1),
        header(MSG_ALIVE, u64::MAX, 1),
        header(MSG_DEAD, out, 0)[..9].to_vec(),
    ];
    let mut ping_req = header(MSG_PING_REQ, PEER_ACTOR, 0)[..9].to_vec();
    ping_req.extend_from_slice(&out.to_be_bytes());
    ping_req.extend_from_slice(&ipv4(node.peer_addr()));
    ping_req.extend_from_slice(&ipv4(node.peer_addr()));
    cases.push(ping_req);
    for bytes in &cases {
        node.send(bytes);
        node.feed(bytes);
    }
    assert_eq!(node.dropped(), 2 * cases.len() as u64);
    assert_eq!(node.swim.membership().peer_count(), 0);
}

fn ping_from(from: u64) -> Vec<u8> {
    let mut bytes = header(MSG_PING, from, 1);
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
}

#[test]
fn messages_about_the_local_actor_do_not_panic() {
    let mut node = Node::new();
    // Ping / snapshot "from" ourselves: not added as a peer
    node.feed(&ping_from(LOCAL_ACTOR));
    let mut snapshot = header(MSG_STATE_SNAPSHOT, LOCAL_ACTOR, 1);
    snapshot.extend_from_slice(&1u16.to_be_bytes());
    snapshot.extend_from_slice(&LOCAL_ACTOR.to_be_bytes());
    snapshot.extend_from_slice(&1u64.to_be_bytes());
    snapshot.push(2); // "we are dead"
    snapshot.extend_from_slice(&0u16.to_be_bytes());
    node.feed(&snapshot);
    assert_eq!(node.swim.membership().peer_count(), 0);

    // Ping-req asking us to probe ourselves: dropped
    let mut ping_req = header(MSG_PING_REQ, PEER_ACTOR, 0)[..9].to_vec();
    ping_req.extend_from_slice(&LOCAL_ACTOR.to_be_bytes());
    ping_req.extend_from_slice(&ipv4(node.peer_addr()));
    ping_req.extend_from_slice(&ipv4(node.peer_addr()));
    node.send(&ping_req);
    node.feed(&ping_req);
    assert_eq!(node.dropped(), 2);

    // Dead / suspect about ourselves; alive with the largest incarnation
    node.feed(&header(MSG_DEAD, LOCAL_ACTOR, 0)[..9]);
    node.feed(&header(MSG_SUSPECT, LOCAL_ACTOR, u64::MAX));
    node.feed(&header(MSG_ALIVE, LOCAL_ACTOR, u64::MAX));
    assert_eq!(node.swim.membership().local_incarnation(), u64::MAX);
    node.feed(&header(MSG_SUSPECT, LOCAL_ACTOR, u64::MAX)); // refute at the maximum
    assert_eq!(node.swim.membership().local_incarnation(), u64::MAX);
    let _ = node.swim.run_probe_cycle();
}

#[test]
fn full_membership_snapshot_fits_in_a_datagram() {
    // Pings from many actor ids fill the membership list; the next
    // anti-entropy snapshot must still encode within MAX_MESSAGE_SIZE.
    let mut node = Node::new();
    let base = node.peer_addr();
    for actor in 0..MAX_ACTORS as u64 {
        let source = SocketAddr::new(base.ip(), base.port());
        let _ = node.swim.handle_datagram(&ping_from(actor), source);
    }
    assert_eq!(node.swim.membership().peer_count(), MAX_ACTORS as u32 - 1);
    // First cycle probes and runs anti-entropy (interval 1 ms)
    node.swim.run_probe_cycle().unwrap();
    std::thread::sleep(Duration::from_millis(60));
    node.swim.run_probe_cycle().unwrap();
}

// -----------------------------------------------------------------------------
// Property tests: arbitrary bytes through the receive path
// -----------------------------------------------------------------------------

/// Run `strategy`'s values through one long-lived node, so state (membership,
/// piggyback queue, CRDTs) accumulates across cases like on a real socket.
fn fuzz_one_node(strategy: impl Strategy<Value = Vec<u8>>, cases: u32) {
    let node = RefCell::new(Node::new());
    let config = ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new(config);
    let result = runner.run(&strategy, |bytes| {
        let mut node = node.borrow_mut();
        node.feed(&bytes);
        let _ = node.swim.run_probe_cycle();
        node.state.assert_crdt_invariants();
        Ok(())
    });
    result.unwrap();
}

#[test]
fn proptest_random_bytes() {
    fuzz_one_node(proptest::collection::vec(any::<u8>(), 0..1500), 2000);
}

/// A small id (to reach the apply paths, including 0) or any u64.
fn small_or_any() -> impl Strategy<Value = u64> {
    prop_oneof![0u64..10, any::<u64>()]
}

/// One piggybacked update: each known tag with random (often small) fields,
/// or an arbitrary tag with an arbitrary body.
fn random_update() -> impl Strategy<Value = Vec<u8>> {
    let room = prop_oneof![Just(ROOM), 0u32..10, any::<u32>()];
    prop_oneof![
        (
            0u8..=1,
            room,
            small_or_any(),
            small_or_any(),
            small_or_any()
        )
            .prop_map(|(tag, room, participant, actor, clock)| {
                let mut bytes = participant_added(room, participant, actor, clock);
                bytes[0] = tag;
                bytes
            }),
        (small_or_any(), small_or_any(), small_or_any())
            .prop_map(|(track, timestamp, actor)| track_updated(track, timestamp, actor)),
        (
            3u8..=4,
            small_or_any(),
            small_or_any(),
            small_or_any(),
            small_or_any()
        )
            .prop_map(|(tag, track, participant, actor, clock)| {
                let mut bytes = subscription_added(track, participant, actor, clock);
                bytes[0] = tag;
                bytes
            }),
        (5u8..=6, small_or_any(), small_or_any()).prop_map(|(tag, track, requester)| {
            let mut bytes = relay_subscribe(track, requester);
            bytes[0] = tag;
            bytes
        }),
        (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..50)).prop_map(|(tag, body)| {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(&body);
            bytes
        }),
    ]
}

/// A message with a valid tag and header shape and random payload.
fn structured_message() -> impl Strategy<Value = Vec<u8>> {
    let from = prop_oneof![0u64..4, 0u64..(MAX_ACTORS as u64 + 2), any::<u64>()];
    (
        0u8..=8,
        from,
        any::<u64>(),
        proptest::collection::vec(random_update(), 0..=17),
        proptest::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(tag, from, incarnation, updates, tail)| {
            let mut bytes = header(tag, from, incarnation);
            if tag == MSG_PING || tag == MSG_ACK || tag == MSG_STATE_SNAPSHOT {
                if tag == MSG_STATE_SNAPSHOT {
                    // Members: random bytes chunked as entries, then updates
                    let members = tail.len() / 17;
                    bytes.extend_from_slice(&(members as u16).to_be_bytes());
                    bytes.extend_from_slice(&tail[..members * 17]);
                }
                bytes.extend_from_slice(&(updates.len() as u16).to_be_bytes());
                for update in &updates {
                    bytes.extend_from_slice(&(update.len() as u16).to_be_bytes());
                    bytes.extend_from_slice(update);
                }
            } else {
                bytes.extend_from_slice(&tail);
            }
            bytes
        })
}

#[test]
fn proptest_structured_messages() {
    fuzz_one_node(structured_message(), 3000);
}
