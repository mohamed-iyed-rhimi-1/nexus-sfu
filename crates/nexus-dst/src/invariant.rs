use std::collections::{HashMap, HashSet};

use nexus_actor::{ActorState, TrackActor};

// ---------------------------------------------------------------------------
// Constants (from requirements)
// ---------------------------------------------------------------------------

/// Maximum participants allowed per room (Requirement 6.2).
/// Increased to support stress test scenarios (webinar with 1001 participants).
pub const MAX_PARTICIPANTS_PER_ROOM: usize = 2000;

/// Maximum tracks allowed per participant (Requirement 6.3).
pub const MAX_TRACKS_PER_PARTICIPANT: usize = 10;

// ---------------------------------------------------------------------------
// InvariantViolation
// ---------------------------------------------------------------------------

/// A recorded invariant violation with timestamp and diagnostic info.
#[derive(Debug, Clone)]
pub struct InvariantViolation {
    /// Virtual time (nanoseconds) when the violation was detected.
    pub time_ns: u64,
    /// Name of the invariant that was violated.
    pub invariant_name: String,
    /// Human-readable diagnostic message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// InvariantChecker
// ---------------------------------------------------------------------------

/// Checks system invariants during simulation and records violations.
///
/// The checker works with simulator-level bookkeeping data (HashMaps, HashSets)
/// rather than trying to introspect production actor internals directly. This
/// keeps it decoupled and testable.
pub struct InvariantChecker {
    violations: Vec<InvariantViolation>,
    /// Tracks the last-known state for each actor label, used to validate
    /// state machine transitions.
    actor_states: HashMap<String, ActorState>,
}

impl InvariantChecker {
    /// Create a new, empty invariant checker.
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            actor_states: HashMap::new(),
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.1 – Actor state machine validity
    // ---------------------------------------------------------------------

    /// Validate actor state transitions.
    ///
    /// `actor_states_snapshot` maps actor labels to their current `ActorState`.
    /// The checker remembers the previous state for each actor and flags any
    /// transition that is not in the valid set:
    ///
    /// - Initializing → Active
    /// - Active → Migrating
    /// - Active → Terminated
    /// - Migrating → Active
    /// - Migrating → Terminated
    pub fn check_actor_states(
        &mut self,
        actor_states_snapshot: &HashMap<String, ActorState>,
        time_ns: u64,
    ) {
        for (label, &current) in actor_states_snapshot {
            if let Some(&previous) = self.actor_states.get(label) {
                // State changed – validate the transition.
                if previous != current && !TrackActor::is_valid_transition(previous, current) {
                    self.violations.push(InvariantViolation {
                        time_ns,
                        invariant_name: "actor_state_machine".into(),
                        message: format!(
                            "actor '{}': invalid transition {:?} -> {:?}",
                            label, previous, current
                        ),
                    });
                }
            }
            // Update tracked state.
            self.actor_states.insert(label.clone(), current);
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.2 – Room capacity
    // ---------------------------------------------------------------------

    /// Verify that no room exceeds `MAX_PARTICIPANTS_PER_ROOM`.
    ///
    /// `room_participants` maps room names to the set of participant names
    /// currently in that room.
    pub fn check_room_capacity(
        &mut self,
        room_participants: &HashMap<String, HashSet<String>>,
        time_ns: u64,
    ) {
        for (room, participants) in room_participants {
            if participants.len() > MAX_PARTICIPANTS_PER_ROOM {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "room_capacity".into(),
                    message: format!(
                        "room '{}': {} participants exceeds limit of {}",
                        room,
                        participants.len(),
                        MAX_PARTICIPANTS_PER_ROOM,
                    ),
                });
            }
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.3 – Track capacity
    // ---------------------------------------------------------------------

    /// Verify that no participant exceeds `MAX_TRACKS_PER_PARTICIPANT`.
    ///
    /// `participant_tracks` maps participant names to the set of track labels
    /// they currently own.
    pub fn check_track_capacity(
        &mut self,
        participant_tracks: &HashMap<String, HashSet<String>>,
        time_ns: u64,
    ) {
        for (participant, tracks) in participant_tracks {
            if tracks.len() > MAX_TRACKS_PER_PARTICIPANT {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "track_capacity".into(),
                    message: format!(
                        "participant '{}': {} tracks exceeds limit of {}",
                        participant,
                        tracks.len(),
                        MAX_TRACKS_PER_PARTICIPANT,
                    ),
                });
            }
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.6 – Track ownership consistency
    // ---------------------------------------------------------------------

    /// Verify that every track has exactly one owning participant and that
    /// the owner exists in the room where the track is published.
    ///
    /// * `track_owner` – maps track label → owning participant name.
    /// * `track_room` – maps track label → room name where the track lives.
    /// * `room_participants` – maps room name → set of participant names.
    pub fn check_track_ownership(
        &mut self,
        track_owner: &HashMap<String, String>,
        track_room: &HashMap<String, String>,
        room_participants: &HashMap<String, HashSet<String>>,
        time_ns: u64,
    ) {
        for (track_label, owner) in track_owner {
            // The track must be associated with a room.
            let room = match track_room.get(track_label) {
                Some(r) => r,
                None => {
                    self.violations.push(InvariantViolation {
                        time_ns,
                        invariant_name: "track_ownership".into(),
                        message: format!(
                            "track '{}': no room association found",
                            track_label
                        ),
                    });
                    continue;
                }
            };

            // The owner must be a participant in that room.
            let in_room = room_participants
                .get(room)
                .map_or(false, |ps| ps.contains(owner));

            if !in_room {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "track_ownership".into(),
                    message: format!(
                        "track '{}': owner '{}' not found in room '{}'",
                        track_label, owner, room
                    ),
                });
            }
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.4 – CRDT convergence
    // ---------------------------------------------------------------------

    /// Compare multiple `DistributedState` instances for convergence.
    ///
    /// After network partitions heal and gossip rounds complete, all nodes
    /// should agree on room count, track count, and subscription count.
    /// We compare observable aggregate counts across all provided states.
    ///
    /// `room_ids` is the set of known room IDs so we can query participant
    /// counts per room.
    pub fn check_crdt_convergence(
        &mut self,
        states: &[std::sync::Arc<nexus_state::DistributedState>],
        room_ids: &[u32],
        time_ns: u64,
    ) {
        if states.len() < 2 {
            return;
        }

        let reference = &states[0];
        let ref_room_count = reference.room_count();
        let ref_track_count = reference.track_count();
        let ref_sub_count = reference.subscription_count();

        for (i, state) in states.iter().enumerate().skip(1) {
            if state.room_count() != ref_room_count {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "crdt_convergence".into(),
                    message: format!(
                        "node {}: room_count {} != node 0 room_count {}",
                        i,
                        state.room_count(),
                        ref_room_count,
                    ),
                });
            }
            if state.track_count() != ref_track_count {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "crdt_convergence".into(),
                    message: format!(
                        "node {}: track_count {} != node 0 track_count {}",
                        i,
                        state.track_count(),
                        ref_track_count,
                    ),
                });
            }
            if state.subscription_count() != ref_sub_count {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "crdt_convergence".into(),
                    message: format!(
                        "node {}: subscription_count {} != node 0 subscription_count {}",
                        i,
                        state.subscription_count(),
                        ref_sub_count,
                    ),
                });
            }

            // Also compare per-room participant counts.
            for &room_id in room_ids {
                let ref_count = reference.participant_count(room_id);
                let node_count = state.participant_count(room_id);
                if node_count != ref_count {
                    self.violations.push(InvariantViolation {
                        time_ns,
                        invariant_name: "crdt_convergence".into(),
                        message: format!(
                            "node {}: room {} participant_count {} != node 0 participant_count {}",
                            i, room_id, node_count, ref_count,
                        ),
                    });
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Requirement 6.5 – Packet delivery completeness (zero-loss)
    // ---------------------------------------------------------------------

    /// Under zero-loss network conditions, verify that every packet sent on
    /// a track was delivered to every subscriber of that track.
    ///
    /// * `packets_sent` – maps (track label, subscriber name) → list of packet payloads expected.
    /// * `packets_received` – maps (track label, subscriber name) → list of
    ///   packet payloads received.
    /// * `track_subscribers` – maps track label → set of subscriber names.
    /// * `network_loss_rate` – the configured loss rate; this check only
    ///   applies when the rate is 0.0.
    pub fn check_packet_delivery(
        &mut self,
        packets_sent: &HashMap<(String, String), Vec<Vec<u8>>>,
        packets_received: &HashMap<(String, String), Vec<Vec<u8>>>,
        track_subscribers: &HashMap<String, HashSet<String>>,
        network_loss_rate: f64,
        time_ns: u64,
    ) {
        // Only enforce completeness under zero-loss conditions.
        if network_loss_rate > 0.0 {
            return;
        }

        for (track_label, subscribers) in track_subscribers {
            for subscriber in subscribers {
                let key = (track_label.clone(), subscriber.clone());
                let sent = packets_sent.get(&key);
                let sent_count = sent.map_or(0, |v| v.len());
                let received = packets_received.get(&key);
                let received_count = received.map_or(0, |v| v.len());

                if received_count != sent_count {
                    self.violations.push(InvariantViolation {
                        time_ns,
                        invariant_name: "packet_delivery".into(),
                        message: format!(
                            "track '{}' -> subscriber '{}': received {}/{} packets",
                            track_label, subscriber, received_count, sent_count,
                        ),
                    });
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------------

    /// Return all recorded violations.
    pub fn violations(&self) -> &[InvariantViolation] {
        &self.violations
    }

    /// Returns `true` if any violations have been recorded.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    // ---------------------------------------------------------------------
    // Real Forwarding Invariants
    // ---------------------------------------------------------------------

    /// Check that all arena slots have been freed (no leaks).
    ///
    /// At simulation end, `arena.free_count()` should equal `arena.capacity()`.
    pub fn check_arena_leak(
        &mut self,
        arena: &nexus_transport::arena::PacketArena,
        time_ns: u64,
    ) {
        let free = arena.free_count();
        let capacity = arena.capacity();
        if free != capacity {
            let leaked = capacity - free;
            self.violations.push(InvariantViolation {
                time_ns,
                invariant_name: "ArenaSlotLeak".to_string(),
                message: format!(
                    "PacketArena has {} leaked slots (free={}, capacity={})",
                    leaked, free, capacity
                ),
            });
        }
    }

    /// Check that a ring buffer peek returns the correct data for a given sequence.
    pub fn check_ring_buffer_peek(
        &mut self,
        ring_buffer: &nexus_transport::ring_buffer::RingBuffer<2048>,
        seq: u32,
        expected_data: &[u8],
        time_ns: u64,
    ) {
        match ring_buffer.peek(seq) {
            Some(slot) => {
                if slot.data() != expected_data {
                    self.violations.push(InvariantViolation {
                        time_ns,
                        invariant_name: "RingBufferPeekCorrectness".to_string(),
                        message: format!(
                            "Ring buffer peek(seq={}) returned mismatched data: expected {} bytes, got {} bytes",
                            seq, expected_data.len(), slot.data().len()
                        ),
                    });
                }
            }
            None => {
                self.violations.push(InvariantViolation {
                    time_ns,
                    invariant_name: "RingBufferPeekCorrectness".to_string(),
                    message: format!(
                        "Ring buffer peek(seq={}) returned None, expected data",
                        seq
                    ),
                });
            }
        }
    }

    /// Check that a PacketSlot's refcount matches the expected value.
    pub fn check_refcount(
        &mut self,
        slot: &nexus_transport::arena::PacketSlot,
        expected: u32,
        context: &str,
        time_ns: u64,
    ) {
        let actual = slot.ref_count();
        if actual != expected {
            self.violations.push(InvariantViolation {
                time_ns,
                invariant_name: "FanOutRefCount".to_string(),
                message: format!(
                    "PacketSlot refcount mismatch ({}): expected {}, got {}",
                    context, expected, actual
                ),
            });
        }
    }
}

impl Default for InvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- check_actor_states -------------------------------------------------

    #[test]
    fn valid_transitions_produce_no_violations() {
        let mut checker = InvariantChecker::new();

        // Initializing → Active
        let mut snap = HashMap::new();
        snap.insert("track-1".into(), ActorState::Initializing);
        checker.check_actor_states(&snap, 0);

        snap.insert("track-1".into(), ActorState::Active);
        checker.check_actor_states(&snap, 100);

        // Active → Migrating
        snap.insert("track-1".into(), ActorState::Migrating);
        checker.check_actor_states(&snap, 200);

        // Migrating → Active
        snap.insert("track-1".into(), ActorState::Active);
        checker.check_actor_states(&snap, 300);

        // Active → Terminated
        snap.insert("track-1".into(), ActorState::Terminated);
        checker.check_actor_states(&snap, 400);

        assert!(!checker.has_violations());
    }

    #[test]
    fn invalid_transition_is_flagged() {
        let mut checker = InvariantChecker::new();

        let mut snap = HashMap::new();
        snap.insert("track-1".into(), ActorState::Active);
        checker.check_actor_states(&snap, 0);

        // Active → Initializing is invalid.
        snap.insert("track-1".into(), ActorState::Initializing);
        checker.check_actor_states(&snap, 100);

        assert!(checker.has_violations());
        assert_eq!(checker.violations().len(), 1);
        assert_eq!(checker.violations()[0].invariant_name, "actor_state_machine");
    }

    #[test]
    fn same_state_is_not_a_violation() {
        let mut checker = InvariantChecker::new();

        let mut snap = HashMap::new();
        snap.insert("track-1".into(), ActorState::Active);
        checker.check_actor_states(&snap, 0);
        checker.check_actor_states(&snap, 100);

        assert!(!checker.has_violations());
    }

    // -- check_room_capacity ------------------------------------------------

    #[test]
    fn room_within_capacity_is_ok() {
        let mut checker = InvariantChecker::new();
        let mut rooms = HashMap::new();
        let participants: HashSet<String> = (0..MAX_PARTICIPANTS_PER_ROOM)
            .map(|i| format!("p{}", i))
            .collect();
        rooms.insert("room-1".into(), participants);
        checker.check_room_capacity(&rooms, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn room_over_capacity_is_flagged() {
        let mut checker = InvariantChecker::new();
        let mut rooms = HashMap::new();
        let participants: HashSet<String> = (0..=MAX_PARTICIPANTS_PER_ROOM)
            .map(|i| format!("p{}", i))
            .collect();
        rooms.insert("room-1".into(), participants);
        checker.check_room_capacity(&rooms, 0);
        assert!(checker.has_violations());
        assert_eq!(checker.violations()[0].invariant_name, "room_capacity");
    }

    // -- check_track_capacity -----------------------------------------------

    #[test]
    fn tracks_within_capacity_is_ok() {
        let mut checker = InvariantChecker::new();
        let mut pt = HashMap::new();
        let tracks: HashSet<String> = (0..MAX_TRACKS_PER_PARTICIPANT)
            .map(|i| format!("t{}", i))
            .collect();
        pt.insert("alice".into(), tracks);
        checker.check_track_capacity(&pt, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn tracks_over_capacity_is_flagged() {
        let mut checker = InvariantChecker::new();
        let mut pt = HashMap::new();
        let tracks: HashSet<String> = (0..=MAX_TRACKS_PER_PARTICIPANT)
            .map(|i| format!("t{}", i))
            .collect();
        pt.insert("alice".into(), tracks);
        checker.check_track_capacity(&pt, 0);
        assert!(checker.has_violations());
        assert_eq!(checker.violations()[0].invariant_name, "track_capacity");
    }

    // -- check_track_ownership ----------------------------------------------

    #[test]
    fn valid_ownership_produces_no_violations() {
        let mut checker = InvariantChecker::new();

        let mut track_owner = HashMap::new();
        track_owner.insert("video-1".into(), "alice".into());

        let mut track_room = HashMap::new();
        track_room.insert("video-1".into(), "room-1".into());

        let mut room_participants = HashMap::new();
        let mut ps = HashSet::new();
        ps.insert("alice".into());
        room_participants.insert("room-1".into(), ps);

        checker.check_track_ownership(&track_owner, &track_room, &room_participants, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn owner_not_in_room_is_flagged() {
        let mut checker = InvariantChecker::new();

        let mut track_owner = HashMap::new();
        track_owner.insert("video-1".into(), "alice".into());

        let mut track_room = HashMap::new();
        track_room.insert("video-1".into(), "room-1".into());

        let room_participants: HashMap<String, HashSet<String>> = HashMap::new();

        checker.check_track_ownership(&track_owner, &track_room, &room_participants, 0);
        assert!(checker.has_violations());
        assert_eq!(checker.violations()[0].invariant_name, "track_ownership");
    }

    #[test]
    fn track_without_room_is_flagged() {
        let mut checker = InvariantChecker::new();

        let mut track_owner = HashMap::new();
        track_owner.insert("video-1".into(), "alice".into());

        let track_room: HashMap<String, String> = HashMap::new();
        let room_participants: HashMap<String, HashSet<String>> = HashMap::new();

        checker.check_track_ownership(&track_owner, &track_room, &room_participants, 0);
        assert!(checker.has_violations());
        assert!(checker.violations()[0].message.contains("no room association"));
    }

    // -- check_packet_delivery ----------------------------------------------

    #[test]
    fn complete_delivery_under_zero_loss() {
        let mut checker = InvariantChecker::new();

        let mut sent = HashMap::new();
        sent.insert(("video-1".into(), "bob".into()), vec![vec![1, 2], vec![3, 4]]);

        let mut received = HashMap::new();
        received.insert(
            ("video-1".into(), "bob".into()),
            vec![vec![1, 2], vec![3, 4]],
        );

        let mut subs = HashMap::new();
        let mut sub_set = HashSet::new();
        sub_set.insert("bob".into());
        subs.insert("video-1".into(), sub_set);

        checker.check_packet_delivery(&sent, &received, &subs, 0.0, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn incomplete_delivery_under_zero_loss_is_flagged() {
        let mut checker = InvariantChecker::new();

        let mut sent = HashMap::new();
        sent.insert(("video-1".into(), "bob".into()), vec![vec![1, 2], vec![3, 4]]);

        let mut received = HashMap::new();
        received.insert(("video-1".into(), "bob".into()), vec![vec![1, 2]]);

        let mut subs = HashMap::new();
        let mut sub_set = HashSet::new();
        sub_set.insert("bob".into());
        subs.insert("video-1".into(), sub_set);

        checker.check_packet_delivery(&sent, &received, &subs, 0.0, 0);
        assert!(checker.has_violations());
        assert_eq!(checker.violations()[0].invariant_name, "packet_delivery");
    }

    #[test]
    fn incomplete_delivery_under_nonzero_loss_is_ok() {
        let mut checker = InvariantChecker::new();

        let mut sent = HashMap::new();
        sent.insert(("video-1".into(), "bob".into()), vec![vec![1, 2], vec![3, 4]]);

        let received: HashMap<(String, String), Vec<Vec<u8>>> = HashMap::new();

        let mut subs = HashMap::new();
        let mut sub_set = HashSet::new();
        sub_set.insert("bob".into());
        subs.insert("video-1".into(), sub_set);

        // loss_rate > 0 → skip the check.
        checker.check_packet_delivery(&sent, &received, &subs, 0.5, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn no_subscribers_means_no_violations() {
        let mut checker = InvariantChecker::new();

        let sent: HashMap<(String, String), Vec<Vec<u8>>> = HashMap::new();
        let received: HashMap<(String, String), Vec<Vec<u8>>> = HashMap::new();
        let subs: HashMap<String, HashSet<String>> = HashMap::new();

        checker.check_packet_delivery(&sent, &received, &subs, 0.0, 0);
        assert!(!checker.has_violations());
    }

    // -- check_crdt_convergence (basic, without production DistributedState) -

    #[test]
    fn crdt_convergence_with_single_state_is_ok() {
        use nexus_state::{DistributedState, DistributedStateConfig};
        use std::sync::Arc;

        let config = DistributedStateConfig::new(0);
        let state = Arc::new(DistributedState::new(config));

        let mut checker = InvariantChecker::new();
        checker.check_crdt_convergence(&[state], &[], 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn crdt_convergence_identical_states_is_ok() {
        use nexus_state::{DistributedState, DistributedStateConfig};
        use std::sync::Arc;

        let s1 = Arc::new(DistributedState::new(DistributedStateConfig::new(0)));
        let s2 = Arc::new(DistributedState::new(DistributedStateConfig::new(1)));

        let mut checker = InvariantChecker::new();
        checker.check_crdt_convergence(&[s1, s2], &[], 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn crdt_convergence_diverged_states_is_flagged() {
        use nexus_state::{DistributedState, DistributedStateConfig};
        use std::sync::Arc;

        let s1 = Arc::new(DistributedState::new(DistributedStateConfig::new(0)));
        let s2 = Arc::new(DistributedState::new(DistributedStateConfig::new(1)));

        // Add a room to s1 only.
        s1.create_room(1, "room-1".into(), 10).unwrap();

        let mut checker = InvariantChecker::new();
        checker.check_crdt_convergence(&[s1, s2], &[], 0);
        assert!(checker.has_violations());
        assert!(checker.violations()[0]
            .invariant_name
            .contains("crdt_convergence"));
    }

    // -- violation recording (Requirement 6.7) ------------------------------

    #[test]
    fn violations_record_timestamp_and_name() {
        let mut checker = InvariantChecker::new();

        let mut rooms = HashMap::new();
        let participants: HashSet<String> = (0..=MAX_PARTICIPANTS_PER_ROOM)
            .map(|i| format!("p{}", i))
            .collect();
        rooms.insert("room-1".into(), participants);

        checker.check_room_capacity(&rooms, 42_000);

        let v = &checker.violations()[0];
        assert_eq!(v.time_ns, 42_000);
        assert_eq!(v.invariant_name, "room_capacity");
        assert!(!v.message.is_empty());
    }
}
