//! RoomActor implementation
//!
//! Manages room lifecycle, participants, and track announcements.
//! Follows TigerStyle principles with lock-free reads and bounded operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_channel::{bounded, Receiver, Sender};

use crate::message::RoomActorMessage;
use crate::types::*;

// Re-export DistributedState
use nexus_state::DistributedState;

/// RoomActor manages a single room with multiple participants
///
/// # Invariants
/// - id != 0
/// - name.len() <= 256
/// - max_participants > 0 && <= MAX_PARTICIPANTS_PER_ROOM
/// - participants.len() <= max_participants
/// - tracks.len() <= MAX_TRACKS_PER_ROOM
/// - All participant IDs are non-zero and unique
/// - All track IDs are non-zero and unique
/// - Track owner (participant_id) must exist in participants list
pub struct RoomActor {
    // === Identity ===
    id: RoomId,
    name: String,

    // === Location ===
    worker_id: Arc<AtomicU32>,

    // === State Machine ===
    state: Arc<AtomicU32>,
    health: Arc<AtomicU32>,

    // === Message Queue ===
    message_rx: Receiver<RoomActorMessage>,
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    message_tx: Sender<RoomActorMessage>,

    // === Participants (lock-free) ===
    participants: Arc<ArcSwap<Vec<ParticipantId>>>,

    // === Track Announcements (lock-free) ===
    tracks: Arc<ArcSwap<HashMap<TrackId, ParticipantId>>>,

    // === Capacity ===
    max_participants: u32,

    // === Statistics (atomic) ===
    participant_count: AtomicU32,
    track_count: AtomicU32,
    messages_processed: AtomicU64,

    // === Timestamps ===
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    created_at_ns: u64,
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    last_activity_ns: AtomicU64,

    // === Supervision ===
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    restart_count: AtomicU32,
    last_health_check: AtomicU64,

    // === Distributed State ===
    distributed_state: Arc<DistributedState>,
}

impl RoomActor {
    /// Spawn new room actor
    ///
    /// # Assertions
    /// - id != 0
    /// - name.len() <= 256
    /// - max_participants > 0 && <= MAX_PARTICIPANTS_PER_ROOM
    /// - worker_id < MAX_WORKERS
    pub fn spawn(
        id: RoomId,
        name: String,
        max_participants: u32,
        worker_id: WorkerId,
        created_at_ns: u64,
        distributed_state: Arc<DistributedState>,
    ) -> (Self, Sender<RoomActorMessage>) {
        assert!(id != 0, "room id must not be 0");
        assert!(name.len() <= 256, "name too long: {} bytes", name.len());
        assert!(
            max_participants > 0 && max_participants <= MAX_PARTICIPANTS_PER_ROOM,
            "max_participants {} must be in range (0, {}]",
            max_participants,
            MAX_PARTICIPANTS_PER_ROOM
        );
        assert!(
            worker_id < MAX_WORKERS,
            "worker_id {} exceeds MAX_WORKERS {}",
            worker_id,
            MAX_WORKERS
        );

        let (tx, rx) = bounded(MAX_ACTOR_QUEUE_SIZE);

        let actor = Self {
            id,
            name,
            worker_id: Arc::new(AtomicU32::new(worker_id)),
            state: Arc::new(AtomicU32::new(ActorState::Initializing as u32)),
            health: Arc::new(AtomicU32::new(ActorHealth::Healthy as u32)),
            message_rx: rx,
            message_tx: tx.clone(),
            participants: Arc::new(ArcSwap::new(Arc::new(Vec::new()))),
            tracks: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            max_participants,
            participant_count: AtomicU32::new(0),
            track_count: AtomicU32::new(0),
            messages_processed: AtomicU64::new(0),
            created_at_ns,
            last_activity_ns: AtomicU64::new(created_at_ns),
            restart_count: AtomicU32::new(0),
            last_health_check: AtomicU64::new(created_at_ns),
            distributed_state,
        };

        // Transition to Active state
        actor.transition_state(ActorState::Initializing, ActorState::Active);

        (actor, tx)
    }

    /// Process messages (bounded loop)
    ///
    /// # Loop Bound
    /// Processes up to MAX_MESSAGES_PER_ITERATION (100)
    ///
    /// # Returns
    /// true if actor should continue running, false if terminated
    pub fn process_messages(&mut self) -> bool {
        let mut processed = 0;

        while processed < MAX_MESSAGES_PER_ITERATION {
            match self.message_rx.try_recv() {
                Ok(msg) => {
                    let should_continue = self.handle_message(msg);
                    self.messages_processed.fetch_add(1, Ordering::Relaxed);
                    processed += 1;

                    if !should_continue {
                        return false;
                    }
                }
                Err(_) => break,
            }
        }

        true
    }

    /// Handle single message
    ///
    /// # Returns
    /// true if actor should continue, false if terminated
    fn handle_message(&mut self, msg: RoomActorMessage) -> bool {
        use RoomActorMessage::*;

        match msg {
            AddParticipant {
                participant_id,
                name,
                connection_id,
            } => {
                self.handle_add_participant(participant_id, name, connection_id);
            }
            RemoveParticipant { participant_id } => {
                self.handle_remove_participant(participant_id);
            }
            AnnounceTrack {
                track_id,
                participant_id,
                kind,
            } => {
                self.handle_announce_track(track_id, participant_id, kind);
            }
            RemoveTrackAnnouncement { track_id } => {
                self.handle_remove_track_announcement(track_id);
            }
            GetStats { response_tx } => {
                self.handle_get_stats(response_tx);
            }
            Terminate => {
                self.handle_terminate();
                return false;
            }
            HealthCheck => {
                self.handle_health_check();
            }
        }

        true
    }

    // === Message Handlers ===

    fn handle_add_participant(
        &mut self,
        participant_id: ParticipantId,
        _name: String,
        _connection_id: u64,
    ) {
        assert!(participant_id != 0, "participant_id must not be 0");

        let mut participants = (**self.participants.load()).clone();

        // Check capacity
        if participants.len() >= self.max_participants as usize {
            // Room is full, reject participant
            return;
        }

        assert!(
            participants.len() < MAX_PARTICIPANTS_PER_ROOM as usize,
            "room {} exceeded MAX_PARTICIPANTS_PER_ROOM",
            self.id
        );

        // Check for duplicates
        if participants.contains(&participant_id) {
            return;
        }

        participants.push(participant_id);
        self.participants.store(Arc::new(participants));
        self.participant_count.fetch_add(1, Ordering::Relaxed);

        // Integrate with DistributedState (Requirement 3.1)
        // Call add_participant and log on error (Requirement 3.5)
        if let Err(e) = self.distributed_state.add_participant(self.id as u32, participant_id as u64) {
            eprintln!(
                "Warning: Failed to add participant {} to room {} in distributed state: {:?}",
                participant_id, self.id, e
            );
        }
    }

    fn handle_remove_participant(&mut self, participant_id: ParticipantId) {
        assert!(participant_id != 0, "participant_id must not be 0");

        let mut participants = (**self.participants.load()).clone();

        if let Some(pos) = participants.iter().position(|&id| id == participant_id) {
            participants.remove(pos);
            self.participants.store(Arc::new(participants));
            self.participant_count.fetch_sub(1, Ordering::Relaxed);

            // Remove all tracks owned by this participant
            let mut tracks = (**self.tracks.load()).clone();
            tracks.retain(|_track_id, owner_id| *owner_id != participant_id);
            let removed_count = self.track_count.load(Ordering::Relaxed) - tracks.len() as u32;
            self.tracks.store(Arc::new(tracks));
            self.track_count.fetch_sub(removed_count, Ordering::Relaxed);

            // Remove from distributed state
            if let Err(e) = self.distributed_state.remove_participant(self.id as u32, participant_id as u64) {
                eprintln!("Warning: Failed to remove participant from distributed state: {:?}", e);
            }
        }
    }

    fn handle_announce_track(
        &mut self,
        track_id: TrackId,
        participant_id: ParticipantId,
        _kind: MediaKind,
    ) {
        assert!(track_id != 0, "track_id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        // Verify participant exists in room
        let participants = self.participants.load();
        assert!(
            participants.contains(&participant_id),
            "participant {} not in room {}",
            participant_id,
            self.id
        );

        let mut tracks = (**self.tracks.load()).clone();

        // Check capacity
        assert!(
            tracks.len() < MAX_TRACKS_PER_ROOM,
            "room {} exceeded MAX_TRACKS_PER_ROOM",
            self.id
        );

        // Verify track exists in distributed state (Requirement 3.2)
        // Log warning if missing but still accept locally (eventual consistency)
        if !self.distributed_state.has_track(track_id as u64) {
            eprintln!(
                "Warning: Track {} not found in distributed state when announcing in room {}",
                track_id, self.id
            );
        }

        // Add or update track announcement
        if tracks.insert(track_id, participant_id).is_none() {
            self.track_count.fetch_add(1, Ordering::Relaxed);
        }

        self.tracks.store(Arc::new(tracks));
    }

    fn handle_remove_track_announcement(&mut self, track_id: TrackId) {
        assert!(track_id != 0, "track_id must not be 0");

        let mut tracks = (**self.tracks.load()).clone();

        if tracks.remove(&track_id).is_some() {
            self.track_count.fetch_sub(1, Ordering::Relaxed);
            self.tracks.store(Arc::new(tracks));

            // Remove track from distributed state (Requirement 3.3)
            // Log warning on failure but continue (Requirement 3.5)
            if !self.distributed_state.remove_track(track_id as u64) {
                eprintln!(
                    "Warning: Track {} not found in distributed state when removing from room {}",
                    track_id, self.id
                );
            }
        }
    }

    fn handle_get_stats(&self, response_tx: crossbeam_channel::Sender<crate::message::RoomStats>) {
        // Compute room statistics (Requirement 3.4)
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let uptime_ns = now_ns.saturating_sub(self.created_at_ns);

        let stats = crate::message::RoomStats {
            participant_count: self.participant_count.load(Ordering::Relaxed),
            track_count: self.track_count.load(Ordering::Relaxed),
            uptime_ns,
            messages_processed: self.messages_processed.load(Ordering::Relaxed),
        };

        // Send stats via response channel
        // Ignore send errors (receiver may have dropped)
        let _ = response_tx.send(stats);
    }

    fn handle_terminate(&mut self) {
        self.transition_state(ActorState::Active, ActorState::Terminated);
    }

    fn handle_health_check(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.last_health_check.store(now, Ordering::Relaxed);
    }

    // === State Transitions ===

    /// Transition actor state with validation
    ///
    /// # Panics
    /// Panics if transition is invalid
    pub fn transition_state(&self, expected: ActorState, new: ActorState) {
        let result = self.state.compare_exchange(
            expected as u32,
            new as u32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        assert!(
            result.is_ok(),
            "invalid state transition: expected {:?}, got {:?}",
            expected,
            ActorState::from_u8(result.unwrap_err() as u8)
        );
    }

    // === Capacity Checks ===

    #[inline]
    pub fn is_full(&self) -> bool {
        self.participant_count.load(Ordering::Relaxed) >= self.max_participants
    }

    #[inline]
    pub fn can_add_participant(&self) -> bool {
        !self.is_full()
    }

    // === Getters ===

    #[inline]
    pub fn id(&self) -> RoomId {
        self.id
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn max_participants(&self) -> u32 {
        self.max_participants
    }

    #[inline]
    pub fn participant_count(&self) -> u32 {
        self.participant_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn track_count(&self) -> u32 {
        self.track_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn participants(&self) -> Arc<Vec<ParticipantId>> {
        self.participants.load_full()
    }

    #[inline]
    pub fn tracks(&self) -> Arc<HashMap<TrackId, ParticipantId>> {
        self.tracks.load_full()
    }

    #[inline]
    pub fn state(&self) -> ActorState {
        ActorState::from_u8(self.state.load(Ordering::Relaxed) as u8)
    }

    #[inline]
    pub fn worker_id(&self) -> WorkerId {
        self.worker_id.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn health(&self) -> ActorHealth {
        ActorHealth::from_u8(self.health.load(Ordering::Relaxed) as u8)
    }

    #[inline]
    pub fn messages_processed(&self) -> u64 {
        self.messages_processed.load(Ordering::Relaxed)
    }

    /// Get last health check timestamp in nanoseconds
    #[inline]
    pub fn last_health_check_ns(&self) -> u64 {
        self.last_health_check.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn test_distributed_state() -> Arc<DistributedState> {
        let config = nexus_state::DistributedStateConfig::new(1);
        Arc::new(DistributedState::new(config))
    }

    #[test]
    fn test_spawn_room() {
        let (room, _tx) = RoomActor::spawn(1, "Test Room".to_string(), 100, 0, now_ns(), test_distributed_state());

        assert_eq!(room.id(), 1);
        assert_eq!(room.name(), "Test Room");
        assert_eq!(room.max_participants(), 100);
        assert_eq!(room.participant_count(), 0);
        assert_eq!(room.state(), ActorState::Active);
    }

    #[test]
    #[should_panic(expected = "room id must not be 0")]
    fn test_spawn_zero_id() {
        let _ = RoomActor::spawn(0, "Test".to_string(), 100, 0, now_ns(), test_distributed_state());
    }

    #[test]
    #[should_panic(expected = "name too long")]
    fn test_spawn_long_name() {
        let long_name = "a".repeat(257);
        let _ = RoomActor::spawn(1, long_name, 100, 0, now_ns(), test_distributed_state());
    }

    #[test]
    fn test_add_participant() {
        let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), test_distributed_state());

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
    fn test_room_capacity_enforcement() {
        let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 2, 0, now_ns(), test_distributed_state());

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
        let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), test_distributed_state());

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
    fn test_remove_participant_removes_tracks() {
        let (mut room, tx) = RoomActor::spawn(1, "Test".to_string(), 100, 0, now_ns(), test_distributed_state());

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

        // Remove participant
        tx.send(RoomActorMessage::RemoveParticipant { participant_id: 10 })
            .unwrap();

        room.process_messages();

        assert_eq!(room.participant_count(), 0);
        assert_eq!(room.track_count(), 0);
    }
}
