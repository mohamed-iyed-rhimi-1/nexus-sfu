//! ParticipantActor implementation
//!
//! Manages participant lifecycle, published tracks, and subscriptions.
//! Follows TigerStyle principles with lock-free reads and bounded operations.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_channel::{bounded, Receiver, Sender};

use crate::message::{ConnectionState, ParticipantActorMessage};
use crate::types::*;

// Re-export DistributedState
use nexus_state::DistributedState;

/// ParticipantActor manages a single participant in a room
///
/// # Invariants
/// - id != 0
/// - room_id != 0
/// - connection_id != 0
/// - name.len() <= 256
/// - published_tracks.len() <= MAX_TRACKS_PER_PARTICIPANT
/// - subscriptions.len() <= MAX_SUBSCRIPTIONS_PER_PARTICIPANT
/// - All track IDs are non-zero and unique
pub struct ParticipantActor {
    // === Identity ===
    id: ParticipantId,
    room_id: RoomId,
    name: String,
    connection_id: u64,

    // === Location ===
    worker_id: Arc<AtomicU32>,

    // === State Machine ===
    state: Arc<AtomicU32>,
    health: Arc<AtomicU32>,
    connection_state: Arc<AtomicU32>,

    // === Message Queue ===
    message_rx: Receiver<ParticipantActorMessage>,
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    message_tx: Sender<ParticipantActorMessage>,

    // === Published Tracks (lock-free) ===
    published_tracks: Arc<ArcSwap<Vec<TrackId>>>,

    // === Subscriptions (lock-free) ===
    subscriptions: Arc<ArcSwap<Vec<TrackId>>>,

    // === Session State ===
    session_id: AtomicU64,

    // === Statistics (atomic) ===
    tracks_published: AtomicU32,
    tracks_subscribed: AtomicU32,
    messages_processed: AtomicU64,

    // === Timestamps ===
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    joined_at_ns: u64,
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    last_activity_ns: AtomicU64,

    // === Supervision ===
    #[allow(dead_code)] // Reserved for actor supervision and restart logic
    restart_count: AtomicU32,
    last_health_check: AtomicU64,

    // === Distributed State ===
    distributed_state: Arc<DistributedState>,
}

impl ParticipantActor {
    /// Spawn new participant actor
    ///
    /// # Assertions
    /// - id != 0
    /// - room_id != 0
    /// - connection_id != 0
    /// - name.len() <= 256
    /// - worker_id < MAX_WORKERS
    pub fn spawn(
        id: ParticipantId,
        room_id: RoomId,
        name: String,
        connection_id: u64,
        worker_id: WorkerId,
        joined_at_ns: u64,
        distributed_state: Arc<DistributedState>,
    ) -> (Self, Sender<ParticipantActorMessage>) {
        assert!(id != 0, "participant id must not be 0");
        assert!(room_id != 0, "room id must not be 0");
        assert!(connection_id != 0, "connection id must not be 0");
        assert!(name.len() <= 256, "name too long: {} bytes", name.len());
        assert!(
            worker_id < MAX_WORKERS,
            "worker_id {} exceeds MAX_WORKERS {}",
            worker_id,
            MAX_WORKERS
        );

        let (tx, rx) = bounded(MAX_ACTOR_QUEUE_SIZE);

        let actor = Self {
            id,
            room_id,
            name,
            connection_id,
            worker_id: Arc::new(AtomicU32::new(worker_id)),
            state: Arc::new(AtomicU32::new(ActorState::Initializing as u32)),
            health: Arc::new(AtomicU32::new(ActorHealth::Healthy as u32)),
            connection_state: Arc::new(AtomicU32::new(ConnectionState::Connecting as u32)),
            message_rx: rx,
            message_tx: tx.clone(),
            published_tracks: Arc::new(ArcSwap::new(Arc::new(Vec::new()))),
            subscriptions: Arc::new(ArcSwap::new(Arc::new(Vec::new()))),
            session_id: AtomicU64::new(0),
            tracks_published: AtomicU32::new(0),
            tracks_subscribed: AtomicU32::new(0),
            messages_processed: AtomicU64::new(0),
            joined_at_ns,
            last_activity_ns: AtomicU64::new(joined_at_ns),
            restart_count: AtomicU32::new(0),
            last_health_check: AtomicU64::new(joined_at_ns),
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
    fn handle_message(&mut self, msg: ParticipantActorMessage) -> bool {
        use ParticipantActorMessage::*;

        match msg {
            PublishTrack { track_id, ssrc, kind } => {
                self.handle_publish_track(track_id, ssrc, kind);
            }
            UnpublishTrack { track_id } => {
                self.handle_unpublish_track(track_id);
            }
            SubscribeToTrack { track_id, target_layer } => {
                self.handle_subscribe_to_track(track_id, target_layer);
            }
            UnsubscribeFromTrack { track_id } => {
                self.handle_unsubscribe_from_track(track_id);
            }
            UpdateConnectionState { session_id, state } => {
                self.handle_update_connection_state(session_id, state);
            }
            UpdateMetadata { name } => {
                self.handle_update_metadata(name);
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

    fn handle_publish_track(&mut self, track_id: TrackId, _ssrc: Ssrc, kind: MediaKind) {
        assert!(track_id != 0, "track_id must not be 0");

        let mut tracks = (**self.published_tracks.load()).clone();

        // Check capacity
        assert!(
            tracks.len() < MAX_TRACKS_PER_PARTICIPANT,
            "participant {} exceeded max tracks per participant",
            self.id
        );

        // Check for duplicates
        assert!(
            !tracks.contains(&track_id),
            "track {} already published by participant {}",
            track_id,
            self.id
        );

        tracks.push(track_id);
        self.published_tracks.store(Arc::new(tracks));
        self.tracks_published.fetch_add(1, Ordering::Relaxed);

        // Add track to distributed state
        let track_info = nexus_state::gossip::types::TrackInfo {
            track_type: match kind {
                MediaKind::Audio => 0,
                MediaKind::Video => 1,
            },
            codec: 0,
            bitrate_kbps: 0,
        };
        if let Err(e) = self.distributed_state.add_track(track_id as u64, track_info) {
            eprintln!("Warning: Failed to add track to distributed state: {:?}", e);
        }
    }

    fn handle_unpublish_track(&mut self, track_id: TrackId) {
        assert!(track_id != 0, "track_id must not be 0");

        let mut tracks = (**self.published_tracks.load()).clone();

        if let Some(pos) = tracks.iter().position(|&id| id == track_id) {
            tracks.remove(pos);
            self.published_tracks.store(Arc::new(tracks));

            // Remove track from distributed state
            self.distributed_state.remove_track(track_id as u64);
        }
    }

    fn handle_subscribe_to_track(&mut self, track_id: TrackId, _target_layer: u8) {
        assert!(track_id != 0, "track_id must not be 0");

        let mut subs = (**self.subscriptions.load()).clone();

        // Check capacity
        assert!(
            subs.len() < MAX_SUBSCRIPTIONS_PER_PARTICIPANT,
            "participant {} exceeded max subscriptions",
            self.id
        );

        // Check for duplicates
        if !subs.contains(&track_id) {
            subs.push(track_id);
            self.subscriptions.store(Arc::new(subs));
            self.tracks_subscribed.fetch_add(1, Ordering::Relaxed);

            // Add subscription to distributed state
            if let Err(e) = self.distributed_state.add_subscription(track_id as u64, self.id as u64) {
                eprintln!("Warning: Failed to add subscription to distributed state: {:?}", e);
            }
        }
    }

    fn handle_unsubscribe_from_track(&mut self, track_id: TrackId) {
        assert!(track_id != 0, "track_id must not be 0");

        let mut subs = (**self.subscriptions.load()).clone();

        if let Some(pos) = subs.iter().position(|&id| id == track_id) {
            subs.remove(pos);
            self.subscriptions.store(Arc::new(subs));

            // Remove subscription from distributed state
            if let Err(e) = self.distributed_state.remove_subscription(track_id as u64, self.id as u64) {
                eprintln!("Warning: Failed to remove subscription from distributed state: {:?}", e);
            }
        }
    }

    fn handle_update_connection_state(&mut self, session_id: u64, state: ConnectionState) {
        self.session_id.store(session_id, Ordering::Relaxed);
        self.connection_state.store(state as u32, Ordering::Relaxed);
    }

    fn handle_update_metadata(&mut self, name: String) {
        assert!(name.len() <= 256, "name too long: {} bytes", name.len());
        self.name = name;
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

    /// Transition connection state
    pub fn transition_connection_state(&self, expected: ConnectionState, new: ConnectionState) {
        let result = self.connection_state.compare_exchange(
            expected as u32,
            new as u32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        assert!(
            result.is_ok(),
            "invalid connection state transition: expected {:?}",
            expected
        );
    }

    // === Getters ===

    #[inline]
    pub fn id(&self) -> ParticipantId {
        self.id
    }

    #[inline]
    pub fn room_id(&self) -> RoomId {
        self.room_id
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    #[inline]
    pub fn state(&self) -> ActorState {
        ActorState::from_u8(self.state.load(Ordering::Relaxed) as u8)
    }

    #[inline]
    pub fn connection_state(&self) -> ConnectionState {
        let val = self.connection_state.load(Ordering::Relaxed) as u8;
        match val {
            0 => ConnectionState::Connecting,
            1 => ConnectionState::Connected,
            2 => ConnectionState::Disconnected,
            3 => ConnectionState::Failed,
            _ => panic!("invalid connection state: {}", val),
        }
    }

    #[inline]
    pub fn published_tracks(&self) -> Arc<Vec<TrackId>> {
        self.published_tracks.load_full()
    }

    #[inline]
    pub fn subscriptions(&self) -> Arc<Vec<TrackId>> {
        self.subscriptions.load_full()
    }

    #[inline]
    pub fn session_id(&self) -> u64 {
        self.session_id.load(Ordering::Relaxed)
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
    fn test_spawn_participant() {
        let (participant, _tx) = ParticipantActor::spawn(
            1,
            100,
            "Alice".to_string(),
            1000,
            0,
            now_ns(),
            test_distributed_state(),
        );

        assert_eq!(participant.id(), 1);
        assert_eq!(participant.room_id(), 100);
        assert_eq!(participant.name(), "Alice");
        assert_eq!(participant.connection_id(), 1000);
        assert_eq!(participant.state(), ActorState::Active);
        assert_eq!(participant.connection_state(), ConnectionState::Connecting);
    }

    #[test]
    #[should_panic(expected = "participant id must not be 0")]
    fn test_spawn_zero_id() {
        let _ = ParticipantActor::spawn(0, 100, "Alice".to_string(), 1000, 0, now_ns(), test_distributed_state());
    }

    #[test]
    #[should_panic(expected = "room id must not be 0")]
    fn test_spawn_zero_room_id() {
        let _ = ParticipantActor::spawn(1, 0, "Alice".to_string(), 1000, 0, now_ns(), test_distributed_state());
    }

    #[test]
    #[should_panic(expected = "name too long")]
    fn test_spawn_long_name() {
        let long_name = "a".repeat(257);
        let _ = ParticipantActor::spawn(1, 100, long_name, 1000, 0, now_ns(), test_distributed_state());
    }

    #[test]
    fn test_publish_track() {
        let (mut participant, tx) = ParticipantActor::spawn(
            1,
            100,
            "Alice".to_string(),
            1000,
            0,
            now_ns(),
            test_distributed_state(),
        );

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
    fn test_subscribe_to_track() {
        let (mut participant, tx) = ParticipantActor::spawn(
            1,
            100,
            "Alice".to_string(),
            1000,
            0,
            now_ns(),
            test_distributed_state(),
        );

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
    fn test_update_connection_state() {
        let (mut participant, tx) = ParticipantActor::spawn(
            1,
            100,
            "Alice".to_string(),
            1000,
            0,
            now_ns(),
            test_distributed_state(),
        );

        tx.send(ParticipantActorMessage::UpdateConnectionState {
            session_id: 5000,
            state: ConnectionState::Connected,
        })
        .unwrap();

        participant.process_messages();

        assert_eq!(participant.connection_state(), ConnectionState::Connected);
        assert_eq!(participant.session_id(), 5000);
    }
}
