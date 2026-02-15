//! Actor manager for lifecycle coordination
//!
//! Manages pre-allocated actor pools and coordinates with registry and supervision.

use std::collections::HashMap;
use std::sync::Arc;

use crossbeam_channel::Sender;
use parking_lot::RwLock;

use crate::message::{ParticipantActorMessage, RoomActorMessage, TrackActorMessage};
use crate::participant::ParticipantActor;
use crate::registry::{ActorId, ActorRegistry, ActorType};
use crate::room::RoomActor;
use crate::supervisor::ActorSupervisor;
use crate::track::TrackActor;
use crate::types::*;

// Re-export DistributedState for convenience
pub use nexus_state::DistributedState;

/// Actor error types
#[derive(Debug)]
pub enum ActorError {
    NotFound { actor_type: ActorType, id: u64 },
    AlreadyExists { actor_type: ActorType, id: u64 },
    CapacityExceeded { actor_type: ActorType, max: usize },
    MessageQueueFull { actor_type: ActorType, id: u64 },
    WorkerNotFound { worker_id: u32 },
    MessageSendFailed { actor_type: ActorType, id: u64, reason: String },
}

impl std::fmt::Display for ActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActorError::NotFound { actor_type, id } => {
                write!(f, "{:?} actor {} not found", actor_type, id)
            }
            ActorError::AlreadyExists { actor_type, id } => {
                write!(f, "{:?} actor {} already exists", actor_type, id)
            }
            ActorError::CapacityExceeded { actor_type, max } => {
                write!(f, "{:?} actor capacity exceeded (max {})", actor_type, max)
            }
            ActorError::MessageQueueFull { actor_type, id } => {
                write!(f, "{:?} actor {} message queue full", actor_type, id)
            }
            ActorError::WorkerNotFound { worker_id } => {
                write!(f, "Worker {} not found", worker_id)
            }
            ActorError::MessageSendFailed { actor_type, id, reason } => {
                write!(f, "{:?} actor {} message send failed: {}", actor_type, id, reason)
            }
        }
    }
}

impl std::error::Error for ActorError {}

/// Default health check timeout in milliseconds
const DEFAULT_HEALTH_TIMEOUT_MS: u64 = 5000;

/// Default maximum restart retries
const DEFAULT_MAX_RESTART_RETRIES: u32 = 3;

/// Supervision statistics
#[derive(Debug, Clone, Default)]
pub struct SupervisionStats {
    /// Number of health checks performed in last cycle
    pub checks_performed: u32,
    /// Number of restart attempts in last cycle
    pub restarts_attempted: u32,
    /// Number of successful restarts in last cycle
    pub restarts_succeeded: u32,
}

/// Pre-allocated actor pools and lifecycle management
pub struct ActorManager {
    /// Room actors (pre-allocated slots)
    rooms: RwLock<HashMap<RoomId, (RoomActor, Sender<RoomActorMessage>)>>,

    /// Participant actors (pre-allocated slots)
    participants: RwLock<HashMap<ParticipantId, (ParticipantActor, Sender<ParticipantActorMessage>)>>,

    /// Track actors (pre-allocated slots)
    tracks: RwLock<HashMap<TrackId, (TrackActor, Sender<TrackActorMessage>)>>,

    /// Actor registry
    registry: Arc<ActorRegistry>,

    /// Distributed state for CRDT synchronization
    distributed_state: Arc<DistributedState>,

    /// Supervisors per actor type
    room_supervisors: RwLock<HashMap<RoomId, ActorSupervisor>>,
    participant_supervisors: RwLock<HashMap<ParticipantId, ActorSupervisor>>,
    track_supervisors: RwLock<HashMap<TrackId, ActorSupervisor>>,

    /// Capacity limits (fixed at initialization)
    max_rooms: usize,
    max_participants: usize,
    max_tracks: usize,

    /// Pre-allocation flag
    pre_allocated: bool,

    /// Health check timeout in milliseconds
    health_timeout_ms: u64,

    /// Maximum restart retries before removing actor
    max_restart_retries: u32,

    /// Restart count per actor (tracks retries)
    restart_counts: RwLock<HashMap<ActorId, u32>>,

    /// Last supervision statistics
    last_supervision_stats: RwLock<SupervisionStats>,
}

impl ActorManager {
    /// Create new actor manager with pre-allocated capacity
    ///
    /// # Assertions
    /// - max_rooms <= MAX_ROOMS
    /// - max_participants <= MAX_PARTICIPANTS
    /// - max_tracks <= MAX_TRACKS
    pub fn new(
        max_rooms: usize,
        max_participants: usize,
        max_tracks: usize,
        distributed_state: Arc<DistributedState>,
    ) -> Self {
        assert!(
            max_rooms <= MAX_ROOMS,
            "max_rooms {} exceeds MAX_ROOMS {}",
            max_rooms,
            MAX_ROOMS
        );
        assert!(
            max_participants <= MAX_PARTICIPANTS,
            "max_participants {} exceeds MAX_PARTICIPANTS {}",
            max_participants,
            MAX_PARTICIPANTS
        );
        assert!(
            max_tracks <= MAX_TRACKS,
            "max_tracks {} exceeds MAX_TRACKS {}",
            max_tracks,
            MAX_TRACKS
        );

        Self {
            rooms: RwLock::new(HashMap::with_capacity(max_rooms)),
            participants: RwLock::new(HashMap::with_capacity(max_participants)),
            tracks: RwLock::new(HashMap::with_capacity(max_tracks)),
            registry: Arc::new(ActorRegistry::with_capacity(max_tracks)),
            distributed_state,
            room_supervisors: RwLock::new(HashMap::with_capacity(max_rooms)),
            participant_supervisors: RwLock::new(HashMap::with_capacity(max_participants)),
            track_supervisors: RwLock::new(HashMap::with_capacity(max_tracks)),
            max_rooms,
            max_participants,
            max_tracks,
            pre_allocated: false,
            health_timeout_ms: DEFAULT_HEALTH_TIMEOUT_MS,
            max_restart_retries: DEFAULT_MAX_RESTART_RETRIES,
            restart_counts: RwLock::new(HashMap::with_capacity(max_rooms + max_participants + max_tracks)),
            last_supervision_stats: RwLock::new(SupervisionStats::default()),
        }
    }

    /// Create new actor manager with custom supervision settings
    ///
    /// # Arguments
    /// - max_rooms: Maximum number of rooms
    /// - max_participants: Maximum number of participants
    /// - max_tracks: Maximum number of tracks
    /// - distributed_state: Distributed state for CRDT synchronization
    /// - health_timeout_ms: Health check timeout in milliseconds
    /// - max_restart_retries: Maximum restart retries before removing actor
    ///
    /// # Assertions
    /// - max_rooms <= MAX_ROOMS
    /// - max_participants <= MAX_PARTICIPANTS
    /// - max_tracks <= MAX_TRACKS
    /// - health_timeout_ms > 0
    /// - max_restart_retries > 0
    pub fn with_supervision_config(
        max_rooms: usize,
        max_participants: usize,
        max_tracks: usize,
        distributed_state: Arc<DistributedState>,
        health_timeout_ms: u64,
        max_restart_retries: u32,
    ) -> Self {
        assert!(health_timeout_ms > 0, "health_timeout_ms must be > 0");
        assert!(max_restart_retries > 0, "max_restart_retries must be > 0");

        let mut manager = Self::new(max_rooms, max_participants, max_tracks, distributed_state);
        manager.health_timeout_ms = health_timeout_ms;
        manager.max_restart_retries = max_restart_retries;
        manager
    }

    /// Pre-allocate actor pools at startup
    ///
    /// This initializes the HashMaps with their full capacity to avoid
    /// dynamic allocation during runtime. After calling this, the manager
    /// will enforce that spawns only succeed if capacity is available.
    ///
    /// # Note
    /// This doesn't create actual actor instances, but reserves the memory
    /// for the maximum number of actors. Actors are still created on-demand
    /// but from a fixed-size pool.
    pub fn pre_allocate(&mut self) {
        // Reserve capacity in all collections (acquire locks separately to avoid borrow issues)
        {
            let mut rooms = self.rooms.write();
            let current_cap = rooms.capacity();
            rooms.reserve(self.max_rooms.saturating_sub(current_cap));
        }
        {
            let mut participants = self.participants.write();
            let current_cap = participants.capacity();
            participants.reserve(self.max_participants.saturating_sub(current_cap));
        }
        {
            let mut tracks = self.tracks.write();
            let current_cap = tracks.capacity();
            tracks.reserve(self.max_tracks.saturating_sub(current_cap));
        }
        {
            let mut room_supervisors = self.room_supervisors.write();
            let current_cap = room_supervisors.capacity();
            room_supervisors.reserve(self.max_rooms.saturating_sub(current_cap));
        }
        {
            let mut participant_supervisors = self.participant_supervisors.write();
            let current_cap = participant_supervisors.capacity();
            participant_supervisors.reserve(self.max_participants.saturating_sub(current_cap));
        }
        {
            let mut track_supervisors = self.track_supervisors.write();
            let current_cap = track_supervisors.capacity();
            track_supervisors.reserve(self.max_tracks.saturating_sub(current_cap));
        }

        self.pre_allocated = true;
    }

    /// Check if actor pools have been pre-allocated
    pub fn is_pre_allocated(&self) -> bool {
        self.pre_allocated
    }

    /// Get registry reference
    pub fn registry(&self) -> Arc<ActorRegistry> {
        Arc::clone(&self.registry)
    }

    /// Get distributed state reference
    pub fn distributed_state(&self) -> Arc<DistributedState> {
        Arc::clone(&self.distributed_state)
    }

    /// Get current capacity usage
    pub fn capacity_usage(&self) -> (usize, usize, usize) {
        (
            self.rooms.read().len(),
            self.participants.read().len(),
            self.tracks.read().len(),
        )
    }

    /// Get maximum capacities
    pub fn max_capacities(&self) -> (usize, usize, usize) {
        (self.max_rooms, self.max_participants, self.max_tracks)
    }

    // === Room Actor Management ===

    /// Spawn room actor
    pub fn spawn_room(
        &self,
        id: RoomId,
        name: String,
        max_participants: u32,
        worker_id: WorkerId,
    ) -> Result<(), ActorError> {
        let mut rooms = self.rooms.write();

        if rooms.contains_key(&id) {
            return Err(ActorError::AlreadyExists {
                actor_type: ActorType::Room,
                id,
            });
        }

        if rooms.len() >= self.max_rooms {
            return Err(ActorError::CapacityExceeded {
                actor_type: ActorType::Room,
                max: self.max_rooms,
            });
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let (actor, tx) = RoomActor::spawn(
            id,
            name.clone(),
            max_participants,
            worker_id,
            now,
            Arc::clone(&self.distributed_state),
        );

        // Register in registry
        self.registry.register_room(id, worker_id);

        // Create room in distributed state
        if let Err(e) = self.distributed_state.create_room(id as u32, name, max_participants) {
            // Log error but don't fail - room actor is created
            eprintln!("Warning: Failed to create room in distributed state: {:?}", e);
        }

        // Create supervisor
        let supervisor = ActorSupervisor::new(
            ActorId::room(id),
            RestartPolicy::Limited(3),
            worker_id,
        );
        self.room_supervisors.write().insert(id, supervisor);

        rooms.insert(id, (actor, tx));

        Ok(())
    }

    /// Terminate room actor
    pub fn terminate_room(&self, room_id: RoomId) -> Result<(), ActorError> {
        let mut rooms = self.rooms.write();

        if let Some((_actor, tx)) = rooms.remove(&room_id) {
            let _ = tx.send(RoomActorMessage::Terminate);
            self.registry.unregister_room(room_id);
            self.room_supervisors.write().remove(&room_id);
            Ok(())
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Room,
                id: room_id,
            })
        }
    }

    /// Send message to room
    pub fn send_to_room(
        &self,
        room_id: RoomId,
        msg: RoomActorMessage,
    ) -> Result<(), ActorError> {
        let rooms = self.rooms.read();

        if let Some((_actor, tx)) = rooms.get(&room_id) {
            tx.send(msg).map_err(|_| ActorError::MessageQueueFull {
                actor_type: ActorType::Room,
                id: room_id,
            })
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Room,
                id: room_id,
            })
        }
    }

    // === Participant Actor Management ===

    /// Spawn participant actor
    pub fn spawn_participant(
        &self,
        id: ParticipantId,
        room_id: RoomId,
        name: String,
        connection_id: u64,
        worker_id: WorkerId,
    ) -> Result<(), ActorError> {
        // Validate room exists
        if self.registry.lookup_room(room_id).is_none() {
            return Err(ActorError::NotFound {
                actor_type: ActorType::Room,
                id: room_id,
            });
        }

        let mut participants = self.participants.write();

        if participants.contains_key(&id) {
            return Err(ActorError::AlreadyExists {
                actor_type: ActorType::Participant,
                id,
            });
        }

        if participants.len() >= self.max_participants {
            return Err(ActorError::CapacityExceeded {
                actor_type: ActorType::Participant,
                max: self.max_participants,
            });
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let (actor, tx) = ParticipantActor::spawn(
            id,
            room_id,
            name,
            connection_id,
            worker_id,
            now,
            Arc::clone(&self.distributed_state),
        );

        // Register in registry
        self.registry.register_participant(id, room_id, worker_id);

        // Add participant to distributed state
        if let Err(e) = self.distributed_state.add_participant(room_id as u32, id as u64) {
            eprintln!("Warning: Failed to add participant to distributed state: {:?}", e);
        }

        // Create supervisor
        let supervisor = ActorSupervisor::new(
            ActorId::participant(id),
            RestartPolicy::Limited(3),
            worker_id,
        );
        self.participant_supervisors.write().insert(id, supervisor);

        participants.insert(id, (actor, tx));

        Ok(())
    }

    /// Terminate participant actor
    pub fn terminate_participant(&self, participant_id: ParticipantId) -> Result<(), ActorError> {
        let mut participants = self.participants.write();

        if let Some((_actor, tx)) = participants.remove(&participant_id) {
            let _ = tx.send(ParticipantActorMessage::Terminate);
            self.registry.unregister_participant(participant_id);
            self.participant_supervisors.write().remove(&participant_id);
            Ok(())
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Participant,
                id: participant_id,
            })
        }
    }

    /// Send message to participant
    pub fn send_to_participant(
        &self,
        participant_id: ParticipantId,
        msg: ParticipantActorMessage,
    ) -> Result<(), ActorError> {
        let participants = self.participants.read();

        if let Some((_actor, tx)) = participants.get(&participant_id) {
            tx.send(msg).map_err(|_| ActorError::MessageQueueFull {
                actor_type: ActorType::Participant,
                id: participant_id,
            })
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Participant,
                id: participant_id,
            })
        }
    }

    // === Track Actor Management ===

    /// Spawn track actor
    pub fn spawn_track(
        &self,
        id: TrackId,
        participant_id: ParticipantId,
        ssrc: Ssrc,
        kind: MediaKind,
        worker_id: WorkerId,
    ) -> Result<(), ActorError> {
        // Validate participant exists
        if self.registry.lookup_participant(participant_id).is_none() {
            return Err(ActorError::NotFound {
                actor_type: ActorType::Participant,
                id: participant_id,
            });
        }

        let mut tracks = self.tracks.write();

        if tracks.contains_key(&id) {
            return Err(ActorError::AlreadyExists {
                actor_type: ActorType::Track,
                id,
            });
        }

        if tracks.len() >= self.max_tracks {
            return Err(ActorError::CapacityExceeded {
                actor_type: ActorType::Track,
                max: self.max_tracks,
            });
        }

        let (actor, tx) = TrackActor::spawn(id, participant_id, ssrc, kind, worker_id);

        // Register in registry
        self.registry.register_track(id, participant_id, worker_id);

        // Add track to distributed state
        let track_info = nexus_state::gossip::types::TrackInfo {
            track_type: match kind {
                MediaKind::Audio => 0,
                MediaKind::Video => 1,
            },
            content_type: 0,
            codec: 0, // Default codec
            bitrate_kbps: 0, // Default bitrate
            owner_node: 0, // Set by orchestrator when node ID is known
        };
        if let Err(e) = self.distributed_state.add_track(id as u64, track_info) {
            eprintln!("Warning: Failed to add track to distributed state: {:?}", e);
        }

        // Create supervisor
        let supervisor = ActorSupervisor::new(
            ActorId::track(id),
            RestartPolicy::Limited(3),
            worker_id,
        );
        self.track_supervisors.write().insert(id, supervisor);

        tracks.insert(id, (actor, tx));

        Ok(())
    }

    /// Terminate track actor
    pub fn terminate_track(&self, track_id: TrackId) -> Result<(), ActorError> {
        let mut tracks = self.tracks.write();

        if let Some((_actor, tx)) = tracks.remove(&track_id) {
            let _ = tx.send(TrackActorMessage::Terminate);
            self.registry.unregister_track(track_id);
            self.track_supervisors.write().remove(&track_id);
            Ok(())
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Track,
                id: track_id,
            })
        }
    }

    /// Send message to track
    pub fn send_to_track(
        &self,
        track_id: TrackId,
        msg: TrackActorMessage,
    ) -> Result<(), ActorError> {
        let tracks = self.tracks.read();

        if let Some((_actor, tx)) = tracks.get(&track_id) {
            tx.send(msg).map_err(|_| ActorError::MessageQueueFull {
                actor_type: ActorType::Track,
                id: track_id,
            })
        } else {
            Err(ActorError::NotFound {
                actor_type: ActorType::Track,
                id: track_id,
            })
        }
    }

    // === Supervision ===

    /// Run supervision loop (bounded)
    ///
    /// # Loop Bound
    /// Checks up to MAX_HEALTH_CHECKS_PER_ITERATION (100)
    ///
    /// # Returns
    /// SupervisionStats containing checks performed, restarts attempted, and restarts succeeded
    pub fn supervise(&self) -> SupervisionStats {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let timeout_ns = self.health_timeout_ms * 1_000_000;

        let mut checks_performed: u32 = 0;
        let mut restarts_attempted: u32 = 0;
        let mut restarts_succeeded: u32 = 0;

        // Collect unhealthy actors to process
        let mut unhealthy_rooms: Vec<RoomId> = Vec::new();
        let mut unhealthy_participants: Vec<ParticipantId> = Vec::new();
        let mut unhealthy_tracks: Vec<TrackId> = Vec::new();

        // Check rooms (bounded by MAX_HEALTH_CHECKS_PER_ITERATION)
        {
            let rooms = self.rooms.read();
            for (&room_id, (actor, _tx)) in rooms.iter() {
                if checks_performed >= MAX_HEALTH_CHECKS_PER_ITERATION as u32 {
                    break;
                }
                
                // Send health check message
                let _ = self.send_to_room(room_id, RoomActorMessage::HealthCheck);
                
                // Check last health check timestamp
                let last_check_ns = actor.last_health_check_ns();
                if now_ns.saturating_sub(last_check_ns) > timeout_ns {
                    unhealthy_rooms.push(room_id);
                }
                checks_performed += 1;
            }
        }

        // Check participants (bounded by remaining checks)
        {
            let participants = self.participants.read();
            for (&participant_id, (actor, _tx)) in participants.iter() {
                if checks_performed >= MAX_HEALTH_CHECKS_PER_ITERATION as u32 {
                    break;
                }
                
                // Send health check message
                let _ = self.send_to_participant(participant_id, ParticipantActorMessage::HealthCheck);
                
                // Check last health check timestamp
                let last_check_ns = actor.last_health_check_ns();
                if now_ns.saturating_sub(last_check_ns) > timeout_ns {
                    unhealthy_participants.push(participant_id);
                }
                checks_performed += 1;
            }
        }

        // Check tracks (bounded by remaining checks)
        {
            let tracks = self.tracks.read();
            for (&track_id, (actor, _tx)) in tracks.iter() {
                if checks_performed >= MAX_HEALTH_CHECKS_PER_ITERATION as u32 {
                    break;
                }
                
                // Send health check message
                let _ = self.send_to_track(track_id, TrackActorMessage::HealthCheck);
                
                // Check last health check timestamp
                let last_check_ns = actor.last_health_check_ns();
                if now_ns.saturating_sub(last_check_ns) > timeout_ns {
                    unhealthy_tracks.push(track_id);
                }
                checks_performed += 1;
            }
        }

        // Process unhealthy rooms
        for room_id in unhealthy_rooms {
            let actor_id = ActorId::room(room_id);
            restarts_attempted += 1;
            
            if self.attempt_restart_room(room_id) {
                restarts_succeeded += 1;
                // Reset restart count on success
                self.restart_counts.write().remove(&actor_id);
            } else {
                // Increment restart count
                let mut counts = self.restart_counts.write();
                let count = counts.entry(actor_id).or_insert(0);
                *count += 1;
                
                if *count >= self.max_restart_retries {
                    // Max retries exceeded, remove actor
                    eprintln!(
                        "Room {} failed to restart after {} attempts, removing from registry",
                        room_id, self.max_restart_retries
                    );
                    drop(counts);
                    let _ = self.terminate_room(room_id);
                    self.restart_counts.write().remove(&actor_id);
                }
            }
        }

        // Process unhealthy participants
        for participant_id in unhealthy_participants {
            let actor_id = ActorId::participant(participant_id);
            restarts_attempted += 1;
            
            if self.attempt_restart_participant(participant_id) {
                restarts_succeeded += 1;
                self.restart_counts.write().remove(&actor_id);
            } else {
                let mut counts = self.restart_counts.write();
                let count = counts.entry(actor_id).or_insert(0);
                *count += 1;
                
                if *count >= self.max_restart_retries {
                    eprintln!(
                        "Participant {} failed to restart after {} attempts, removing from registry",
                        participant_id, self.max_restart_retries
                    );
                    drop(counts);
                    let _ = self.terminate_participant(participant_id);
                    self.restart_counts.write().remove(&actor_id);
                }
            }
        }

        // Process unhealthy tracks
        for track_id in unhealthy_tracks {
            let actor_id = ActorId::track(track_id);
            restarts_attempted += 1;
            
            if self.attempt_restart_track(track_id) {
                restarts_succeeded += 1;
                self.restart_counts.write().remove(&actor_id);
            } else {
                let mut counts = self.restart_counts.write();
                let count = counts.entry(actor_id).or_insert(0);
                *count += 1;
                
                if *count >= self.max_restart_retries {
                    eprintln!(
                        "Track {} failed to restart after {} attempts, removing from registry",
                        track_id, self.max_restart_retries
                    );
                    drop(counts);
                    let _ = self.terminate_track(track_id);
                    self.restart_counts.write().remove(&actor_id);
                }
            }
        }

        let stats = SupervisionStats {
            checks_performed,
            restarts_attempted,
            restarts_succeeded,
        };

        // Store last supervision stats
        *self.last_supervision_stats.write() = stats.clone();

        stats
    }

    /// Attempt to restart a room actor
    ///
    /// # Returns
    /// true if restart succeeded, false otherwise
    fn attempt_restart_room(&self, room_id: RoomId) -> bool {
        // Get room info before terminating
        let (name, max_participants, worker_id) = {
            let rooms = self.rooms.read();
            if let Some((actor, _)) = rooms.get(&room_id) {
                (actor.name().to_string(), actor.max_participants(), actor.worker_id())
            } else {
                return false;
            }
        };

        // Terminate the old actor
        if self.terminate_room(room_id).is_err() {
            return false;
        }

        // Spawn a new actor with the same configuration
        self.spawn_room(room_id, name, max_participants, worker_id).is_ok()
    }

    /// Attempt to restart a participant actor
    ///
    /// # Returns
    /// true if restart succeeded, false otherwise
    fn attempt_restart_participant(&self, participant_id: ParticipantId) -> bool {
        // Get participant info before terminating
        let (room_id, name, connection_id, worker_id) = {
            let participants = self.participants.read();
            if let Some((actor, _)) = participants.get(&participant_id) {
                (actor.room_id(), actor.name().to_string(), actor.connection_id(), actor.worker_id())
            } else {
                return false;
            }
        };

        // Terminate the old actor
        if self.terminate_participant(participant_id).is_err() {
            return false;
        }

        // Spawn a new actor with the same configuration
        self.spawn_participant(participant_id, room_id, name, connection_id, worker_id).is_ok()
    }

    /// Attempt to restart a track actor
    ///
    /// # Returns
    /// true if restart succeeded, false otherwise
    fn attempt_restart_track(&self, track_id: TrackId) -> bool {
        // Get track info before terminating
        let (participant_id, ssrc, kind, worker_id) = {
            let tracks = self.tracks.read();
            if let Some((actor, _)) = tracks.get(&track_id) {
                (actor.participant_id(), actor.ssrc(), actor.kind(), actor.worker_id())
            } else {
                return false;
            }
        };

        // Terminate the old actor
        if self.terminate_track(track_id).is_err() {
            return false;
        }

        // Spawn a new actor with the same configuration
        self.spawn_track(track_id, participant_id, ssrc, kind, worker_id).is_ok()
    }

    /// Get last supervision statistics
    pub fn last_supervision_stats(&self) -> SupervisionStats {
        self.last_supervision_stats.read().clone()
    }

    /// Get health timeout in milliseconds
    pub fn health_timeout_ms(&self) -> u64 {
        self.health_timeout_ms
    }

    /// Get maximum restart retries
    pub fn max_restart_retries(&self) -> u32 {
        self.max_restart_retries
    }

    /// Get restart count for an actor
    pub fn restart_count(&self, actor_id: ActorId) -> u32 {
        self.restart_counts.read().get(&actor_id).copied().unwrap_or(0)
    }

    // === High-Level Operations (for RoomManager compatibility) ===

    /// Create a room (convenience method)
    pub fn create_room(&self, name: String, max_participants: u32) -> Result<RoomId, ActorError> {
        // Generate unique room ID
        let room_id = self.generate_room_id();
        
        // Spawn room actor on worker 0 (default)
        self.spawn_room(room_id, name, max_participants, 0)?;
        
        Ok(room_id)
    }

    /// Remove a room (convenience method)
    pub fn remove_room(&self, room_id: RoomId) -> Result<(), ActorError> {
        // Remove room from distributed state (returns bool)
        let _removed = self.distributed_state.remove_room(room_id as u32);
        
        self.terminate_room(room_id)
    }

    /// Check if room exists (convenience method)
    pub fn get_room(&self, room_id: RoomId) -> Option<RoomId> {
        let rooms = self.rooms.read();
        if rooms.contains_key(&room_id) {
            Some(room_id)
        } else {
            None
        }
    }

    /// Get room by name (convenience method)
    /// 
    /// Searches through distributed state to find a room by name.
    /// Returns the room ID if found.
    pub fn get_room_by_name(&self, name: &str) -> Option<RoomId> {
        // Search through all rooms in distributed state
        let rooms = self.rooms.read();
        for room_id in rooms.keys() {
            if let Some(metadata) = self.distributed_state.get_room(*room_id as u32) {
                if metadata.name() == name {
                    return Some(*room_id);
                }
            }
        }
        None
    }

    /// Add participant to room (convenience method - 2-arg version for tests)
    ///
    /// Generates participant ID automatically and spawns participant actor.
    /// Notifies room actor and updates distributed state.
    ///
    /// # Arguments
    /// * `room_id` - Room to join
    /// * `name` - Participant name
    ///
    /// # Returns
    /// Generated participant ID on success
    pub fn add_participant(
        &self,
        room_id: RoomId,
        name: String,
    ) -> Result<ParticipantId, ActorError> {
        // Generate unique participant ID
        let participant_id = self.generate_participant_id();
        
        // Generate connection ID (for now, use participant_id)
        let connection_id = participant_id;
        
        // Spawn participant actor on worker 0 (default)
        self.spawn_participant(participant_id, room_id, name.clone(), connection_id, 0)?;
        
        // Notify room actor
        self.send_to_room(
            room_id,
            RoomActorMessage::AddParticipant {
                participant_id,
                name,
                connection_id,
            },
        )?;
        
        Ok(participant_id)
    }

    /// Remove participant (convenience method)
    ///
    /// Removes participant from room, notifies room actor, and updates distributed state.
    ///
    /// # Arguments
    /// * `participant_id` - Participant to remove
    pub fn remove_participant(&self, participant_id: ParticipantId) -> Result<(), ActorError> {
        // Get room_id from participant actor before terminating
        let room_id = {
            let participants = self.participants.read();
            if let Some((actor, _)) = participants.get(&participant_id) {
                actor.room_id()
            } else {
                return Err(ActorError::NotFound {
                    actor_type: ActorType::Participant,
                    id: participant_id,
                });
            }
        };
        
        // Notify room actor first
        self.send_to_room(
            room_id,
            RoomActorMessage::RemoveParticipant { participant_id },
        )?;
        
        // Remove from distributed state (returns Result<Dot, CrdtError>)
        let _ = self.distributed_state.remove_participant(room_id as u32, participant_id as u64);
        
        // Terminate participant actor
        self.terminate_participant(participant_id)
    }

    /// Join a room (convenience method - legacy compatibility)
    pub fn join_room(
        &self,
        room_id: RoomId,
        name: String,
        connection_id: u64,
    ) -> Result<ParticipantId, ActorError> {
        // Generate unique participant ID
        let participant_id = self.generate_participant_id();
        
        // Spawn participant actor on worker 0 (default)
        self.spawn_participant(participant_id, room_id, name.clone(), connection_id, 0)?;
        
        // Notify room actor
        self.send_to_room(
            room_id,
            RoomActorMessage::AddParticipant {
                participant_id,
                name,
                connection_id,
            },
        )?;
        
        Ok(participant_id)
    }

    /// Leave a room (convenience method - legacy compatibility)
    pub fn leave_room(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> Result<(), ActorError> {
        // Notify room actor
        self.send_to_room(
            room_id,
            RoomActorMessage::RemoveParticipant { participant_id },
        )?;
        
        // Terminate participant actor
        self.terminate_participant(participant_id)
    }

    /// Publish a track (convenience method - 3-arg version for tests)
    ///
    /// Generates track ID automatically and spawns track actor.
    /// Notifies participant actor and updates distributed state.
    ///
    /// # Arguments
    /// * `participant_id` - Participant publishing the track
    /// * `kind` - Media kind (audio/video)
    /// * `ssrc` - RTP SSRC
    ///
    /// # Returns
    /// Generated track ID on success
    pub fn publish_track(
        &self,
        participant_id: ParticipantId,
        kind: MediaKind,
        ssrc: Ssrc,
    ) -> Result<TrackId, ActorError> {
        // Generate unique track ID
        let track_id = self.generate_track_id();
        
        // Call 4-arg version
        self.publish_track_with_id(participant_id, track_id, ssrc, kind)?;
        
        Ok(track_id)
    }

    /// Publish a track with explicit ID (4-arg version - internal)
    ///
    /// Renamed from original publish_track to avoid conflict.
    pub fn publish_track_with_id(
        &self,
        participant_id: ParticipantId,
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
    ) -> Result<(), ActorError> {
        // Spawn track actor on worker 0 (default)
        self.spawn_track(track_id, participant_id, ssrc, kind, 0)?;
        
        // Notify participant actor
        self.send_to_participant(
            participant_id,
            ParticipantActorMessage::PublishTrack { track_id, ssrc, kind },
        )?;
        
        Ok(())
    }

    /// Subscribe to a track (convenience method)
    ///
    /// Subscribes a participant to receive packets from a track.
    /// Sends SubscribeToTrack message to participant actor and returns
    /// the worker_id so the caller can send ActorSubscribe to the worker.
    ///
    /// # Arguments
    /// * `subscriber_id` - Participant subscribing
    /// * `track_id` - Track to subscribe to
    /// * `dest_addr` - Destination socket address for forwarding RTP packets
    ///
    /// # Returns
    /// * `Ok(worker_id)` - Worker ID that owns the track
    /// * `Err(ActorError)` - If track not found or other error
    ///
    /// # Assertions
    /// * `dest_addr.port() > 0` - Destination port must be valid
    pub fn subscribe_to_track(
        &self,
        subscriber_id: ParticipantId,
        track_id: TrackId,
        dest_addr: std::net::SocketAddr,
    ) -> Result<u32, ActorError> {
        // Precondition: validate destination address
        assert!(dest_addr.port() > 0, "destination port must be valid (> 0)");
        
        // Verify track exists and get worker ID
        let worker_id = self.registry.lookup_track(track_id).ok_or(ActorError::NotFound {
            actor_type: ActorType::Track,
            id: track_id,
        })?;
        
        // Send subscribe message to participant actor
        self.send_to_participant(
            subscriber_id,
            ParticipantActorMessage::SubscribeToTrack {
                track_id,
                target_layer: 0, // Default to base layer
            },
        )?;
        
        // Update distributed state (returns Result<Dot, CrdtError>)
        let _ = self.distributed_state.add_subscription(track_id as u64, subscriber_id as u64);
        
        // Return worker_id so caller can send ActorSubscribe message
        Ok(worker_id)
    }

    /// Unpublish a track (convenience method)
    pub fn unpublish_track(
        &self,
        participant_id: ParticipantId,
        track_id: TrackId,
    ) -> Result<(), ActorError> {
        // Notify participant actor
        self.send_to_participant(
            participant_id,
            ParticipantActorMessage::UnpublishTrack { track_id },
        )?;
        
        // Remove from distributed state (returns bool)
        let _removed = self.distributed_state.remove_track(track_id as u64);
        
        // Terminate track actor
        self.terminate_track(track_id)
    }

    // === ID Generation ===

    fn generate_room_id(&self) -> RoomId {
        use std::sync::atomic::{AtomicU64, Ordering};
        static ROOM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        ROOM_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    fn generate_participant_id(&self) -> ParticipantId {
        use std::sync::atomic::{AtomicU64, Ordering};
        static PARTICIPANT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        PARTICIPANT_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    fn generate_track_id(&self) -> TrackId {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TRACK_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        TRACK_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    // === Statistics ===

    pub fn room_count(&self) -> usize {
        self.rooms.read().len()
    }

    pub fn participant_count(&self) -> usize {
        self.participants.read().len()
    }

    pub fn track_count(&self) -> usize {
        self.tracks.read().len()
    }

    /// Get participant name by ID
    ///
    /// # Arguments
    /// * `participant_id` - The participant ID to look up
    ///
    /// # Returns
    /// The participant's name if found, None otherwise
    ///
    /// # Assertions
    /// - participant_id != 0
    pub fn get_participant_name(&self, participant_id: ParticipantId) -> Option<String> {
        assert!(participant_id != 0, "participant_id must not be 0");
        
        let participants = self.participants.read();
        participants.get(&participant_id).map(|(actor, _)| actor.name().to_string())
    }

    /// Get participant info (name and room_id) by ID
    ///
    /// # Arguments
    /// * `participant_id` - The participant ID to look up
    ///
    /// # Returns
    /// Tuple of (name, room_id) if found, None otherwise
    ///
    /// # Assertions
    /// - participant_id != 0
    pub fn get_participant_info(&self, participant_id: ParticipantId) -> Option<(String, RoomId)> {
        assert!(participant_id != 0, "participant_id must not be 0");
        
        let participants = self.participants.read();
        participants.get(&participant_id).map(|(actor, _)| {
            (actor.name().to_string(), actor.room_id())
        })
    }

    /// Get all tracks published by a participant
    ///
    /// # Arguments
    /// * `participant_id` - The participant ID to look up
    ///
    /// # Returns
    /// Vector of track IDs published by the participant
    ///
    /// # Assertions
    /// - participant_id != 0
    pub fn get_participant_tracks(&self, participant_id: ParticipantId) -> Vec<TrackId> {
        assert!(participant_id != 0, "participant_id must not be 0");
        
        let participants = self.participants.read();
        if let Some((actor, _)) = participants.get(&participant_id) {
            actor.published_tracks().to_vec()
        } else {
            Vec::new()
        }
    }

    /// Get all tracks in a room
    ///
    /// Iterates through all participants in the room and collects their published tracks.
    ///
    /// # Arguments
    /// * `room_id` - The room ID to look up
    ///
    /// # Returns
    /// Vector of (track_id, participant_id, media_kind) tuples for all tracks in the room
    ///
    /// # Assertions
    /// - room_id != 0
    pub fn get_room_tracks(&self, room_id: RoomId) -> Vec<(TrackId, ParticipantId, MediaKind)> {
        assert!(room_id != 0, "room_id must not be 0");
        
        let mut result = Vec::new();
        
        // Get all participants in the room from registry
        let participant_ids = self.registry.participants_in_room(room_id);
        
        // For each participant, get their published tracks
        let tracks = self.tracks.read();
        for pid in participant_ids {
            // Get tracks for this participant
            for (&track_id, (actor, _)) in tracks.iter() {
                if actor.participant_id() == pid {
                    result.push((track_id, pid, actor.kind()));
                }
            }
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_distributed_state() -> Arc<DistributedState> {
        let config = nexus_state::DistributedStateConfig::with_limits(1, 100, 1000, 10000);
        Arc::new(DistributedState::new(config))
    }

    #[test]
    fn test_actor_manager_new() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);
        assert_eq!(manager.room_count(), 0);
        assert_eq!(manager.participant_count(), 0);
        assert_eq!(manager.track_count(), 0);
    }

    #[test]
    fn test_spawn_room() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        let result = manager.spawn_room(1, "Test Room".to_string(), 100, 0);
        assert!(result.is_ok());
        assert_eq!(manager.room_count(), 1);

        // Verify registry
        assert_eq!(manager.registry().lookup_room(1), Some(0));
    }

    #[test]
    fn test_spawn_room_duplicate() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        manager.spawn_room(1, "Test".to_string(), 100, 0).unwrap();
        let result = manager.spawn_room(1, "Test2".to_string(), 100, 0);

        assert!(matches!(result, Err(ActorError::AlreadyExists { .. })));
    }

    #[test]
    fn test_spawn_participant() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        // Spawn room first
        manager.spawn_room(1, "Test".to_string(), 100, 0).unwrap();

        let result = manager.spawn_participant(10, 1, "Alice".to_string(), 1000, 0);
        assert!(result.is_ok());
        assert_eq!(manager.participant_count(), 1);

        // Verify registry
        assert_eq!(manager.registry().lookup_participant(10), Some(0));
    }

    #[test]
    fn test_spawn_participant_without_room() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        // Try to spawn participant without room
        let result = manager.spawn_participant(10, 1, "Alice".to_string(), 1000, 0);
        assert!(matches!(result, Err(ActorError::NotFound { .. })));
    }

    #[test]
    fn test_spawn_track() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        // Spawn room and participant first
        manager.spawn_room(1, "Test".to_string(), 100, 0).unwrap();
        manager.spawn_participant(10, 1, "Alice".to_string(), 1000, 0).unwrap();

        let result = manager.spawn_track(100, 10, 12345, MediaKind::Video, 0);
        assert!(result.is_ok());
        assert_eq!(manager.track_count(), 1);

        // Verify registry
        assert_eq!(manager.registry().lookup_track(100), Some(0));
    }

    #[test]
    fn test_spawn_track_without_participant() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        // Try to spawn track without participant
        let result = manager.spawn_track(100, 10, 12345, MediaKind::Video, 0);
        assert!(matches!(result, Err(ActorError::NotFound { .. })));
    }

    #[test]
    fn test_capacity_enforcement() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(2, 100, 1000, state);

        manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
        manager.spawn_room(2, "Room2".to_string(), 100, 0).unwrap();

        let result = manager.spawn_room(3, "Room3".to_string(), 100, 0);
        assert!(matches!(result, Err(ActorError::CapacityExceeded { .. })));
    }

    #[test]
    fn test_terminate_room() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        manager.spawn_room(1, "Test".to_string(), 100, 0).unwrap();
        assert_eq!(manager.room_count(), 1);

        let result = manager.terminate_room(1);
        assert!(result.is_ok());
        assert_eq!(manager.room_count(), 0);

        // Verify unregistered
        assert_eq!(manager.registry().lookup_room(1), None);
    }

    #[test]
    fn test_send_to_room() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        manager.spawn_room(1, "Test".to_string(), 100, 0).unwrap();

        let result = manager.send_to_room(
            1,
            RoomActorMessage::AddParticipant {
                participant_id: 10,
                name: "Alice".to_string(),
                connection_id: 1000,
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_to_nonexistent_room() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);

        let result = manager.send_to_room(999, RoomActorMessage::HealthCheck);
        assert!(matches!(result, Err(ActorError::NotFound { .. })));
    }

    #[test]
    fn test_pre_allocation() {
        let state = create_test_distributed_state();
        let mut manager = ActorManager::new(10, 100, 1000, state);

        assert!(!manager.is_pre_allocated());

        manager.pre_allocate();

        assert!(manager.is_pre_allocated());

        // Verify capacities
        let (max_rooms, max_participants, max_tracks) = manager.max_capacities();
        assert_eq!(max_rooms, 10);
        assert_eq!(max_participants, 100);
        assert_eq!(max_tracks, 1000);

        // Verify usage is still 0
        let (rooms, participants, tracks) = manager.capacity_usage();
        assert_eq!(rooms, 0);
        assert_eq!(participants, 0);
        assert_eq!(tracks, 0);
    }

    #[test]
    fn test_capacity_enforcement_after_pre_allocation() {
        let state = create_test_distributed_state();
        let mut manager = ActorManager::new(2, 5, 10, state);
        manager.pre_allocate();

        // Fill room capacity
        manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
        manager.spawn_room(2, "Room2".to_string(), 100, 0).unwrap();

        // Should still fail when full
        let result = manager.spawn_room(3, "Room3".to_string(), 100, 0);
        assert!(matches!(result, Err(ActorError::CapacityExceeded { .. })));

        let (rooms, _, _) = manager.capacity_usage();
        assert_eq!(rooms, 2);
    }

    #[test]
    fn test_supervision_config() {
        let state = create_test_distributed_state();
        let manager = ActorManager::with_supervision_config(10, 100, 1000, state, 3000, 5);
        
        assert_eq!(manager.health_timeout_ms(), 3000);
        assert_eq!(manager.max_restart_retries(), 5);
    }

    #[test]
    fn test_supervision_default_config() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);
        
        assert_eq!(manager.health_timeout_ms(), DEFAULT_HEALTH_TIMEOUT_MS);
        assert_eq!(manager.max_restart_retries(), DEFAULT_MAX_RESTART_RETRIES);
    }

    #[test]
    fn test_supervise_healthy_actors() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);
        
        // Spawn some actors
        manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
        manager.spawn_room(2, "Room2".to_string(), 100, 0).unwrap();
        
        // Run supervision - should check actors but not restart any
        let stats = manager.supervise();
        
        assert_eq!(stats.checks_performed, 2);
        assert_eq!(stats.restarts_attempted, 0);
        assert_eq!(stats.restarts_succeeded, 0);
    }

    #[test]
    fn test_supervise_bounded_checks() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(200, 1000, 10000, state);
        
        // Spawn more actors than MAX_HEALTH_CHECKS_PER_ITERATION
        for i in 1..=150 {
            manager.spawn_room(i, format!("Room{}", i), 100, 0).unwrap();
        }
        
        // Run supervision - should be bounded
        let stats = manager.supervise();
        
        // Should check at most MAX_HEALTH_CHECKS_PER_ITERATION actors
        assert!(stats.checks_performed <= MAX_HEALTH_CHECKS_PER_ITERATION as u32);
    }

    #[test]
    fn test_restart_count_tracking() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);
        
        manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
        
        // Initially no restart count
        let actor_id = ActorId::room(1);
        assert_eq!(manager.restart_count(actor_id), 0);
    }

    #[test]
    fn test_last_supervision_stats() {
        let state = create_test_distributed_state();
        let manager = ActorManager::new(10, 100, 1000, state);
        
        manager.spawn_room(1, "Room1".to_string(), 100, 0).unwrap();
        
        // Run supervision
        let stats = manager.supervise();
        
        // Verify last stats are stored
        let last_stats = manager.last_supervision_stats();
        assert_eq!(last_stats.checks_performed, stats.checks_performed);
        assert_eq!(last_stats.restarts_attempted, stats.restarts_attempted);
        assert_eq!(last_stats.restarts_succeeded, stats.restarts_succeeded);
    }
}
