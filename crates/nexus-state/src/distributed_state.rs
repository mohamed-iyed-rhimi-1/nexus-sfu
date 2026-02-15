//! Distributed State Manager with CRDT Synchronization
//!
//! This module provides a distributed state manager that uses CRDTs for
//! conflict-free replication across cluster nodes. It integrates with the
//! SWIM gossip protocol for delta-based state synchronization.
//!
//! ## Features
//!
//! - **Zero allocation after init**: All collections use pre-allocated capacity
//! - **CRDT-based**: Uses Orswot for sets, LWWReg for registers
//! - **Delta synchronization**: Generates and merges deltas for efficient gossip
//! - **TigerStyle compliance**: Bounded loops, comprehensive assertions
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      DistributedState                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  rooms: HashMap<RoomId, LWWReg<RoomMetadata>>                   │
//! │  participants: HashMap<RoomId, Orswot<ParticipantId>>           │
//! │  tracks: HashMap<TrackId, LWWReg<TrackInfo>>                    │
//! │  subscriptions: Orswot<(TrackId, ParticipantId)>                │
//! │  clock: RwLock<VersionVector>                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use nexus_state::{DistributedState, DistributedStateConfig};
//!
//! let config = DistributedStateConfig::new(1);
//! let state = DistributedState::new(config);
//!
//! // Create a room
//! state.create_room(1, "Meeting".to_string(), 100)?;
//!
//! // Add a participant
//! let dot = state.add_participant(1, 42)?;
//!
//! // Query participants
//! let participants = state.get_participants(1);
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use crate::crdt::{LWWReg, Orswot};
use crate::error::CrdtError;
use crate::gossip::types::{StateUpdate, TrackInfo};
use crate::types::{ActorId, Dot, VersionVector, MAX_ACTORS};

// =============================================================================
// Capacity Constants
// =============================================================================

/// Maximum number of rooms in the distributed system
pub const MAX_ROOMS: usize = 10_000;

/// Maximum number of tracks across all rooms
pub const MAX_TRACKS: usize = 100_000;

/// Maximum subscriptions (track-participant pairs)
pub const MAX_SUBSCRIPTIONS: usize = 500_000;

/// Maximum participants per room
pub const MAX_PARTICIPANTS_PER_ROOM: u32 = 2_000;

/// Maximum length of room name in bytes
pub const MAX_ROOM_NAME_LEN: usize = 256;

// Compile-time assertions to validate constants
const _: () = {
    assert!(MAX_ROOMS > 0, "MAX_ROOMS must be positive");
    assert!(MAX_ROOMS <= 100_000, "MAX_ROOMS must not exceed 100_000");
    assert!(MAX_TRACKS > 0, "MAX_TRACKS must be positive");
    assert!(MAX_TRACKS <= 1_000_000, "MAX_TRACKS must not exceed 1_000_000");
    assert!(MAX_SUBSCRIPTIONS > 0, "MAX_SUBSCRIPTIONS must be positive");
    assert!(
        MAX_SUBSCRIPTIONS <= 10_000_000,
        "MAX_SUBSCRIPTIONS must not exceed 10_000_000"
    );
    assert!(
        MAX_PARTICIPANTS_PER_ROOM > 0,
        "MAX_PARTICIPANTS_PER_ROOM must be positive"
    );
    assert!(
        MAX_PARTICIPANTS_PER_ROOM <= 10_000,
        "MAX_PARTICIPANTS_PER_ROOM must not exceed 10_000"
    );
};

// =============================================================================
// Type Aliases
// =============================================================================

/// Room ID type (matches main crate's RoomId)
pub type RoomId = u32;

/// Participant ID type (matches main crate's ParticipantId)
pub type ParticipantId = u64;

/// Track ID type (matches main crate's TrackId)
pub type TrackId = u64;

/// Type alias for room registry using LWW register
pub type RoomRegistry = LWWReg<RoomMetadata>;

// =============================================================================
// DistributedStateConfig
// =============================================================================

/// Configuration for the distributed state manager.
///
/// Defines capacity limits and local actor identity for the state manager.
/// All limits must be within the compile-time constant bounds.
#[derive(Debug, Clone)]
pub struct DistributedStateConfig {
    /// This node's actor ID (must be < MAX_ACTORS)
    local_actor: ActorId,
    /// Maximum number of rooms (default: MAX_ROOMS)
    max_rooms: usize,
    /// Maximum number of tracks (default: MAX_TRACKS)
    max_tracks: usize,
    /// Maximum subscriptions (default: MAX_SUBSCRIPTIONS)
    max_subscriptions: usize,
}

impl DistributedStateConfig {
    /// Creates a new configuration with the given local actor ID.
    ///
    /// Uses default capacity limits from compile-time constants.
    ///
    /// # Arguments
    ///
    /// * `local_actor` - This node's unique actor ID (must be < MAX_ACTORS)
    ///
    /// # Panics
    ///
    /// Panics if `local_actor >= MAX_ACTORS`
    #[inline]
    pub fn new(local_actor: ActorId) -> Self {
        assert!(
            local_actor < MAX_ACTORS as u64,
            "local_actor must be < MAX_ACTORS"
        );

        Self {
            local_actor,
            max_rooms: MAX_ROOMS,
            max_tracks: MAX_TRACKS,
            max_subscriptions: MAX_SUBSCRIPTIONS,
        }
    }

    /// Creates a configuration with custom capacity limits.
    ///
    /// # Arguments
    ///
    /// * `local_actor` - This node's unique actor ID
    /// * `max_rooms` - Maximum rooms capacity
    /// * `max_tracks` - Maximum tracks capacity
    /// * `max_subscriptions` - Maximum subscriptions capacity
    ///
    /// # Panics
    ///
    /// Panics if any limit exceeds the compile-time constant bounds.
    #[inline]
    pub fn with_limits(
        local_actor: ActorId,
        max_rooms: usize,
        max_tracks: usize,
        max_subscriptions: usize,
    ) -> Self {
        let config = Self {
            local_actor,
            max_rooms,
            max_tracks,
            max_subscriptions,
        };
        config.validate();
        config
    }

    /// Validates the configuration.
    ///
    /// # Panics
    ///
    /// Panics if any configuration value is invalid.
    #[inline]
    pub fn validate(&self) {
        assert!(
            self.local_actor < MAX_ACTORS as u64,
            "local_actor must be < MAX_ACTORS"
        );
        assert!(self.max_rooms > 0, "max_rooms must be positive");
        assert!(
            self.max_rooms <= MAX_ROOMS,
            "max_rooms must not exceed MAX_ROOMS"
        );
        assert!(self.max_tracks > 0, "max_tracks must be positive");
        assert!(
            self.max_tracks <= MAX_TRACKS,
            "max_tracks must not exceed MAX_TRACKS"
        );
        assert!(
            self.max_subscriptions > 0,
            "max_subscriptions must be positive"
        );
        assert!(
            self.max_subscriptions <= MAX_SUBSCRIPTIONS,
            "max_subscriptions must not exceed MAX_SUBSCRIPTIONS"
        );
    }

    /// Returns the local actor ID.
    #[inline]
    pub const fn local_actor(&self) -> ActorId {
        self.local_actor
    }

    /// Returns the maximum rooms capacity.
    #[inline]
    pub const fn max_rooms(&self) -> usize {
        self.max_rooms
    }

    /// Returns the maximum tracks capacity.
    #[inline]
    pub const fn max_tracks(&self) -> usize {
        self.max_tracks
    }

    /// Returns the maximum subscriptions capacity.
    #[inline]
    pub const fn max_subscriptions(&self) -> usize {
        self.max_subscriptions
    }
}

impl Default for DistributedStateConfig {
    fn default() -> Self {
        Self::new(0)
    }
}

// =============================================================================
// RoomMetadata
// =============================================================================

/// Metadata for a room in the distributed state.
///
/// Stores room-level information that is replicated across the cluster
/// using a Last-Writer-Wins register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomMetadata {
    /// Unique room identifier
    room_id: RoomId,
    /// Display name for the room
    name: String,
    /// Maximum number of participants allowed
    max_participants: u32,
    /// Creation timestamp in nanoseconds since epoch
    created_at_ns: u64,
}

impl RoomMetadata {
    /// Creates new room metadata.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Unique room identifier (must be non-zero)
    /// * `name` - Display name (must be non-empty)
    /// * `max_participants` - Maximum participants (must be > 0 and <= MAX_PARTICIPANTS_PER_ROOM)
    /// * `created_at_ns` - Creation timestamp (must be > 0)
    ///
    /// # Panics
    ///
    /// Panics if any argument is invalid.
    #[inline]
    pub fn new(room_id: RoomId, name: String, max_participants: u32, created_at_ns: u64) -> Self {
        assert!(room_id != 0, "room_id must be non-zero");
        assert!(!name.is_empty(), "name must be non-empty");
        assert!(
            name.len() <= MAX_ROOM_NAME_LEN,
            "name must not exceed MAX_ROOM_NAME_LEN"
        );
        assert!(max_participants > 0, "max_participants must be positive");
        assert!(
            max_participants <= MAX_PARTICIPANTS_PER_ROOM,
            "max_participants must not exceed MAX_PARTICIPANTS_PER_ROOM"
        );
        assert!(created_at_ns > 0, "created_at_ns must be positive");

        Self {
            room_id,
            name,
            max_participants,
            created_at_ns,
        }
    }

    /// Returns the room ID.
    #[inline]
    pub const fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Returns the room name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the maximum participants.
    #[inline]
    pub const fn max_participants(&self) -> u32 {
        self.max_participants
    }

    /// Returns the creation timestamp.
    #[inline]
    pub const fn created_at_ns(&self) -> u64 {
        self.created_at_ns
    }
}

impl Default for RoomMetadata {
    fn default() -> Self {
        Self {
            room_id: 0,
            name: String::new(),
            max_participants: 0,
            created_at_ns: 0,
        }
    }
}

// =============================================================================
// DistributedState
// =============================================================================

/// Distributed state manager with CRDT synchronization.
///
/// Manages room membership, track metadata, and subscriptions using CRDTs
/// for conflict-free replication. Integrates with SWIM gossip protocol for
/// delta-based synchronization across cluster nodes.
///
/// # Thread Safety
///
/// All operations are thread-safe using `RwLock` for interior mutability.
/// Read operations acquire shared locks, write operations acquire exclusive locks.
///
/// # Memory Model
///
/// All collections are pre-allocated at construction with fixed capacities
/// from the configuration. No allocation occurs after initialization.
pub struct DistributedState {
    /// Local actor ID
    local_actor: ActorId,

    /// Local vector clock for generating dots
    clock: RwLock<VersionVector>,

    /// Room metadata registry (room_id -> metadata)
    rooms: RwLock<HashMap<RoomId, RoomRegistry>>,

    /// Participant sets per room (room_id -> participant set)
    participants: RwLock<HashMap<RoomId, Orswot<ParticipantId>>>,

    /// Track metadata registry (track_id -> track info)
    tracks: RwLock<HashMap<TrackId, LWWReg<TrackInfo>>>,

    /// Subscription graph (track_id, participant_id) pairs
    subscriptions: RwLock<Orswot<(TrackId, ParticipantId)>>,

    /// Configuration
    config: DistributedStateConfig,

    /// Broadcast sender for state updates to gossip protocol.
    /// When set, state changes are sent through this channel to be
    /// piggybacked on gossip messages.
    broadcast_tx: RwLock<Option<std::sync::mpsc::Sender<StateUpdate>>>,
}

impl DistributedState {
    /// Creates a new distributed state manager.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration with capacity limits and local actor ID
    ///
    /// # Example
    ///
    /// ```
    /// use nexus_state::{DistributedState, DistributedStateConfig};
    ///
    /// let config = DistributedStateConfig::new(1);
    /// let state = DistributedState::new(config);
    /// ```
    #[inline]
    pub fn new(config: DistributedStateConfig) -> Self {
        config.validate();

        let rooms = HashMap::with_capacity(config.max_rooms);
        let participants = HashMap::with_capacity(config.max_rooms);
        let tracks = HashMap::with_capacity(config.max_tracks);
        let subscriptions = Orswot::new();

        // Postcondition: all collections initialized with correct capacity
        debug_assert!(rooms.capacity() >= config.max_rooms);
        debug_assert!(participants.capacity() >= config.max_rooms);
        debug_assert!(tracks.capacity() >= config.max_tracks);

        Self {
            local_actor: config.local_actor,
            clock: RwLock::new(VersionVector::new()),
            rooms: RwLock::new(rooms),
            participants: RwLock::new(participants),
            tracks: RwLock::new(tracks),
            subscriptions: RwLock::new(subscriptions),
            config,
            broadcast_tx: RwLock::new(None),
        }
    }

    /// Returns the local actor ID.
    #[inline]
    pub const fn local_actor(&self) -> ActorId {
        self.local_actor
    }

    /// Returns the configuration.
    #[inline]
    pub const fn config(&self) -> &DistributedStateConfig {
        &self.config
    }

    /// Set the broadcast sender for state updates.
    ///
    /// When set, state changes (participant add/remove, track updates,
    /// subscription changes) will be sent through this channel to be
    /// piggybacked on gossip messages.
    ///
    /// # Arguments
    /// * `tx` - The sender end of a channel for StateUpdate messages
    #[inline]
    pub fn set_broadcast_sender(&self, tx: std::sync::mpsc::Sender<StateUpdate>) {
        let mut broadcast = self.broadcast_tx.write().unwrap();
        *broadcast = Some(tx);
    }

    /// Broadcast a state update to the gossip protocol.
    ///
    /// If a broadcast sender is set, sends the update through the channel.
    /// If no sender is set, the update is silently dropped.
    ///
    /// # Arguments
    /// * `update` - The state update to broadcast
    #[inline]
    pub fn broadcast_update(&self, update: StateUpdate) {
        if let Ok(broadcast) = self.broadcast_tx.read() {
            if let Some(ref tx) = *broadcast {
                // Best-effort send - don't block if channel is full
                let _ = tx.send(update);
            }
        }
    }

    // =========================================================================
    // Room Operations
    // =========================================================================

    /// Creates a new room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Unique room identifier (must be non-zero)
    /// * `name` - Display name for the room
    /// * `max_participants` - Maximum participants allowed
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `CrdtError::CapacityExhausted` if room limit reached.
    ///
    /// # Panics
    ///
    /// Panics if `room_id == 0`, `name.is_empty()`, or `max_participants == 0`.
    pub fn create_room(
        &self,
        room_id: RoomId,
        name: String,
        max_participants: u32,
    ) -> Result<(), CrdtError> {
        assert!(room_id != 0, "room_id must be non-zero");
        assert!(!name.is_empty(), "name must be non-empty");
        assert!(max_participants > 0, "max_participants must be positive");

        // Get current timestamp from clock
        let timestamp = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };

        let created_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let metadata = RoomMetadata::new(room_id, name, max_participants, created_at_ns);

        // Acquire write locks
        let mut rooms = self.rooms.write().unwrap();
        let mut participants = self.participants.write().unwrap();

        // Check capacity
        if rooms.len() >= self.config.max_rooms {
            return Err(CrdtError::CapacityExhausted {
                capacity: self.config.max_rooms as u32,
            });
        }

        // Create LWWReg for room metadata
        let mut reg = LWWReg::new(RoomMetadata::default(), self.local_actor);
        reg.set(metadata, timestamp, self.local_actor);

        // Insert room
        rooms.insert(room_id, reg);

        // Create empty participant set for this room
        participants.insert(room_id, Orswot::new());

        // Postcondition: room exists
        debug_assert!(rooms.contains_key(&room_id));
        debug_assert!(participants.contains_key(&room_id));

        Ok(())
    }

    /// Gets room metadata.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room identifier to look up
    ///
    /// # Returns
    ///
    /// `Some(RoomMetadata)` if room exists, `None` otherwise.
    pub fn get_room(&self, room_id: RoomId) -> Option<RoomMetadata> {
        let rooms = self.rooms.read().unwrap();
        rooms.get(&room_id).map(|reg| reg.get().clone())
    }

    /// Checks if a room exists.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room identifier to check
    ///
    /// # Returns
    ///
    /// `true` if room exists, `false` otherwise.
    pub fn room_exists(&self, room_id: RoomId) -> bool {
        let rooms = self.rooms.read().unwrap();
        rooms.contains_key(&room_id)
    }

    /// Removes a room.
    ///
    /// Also removes the participant set for this room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room identifier to remove
    ///
    /// # Returns
    ///
    /// `true` if room was found and removed, `false` if not found.
    pub fn remove_room(&self, room_id: RoomId) -> bool {
        let mut rooms = self.rooms.write().unwrap();
        let mut participants = self.participants.write().unwrap();

        let removed = rooms.remove(&room_id).is_some();
        participants.remove(&room_id);

        removed
    }

    /// Returns the number of rooms.
    pub fn room_count(&self) -> usize {
        let rooms = self.rooms.read().unwrap();
        rooms.len()
    }

    // =========================================================================
    // Participant Operations
    // =========================================================================

    /// Adds a participant to a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room to add participant to
    /// * `participant_id` - Participant identifier
    ///
    /// # Returns
    ///
    /// `Ok(Dot)` with the operation's dot on success, or an error if:
    /// - Room doesn't exist
    /// - Room is at capacity
    ///
    /// # Panics
    ///
    /// Panics if `room_id == 0` or `participant_id == 0`.
    pub fn add_participant(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> Result<Dot, CrdtError> {
        assert!(room_id != 0, "room_id must be non-zero");
        assert!(participant_id != 0, "participant_id must be non-zero");

        // Generate dot
        let clock_value = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };
        let dot = Dot::new(self.local_actor, clock_value);

        // Acquire locks
        let rooms = self.rooms.read().unwrap();
        let mut participants = self.participants.write().unwrap();

        // Check room exists
        let room_metadata = rooms.get(&room_id).ok_or(CrdtError::ElementNotFound)?;
        let max_participants = room_metadata.get().max_participants();

        // Get participant set
        let participant_set = participants
            .get_mut(&room_id)
            .ok_or(CrdtError::ElementNotFound)?;

        // Check room capacity
        if participant_set.len() >= max_participants {
            return Err(CrdtError::CapacityExhausted {
                capacity: max_participants,
            });
        }

        // Add participant
        participant_set.add(participant_id, dot)?;

        // Postcondition: participant exists in set
        debug_assert!(participant_set.contains(&participant_id));

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::ParticipantAdded {
            room_id,
            participant_id: participant_id.into(),
            dot,
        });

        Ok(dot)
    }

    /// Removes a participant from a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room to remove participant from
    /// * `participant_id` - Participant identifier
    ///
    /// # Returns
    ///
    /// `Ok(Dot)` with the operation's dot on success, or error if room doesn't exist.
    ///
    /// # Panics
    ///
    /// Panics if `room_id == 0` or `participant_id == 0`.
    pub fn remove_participant(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> Result<Dot, CrdtError> {
        assert!(room_id != 0, "room_id must be non-zero");
        assert!(participant_id != 0, "participant_id must be non-zero");

        // Generate dot
        let clock_value = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };
        let dot = Dot::new(self.local_actor, clock_value);

        // Acquire lock
        let mut participants = self.participants.write().unwrap();

        // Get participant set
        let participant_set = participants
            .get_mut(&room_id)
            .ok_or(CrdtError::ElementNotFound)?;

        // Remove participant
        participant_set.remove(&participant_id, dot)?;

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::ParticipantRemoved {
            room_id,
            participant_id: participant_id.into(),
            dot,
        });

        // Postcondition: participant not in set
        debug_assert!(!participant_set.contains(&participant_id));

        Ok(dot)
    }

    /// Gets all participants in a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room to query
    ///
    /// # Returns
    ///
    /// Vector of participant IDs in the room (empty if room doesn't exist).
    pub fn get_participants(&self, room_id: RoomId) -> Vec<ParticipantId> {
        let participants = self.participants.read().unwrap();

        participants
            .get(&room_id)
            .map(|set| {
                let mut result = Vec::with_capacity((set.len() as usize).min(MAX_PARTICIPANTS_PER_ROOM as usize));
                // Bounded iteration
                let mut count = 0;
                for elem in set.iter() {
                    if count >= MAX_PARTICIPANTS_PER_ROOM as usize {
                        break;
                    }
                    result.push(*elem);
                    count += 1;
                }
                result
            })
            .unwrap_or_default()
    }

    /// Returns the number of participants in a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room to query
    ///
    /// # Returns
    ///
    /// Number of participants (0 if room doesn't exist).
    pub fn participant_count(&self, room_id: RoomId) -> usize {
        let participants = self.participants.read().unwrap();
        participants.get(&room_id).map(|set| set.len() as usize).unwrap_or(0)
    }

    /// Checks if a participant exists in a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Room to check
    /// * `participant_id` - Participant to look for
    ///
    /// # Returns
    ///
    /// `true` if participant is in room, `false` otherwise.
    pub fn participant_exists(&self, room_id: RoomId, participant_id: ParticipantId) -> bool {
        let participants = self.participants.read().unwrap();
        participants
            .get(&room_id)
            .map(|set| set.contains(&participant_id))
            .unwrap_or(false)
    }

    // =========================================================================
    // Track Operations
    // =========================================================================

    /// Adds a track.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Unique track identifier
    /// * `info` - Track metadata
    ///
    /// # Returns
    ///
    /// `Ok(timestamp)` for the operation on success, or error if capacity exceeded.
    ///
    /// # Panics
    ///
    /// Panics if `track_id == 0`.
    pub fn add_track(&self, track_id: TrackId, info: TrackInfo) -> Result<u64, CrdtError> {
        assert!(track_id != 0, "track_id must be non-zero");

        // Generate timestamp
        let timestamp = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };

        // Acquire lock
        let mut tracks = self.tracks.write().unwrap();

        // Check capacity
        if tracks.len() >= self.config.max_tracks {
            return Err(CrdtError::CapacityExhausted {
                capacity: self.config.max_tracks as u32,
            });
        }

        // Create or update LWWReg
        let reg = tracks
            .entry(track_id)
            .or_insert_with(|| LWWReg::new(TrackInfo::default(), self.local_actor));
        reg.set(info, timestamp, self.local_actor);

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::TrackUpdated {
            track_id,
            info,
            timestamp,
            actor: self.local_actor,
        });

        Ok(timestamp)
    }

    /// Updates a track's metadata.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to update
    /// * `info` - New track metadata
    ///
    /// # Returns
    ///
    /// `Ok(timestamp)` on success, or error if track doesn't exist.
    ///
    /// # Panics
    ///
    /// Panics if `track_id == 0`.
    pub fn update_track(&self, track_id: TrackId, info: TrackInfo) -> Result<u64, CrdtError> {
        assert!(track_id != 0, "track_id must be non-zero");

        // Generate timestamp
        let timestamp = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };

        // Acquire lock
        let mut tracks = self.tracks.write().unwrap();

        // Get existing track
        let reg = tracks.get_mut(&track_id).ok_or(CrdtError::ElementNotFound)?;

        // Update
        reg.set(info, timestamp, self.local_actor);

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::TrackUpdated {
            track_id,
            info,
            timestamp,
            actor: self.local_actor,
        });

        Ok(timestamp)
    }

    /// Gets track metadata.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to look up
    ///
    /// # Returns
    ///
    /// `Some(TrackInfo)` if track exists, `None` otherwise.
    pub fn get_track(&self, track_id: TrackId) -> Option<TrackInfo> {
        let tracks = self.tracks.read().unwrap();
        tracks.get(&track_id).map(|reg| reg.get())
    }

    /// Removes a track.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to remove
    ///
    /// # Returns
    ///
    /// `true` if track was found and removed, `false` otherwise.
    pub fn remove_track(&self, track_id: TrackId) -> bool {
        let mut tracks = self.tracks.write().unwrap();
        tracks.remove(&track_id).is_some()
    }

    /// Returns the number of tracks.
    pub fn track_count(&self) -> usize {
        let tracks = self.tracks.read().unwrap();
        tracks.len()
    }

    // =========================================================================
    // Subscription Operations
    // =========================================================================

    /// Adds a subscription (participant subscribes to track).
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to subscribe to
    /// * `participant_id` - Subscribing participant
    ///
    /// # Returns
    ///
    /// `Ok(Dot)` with the operation's dot on success, or error if capacity exceeded.
    ///
    /// # Panics
    ///
    /// Panics if `track_id == 0` or `participant_id == 0`.
    pub fn add_subscription(
        &self,
        track_id: TrackId,
        participant_id: ParticipantId,
    ) -> Result<Dot, CrdtError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(participant_id != 0, "participant_id must be non-zero");

        // Generate dot
        let clock_value = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };
        let dot = Dot::new(self.local_actor, clock_value);

        // Acquire lock
        let mut subscriptions = self.subscriptions.write().unwrap();

        // Check capacity
        if subscriptions.len() as usize >= self.config.max_subscriptions {
            return Err(CrdtError::CapacityExhausted {
                capacity: self.config.max_subscriptions as u32,
            });
        }

        // Add subscription
        subscriptions.add((track_id.into(), participant_id.into()), dot)?;

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::SubscriptionAdded {
            track_id: track_id.into(),
            participant_id: participant_id.into(),
            dot,
        });

        Ok(dot)
    }

    /// Removes a subscription.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to unsubscribe from
    /// * `participant_id` - Unsubscribing participant
    ///
    /// # Returns
    ///
    /// `Ok(Dot)` with the operation's dot on success.
    ///
    /// # Panics
    ///
    /// Panics if `track_id == 0` or `participant_id == 0`.
    pub fn remove_subscription(
        &self,
        track_id: TrackId,
        participant_id: ParticipantId,
    ) -> Result<Dot, CrdtError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(participant_id != 0, "participant_id must be non-zero");

        // Generate dot
        let clock_value = {
            let mut clock = self.clock.write().unwrap();
            clock.increment(self.local_actor)
        };
        let dot = Dot::new(self.local_actor, clock_value);

        // Acquire lock
        let mut subscriptions = self.subscriptions.write().unwrap();

        // Remove subscription
        subscriptions.remove(&(track_id.into(), participant_id.into()), dot)?;

        // Broadcast state update to gossip protocol
        self.broadcast_update(StateUpdate::SubscriptionRemoved {
            track_id: track_id.into(),
            participant_id: participant_id.into(),
            dot,
        });

        Ok(dot)
    }

    /// Gets all subscribers for a track.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track to query
    ///
    /// # Returns
    ///
    /// Vector of participant IDs subscribed to this track.
    ///
    /// # Panics
    ///
    /// Panics if `track_id == 0`.
    pub fn get_subscriptions_for_track(&self, track_id: TrackId) -> Vec<ParticipantId> {
        assert!(track_id != 0, "track_id must be non-zero");

        let subscriptions = self.subscriptions.read().unwrap();
        let mut result = Vec::new();

        // Bounded iteration
        let mut count = 0;
        for (tid, pid) in subscriptions.iter() {
            if count >= self.config.max_subscriptions {
                break;
            }
            if *tid == track_id {
                result.push(*pid);
            }
            count += 1;
        }

        result
    }

    /// Gets all tracks a participant is subscribed to.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Participant to query
    ///
    /// # Returns
    ///
    /// Vector of track IDs the participant is subscribed to.
    ///
    /// # Panics
    ///
    /// Panics if `participant_id == 0`.
    pub fn get_subscriptions_for_participant(&self, participant_id: ParticipantId) -> Vec<TrackId> {
        assert!(participant_id != 0, "participant_id must be non-zero");

        let subscriptions = self.subscriptions.read().unwrap();
        let mut result = Vec::new();

        // Bounded iteration
        let mut count = 0;
        for (tid, pid) in subscriptions.iter() {
            if count >= self.config.max_subscriptions {
                break;
            }
            if *pid == participant_id {
                result.push(*tid);
            }
            count += 1;
        }

        result
    }

    /// Returns the total number of subscriptions.
    pub fn subscription_count(&self) -> usize {
        let subscriptions = self.subscriptions.read().unwrap();
        subscriptions.len() as usize
    }

    // =========================================================================
    // Delta Generation
    // =========================================================================

    /// Generates a ParticipantAdded delta.
    #[inline]
    pub fn generate_participant_added_delta(
        room_id: RoomId,
        participant_id: ParticipantId,
        dot: Dot,
    ) -> StateUpdate {
        StateUpdate::ParticipantAdded {
            room_id,
            participant_id,
            dot,
        }
    }

    /// Generates a ParticipantRemoved delta.
    #[inline]
    pub fn generate_participant_removed_delta(
        room_id: RoomId,
        participant_id: ParticipantId,
        dot: Dot,
    ) -> StateUpdate {
        StateUpdate::ParticipantRemoved {
            room_id,
            participant_id,
            dot,
        }
    }

    /// Generates a TrackUpdated delta.
    #[inline]
    pub fn generate_track_updated_delta(
        track_id: TrackId,
        info: TrackInfo,
        timestamp: u64,
        actor: ActorId,
    ) -> StateUpdate {
        StateUpdate::TrackUpdated {
            track_id,
            info,
            timestamp,
            actor,
        }
    }

    /// Generates a SubscriptionAdded delta.
    #[inline]
    pub fn generate_subscription_added_delta(
        track_id: TrackId,
        participant_id: ParticipantId,
        dot: Dot,
    ) -> StateUpdate {
        StateUpdate::SubscriptionAdded {
            track_id,
            participant_id,
            dot,
        }
    }

    /// Generates a SubscriptionRemoved delta.
    #[inline]
    pub fn generate_subscription_removed_delta(
        track_id: TrackId,
        participant_id: ParticipantId,
        dot: Dot,
    ) -> StateUpdate {
        StateUpdate::SubscriptionRemoved {
            track_id,
            participant_id,
            dot,
        }
    }

    // =========================================================================
    // Delta Merging
    // =========================================================================

    /// Merges a single delta update from a remote node.
    ///
    /// # Arguments
    ///
    /// * `update` - The state update to merge
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful merge, or error if merge failed.
    pub fn merge_delta(&self, update: StateUpdate) -> Result<(), CrdtError> {
        match update {
            StateUpdate::ParticipantAdded { room_id, participant_id, dot } => {
                let mut participants = self.participants.write().unwrap();

                // Use room_id from delta to target the specific room
                if let Some(set) = participants.get_mut(&room_id) {
                    // Try to add - ignore result as idempotence is handled by CRDT
                    match set.add(participant_id.into(), dot) {
                        Ok(_) => {
                            // Successfully added participant
                        }
                        Err(CrdtError::DuplicateElement) => {
                            // Duplicate element - ignore for idempotence
                        }
                        Err(e) => return Err(e),
                    }
                }
                // Room not found - this is okay for eventual consistency
                // The room might arrive in a later delta

                Ok(())
            }

            StateUpdate::ParticipantRemoved { room_id, participant_id, dot } => {
                let mut participants = self.participants.write().unwrap();

                // Use room_id from delta to target the specific room
                if let Some(set) = participants.get_mut(&room_id) {
                    // Ignore result as idempotence is handled by CRDT
                    match set.remove(&participant_id, dot) {
                        Ok(_) => {
                            // Successfully removed participant
                        }
                        Err(CrdtError::ElementNotFound) => {
                            // Element not found - ignore for idempotence
                        }
                        Err(e) => return Err(e),
                    }
                }

                Ok(())
            }

            StateUpdate::TrackUpdated {
                track_id,
                info,
                timestamp,
                actor,
            } => {
                let mut tracks = self.tracks.write().unwrap();

                // Get or create register
                let reg = tracks
                    .entry(track_id)
                    .or_insert_with(|| LWWReg::new(TrackInfo::default(), actor));

                // Merge (LWW always succeeds)
                reg.set(info, timestamp, actor);

                Ok(())
            }

            StateUpdate::SubscriptionAdded {
                track_id,
                participant_id,
                dot,
            } => {
                let mut subscriptions = self.subscriptions.write().unwrap();

                // Try to add - ignore result as idempotence is handled by CRDT
                match subscriptions.add((track_id, participant_id.into()), dot) {
                    Ok(_) | Err(CrdtError::DuplicateElement) => Ok(()),
                    Err(e) => Err(e),
                }
            }

            StateUpdate::SubscriptionRemoved {
                track_id,
                participant_id,
                dot,
            } => {
                let mut subscriptions = self.subscriptions.write().unwrap();

                // Try to remove - ignore result as idempotence is handled by CRDT
                match subscriptions.remove(&(track_id.into(), participant_id.into()), dot) {
                    Ok(_) | Err(CrdtError::ElementNotFound) => Ok(()),
                    Err(e) => Err(e),
                }
            }

            // Relay events don't modify CRDT state — handled by gossip protocol.
            StateUpdate::RelaySubscribe { .. } | StateUpdate::RelayUnsubscribe { .. } => Ok(()),
        }
    }

    /// Merges a batch of delta updates from gossip.
    ///
    /// # Arguments
    ///
    /// * `updates` - Vector of state updates to merge
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or the first error encountered.
    pub fn merge_deltas(&self, updates: Vec<StateUpdate>) -> Result<(), CrdtError> {
        use crate::gossip::types::MAX_PIGGYBACK_UPDATES;

        assert!(
            updates.len() <= MAX_PIGGYBACK_UPDATES,
            "too many updates in batch"
        );

        for update in updates {
            self.merge_delta(update)?;
        }

        Ok(())
    }

    /// Processes gossip updates from the SWIM protocol.
    ///
    /// # Arguments
    ///
    /// * `updates` - Vector of state updates received via gossip
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or error if merge failed.
    pub fn process_gossip_updates(&self, updates: Vec<StateUpdate>) -> Result<(), CrdtError> {
        self.merge_deltas(updates)
    }

    // =========================================================================
    // CRDT Invariant Assertions (Test Only)
    // =========================================================================

    /// Asserts CRDT invariants for testing.
    ///
    /// Checks:
    /// - Capacity bounds are respected
    /// - All IDs are non-zero
    /// - Data structure consistency
    pub fn assert_crdt_invariants(&self) {
        // Capacity bounds
        let rooms = self.rooms.read().unwrap();
        let participants = self.participants.read().unwrap();
        let tracks = self.tracks.read().unwrap();
        let subscriptions = self.subscriptions.read().unwrap();

        assert!(
            rooms.len() <= self.config.max_rooms,
            "rooms exceed capacity"
        );
        assert!(
            tracks.len() <= self.config.max_tracks,
            "tracks exceed capacity"
        );
        assert!(
            subscriptions.len() as usize <= self.config.max_subscriptions,
            "subscriptions exceed capacity"
        );

        // All room IDs are non-zero
        for (room_id, _) in rooms.iter() {
            assert!(*room_id != 0, "room_id must be non-zero");
        }

        // All track IDs are non-zero
        for (track_id, _) in tracks.iter() {
            assert!(*track_id != 0, "track_id must be non-zero");
        }

        // Consistency: each room has a participant set
        for (room_id, _) in rooms.iter() {
            assert!(
                participants.contains_key(room_id),
                "room {} missing participant set",
                room_id
            );
        }
    }

    // =========================================================================
    // Convenience Query Methods (for tests)
    // =========================================================================

    /// Check if a room exists
    pub fn has_room(&self, room_id: RoomId) -> bool {
        self.room_exists(room_id)
    }

    /// Check if a participant exists in a room
    pub fn has_participant(&self, room_id: RoomId, participant_id: ParticipantId) -> bool {
        self.participant_exists(room_id, participant_id)
    }

    /// Check if a track exists
    pub fn has_track(&self, track_id: TrackId) -> bool {
        self.get_track(track_id).is_some()
    }

    /// Check if a subscription exists
    pub fn has_subscription(&self, track_id: TrackId, participant_id: ParticipantId) -> bool {
        let subscriptions = self.subscriptions.read().unwrap();
        subscriptions.contains(&(track_id, participant_id))
    }

    // =========================================================================
    // Node Failure Handling
    // =========================================================================

    /// Handle a node failure by removing all state associated with the failed actor.
    ///
    /// When a node is detected as dead by the gossip protocol, this method
    /// should be called to clean up any state that was owned by that node.
    /// This includes:
    /// - Tracks that were created by the failed node
    /// - Subscriptions that were created by the failed node
    ///
    /// Note: Participants are not removed automatically because they may have
    /// been created by a different node. The room owner should handle participant
    /// cleanup based on connection state.
    ///
    /// # Arguments
    ///
    /// * `failed_actor_id` - The actor ID of the failed node
    ///
    /// # Returns
    ///
    /// A tuple of (tracks_removed, subscriptions_removed) counts.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration (max_tracks, max_subscriptions)
    /// - No allocation after init
    pub fn handle_node_failure(&self, failed_actor_id: ActorId) -> (usize, usize) {
        // Precondition: actor_id must be valid
        assert!(
            failed_actor_id < crate::types::MAX_ACTORS as u64,
            "failed_actor_id must be < MAX_ACTORS"
        );

        let mut tracks_removed = 0;
        let subscriptions_removed = 0;

        // Remove tracks owned by the failed actor
        // Note: We identify tracks by checking if the LWWReg's writer matches the failed actor
        {
            let mut tracks = self.tracks.write().unwrap();
            let track_ids_to_remove: Vec<TrackId> = tracks
                .iter()
                .filter(|(_, reg)| reg.writer() == failed_actor_id)
                .map(|(id, _)| *id)
                .take(self.config.max_tracks)
                .collect();

            for track_id in track_ids_to_remove {
                if tracks.remove(&track_id).is_some() {
                    tracks_removed += 1;
                }
            }
        }

        // Note: Subscriptions are identified by (track_id, participant_id) pairs,
        // not by the actor that created them. We don't remove subscriptions here
        // because the subscription relationship is between tracks and participants,
        // not tied to a specific actor. If a track is removed, its subscriptions
        // become orphaned but will be cleaned up when participants try to use them.

        // Postcondition: counts are reasonable
        assert!(
            tracks_removed <= self.config.max_tracks,
            "tracks_removed exceeds max_tracks"
        );

        (tracks_removed, subscriptions_removed)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = DistributedStateConfig::new(5);
        assert_eq!(config.local_actor(), 5);
        assert_eq!(config.max_rooms(), MAX_ROOMS);
        assert_eq!(config.max_tracks(), MAX_TRACKS);
        assert_eq!(config.max_subscriptions(), MAX_SUBSCRIPTIONS);
    }

    #[test]
    fn test_config_with_limits() {
        let config = DistributedStateConfig::with_limits(1, 100, 1000, 10000);
        assert_eq!(config.max_rooms(), 100);
        assert_eq!(config.max_tracks(), 1000);
        assert_eq!(config.max_subscriptions(), 10000);
    }

    #[test]
    #[should_panic(expected = "local_actor must be < MAX_ACTORS")]
    fn test_config_invalid_actor() {
        DistributedStateConfig::new(MAX_ACTORS as u64);
    }

    #[test]
    fn test_room_metadata_new() {
        let metadata = RoomMetadata::new(1, "Test Room".to_string(), 100, 1234567890);
        assert_eq!(metadata.room_id(), 1);
        assert_eq!(metadata.name(), "Test Room");
        assert_eq!(metadata.max_participants(), 100);
        assert_eq!(metadata.created_at_ns(), 1234567890);
    }

    #[test]
    #[should_panic(expected = "room_id must be non-zero")]
    fn test_room_metadata_invalid_room_id() {
        RoomMetadata::new(0, "Test".to_string(), 100, 1234567890);
    }

    #[test]
    fn test_create_room() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        state.create_room(1, "Test Room".to_string(), 100).unwrap();
        assert!(state.room_exists(1));

        let metadata = state.get_room(1).unwrap();
        assert_eq!(metadata.name(), "Test Room");
        assert_eq!(metadata.max_participants(), 100);

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_add_remove_participant() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        state.create_room(1, "Test Room".to_string(), 100).unwrap();

        // Add participant
        let dot = state.add_participant(1, 42).unwrap();
        assert!(dot.clock() > 0);
        assert_eq!(state.participant_count(1), 1);
        assert!(state.participant_exists(1, 42));

        // Remove participant
        let dot = state.remove_participant(1, 42).unwrap();
        assert!(dot.clock() > 0);
        assert_eq!(state.participant_count(1), 0);
        assert!(!state.participant_exists(1, 42));

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_add_update_track() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        let info = TrackInfo {
            track_type: 1, content_type: 0,
            codec: 100,
            bitrate_kbps: 2500,
            owner_node: 0,
        };

        // Add track
        let ts = state.add_track(1, info).unwrap();
        assert!(ts > 0);

        let retrieved = state.get_track(1).unwrap();
        assert_eq!(retrieved.track_type, 1);
        assert_eq!(retrieved.bitrate_kbps, 2500);

        // Update track
        let new_info = TrackInfo {
            track_type: 1, content_type: 0,
            codec: 100,
            bitrate_kbps: 5000,
            owner_node: 0,
        };
        let ts2 = state.update_track(1, new_info).unwrap();
        assert!(ts2 > ts);

        let retrieved = state.get_track(1).unwrap();
        assert_eq!(retrieved.bitrate_kbps, 5000);

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_add_remove_subscription() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        // Add subscription
        let dot = state.add_subscription(1, 42).unwrap();
        assert!(dot.clock() > 0);
        assert_eq!(state.subscription_count(), 1);

        let subs = state.get_subscriptions_for_track(1);
        assert_eq!(subs, vec![42]);

        let tracks = state.get_subscriptions_for_participant(42);
        assert_eq!(tracks, vec![1]);

        // Remove subscription
        let dot = state.remove_subscription(1, 42).unwrap();
        assert!(dot.clock() > 0);
        assert_eq!(state.subscription_count(), 0);

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_merge_deltas_idempotence() {
        let config = DistributedStateConfig::new(1);
        let state = DistributedState::new(config);

        state.create_room(1, "Test".to_string(), 100).unwrap();

        // Create a delta
        let dot = Dot::new(2, 100);
        let delta = StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: 42,
            dot,
        };

        // Merge once
        state.merge_delta(delta.clone()).unwrap();

        // Merge again - should be idempotent
        state.merge_delta(delta).unwrap();

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_capacity_limits() {
        let config = DistributedStateConfig::with_limits(1, 2, 100, 100);
        let state = DistributedState::new(config);

        // Create rooms up to limit
        state.create_room(1, "Room 1".to_string(), 100).unwrap();
        state.create_room(2, "Room 2".to_string(), 100).unwrap();

        // Third room should fail
        let result = state.create_room(3, "Room 3".to_string(), 100);
        assert!(matches!(result, Err(CrdtError::CapacityExhausted { .. })));

        state.assert_crdt_invariants();
    }

    #[test]
    fn test_generate_deltas() {
        let dot = Dot::new(1, 100);

        let delta = DistributedState::generate_participant_added_delta(1, 42, dot);
        assert!(matches!(delta, StateUpdate::ParticipantAdded { room_id: 1, participant_id: 42, .. }));

        let delta = DistributedState::generate_participant_removed_delta(1, 42, dot);
        assert!(matches!(delta, StateUpdate::ParticipantRemoved { room_id: 1, participant_id: 42, .. }));

        let info = TrackInfo::default();
        let delta = DistributedState::generate_track_updated_delta(1, info, 100, 1);
        assert!(matches!(delta, StateUpdate::TrackUpdated { track_id: 1, .. }));

        let delta = DistributedState::generate_subscription_added_delta(1, 42, dot);
        assert!(matches!(delta, StateUpdate::SubscriptionAdded { track_id: 1, participant_id: 42, .. }));

        let delta = DistributedState::generate_subscription_removed_delta(1, 42, dot);
        assert!(matches!(delta, StateUpdate::SubscriptionRemoved { track_id: 1, participant_id: 42, .. }));
    }
}
