//! Actor registry for location tracking
//!
//! Maps actor IDs (Room/Participant/Track) -> WorkerId for message routing.
//! Thread-safe with RwLock (read-heavy workload).

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::types::*;

/// Maximum actors in registry
const MAX_REGISTRY_SIZE: usize = 100_000;

/// Actor type discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActorType {
    Room = 0,
    Participant = 1,
    Track = 2,
}

/// Actor identifier (type + id)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorId {
    actor_type: ActorType,
    id: u64,
}

impl ActorId {
    pub fn room(id: RoomId) -> Self {
        assert!(id != 0, "room id must not be 0");
        Self {
            actor_type: ActorType::Room,
            id,
        }
    }

    pub fn participant(id: ParticipantId) -> Self {
        assert!(id != 0, "participant id must not be 0");
        Self {
            actor_type: ActorType::Participant,
            id,
        }
    }

    pub fn track(id: TrackId) -> Self {
        assert!(id != 0, "track id must not be 0");
        Self {
            actor_type: ActorType::Track,
            id,
        }
    }

    pub fn actor_type(&self) -> ActorType {
        self.actor_type
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Registry for tracking actor locations
///
/// Maps actor IDs (Room/Participant/Track) -> WorkerId for message routing.
/// Thread-safe with RwLock (read-heavy workload).
pub struct ActorRegistry {
    /// Room locations
    rooms: RwLock<HashMap<RoomId, WorkerId>>,
    /// Participant locations
    participants: RwLock<HashMap<ParticipantId, WorkerId>>,
    /// Track to worker mapping
    tracks: RwLock<HashMap<TrackId, WorkerId>>,
    /// Room to participants relationship mapping
    room_participants: RwLock<HashMap<RoomId, Vec<ParticipantId>>>,
    /// Participant to tracks relationship mapping
    participant_tracks: RwLock<HashMap<ParticipantId, Vec<TrackId>>>,
}

impl ActorRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::with_capacity(128)),
            participants: RwLock::new(HashMap::with_capacity(1024)),
            tracks: RwLock::new(HashMap::with_capacity(1024)),
            room_participants: RwLock::new(HashMap::with_capacity(128)),
            participant_tracks: RwLock::new(HashMap::with_capacity(1024)),
        }
    }

    /// Create registry with specified capacity
    ///
    /// # Assertions
    /// - capacity <= MAX_REGISTRY_SIZE
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity <= MAX_REGISTRY_SIZE,
            "capacity exceeds max registry size"
        );

        Self {
            rooms: RwLock::new(HashMap::with_capacity(capacity / 100)),
            participants: RwLock::new(HashMap::with_capacity(capacity / 10)),
            tracks: RwLock::new(HashMap::with_capacity(capacity)),
            room_participants: RwLock::new(HashMap::with_capacity(capacity / 100)),
            participant_tracks: RwLock::new(HashMap::with_capacity(capacity / 10)),
        }
    }

    // === Room Registration ===

    /// Register room actor
    ///
    /// # Returns
    /// Previous worker id if room was already registered
    ///
    /// # Assertions
    /// - room_id != 0
    /// - Registry size < MAX_ROOMS
    pub fn register_room(&self, room_id: RoomId, worker_id: WorkerId) -> Option<WorkerId> {
        assert!(room_id != 0, "room_id must not be 0");

        let mut rooms = self.rooms.write();
        assert!(
            rooms.len() < MAX_ROOMS,
            "room registry full (max {})",
            MAX_ROOMS
        );

        rooms.insert(room_id, worker_id)
    }

    /// Unregister room
    pub fn unregister_room(&self, room_id: RoomId) -> Option<WorkerId> {
        self.rooms.write().remove(&room_id)
    }

    /// Lookup room location
    pub fn lookup_room(&self, room_id: RoomId) -> Option<WorkerId> {
        self.rooms.read().get(&room_id).copied()
    }

    // === Participant Registration ===

    /// Register participant actor with room relationship
    ///
    /// # Returns
    /// Previous worker id if participant was already registered
    ///
    /// # Assertions
    /// - participant_id != 0
    /// - room_id != 0
    /// - Registry size < MAX_PARTICIPANTS
    pub fn register_participant(
        &self,
        participant_id: ParticipantId,
        room_id: RoomId,
        worker_id: WorkerId,
    ) -> Option<WorkerId> {
        assert!(participant_id != 0, "participant_id must not be 0");
        assert!(room_id != 0, "room_id must not be 0");

        let mut participants = self.participants.write();
        assert!(
            participants.len() < MAX_PARTICIPANTS,
            "participant registry full (max {})",
            MAX_PARTICIPANTS
        );

        let prev = participants.insert(participant_id, worker_id);

        // Update room-participant relationship
        let mut room_participants = self.room_participants.write();
        let participants_vec = room_participants.entry(room_id).or_insert_with(Vec::new);
        if !participants_vec.contains(&participant_id) {
            participants_vec.push(participant_id);
        }

        prev
    }

    /// Unregister participant and remove from room relationship
    pub fn unregister_participant(&self, participant_id: ParticipantId) -> Option<WorkerId> {
        let result = self.participants.write().remove(&participant_id);

        // Remove from room-participant relationship
        let mut room_participants = self.room_participants.write();
        for participants_vec in room_participants.values_mut() {
            participants_vec.retain(|&pid| pid != participant_id);
        }

        // Also clean up participant-track relationship
        self.participant_tracks.write().remove(&participant_id);

        result
    }

    /// Lookup participant location
    pub fn lookup_participant(&self, participant_id: ParticipantId) -> Option<WorkerId> {
        self.participants.read().get(&participant_id).copied()
    }

    // === Track Registration (existing methods) ===

    /// Register track actor location with participant relationship
    ///
    /// # Arguments
    /// - track_id: Unique track identifier
    /// - participant_id: Participant owning this track
    /// - worker_id: Worker hosting this track
    ///
    /// # Returns
    /// Previous worker id if track was already registered
    ///
    /// # Assertions
    /// - track_id != 0
    /// - participant_id != 0
    /// - Registry size < MAX_TRACKS
    pub fn register_track(
        &self,
        track_id: TrackId,
        participant_id: ParticipantId,
        worker_id: WorkerId,
    ) -> Option<WorkerId> {
        assert!(track_id != 0, "track_id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        let mut tracks = self.tracks.write();
        assert!(
            tracks.len() < MAX_TRACKS,
            "track registry full (max {})",
            MAX_TRACKS
        );

        let prev = tracks.insert(track_id, worker_id);

        // Update participant-track relationship
        let mut participant_tracks = self.participant_tracks.write();
        let tracks_vec = participant_tracks.entry(participant_id).or_insert_with(Vec::new);
        if !tracks_vec.contains(&track_id) {
            tracks_vec.push(track_id);
        }

        prev
    }

    /// Unregister track and remove from participant relationship
    pub fn unregister_track(&self, track_id: TrackId) -> Option<WorkerId> {
        let result = self.tracks.write().remove(&track_id);

        // Remove from participant-track relationship
        let mut participant_tracks = self.participant_tracks.write();
        for tracks_vec in participant_tracks.values_mut() {
            tracks_vec.retain(|&tid| tid != track_id);
        }

        result
    }

    /// Lookup track location
    pub fn lookup_track(&self, track_id: TrackId) -> Option<WorkerId> {
        self.tracks.read().get(&track_id).copied()
    }

    // === Legacy methods (for backward compatibility) ===

    /// Register actor location (legacy, uses track registry without participant relationship)
    ///
    /// Note: This method does not track participant-track relationships.
    /// Use `register_track` with participant_id for full relationship tracking.
    pub fn register(&self, track_id: TrackId, worker_id: WorkerId) -> Option<WorkerId> {
        assert!(track_id != 0, "track_id must not be 0");

        let mut tracks = self.tracks.write();
        assert!(
            tracks.len() < MAX_TRACKS,
            "track registry full (max {})",
            MAX_TRACKS
        );

        tracks.insert(track_id, worker_id)
    }

    /// Unregister actor (legacy)
    pub fn unregister(&self, track_id: TrackId) -> Option<WorkerId> {
        self.unregister_track(track_id)
    }

    /// Lookup actor location (legacy)
    pub fn lookup(&self, track_id: TrackId) -> Option<WorkerId> {
        self.lookup_track(track_id)
    }

    /// Update actor location (for migration)
    ///
    /// # Returns
    /// true if track was found and updated
    pub fn update_location(&self, track_id: TrackId, new_worker_id: WorkerId) -> bool {
        let mut tracks = self.tracks.write();
        if tracks.contains_key(&track_id) {
            tracks.insert(track_id, new_worker_id);
            true
        } else {
            false
        }
    }

    // === Query Methods ===

    /// Get total actor count
    pub fn count(&self) -> usize {
        self.rooms.read().len() + self.participants.read().len() + self.tracks.read().len()
    }

    /// Get room count
    pub fn room_count(&self) -> usize {
        self.rooms.read().len()
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.read().len()
    }

    /// Get track count
    pub fn track_count(&self) -> usize {
        self.tracks.read().len()
    }

    /// Check if registry contains track
    pub fn contains(&self, track_id: TrackId) -> bool {
        self.tracks.read().contains_key(&track_id)
    }

    /// Get all tracks on a specific worker
    pub fn tracks_on_worker(&self, worker_id: WorkerId) -> Vec<TrackId> {
        self.tracks
            .read()
            .iter()
            .filter(|(_, &wid)| wid == worker_id)
            .map(|(&tid, _)| tid)
            .collect()
    }

    /// Get all participants in a room
    ///
    /// # Arguments
    /// - room_id: Room identifier to query
    ///
    /// # Returns
    /// Vector of participant IDs in the room
    ///
    /// # Assertions
    /// - room_id != 0
    pub fn participants_in_room(&self, room_id: RoomId) -> Vec<ParticipantId> {
        assert!(room_id != 0, "room_id must not be 0");

        let room_participants = self.room_participants.read();
        room_participants
            .get(&room_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all tracks for a participant
    ///
    /// # Arguments
    /// - participant_id: Participant identifier to query
    ///
    /// # Returns
    /// Vector of track IDs belonging to the participant
    ///
    /// # Assertions
    /// - participant_id != 0
    pub fn tracks_for_participant(&self, participant_id: ParticipantId) -> Vec<TrackId> {
        assert!(participant_id != 0, "participant_id must not be 0");

        let participant_tracks = self.participant_tracks.read();
        participant_tracks
            .get(&participant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get track count per worker
    pub fn tracks_per_worker(&self) -> HashMap<WorkerId, usize> {
        let tracks = self.tracks.read();
        let mut counts: HashMap<WorkerId, usize> = HashMap::new();

        for &worker_id in tracks.values() {
            *counts.entry(worker_id).or_insert(0) += 1;
        }

        counts
    }

    /// Clear all registrations
    pub fn clear(&self) {
        self.rooms.write().clear();
        self.participants.write().clear();
        self.tracks.write().clear();
        self.room_participants.write().clear();
        self.participant_tracks.write().clear();
    }
}

impl Default for ActorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ActorRegistry::new();
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.room_count(), 0);
        assert_eq!(registry.participant_count(), 0);
        assert_eq!(registry.track_count(), 0);
    }

    #[test]
    fn test_actor_id_creation() {
        let room_id = ActorId::room(1);
        assert_eq!(room_id.actor_type(), ActorType::Room);
        assert_eq!(room_id.id(), 1);

        let participant_id = ActorId::participant(10);
        assert_eq!(participant_id.actor_type(), ActorType::Participant);
        assert_eq!(participant_id.id(), 10);

        let track_id = ActorId::track(100);
        assert_eq!(track_id.actor_type(), ActorType::Track);
        assert_eq!(track_id.id(), 100);
    }

    #[test]
    #[should_panic(expected = "room id must not be 0")]
    fn test_actor_id_room_zero() {
        let _ = ActorId::room(0);
    }

    #[test]
    fn test_registry_room_operations() {
        let registry = ActorRegistry::new();

        registry.register_room(1, 0);
        registry.register_room(2, 1);

        assert_eq!(registry.lookup_room(1), Some(0));
        assert_eq!(registry.lookup_room(2), Some(1));
        assert_eq!(registry.lookup_room(999), None);
        assert_eq!(registry.room_count(), 2);

        assert_eq!(registry.unregister_room(1), Some(0));
        assert_eq!(registry.lookup_room(1), None);
        assert_eq!(registry.room_count(), 1);
    }

    #[test]
    fn test_registry_participant_operations() {
        let registry = ActorRegistry::new();

        registry.register_participant(10, 1, 0);
        registry.register_participant(20, 1, 1);

        assert_eq!(registry.lookup_participant(10), Some(0));
        assert_eq!(registry.lookup_participant(20), Some(1));
        assert_eq!(registry.lookup_participant(999), None);
        assert_eq!(registry.participant_count(), 2);

        assert_eq!(registry.unregister_participant(10), Some(0));
        assert_eq!(registry.lookup_participant(10), None);
        assert_eq!(registry.participant_count(), 1);
    }

    #[test]
    fn test_registry_track_operations() {
        let registry = ActorRegistry::new();

        registry.register_track(100, 10, 0);
        registry.register_track(200, 10, 1);
        registry.register_track(300, 20, 0);

        assert_eq!(registry.lookup_track(100), Some(0));
        assert_eq!(registry.lookup_track(200), Some(1));
        assert_eq!(registry.lookup_track(300), Some(0));
        assert_eq!(registry.lookup_track(999), None);
        assert_eq!(registry.track_count(), 3);
    }

    #[test]
    fn test_registry_register_lookup() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);
        registry.register(2, 1);
        registry.register(3, 0);

        assert_eq!(registry.lookup(1), Some(0));
        assert_eq!(registry.lookup(2), Some(1));
        assert_eq!(registry.lookup(3), Some(0));
        assert_eq!(registry.lookup(999), None);
        assert_eq!(registry.track_count(), 3);
    }

    #[test]
    fn test_registry_unregister() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);
        registry.register(2, 1);

        assert_eq!(registry.unregister(1), Some(0));
        assert_eq!(registry.lookup(1), None);
        assert_eq!(registry.track_count(), 1);

        assert_eq!(registry.unregister(999), None);
    }

    #[test]
    fn test_registry_update_location() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);

        assert!(registry.update_location(1, 2));
        assert_eq!(registry.lookup(1), Some(2));

        assert!(!registry.update_location(999, 0));
    }

    #[test]
    fn test_registry_contains() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);

        assert!(registry.contains(1));
        assert!(!registry.contains(999));
    }

    #[test]
    fn test_registry_tracks_on_worker() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);
        registry.register(2, 1);
        registry.register(3, 0);
        registry.register(4, 0);

        let tracks_on_0 = registry.tracks_on_worker(0);
        assert_eq!(tracks_on_0.len(), 3);
        assert!(tracks_on_0.contains(&1));
        assert!(tracks_on_0.contains(&3));
        assert!(tracks_on_0.contains(&4));

        let tracks_on_1 = registry.tracks_on_worker(1);
        assert_eq!(tracks_on_1.len(), 1);
        assert!(tracks_on_1.contains(&2));

        let tracks_on_2 = registry.tracks_on_worker(2);
        assert!(tracks_on_2.is_empty());
    }

    #[test]
    fn test_registry_tracks_per_worker() {
        let registry = ActorRegistry::new();

        registry.register(1, 0);
        registry.register(2, 1);
        registry.register(3, 0);
        registry.register(4, 2);
        registry.register(5, 0);

        let counts = registry.tracks_per_worker();
        assert_eq!(counts.get(&0), Some(&3));
        assert_eq!(counts.get(&1), Some(&1));
        assert_eq!(counts.get(&2), Some(&1));
    }

    #[test]
    fn test_registry_clear() {
        let registry = ActorRegistry::new();

        registry.register_room(1, 0);
        registry.register_participant(10, 1, 0);
        registry.register_track(100, 10, 0);

        assert_eq!(registry.count(), 3);

        registry.clear();

        assert_eq!(registry.count(), 0);
        assert_eq!(registry.lookup_room(1), None);
        assert_eq!(registry.lookup_participant(10), None);
        assert_eq!(registry.lookup_track(100), None);
    }

    #[test]
    #[should_panic(expected = "track_id must not be 0")]
    fn test_registry_register_zero_id() {
        let registry = ActorRegistry::new();
        registry.register(0, 0);
    }

    #[test]
    fn test_registry_re_register() {
        let registry = ActorRegistry::new();

        let prev = registry.register(1, 0);
        assert_eq!(prev, None);

        let prev = registry.register(1, 2);
        assert_eq!(prev, Some(0));
        assert_eq!(registry.lookup(1), Some(2));
    }

    #[test]
    fn test_registry_multi_type_count() {
        let registry = ActorRegistry::new();

        registry.register_room(1, 0);
        registry.register_room(2, 0);
        registry.register_participant(10, 1, 0);
        registry.register_participant(20, 1, 1);
        registry.register_participant(30, 2, 1);
        registry.register_track(100, 10, 0);

        assert_eq!(registry.room_count(), 2);
        assert_eq!(registry.participant_count(), 3);
        assert_eq!(registry.track_count(), 1);
        assert_eq!(registry.count(), 6);
    }

    #[test]
    fn test_participants_in_room() {
        let registry = ActorRegistry::new();

        // Register participants in room 1
        registry.register_participant(10, 1, 0);
        registry.register_participant(20, 1, 1);
        registry.register_participant(30, 1, 0);

        // Register participant in room 2
        registry.register_participant(40, 2, 1);

        let room1_participants = registry.participants_in_room(1);
        assert_eq!(room1_participants.len(), 3);
        assert!(room1_participants.contains(&10));
        assert!(room1_participants.contains(&20));
        assert!(room1_participants.contains(&30));

        let room2_participants = registry.participants_in_room(2);
        assert_eq!(room2_participants.len(), 1);
        assert!(room2_participants.contains(&40));

        // Non-existent room returns empty
        let room3_participants = registry.participants_in_room(3);
        assert!(room3_participants.is_empty());
    }

    #[test]
    fn test_tracks_for_participant() {
        let registry = ActorRegistry::new();

        // Register tracks for participant 10
        registry.register_track(100, 10, 0);
        registry.register_track(101, 10, 0);
        registry.register_track(102, 10, 1);

        // Register track for participant 20
        registry.register_track(200, 20, 0);

        let p10_tracks = registry.tracks_for_participant(10);
        assert_eq!(p10_tracks.len(), 3);
        assert!(p10_tracks.contains(&100));
        assert!(p10_tracks.contains(&101));
        assert!(p10_tracks.contains(&102));

        let p20_tracks = registry.tracks_for_participant(20);
        assert_eq!(p20_tracks.len(), 1);
        assert!(p20_tracks.contains(&200));

        // Non-existent participant returns empty
        let p30_tracks = registry.tracks_for_participant(30);
        assert!(p30_tracks.is_empty());
    }

    #[test]
    fn test_unregister_participant_removes_from_room() {
        let registry = ActorRegistry::new();

        registry.register_participant(10, 1, 0);
        registry.register_participant(20, 1, 1);

        assert_eq!(registry.participants_in_room(1).len(), 2);

        registry.unregister_participant(10);

        let remaining = registry.participants_in_room(1);
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains(&20));
        assert!(!remaining.contains(&10));
    }

    #[test]
    fn test_unregister_track_removes_from_participant() {
        let registry = ActorRegistry::new();

        registry.register_track(100, 10, 0);
        registry.register_track(101, 10, 0);

        assert_eq!(registry.tracks_for_participant(10).len(), 2);

        registry.unregister_track(100);

        let remaining = registry.tracks_for_participant(10);
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains(&101));
        assert!(!remaining.contains(&100));
    }

    #[test]
    #[should_panic(expected = "room_id must not be 0")]
    fn test_participants_in_room_zero_id() {
        let registry = ActorRegistry::new();
        registry.participants_in_room(0);
    }

    #[test]
    #[should_panic(expected = "participant_id must not be 0")]
    fn test_tracks_for_participant_zero_id() {
        let registry = ActorRegistry::new();
        registry.tracks_for_participant(0);
    }
}
