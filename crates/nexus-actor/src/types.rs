//! Core types for the Nexus Actor System
//!
//! Defines fundamental actor types following TigerStyle principles:
//! - Explicit types (u32, u64, not usize)
//! - Compile-time size assertions
//! - All enums derive required traits

/// Worker identifier (0-based index into worker pool)
pub type WorkerId = u32;

/// Track identifier (unique across system)
pub type TrackId = u64;

/// Participant identifier
pub type ParticipantId = u64;

/// Room identifier
pub type RoomId = u64;

/// RTP SSRC identifier
pub type Ssrc = u32;

/// Maximum actors per worker (fixed bound)
pub const MAX_ACTORS_PER_WORKER: usize = 10_000;

/// Maximum pending messages in actor queue
pub const MAX_ACTOR_QUEUE_SIZE: usize = 1024;

/// Maximum workers in pool
pub const MAX_WORKERS: u32 = 256;

/// Maximum rooms in system
pub const MAX_ROOMS: usize = 1_000;

/// Maximum participants per room
pub const MAX_PARTICIPANTS_PER_ROOM: u32 = 2_000;

/// Maximum total participants
pub const MAX_PARTICIPANTS: usize = 2_000_000;

/// Maximum tracks per participant
pub const MAX_TRACKS_PER_PARTICIPANT: usize = 10;

/// Maximum subscriptions per participant
pub const MAX_SUBSCRIPTIONS_PER_PARTICIPANT: usize = 100;

/// Maximum tracks per room
pub const MAX_TRACKS_PER_ROOM: usize = 10_000;

/// Maximum total tracks
pub const MAX_TRACKS: usize = 20_000_000;

/// Maximum messages processed per iteration
pub const MAX_MESSAGES_PER_ITERATION: usize = 100;

/// Maximum health checks per supervision iteration
pub const MAX_HEALTH_CHECKS_PER_ITERATION: usize = 100;

/// Maximum concurrent migrations per worker
pub const MAX_CONCURRENT_MIGRATIONS: usize = 10;

/// Migration rebalancing interval (30 seconds)
pub const MIGRATION_REBALANCE_INTERVAL_SECS: u64 = 30;

/// Subscriber gravity threshold for migration (80%)
pub const MIGRATION_GRAVITY_THRESHOLD_PERCENT: u8 = 80;

/// Maximum migration retries on failure
pub const MAX_MIGRATION_RETRIES: u32 = 3;

/// Migration timeout (5 seconds)
pub const MIGRATION_TIMEOUT_SECS: u64 = 5;

/// Migration sequence number type
pub type MigrationSeqNum = u64;

/// Migration identifier (unique per migration)
pub type MigrationId = u64;

/// Media type for tracks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// Audio track
    Audio,
    /// Video track
    Video,
}

/// Actor lifecycle state machine
///
/// Valid transitions:
/// - Initializing -> Active
/// - Active -> Migrating
/// - Active -> Terminated
/// - Migrating -> Active
/// - Migrating -> Terminated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorState {
    /// Actor is initializing (not yet ready)
    Initializing = 0,
    /// Actor is active and processing messages
    Active = 1,
    /// Actor is migrating to another worker
    Migrating = 2,
    /// Actor has terminated (final state)
    Terminated = 3,
}

impl ActorState {
    /// Convert from u8 to ActorState
    ///
    /// # Assertions
    /// - value must be valid state (0-3)
    #[inline]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ActorState::Initializing,
            1 => ActorState::Active,
            2 => ActorState::Migrating,
            3 => ActorState::Terminated,
            _ => panic!("invalid ActorState value: {}", value),
        }
    }
}

/// Actor health status for supervision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorHealth {
    /// Actor is healthy
    Healthy = 0,
    /// Actor is degraded (slow, errors)
    Degraded = 1,
    /// Actor has failed (panic, deadlock)
    Failed = 2,
}

impl ActorHealth {
    /// Convert from u8 to ActorHealth
    ///
    /// # Assertions
    /// - value must be valid health (0-2)
    #[inline]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ActorHealth::Healthy,
            1 => ActorHealth::Degraded,
            2 => ActorHealth::Failed,
            _ => panic!("invalid ActorHealth value: {}", value),
        }
    }
}

/// Restart policy for failed actors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Never restart (terminate permanently)
    Never,
    /// Restart once on failure
    Once,
    /// Restart up to N times
    Limited(u32),
    /// Always restart (infinite)
    Always,
}

// Compile-time size assertions
const _: () = {
    assert!(std::mem::size_of::<ActorState>() == 1);
    assert!(std::mem::size_of::<ActorHealth>() == 1);
    assert!(std::mem::size_of::<MediaKind>() == 1);
    assert!(MAX_ACTOR_QUEUE_SIZE.is_power_of_two());
    
    // Capacity sanity checks
    assert!(MAX_ROOMS > 0);
    assert!(MAX_PARTICIPANTS_PER_ROOM > 0);
    assert!(MAX_PARTICIPANTS > 0);
    assert!(MAX_TRACKS_PER_PARTICIPANT > 0);
    assert!(MAX_SUBSCRIPTIONS_PER_PARTICIPANT > 0);
    assert!(MAX_TRACKS_PER_ROOM > 0);
    assert!(MAX_TRACKS > 0);
    
    // Ensure capacity relationships are valid
    assert!(MAX_PARTICIPANTS >= MAX_ROOMS * MAX_PARTICIPANTS_PER_ROOM as usize);
    assert!(MAX_TRACKS >= MAX_PARTICIPANTS * MAX_TRACKS_PER_PARTICIPANT);
    
    // Migration constraints
    assert!(MAX_CONCURRENT_MIGRATIONS > 0);
    assert!(MAX_CONCURRENT_MIGRATIONS <= 100);
    assert!(MIGRATION_REBALANCE_INTERVAL_SECS > 0);
    assert!(MIGRATION_GRAVITY_THRESHOLD_PERCENT > 0);
    assert!(MIGRATION_GRAVITY_THRESHOLD_PERCENT <= 100);
    assert!(MAX_MIGRATION_RETRIES > 0);
    assert!(MIGRATION_TIMEOUT_SECS > 0);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_state_from_u8() {
        assert_eq!(ActorState::from_u8(0), ActorState::Initializing);
        assert_eq!(ActorState::from_u8(1), ActorState::Active);
        assert_eq!(ActorState::from_u8(2), ActorState::Migrating);
        assert_eq!(ActorState::from_u8(3), ActorState::Terminated);
    }

    #[test]
    #[should_panic(expected = "invalid ActorState value")]
    fn test_actor_state_invalid() {
        ActorState::from_u8(4);
    }

    #[test]
    fn test_actor_health_from_u8() {
        assert_eq!(ActorHealth::from_u8(0), ActorHealth::Healthy);
        assert_eq!(ActorHealth::from_u8(1), ActorHealth::Degraded);
        assert_eq!(ActorHealth::from_u8(2), ActorHealth::Failed);
    }

    #[test]
    #[should_panic(expected = "invalid ActorHealth value")]
    fn test_actor_health_invalid() {
        ActorHealth::from_u8(3);
    }
}
