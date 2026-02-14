//! Core type aliases for Nexus SFU.
//!
//! Shared types are defined in the `nexus-core` crate and
//! re-exported here for backward compatibility. Types specific
//! to the root crate (CRDT wrappers, TrackInfo) remain here.
//!
//! All types use explicit sizing (u32, u64) instead of usize
//! for semantic clarity and cross-platform consistency.
//! This follows TigerStyle guidelines (Requirement 13.4).

// Re-export all shared types from nexus-core so that
// existing `use crate::types::X` imports continue to work
// without modification across the codebase.
pub use nexus_core::types::{
    BandwidthBps, ConnectionId, MediaKind, ParticipantId,
    RoomId, Ssrc, TimestampNs, TrackId,
};

// ============================================================
// CRDT Type Aliases for Distributed State
// These are root-crate-specific because they depend on
// nexus-state, which nexus-core must not depend on.
// ============================================================

/// A distributed set of participants using CRDT
/// (Observed-Remove Set).
///
/// Supports concurrent add/remove operations across
/// distributed nodes with automatic conflict resolution.
pub type ParticipantSet =
    nexus_state::crdt::Orswot<ParticipantId>;

/// A distributed counter for packet statistics using
/// CRDT (Grow-Only Counter).
///
/// Each node can increment independently, and totals are
/// computed by summing all node contributions.
pub type PacketCounter = nexus_state::crdt::GCounter;

/// Track information for distributed metadata storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackInfo {
    /// Track identifier
    pub track_id: TrackId,
    /// Media kind (audio/video)
    pub kind: Option<MediaKind>,
    /// Bitrate in bits per second
    pub bitrate_bps: BandwidthBps,
    /// Whether the track is currently active
    pub active: bool,
}

/// A distributed register for track metadata using CRDT
/// (Last-Writer-Wins Register).
///
/// Concurrent updates are resolved by timestamp, with
/// deterministic tie-breaking by actor ID.
pub type TrackMetadata =
    nexus_state::crdt::LWWReg<TrackInfo>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_kind_display() {
        assert_eq!(format!("{}", MediaKind::Audio), "audio");
        assert_eq!(format!("{}", MediaKind::Video), "video");
    }

    #[test]
    fn test_type_sizes() {
        // Verify explicit sizing matches expectations
        assert_eq!(std::mem::size_of::<TrackId>(), 8);
        assert_eq!(std::mem::size_of::<ParticipantId>(), 8);
        assert_eq!(std::mem::size_of::<RoomId>(), 4);
        assert_eq!(std::mem::size_of::<Ssrc>(), 4);
        assert_eq!(std::mem::size_of::<TimestampNs>(), 8);
        assert_eq!(std::mem::size_of::<BandwidthBps>(), 8);
    }
}
