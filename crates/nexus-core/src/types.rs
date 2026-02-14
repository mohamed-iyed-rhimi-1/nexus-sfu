//! Shared type aliases and enums used across all Nexus SFU crates.
//!
//! All identifiers use explicitly-sized types (u32, u64) instead
//! of usize, following TigerStyle and NASA safety rules.
//! This module is the single source of truth for core type
//! definitions — all other crates re-export from here.

use serde::{Deserialize, Serialize};

/// Unique identifier for a media track.
/// Tracks represent individual audio or video streams
/// from participants. Using u64 for consistency with
/// nexus-actor crate's actor addressing.
pub type TrackId = u64;

/// Unique identifier for a participant in a room.
/// Each participant can publish multiple tracks and
/// subscribe to others. Using u64 for consistency with
/// nexus-actor crate's actor addressing.
pub type ParticipantId = u64;

/// Unique identifier for a room.
/// Rooms contain participants and manage track
/// subscriptions.
pub type RoomId = u32;

/// Unique identifier for a WebSocket connection.
/// Used to track signaling connections for participants.
pub type ConnectionId = u32;

/// RTP Synchronization Source identifier.
/// 32-bit value identifying the source of an RTP stream.
/// Used for routing packets to the correct track.
pub type Ssrc = u32;

/// Timestamp in nanoseconds since Unix epoch.
/// Used for timing operations like cold subscriber
/// detection and event ordering.
pub type TimestampNs = u64;

/// Bandwidth in bits per second.
/// Used for bandwidth estimation and rate limiting.
pub type BandwidthBps = u64;

/// Media stream kind (audio or video).
///
/// Distinguishes between audio and video tracks for
/// codec selection, forwarding priority, and bandwidth
/// allocation decisions.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash,
    Serialize, Deserialize,
)]
pub enum MediaKind {
    /// Audio stream (typically Opus codec)
    Audio,
    /// Video stream (typically VP8/VP9/H.264)
    Video,
}

impl std::fmt::Display for MediaKind {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            MediaKind::Audio => write!(f, "audio"),
            MediaKind::Video => write!(f, "video"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_kind_display() {
        assert_eq!(format!("{}", MediaKind::Audio), "audio");
        assert_eq!(format!("{}", MediaKind::Video), "video");
    }

    #[test]
    fn test_media_kind_equality() {
        assert_eq!(MediaKind::Audio, MediaKind::Audio);
        assert_eq!(MediaKind::Video, MediaKind::Video);
        assert_ne!(MediaKind::Audio, MediaKind::Video);
    }

    #[test]
    fn test_media_kind_clone_copy() {
        let kind = MediaKind::Audio;
        let cloned = kind.clone();
        let copied = kind;
        assert_eq!(kind, cloned);
        assert_eq!(kind, copied);
    }

    #[test]
    fn test_type_sizes() {
        // Verify explicit sizing matches expectations.
        // TrackId and ParticipantId are u64 for
        // nexus-actor compatibility.
        assert_eq!(std::mem::size_of::<TrackId>(), 8);
        assert_eq!(std::mem::size_of::<ParticipantId>(), 8);
        assert_eq!(std::mem::size_of::<RoomId>(), 4);
        assert_eq!(std::mem::size_of::<ConnectionId>(), 4);
        assert_eq!(std::mem::size_of::<Ssrc>(), 4);
        assert_eq!(std::mem::size_of::<TimestampNs>(), 8);
        assert_eq!(std::mem::size_of::<BandwidthBps>(), 8);
    }

    #[test]
    fn test_media_kind_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MediaKind::Audio);
        set.insert(MediaKind::Video);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&MediaKind::Audio));
        assert!(set.contains(&MediaKind::Video));
    }

    #[test]
    fn test_media_kind_serde_roundtrip() {
        let audio = MediaKind::Audio;
        let json = serde_json::to_string(&audio).unwrap();
        let deserialized: MediaKind =
            serde_json::from_str(&json).unwrap();
        assert_eq!(audio, deserialized);

        let video = MediaKind::Video;
        let json = serde_json::to_string(&video).unwrap();
        let deserialized: MediaKind =
            serde_json::from_str(&json).unwrap();
        assert_eq!(video, deserialized);
    }
}
