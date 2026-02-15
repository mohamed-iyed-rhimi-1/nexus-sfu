//! Worker Pool and Sharding for Nexus SFU MVP.
//!
//! Provides CPU-pinned worker threads with shared-nothing design for maximum
//! cache efficiency and zero lock contention on the hot path.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      WorkerPool                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  workers: [Worker0, Worker1, Worker2, ...]                  │
//! │  track_hasher: ConsistentHash                               │
//! │                                                              │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │ Worker 0 (CPU 0)                                    │    │
//! │  │   tracks: {track_1, track_5, track_9, ...}         │    │
//! │  │   arena: PacketArena                                │    │
//! │  │   batch_sender: BatchSender                         │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! │                                                              │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │ Worker 1 (CPU 1)                                    │    │
//! │  │   tracks: {track_2, track_6, track_10, ...}        │    │
//! │  │   arena: PacketArena                                │    │
//! │  │   batch_sender: BatchSender                         │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! │                                                              │
//! │  ... (one worker per CPU core)                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Requirements Coverage
//!
//! - Requirement 6.1: One worker thread per CPU core
//! - Requirement 6.2: CPU pinning using OS affinity APIs
//! - Requirement 6.3: Each worker owns tracks exclusively
//! - Requirement 6.4: Consistent hashing for track assignment
//! - Requirement 6.5: Load balancing for new tracks
//! - Requirement 6.6: SPSC channels for cross-worker communication
//! - Requirement 6.7: Worker panic handling with restart
//! - Requirement 6.8: Graceful shutdown with draining

mod pool;
mod shard;
pub mod spsc;

#[cfg(test)]
mod spsc_proptest;

pub use pool::{MediaWorker, WorkerHandle, WorkerPool};
pub use shard::ConsistentHash;
pub use spsc::{SpscChannel, SpscSender, SpscReceiver, channel as spsc_channel};

use std::net::SocketAddr;

use nexus_transport::arena::PacketSlot;
use crate::types::{MediaKind, ParticipantId, Ssrc, TrackId};

/// Messages sent to workers via SPSC channels.
///
/// Workers receive these messages and process them in their run loop.
/// This enables cross-worker communication without shared state.
#[derive(Debug)]
pub enum WorkerMessage {
    /// Assign a new track to this worker.
    AssignTrack {
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
    },

    /// Remove a track from this worker.
    RemoveTrack { track_id: TrackId },

    /// Route a packet to a track owned by this worker.
    Packet { 
        track_id: TrackId, 
        packet: PacketSlot,
        source_addr: SocketAddr,
    },

    /// Shutdown the worker gracefully.
    Shutdown,

    // === Actor System Messages ===

    /// Spawn a new TrackActor on this worker.
    SpawnActor {
        track_id: TrackId,
        participant_id: ParticipantId,
        ssrc: Ssrc,
        kind: MediaKind,
        /// Content type: 0=camera, 1=screen, 2=audio.
        content_type: u8,
    },

    /// Send a message to a TrackActor.
    ActorSubscribe {
        track_id: TrackId,
        subscriber_id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
    },

    /// Unsubscribe from a TrackActor.
    ActorUnsubscribe {
        track_id: TrackId,
        subscriber_id: u32,
    },

    /// Process packet through actor system.
    ActorPacket {
        track_id: TrackId,
        packet: PacketSlot,
        source_addr: SocketAddr,
    },

    /// Terminate a TrackActor.
    TerminateActor { track_id: TrackId },

    // === Migration Messages ===

    /// Prepare track for migration (freeze state).
    PrepareMigration {
        migration_id: u64,
        track_id: TrackId,
        target_worker_id: u32,
    },

    /// Transfer migrated track state to this worker.
    TransferMigrationState {
        migration_id: u64,
        snapshot: nexus_actor::MigrationSnapshot,
    },

    /// Resume track after migration complete.
    ResumeMigration {
        migration_id: u64,
        track_id: TrackId,
    },

    /// Abort migration on failure.
    AbortMigration {
        migration_id: u64,
        track_id: TrackId,
    },

    // === Bandwidth Allocation Messages ===

    /// Update bandwidth allocation for track.
    UpdateBandwidth {
        track_id: TrackId,
        allocated_bps: u64,
        target_layer: u8,
    },

    /// Process RTCP receiver report for BWE.
    RtcpReceiverReport {
        ssrc: Ssrc,
        fraction_lost: u8,
        rtt_us: Option<u64>,
        timestamp_us: u64,
    },

    /// Process transport-wide feedback for BWE.
    TransportFeedback {
        feedback: nexus_bwe::TransportFeedback,
        timestamp_us: u64,
    },

    /// Process RTCP PLI (Picture Loss Indication) feedback.
    RtcpPli {
        media_ssrc: u32,
        sender_ssrc: u32,
    },

    /// Process RTCP NACK (Negative Acknowledgement) feedback.
    RtcpNack {
        media_ssrc: u32,
        sender_ssrc: u32,
        lost_packets: Vec<u16>,
    },

    /// Set publisher SRTCP context for a track (for PLI/NACK protection).
    SetPublisherSrtcp {
        track_id: TrackId,
        key_material: nexus_transport::srtp::KeyMaterial,
        srtp_policy: nexus_transport::srtp::SrtpPolicy,
    },

    /// Set subscriber SRTP context for a track (for SR/RTP protection).
    /// This message is sent when a subscriber's DTLS handshake completes,
    /// enabling SRTP protection of outbound RTP packets and RTCP SRs.
    SetSubscriberSrtp {
        track_id: TrackId,
        subscriber_id: u32,
        key_material: nexus_transport::srtp::KeyMaterial,
        srtp_policy: nexus_transport::srtp::SrtpPolicy,
    },

    /// Add a subscriber to a track.
    AddSubscriber {
        track_id: TrackId,
        subscriber_id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
        target_layer: u8,
        srtp_context: nexus_transport::srtp::SrtpContext,
    },

    /// Remove a subscriber from a track.
    RemoveSubscriber {
        track_id: TrackId,
        subscriber_id: u32,
    },

    /// Map a simulcast layer SSRC to a track actor.
    SetSimulcastSsrc {
        track_id: TrackId,
        layer: u8,
        ssrc: Ssrc,
    },

    /// Set target simulcast layer for a subscriber.
    SetSubscriberLayer {
        track_id: TrackId,
        subscriber_id: u32,
        target_layer: u8,
    },

    /// Update the MID value injected into forwarded RTP packets.
    /// Sent after renegotiation assigns a MID to a forwarded track.
    SetTrackMid {
        track_id: TrackId,
        mid_ext_id: u8,
        mid_value: [u8; 4],
        mid_value_len: u8,
    },

    /// Update viewport filter for a subscriber.
    /// Sent when a client sends a Viewport signaling message.
    UpdateViewport {
        track_id: TrackId,
        subscriber_id: u32,
        /// Source participant IDs visible in the subscriber's UI (sorted).
        visible: Vec<u32>,
        /// Source participant IDs pinned by the subscriber (sorted).
        pinned: Vec<u32>,
    },

    /// Set content type on a track actor (0=camera, 1=screen, 2=audio).
    /// Screen share tracks bypass viewport filtering.
    SetContentType {
        track_id: TrackId,
        content_type: u8,
    },

    /// Add a relay subscriber — forwards packets to a peer SFU node.
    /// No SRTP needed (inter-node traffic on private network).
    AddRelaySubscriber {
        track_id: TrackId,
        peer_node: u64,
        /// Subscriber ID (derived from peer_node for uniqueness).
        subscriber_id: u32,
    },

    /// Inject a relay packet received from a peer node into the local pipeline.
    RelayPacket {
        track_id: TrackId,
        data: [u8; 1500],
        len: u16,
    },
}

/// Worker statistics for monitoring.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerStats {
    /// Number of tracks owned by this worker.
    pub track_count: u32,
    /// Total packets processed by this worker.
    pub packets_processed: u64,
    /// Total packets dropped (track not found, etc.).
    pub packets_dropped: u64,
    /// Number of batch flushes performed.
    pub batches_flushed: u64,
    /// Total bytes copied during subscriber fan-out (for capacity planning).
    /// Requirement 29.5: Track bytes copied per fan-out operation.
    pub bytes_copied_fanout: u64,
    /// Arena allocation failures during fan-out operations.
    /// Requirement 29.3: Track arena exhaustion events.
    pub arena_alloc_failures_fanout: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_message_debug() {
        let msg = WorkerMessage::Shutdown;
        assert!(format!("{:?}", msg).contains("Shutdown"));
    }

    #[test]
    fn test_worker_stats_default() {
        let stats = WorkerStats::default();
        assert_eq!(stats.track_count, 0);
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.packets_dropped, 0);
        assert_eq!(stats.batches_flushed, 0);
        assert_eq!(stats.bytes_copied_fanout, 0);
        assert_eq!(stats.arena_alloc_failures_fanout, 0);
    }
}
