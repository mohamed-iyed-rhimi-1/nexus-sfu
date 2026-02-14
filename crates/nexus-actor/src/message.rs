//! Actor message protocol
//!
//! Defines message types for actor communication.
//! All messages use explicit field names (no tuple variants).
//! Message sizes are bounded (no unbounded Vec/String).

use std::net::SocketAddr;
use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::types::*;

/// Room statistics snapshot
///
/// Contains point-in-time statistics for a room.
/// All fields use explicit types (u32, u64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomStats {
    /// Number of participants currently in the room
    pub participant_count: u32,
    /// Number of tracks announced in the room
    pub track_count: u32,
    /// Room uptime in nanoseconds since creation
    pub uptime_ns: u64,
    /// Total messages processed by the room actor
    pub messages_processed: u64,
}

/// Migration state snapshot for transfer
#[derive(Debug, Clone)]
pub struct MigrationSnapshot {
    /// Track identifier
    pub track_id: TrackId,
    /// Source worker
    pub source_worker_id: WorkerId,
    /// Target worker
    pub target_worker_id: WorkerId,
    /// Last processed sequence number
    pub last_seq_num: MigrationSeqNum,
    /// Subscriber list snapshot
    pub subscribers: Vec<SubscriberSnapshot>,
    /// Statistics snapshot
    pub stats: TrackStatsSnapshot,
}

/// Subscriber snapshot for migration
#[derive(Debug, Clone)]
pub struct SubscriberSnapshot {
    pub id: u32,
    pub participant_id: u64,
    pub dest_addr: SocketAddr,
    pub target_layer: u8,
    pub packets_forwarded: u64,
}

/// Track statistics snapshot
#[derive(Debug, Clone)]
pub struct TrackStatsSnapshot {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
}

/// Packet data slot for zero-copy forwarding
///
/// Contains packet data with reference counting for
/// efficient forwarding to multiple subscribers.
#[derive(Debug, Clone)]
pub struct PacketSlot {
    /// Packet data (reference counted)
    data: Arc<[u8]>,
    /// Actual length of packet data
    len: u32,
}

impl PacketSlot {
    /// Create new packet slot from data
    ///
    /// # Assertions
    /// - data.len() > 0
    /// - data.len() <= MAX_PACKET_SIZE
    pub fn new(data: &[u8]) -> Self {
        const MAX_PACKET_SIZE: usize = 65535;
        assert!(!data.is_empty(), "packet data must not be empty");
        assert!(data.len() <= MAX_PACKET_SIZE, "packet too large");

        Self {
            data: Arc::from(data),
            len: data.len() as u32,
        }
    }

    /// Get packet length
    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Check if packet is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get packet data as slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// Clone packet slot (shallow copy, reference counted)
    #[inline]
    pub fn clone_shallow(&self) -> Self {
        Self {
            data: Arc::clone(&self.data),
            len: self.len,
        }
    }
}

/// Messages sent to TrackActor
///
/// All variants use explicit field names for clarity.
/// No unbounded collections in message payloads.
#[derive(Debug)]
pub enum TrackActorMessage {
    /// Subscribe a participant to this track
    Subscribe {
        subscriber_id: u32,
        participant_id: u64,
        dest_addr: SocketAddr,
    },

    /// Unsubscribe a participant
    Unsubscribe { subscriber_id: u32 },

    /// Update quality/layer for subscriber
    UpdateQuality { subscriber_id: u32, target_layer: u8 },

    /// Promote cold subscriber to hot
    PromoteSubscriber { subscriber_id: u32 },

    /// Demote hot subscriber to cold
    DemoteSubscriber { subscriber_id: u32 },

    /// Process incoming packet
    ProcessPacket { packet: PacketSlot },

    /// Process packet with sequence number for ordering
    ProcessPacketSeq {
        packet: PacketSlot,
        seq_num: MigrationSeqNum,
    },

    /// Prepare for migration (freeze state)
    PrepareMigration {
        migration_id: MigrationId,
        target_worker_id: WorkerId,
    },

    /// Transfer state snapshot to target worker
    TransferState {
        migration_id: MigrationId,
        snapshot: MigrationSnapshot,
    },

    /// Resume after migration complete
    ResumeMigration { migration_id: MigrationId },

    /// Abort migration on failure
    AbortMigration { migration_id: MigrationId },

    /// Initiate migration to another worker
    BeginMigration { target_worker_id: WorkerId },

    /// Complete migration (sent by target worker)
    CompleteMigration,

    /// Terminate actor gracefully
    Terminate,

    /// Health check ping
    HealthCheck,
}

/// Response from TrackActor
///
/// Simple response types with bounded data.
#[derive(Debug)]
pub enum TrackActorResponse {
    /// Operation succeeded
    Ok,

    /// Operation failed with error code
    Error { code: u32, message: &'static str },

    /// Health check response
    HealthStatus {
        state: ActorState,
        health: ActorHealth,
        queue_depth: u32,
        subscriber_count: u32,
    },

    /// Migration response
    MigrationReady { track_id: TrackId, worker_id: WorkerId },
}

/// Connection state for participant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    Connecting = 0,
    Connected = 1,
    Disconnected = 2,
    Failed = 3,
}

/// Messages sent to ParticipantActor
#[derive(Debug)]
pub enum ParticipantActorMessage {
    /// Publish a new track
    PublishTrack {
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
    },

    /// Unpublish a track
    UnpublishTrack {
        track_id: TrackId,
    },

    /// Subscribe to a track from another participant
    SubscribeToTrack {
        track_id: TrackId,
        target_layer: u8,
    },

    /// Unsubscribe from a track
    UnsubscribeFromTrack {
        track_id: TrackId,
    },

    /// Update connection state (ICE/DTLS)
    UpdateConnectionState {
        session_id: u64,
        state: ConnectionState,
    },

    /// Set participant metadata (name, etc.)
    UpdateMetadata {
        name: String,
    },

    /// Terminate participant gracefully
    Terminate,

    /// Health check ping
    HealthCheck,
}

/// Messages sent to RoomActor
#[derive(Debug)]
pub enum RoomActorMessage {
    /// Add participant to room
    AddParticipant {
        participant_id: ParticipantId,
        name: String,
        connection_id: u64,
    },

    /// Remove participant from room
    RemoveParticipant {
        participant_id: ParticipantId,
    },

    /// Announce track to all participants
    AnnounceTrack {
        track_id: TrackId,
        participant_id: ParticipantId,
        kind: MediaKind,
    },

    /// Remove track announcement
    RemoveTrackAnnouncement {
        track_id: TrackId,
    },

    /// Get room statistics with response channel
    GetStats {
        response_tx: Sender<RoomStats>,
    },

    /// Terminate room gracefully
    Terminate,

    /// Health check ping
    HealthCheck,
}

// Compile-time size assertions
const _: () = {
    // Ensure PacketSlot is reasonably sized
    assert!(std::mem::size_of::<PacketSlot>() <= 24);
    
    // Ensure migration messages are reasonably sized
    assert!(std::mem::size_of::<MigrationSnapshot>() <= 1024);
    assert!(std::mem::size_of::<SubscriberSnapshot>() <= 64);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_slot_new() {
        let data = [1u8, 2, 3, 4, 5];
        let slot = PacketSlot::new(&data);

        assert_eq!(slot.len(), 5);
        assert!(!slot.is_empty());
        assert_eq!(slot.as_slice(), &data);
    }

    #[test]
    fn test_packet_slot_clone_shallow() {
        let data = [1u8, 2, 3, 4, 5];
        let slot1 = PacketSlot::new(&data);
        let slot2 = slot1.clone_shallow();

        assert_eq!(slot1.len(), slot2.len());
        assert_eq!(slot1.as_slice(), slot2.as_slice());
        // Verify it's a shallow copy (same Arc)
        assert!(Arc::ptr_eq(&slot1.data, &slot2.data));
    }

    #[test]
    #[should_panic(expected = "packet data must not be empty")]
    fn test_packet_slot_empty() {
        let _slot = PacketSlot::new(&[]);
    }
}
