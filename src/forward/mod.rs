//! Track and SSRC Router for Nexus SFU MVP.
//!
//! Provides media track management with ring buffers and subscriber lists,
//! plus SSRC-based routing for efficient packet delivery.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      SsrcRouter                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  routes: DashMap<SSRC, (TrackId, WorkerId)>                 │
//! │                                                              │
//! │  Packet arrives with SSRC=12345                             │
//! │       │                                                      │
//! │       ▼                                                      │
//! │  lookup(12345) -> Some((track_id=7, worker_id=2))           │
//! │       │                                                      │
//! │       ▼                                                      │
//! │  Route to Worker 2, Track 7                                 │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Track                                 │
//! ├─────────────────────────────────────────────────────────────┤
//! │  id: TrackId                                                │
//! │  ssrc: Ssrc                                                 │
//! │  kind: MediaKind                                            │
//! │  ring_buffer: RingBuffer<2048>                              │
//! │  subscribers: Arc<ArcSwap<SubscriberList>>                  │
//! │  stats: TrackStats                                          │
//! │                                                              │
//! │  forward(packet, batch_sender)                              │
//! │       │                                                      │
//! │       ▼                                                      │
//! │  For each hot subscriber:                                   │
//! │    batch_sender.queue(dest, packet.clone_shallow())         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Requirements Coverage
//!
//! - Requirement 7.1: O(1) SSRC lookup
//! - Requirement 7.2: Lock-free hash map for SSRC routing
//! - Requirement 7.3: New track creation on new SSRC
//! - Requirement 7.4: SSRC mapping cleanup on track removal
//! - Requirement 7.5: Ring buffer storage and subscriber forwarding
//! - Requirement 7.6: Copy-on-write subscriber list
//! - Requirement 7.7: SSRC collision detection
//! - Requirement 8.1: Hot/cold subscriber classification
//! - Requirement 8.2: Mark as hot when receiving packets
//! - Requirement 8.3: Mark as cold after timeout
//! - Requirement 8.4: Iterate only hot subscribers in fast path
//! - Requirement 8.6: Promote cold to hot on packet request
//! - Requirement 8.7: Track statistics for hot/cold transitions
//! - Requirement 9.1: Store visible participant list on viewport update
//! - Requirement 9.2: Check if source is in subscriber's viewport
//! - Requirement 9.3: Skip forwarding if source not in viewport
//! - Requirement 9.4: Support priority levels for participants
//! - Requirement 9.5: Always forward pinned participants
//! - Requirement 9.6: Track statistics for filtered vs forwarded
//! - Requirement 19.7: XdpPacketProcessor integrates XDP fast path with user-space cold path

pub mod multicast;
mod router;
pub mod selective;
pub mod processor;

pub use router::{SsrcRouter, SsrcError};

// Re-export subscriber types from multicast module
pub use multicast::{
    Subscriber, SubscriberList, SubscriberListStats, SubscriberListStatsSnapshot,
    DEFAULT_COLD_TIMEOUT_NS, MAX_SUBSCRIBERS_PER_TRACK,
};

// Re-export selective forwarding types
// Note: ViewportFilter is also available in multicast for backward compatibility
pub use selective::{
    ViewportFilter, ViewportFilterStats, ViewportFilterStatsSnapshot,
    MAX_VISIBLE_PARTICIPANTS, MAX_PRIORITY,
};

// Re-export XDP processor types
pub use processor::{
    XdpPacketProcessor, XdpProcessorConfig, XdpProcessorStats, XdpProcessorStatsSnapshot,
    PacketType, PacketHandler, process_fallback_batch,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify module exports are accessible
        let _ = SsrcRouter::new();
    }
}
