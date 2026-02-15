//! Recording sink — the hot-path component.
//!
//! `RecordingSink` is injected into the forwarding pipeline as a virtual
//! subscriber. It copies packet data into a pre-allocated `WriteCommand`
//! and sends it to the background `DiskWriter` via a bounded channel.
//!
//! # TigerStyle Compliance
//!
//! - Zero heap allocation on the hot path
//! - ≥2 assertions per public function
//! - Explicit error handling (drop on backpressure, never block)
//! - No recursion (NASA Rule 1)

use nexus_core::TrackId;

use crate::format::MAX_RECORD_PAYLOAD;
use crate::writer::{DiskWriter, WriteCommand};

/// Recording sink for a single track.
///
/// Sits in the forwarding path. Call `record_packet` for every
/// RTP packet that should be recorded. Non-blocking — drops
/// packets if the writer channel is full.
pub struct RecordingSink<'a> {
    track_id: TrackId,
    writer: &'a DiskWriter,
    /// Recording start time (nanos since epoch) for relative timestamps.
    start_time_ns: u64,
    /// Packets successfully queued.
    pub packets_queued: u64,
    /// Packets dropped due to backpressure.
    pub packets_dropped: u64,
}

impl<'a> RecordingSink<'a> {
    /// Create a new recording sink for a track.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(track_id: TrackId, writer: &'a DiskWriter, start_time_ns: u64) -> Self {
        assert!(track_id > 0, "track_id must be non-zero");
        assert!(start_time_ns > 0, "start_time_ns must be positive");

        Self {
            track_id,
            writer,
            start_time_ns,
            packets_queued: 0,
            packets_dropped: 0,
        }
    }

    /// Record a single RTP packet. Non-blocking.
    ///
    /// `current_time_ns` is the wall-clock time of packet receipt.
    /// `data` is the raw RTP packet bytes.
    ///
    /// Returns `true` if queued, `false` if dropped.
    ///
    /// # TigerStyle: ≥2 assertions, bounded copy
    pub fn record_packet(
        &mut self,
        current_time_ns: u64,
        data: &[u8],
    ) -> bool {
        assert!(!data.is_empty(), "packet data must be non-empty");
        assert!(current_time_ns >= self.start_time_ns, "time must not go backwards");

        let len = data.len();
        if len > MAX_RECORD_PAYLOAD {
            self.packets_dropped += 1;
            return false;
        }

        let timestamp_us = (current_time_ns - self.start_time_ns) / 1_000;

        let mut cmd = WriteCommand {
            track_id: self.track_id,
            timestamp_us,
            len: len as u16,
            data: [0u8; MAX_RECORD_PAYLOAD],
        };
        cmd.data[..len].copy_from_slice(data);

        if self.writer.write_packet(cmd) {
            self.packets_queued += 1;
            true
        } else {
            self.packets_dropped += 1;
            false
        }
    }
}
