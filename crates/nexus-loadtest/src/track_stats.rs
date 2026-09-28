//! Per-track receive statistics, for tests that assert on what a client
//! actually received (the aggregate counters in `ClientMetrics` cannot tell
//! one track from another).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

/// Most tracks recorded per client; later tracks are ignored.
pub const MAX_TRACKS: usize = 64;

/// What one client received on one remote track (keyed by SSRC).
#[derive(Clone, Debug)]
pub struct TrackRxStats {
    /// SSRC of the received stream (as rewritten by the SFU).
    pub ssrc: u32,
    /// `audio` or `video`.
    pub kind: String,
    /// Codec MIME type, e.g. `video/VP8`.
    pub mime_type: String,
    /// RTP packets received, padding included.
    pub packets: u64,
    /// First sequence number received.
    pub first_seq: u16,
    /// Highest extended sequence number received (first_seq-relative
    /// arithmetic handles wrap-around).
    pub highest_ext_seq: u64,
    /// Packets that arrived after a higher sequence number (reordered).
    pub reordered: u64,
    /// Packets whose sequence number was already received (within the last
    /// 128 sequence numbers).
    pub duplicates: u64,
    /// Bit i set: sequence number `highest_ext_seq - i` was received.
    recent: u128,
    /// First RTP timestamp received.
    pub first_timestamp: u32,
    /// Last RTP timestamp received.
    pub last_timestamp: u32,
    /// Times the RTP timestamp went backwards between consecutive
    /// in-order packets.
    pub timestamp_regressions: u64,
    /// When the first packet arrived.
    pub first_arrival: Instant,
    /// When the last packet arrived.
    pub last_arrival: Instant,
    /// The same, as wall-clock time (to compare with RTCP sender reports).
    pub last_arrival_wall: SystemTime,
    /// Publisher SSRC read from the first payload marker (`media::read_marker`).
    pub marker_ssrc: Option<u32>,
    /// Payload markers read.
    pub markers: u64,
    /// Markers naming another publisher SSRC than the first one.
    pub marker_mismatches: u64,
    /// Markers whose frame counter went backwards.
    pub marker_regressions: u64,
    /// Frame counter of the last marker.
    last_marker_frame: u32,
}

impl TrackRxStats {
    fn new(ssrc: u32, kind: &str, mime_type: &str, seq: u16, timestamp: u32) -> Self {
        let now = Instant::now();
        Self {
            ssrc,
            kind: kind.to_string(),
            mime_type: mime_type.to_string(),
            packets: 1,
            first_seq: seq,
            highest_ext_seq: seq as u64,
            reordered: 0,
            duplicates: 0,
            recent: 1,
            first_timestamp: timestamp,
            last_timestamp: timestamp,
            timestamp_regressions: 0,
            first_arrival: now,
            last_arrival: now,
            last_arrival_wall: SystemTime::now(),
            marker_ssrc: None,
            markers: 0,
            marker_mismatches: 0,
            marker_regressions: 0,
            last_marker_frame: 0,
        }
    }

    fn record_marker(&mut self, ssrc: u32, frame: u32) {
        match self.marker_ssrc {
            None => self.marker_ssrc = Some(ssrc),
            Some(first) if first != ssrc => self.marker_mismatches += 1,
            Some(_) => {
                if frame < self.last_marker_frame {
                    self.marker_regressions += 1;
                }
            }
        }
        self.markers += 1;
        self.last_marker_frame = frame;
    }

    /// Sequence numbers expected from the first to the highest received.
    pub fn expected_packets(&self) -> u64 {
        self.highest_ext_seq - self.first_seq as u64 + 1
    }

    /// Sequence numbers between the first and highest never received.
    pub fn missing_packets(&self) -> u64 {
        let unique = self.packets - self.duplicates;
        self.expected_packets().saturating_sub(unique)
    }

    fn record(&mut self, seq: u16, timestamp: u32) {
        self.packets += 1;
        self.last_arrival = Instant::now();
        self.last_arrival_wall = SystemTime::now();
        // Extend the 16-bit sequence number relative to the highest seen.
        let highest = self.highest_ext_seq;
        let delta = seq.wrapping_sub(highest as u16) as i16 as i64;
        let ext = (highest as i64 + delta).max(0) as u64;
        if ext > highest {
            let shift = ext - highest;
            self.recent = if shift >= 128 {
                0
            } else {
                self.recent << shift
            };
            self.recent |= 1;
            self.highest_ext_seq = ext;
            // RTP timestamps move forward modulo 2^32 on in-order packets.
            let ts_delta = timestamp.wrapping_sub(self.last_timestamp) as i32;
            if ts_delta < 0 {
                self.timestamp_regressions += 1;
            }
            self.last_timestamp = timestamp;
        } else {
            let age = highest - ext;
            let bit = if age < 128 { 1u128 << age } else { 0 };
            if bit != 0 && self.recent & bit != 0 {
                self.duplicates += 1;
            } else {
                self.recent |= bit;
                self.reordered += 1;
            }
        }
    }
}

/// Shared per-track stats of one client, filled by its RTP reader tasks.
#[derive(Clone, Default)]
pub struct TrackStatsMap {
    inner: Arc<Mutex<HashMap<u32, TrackRxStats>>>,
}

impl TrackStatsMap {
    /// Record one received RTP packet.
    pub fn record(&self, ssrc: u32, kind: &str, mime_type: &str, seq: u16, timestamp: u32) {
        let mut map = self.inner.lock().expect("track stats lock");
        if let Some(stats) = map.get_mut(&ssrc) {
            stats.record(seq, timestamp);
        } else if map.len() < MAX_TRACKS {
            map.insert(
                ssrc,
                TrackRxStats::new(ssrc, kind, mime_type, seq, timestamp),
            );
        }
    }

    /// Record the payload marker `(marker_ssrc, frame)` of a packet received on
    /// `ssrc` (after `record` created the track).
    pub fn record_marker(&self, ssrc: u32, marker_ssrc: u32, frame: u32) {
        let mut map = self.inner.lock().expect("track stats lock");
        if let Some(stats) = map.get_mut(&ssrc) {
            stats.record_marker(marker_ssrc, frame);
        }
    }

    /// Snapshot of every track, sorted by SSRC.
    pub fn snapshot(&self) -> Vec<TrackRxStats> {
        let map = self.inner.lock().expect("track stats lock");
        let mut tracks: Vec<TrackRxStats> = map.values().cloned().collect();
        tracks.sort_by_key(|t| t.ssrc);
        tracks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_with_wrap() {
        let map = TrackStatsMap::default();
        for (i, seq) in [65534u16, 65535, 0, 1].into_iter().enumerate() {
            map.record(7, "video", "video/VP8", seq, 1000 + i as u32 * 3000);
        }
        let t = &map.snapshot()[0];
        assert_eq!(t.packets, 4);
        assert_eq!(t.expected_packets(), 4);
        assert_eq!(t.missing_packets(), 0);
        assert_eq!(t.timestamp_regressions, 0);
    }

    #[test]
    fn test_gap_and_duplicate() {
        let map = TrackStatsMap::default();
        for seq in [10u16, 11, 13, 13, 12] {
            map.record(9, "audio", "audio/opus", seq, seq as u32 * 960);
        }
        let t = &map.snapshot()[0];
        assert_eq!(t.expected_packets(), 4);
        assert_eq!((t.duplicates, t.reordered), (1, 1));
        assert_eq!(t.missing_packets(), 0, "12 arrived late, not lost");

        map.record(9, "audio", "audio/opus", 16, 0);
        assert_eq!(map.snapshot()[0].missing_packets(), 2, "14 and 15");
    }

    #[test]
    fn test_markers() {
        let map = TrackStatsMap::default();
        map.record(3, "video", "video/VP8", 1, 0);
        map.record_marker(3, 77, 1);
        map.record_marker(3, 77, 2);
        map.record_marker(3, 77, 1); // backwards
        map.record_marker(3, 78, 3); // another publisher
        map.record_marker(4, 77, 1); // unknown track: ignored
        let t = &map.snapshot()[0];
        assert_eq!(t.marker_ssrc, Some(77));
        assert_eq!(t.markers, 4);
        assert_eq!((t.marker_mismatches, t.marker_regressions), (1, 1));
        assert_eq!(map.snapshot().len(), 1);
    }
}
