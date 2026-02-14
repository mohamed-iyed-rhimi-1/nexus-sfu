//! Speaker Detection for Priority Allocation
//!
//! Detects active speaker based on packet rate to prioritize bandwidth allocation.

use crate::allocation::TrackPriority;
use std::collections::HashMap;

pub type TrackId = u64;

const MAX_TRACKS: usize = 100;
const WINDOW_DURATION_US: u64 = 1_000_000; // 1 second
const SPEAKER_THRESHOLD_PPS: u32 = 30; // packets per second
const SILENCE_THRESHOLD_PPS: u32 = 5;

// Compile-time assertion: speaker threshold must be greater than silence threshold
const _: () = assert!(SPEAKER_THRESHOLD_PPS > SILENCE_THRESHOLD_PPS);

/// Media kind for priority inference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
    ScreenShare,
}

/// Packet rate tracker for a single track
#[derive(Debug, Clone)]
struct PacketRateTracker {
    packets_in_window: u32,
    window_start_us: u64,
    last_packet_count: u64,
}

impl PacketRateTracker {
    fn new(timestamp_us: u64) -> Self {
        Self {
            packets_in_window: 0,
            window_start_us: timestamp_us,
            last_packet_count: 0,
        }
    }

    fn update(&mut self, packet_count: u64, timestamp_us: u64) {
        // Reset window if expired
        if timestamp_us.saturating_sub(self.window_start_us) >= WINDOW_DURATION_US {
            self.packets_in_window = 0;
            self.window_start_us = timestamp_us;
            self.last_packet_count = packet_count;
        } else {
            // Accumulate packets in current window
            let new_packets = packet_count.saturating_sub(self.last_packet_count);
            self.packets_in_window = self.packets_in_window.saturating_add(new_packets as u32);
            self.last_packet_count = packet_count;
        }
    }

    fn packets_per_second(&self) -> u32 {
        self.packets_in_window
    }
}

/// Speaker detector for active speaker identification
pub struct SpeakerDetector {
    packet_rates: HashMap<TrackId, PacketRateTracker>,
    current_speaker: Option<TrackId>,
    speaker_threshold_pps: u32,
    #[allow(dead_code)] // Reserved for silence detection threshold
    silence_threshold_pps: u32,
}

impl SpeakerDetector {
    /// Create new speaker detector with default thresholds
    pub fn new() -> Self {
        Self {
            packet_rates: HashMap::with_capacity(MAX_TRACKS),
            current_speaker: None,
            speaker_threshold_pps: SPEAKER_THRESHOLD_PPS,
            silence_threshold_pps: SILENCE_THRESHOLD_PPS,
        }
    }

    /// Update packet rate for a track
    pub fn update(&mut self, track_id: TrackId, packet_count: u64, timestamp_us: u64) {
        assert!(
            self.packet_rates.len() <= MAX_TRACKS,
            "Track count exceeds maximum of {}",
            MAX_TRACKS
        );

        self.packet_rates
            .entry(track_id)
            .or_insert_with(|| PacketRateTracker::new(timestamp_us))
            .update(packet_count, timestamp_us);
    }

    /// Detect current speaker based on packet rates
    pub fn detect_speaker(&mut self, _timestamp_us: u64) -> Option<TrackId> {
        // Find track with highest packet rate above threshold
        let mut max_rate = self.speaker_threshold_pps;
        let mut speaker = None;

        for (track_id, tracker) in &self.packet_rates {
            let rate = tracker.packets_per_second();
            if rate > max_rate {
                max_rate = rate;
                speaker = Some(*track_id);
            }
        }

        // Update current speaker if changed
        if speaker != self.current_speaker {
            self.current_speaker = speaker;
        }

        self.current_speaker
    }

    /// Get priority for a track based on speaker status and media kind
    pub fn get_priority(&self, track_id: TrackId, kind: MediaKind) -> TrackPriority {
        // Check if this is the current speaker
        if self.current_speaker == Some(track_id) {
            return TrackPriority::Critical;
        }

        // Infer priority from media kind
        match kind {
            MediaKind::ScreenShare => TrackPriority::High,
            MediaKind::Video => TrackPriority::Normal,
            MediaKind::Audio => TrackPriority::Normal,
        }
    }

    /// Get current speaker
    pub fn current_speaker(&self) -> Option<TrackId> {
        self.current_speaker
    }

    /// Get packet rate for a track
    pub fn get_packet_rate(&self, track_id: TrackId) -> Option<u32> {
        self.packet_rates
            .get(&track_id)
            .map(|t| t.packets_per_second())
    }
}

impl Default for SpeakerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_rate_tracking() {
        let mut detector = SpeakerDetector::new();

        // Send 50 packets in first second
        detector.update(1, 50, 0);
        assert_eq!(detector.get_packet_rate(1), Some(50));

        // Window should reset after 1 second - packets_in_window resets to 0
        // and last_packet_count is set to the current packet_count
        detector.update(1, 100, 1_500_000);
        assert_eq!(detector.get_packet_rate(1), Some(0));
        
        // Next update within the new window should count new packets
        detector.update(1, 130, 1_600_000);
        assert_eq!(detector.get_packet_rate(1), Some(30)); // 130 - 100 = 30
    }

    #[test]
    fn test_speaker_detection() {
        let mut detector = SpeakerDetector::new();

        // Track 1: Low rate (below threshold)
        detector.update(1, 10, 0);

        // Track 2: High rate (above threshold)
        detector.update(2, 50, 0);

        let speaker = detector.detect_speaker(0);
        assert_eq!(speaker, Some(2));
        assert_eq!(detector.current_speaker(), Some(2));
    }

    #[test]
    fn test_priority_assignment() {
        let mut detector = SpeakerDetector::new();

        // Make track 1 the speaker
        detector.update(1, 50, 0);
        detector.detect_speaker(0);

        // Speaker gets Critical priority
        assert_eq!(
            detector.get_priority(1, MediaKind::Video),
            TrackPriority::Critical
        );

        // Non-speaker video gets Normal priority
        assert_eq!(
            detector.get_priority(2, MediaKind::Video),
            TrackPriority::Normal
        );

        // Screen share gets High priority
        assert_eq!(
            detector.get_priority(3, MediaKind::ScreenShare),
            TrackPriority::High
        );
    }

    #[test]
    fn test_speaker_transition() {
        let mut detector = SpeakerDetector::new();

        // Track 1 is initially speaker
        detector.update(1, 50, 0);
        assert_eq!(detector.detect_speaker(0), Some(1));

        // Track 2 becomes speaker with higher rate
        detector.update(2, 80, 100_000);
        assert_eq!(detector.detect_speaker(100_000), Some(2));
    }
}
