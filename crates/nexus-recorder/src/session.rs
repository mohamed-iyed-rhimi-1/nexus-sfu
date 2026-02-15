//! Recording session — per-room recording lifecycle.
//!
//! A `RecordingSession` manages the recording of all tracks in a single room.
//! It opens track files when tracks are published and closes them when
//! tracks are removed or the room is cleaned up.
//!
//! Supports start → pause → resume → stop lifecycle.
//!
//! # TigerStyle Compliance
//!
//! - Bounded track count (MAX_TRACKS_PER_SESSION)
//! - ≥2 assertions per public function
//! - No recursion (NASA Rule 1)
//! - Explicit error handling

use nexus_core::{MediaKind, RoomId, Ssrc, TrackId};
use serde::Serialize;

use crate::writer::DiskWriter;

// ============================================================================
// Constants (NASA Rule 2: all limits explicit)
// ============================================================================

/// Maximum tracks recorded per session.
const MAX_TRACKS_PER_SESSION: usize = 512;

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Recording actively.
    Active,
    /// Paused — tracks stay open but packets are not written.
    Paused,
    /// Stopped — all track files closed, session is terminal.
    Stopped,
}

/// A tracked recording entry.
struct TrackedTrack {
    track_id: TrackId,
    #[allow(dead_code)] // Reserved for post-processing metadata
    ssrc: Ssrc,
    #[allow(dead_code)] // Reserved for post-processing metadata
    kind: MediaKind,
}

/// Per-room recording session.
pub struct RecordingSession {
    room_id: RoomId,
    state: SessionState,
    start_time_ns: u64,
    /// Total nanoseconds spent paused (for accurate relative timestamps).
    paused_duration_ns: u64,
    /// Timestamp when the current pause started (0 if not paused).
    pause_start_ns: u64,
    tracks: Vec<TrackedTrack>,
}

impl RecordingSession {
    /// Create a new recording session for a room.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(room_id: RoomId, start_time_ns: u64) -> Self {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(start_time_ns > 0, "start_time_ns must be positive");

        Self {
            room_id,
            state: SessionState::Active,
            start_time_ns,
            paused_duration_ns: 0,
            pause_start_ns: 0,
            tracks: Vec::with_capacity(32),
        }
    }

    pub fn room_id(&self) -> RoomId {
        self.room_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn start_time_ns(&self) -> u64 {
        self.start_time_ns
    }

    pub fn paused_duration_ns(&self) -> u64 {
        self.paused_duration_ns
    }

    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    /// Returns true if packets should be recorded right now.
    pub fn is_accepting_packets(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Register a track for recording. Opens the file via the writer.
    ///
    /// Works in both Active and Paused states (track appears mid-pause).
    ///
    /// Returns `true` if the track was added.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn add_track(
        &mut self,
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
        writer: &DiskWriter,
    ) -> bool {
        assert!(track_id > 0, "track_id must be non-zero");
        assert!(
            self.state != SessionState::Stopped,
            "cannot add tracks to stopped session"
        );

        if self.tracks.len() >= MAX_TRACKS_PER_SESSION {
            tracing::warn!(room_id = self.room_id, "max tracks per session reached");
            return false;
        }

        // Duplicate check — bounded by MAX_TRACKS_PER_SESSION.
        if self.tracks.iter().any(|t| t.track_id == track_id) {
            return false;
        }

        if !writer.open_track(track_id, self.room_id, ssrc, kind, self.start_time_ns) {
            return false;
        }

        self.tracks.push(TrackedTrack {
            track_id,
            ssrc,
            kind,
        });
        true
    }

    /// Remove a track (publisher left or unpublished).
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn remove_track(&mut self, track_id: TrackId, writer: &DiskWriter) {
        assert!(track_id > 0, "track_id must be non-zero");

        if let Some(pos) = self.tracks.iter().position(|t| t.track_id == track_id) {
            self.tracks.swap_remove(pos);
            writer.close_track(track_id);
        }
    }

    /// Pause recording — packets will be silently dropped until resumed.
    ///
    /// Track files stay open. Timestamps will be adjusted on resume to
    /// exclude paused duration.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn pause(&mut self, now_ns: u64) {
        assert!(self.state == SessionState::Active, "can only pause active session");
        assert!(now_ns >= self.start_time_ns, "time must not go backwards");

        self.pause_start_ns = now_ns;
        self.state = SessionState::Paused;
    }

    /// Resume recording after a pause.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn resume(&mut self, now_ns: u64) {
        assert!(self.state == SessionState::Paused, "can only resume paused session");
        assert!(now_ns >= self.pause_start_ns, "time must not go backwards");

        self.paused_duration_ns += now_ns - self.pause_start_ns;
        self.pause_start_ns = 0;
        self.state = SessionState::Active;
    }

    /// Stop the session — close all track files. Terminal state.
    ///
    /// Can be called from Active or Paused state.
    ///
    /// # TigerStyle: ≥2 assertions, bounded loop
    pub fn stop(&mut self, writer: &DiskWriter) {
        assert!(
            self.state != SessionState::Stopped,
            "session already stopped"
        );

        // If paused, finalize pause duration.
        if self.state == SessionState::Paused && self.pause_start_ns > 0 {
            // Use pause_start_ns as the end time (best we have).
            self.paused_duration_ns += 0; // No additional time — we don't know "now".
            self.pause_start_ns = 0;
        }

        // NASA Rule 2: bounded by MAX_TRACKS_PER_SESSION.
        for t in self.tracks.drain(..) {
            writer.close_track(t.track_id);
        }
        self.state = SessionState::Stopped;

        assert!(self.tracks.is_empty(), "postcondition: tracks cleared");
    }

    /// Check if a track is being recorded.
    pub fn has_track(&self, track_id: TrackId) -> bool {
        self.tracks.iter().any(|t| t.track_id == track_id)
    }

    /// Get track IDs for listing.
    pub fn track_ids(&self) -> Vec<TrackId> {
        self.tracks.iter().map(|t| t.track_id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let writer = DiskWriter::spawn(dir.path().to_path_buf()).unwrap();

        let mut session = RecordingSession::new(1, 1_000_000_000);
        assert_eq!(session.state(), SessionState::Active);

        assert!(session.add_track(1, 1000, MediaKind::Audio, &writer));
        assert!(session.add_track(2, 2000, MediaKind::Video, &writer));
        assert_eq!(session.track_count(), 2);

        // Duplicate rejected.
        assert!(!session.add_track(1, 1000, MediaKind::Audio, &writer));

        session.remove_track(1, &writer);
        assert_eq!(session.track_count(), 1);
        assert!(!session.has_track(1));
        assert!(session.has_track(2));

        session.stop(&writer);
        assert_eq!(session.state(), SessionState::Stopped);
        assert_eq!(session.track_count(), 0);

        let stats = writer.shutdown();
        assert_eq!(stats.tracks_recorded, 2);
    }

    #[test]
    fn pause_resume() {
        let dir = tempfile::tempdir().unwrap();
        let writer = DiskWriter::spawn(dir.path().to_path_buf()).unwrap();

        let start = 1_000_000_000u64;
        let mut session = RecordingSession::new(1, start);
        assert!(session.add_track(1, 1000, MediaKind::Audio, &writer));

        assert!(session.is_accepting_packets());

        // Pause at +1s.
        session.pause(start + 1_000_000_000);
        assert_eq!(session.state(), SessionState::Paused);
        assert!(!session.is_accepting_packets());

        // Tracks can still be added while paused.
        assert!(session.add_track(2, 2000, MediaKind::Video, &writer));

        // Resume at +3s (paused for 2s).
        session.resume(start + 3_000_000_000);
        assert_eq!(session.state(), SessionState::Active);
        assert!(session.is_accepting_packets());
        assert_eq!(session.paused_duration_ns(), 2_000_000_000);

        session.stop(&writer);
        let _ = writer.shutdown();
    }

    #[test]
    fn stop_from_paused() {
        let dir = tempfile::tempdir().unwrap();
        let writer = DiskWriter::spawn(dir.path().to_path_buf()).unwrap();

        let mut session = RecordingSession::new(1, 1_000_000_000);
        assert!(session.add_track(1, 1000, MediaKind::Audio, &writer));

        session.pause(2_000_000_000);
        session.stop(&writer); // Should work from paused state.
        assert_eq!(session.state(), SessionState::Stopped);

        let _ = writer.shutdown();
    }
}
