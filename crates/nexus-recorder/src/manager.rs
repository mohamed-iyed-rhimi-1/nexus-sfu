//! Recording manager — coordinates all recording sessions.
//!
//! The `RecordingManager` is the top-level API. SDK consumers call
//! start/pause/resume/stop via REST endpoints which delegate here.
//!
//! # TigerStyle Compliance
//!
//! - Bounded session count (MAX_CONCURRENT_SESSIONS)
//! - ≥2 assertions per public function
//! - No recursion (NASA Rule 1)
//! - All loops bounded (NASA Rule 2)
//! - Explicit error handling

use std::path::PathBuf;

use nexus_core::{MediaKind, RoomId, Ssrc, TrackId};
use serde::Serialize;
use tracing::info;

use crate::session::{RecordingSession, SessionState};
use crate::sink::RecordingSink;
use crate::writer::{DiskWriter, WriterStats};

// ============================================================================
// Constants (NASA Rule 2)
// ============================================================================

/// Maximum concurrent recording sessions.
const MAX_CONCURRENT_SESSIONS: usize = 1024;

/// Maximum recordings returned in a list query.
const MAX_LIST_RESULTS: usize = 256;

/// Recording manager errors.
#[derive(Debug)]
pub enum RecorderError {
    IoError(std::io::Error),
    SessionNotFound(RoomId),
    SessionAlreadyExists(RoomId),
    CapacityExceeded,
    InvalidState { room_id: RoomId, current: SessionState, expected: &'static str },
}

impl std::fmt::Display for RecorderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecorderError::IoError(e) => write!(f, "I/O error: {}", e),
            RecorderError::SessionNotFound(id) => write!(f, "no recording for room {}", id),
            RecorderError::SessionAlreadyExists(id) => {
                write!(f, "recording already exists for room {}", id)
            }
            RecorderError::CapacityExceeded => write!(f, "max concurrent recordings reached"),
            RecorderError::InvalidState { room_id, current, expected } => {
                write!(
                    f,
                    "room {} recording is {:?}, expected {}",
                    room_id, current, expected
                )
            }
        }
    }
}

impl std::error::Error for RecorderError {}

impl From<std::io::Error> for RecorderError {
    fn from(e: std::io::Error) -> Self {
        RecorderError::IoError(e)
    }
}

/// Info returned by list queries.
#[derive(Debug, Clone, Serialize)]
pub struct RecordingInfo {
    pub room_id: RoomId,
    pub state: SessionState,
    pub start_time_ns: u64,
    pub paused_duration_ns: u64,
    pub track_count: usize,
    pub track_ids: Vec<TrackId>,
}

/// Top-level recording coordinator.
pub struct RecordingManager {
    writer: DiskWriter,
    sessions: Vec<RecordingSession>,
    output_dir: PathBuf,
}

impl RecordingManager {
    /// Create a new recording manager.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(output_dir: PathBuf) -> Result<Self, RecorderError> {
        assert!(
            output_dir.as_os_str().len() > 0,
            "output_dir must be non-empty"
        );

        let writer = DiskWriter::spawn(output_dir.clone())?;

        assert!(output_dir.is_dir(), "output_dir must exist after spawn");

        info!(dir = %output_dir.display(), "recording manager initialized");

        Ok(Self {
            writer,
            sessions: Vec::with_capacity(64),
            output_dir,
        })
    }

    /// Start recording a room.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn start_recording(
        &mut self,
        room_id: RoomId,
        start_time_ns: u64,
    ) -> Result<(), RecorderError> {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(start_time_ns > 0, "start_time_ns must be positive");

        if self.sessions.len() >= MAX_CONCURRENT_SESSIONS {
            return Err(RecorderError::CapacityExceeded);
        }

        if self.sessions.iter().any(|s| s.room_id() == room_id && s.state() != SessionState::Stopped) {
            return Err(RecorderError::SessionAlreadyExists(room_id));
        }

        let session = RecordingSession::new(room_id, start_time_ns);
        self.sessions.push(session);

        info!(room_id, "recording started");
        Ok(())
    }

    /// Pause recording a room — packets silently dropped until resumed.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn pause_recording(
        &mut self,
        room_id: RoomId,
        now_ns: u64,
    ) -> Result<(), RecorderError> {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(now_ns > 0, "now_ns must be positive");

        let session = self.find_session_mut(room_id)?;

        if session.state() != SessionState::Active {
            return Err(RecorderError::InvalidState {
                room_id,
                current: session.state(),
                expected: "active",
            });
        }

        session.pause(now_ns);
        info!(room_id, "recording paused");
        Ok(())
    }

    /// Resume recording a room after pause.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn resume_recording(
        &mut self,
        room_id: RoomId,
        now_ns: u64,
    ) -> Result<(), RecorderError> {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(now_ns > 0, "now_ns must be positive");

        let session = self.find_session_mut(room_id)?;

        if session.state() != SessionState::Paused {
            return Err(RecorderError::InvalidState {
                room_id,
                current: session.state(),
                expected: "paused",
            });
        }

        session.resume(now_ns);
        info!(room_id, "recording resumed");
        Ok(())
    }

    /// Stop recording a room — closes all track files. Terminal.
    ///
    /// Can be called from Active or Paused state.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn stop_recording(&mut self, room_id: RoomId) -> Result<(), RecorderError> {
        assert!(room_id > 0, "room_id must be non-zero");

        let pos = self
            .sessions
            .iter()
            .position(|s| s.room_id() == room_id && s.state() != SessionState::Stopped)
            .ok_or(RecorderError::SessionNotFound(room_id))?;

        let session = &mut self.sessions[pos];

        if session.state() == SessionState::Stopped {
            return Err(RecorderError::InvalidState {
                room_id,
                current: SessionState::Stopped,
                expected: "active or paused",
            });
        }

        session.stop(&self.writer);
        self.sessions.swap_remove(pos);

        info!(room_id, "recording stopped");
        Ok(())
    }

    /// Notify that a track was published in a room.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn on_track_added(
        &mut self,
        room_id: RoomId,
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
    ) {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(track_id > 0, "track_id must be non-zero");

        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.room_id() == room_id && s.state() != SessionState::Stopped);
        if let Some(session) = session {
            session.add_track(track_id, ssrc, kind, &self.writer);
        }
    }

    /// Notify that a track was removed from a room.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn on_track_removed(&mut self, room_id: RoomId, track_id: TrackId) {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(track_id > 0, "track_id must be non-zero");

        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.room_id() == room_id && s.state() != SessionState::Stopped);
        if let Some(session) = session {
            session.remove_track(track_id, &self.writer);
        }
    }

    /// Create a `RecordingSink` for a track in an actively recorded room.
    ///
    /// Returns `None` if the room is not actively recording (paused/stopped/absent).
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn sink_for_track(&self, room_id: RoomId, track_id: TrackId) -> Option<RecordingSink<'_>> {
        assert!(room_id > 0, "room_id must be non-zero");
        assert!(track_id > 0, "track_id must be non-zero");

        let session = self
            .sessions
            .iter()
            .find(|s| s.room_id() == room_id && s.is_accepting_packets())?;

        if !session.has_track(track_id) {
            return None;
        }

        Some(RecordingSink::new(
            track_id,
            &self.writer,
            session.start_time_ns(),
        ))
    }

    /// Check if a room is actively recording (not paused, not stopped).
    pub fn is_recording(&self, room_id: RoomId) -> bool {
        self.sessions
            .iter()
            .any(|s| s.room_id() == room_id && s.is_accepting_packets())
    }

    /// Get recording info for a specific room.
    pub fn get_recording(&self, room_id: RoomId) -> Option<RecordingInfo> {
        self.sessions
            .iter()
            .find(|s| s.room_id() == room_id)
            .map(session_to_info)
    }

    /// List all recordings (active + paused). Stopped sessions are already removed.
    ///
    /// # TigerStyle: bounded result
    pub fn list_recordings(&self) -> Vec<RecordingInfo> {
        self.sessions
            .iter()
            .take(MAX_LIST_RESULTS)
            .map(session_to_info)
            .collect()
    }

    /// List recordings filtered by room ID.
    pub fn list_recordings_by_room(&self, room_id: RoomId) -> Vec<RecordingInfo> {
        self.sessions
            .iter()
            .filter(|s| s.room_id() == room_id)
            .take(MAX_LIST_RESULTS)
            .map(session_to_info)
            .collect()
    }

    /// Number of active recording sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.state() == SessionState::Active)
            .count()
    }

    /// Shut down the manager — stops all sessions and flushes to disk.
    ///
    /// # TigerStyle: bounded loop
    pub fn shutdown(mut self) -> WriterStats {
        for session in self.sessions.iter_mut() {
            if session.state() != SessionState::Stopped {
                session.stop(&self.writer);
            }
        }
        self.sessions.clear();
        self.writer.shutdown()
    }

    /// Output directory path.
    pub fn output_dir(&self) -> &PathBuf {
        &self.output_dir
    }

    fn find_session_mut(&mut self, room_id: RoomId) -> Result<&mut RecordingSession, RecorderError> {
        self.sessions
            .iter_mut()
            .find(|s| s.room_id() == room_id && s.state() != SessionState::Stopped)
            .ok_or(RecorderError::SessionNotFound(room_id))
    }
}

fn session_to_info(s: &RecordingSession) -> RecordingInfo {
    RecordingInfo {
        room_id: s.room_id(),
        state: s.state(),
        start_time_ns: s.start_time_ns(),
        paused_duration_ns: s.paused_duration_ns(),
        track_count: s.track_count(),
        track_ids: s.track_ids(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf()).unwrap();

        let room_id: RoomId = 1;
        let start_ns: u64 = 1_000_000_000;

        mgr.start_recording(room_id, start_ns).unwrap();
        assert!(mgr.is_recording(room_id));
        assert_eq!(mgr.active_session_count(), 1);

        // Duplicate rejected.
        assert!(mgr.start_recording(room_id, start_ns).is_err());

        mgr.on_track_added(room_id, 1, 1000, MediaKind::Audio);
        mgr.on_track_added(room_id, 2, 2000, MediaKind::Video);

        // Record a packet.
        {
            let mut sink = mgr.sink_for_track(room_id, 1).unwrap();
            let rtp = [0x80, 0x6F, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
            assert!(sink.record_packet(start_ns + 1_000_000, &rtp));
            assert_eq!(sink.packets_queued, 1);
        }

        mgr.stop_recording(room_id).unwrap();
        assert!(!mgr.is_recording(room_id));

        let stats = mgr.shutdown();
        assert_eq!(stats.tracks_recorded, 2);
        assert_eq!(stats.packets_written, 1);
        assert_eq!(stats.write_errors, 0);
    }

    #[test]
    fn pause_resume_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf()).unwrap();

        let room_id: RoomId = 1;
        let start_ns: u64 = 1_000_000_000;

        mgr.start_recording(room_id, start_ns).unwrap();
        mgr.on_track_added(room_id, 1, 1000, MediaKind::Audio);

        // Active — sink available.
        assert!(mgr.sink_for_track(room_id, 1).is_some());

        // Pause — sink not available.
        mgr.pause_recording(room_id, start_ns + 1_000_000_000).unwrap();
        assert!(mgr.sink_for_track(room_id, 1).is_none());
        assert!(!mgr.is_recording(room_id));

        // Double pause fails.
        assert!(mgr.pause_recording(room_id, start_ns + 2_000_000_000).is_err());

        // Resume — sink available again.
        mgr.resume_recording(room_id, start_ns + 3_000_000_000).unwrap();
        assert!(mgr.sink_for_track(room_id, 1).is_some());
        assert!(mgr.is_recording(room_id));

        // Double resume fails.
        assert!(mgr.resume_recording(room_id, start_ns + 4_000_000_000).is_err());

        mgr.stop_recording(room_id).unwrap();
        let _ = mgr.shutdown();
    }

    #[test]
    fn list_recordings() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf()).unwrap();

        mgr.start_recording(1, 1_000_000_000).unwrap();
        mgr.start_recording(2, 2_000_000_000).unwrap();
        mgr.on_track_added(1, 10, 1000, MediaKind::Audio);
        mgr.on_track_added(2, 20, 2000, MediaKind::Video);

        let all = mgr.list_recordings();
        assert_eq!(all.len(), 2);

        let room1 = mgr.list_recordings_by_room(1);
        assert_eq!(room1.len(), 1);
        assert_eq!(room1[0].room_id, 1);
        assert_eq!(room1[0].track_count, 1);

        let info = mgr.get_recording(1).unwrap();
        assert_eq!(info.state, SessionState::Active);
        assert_eq!(info.track_ids, vec![10]);

        assert!(mgr.get_recording(99).is_none());

        let _ = mgr.shutdown();
    }

    #[test]
    fn stop_from_paused() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf()).unwrap();

        mgr.start_recording(1, 1_000_000_000).unwrap();
        mgr.pause_recording(1, 2_000_000_000).unwrap();
        mgr.stop_recording(1).unwrap(); // Should work from paused.
        assert!(mgr.get_recording(1).is_none());

        let _ = mgr.shutdown();
    }

    #[test]
    fn unrecorded_room_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf()).unwrap();

        mgr.on_track_added(99, 1, 1000, MediaKind::Audio);
        mgr.on_track_removed(99, 1);
        assert!(mgr.sink_for_track(99, 1).is_none());

        let stats = mgr.shutdown();
        assert_eq!(stats.tracks_recorded, 0);
    }
}
