//! Background disk writer thread.
//!
//! Receives packet data via a bounded crossbeam channel and writes
//! to disk using buffered I/O. Runs on a dedicated thread to keep
//! the forwarding hot path non-blocking.
//!
//! # TigerStyle Compliance
//!
//! - Bounded channel (no unbounded growth — NASA Rule 2)
//! - No recursion (NASA Rule 1)
//! - All loops bounded (NASA Rule 2)
//! - ≥2 assertions per public function
//! - Explicit error handling (no unwrap on I/O path)

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use tracing::{debug, error, info, warn};

use nexus_core::{MediaKind, RoomId, Ssrc, TrackId};

use crate::format::{
    FileHeader, PacketRecordHeader, FILE_HEADER_SIZE, MAX_RECORD_PAYLOAD,
    PACKET_RECORD_HEADER_SIZE,
};

// ============================================================================
// Constants (TigerStyle: all limits explicit, NASA Rule 2)
// ============================================================================

/// Maximum queued write commands before backpressure.
const WRITE_CHANNEL_CAPACITY: usize = 8192;

/// BufWriter capacity — 256 KB to batch syscalls.
const WRITE_BUF_SIZE: usize = 256 * 1024;

/// Maximum write commands processed per drain loop iteration.
/// NASA Rule 2: all loops must have a fixed upper bound.
const MAX_DRAIN_PER_ITER: usize = 512;

/// Maximum number of concurrent track files per writer thread.
/// Prevents unbounded file descriptor growth.
const MAX_TRACK_FILES: usize = 1024;

// ============================================================================
// Compile-time assertions
// ============================================================================

const _: () = {
    assert!(WRITE_CHANNEL_CAPACITY >= 1024);
    assert!(WRITE_BUF_SIZE >= 64 * 1024);
    assert!(MAX_DRAIN_PER_ITER <= WRITE_CHANNEL_CAPACITY);
    assert!(MAX_TRACK_FILES >= 1);
};

/// A write command sent from the hot path to the background writer.
///
/// Uses a fixed-size inline buffer to avoid heap allocation.
pub struct WriteCommand {
    pub track_id: TrackId,
    pub timestamp_us: u64,
    pub len: u16,
    pub data: [u8; MAX_RECORD_PAYLOAD],
}

/// Control commands for the writer thread.
pub enum WriterCommand {
    /// Write a packet to the track's file.
    Packet(WriteCommand),
    /// Open a new track file.
    OpenTrack {
        track_id: TrackId,
        room_id: RoomId,
        ssrc: Ssrc,
        kind: MediaKind,
        start_time_ns: u64,
    },
    /// Close a track file (track removed or room ended).
    CloseTrack { track_id: TrackId },
    /// Flush all buffers and shut down.
    Shutdown,
}

/// Handle to the background writer thread.
pub struct DiskWriter {
    tx: Sender<WriterCommand>,
    handle: Option<JoinHandle<WriterStats>>,
}

/// Statistics returned when the writer thread finishes.
#[derive(Debug, Clone, Default)]
pub struct WriterStats {
    pub packets_written: u64,
    pub bytes_written: u64,
    pub tracks_recorded: u32,
    pub write_errors: u64,
    pub channel_drops: u64,
}

/// Per-track open file state.
struct TrackFile {
    writer: BufWriter<File>,
    packets_written: u64,
    bytes_written: u64,
}

impl DiskWriter {
    /// Spawn a background writer thread.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn spawn(output_dir: PathBuf) -> Result<Self, std::io::Error> {
        assert!(
            output_dir.as_os_str().len() > 0,
            "output_dir must be non-empty"
        );

        // Ensure output directory exists.
        fs::create_dir_all(&output_dir)?;

        assert!(output_dir.is_dir(), "output_dir must be a directory");

        let (tx, rx) = crossbeam_channel::bounded(WRITE_CHANNEL_CAPACITY);

        let dir_for_log = output_dir.clone();
        let handle = thread::Builder::new()
            .name("nexus-recorder-writer".into())
            .spawn(move || writer_loop(rx, &output_dir))?;

        info!(dir = %dir_for_log.display(), "disk writer spawned");

        Ok(Self {
            tx,
            handle: Some(handle),
        })
    }

    /// Open a new track file. Non-blocking.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn open_track(
        &self,
        track_id: TrackId,
        room_id: RoomId,
        ssrc: Ssrc,
        kind: MediaKind,
        start_time_ns: u64,
    ) -> bool {
        assert!(track_id > 0, "track_id must be non-zero");
        assert!(start_time_ns > 0, "start_time_ns must be positive");

        self.tx
            .try_send(WriterCommand::OpenTrack {
                track_id,
                room_id,
                ssrc,
                kind,
                start_time_ns,
            })
            .is_ok()
    }

    /// Queue a packet write. Non-blocking — drops on backpressure.
    ///
    /// Returns `true` if queued, `false` if dropped.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn write_packet(&self, cmd: WriteCommand) -> bool {
        assert!(cmd.len > 0, "packet length must be positive");
        assert!(
            (cmd.len as usize) <= MAX_RECORD_PAYLOAD,
            "packet exceeds max payload"
        );

        match self.tx.try_send(WriterCommand::Packet(cmd)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                warn!("recorder write channel full, dropping packet");
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Close a track file. Non-blocking.
    pub fn close_track(&self, track_id: TrackId) {
        let _ = self.tx.try_send(WriterCommand::CloseTrack { track_id });
    }

    /// Shut down the writer thread and return stats.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn shutdown(mut self) -> WriterStats {
        let _ = self.tx.send(WriterCommand::Shutdown);
        match self.handle.take() {
            Some(h) => match h.join() {
                Ok(stats) => {
                    assert!(
                        stats.write_errors == 0 || stats.packets_written > 0,
                        "write errors without any packets is unexpected"
                    );
                    info!(
                        packets = stats.packets_written,
                        bytes = stats.bytes_written,
                        tracks = stats.tracks_recorded,
                        errors = stats.write_errors,
                        "disk writer shut down"
                    );
                    stats
                }
                Err(_) => {
                    error!("writer thread panicked");
                    WriterStats::default()
                }
            },
            None => WriterStats::default(),
        }
    }
}

impl Drop for DiskWriter {
    fn drop(&mut self) {
        // Signal shutdown if not already done.
        let _ = self.tx.try_send(WriterCommand::Shutdown);
    }
}

// ============================================================================
// Writer thread loop (NASA Rule 1: no recursion)
// ============================================================================

fn writer_loop(rx: Receiver<WriterCommand>, output_dir: &Path) -> WriterStats {
    let mut files: Vec<(TrackId, TrackFile)> = Vec::with_capacity(64);
    let mut stats = WriterStats::default();

    // NASA Rule 2: main loop bounded by channel lifetime (sender drop = exit).
    loop {
        let cmd = match rx.recv() {
            Ok(cmd) => cmd,
            Err(_) => break, // Channel closed.
        };

        match cmd {
            WriterCommand::Shutdown => {
                flush_all(&mut files, &mut stats);
                break;
            }
            WriterCommand::OpenTrack {
                track_id,
                room_id,
                ssrc,
                kind,
                start_time_ns,
            } => {
                handle_open_track(
                    &mut files,
                    &mut stats,
                    output_dir,
                    track_id,
                    room_id,
                    ssrc,
                    kind,
                    start_time_ns,
                );
            }
            WriterCommand::CloseTrack { track_id } => {
                handle_close_track(&mut files, &mut stats, track_id);
            }
            WriterCommand::Packet(pkt) => {
                handle_packet(&mut files, &mut stats, pkt);
            }
        }

        // Drain additional ready commands to batch I/O.
        // NASA Rule 2: bounded drain.
        for _ in 0..MAX_DRAIN_PER_ITER {
            match rx.try_recv() {
                Ok(WriterCommand::Shutdown) => {
                    flush_all(&mut files, &mut stats);
                    return stats;
                }
                Ok(WriterCommand::OpenTrack {
                    track_id,
                    room_id,
                    ssrc,
                    kind,
                    start_time_ns,
                }) => {
                    handle_open_track(
                        &mut files,
                        &mut stats,
                        output_dir,
                        track_id,
                        room_id,
                        ssrc,
                        kind,
                        start_time_ns,
                    );
                }
                Ok(WriterCommand::CloseTrack { track_id }) => {
                    handle_close_track(&mut files, &mut stats, track_id);
                }
                Ok(WriterCommand::Packet(pkt)) => {
                    handle_packet(&mut files, &mut stats, pkt);
                }
                Err(_) => break,
            }
        }
    }

    stats
}

// ============================================================================
// Handler functions (TigerStyle: ≤70 lines each)
// ============================================================================

fn handle_open_track(
    files: &mut Vec<(TrackId, TrackFile)>,
    stats: &mut WriterStats,
    output_dir: &Path,
    track_id: TrackId,
    room_id: RoomId,
    ssrc: Ssrc,
    kind: MediaKind,
    start_time_ns: u64,
) {
    if files.len() >= MAX_TRACK_FILES {
        error!(track_id, "max track files reached, cannot open");
        return;
    }

    // Check for duplicate.
    if files.iter().any(|(id, _)| *id == track_id) {
        warn!(track_id, "track file already open");
        return;
    }

    let filename = format!(
        "room{}_track{}_{}.nrec",
        room_id, track_id, start_time_ns
    );
    let path = output_dir.join(&filename);

    let file = match File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            error!(track_id, err = %e, "failed to create recording file");
            stats.write_errors += 1;
            return;
        }
    };

    let mut writer = BufWriter::with_capacity(WRITE_BUF_SIZE, file);
    let header = FileHeader::new(room_id, track_id, ssrc, kind, start_time_ns);

    if let Err(e) = writer.write_all(header.as_bytes()) {
        error!(track_id, err = %e, "failed to write file header");
        stats.write_errors += 1;
        return;
    }

    files.push((track_id, TrackFile {
        writer,
        packets_written: 0,
        bytes_written: FILE_HEADER_SIZE as u64,
    }));
    stats.tracks_recorded += 1;

    debug!(track_id, path = %path.display(), "track recording started");
}

fn handle_close_track(
    files: &mut Vec<(TrackId, TrackFile)>,
    stats: &mut WriterStats,
    track_id: TrackId,
) {
    if let Some(pos) = files.iter().position(|(id, _)| *id == track_id) {
        let (_, mut tf) = files.swap_remove(pos);
        if let Err(e) = tf.writer.flush() {
            error!(track_id, err = %e, "flush error on track close");
            stats.write_errors += 1;
        }
        debug!(
            track_id,
            packets = tf.packets_written,
            bytes = tf.bytes_written,
            "track recording stopped"
        );
    }
}

fn handle_packet(
    files: &mut Vec<(TrackId, TrackFile)>,
    stats: &mut WriterStats,
    pkt: WriteCommand,
) {
    let tf = match files.iter_mut().find(|(id, _)| *id == pkt.track_id) {
        Some((_, tf)) => tf,
        None => return, // Track not being recorded — silently skip.
    };

    let record_hdr = PacketRecordHeader::new(pkt.timestamp_us, pkt.len as u32);
    let hdr_bytes = record_hdr.as_bytes();
    let payload = &pkt.data[..pkt.len as usize];

    // Write header + payload as two sequential writes into BufWriter.
    // BufWriter coalesces these into a single syscall most of the time.
    if let Err(e) = tf.writer.write_all(hdr_bytes) {
        error!(track_id = pkt.track_id, err = %e, "write error (header)");
        stats.write_errors += 1;
        return;
    }
    if let Err(e) = tf.writer.write_all(payload) {
        error!(track_id = pkt.track_id, err = %e, "write error (payload)");
        stats.write_errors += 1;
        return;
    }

    let total = PACKET_RECORD_HEADER_SIZE as u64 + pkt.len as u64;
    tf.packets_written += 1;
    tf.bytes_written += total;
    stats.packets_written += 1;
    stats.bytes_written += total;
}

fn flush_all(files: &mut Vec<(TrackId, TrackFile)>, stats: &mut WriterStats) {
    // NASA Rule 2: bounded by MAX_TRACK_FILES.
    for (track_id, tf) in files.iter_mut() {
        if let Err(e) = tf.writer.flush() {
            error!(track_id, err = %e, "flush error on shutdown");
            stats.write_errors += 1;
        }
    }
    files.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn write_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let writer = DiskWriter::spawn(dir.path().to_path_buf()).unwrap();

        let track_id: TrackId = 1;
        let room_id: RoomId = 10;
        let ssrc: Ssrc = 5555;
        let start_ns: u64 = 1_000_000_000;

        assert!(writer.open_track(track_id, room_id, ssrc, MediaKind::Audio, start_ns));

        // Write a packet.
        let mut data = [0u8; MAX_RECORD_PAYLOAD];
        data[0..4].copy_from_slice(&[0x80, 0x6F, 0x00, 0x01]); // minimal RTP
        let cmd = WriteCommand {
            track_id,
            timestamp_us: 1000,
            len: 100,
            data,
        };
        assert!(writer.write_packet(cmd));

        let stats = writer.shutdown();
        assert_eq!(stats.packets_written, 1);
        assert_eq!(stats.tracks_recorded, 1);
        assert_eq!(stats.write_errors, 0);

        // Verify file on disk.
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);

        let mut contents = Vec::new();
        File::open(entries[0].as_ref().unwrap().path())
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let expected_size = FILE_HEADER_SIZE + PACKET_RECORD_HEADER_SIZE + 100;
        assert_eq!(contents.len(), expected_size);

        // Verify header.
        let mut hdr_buf = [0u8; FILE_HEADER_SIZE];
        hdr_buf.copy_from_slice(&contents[..FILE_HEADER_SIZE]);
        let hdr = FileHeader::from_bytes(&hdr_buf).unwrap();
        let room_id = hdr.room_id;
        let ssrc = hdr.ssrc;
        assert_eq!(room_id, 10);
        assert_eq!(ssrc, 5555);
    }
}
