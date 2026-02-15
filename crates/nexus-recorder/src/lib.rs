#![deny(warnings)]

//! nexus-recorder: Production-grade room recording for Nexus SFU.
//!
//! Records all media tracks in a room to disk as raw RTP packets
//! in the `.nrec` binary format. Post-process to WebM/MP4 with ffmpeg.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  SFU forwarding pipeline (hot path)                 │
//! │                                                     │
//! │  forward_to_subscribers_static()                    │
//! │      ├── real subscriber → UDP sendto               │
//! │      └── RecordingSink  → WriteCommand (inline buf) │
//! │              │                                      │
//! │              ▼ crossbeam bounded channel             │
//! │      ┌──────────────┐                               │
//! │      │  DiskWriter   │  background thread            │
//! │      │  BufWriter    │  256KB buffer → syscall       │
//! │      └──────┬───────┘                               │
//! │             ▼                                        │
//! │      room1_track1_*.nrec                            │
//! │      room1_track2_*.nrec                            │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle + NASA 10 Rules Compliance
//!
//! 1. No recursion anywhere in this crate
//! 2. All loops have fixed upper bounds
//! 3. No dynamic allocation after initialization on the hot path
//! 4. ≥2 assertions per public function (pre/post conditions)
//! 5. Compile-time size assertions on all wire-format structs
//! 6. All data objects declared at smallest possible scope
//! 7. All return values checked (no ignored Results)
//! 8. Limited preprocessor/macro use
//! 9. Restricted pointer/unsafe use (only for repr(C) transmute)
//! 10. All code compiles warning-free with deny(warnings)

pub mod format;
pub mod writer;
pub mod sink;
pub mod session;
pub mod manager;

pub use format::{FileHeader, FormatError, PacketRecordHeader, MAX_RECORD_PAYLOAD};
pub use writer::{DiskWriter, WriteCommand, WriterStats};
pub use sink::RecordingSink;
pub use session::{RecordingSession, SessionState};
pub use manager::{RecorderError, RecordingInfo, RecordingManager};
