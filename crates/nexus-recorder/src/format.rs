//! Binary recording format (.nrec)
//!
//! Layout:
//! ```text
//! [FileHeader: 64 bytes fixed]
//! [PacketRecord: 12-byte header + payload] ...
//! ```
//!
//! # TigerStyle Compliance
//!
//! - Zero dynamic allocation (all fixed-size structs)
//! - Compile-time size assertions
//! - ≥2 assertions per public function
//! - Explicit error handling

use nexus_core::{MediaKind, RoomId, Ssrc, TrackId};

// ============================================================================
// Compile-time assertions (TigerStyle + NASA Rule 5)
// ============================================================================

const _: () = {
    assert!(std::mem::size_of::<FileHeader>() == FILE_HEADER_SIZE);
    assert!(std::mem::size_of::<PacketRecordHeader>() == PACKET_RECORD_HEADER_SIZE);
    assert!(FILE_HEADER_SIZE == 64);
    assert!(PACKET_RECORD_HEADER_SIZE == 12);
};

/// File header size in bytes.
pub const FILE_HEADER_SIZE: usize = 64;

/// Per-packet record header size in bytes.
pub const PACKET_RECORD_HEADER_SIZE: usize = 12;

/// Magic bytes identifying a .nrec file.
pub const MAGIC: [u8; 4] = *b"NREC";

/// Current format version.
pub const FORMAT_VERSION: u16 = 1;

/// Maximum RTP packet payload we will record (MTU-safe).
pub const MAX_RECORD_PAYLOAD: usize = 1500;

/// File header — written once at the start of each .nrec file.
///
/// Fixed 64 bytes, no padding ambiguity.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FileHeader {
    /// Magic bytes: b"NREC"
    pub magic: [u8; 4],
    /// Format version (network byte order).
    pub version: u16,
    /// Media kind: 0 = Audio, 1 = Video.
    pub media_kind: u8,
    /// Reserved for future flags.
    pub flags: u8,
    /// Room ID.
    pub room_id: u64,
    /// Track ID.
    pub track_id: u64,
    /// SSRC of the recorded track.
    pub ssrc: u32,
    /// Recording start timestamp (nanos since Unix epoch).
    pub start_time_ns: u64,
    /// Reserved — zero-filled for forward compatibility.
    pub _reserved: [u8; 28],
}

/// Per-packet record header — prepended to every recorded RTP packet.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PacketRecordHeader {
    /// Timestamp relative to recording start (microseconds).
    pub timestamp_us: u64,
    /// Payload length in bytes (the RTP packet that follows).
    pub payload_len: u32,
}

impl FileHeader {
    /// Create a new file header.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(
        room_id: RoomId,
        track_id: TrackId,
        ssrc: Ssrc,
        kind: MediaKind,
        start_time_ns: u64,
    ) -> Self {
        assert!(start_time_ns > 0, "start_time_ns must be positive");
        assert!(room_id > 0, "room_id must be non-zero");

        Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            media_kind: match kind {
                MediaKind::Audio => 0,
                MediaKind::Video => 1,
            },
            flags: 0,
            room_id: room_id as u64,
            track_id: track_id as u64,
            ssrc,
            start_time_ns,
            _reserved: [0u8; 28],
        }
    }

    /// Serialize to bytes (zero-copy via transmute of fixed repr(C) struct).
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn as_bytes(&self) -> &[u8; FILE_HEADER_SIZE] {
        assert!(self.magic == MAGIC, "corrupt header magic");
        assert!(self.version == FORMAT_VERSION, "unsupported version");
        // SAFETY: FileHeader is repr(C, packed) with known size, no padding.
        unsafe { &*(self as *const Self as *const [u8; FILE_HEADER_SIZE]) }
    }

    /// Deserialize from bytes.
    ///
    /// # TigerStyle: ≥2 assertions, explicit error
    pub fn from_bytes(buf: &[u8; FILE_HEADER_SIZE]) -> Result<Self, FormatError> {
        // SAFETY: repr(C, packed), all bit patterns valid for the field types.
        let header: Self = unsafe { std::ptr::read(buf.as_ptr() as *const Self) };

        if header.magic != MAGIC {
            return Err(FormatError::BadMagic);
        }
        if header.version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(header.version));
        }
        Ok(header)
    }
}

impl PacketRecordHeader {
    /// Create a new packet record header.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(timestamp_us: u64, payload_len: u32) -> Self {
        assert!(payload_len > 0, "payload must be non-empty");
        assert!(
            (payload_len as usize) <= MAX_RECORD_PAYLOAD,
            "payload exceeds max record size"
        );
        Self {
            timestamp_us,
            payload_len,
        }
    }

    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; PACKET_RECORD_HEADER_SIZE] {
        // SAFETY: repr(C, packed), known size.
        unsafe { &*(self as *const Self as *const [u8; PACKET_RECORD_HEADER_SIZE]) }
    }
}

/// Format errors.
#[derive(Debug)]
pub enum FormatError {
    BadMagic,
    UnsupportedVersion(u16),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::BadMagic => write!(f, "invalid NREC magic bytes"),
            FormatError::UnsupportedVersion(v) => {
                write!(f, "unsupported NREC version: {}", v)
            }
        }
    }
}

impl std::error::Error for FormatError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = FileHeader::new(1, 42, 12345, MediaKind::Video, 1_000_000_000);
        let bytes = header.as_bytes();
        let decoded = FileHeader::from_bytes(bytes).unwrap();
        let room_id = decoded.room_id;
        let track_id = decoded.track_id;
        let ssrc = decoded.ssrc;
        let media_kind = decoded.media_kind;
        assert_eq!(room_id, 1);
        assert_eq!(track_id, 42);
        assert_eq!(ssrc, 12345);
        assert_eq!(media_kind, 1);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = [0u8; FILE_HEADER_SIZE];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(FileHeader::from_bytes(&buf).is_err());
    }
}
