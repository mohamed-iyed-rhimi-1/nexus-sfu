//! Codec-specific RTP payload parsing modules.
//!
//! Each codec module parses codec-specific RTP payload headers
//! to extract keyframe indicators and layer information.
//! Supported codecs: VP8, VP9, H264, AV1, Opus.
//!
//! The `is_keyframe` function provides codec-agnostic keyframe
//! detection based on RTP payload type.

pub mod av1;
pub mod h264;
pub mod opus;
pub mod vp8;
pub mod vp9;

use thiserror::Error;

/// Common payload type constants for codec identification.
/// These are the dynamic payload types commonly negotiated
/// via SDP for WebRTC sessions.
pub const PT_VP8: u8 = 96;
pub const PT_VP9: u8 = 98;
pub const PT_H264: u8 = 102;
pub const PT_AV1: u8 = 35;
pub const PT_OPUS: u8 = 111;

/// Codec-specific parsing errors.
///
/// Every variant carries context about what went wrong.
/// No silent failures — all errors are explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodecError {
    /// Payload too short for the codec header
    #[error(
        "payload too short: {actual_bytes} bytes, \
         need at least {min_bytes}"
    )]
    TooShort {
        actual_bytes: usize,
        min_bytes: usize,
    },

    /// Invalid or unsupported codec header field
    #[error("invalid header field: {field}")]
    InvalidField { field: &'static str },

    /// Unsupported codec feature or extension
    #[error("unsupported feature: {feature}")]
    Unsupported { feature: &'static str },
}

/// Temporal/spatial layer information extracted from codec
/// payload headers. Not all codecs provide all fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayerInfo {
    /// Temporal layer index (0 = base layer)
    pub temporal_layer: Option<u8>,
    /// Spatial layer index (0 = base layer)
    pub spatial_layer: Option<u8>,
}

/// Codec-agnostic keyframe detection.
///
/// Inspects the RTP payload data to determine if the packet
/// contains a keyframe for the given payload type. Returns
/// `false` for unknown payload types or parse failures.
///
/// # Arguments
///
/// * `payload_type` - RTP payload type from the RTP header
/// * `data` - RTP payload data (after the RTP header)
///
/// # TigerStyle
///
/// Asserts: data.len() >= 1
/// Asserts: result is deterministic for same inputs
pub fn is_keyframe(payload_type: u8, data: &[u8]) -> bool {
    // Precondition: need at least 1 byte of payload
    debug_assert!(
        !data.is_empty(),
        "is_keyframe called with empty payload"
    );
    if data.is_empty() {
        return false;
    }

    // Dispatch to codec-specific keyframe detection.
    // Unknown payload types return false — safe default.
    match payload_type {
        PT_VP8 => vp8::Vp8PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe),
        PT_VP9 => vp9::Vp9PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe),
        PT_H264 => h264::H264PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe()),
        PT_AV1 => av1::Av1PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe()),
        // Opus is audio-only; every packet is independently
        // decodable, so treat all as "keyframes".
        PT_OPUS => true,
        _ => false,
    }
}
