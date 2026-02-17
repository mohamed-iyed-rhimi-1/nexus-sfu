//! Codec-specific RTP payload parsing modules.
//!
//! Each codec module parses codec-specific RTP payload headers
//! to extract keyframe indicators and layer information.
//! Supported codecs: VP8, VP9, H264, AV1, Opus.
//!
//! The `is_keyframe` function provides codec-agnostic keyframe
//! detection. Callers must map SDP-negotiated payload types to
//! `MediaCodec` variants — payload types are dynamic per session.

pub mod av1;
pub mod h264;
pub mod opus;
pub mod vp8;
pub mod vp9;

use thiserror::Error;

/// Media codec identifier.
///
/// Used to dispatch codec-specific parsing. Callers must resolve
/// SDP-negotiated dynamic payload types to this enum before
/// calling `is_keyframe()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MediaCodec {
    Vp8,
    Vp9,
    H264,
    Av1,
    Opus,
}

/// Common payload type constants — typical defaults only.
///
/// These are NOT authoritative. Dynamic payload types are
/// negotiated per-session via SDP. Use `MediaCodec` for
/// dispatch, not raw PT values.
pub const PT_VP8: u8 = 96;
pub const PT_VP9: u8 = 98;
pub const PT_H264: u8 = 102;
pub const PT_AV1: u8 = 35;
pub const PT_OPUS: u8 = 111;

/// Codec-specific parsing errors.
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
/// payload headers.
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
/// contains a keyframe for the given codec. Returns `false`
/// for parse failures.
///
/// # Arguments
///
/// * `codec` - Media codec (resolved from SDP negotiation)
/// * `data` - RTP payload data (after the RTP header)
pub fn is_keyframe(codec: MediaCodec, data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    match codec {
        MediaCodec::Vp8 => vp8::Vp8PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe),
        MediaCodec::Vp9 => vp9::Vp9PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe),
        MediaCodec::H264 => h264::H264PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe()),
        MediaCodec::Av1 => av1::Av1PayloadHeader::parse(data)
            .map_or(false, |h| h.is_keyframe()),
        MediaCodec::Opus => true,
    }
}
