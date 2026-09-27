//! SDP (Session Description Protocol) parsing and generation.
//!
//! RFC 8866 compliant SDP handling for WebRTC signaling.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         SDP Module                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
//! │  │   Parser     │  │  Generator   │  │  Attributes  │          │
//! │  │  (Offer)     │──▶│  (Answer)    │──▶│  (ICE/DTLS)  │          │
//! │  └──────────────┘  └──────────────┘  └──────────────┘          │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - Fixed-size buffers where possible
//! - No dynamic allocation in hot paths
//! - Comprehensive error handling

mod attributes;
mod error;
mod media;
mod negotiator;
mod parser;
mod printer;
mod session;

pub use attributes::{
    CandidateType, Direction, DtlsFingerprint, DtlsSetup, ExtMap, FingerprintAlgorithm, Fmtp,
    IceCandidate, RtcpFeedback, RtpCodec, SsrcInfo,
};
pub use error::SdpError;
pub use media::{
    MediaDescription, MediaType, Mid, Msid, Rid, SimulcastAttr, SsrcGroup, TransportProtocol,
};
pub use negotiator::{
    default_supported_codecs, offered_extmaps, CodecCapability, CodecType, OfferMline,
    RecycledMline, SdpNegotiator, TrackMline,
};
pub use parser::SdpParser;
pub use printer::SdpPrinter;
pub use session::{Origin, SessionDescription, Timing};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of media sections in an SDP.
///
/// A 10-client call needs 20 m-lines per session, and the negotiator gives each new
/// sendonly m-line an unused PT from 96-127, so ≈ 30 is the practical ceiling anyway.
pub const MAX_MEDIA_SECTIONS: usize = 32;

/// Maximum number of codecs per media section.
pub const MAX_CODECS_PER_MEDIA: usize = 16;

/// Maximum number of ICE candidates per media section.
pub const MAX_CANDIDATES_PER_MEDIA: usize = 32;

/// Maximum number of SSRC entries per media section.
pub const MAX_SSRCS_PER_MEDIA: usize = 8;

/// Maximum number of header extensions per media section.
pub const MAX_EXTMAPS_PER_MEDIA: usize = 16;

/// Maximum SDP size in bytes (32 m-lines with extmaps and rtcp-fb fit well below it).
pub const MAX_SDP_SIZE: usize = 131_072;

/// Maximum length of a `mid` in bytes.
pub const MAX_MID_LEN: usize = 16;

/// Maximum length of the BUNDLE group value: every mid plus a separator.
pub const MAX_BUNDLE_LEN: usize = MAX_MEDIA_SECTIONS * (MAX_MID_LEN + 1);

/// SDP version (always 0).
pub const SDP_VERSION: u8 = 0;

// Compile-time assertions for bounds (TigerStyle)
const _: () = assert!(
    MAX_MEDIA_SECTIONS <= 32,
    "MAX_MEDIA_SECTIONS is bounded by the dynamic PT range (96-127)"
);
const _: () = assert!(
    MAX_CODECS_PER_MEDIA == 16,
    "MAX_CODECS_PER_MEDIA must be exactly 16 to prevent memory exhaustion"
);
const _: () = assert!(
    MAX_CANDIDATES_PER_MEDIA == 32,
    "MAX_CANDIDATES_PER_MEDIA must match ICE module MAX_CANDIDATES"
);
const _: () = assert!(
    MAX_SSRCS_PER_MEDIA <= 8,
    "MAX_SSRCS_PER_MEDIA must be bounded for simulcast scenarios"
);
const _: () = assert!(
    MAX_SDP_SIZE == 128 * 1024,
    "MAX_SDP_SIZE must be 128KB to prevent DoS attacks"
);

const _: () = assert!(
    MAX_BUNDLE_LEN <= u16::MAX as usize,
    "bundle_group_len is a u16"
);

// Assert string buffer sizes are reasonable
const _: () = assert!(
    std::mem::size_of::<session::Origin>() <= 256,
    "Origin struct must fit in 256 bytes"
);

/// Minimum ICE ufrag length (RFC 8445).
pub const MIN_ICE_UFRAG_LEN: usize = 4;

/// Minimum ICE pwd length (RFC 8445).
pub const MIN_ICE_PWD_LEN: usize = 22;

/// Maximum ICE ufrag length (RFC 8445 §5.3: up to 256 ice-chars).
pub const MAX_ICE_UFRAG_LEN: usize = 256;

/// Maximum ICE pwd length (RFC 8445 §5.3: up to 256 ice-chars).
pub const MAX_ICE_PWD_LEN: usize = 256;

/// Maximum RTCP feedback entries per media section.
pub const MAX_RTCP_FB_PER_MEDIA: usize = 32;

/// Maximum SSRC groups per media section.
pub const MAX_SSRC_GROUPS_PER_MEDIA: usize = 8;

/// Maximum RID entries per media section.
pub const MAX_RIDS_PER_MEDIA: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SDP_VERSION, 0);
        const { assert!(MAX_MEDIA_SECTIONS >= 8) };
    }
}
