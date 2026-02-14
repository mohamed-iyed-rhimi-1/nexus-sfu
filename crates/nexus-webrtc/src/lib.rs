//! WebRTC transport and SDP parsing for Nexus SFU.
//!
//! This crate contains self-contained protocol implementations:
//! - `sdp`: RFC 8866 compliant SDP parsing and generation
//! - `webrtc`: WebRTC transport layer (ICE/DTLS/SRTP integration)

pub mod sdp;
pub mod webrtc;

// Convenience re-exports for commonly used types
pub use sdp::{
    SdpParser, SdpPrinter, SdpNegotiator, SdpError, SessionDescription,
    MediaDescription, MediaType, IceCandidate, DtlsFingerprint, FingerprintAlgorithm,
    DtlsSetup, Direction, CodecCapability, CodecType,
};

pub use webrtc::{
    WebRtcSession, SessionConfig, SessionState,
    WebRtcTransport, WebRtcError,
    TransportId, TransportStats,
    PacketType,
};
