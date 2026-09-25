//! WebRTC transport and SDP parsing for Nexus SFU.
//!
//! This crate contains self-contained protocol implementations:
//! - `sdp`: RFC 8866 compliant SDP parsing and generation
//! - `webrtc`: WebRTC transport layer (ICE/DTLS/SRTP integration)

pub mod sdp;
pub mod webrtc;

// Convenience re-exports for commonly used types
pub use sdp::{
    CodecCapability, CodecType, Direction, DtlsFingerprint, DtlsSetup, FingerprintAlgorithm,
    IceCandidate, MediaDescription, MediaType, SdpError, SdpNegotiator, SdpParser, SdpPrinter,
    SessionDescription,
};

pub use webrtc::{
    PacketType, SessionConfig, SessionState, TransportId, TransportStats, WebRtcError,
    WebRtcSession, WebRtcTransport,
};
