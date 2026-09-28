//! SDP for Nexus SFU: RFC 8866 parsing and printing, and the offer/answer
//! negotiator the orchestrator uses (`sdp`). The old WebRTC transport and session
//! (ICE, DTLS, SRTP per session) were removed in Phase 1: the data plane is
//! `nexus-dataplane`, DTLS runs in the orchestrator.

pub mod sdp;

// Convenience re-exports for commonly used types
pub use sdp::{
    CodecCapability, CodecType, Direction, DtlsFingerprint, DtlsSetup, FingerprintAlgorithm,
    IceCandidate, MediaDescription, MediaType, SdpError, SdpNegotiator, SdpParser, SdpPrinter,
    SessionDescription,
};
