//! WebRTC Transport Layer
//!
//! Unified transport integrating ICE, DTLS, and SRTP for secure
//! real-time media communication.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      WebRTC Transport                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
//! │  │    ICE      │  │    DTLS     │  │         SRTP            │ │
//! │  │  Candidate  │  │  Handshake  │  │  Encrypt/Decrypt        │ │
//! │  │  Gathering  │  │  Key Export │  │  Replay Protection      │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │                   Transport State Machine                  │ │
//! │  │  New → Connecting → Connected → Failed/Closed             │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │                    Packet Pipeline                         │ │
//! │  │  UDP ←→ ICE ←→ DTLS/SRTP Demux ←→ Application             │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Packet Demultiplexing (RFC 5764)
//!
//! Incoming UDP packets are classified by first byte:
//! - 0-3: STUN
//! - 20-63: DTLS
//! - 128-191: RTP/RTCP (SRTP)
//!
//! # Zero-Copy Design
//!
//! All packet processing is done in-place to minimize allocations
//! on the hot path.

mod demux;
mod error;
mod session;
mod transport;
mod types;

pub use demux::{PacketType, quick_classify, demux_and_validate, ValidationResult, RecoveryHint, RecoveryAction};
pub use error::WebRtcError;
pub use session::{WebRtcSession, SessionConfig, SessionState, IncomingData, MAX_SESSIONS};
pub use transport::{WebRtcTransport, TransportConfig, TransportState};
pub use types::{
    TransportId, MediaType, TransportStats,
    IceParameters, DtlsParameters, DtlsFingerprint, DtlsRole,
    FingerprintAlgorithm,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum packet size for WebRTC (typical MTU).
pub const MAX_PACKET_SIZE: usize = 1500;

/// Maximum number of ICE candidates per transport.
pub const MAX_ICE_CANDIDATES: usize = 32;

/// DTLS handshake timeout in milliseconds.
pub const DTLS_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// ICE connectivity check timeout in milliseconds.
pub const ICE_CHECK_TIMEOUT_MS: u64 = 5_000;

/// Keep-alive interval for ICE in milliseconds.
pub const ICE_KEEPALIVE_MS: u64 = 15_000;

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_PACKET_SIZE, 1500);
        assert_eq!(MAX_ICE_CANDIDATES, 32);
        assert!(DTLS_HANDSHAKE_TIMEOUT_MS > 0);
        assert!(ICE_CHECK_TIMEOUT_MS > 0);
    }
}
