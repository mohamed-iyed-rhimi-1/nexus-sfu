//! SRTP (Secure Real-time Transport Protocol) implementation.
//!
//! RFC 3711 compliant implementation with:
//! - AES-128-GCM encryption (RFC 7714)
//! - Key derivation from DTLS master secret
//! - Replay protection with sliding window
//! - SRTP and SRTCP support
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     SRTP Context                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
//! │  │ Key Material │  │ Cipher Suite │  │ Replay Protection │  │
//! │  │              │  │  AES-128-GCM │  │  Sliding Window   │  │
//! │  └──────────────┘  └──────────────┘  └──────────────────┘  │
//! │                                                             │
//! │  ┌──────────────────────────────────────────────────────┐  │
//! │  │                   Crypto Transform                    │  │
//! │  │  protect_rtp() / unprotect_rtp()                     │  │
//! │  │  protect_rtcp() / unprotect_rtcp()                   │  │
//! │  └──────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Zero-Copy Design
//!
//! All operations work in-place on buffers to avoid allocations
//! on the hot path. The protect/unprotect functions modify the
//! provided buffer directly.

mod context;
mod crypto;
mod error;
mod keys;
mod replay;
mod types;

pub use context::{PoolStats, SrtpContext, SrtpSession, SrtpSessionPool, SrtpStats};
pub use crypto::{AesCmHmacCipher, AesGcmCipher, CipherSuite, SrtpCipher};
pub use error::SrtpError;
pub use keys::{KeyDerivation, KeyMaterial, SrtpKeys};
pub use replay::ReplayProtection;
pub use types::{PacketIndex, ProtectionProfile, Roc, RtcpHeader, RtpHeader, SeqNum, Ssrc, SrtpPolicy};

// ============================================================================
// Constants (RFC 3711 / RFC 7714)
// ============================================================================

/// RTP header size (minimum).
pub const RTP_HEADER_SIZE: usize = 12;

/// RTCP header size (minimum).
pub const RTCP_HEADER_SIZE: usize = 8;

/// AES-128-GCM authentication tag size.
pub const SRTP_AUTH_TAG_SIZE: usize = 16;

/// AES-128-GCM salt size.
pub const SRTP_SALT_SIZE: usize = 12;

/// AES-128 key size.
pub const SRTP_KEY_SIZE: usize = 16;

/// Maximum SRTP packet size.
pub const MAX_SRTP_PACKET_SIZE: usize = 1500;

/// SRTCP index mask (31 bits).
pub const SRTCP_INDEX_MASK: u32 = 0x7FFF_FFFF;

/// SRTCP encrypted flag bit.
pub const SRTCP_E_FLAG: u32 = 0x8000_0000;

/// Replay window size (64 packets).
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// Label for RTP encryption key derivation.
pub const LABEL_RTP_ENCRYPTION: u8 = 0x00;

/// Label for RTP authentication key derivation.
pub const LABEL_RTP_AUTH: u8 = 0x01;

/// Label for RTP salt derivation.
pub const LABEL_RTP_SALT: u8 = 0x02;

/// Label for RTCP encryption key derivation.
pub const LABEL_RTCP_ENCRYPTION: u8 = 0x03;

/// Label for RTCP authentication key derivation.
pub const LABEL_RTCP_AUTH: u8 = 0x04;

/// Label for RTCP salt derivation.
pub const LABEL_RTCP_SALT: u8 = 0x05;

/// Maximum concurrent SRTP sessions (production limit).
pub const MAX_SRTP_SESSIONS: u32 = 1000;

/// Maximum SRTP packet size.
///
/// Must accommodate the largest UDP datagram the transport layer can receive.
/// WebRTC peers may send datagrams larger than Ethernet MTU when IP
/// fragmentation is in play (e.g. raw audio samples before Opus encoding).
pub const MAX_PACKET_SIZE: u32 = 8192;

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

const _: () = assert!(
    MAX_SRTP_SESSIONS <= 10000,
    "session count must not exceed 10,000"
);

const _: () = assert!(
    MAX_PACKET_SIZE as usize >= RTP_HEADER_SIZE + SRTP_AUTH_TAG_SIZE,
    "max packet size must accommodate header and tag"
);

const _: () = assert!(
    REPLAY_WINDOW_SIZE == 64,
    "replay window must be exactly 64 packets"
);

const _: () = assert!(
    SRTP_KEY_SIZE == 16,
    "AES-128 key must be 16 bytes"
);

const _: () = assert!(
    SRTP_SALT_SIZE == 12,
    "GCM salt must be 12 bytes"
);

const _: () = assert!(
    SRTP_AUTH_TAG_SIZE == 16,
    "GCM auth tag must be 16 bytes"
);

const _: () = assert!(
    RTP_HEADER_SIZE == 12,
    "RTP header must be 12 bytes minimum"
);

const _: () = assert!(
    RTCP_HEADER_SIZE == 8,
    "RTCP header must be 8 bytes minimum"
);

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(RTP_HEADER_SIZE, 12);
        assert_eq!(RTCP_HEADER_SIZE, 8);
        assert_eq!(SRTP_AUTH_TAG_SIZE, 16);
        assert_eq!(SRTP_SALT_SIZE, 12);
        assert_eq!(SRTP_KEY_SIZE, 16);
        assert_eq!(REPLAY_WINDOW_SIZE, 64);
    }

    #[test]
    fn test_srtcp_masks() {
        // E flag should be in bit 31
        assert_eq!(SRTCP_E_FLAG, 0x8000_0000);
        // Index uses lower 31 bits
        assert_eq!(SRTCP_INDEX_MASK, 0x7FFF_FFFF);
        // E flag and index should be complementary
        assert_eq!(SRTCP_E_FLAG | SRTCP_INDEX_MASK, 0xFFFF_FFFF);
    }
}
