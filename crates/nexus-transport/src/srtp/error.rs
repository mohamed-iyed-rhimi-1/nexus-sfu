//! SRTP error types.
//!
//! Explicit error handling following NASA Power of 10 Rule #5.

use core::fmt;

/// SRTP operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpError {
    /// Packet too short to be valid RTP/RTCP.
    PacketTooShort,
    
    /// Packet exceeds maximum allowed size.
    PacketTooLarge,
    
    /// Invalid RTP header.
    InvalidRtpHeader,
    
    /// Invalid RTCP header.
    InvalidRtcpHeader,
    
    /// Authentication failed (tag mismatch).
    AuthenticationFailed,
    
    /// Encryption failed.
    EncryptionFailed,
    
    /// Decryption failed.
    DecryptionFailed,
    
    /// Replay attack detected.
    ReplayDetected,
    
    /// Key derivation failed.
    KeyDerivationFailed,
    
    /// Invalid key material.
    InvalidKeyMaterial,
    
    /// Context not initialized.
    NotInitialized,
    
    /// Buffer too small for output.
    BufferTooSmall,
    
    /// Invalid SSRC.
    InvalidSsrc,
    
    /// Rollover counter overflow.
    RocOverflow,
    
    /// SRTCP index overflow.
    SrtcpIndexOverflow,
    
    /// Unsupported cipher suite.
    UnsupportedCipherSuite,
    
    /// Invalid protection profile.
    InvalidProfile,
    
    /// Session pool at capacity.
    SessionLimitReached,
    
    /// Duplicate session for SSRC.
    DuplicateSession,
    
    /// Invalid buffer length.
    InvalidBufferLength,
    
    /// Nonce generation failed.
    NonceGenerationFailed,
}

impl fmt::Display for SrtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "packet too short"),
            Self::PacketTooLarge => write!(f, "packet too large"),
            Self::InvalidRtpHeader => write!(f, "invalid RTP header"),
            Self::InvalidRtcpHeader => write!(f, "invalid RTCP header"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::ReplayDetected => write!(f, "replay detected"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::InvalidKeyMaterial => write!(f, "invalid key material"),
            Self::NotInitialized => write!(f, "context not initialized"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidSsrc => write!(f, "invalid SSRC"),
            Self::RocOverflow => write!(f, "ROC overflow"),
            Self::SrtcpIndexOverflow => write!(f, "SRTCP index overflow"),
            Self::UnsupportedCipherSuite => write!(f, "unsupported cipher suite"),
            Self::InvalidProfile => write!(f, "invalid protection profile"),
            Self::SessionLimitReached => write!(f, "session limit reached"),
            Self::DuplicateSession => write!(f, "duplicate session"),
            Self::InvalidBufferLength => write!(f, "invalid buffer length"),
            Self::NonceGenerationFailed => write!(f, "nonce generation failed"),
        }
    }
}

impl std::error::Error for SrtpError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(SrtpError::PacketTooShort.to_string(), "packet too short");
        assert_eq!(SrtpError::AuthenticationFailed.to_string(), "authentication failed");
        assert_eq!(SrtpError::ReplayDetected.to_string(), "replay detected");
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(SrtpError::PacketTooShort, SrtpError::PacketTooShort);
        assert_ne!(SrtpError::PacketTooShort, SrtpError::PacketTooLarge);
    }

    #[test]
    fn test_error_clone() {
        let e1 = SrtpError::ReplayDetected;
        let e2 = e1;
        assert_eq!(e1, e2);
    }
}
