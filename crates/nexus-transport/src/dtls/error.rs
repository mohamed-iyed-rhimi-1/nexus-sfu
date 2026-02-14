//! DTLS Error Types.
//!
//! Error types for DTLS operations.
//!
//! # TigerStyle Compliance
//!
//! - All error cases are explicit
//! - No silent failures
//! - Descriptive error messages

use thiserror::Error;

/// DTLS Error.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Record too short.
    #[error("record too short: {actual} bytes, minimum {min}")]
    RecordTooShort {
        actual: usize,
        min: usize,
    },

    /// Invalid record type.
    #[error("invalid record content type: {0}")]
    InvalidContentType(u8),

    /// Invalid handshake type.
    #[error("invalid handshake type: {0}")]
    InvalidHandshakeType(u8),

    /// Invalid protocol version.
    #[error("invalid DTLS version: 0x{0:04X}")]
    InvalidVersion(u16),

    /// Handshake failure.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Unexpected message.
    #[error("unexpected message: expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    
    /// Invalid state for operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Invalid certificate.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Decryption error.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Encryption error.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Unsupported cipher suite.
    #[error("unsupported cipher suite: 0x{0:04X}")]
    UnsupportedCipherSuite(u16),

    /// Unsupported SRTP profile.
    #[error("unsupported SRTP profile: 0x{0:04X}")]
    UnsupportedSrtpProfile(u16),

    /// Session not established.
    #[error("session not established")]
    NotEstablished,

    /// Session expired.
    #[error("session expired")]
    Expired,
    
    /// Handshake timeout (30 seconds exceeded).
    #[error("handshake timeout: exceeded 30 seconds")]
    HandshakeTimeout,

    /// Buffer too small.
    #[error("buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        needed: usize,
        available: usize,
    },

    /// Sequence number overflow.
    #[error("sequence number overflow")]
    SequenceOverflow,

    /// Retransmission limit exceeded.
    #[error("retransmission limit exceeded")]
    RetransmissionLimitExceeded,

    /// Alert received.
    #[error("alert received: level={level}, description={description}")]
    AlertReceived {
        level: u8,
        description: u8,
    },

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl DtlsError {
    /// Create handshake failed error.
    #[inline]
    pub fn handshake_failed(msg: impl Into<String>) -> Self {
        Self::HandshakeFailed(msg.into())
    }

    /// Create invalid certificate error.
    #[inline]
    pub fn invalid_certificate(msg: impl Into<String>) -> Self {
        Self::InvalidCertificate(msg.into())
    }

    /// Create verification failed error.
    #[inline]
    pub fn verification_failed(msg: impl Into<String>) -> Self {
        Self::VerificationFailed(msg.into())
    }
    
    /// Create invalid state error.
    #[inline]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::InvalidState(msg.into())
    }
    
    /// Create signature verification failed error.
    #[inline]
    pub fn signature_verification_failed(msg: impl Into<String>) -> Self {
        Self::SignatureVerificationFailed(msg.into())
    }
    
    /// Returns true if this is a fatal error (session should be terminated).
    #[inline]
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::HandshakeTimeout
                | Self::RetransmissionLimitExceeded
                | Self::DecryptionFailed
                | Self::SignatureVerificationFailed(_)
                | Self::InvalidCertificate(_)
        )
    }
    
    /// Returns true if this error is recoverable (can retry).
    #[inline]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::RecordTooShort { .. }
                | Self::BufferTooSmall { .. }
        )
    }
}
