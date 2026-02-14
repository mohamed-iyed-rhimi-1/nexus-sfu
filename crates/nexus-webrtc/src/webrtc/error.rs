//! WebRTC transport error types.

use core::fmt;

/// WebRTC transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcError {
    /// Transport not initialized.
    NotInitialized,
    
    /// Transport already started.
    AlreadyStarted,
    
    /// Invalid transport state for operation.
    InvalidState,
    
    /// ICE gathering failed.
    IceGatheringFailed,
    
    /// ICE connection failed.
    IceConnectionFailed,
    
    /// ICE connection timed out.
    IceTimeout,
    
    /// No valid ICE candidate pair.
    NoValidCandidatePair,
    
    /// DTLS handshake failed.
    DtlsHandshakeFailed,
    
    /// DTLS handshake timed out.
    DtlsTimeout,
    
    /// DTLS certificate verification failed.
    DtlsCertificateInvalid,
    
    /// DTLS fingerprint mismatch.
    DtlsFingerprintMismatch,
    
    /// SRTP initialization failed.
    SrtpInitFailed,
    
    /// SRTP protection failed.
    SrtpProtectFailed,
    
    /// SRTP unprotection failed (auth/decrypt).
    SrtpUnprotectFailed,
    
    /// Replay attack detected.
    ReplayDetected,
    
    /// Packet too short.
    PacketTooShort,
    
    /// Packet too large.
    PacketTooLarge,
    
    /// Invalid packet format.
    InvalidPacket,
    
    /// Unknown packet type.
    UnknownPacketType,
    
    /// Buffer too small.
    BufferTooSmall,
    
    /// Send failed.
    SendFailed,
    
    /// Receive failed.
    ReceiveFailed,
    
    /// Transport closed.
    Closed,
    
    /// Maximum candidates exceeded.
    TooManyCandidates,
    
    /// Maximum sessions exceeded.
    TooManySessions,
    
    /// Address mismatch (source address doesn't match expected remote).
    AddressMismatch,
    
    /// Malformed packet (failed validation).
    MalformedPacket,
    
    /// Invalid configuration.
    InvalidConfig,
    
    /// Internal error.
    Internal,
}

impl fmt::Display for WebRtcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "transport not initialized"),
            Self::AlreadyStarted => write!(f, "transport already started"),
            Self::InvalidState => write!(f, "invalid transport state"),
            Self::IceGatheringFailed => write!(f, "ICE gathering failed"),
            Self::IceConnectionFailed => write!(f, "ICE connection failed"),
            Self::IceTimeout => write!(f, "ICE connection timeout"),
            Self::NoValidCandidatePair => write!(f, "no valid ICE candidate pair"),
            Self::DtlsHandshakeFailed => write!(f, "DTLS handshake failed"),
            Self::DtlsTimeout => write!(f, "DTLS handshake timeout"),
            Self::DtlsCertificateInvalid => write!(f, "DTLS certificate invalid"),
            Self::DtlsFingerprintMismatch => write!(f, "DTLS fingerprint mismatch"),
            Self::SrtpInitFailed => write!(f, "SRTP initialization failed"),
            Self::SrtpProtectFailed => write!(f, "SRTP protect failed"),
            Self::SrtpUnprotectFailed => write!(f, "SRTP unprotect failed"),
            Self::ReplayDetected => write!(f, "replay attack detected"),
            Self::PacketTooShort => write!(f, "packet too short"),
            Self::PacketTooLarge => write!(f, "packet too large"),
            Self::InvalidPacket => write!(f, "invalid packet"),
            Self::UnknownPacketType => write!(f, "unknown packet type"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::SendFailed => write!(f, "send failed"),
            Self::ReceiveFailed => write!(f, "receive failed"),
            Self::Closed => write!(f, "transport closed"),
            Self::TooManyCandidates => write!(f, "too many ICE candidates"),
            Self::TooManySessions => write!(f, "too many sessions"),
            Self::AddressMismatch => write!(f, "source address mismatch"),
            Self::MalformedPacket => write!(f, "malformed packet"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
            Self::Internal => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for WebRtcError {}

// Convert from component errors
impl From<nexus_transport::ice::IceError> for WebRtcError {
    fn from(e: nexus_transport::ice::IceError) -> Self {
        use nexus_transport::ice::IceError;
        match e {
            IceError::StunTimeout { .. } => Self::IceTimeout,
            IceError::TooManyCandidates { .. } => Self::TooManyCandidates,
            IceError::NoCandidates => Self::NoValidCandidatePair,
            _ => Self::IceConnectionFailed,
        }
    }
}

impl From<nexus_transport::dtls::DtlsError> for WebRtcError {
    fn from(e: nexus_transport::dtls::DtlsError) -> Self {
        use nexus_transport::dtls::DtlsError;
        match e {
            DtlsError::HandshakeFailed(_) => Self::DtlsHandshakeFailed,
            DtlsError::RetransmissionLimitExceeded => Self::DtlsTimeout,
            DtlsError::InvalidCertificate(_) => Self::DtlsCertificateInvalid,
            DtlsError::VerificationFailed(_) => Self::DtlsFingerprintMismatch,
            _ => Self::DtlsHandshakeFailed,
        }
    }
}

impl From<nexus_transport::srtp::SrtpError> for WebRtcError {
    fn from(e: nexus_transport::srtp::SrtpError) -> Self {
        match e {
            nexus_transport::srtp::SrtpError::ReplayDetected => Self::ReplayDetected,
            nexus_transport::srtp::SrtpError::AuthenticationFailed => Self::SrtpUnprotectFailed,
            nexus_transport::srtp::SrtpError::EncryptionFailed => Self::SrtpProtectFailed,
            nexus_transport::srtp::SrtpError::DecryptionFailed => Self::SrtpUnprotectFailed,
            _ => Self::SrtpUnprotectFailed,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(WebRtcError::IceTimeout.to_string(), "ICE connection timeout");
        assert_eq!(WebRtcError::DtlsHandshakeFailed.to_string(), "DTLS handshake failed");
        assert_eq!(WebRtcError::ReplayDetected.to_string(), "replay attack detected");
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(WebRtcError::IceTimeout, WebRtcError::IceTimeout);
        assert_ne!(WebRtcError::IceTimeout, WebRtcError::DtlsTimeout);
    }
}
