//! ICE Error Types.
//!
//! Comprehensive error types for ICE operations following TigerStyle:
//! - Explicit error variants with context
//! - No dynamic allocation in error paths
//! - Detailed error messages for debugging

use std::net::SocketAddr;

/// ICE-specific errors.
///
/// All error variants include sufficient context for debugging
/// without requiring dynamic allocation.
#[derive(Debug, thiserror::Error)]
pub enum IceError {
    // ========== STUN Errors ==========
    
    /// STUN message too short to parse.
    #[error("STUN message too short: {actual_bytes} bytes, minimum {min_bytes} bytes")]
    StunTooShort {
        actual_bytes: u32,
        min_bytes: u32,
    },

    /// Invalid STUN message header.
    #[error("invalid STUN header: first two bits must be 0")]
    StunInvalidHeader,

    /// Invalid STUN magic cookie.
    #[error("invalid STUN magic cookie: expected 0x2112A442, got 0x{actual:08X}")]
    StunInvalidMagicCookie {
        actual: u32,
    },

    /// Unknown STUN method.
    #[error("unknown STUN method: 0x{method:04X}")]
    StunUnknownMethod {
        method: u16,
    },

    /// Invalid STUN attribute.
    #[error("invalid STUN attribute type 0x{attr_type:04X}: {reason}")]
    StunInvalidAttribute {
        attr_type: u16,
        reason: &'static str,
    },

    /// STUN MESSAGE-INTEGRITY verification failed.
    #[error("STUN MESSAGE-INTEGRITY verification failed")]
    StunIntegrityFailed,

    /// STUN FINGERPRINT verification failed.
    #[error("STUN FINGERPRINT verification failed: expected 0x{expected:08X}, got 0x{actual:08X}")]
    StunFingerprintFailed {
        expected: u32,
        actual: u32,
    },

    /// STUN transaction timeout.
    #[error("STUN transaction timeout after {timeout_ms} ms")]
    StunTimeout {
        timeout_ms: u32,
    },

    /// STUN error response received.
    #[error("STUN error response: {code} {reason}")]
    StunErrorResponse {
        code: u16,
        reason: &'static str,
    },

    // ========== ICE Errors ==========

    /// Too many candidates.
    #[error("too many candidates: {count} exceeds maximum {max}")]
    TooManyCandidates {
        count: u32,
        max: u32,
    },

    /// Too many candidate pairs.
    #[error("too many candidate pairs: {count} exceeds maximum {max}")]
    TooManyPairs {
        count: u32,
        max: u32,
    },

    /// Invalid candidate SDP.
    #[error("invalid candidate SDP: {reason}")]
    InvalidCandidateSdp {
        reason: &'static str,
    },

    /// ICE connectivity check failed.
    #[error("connectivity check failed for pair {local_addr} -> {remote_addr}")]
    ConnectivityCheckFailed {
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },

    /// ICE role conflict.
    #[error("ICE role conflict: both agents have same role")]
    RoleConflict,

    /// No valid candidate pairs.
    #[error("no valid candidate pairs found")]
    NoPairs,

    /// ICE failed to connect.
    #[error("ICE failed: all candidate pairs exhausted")]
    Failed,

    /// Invalid ICE state transition.
    #[error("invalid ICE state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: super::IceConnectionState,
        to: super::IceConnectionState,
    },

    /// Remote credentials not set.
    #[error("remote ICE credentials not set")]
    NoRemoteCredentials,

    /// No candidates available.
    #[error("no candidates available")]
    NoCandidates,

    /// Invalid candidate.
    #[error("invalid candidate: {reason}")]
    InvalidCandidate {
        reason: &'static str,
    },

    /// Invalid state for operation.
    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },

    /// Candidate gathering failed.
    #[error("candidate gathering failed: {reason}")]
    GatheringFailed {
        reason: &'static str,
    },

    // ========== Transport Errors ==========

    /// Socket bind failed.
    #[error("failed to bind socket to {addr}: {reason}")]
    BindFailed {
        addr: SocketAddr,
        reason: &'static str,
    },

    /// Socket send failed.
    #[error("failed to send to {addr}: {reason}")]
    SendFailed {
        addr: SocketAddr,
        reason: &'static str,
    },

    /// Socket receive failed.
    #[error("failed to receive: {reason}")]
    RecvFailed {
        reason: &'static str,
    },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl IceError {
    /// Returns true if this error is recoverable.
    ///
    /// Recoverable errors may succeed on retry.
    #[inline]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::StunTimeout { .. }
            | Self::ConnectivityCheckFailed { .. }
            | Self::SendFailed { .. }
            | Self::RecvFailed { .. }
        )
    }

    /// Returns true if this is a STUN protocol error.
    #[inline]
    pub const fn is_stun_error(&self) -> bool {
        matches!(
            self,
            Self::StunTooShort { .. }
            | Self::StunInvalidHeader
            | Self::StunInvalidMagicCookie { .. }
            | Self::StunUnknownMethod { .. }
            | Self::StunInvalidAttribute { .. }
            | Self::StunIntegrityFailed
            | Self::StunFingerprintFailed { .. }
            | Self::StunTimeout { .. }
            | Self::StunErrorResponse { .. }
        )
    }
}

// Conversion to SfuError is handled by #[from] in SfuError::Ice

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_recoverable() {
        let timeout = IceError::StunTimeout { timeout_ms: 500 };
        assert!(timeout.is_recoverable());

        let failed = IceError::Failed;
        assert!(!failed.is_recoverable());
    }

    #[test]
    fn test_error_is_stun_error() {
        let stun_err = IceError::StunInvalidHeader;
        assert!(stun_err.is_stun_error());

        let ice_err = IceError::NoPairs;
        assert!(!ice_err.is_stun_error());
    }

    #[test]
    fn test_error_display() {
        let err = IceError::StunTooShort {
            actual_bytes: 10,
            min_bytes: 20,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("20"));
    }
}
