//! TURN error types.
//!
//! Comprehensive error types for TURN operations following TigerStyle.

use std::net::SocketAddr;
use thiserror::Error;

/// TURN-specific errors.
#[derive(Debug, Error)]
pub enum TurnError {
    // ========== Allocation Errors ==========
    
    /// Allocation request failed.
    #[error("allocation failed: {reason}")]
    AllocationFailed {
        reason: &'static str,
    },
    
    /// Allocation not found.
    #[error("allocation not found")]
    AllocationNotFound,
    
    /// Allocation already exists.
    #[error("allocation already exists")]
    AllocationExists,
    
    /// Allocation expired.
    #[error("allocation expired")]
    AllocationExpired,
    
    /// Maximum allocations reached.
    #[error("maximum allocations reached: {count}/{max}")]
    MaxAllocationsReached {
        count: u32,
        max: u32,
    },
    
    // ========== Permission Errors ==========
    
    /// Permission denied.
    #[error("permission denied for peer {peer}")]
    PermissionDenied {
        peer: SocketAddr,
    },
    
    /// Permission creation failed.
    #[error("failed to create permission: {reason}")]
    PermissionFailed {
        reason: &'static str,
    },
    
    /// Maximum permissions reached.
    #[error("maximum permissions reached: {count}/{max}")]
    MaxPermissionsReached {
        count: u32,
        max: u32,
    },
    
    // ========== Channel Binding Errors ==========
    
    /// Channel binding failed.
    #[error("channel binding failed: {reason}")]
    ChannelBindFailed {
        reason: &'static str,
    },
    
    /// Invalid channel number.
    #[error("invalid channel number: {channel} (must be 0x4000-0x7FFF)")]
    InvalidChannelNumber {
        channel: u16,
    },
    
    /// Channel already bound.
    #[error("channel {channel} already bound to different peer")]
    ChannelAlreadyBound {
        channel: u16,
    },
    
    /// Peer already bound to different channel.
    #[error("peer {peer} already bound to channel {channel}")]
    PeerAlreadyBound {
        peer: SocketAddr,
        channel: u16,
    },
    
    /// Maximum channel bindings reached.
    #[error("maximum channel bindings reached: {count}/{max}")]
    MaxChannelBindingsReached {
        count: u32,
        max: u32,
    },
    
    // ========== Authentication Errors ==========
    
    /// Authentication required.
    #[error("authentication required")]
    AuthenticationRequired {
        realm: [u8; 128],
        realm_len: u8,
        nonce: [u8; 128],
        nonce_len: u8,
    },
    
    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,
    
    /// Invalid credentials.
    #[error("invalid credentials")]
    InvalidCredentials,
    
    /// Stale nonce.
    #[error("stale nonce, retry with new nonce")]
    StaleNonce {
        nonce: [u8; 128],
        nonce_len: u8,
    },
    
    // ========== Network Errors ==========
    
    /// Server unreachable.
    #[error("TURN server unreachable: {addr}")]
    ServerUnreachable {
        addr: SocketAddr,
    },
    
    /// Request timeout.
    #[error("request timeout after {timeout_ms}ms")]
    Timeout {
        timeout_ms: u32,
    },
    
    /// Send failed.
    #[error("send failed: {reason}")]
    SendFailed {
        reason: &'static str,
    },
    
    // ========== Protocol Errors ==========
    
    /// Invalid message.
    #[error("invalid TURN message: {reason}")]
    InvalidMessage {
        reason: &'static str,
    },
    
    /// Unexpected response.
    #[error("unexpected response: expected {expected}, got {actual}")]
    UnexpectedResponse {
        expected: &'static str,
        actual: &'static str,
    },
    
    /// Unsupported transport.
    #[error("unsupported transport: {transport}")]
    UnsupportedTransport {
        transport: u8,
    },
    
    /// Server error response.
    #[error("server error {code}: {reason}")]
    ServerError {
        code: u16,
        reason: &'static str,
    },
    
    // ========== State Errors ==========
    
    /// Invalid state for operation.
    #[error("invalid state: expected {expected}, actual {actual}")]
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },
    
    /// Client not initialized.
    #[error("TURN client not initialized")]
    NotInitialized,
    
    /// Already refreshing.
    #[error("refresh already in progress")]
    RefreshInProgress,
    
    // ========== Data Errors ==========
    
    /// Data too large.
    #[error("data too large: {size} bytes (max {max})")]
    DataTooLarge {
        size: usize,
        max: usize,
    },
    
    /// Buffer too small.
    #[error("buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        needed: usize,
        available: usize,
    },
}

impl TurnError {
    /// Create an AuthenticationRequired error.
    pub fn auth_required(realm: &[u8], nonce: &[u8]) -> Self {
        let mut realm_buf = [0u8; 128];
        let mut nonce_buf = [0u8; 128];
        
        let realm_len = realm.len().min(128);
        let nonce_len = nonce.len().min(128);
        
        realm_buf[..realm_len].copy_from_slice(&realm[..realm_len]);
        nonce_buf[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        
        Self::AuthenticationRequired {
            realm: realm_buf,
            realm_len: realm_len as u8,
            nonce: nonce_buf,
            nonce_len: nonce_len as u8,
        }
    }
    
    /// Create a StaleNonce error.
    pub fn stale_nonce(nonce: &[u8]) -> Self {
        let mut nonce_buf = [0u8; 128];
        let nonce_len = nonce.len().min(128);
        nonce_buf[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        
        Self::StaleNonce {
            nonce: nonce_buf,
            nonce_len: nonce_len as u8,
        }
    }
    
    /// Map STUN error code to TurnError.
    pub fn from_error_code(code: u16, _reason: &[u8]) -> Self {
        match code {
            401 => Self::AuthenticationFailed,
            403 => Self::PermissionFailed { reason: "forbidden" },
            420 => Self::InvalidMessage { reason: "unknown attribute" },
            437 => Self::AllocationFailed { reason: "allocation mismatch" },
            438 => Self::StaleNonce { 
                nonce: [0u8; 128], 
                nonce_len: 0,
            },
            441 => Self::InvalidCredentials,
            442 => Self::UnsupportedTransport { transport: 0 },
            486 => Self::MaxAllocationsReached { count: 0, max: 0 },
            500 => Self::ServerError { code: 500, reason: "server error" },
            508 => Self::ServerError { code: 508, reason: "insufficient capacity" },
            _ => Self::ServerError { 
                code, 
                reason: "unknown error",
            },
        }
    }
    
    /// Returns true if this error requires re-authentication.
    pub fn requires_reauth(&self) -> bool {
        matches!(self, 
            Self::AuthenticationRequired { .. } | 
            Self::StaleNonce { .. } |
            Self::AuthenticationFailed
        )
    }
    
    /// Returns true if this error is retriable.
    pub fn is_retriable(&self) -> bool {
        matches!(self,
            Self::Timeout { .. } |
            Self::StaleNonce { .. } |
            Self::ServerError { code: 500, .. }
        )
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
        let err = TurnError::AllocationFailed { reason: "quota exceeded" };
        assert!(err.to_string().contains("quota exceeded"));
        
        let err = TurnError::InvalidChannelNumber { channel: 0x1000 };
        // 0x1000 = 4096 in decimal
        assert!(err.to_string().contains("4096"));
    }

    #[test]
    fn test_from_error_code() {
        let err = TurnError::from_error_code(401, b"Unauthorized");
        assert!(matches!(err, TurnError::AuthenticationFailed));
        
        let err = TurnError::from_error_code(486, b"Allocation Quota Reached");
        assert!(matches!(err, TurnError::MaxAllocationsReached { .. }));
    }

    #[test]
    fn test_requires_reauth() {
        let err = TurnError::AuthenticationFailed;
        assert!(err.requires_reauth());
        
        let err = TurnError::AllocationFailed { reason: "test" };
        assert!(!err.requires_reauth());
    }

    #[test]
    fn test_is_retriable() {
        let err = TurnError::Timeout { timeout_ms: 5000 };
        assert!(err.is_retriable());
        
        let err = TurnError::InvalidCredentials;
        assert!(!err.is_retriable());
    }

    #[test]
    fn test_auth_required_helper() {
        let err = TurnError::auth_required(b"example.com", b"abc123");
        if let TurnError::AuthenticationRequired { realm, realm_len, nonce, nonce_len } = err {
            assert_eq!(realm_len, 11);
            assert_eq!(&realm[..11], b"example.com");
            assert_eq!(nonce_len, 6);
            assert_eq!(&nonce[..6], b"abc123");
        } else {
            panic!("wrong error type");
        }
    }
}
