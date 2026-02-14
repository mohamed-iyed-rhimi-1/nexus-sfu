//! SDP error types.

use thiserror::Error;

/// SDP parsing and generation errors.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SdpError {
    /// Invalid SDP format.
    #[error("invalid SDP format: {reason}")]
    InvalidFormat { reason: &'static str },
    
    /// Missing required field.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
    
    /// Invalid version.
    #[error("invalid SDP version: {version}")]
    InvalidVersion { version: u8 },
    
    /// Invalid media type.
    #[error("invalid media type: {media_type}")]
    InvalidMediaType { media_type: String },
    
    /// Invalid transport protocol.
    #[error("invalid transport: {transport}")]
    InvalidTransport { transport: String },
    
    /// Invalid attribute.
    #[error("invalid attribute: {name}={value}")]
    InvalidAttribute { name: String, value: String },
    
    /// Too many media sections.
    #[error("too many media sections: {count} > {max}")]
    TooManyMedia { count: usize, max: usize },
    
    /// Too many codecs.
    #[error("too many codecs: {count} > {max}")]
    TooManyCodecs { count: usize, max: usize },
    
    /// Too many candidates.
    #[error("too many ICE candidates: {count} > {max}")]
    TooManyCandidates { count: usize, max: usize },
    
    /// Invalid ICE candidate.
    #[error("invalid ICE candidate: {reason}")]
    InvalidCandidate { reason: &'static str },
    
    /// Invalid DTLS fingerprint.
    #[error("invalid DTLS fingerprint: {reason}")]
    InvalidFingerprint { reason: &'static str },
    
    /// Invalid connection info.
    #[error("invalid connection info: {reason}")]
    InvalidConnection { reason: &'static str },
    
    /// Parse error.
    #[error("parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },
    
    /// SDP too large.
    #[error("SDP too large: {size} > {max}")]
    TooLarge { size: usize, max: usize },
    
    /// Unsupported feature.
    #[error("unsupported feature: {feature}")]
    Unsupported { feature: &'static str },

    /// Missing required ICE credentials.
    #[error("missing required ICE credentials: {field}")]
    MissingIceCredentials { field: &'static str },

    /// Missing required DTLS fingerprint.
    #[error("missing required DTLS fingerprint")]
    MissingFingerprint,

    /// Invalid ICE credential length.
    #[error("invalid ICE credential length: {field} has {actual} bytes, expected {min}-{max}")]
    InvalidIceCredentialLength {
        field: &'static str,
        actual: usize,
        min: usize,
        max: usize,
    },

    /// Unsupported fingerprint algorithm (only SHA-256 allowed).
    #[error("unsupported fingerprint algorithm: {algorithm}, only sha-256 allowed")]
    UnsupportedFingerprintAlgorithm { algorithm: String },

    /// BUNDLE group inconsistency.
    #[error("BUNDLE group references non-existent MID: {mid}")]
    InvalidBundleGroup { mid: String },

    /// Codec negotiation failure.
    #[error("no common codec found for media type: {media_type}")]
    NoCommonCodec { media_type: String },
}

impl SdpError {
    /// Check if this is a recoverable error.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, 
            SdpError::InvalidAttribute { .. } |
            SdpError::InvalidCandidate { .. }
        )
    }

    /// Get numeric error code for logging/metrics.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit error codes for monitoring
    /// - Bounded range 1000-1999 for SDP errors
    pub fn error_code(&self) -> u16 {
        match self {
            SdpError::InvalidFormat { .. } => 1001,
            SdpError::MissingField { .. } => 1002,
            SdpError::InvalidVersion { .. } => 1003,
            SdpError::InvalidMediaType { .. } => 1004,
            SdpError::InvalidTransport { .. } => 1005,
            SdpError::InvalidAttribute { .. } => 1006,
            SdpError::TooManyMedia { .. } => 1007,
            SdpError::TooManyCodecs { .. } => 1008,
            SdpError::TooManyCandidates { .. } => 1009,
            SdpError::InvalidCandidate { .. } => 1010,
            SdpError::InvalidFingerprint { .. } => 1011,
            SdpError::InvalidConnection { .. } => 1012,
            SdpError::ParseError { .. } => 1013,
            SdpError::TooLarge { .. } => 1014,
            SdpError::Unsupported { .. } => 1015,
            SdpError::MissingIceCredentials { .. } => 1016,
            SdpError::MissingFingerprint => 1017,
            SdpError::InvalidIceCredentialLength { .. } => 1018,
            SdpError::UnsupportedFingerprintAlgorithm { .. } => 1019,
            SdpError::InvalidBundleGroup { .. } => 1020,
            SdpError::NoCommonCodec { .. } => 1021,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SdpError::MissingField { field: "o=" };
        assert!(err.to_string().contains("o="));
    }

    #[test]
    fn test_is_recoverable() {
        let err = SdpError::InvalidAttribute { 
            name: "foo".to_string(), 
            value: "bar".to_string() 
        };
        assert!(err.is_recoverable());
        
        let err = SdpError::InvalidVersion { version: 1 };
        assert!(!err.is_recoverable());
    }
}
