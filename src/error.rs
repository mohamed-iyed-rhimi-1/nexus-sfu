//! Error types for Nexus SFU.
//!
//! All core error types are defined in `nexus-core` and re-exported
//! here for backward compatibility. The root crate extends `SfuError`
//! with additional variants for ICE and CRDT errors that depend on
//! crates outside nexus-core's dependency graph.
//!
//! # Error Categories
//!
//! - **Hot Path Errors**: Return `Option` or `Result`, never panic
//!   - Arena exhaustion → Return `None`, caller drops packet
//!   - Parse failure → Log and drop packet
//!   - Send failure → Increment counter, continue
//!
//! - **Control Path Errors**: Return `Result` with detailed error
//!   - Room operations → Return `RoomError`
//!   - Signaling → Return `SignalingError`
//!   - Configuration → Panic at startup (fail fast)

// Re-export all sub-error types from nexus-core.
// These are the single source of truth for error definitions.
pub use nexus_core::error::{
    TransportError,
    ParseError,
    RtpError,
    RtcpError,
    ArenaError,
    WorkerError,
    SignalingError,
    RoomError,
    SsrcError,
    ApiError,
    signaling_error_codes,
};

// Re-export the core SfuError for crates that only need
// the base variants (no ICE/CRDT).
pub use nexus_core::error::SfuError as CoreSfuError;

use thiserror::Error;

/// Top-level SFU error type for the root crate.
///
/// Extends `nexus_core::SfuError` with additional variants for
/// ICE and CRDT errors that depend on crates outside nexus-core.
#[derive(Debug, Error)]
pub enum SfuError {
    /// Transport layer error (UDP, io_uring, kqueue)
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// Packet parsing error (RTP, RTCP, JSON)
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// Room management error
    #[error("room error: {0}")]
    Room(#[from] RoomError),

    /// WebSocket signaling error
    #[error("signaling error: {0}")]
    Signaling(#[from] SignalingError),

    /// Packet arena error
    #[error("arena error: {0}")]
    Arena(#[from] ArenaError),

    /// Worker pool error
    #[error("worker error: {0}")]
    Worker(#[from] WorkerError),

    /// ICE error
    #[error("ICE error: {0}")]
    Ice(#[from] nexus_transport::ice::IceError),

    /// CRDT state management error
    #[error("CRDT error: {0}")]
    Crdt(#[from] nexus_state::error::CrdtError),

    /// API error
    #[error("api error: {0}")]
    Api(#[from] ApiError),
}

/// Allow converting a core SfuError into the root crate's SfuError.
/// This enables code that returns `nexus_core::SfuError` to be used
/// seamlessly in the root crate context.
impl From<CoreSfuError> for SfuError {
    fn from(err: CoreSfuError) -> Self {
        match err {
            CoreSfuError::Transport(e) => SfuError::Transport(e),
            CoreSfuError::Parse(e) => SfuError::Parse(e),
            CoreSfuError::Room(e) => SfuError::Room(e),
            CoreSfuError::Arena(e) => SfuError::Arena(e),
            CoreSfuError::Worker(e) => SfuError::Worker(e),
            CoreSfuError::Signaling(e) => SfuError::Signaling(e),
            CoreSfuError::Api(e) => SfuError::Api(e),
        }
    }
}

/// Helper to convert `serde_json::Error` into `ParseError`.
///
/// nexus-core stores JSON errors as strings to avoid pulling
/// serde_json into its dependency graph. Use this function
/// instead of a `From` impl (which would violate orphan rules).
pub fn json_parse_error(err: serde_json::Error) -> ParseError {
    ParseError::Json(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;

    #[test]
    fn test_sfu_error_display() {
        let err = SfuError::Arena(ArenaError::Exhausted {
            capacity_slots: 1000,
        });
        assert!(err.to_string().contains("exhausted"));
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_transport_error_display() {
        let addr: SocketAddr =
            "127.0.0.1:8080".parse().unwrap();
        let err = TransportError::BindFailed {
            addr,
            source: io::Error::new(
                io::ErrorKind::AddrInUse,
                "address in use",
            ),
        };
        assert!(err.to_string().contains("127.0.0.1:8080"));
    }

    #[test]
    fn test_rtp_error_display() {
        let err = RtpError::TooShort {
            actual_bytes: 8,
            min_bytes: 12,
        };
        assert!(err.to_string().contains("8"));
        assert!(err.to_string().contains("12"));

        let err = RtpError::InvalidVersion { version: 3 };
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn test_room_error_display() {
        let err = RoomError::RoomFull {
            room_id: 42,
            max_participants: 500,
        };
        assert!(err.to_string().contains("42"));
        assert!(err.to_string().contains("500"));
    }

    #[test]
    fn test_error_conversions() {
        // Test From implementations
        let rtp_err = RtpError::InvalidVersion { version: 1 };
        let parse_err: ParseError = rtp_err.into();
        let sfu_err: SfuError = parse_err.into();
        assert!(matches!(
            sfu_err,
            SfuError::Parse(ParseError::Rtp(_))
        ));
    }

    #[test]
    fn test_ssrc_error() {
        let err = SsrcError::AlreadyExists { ssrc: 12345 };
        assert!(err.to_string().contains("12345"));

        let err = SsrcError::NotFound { ssrc: 67890 };
        assert!(err.to_string().contains("67890"));
    }

    #[test]
    fn test_signaling_error_codes_unique() {
        use signaling_error_codes::*;
        assert_eq!(CONNECTION_FAILED, 1001);
        assert_eq!(INVALID_MESSAGE, 1002);
        assert_eq!(AUTH_FAILED, 1003);
        assert_eq!(ROOM_NOT_FOUND, 1004);
        assert_eq!(PARTICIPANT_NOT_FOUND, 1005);
        assert_eq!(SEND_FAILED, 1006);
        assert_eq!(CONNECTION_TIMEOUT, 1007);
        assert_eq!(CONNECTION_LIMIT, 1008);
        assert_eq!(QUEUE_FULL, 1009);
        assert_eq!(INVALID_STATE, 1010);
        assert_eq!(CONSENT_FAILED, 1011);
        assert_eq!(RECONNECT_EXHAUSTED, 1012);
        assert_eq!(VALIDATION_FAILED, 1013);
        assert_eq!(SERVER_NOT_RUNNING, 1014);
        assert_eq!(HEALTH_CHECK_FAILED, 1015);
    }

    #[test]
    fn test_signaling_error_code_method() {
        let err = SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        };
        assert_eq!(err.error_code(), 1008);

        let err = SignalingError::MessageQueueFull {
            connection_id: 42,
            queue_size: 1000,
        };
        assert_eq!(err.error_code(), 1009);

        let err = SignalingError::InvalidState {
            expected: "Running",
            actual: "Stopped",
        };
        assert_eq!(err.error_code(), 1010);

        let err = SignalingError::ConsentCheckFailed {
            connection_id: 123,
            elapsed_ms: 35_000,
        };
        assert_eq!(err.error_code(), 1011);
    }

    #[test]
    fn test_signaling_error_display_format() {
        let err = SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        };
        let msg = err.to_string();
        assert!(msg.starts_with("[E1008]"));
        assert!(msg.contains("10000"));

        let err = SignalingError::MessageQueueFull {
            connection_id: 42,
            queue_size: 1000,
        };
        let msg = err.to_string();
        assert!(msg.starts_with("[E1009]"));
        assert!(msg.contains("42"));
        assert!(msg.contains("1000"));

        let err = SignalingError::InvalidState {
            expected: "Running",
            actual: "Stopped",
        };
        let msg = err.to_string();
        assert!(msg.starts_with("[E1010]"));
        assert!(msg.contains("Running"));
        assert!(msg.contains("Stopped"));
    }

    #[test]
    fn test_signaling_error_is_recoverable() {
        assert!(SignalingError::ConnectionTimeout {
            connection_id: 1,
            timeout_ms: 5000,
        }
        .is_recoverable());
        assert!(SignalingError::SendFailed {
            connection_id: 1,
            reason: "test".into(),
        }
        .is_recoverable());
        assert!(SignalingError::MessageQueueFull {
            connection_id: 1,
            queue_size: 1000,
        }
        .is_recoverable());
        assert!(SignalingError::ConsentCheckFailed {
            connection_id: 1,
            elapsed_ms: 35000,
        }
        .is_recoverable());

        // Non-recoverable errors
        assert!(!SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        }
        .is_recoverable());
        assert!(!SignalingError::InvalidState {
            expected: "Running",
            actual: "Stopped",
        }
        .is_recoverable());
        assert!(!SignalingError::ReconnectionExhausted {
            connection_id: 1,
            attempts: 6,
            max_attempts: 6,
        }
        .is_recoverable());
    }

    #[test]
    fn test_signaling_error_is_resource_exhaustion() {
        assert!(SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        }
        .is_resource_exhaustion());
        assert!(SignalingError::MessageQueueFull {
            connection_id: 1,
            queue_size: 1000,
        }
        .is_resource_exhaustion());
        assert!(SignalingError::ReconnectionExhausted {
            connection_id: 1,
            attempts: 6,
            max_attempts: 6,
        }
        .is_resource_exhaustion());

        // Non-resource exhaustion errors
        assert!(!SignalingError::ConnectionTimeout {
            connection_id: 1,
            timeout_ms: 5000,
        }
        .is_resource_exhaustion());
        assert!(!SignalingError::InvalidMessage {
            reason: "test".into(),
        }
        .is_resource_exhaustion());
    }

    #[test]
    fn test_signaling_error_new_variants_display() {
        let err = SignalingError::ReconnectionExhausted {
            connection_id: 99,
            attempts: 6,
            max_attempts: 6,
        };
        let msg = err.to_string();
        assert!(msg.contains("[E1012]"));
        assert!(msg.contains("99"));
        assert!(msg.contains("6/6"));

        let err = SignalingError::ValidationFailed {
            field: "room_name",
            reason: "exceeds 256 chars",
        };
        let msg = err.to_string();
        assert!(msg.contains("[E1013]"));
        assert!(msg.contains("room_name"));
        assert!(msg.contains("256"));

        let err = SignalingError::ServerNotRunning {
            current_state: "Stopped",
        };
        let msg = err.to_string();
        assert!(msg.contains("[E1014]"));
        assert!(msg.contains("Stopped"));

        let err = SignalingError::HealthCheckFailed {
            reason: "no active workers",
        };
        let msg = err.to_string();
        assert!(msg.contains("[E1015]"));
        assert!(msg.contains("no active workers"));
    }

    #[test]
    fn test_core_sfu_error_conversion() {
        // Verify CoreSfuError can be converted to root SfuError
        let core_err = CoreSfuError::Arena(
            ArenaError::Exhausted { capacity_slots: 42 },
        );
        let root_err: SfuError = core_err.into();
        assert!(matches!(root_err, SfuError::Arena(_)));
    }

    #[test]
    fn test_serde_json_to_parse_error() {
        // Verify serde_json::Error converts to ParseError::Json
        // via the helper function
        let json_str = "not valid json";
        let json_err: Result<serde_json::Value, _> =
            serde_json::from_str(json_str);
        let parse_err =
            super::json_parse_error(json_err.unwrap_err());
        assert!(matches!(parse_err, ParseError::Json(_)));
    }
}
