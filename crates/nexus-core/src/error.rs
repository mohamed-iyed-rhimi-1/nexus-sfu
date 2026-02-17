//! Unified error hierarchy for the Nexus SFU system.
//!
//! Every error variant carries context describing what went wrong
//! and where. No silent failures — all errors are explicit.
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

use std::fmt;
use std::io;
use std::net::SocketAddr;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Top-level SFU error
// ---------------------------------------------------------------------------

/// Top-level SFU error type.
///
/// Wraps all domain-specific errors for unified error handling.
/// Downstream crates may extend this with additional variants
/// via wrapper enums in their own error modules.
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

    /// Packet arena error
    #[error("arena error: {0}")]
    Arena(#[from] ArenaError),

    /// Worker pool error
    #[error("worker error: {0}")]
    Worker(#[from] WorkerError),

    /// WebSocket signaling error
    #[error("signaling error: {0}")]
    Signaling(#[from] SignalingError),

    /// API error
    #[error("api error: {0}")]
    Api(#[from] ApiError),
}

// ---------------------------------------------------------------------------
// Transport layer errors
// ---------------------------------------------------------------------------

/// Transport layer errors.
///
/// Covers UDP socket operations, io_uring (Linux), and kqueue (macOS).
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to bind socket to address
    #[error("failed to bind to {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },

    /// Failed to receive packets
    #[error("receive failed: {source}")]
    RecvFailed {
        #[source]
        source: io::Error,
    },

    /// Failed to send packet to destination
    #[error("send to {dest} failed: {source}")]
    SendFailed {
        dest: SocketAddr,
        #[source]
        source: io::Error,
    },

    /// Socket buffer exhausted
    #[error("buffer exhausted")]
    BufferExhausted,

    /// io_uring submission queue full (Linux only)
    #[error("io_uring submission queue full")]
    IoUringQueueFull,

    /// io_uring initialization failed (Linux only)
    #[error("io_uring initialization failed: {message}")]
    IoUringInitFailed {
        message: String,
    },

    /// Configuration error
    #[error("configuration error: {message}")]
    ConfigError {
        message: String,
    },

    /// Failed to set socket option
    #[error("failed to set socket option: {source}")]
    SetSockOptFailed {
        #[source]
        source: io::Error,
    },
}

// ---------------------------------------------------------------------------
// Packet parsing errors
// ---------------------------------------------------------------------------

/// Packet parsing errors.
///
/// Covers RTP, RTCP, and JSON message parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    /// RTP packet parsing error
    #[error("RTP parse error: {0}")]
    Rtp(#[from] RtpError),

    /// RTCP packet parsing error
    #[error("RTCP parse error: {0}")]
    Rtcp(#[from] RtcpError),

    /// JSON message parsing error (stored as string to avoid
    /// pulling serde_json into nexus-core's required deps)
    #[error("JSON parse error: {0}")]
    Json(String),
}

// ---------------------------------------------------------------------------
// RTP parsing errors
// ---------------------------------------------------------------------------

/// RTP packet parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpError {
    /// Packet too short to contain RTP header
    TooShort {
        actual_bytes: usize,
        min_bytes: usize,
    },

    /// Invalid RTP version (must be 2)
    InvalidVersion { version: u8 },

    /// CSRC count exceeds available bytes
    InvalidCsrcCount {
        count: u8,
        available_bytes: usize,
    },

    /// Invalid header extension
    InvalidExtension,

    /// Invalid padding (last byte is 0 or exceeds payload)
    InvalidPadding {
        padding_len: u8,
        available_bytes: usize,
    },
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpError::TooShort {
                actual_bytes,
                min_bytes,
            } => {
                write!(
                    f,
                    "packet too short: {} bytes, need at least {}",
                    actual_bytes, min_bytes
                )
            }
            RtpError::InvalidVersion { version } => {
                write!(
                    f,
                    "invalid RTP version: {}, expected 2",
                    version
                )
            }
            RtpError::InvalidCsrcCount {
                count,
                available_bytes,
            } => {
                write!(
                    f,
                    "CSRC count {} exceeds available {} bytes",
                    count, available_bytes
                )
            }
            RtpError::InvalidExtension => {
                write!(f, "invalid header extension")
            }
            RtpError::InvalidPadding {
                padding_len,
                available_bytes,
            } => {
                write!(
                    f,
                    "invalid padding: padding_len {} exceeds available {} bytes",
                    padding_len, available_bytes
                )
            }
        }
    }
}

impl std::error::Error for RtpError {}

// ---------------------------------------------------------------------------
// RTCP parsing errors
// ---------------------------------------------------------------------------

/// RTCP packet parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpError {
    /// Packet too short to contain RTCP header
    TooShort {
        actual_bytes: usize,
        min_bytes: usize,
    },

    /// Invalid RTCP version (must be 2)
    InvalidVersion { version: u8 },

    /// Invalid packet type
    InvalidPacketType { packet_type: u8 },

    /// Invalid report block count
    InvalidReportCount {
        count: u8,
        available_bytes: usize,
    },
}

impl fmt::Display for RtcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtcpError::TooShort {
                actual_bytes,
                min_bytes,
            } => {
                write!(
                    f,
                    "packet too short: {} bytes, need at least {}",
                    actual_bytes, min_bytes
                )
            }
            RtcpError::InvalidVersion { version } => {
                write!(
                    f,
                    "invalid RTCP version: {}, expected 2",
                    version
                )
            }
            RtcpError::InvalidPacketType { packet_type } => {
                write!(
                    f,
                    "invalid RTCP packet type: {}",
                    packet_type
                )
            }
            RtcpError::InvalidReportCount {
                count,
                available_bytes,
            } => {
                write!(
                    f,
                    "report count {} exceeds available {} bytes",
                    count, available_bytes
                )
            }
        }
    }
}

impl std::error::Error for RtcpError {}

// ---------------------------------------------------------------------------
// Arena errors
// ---------------------------------------------------------------------------

/// Packet arena errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaError {
    /// Arena free list exhausted
    Exhausted { capacity_slots: u32 },

    /// Invalid slot index
    InvalidSlot { index: u32, capacity_slots: u32 },

    /// Memory mapping failed
    MmapFailed,
}

impl fmt::Display for ArenaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArenaError::Exhausted { capacity_slots } => {
                write!(
                    f,
                    "arena exhausted: all {} slots in use",
                    capacity_slots
                )
            }
            ArenaError::InvalidSlot {
                index,
                capacity_slots,
            } => {
                write!(
                    f,
                    "invalid slot index {}, capacity is {}",
                    index, capacity_slots
                )
            }
            ArenaError::MmapFailed => {
                write!(f, "memory mapping failed")
            }
        }
    }
}

impl std::error::Error for ArenaError {}

// ---------------------------------------------------------------------------
// Worker pool errors
// ---------------------------------------------------------------------------

/// Worker pool errors.
#[derive(Debug)]
pub enum WorkerError {
    /// Worker channel is full
    ChannelFull { worker_id: u32 },

    /// Worker thread panicked
    WorkerPanicked { worker_id: u32, message: String },

    /// Shutdown timed out
    ShutdownTimeout { timeout_ms: u64 },

    /// Failed to pin worker to CPU core
    AffinityFailed { worker_id: u32, core_id: u32 },

    /// Invalid worker configuration
    InvalidConfig { message: String },
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::ChannelFull { worker_id } => {
                write!(f, "worker {} channel full", worker_id)
            }
            WorkerError::WorkerPanicked {
                worker_id,
                message,
            } => {
                write!(
                    f,
                    "worker {} panicked: {}",
                    worker_id, message
                )
            }
            WorkerError::ShutdownTimeout { timeout_ms } => {
                write!(
                    f,
                    "shutdown timed out after {}ms",
                    timeout_ms
                )
            }
            WorkerError::AffinityFailed {
                worker_id,
                core_id,
            } => {
                write!(
                    f,
                    "failed to pin worker {} to core {}",
                    worker_id, core_id
                )
            }
            WorkerError::InvalidConfig { message } => {
                write!(f, "invalid worker config: {}", message)
            }
        }
    }
}

impl std::error::Error for WorkerError {}

// ---------------------------------------------------------------------------
// Signaling errors
// ---------------------------------------------------------------------------

/// WebSocket signaling errors.
///
/// Error codes are explicit and unique per NASA's Power of 10 Rule 6.
/// All values use explicit u32/u64 types for bounded error reporting.
#[derive(Debug)]
pub enum SignalingError {
    /// WebSocket connection failed — Error code: 1001
    ConnectionFailed { source: io::Error },

    /// Invalid signaling message — Error code: 1002
    InvalidMessage { reason: String },

    /// Authentication failed — Error code: 1003
    AuthenticationFailed { participant_name: String },

    /// Room not found — Error code: 1004
    RoomNotFound { room_id: u32 },

    /// Participant not found — Error code: 1005
    ParticipantNotFound { participant_id: u32 },

    /// WebSocket send failed — Error code: 1006
    SendFailed { connection_id: u32, reason: String },

    /// Connection timeout — Error code: 1007
    ConnectionTimeout { connection_id: u32, timeout_ms: u64 },

    /// Connection limit reached — Error code: 1008
    ConnectionLimitReached { max_connections: u32 },

    /// Message queue full — Error code: 1009
    MessageQueueFull { connection_id: u32, queue_size: u32 },

    /// Invalid state transition — Error code: 1010
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },

    /// Consent freshness check failed (RFC 7675) — Error code: 1011
    ConsentCheckFailed { connection_id: u32, elapsed_ms: u64 },

    /// Reconnection attempts exhausted — Error code: 1012
    ReconnectionExhausted {
        connection_id: u32,
        attempts: u32,
        max_attempts: u32,
    },

    /// Message validation failed — Error code: 1013
    ValidationFailed {
        field: &'static str,
        reason: &'static str,
    },

    /// Server not in expected state — Error code: 1014
    ServerNotRunning { current_state: &'static str },

    /// Health check failed — Error code: 1015
    HealthCheckFailed { reason: &'static str },
}

/// Signaling error codes for explicit error identification.
///
/// Per NASA's Power of 10 Rule 6: All error codes are unique
/// and documented. Compile-time assertions ensure uniqueness.
pub mod signaling_error_codes {
    /// Connection failed error code
    pub const CONNECTION_FAILED: u32 = 1001;
    /// Invalid message error code
    pub const INVALID_MESSAGE: u32 = 1002;
    /// Authentication failed error code
    pub const AUTH_FAILED: u32 = 1003;
    /// Room not found error code
    pub const ROOM_NOT_FOUND: u32 = 1004;
    /// Participant not found error code
    pub const PARTICIPANT_NOT_FOUND: u32 = 1005;
    /// Send failed error code
    pub const SEND_FAILED: u32 = 1006;
    /// Connection timeout error code
    pub const CONNECTION_TIMEOUT: u32 = 1007;
    /// Connection limit reached error code
    pub const CONNECTION_LIMIT: u32 = 1008;
    /// Message queue full error code
    pub const QUEUE_FULL: u32 = 1009;
    /// Invalid state error code
    pub const INVALID_STATE: u32 = 1010;
    /// Consent check failed error code
    pub const CONSENT_FAILED: u32 = 1011;
    /// Reconnection exhausted error code
    pub const RECONNECT_EXHAUSTED: u32 = 1012;
    /// Validation failed error code
    pub const VALIDATION_FAILED: u32 = 1013;
    /// Server not running error code
    pub const SERVER_NOT_RUNNING: u32 = 1014;
    /// Health check failed error code
    pub const HEALTH_CHECK_FAILED: u32 = 1015;

    // Compile-time assertion: All error codes must be unique
    const _: () = {
        const CODES: [u32; 15] = [
            CONNECTION_FAILED,
            INVALID_MESSAGE,
            AUTH_FAILED,
            ROOM_NOT_FOUND,
            PARTICIPANT_NOT_FOUND,
            SEND_FAILED,
            CONNECTION_TIMEOUT,
            CONNECTION_LIMIT,
            QUEUE_FULL,
            INVALID_STATE,
            CONSENT_FAILED,
            RECONNECT_EXHAUSTED,
            VALIDATION_FAILED,
            SERVER_NOT_RUNNING,
            HEALTH_CHECK_FAILED,
        ];
        let mut i = 0;
        while i < CODES.len() - 1 {
            assert!(
                CODES[i] < CODES[i + 1],
                "Error codes must be unique and sequential"
            );
            i += 1;
        }
    };
}

impl SignalingError {
    /// Returns the numeric error code for this error.
    ///
    /// Error codes are stable and documented for client-side handling.
    #[inline]
    #[must_use]
    pub const fn error_code(&self) -> u32 {
        use signaling_error_codes::*;
        match self {
            SignalingError::ConnectionFailed { .. } => CONNECTION_FAILED,
            SignalingError::InvalidMessage { .. } => INVALID_MESSAGE,
            SignalingError::AuthenticationFailed { .. } => AUTH_FAILED,
            SignalingError::RoomNotFound { .. } => ROOM_NOT_FOUND,
            SignalingError::ParticipantNotFound { .. } => {
                PARTICIPANT_NOT_FOUND
            }
            SignalingError::SendFailed { .. } => SEND_FAILED,
            SignalingError::ConnectionTimeout { .. } => {
                CONNECTION_TIMEOUT
            }
            SignalingError::ConnectionLimitReached { .. } => {
                CONNECTION_LIMIT
            }
            SignalingError::MessageQueueFull { .. } => QUEUE_FULL,
            SignalingError::InvalidState { .. } => INVALID_STATE,
            SignalingError::ConsentCheckFailed { .. } => {
                CONSENT_FAILED
            }
            SignalingError::ReconnectionExhausted { .. } => {
                RECONNECT_EXHAUSTED
            }
            SignalingError::ValidationFailed { .. } => {
                VALIDATION_FAILED
            }
            SignalingError::ServerNotRunning { .. } => {
                SERVER_NOT_RUNNING
            }
            SignalingError::HealthCheckFailed { .. } => {
                HEALTH_CHECK_FAILED
            }
        }
    }

    /// Returns true if this is a recoverable error.
    ///
    /// Recoverable errors may succeed on retry with backoff.
    #[inline]
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            SignalingError::ConnectionTimeout { .. }
                | SignalingError::SendFailed { .. }
                | SignalingError::MessageQueueFull { .. }
                | SignalingError::ConsentCheckFailed { .. }
        )
    }

    /// Returns true if this is a resource exhaustion error.
    ///
    /// Resource exhaustion errors indicate bounded limits
    /// have been reached.
    #[inline]
    #[must_use]
    pub const fn is_resource_exhaustion(&self) -> bool {
        matches!(
            self,
            SignalingError::ConnectionLimitReached { .. }
                | SignalingError::MessageQueueFull { .. }
                | SignalingError::ReconnectionExhausted { .. }
        )
    }
}

impl fmt::Display for SignalingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignalingError::ConnectionFailed { source } => {
                write!(
                    f, "[E{}] connection failed: {}",
                    self.error_code(), source
                )
            }
            SignalingError::InvalidMessage { reason } => {
                write!(
                    f, "[E{}] invalid message: {}",
                    self.error_code(), reason
                )
            }
            SignalingError::AuthenticationFailed {
                participant_name,
            } => {
                write!(
                    f, "[E{}] authentication failed for '{}'",
                    self.error_code(), participant_name
                )
            }
            SignalingError::RoomNotFound { room_id } => {
                write!(
                    f, "[E{}] room {} not found",
                    self.error_code(), room_id
                )
            }
            SignalingError::ParticipantNotFound {
                participant_id,
            } => {
                write!(
                    f, "[E{}] participant {} not found",
                    self.error_code(), participant_id
                )
            }
            SignalingError::SendFailed {
                connection_id,
                reason,
            } => {
                write!(
                    f,
                    "[E{}] send to connection {} failed: {}",
                    self.error_code(),
                    connection_id,
                    reason
                )
            }
            SignalingError::ConnectionTimeout {
                connection_id,
                timeout_ms,
            } => {
                write!(
                    f,
                    "[E{}] connection {} timed out after {}ms",
                    self.error_code(),
                    connection_id,
                    timeout_ms
                )
            }
            SignalingError::ConnectionLimitReached {
                max_connections,
            } => {
                write!(
                    f,
                    "[E{}] connection limit reached: max {} connections",
                    self.error_code(),
                    max_connections
                )
            }
            SignalingError::MessageQueueFull {
                connection_id,
                queue_size,
            } => {
                write!(
                    f,
                    "[E{}] message queue full for connection {}: \
                     {} messages",
                    self.error_code(),
                    connection_id,
                    queue_size
                )
            }
            SignalingError::InvalidState {
                expected,
                actual,
            } => {
                write!(
                    f,
                    "[E{}] invalid state: expected {}, got {}",
                    self.error_code(),
                    expected,
                    actual
                )
            }
            SignalingError::ConsentCheckFailed {
                connection_id,
                elapsed_ms,
            } => {
                write!(
                    f,
                    "[E{}] consent check failed for connection \
                     {}: {}ms elapsed",
                    self.error_code(),
                    connection_id,
                    elapsed_ms
                )
            }
            SignalingError::ReconnectionExhausted {
                connection_id,
                attempts,
                max_attempts,
            } => {
                write!(
                    f,
                    "[E{}] reconnection exhausted for connection \
                     {}: {}/{} attempts",
                    self.error_code(),
                    connection_id,
                    attempts,
                    max_attempts
                )
            }
            SignalingError::ValidationFailed { field, reason } => {
                write!(
                    f,
                    "[E{}] validation failed for '{}': {}",
                    self.error_code(),
                    field,
                    reason
                )
            }
            SignalingError::ServerNotRunning { current_state } => {
                write!(
                    f,
                    "[E{}] server not running: current state is {}",
                    self.error_code(),
                    current_state
                )
            }
            SignalingError::HealthCheckFailed { reason } => {
                write!(
                    f,
                    "[E{}] health check failed: {}",
                    self.error_code(),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for SignalingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignalingError::ConnectionFailed { source } => {
                Some(source)
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Room management errors
// ---------------------------------------------------------------------------

/// Room management errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomError {
    /// Room is at maximum capacity
    RoomFull { room_id: u32, max_participants: u32 },

    /// Room not found
    RoomNotFound { room_id: u32 },

    /// Participant not found in room
    ParticipantNotFound {
        room_id: u32,
        participant_id: u32,
    },

    /// Room name too long
    NameTooLong { len: usize, max_len: usize },

    /// Room name already exists
    NameAlreadyExists { name: String },

    /// Track not found
    TrackNotFound { track_id: u32 },

    /// SSRC collision detected
    SsrcCollision { ssrc: u32 },
}

impl fmt::Display for RoomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoomError::RoomFull {
                room_id,
                max_participants,
            } => {
                write!(
                    f,
                    "room {} is full (max {} participants)",
                    room_id, max_participants
                )
            }
            RoomError::RoomNotFound { room_id } => {
                write!(f, "room {} not found", room_id)
            }
            RoomError::ParticipantNotFound {
                room_id,
                participant_id,
            } => {
                write!(
                    f,
                    "participant {} not found in room {}",
                    participant_id, room_id
                )
            }
            RoomError::NameTooLong { len, max_len } => {
                write!(
                    f,
                    "room name too long: {} chars, max {}",
                    len, max_len
                )
            }
            RoomError::NameAlreadyExists { name } => {
                write!(
                    f,
                    "room name '{}' already exists",
                    name
                )
            }
            RoomError::TrackNotFound { track_id } => {
                write!(f, "track {} not found", track_id)
            }
            RoomError::SsrcCollision { ssrc } => {
                write!(f, "SSRC {} already registered", ssrc)
            }
        }
    }
}

impl std::error::Error for RoomError {}

// ---------------------------------------------------------------------------
// SSRC router errors
// ---------------------------------------------------------------------------

/// SSRC router errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrcError {
    /// SSRC already registered
    AlreadyExists { ssrc: u32 },

    /// SSRC not found
    NotFound { ssrc: u32 },
}

impl fmt::Display for SsrcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsrcError::AlreadyExists { ssrc } => {
                write!(f, "SSRC {} already exists", ssrc)
            }
            SsrcError::NotFound { ssrc } => {
                write!(f, "SSRC {} not found", ssrc)
            }
        }
    }
}

impl std::error::Error for SsrcError {}

// ---------------------------------------------------------------------------
// API errors
// ---------------------------------------------------------------------------

/// API-specific errors for the HTTP/gRPC server.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Unauthorized — missing or invalid JWT token
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// Resource not found
    #[error("not found: {resource}")]
    NotFound { resource: String },

    /// Bad request — invalid input
    #[error("bad request: {message}")]
    BadRequest { message: String },

    /// Internal server error
    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        }
        .is_recoverable());
    }

    #[test]
    fn test_signaling_error_is_resource_exhaustion() {
        assert!(SignalingError::ConnectionLimitReached {
            max_connections: 10_000,
        }
        .is_resource_exhaustion());
        assert!(!SignalingError::ConnectionTimeout {
            connection_id: 1,
            timeout_ms: 5000,
        }
        .is_resource_exhaustion());
    }

    #[test]
    fn test_api_error_display() {
        let err = ApiError::Unauthorized {
            reason: "expired token".into(),
        };
        assert!(err.to_string().contains("expired token"));

        let err = ApiError::NotFound {
            resource: "room/42".into(),
        };
        assert!(err.to_string().contains("room/42"));
    }
}
