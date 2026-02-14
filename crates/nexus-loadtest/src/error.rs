//! Error types for load testing
//!
//! Defines error types for connection, signaling, client, and test errors.

use std::time::Duration;
use thiserror::Error;

use nexus_core::TrackId;

/// Top-level error type for load testing operations
#[derive(Error, Debug)]
pub enum LoadTestError {
    /// Connection to SFU failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Signaling protocol error
    #[error("Signaling error: {0}")]
    SignalingError(#[from] SignalingError),

    /// WebRTC error
    #[error("WebRTC error: {0}")]
    WebRtcError(String),

    /// Operation timed out
    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Client error
    #[error("Client error: {0}")]
    ClientError(#[from] ClientError),

    /// Report generation error
    #[error("Report error: {0}")]
    ReportError(String),

    /// Prometheus server error
    #[error("Prometheus error: {0}")]
    PrometheusError(String),
}

/// Signaling-specific errors
#[derive(Error, Debug)]
pub enum SignalingError {
    /// Connection was refused by the server
    #[error("Connection refused")]
    ConnectionRefused,

    /// Invalid URL format
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Protocol-level error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Room not found on server
    #[error("Room not found: {0}")]
    RoomNotFound(String),

    /// Connection was closed unexpectedly
    #[error("Connection closed")]
    ConnectionClosed,

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    /// QUIC transport error
    #[error("QUIC error: {0}")]
    QuicError(String),

    /// Message serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Connection attempt timed out
    #[error("Connection timeout after {0:?}")]
    Timeout(std::time::Duration),
}

/// Client-specific errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// Failed to create WebRTC peer connection
    #[error("Failed to create peer connection: {0}")]
    PeerConnectionFailed(String),

    /// Failed to create SDP offer
    #[error("Failed to create offer: {0}")]
    OfferFailed(String),

    /// Failed to set remote SDP description
    #[error("Failed to set remote description: {0}")]
    RemoteDescriptionFailed(String),

    /// ICE connection failed
    #[error("ICE connection failed")]
    IceConnectionFailed,

    /// Track subscription failed
    #[error("Track subscription failed: {0}")]
    SubscriptionFailed(TrackId),

    /// Client is in invalid state for operation
    #[error("Invalid client state: expected {expected}, got {actual}")]
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },

    /// Media generation error
    #[error("Media generation error: {0}")]
    MediaError(String),
}
