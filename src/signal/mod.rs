//! Signaling module for WebSocket and QUIC communication.
//!
//! This module provides signaling handlers for WebRTC session establishment.
//!
//! ## Default Behavior
//!
//! The signaling server uses QUIC as the primary transport with automatic
//! WebSocket fallback:
//!
//! 1. Attempts to start QUIC signaling server
//! 2. If QUIC succeeds, also starts WebSocket for fallback clients
//! 3. If QUIC fails (no TLS certs, port blocked, etc.), falls back to WebSocket only
//!
//! ## Components
//!
//! - `server`: QUIC-first signaling with WebSocket fallback (default)
//! - Handler and WebSocket server now live in `nexus-signal` crate
//!
//! ## Usage
//!
//! ```rust,ignore
//! use nexus_sfu::signal::{SignalingServer, SignalingConfig};
//!
//! let config = SignalingConfig {
//!     quic_addr: "0.0.0.0:4433".parse().unwrap(),
//!     ws_addr: "0.0.0.0:8080".parse().unwrap(),
//!     ..Default::default()
//! };
//!
//! let server = SignalingServer::new(config, shutdown, orchestrator_tx)?;
//! server.run().await?; // Tries QUIC first, falls back to WebSocket
//! ```

pub mod server;

// Re-export handler types from nexus-signal
pub use nexus_signal::websocket::handler::{
    error_codes as handler_error_codes, ClientStats, JoinResponse, MessageType, SessionTicket,
    SignalingHandler, SignalingHandlerError, TrackEntry, MAX_PARTICIPANT_NAME_LEN,
    MAX_SESSION_TICKETS, MAX_STATS_PAYLOAD_SIZE, MAX_TRACKS_IN_RESPONSE, TICKET_LIFETIME_SECS,
};

// Re-export websocket server types from nexus-signal
pub use nexus_signal::websocket::server::{OrchestratorEvent, WebSocketServer};

// Re-export signaling server (QUIC-first with WebSocket fallback)
pub use server::{ActiveTransport, SignalingConfig, SignalingServer};

// Re-export from nexus_signal
pub use nexus_signal::{OfferTrack, ParticipantInfo, QuicSignaling, SignalMessage, TrackInfo};

// Legacy constants for backward compatibility
pub const MAX_CONNECTIONS: u32 = 10_000;
pub const MAX_MESSAGE_QUEUE_SIZE: u32 = 1_000;
pub const DEFAULT_PING_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 60_000;
pub const CONSENT_FRESHNESS_INTERVAL_MS: u64 = 30_000;

// Error codes for signaling
pub mod error_codes {
    pub const INVALID_MESSAGE: &str = "INVALID_MESSAGE";
    pub const ROOM_NOT_FOUND: &str = "ROOM_NOT_FOUND";
    pub const PARTICIPANT_NOT_FOUND: &str = "PARTICIPANT_NOT_FOUND";
    pub const ROOM_FULL: &str = "ROOM_FULL";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
}

// ============================================================================
// Shared Signaling Connections Registry (re-exported from nexus-signal)
// ============================================================================

pub use nexus_signal::websocket::{
    register_signaling_connection, signaling_connections, unregister_signaling_connection,
    SignalingConnectionHandle,
};
