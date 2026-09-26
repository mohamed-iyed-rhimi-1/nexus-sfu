//! Signaling over WebSocket + JSON.
//!
//! The WebSocket server lives in the `nexus-signal` crate; `server` wraps it
//! for startup. The QUIC module in `nexus-signal` is not started (it is not
//! connected to the orchestrator).
//!
//! ## Usage
//!
//! ```rust,ignore
//! use nexus_sfu::signal::{SignalingServer, SignalingConfig};
//!
//! let config = SignalingConfig {
//!     ws_addr: "0.0.0.0:8080".parse().unwrap(),
//!     ..Default::default()
//! };
//!
//! let server = SignalingServer::new(config, shutdown, orchestrator_tx)?;
//! let addr = server.local_addr();
//! server.run().await?;
//! ```

pub mod server;

// Re-export websocket server types from nexus-signal
pub use nexus_signal::websocket::server::{OrchestratorEvent, WebSocketServer};

// Re-export signaling server
pub use server::{SignalingConfig, SignalingServer};

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
    new_signaling_connections, register_signaling_connection, unregister_signaling_connection,
    SignalingConnectionHandle, SignalingConnections,
};
