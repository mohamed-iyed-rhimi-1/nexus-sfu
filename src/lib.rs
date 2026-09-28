#![deny(warnings)]

//! Nexus SFU: a WebRTC Selective Forwarding Unit.
//!
//! The binary crate wires the control plane to the data plane (`server::start`):
//!
//! - **Data plane:** `nexus-dataplane` shards (receive, SRTP, rewrite, fan-out,
//!   send), driven only through commands and events.
//! - **Control plane:** WebSocket signaling, rooms, SDP negotiation, DTLS
//!   handshakes and timers (`orchestrator`), on Tokio.
//!
//! See `architecture.md` for what runs today and `docs/dataplane-design.md` for the
//! design.
//!
//! # Code Style
//!
//! All code follows TigerStyle and NASA's 10 Rules for Safety-Critical Code:
//! - Zero dynamic allocation after initialization
//! - Fixed loop bounds
//! - Comprehensive assertions
//! - Explicit error handling

// =============================================================================
// Application modules (unique to binary crate)
// =============================================================================
// These modules contain application-level orchestration code specific to the
// Nexus SFU binary. They are not part of the library crates.

pub mod config;
pub mod error;
pub mod node;
pub mod orchestrator;
pub mod server;
pub mod signal;
pub mod tracing;
pub mod types;

// =============================================================================
// Crate Re-exports
// =============================================================================
// Re-export workspace crates for direct access. Types are also available
// through the crate paths (e.g., nexus_transport::srtp::SrtpInbound).

// -----------------------------------------------------------------------------
// nexus-transport: SRTP, STUN, candidates, OpenSSL DTLS engine, socket setup
// -----------------------------------------------------------------------------
pub use nexus_transport;

// -----------------------------------------------------------------------------
// nexus-media: RTP/RTCP parsing, header extensions (codecs, simulcast unused)
// -----------------------------------------------------------------------------
pub use nexus_media;

// -----------------------------------------------------------------------------
// nexus-state: CRDT state (single node), SWIM gossip (off unless configured)
// -----------------------------------------------------------------------------
pub use nexus_state;
pub use nexus_state::SwimProtocol;
pub use nexus_state::{
    DistributedState, DistributedStateConfig, GCounter, GossipConfig, LWWReg, Orswot, SeedPeer,
};

// -----------------------------------------------------------------------------
// nexus-signal: WebSocket signaling (the QUIC module is not started)
// -----------------------------------------------------------------------------
pub use nexus_signal;
pub use nexus_signal::{
    QuicConfig, QuicSignaling, SignalMessage as QuicSignalMessage,
    WebSocketServer as NexusWebSocketServer,
};

// -----------------------------------------------------------------------------
// nexus-bwe: Bandwidth estimation (GCC; not on the live path)
// -----------------------------------------------------------------------------
pub use nexus_bwe;
pub use nexus_bwe::{
    CongestionController, DelayBasedBweDetector, GccStats, GccStatsSnapshot, ProbeController,
    RttEstimator, SimulcastLayer, TrackAllocation, TrackPriority,
};

// -----------------------------------------------------------------------------
// nexus-api: HTTP REST API
// -----------------------------------------------------------------------------
pub use nexus_api;
pub use nexus_api::{ApiServer, JwtValidator};

// -----------------------------------------------------------------------------
// nexus-webrtc: SDP parsing, printing and negotiation
// -----------------------------------------------------------------------------
pub use nexus_webrtc;

// =============================================================================
// Convenience Re-exports
// =============================================================================
// Direct access to commonly used types without requiring module prefixes.
// All crate re-exports reference crate paths directly (no wrapper modules).

// -----------------------------------------------------------------------------
// nexus-media: RTP/RTCP types
// -----------------------------------------------------------------------------
pub use nexus_media::rtcp::{ReceiverReportBlock, RtcpHeader, RtcpType, SenderReport};
pub use nexus_media::rtp::RtpHeader;

// -----------------------------------------------------------------------------
// Application modules: config, error, tracing, types
// -----------------------------------------------------------------------------
pub use config::{
    ApiConfig, BweConfig, ConfigError, DataplaneSettings, LoggingConfig, MetricsConfig,
    NexusConfig, RoomConfig, SecurityConfig, TransportConfig,
};
pub use error::{
    signaling_error_codes, ApiError, ParseError, RoomError, RtcpError, RtpError, SfuError,
    SignalingError, TransportError,
};
pub use tracing::{
    init_tracing, init_tracing_extended, ExtendedLoggingConfig, HotPathMetrics,
    HotPathMetricsSnapshot, LatencyGuard, LatencyKind, TracingError, HOT_PATH_METRICS,
};
pub use types::{
    BandwidthBps, ConnectionId, MediaKind, ParticipantId, RoomId, Ssrc, TimestampNs, TrackId,
};
/// Nexus SFU MVP version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Performance tier information
pub mod tier {
    /// Phase 1: one data-plane shard (recvmmsg/sendmmsg on Linux)
    pub const CURRENT: &str = "MVP - Phase 1 data plane, one shard";

    /// Expected performance metrics
    pub mod metrics {
        /// Packets per second per core (target)
        pub const PACKETS_PER_SEC_PER_CORE: u64 = 500_000;
        /// Forwarding latency in milliseconds (P50 target, design §3)
        pub const LATENCY_P50_MS: u64 = 1;
        /// Forwarding latency in milliseconds (P99 target, design §3)
        pub const LATENCY_P99_MS: u64 = 5;
        /// Maximum participants per room
        pub const MAX_PARTICIPANTS_PER_ROOM: u32 = 1000;
        /// Session state per participant in bytes (budget, checked by `benches/memory.rs`;
        /// the signaling connection is extra)
        pub const MEMORY_PER_PARTICIPANT_BYTES: u64 = 25 * 1024;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // VERSION comes from CARGO_PKG_VERSION; check it's a semver triple
        assert_eq!(
            VERSION.split('.').count(),
            3,
            "unexpected version {VERSION}"
        );
    }

    #[test]
    fn test_tier_info() {
        assert!(tier::CURRENT.contains("MVP"));
        const { assert!(tier::metrics::PACKETS_PER_SEC_PER_CORE >= 500_000) };
    }

    #[test]
    fn test_default_config_is_valid() {
        let config = NexusConfig::default();
        assert!(config.validate().is_ok());
    }
}
