#![deny(warnings)]

//! Nexus SFU MVP - High-performance WebRTC Selective Forwarding Unit
//!
//! This is the Minimum Viable Product implementation focusing on four key optimizations:
//! 1. **Batch Forwarding** - sendmmsg for single-syscall multi-packet sends
//! 2. **Worker Sharding** - Consistent hashing distributes tracks across CPU cores
//! 3. **Hot/Cold Separation** - Optimized iteration for active subscribers
//! 4. **Selective Forwarding** - Viewport-based filtering reduces bandwidth
//!
//! # Architecture
//!
//! The SFU separates control plane (can allocate, use locks) from data plane
//! (zero allocation, lock-free):
//!
//! - **Control Plane**: WebSocket signaling, room management, subscription changes
//! - **Data Plane**: Packet receive/send, RTP parsing, SSRC routing, forwarding
//!
//! # Performance Targets
//!
//! - 500-1000 participants per room
//! - P50 latency < 20ms, P99 < 50ms
//! - 500K+ packets/sec/core
//! - < 500KB memory per participant
//!
//! # Code Style
//!
//! All code follows TigerStyle and NASA's 10 Rules for Safety-Critical Code:
//! - Zero dynamic allocation after initialization
//! - Fixed loop bounds
//! - Comprehensive assertions
//! - Explicit error handling

// =============================================================================
// Re-export modules (thin wrappers over library crates)
// =============================================================================
// The transport module re-exports from nexus_transport and includes local af_xdp.

pub mod transport;    // → nexus_transport + local af_xdp

// =============================================================================
// Application modules (unique to binary crate)
// =============================================================================
// These modules contain application-level orchestration code specific to the
// Nexus SFU binary. They are not part of the library crates.

pub mod config;
pub mod clock;
pub mod error;
pub mod forward;
pub mod orchestrator;
pub mod proto;
pub mod relay;
pub mod sfu;
pub mod signal;
pub mod spin;
pub mod state;
pub mod track_registry;
pub mod tracing;
pub mod types;
pub mod worker;

// =============================================================================
// Crate Re-exports
// =============================================================================
// Re-export workspace crates for direct access. Types are also available
// through the re-export modules above (e.g., nexus_transport::ice::IceAgent).

// -----------------------------------------------------------------------------
// nexus-actor: Actor system for room/participant/track management
// -----------------------------------------------------------------------------
pub use nexus_actor;
pub use nexus_actor::{
    ActorManager, RoomActor, ParticipantActor, TrackActor,
    ActorRegistry, ActorSupervisor, ActorState, ActorHealth,
    RestartPolicy, TrackActorMessage, TrackActorResponse,
    PacketSlot as ActorPacketSlot,
    WorkerId as ActorWorkerId, MediaKind as ActorMediaKind,
};

// -----------------------------------------------------------------------------
// nexus-transport: Low-level transport (UDP, SRTP, DTLS, ICE)
// -----------------------------------------------------------------------------
pub use nexus_transport;

// -----------------------------------------------------------------------------
// nexus-media: RTP/RTCP parsing, codecs, simulcast
// -----------------------------------------------------------------------------
pub use nexus_media;

// -----------------------------------------------------------------------------
// nexus-state: Distributed state (CRDTs, SWIM protocol)
// -----------------------------------------------------------------------------
pub use nexus_state;
pub use nexus_state::{
    DistributedState, DistributedStateConfig,
    Orswot, LWWReg, GCounter,
    GossipConfig, SeedPeer,
};
pub use nexus_state::SwimProtocol;

// -----------------------------------------------------------------------------
// nexus-signal: QUIC signaling with WebSocket fallback
// -----------------------------------------------------------------------------
pub use nexus_signal;
pub use nexus_signal::{
    QuicSignaling, QuicConfig, WebSocketServer as NexusWebSocketServer,
    SignalMessage as QuicSignalMessage,
};

// -----------------------------------------------------------------------------
// nexus-bwe: Bandwidth estimation (GCC)
// -----------------------------------------------------------------------------
pub use nexus_bwe;
pub use nexus_bwe::{
    CongestionController, GccStats, GccStatsSnapshot,
    TrackAllocation, TrackPriority, SimulcastLayer,
    DelayBasedBweDetector,
    RttEstimator, ProbeController,
};

// -----------------------------------------------------------------------------
// nexus-api: HTTP REST API
// -----------------------------------------------------------------------------
pub use nexus_api;
pub use nexus_api::{ApiServer, JwtValidator};

// -----------------------------------------------------------------------------
// nexus-webrtc: WebRTC transport and SDP parsing
// -----------------------------------------------------------------------------
pub use nexus_webrtc;

// =============================================================================
// Convenience Re-exports
// =============================================================================
// Direct access to commonly used types without requiring module prefixes.
// All crate re-exports reference crate paths directly (no wrapper modules).

// -----------------------------------------------------------------------------
// nexus-transport: arena, ICE, TURN
// -----------------------------------------------------------------------------
pub use nexus_transport::arena::{PacketArena, PacketSlot, SLOT_SIZE_BYTES};
pub use nexus_transport::ice::{
    IceAgent, IceConfig, IceRole, IceCredentials, IceConnectionState, IceGatheringState,
    Candidate, CandidateType, CandidatePair, CandidatePairState,
    CandidateGatherer, Checklist, ChecklistState,
    StunMessage, StunAttribute, StunClass, StunMethod, IceError,
};
pub use nexus_transport::turn::{
    TurnClient, TurnClientConfig, TurnError,
    Allocation, AllocationState,
    TurnCredentials, TurnServerInfo, Permission, ChannelBinding,
    RelayedAddress, TransportProtocol,
    CHANNEL_NUMBER_MIN, CHANNEL_NUMBER_MAX, DEFAULT_ALLOCATION_LIFETIME,
    PERMISSION_LIFETIME, CHANNEL_BINDING_LIFETIME,
};

// -----------------------------------------------------------------------------
// nexus-media: RTP/RTCP types
// -----------------------------------------------------------------------------
pub use nexus_media::rtcp::{ReceiverReportBlock, RtcpHeader, RtcpType, SenderReport};
pub use nexus_media::rtp::RtpHeader;

// -----------------------------------------------------------------------------
// Application modules: config, error, forward, sfu, worker, etc.
// -----------------------------------------------------------------------------
pub use config::{
    NexusConfig, MemoryConfig, WorkerConfig, RoomConfig, BweConfig,
    SecurityConfig, LoggingConfig, ActorConfig, MetricsConfig, ApiConfig, XdpConfig,
    ConfigError,
    TransportConfig,  // Application-level transport config (distinct from UdpTransportConfig)
};
pub use error::{
    ArenaError, ParseError, RoomError, RtcpError, RtpError, SfuError,
    SignalingError, TransportError, WorkerError, ApiError, signaling_error_codes,
};
pub use forward::{
    SsrcError, SsrcRouter,
    Subscriber, SubscriberList, SubscriberListStats, SubscriberListStatsSnapshot,
    ViewportFilter, DEFAULT_COLD_TIMEOUT_NS, MAX_SUBSCRIBERS_PER_TRACK,
    PacketType, PacketHandler,
};
pub use sfu::{Sfu, SfuStats, DrainState};
pub use spin::SpinLoop;
pub use state::{ForwardEntry, ForwardTable, XdpError};
pub use tracing::{
    init_tracing, init_tracing_extended, ExtendedLoggingConfig, TracingError,
    HotPathMetrics, HotPathMetricsSnapshot, LatencyGuard, LatencyKind,
    HOT_PATH_METRICS,
};
pub use transport::{
    BatchSender, BatchSenderStats, BatchSenderStatsSnapshot,
    RecvPacket, TransportStats, TransportStatsSnapshot, UdpTransport,
    TransportConfig as UdpTransportConfig,  // Low-level UDP transport config
};
pub use types::{BandwidthBps, ConnectionId, MediaKind, ParticipantId, RoomId, Ssrc, TimestampNs, TrackId};
pub use worker::{ConsistentHash, MediaWorker, WorkerHandle, WorkerMessage, WorkerPool, WorkerStats};

/// Nexus SFU MVP version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Performance tier information
pub mod tier {
    /// MVP: io_uring/kqueue with batch forwarding
    pub const CURRENT: &str = "MVP - Batch Forwarding with Worker Sharding";

    /// Tier 2: XDP kernel bypass (optional, Linux only)
    pub const TIER2: &str = "XDP Kernel Bypass - 15M+ packets/sec/core";

    /// Expected performance metrics
    pub mod metrics {
        /// Packets per second per core (target)
        pub const PACKETS_PER_SEC_PER_CORE: u64 = 500_000;
        /// Packets per second per core with XDP (target)
        pub const PACKETS_PER_SEC_PER_CORE_XDP: u64 = 15_000_000;
        /// Latency in milliseconds (P50 target)
        pub const LATENCY_P50_MS: u64 = 20;
        /// Latency in microseconds with XDP (P50 target)
        pub const LATENCY_P50_US_XDP: u64 = 100;
        /// Latency in milliseconds (P99 target)
        pub const LATENCY_P99_MS: u64 = 50;
        /// Maximum participants per room
        pub const MAX_PARTICIPANTS_PER_ROOM: u32 = 1000;
        /// Memory per participant in bytes (target)
        pub const MEMORY_PER_PARTICIPANT_BYTES: u64 = 500 * 1024;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_tier_info() {
        assert!(tier::CURRENT.contains("MVP"));
        assert!(tier::metrics::PACKETS_PER_SEC_PER_CORE >= 500_000);
    }

    #[test]
    fn test_default_config_is_valid() {
        let config = NexusConfig::default();
        assert!(config.validate().is_ok());
    }
}
