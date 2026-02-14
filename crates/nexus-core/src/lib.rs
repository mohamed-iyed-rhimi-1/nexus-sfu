#![deny(warnings)]

//! nexus-core: Shared types, error types, and configuration
//! primitives for the Nexus SFU crate ecosystem.
//!
//! This crate is the single source of truth for core primitives
//! that all other nexus-* crates depend on. It has zero external
//! dependencies beyond std, serde, and thiserror.

pub mod types;
pub mod error;
pub mod config;

// Re-export all shared types at crate root for convenience.
// Consumers can use `nexus_core::TrackId` instead of
// `nexus_core::types::TrackId`.
pub use types::{
    TrackId, ParticipantId, RoomId, ConnectionId,
    Ssrc, TimestampNs, BandwidthBps, MediaKind,
};

// Re-export all error types at crate root for convenience.
// Consumers can use `nexus_core::SfuError` instead of
// `nexus_core::error::SfuError`.
pub use error::{
    SfuError, TransportError, ParseError,
    RtpError, RtcpError, ArenaError, WorkerError,
    SignalingError, RoomError, SsrcError, ApiError,
    signaling_error_codes,
};

// Re-export config primitives and validation trait.
// The full NexusConfig aggregator stays in the root crate
// because it depends on crate-specific configs (GossipConfig, etc.).
pub use config::{
    Validate, ConfigError,
    TransportConfig, MemoryConfig, WorkerConfig,
    RoomConfig, BweConfig, LoggingConfig, LogLevel,
    SecurityConfig, ActorConfig, MetricsConfig,
};
