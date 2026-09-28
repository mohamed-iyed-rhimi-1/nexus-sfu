#![deny(warnings)]

//! nexus-core: Shared types, error types, and configuration
//! primitives for the Nexus SFU crate ecosystem.
//!
//! This crate is the single source of truth for core primitives
//! that all other nexus-* crates depend on. It has zero external
//! dependencies beyond std, serde, and thiserror.

pub mod config;
pub mod error;
pub mod types;

// Re-export all shared types at crate root for convenience.
// Consumers can use `nexus_core::TrackId` instead of
// `nexus_core::types::TrackId`.
pub use types::{
    BandwidthBps, ConnectionId, MediaKind, ParticipantId, RoomId, Ssrc, TimestampNs, TrackId,
};

// Re-export all error types at crate root for convenience.
// Consumers can use `nexus_core::SfuError` instead of
// `nexus_core::error::SfuError`.
pub use error::{
    signaling_error_codes, ApiError, ArenaError, ParseError, RoomError, RtcpError, RtpError,
    SfuError, SignalingError, SsrcError, TransportError,
};

// Re-export config primitives and validation trait.
// The full NexusConfig aggregator stays in the root crate
// because it depends on crate-specific configs (GossipConfig, etc.).
pub use config::{
    ActorConfig, BweConfig, ConfigError, LogLevel, LoggingConfig, MemoryConfig, MetricsConfig,
    RoomConfig, SecurityConfig, TransportConfig, Validate, WorkerConfig, MAX_ANNOUNCED_IPS,
};
