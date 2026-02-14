// Configuration module - hierarchical, modular configuration system
// TigerStyle: Explicit types, units in names, comprehensive validation

mod api;
mod ice;
mod loader;
mod validation;
mod watcher;
mod xdp;

pub use api::ApiConfig;
pub use ice::{IceServerConfig, TurnServerConfig, GOOGLE_STUN_SERVERS, MAX_STUN_SERVERS, MAX_TURN_SERVERS};
pub use loader::ConfigLoader;
pub use validation::ConfigError;
pub use watcher::ConfigWatcher;
pub use xdp::XdpConfig;

// Import config structs from nexus-core (single source of truth)
pub use nexus_core::config::{
    TransportConfig, MemoryConfig, WorkerConfig, RoomConfig,
    BweConfig, LoggingConfig, LogLevel, SecurityConfig,
    ActorConfig, MetricsConfig, Validate,
};

use serde::{Deserialize, Serialize};
use std::path::Path;

// Re-export crate configs
pub use nexus_state::gossip::GossipConfig;
pub use nexus_signal::QuicConfig;

/// Cluster configuration for multi-node deployment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique node ID for this SFU instance.
    /// Must be unique across all nodes in the cluster.
    /// If 0, auto-generated from machine ID + process ID + timestamp.
    /// Range: 1..=u64::MAX (0 triggers auto-generation).
    #[serde(default)]
    pub node_id: u64,
}

impl ClusterConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // node_id == 0 is valid (triggers auto-generation)
        Ok(())
    }
}

/// Root configuration aggregator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusConfig {
    pub transport: TransportConfig,
    pub memory: MemoryConfig,
    pub worker: WorkerConfig,
    pub room: RoomConfig,
    pub bwe: BweConfig,
    pub quic: QuicConfig,
    pub gossip: GossipConfig,
    pub actor: ActorConfig,
    pub metrics: MetricsConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub xdp: XdpConfig,
    /// ICE server configuration for STUN/TURN.
    #[serde(default)]
    pub ice_servers: IceServerConfig,
    /// Cluster configuration for multi-node deployment.
    #[serde(default)]
    pub cluster: ClusterConfig,
    /// Graceful drain timeout in milliseconds.
    /// When shutdown is initiated, the SFU will continue forwarding packets
    /// for this duration before terminating connections.
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u32,
}

/// Default drain timeout: 5 seconds
fn default_drain_timeout_ms() -> u32 {
    5000
}

/// Helper to bridge nexus-core's `Validate` trait (`Result<(), Vec<String>>`)
/// to the local `ConfigError` type.
fn validate_core_config(
    section: &str,
    result: Result<(), Vec<String>>,
) -> Result<(), ConfigError> {
    match result {
        Ok(()) => Ok(()),
        Err(errors) => Err(ConfigError::invalid(
            section,
            &errors.join("; "),
        )),
    }
}

impl NexusConfig {
    /// Load configuration with precedence: env vars > file > defaults
    pub fn load() -> Result<Self, ConfigError> {
        ConfigLoader::load()
    }

    /// Load from specific file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        ConfigLoader::from_file(path)
    }

    /// Validate entire configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate each module using nexus-core's Validate trait
        validate_core_config("transport", self.transport.validate())?;
        validate_core_config("memory", self.memory.validate())?;
        validate_core_config("worker", self.worker.validate())?;
        validate_core_config("room", self.room.validate())?;
        validate_core_config("bwe", self.bwe.validate())?;
        self.quic.validate().map_err(|e| ConfigError::invalid("quic", &e))?;
        self.gossip.validate()?;
        validate_core_config("actor", self.actor.validate())?;
        validate_core_config("metrics", self.metrics.validate())?;
        self.api.validate()?;
        validate_core_config("security", self.security.validate())?;
        validate_core_config("logging", self.logging.validate())?;
        self.xdp.validate()?;
        self.ice_servers.validate()?;
        self.cluster.validate()?;

        // Validate drain_timeout_ms
        if self.drain_timeout_ms == 0 {
            return Err(ConfigError::invalid(
                "drain_timeout_ms",
                "must be > 0",
            ));
        }
        // Maximum drain timeout: 5 minutes (300000ms)
        if self.drain_timeout_ms > 300_000 {
            return Err(ConfigError::invalid(
                "drain_timeout_ms",
                "must be <= 300000 (5 minutes)",
            ));
        }

        // Cross-module validation
        self.validate_cross_module()?;

        Ok(())
    }

    /// Validate relationships between modules
    fn validate_cross_module(&self) -> Result<(), ConfigError> {
        // Arena size validation: The arena is a shared pool for concurrent packets,
        // not a dedicated buffer per track. A reasonable minimum is based on:
        // - Expected concurrent active tracks (not max_track_actors)
        // - Typical packet rate and processing latency
        // For development/testing, we use a much smaller threshold.
        // Production configs should size arena based on actual load.
        let min_arena_mb = 16u64; // Minimum 16MB for basic operation

        if (self.memory.arena_size_mb as u64) < min_arena_mb {
            return Err(ConfigError::invalid(
                "memory.arena_size_mb",
                &format!("must be >= {} MB for basic operation", min_arena_mb),
            ));
        }

        // Worker count should not exceed 2x CPU cores
        let cpu_count = num_cpus::get() as u32;
        let worker_count = if self.worker.num_workers == 0 {
            cpu_count
        } else {
            self.worker.num_workers
        };

        if worker_count > cpu_count * 2 {
            return Err(ConfigError::invalid(
                "worker.num_workers",
                &format!("should not exceed 2x CPU cores ({})", cpu_count * 2),
            ));
        }

        Ok(())
    }

    /// Reload only control plane settings (safe to change at runtime)
    pub fn reload_control_plane(&mut self, new_config: &NexusConfig) {
        // Safe to reload: logging, metrics, room timeouts
        self.logging = new_config.logging.clone();
        self.metrics = new_config.metrics.clone();
        self.room.empty_room_timeout_ms = new_config.room.empty_room_timeout_ms;
        self.bwe = new_config.bwe;

        // NOT safe to reload: memory, workers, transport (require restart)
        // These are ignored during hot-reload
    }
}

impl Default for NexusConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            memory: MemoryConfig::default(),
            worker: WorkerConfig::default(),
            room: RoomConfig::default(),
            bwe: BweConfig::default(),
            quic: QuicConfig::default(),
            gossip: GossipConfig::default(),
            actor: ActorConfig::default(),
            metrics: MetricsConfig::default(),
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            xdp: XdpConfig::default(),
            ice_servers: IceServerConfig::default(),
            cluster: ClusterConfig::default(),
            drain_timeout_ms: default_drain_timeout_ms(),
        }
    }
}

#[cfg(test)]
mod tests;
