// Configuration module - hierarchical, modular configuration system
// TigerStyle: Explicit types, units in names, comprehensive validation

mod api;
mod dataplane;
mod ice;
mod loader;
mod validation;
mod watcher;

pub use api::ApiConfig;
pub use dataplane::DataplaneSettings;
pub use ice::{
    IceServerConfig, TurnServerConfig, GOOGLE_STUN_SERVERS, MAX_STUN_SERVERS, MAX_TURN_SERVERS,
};
pub use loader::ConfigLoader;
pub use validation::ConfigError;
pub use watcher::ConfigWatcher;

// Import config structs from nexus-core (single source of truth)
pub use nexus_core::config::{
    BweConfig, LogLevel, LoggingConfig, MetricsConfig, RoomConfig, SecurityConfig, TransportConfig,
    Validate,
};

use serde::{Deserialize, Serialize};
use std::path::Path;

// Re-export crate configs
pub use nexus_signal::QuicConfig;
pub use nexus_state::gossip::GossipConfig;

/// Cluster configuration for multi-node deployment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique node ID for this SFU instance.
    /// Must be unique across all nodes in the cluster.
    /// If 0, auto-generated from machine ID + process ID + timestamp.
    /// Range: 1..=u64::MAX (0 triggers auto-generation).
    #[serde(default)]
    pub node_id: u64,
    /// Start SWIM gossip with other nodes. Off by default: v1 is single-node,
    /// and gossip is unauthenticated (any sender can spoof membership, rooms and
    /// tracks), so it must not listen unless a cluster is deliberately configured.
    #[serde(default)]
    pub gossip_enabled: bool,
    /// Address the gossip socket binds when `gossip_enabled`. Required then, and a
    /// specific interface address (not 0.0.0.0 or ::); port 0 lets the OS choose.
    #[serde(default)]
    pub gossip_bind_addr: Option<std::net::SocketAddr>,
}

impl ClusterConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // node_id == 0 is valid (triggers auto-generation)
        if !self.gossip_enabled {
            return Ok(());
        }
        match self.gossip_bind_addr {
            None => Err(ConfigError::invalid(
                "cluster",
                "gossip_enabled needs gossip_bind_addr (an interface address)",
            )),
            Some(addr) if addr.ip().is_unspecified() => Err(ConfigError::invalid(
                "cluster",
                "gossip_bind_addr must be a specific address, not 0.0.0.0 or ::",
            )),
            Some(_) => Ok(()),
        }
    }
}

/// Root configuration aggregator.
///
/// Unknown top-level sections are an error: a file that still has the old data
/// plane's `[worker]`, `[memory]` or `[actor]` (removed in Phase 1; their settings
/// that still apply are under `[dataplane]`) fails at startup instead of loading
/// with those settings silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusConfig {
    pub transport: TransportConfig,
    pub room: RoomConfig,
    pub bwe: BweConfig,
    pub quic: QuicConfig,
    pub gossip: GossipConfig,
    pub metrics: MetricsConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    /// ICE server configuration for STUN/TURN.
    #[serde(default)]
    pub ice_servers: IceServerConfig,
    /// Cluster configuration for multi-node deployment.
    #[serde(default)]
    pub cluster: ClusterConfig,
    /// New data plane: shard count and shard settings (note §14).
    #[serde(default)]
    pub dataplane: DataplaneSettings,
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
fn validate_core_config(section: &str, result: Result<(), Vec<String>>) -> Result<(), ConfigError> {
    match result {
        Ok(()) => Ok(()),
        Err(errors) => Err(ConfigError::invalid(section, &errors.join("; "))),
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
        validate_core_config("room", self.room.validate())?;
        validate_core_config("bwe", self.bwe.validate())?;
        self.quic
            .validate()
            .map_err(|e| ConfigError::invalid("quic", &e))?;
        self.gossip.validate()?;
        validate_core_config("metrics", self.metrics.validate())?;
        self.api.validate()?;
        validate_core_config("security", self.security.validate())?;
        validate_core_config("logging", self.logging.validate())?;
        self.ice_servers.validate()?;
        self.cluster.validate()?;
        if !self.cluster.gossip_enabled && !self.gossip.seed_peers.is_empty() {
            return Err(ConfigError::invalid(
                "gossip",
                "seed_peers are set but cluster.gossip_enabled is false",
            ));
        }
        self.validate_dataplane()?;

        // Validate drain_timeout_ms
        if self.drain_timeout_ms == 0 {
            return Err(ConfigError::invalid("drain_timeout_ms", "must be > 0"));
        }
        // Maximum drain timeout: 5 minutes (300000ms)
        if self.drain_timeout_ms > 300_000 {
            return Err(ConfigError::invalid(
                "drain_timeout_ms",
                "must be <= 300000 (5 minutes)",
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

        // NOT safe to reload: transport, dataplane (require restart)
        // These are ignored during hot-reload
    }
}

impl Default for NexusConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            room: RoomConfig::default(),
            bwe: BweConfig::default(),
            quic: QuicConfig::default(),
            gossip: GossipConfig::default(),
            metrics: MetricsConfig::default(),
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            ice_servers: IceServerConfig::default(),
            cluster: ClusterConfig::default(),
            dataplane: DataplaneSettings::default(),
            drain_timeout_ms: default_drain_timeout_ms(),
        }
    }
}

#[cfg(test)]
mod tests;
