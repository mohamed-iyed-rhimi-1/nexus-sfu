//! Configuration for the SWIM gossip protocol.
//!
//! This module provides `GossipConfig` with sensible defaults and
//! validation for all protocol parameters.
//!
//! ## TigerStyle Compliance
//!
//! - All configuration values are validated with assertions
//! - Builder pattern methods return Self for chaining
//! - Defaults are derived from compile-time constants

use std::net::SocketAddr;

use super::types::{GOSSIP_FANOUT, MAX_PEERS, MAX_PIGGYBACK_UPDATES, PING_TIMEOUT_MS, PROBE_INTERVAL_MS, SUSPECT_TIMEOUT_MS};
use crate::error::GossipError;
use crate::types::ActorId;

/// Maximum number of seed peers allowed in configuration.
pub const MAX_SEED_PEERS: usize = 16;

/// A seed peer for bootstrapping the gossip cluster.
///
/// Seed peers are the initial nodes that a new node contacts to join the cluster.
/// They should be stable, well-known nodes that are likely to be available.
///
/// # TigerStyle Compliance
///
/// - Explicit u64 for actor_id (no usize)
/// - Compact struct layout
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeedPeer {
    /// Unique identifier for this peer (must be < MAX_ACTORS)
    pub actor_id: ActorId,
    /// Network address for communication
    pub addr: SocketAddr,
}

impl SeedPeer {
    /// Create a new seed peer.
    ///
    /// # Arguments
    /// * `actor_id` - Unique peer identifier
    /// * `addr` - Network address for communication
    ///
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS`
    #[inline]
    pub fn new(actor_id: ActorId, addr: SocketAddr) -> Self {
        use crate::types::MAX_ACTORS;
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );
        Self { actor_id, addr }
    }
}

/// Configuration for the SWIM gossip protocol.
///
/// All timing values are in milliseconds for consistency.
///
/// # Example
///
/// ```ignore
/// use nexus_state::gossip::GossipConfig;
///
/// let config = GossipConfig::default()
///     .with_probe_interval(500)
///     .with_ping_timeout(200)
///     .with_fanout(5);
///
/// config.validate().expect("config should be valid");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GossipConfig {
    /// Interval between probes in milliseconds
    pub probe_interval_ms: u64,
    /// Timeout for ping response in milliseconds
    pub ping_timeout_ms: u64,
    /// Time before suspect → dead in milliseconds
    pub suspect_timeout_ms: u64,
    /// Number of peers to gossip to for indirect probes
    pub fanout: usize,
    /// Maximum number of state updates to piggyback per message
    pub max_piggyback_updates: usize,
    /// Seed peers for bootstrapping the cluster
    #[cfg_attr(feature = "serde", serde(default))]
    pub seed_peers: Vec<SeedPeer>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            probe_interval_ms: PROBE_INTERVAL_MS,
            ping_timeout_ms: PING_TIMEOUT_MS,
            suspect_timeout_ms: SUSPECT_TIMEOUT_MS,
            fanout: GOSSIP_FANOUT,
            max_piggyback_updates: MAX_PIGGYBACK_UPDATES,
            seed_peers: Vec::new(),
        }
    }
}

impl GossipConfig {
    /// Create a new configuration with default values.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration.
    ///
    /// # Returns
    /// - `Ok(())` if all parameters are valid
    /// - `Err(GossipError::Config)` with description if invalid
    ///
    /// # Validation Rules
    /// - `probe_interval_ms > 0`
    /// - `ping_timeout_ms > 0`
    /// - `suspect_timeout_ms > ping_timeout_ms`
    /// - `fanout > 0 && fanout <= MAX_PEERS`
    /// - `max_piggyback_updates > 0 && max_piggyback_updates <= MAX_PIGGYBACK_UPDATES`
    /// - `seed_peers.len() <= MAX_SEED_PEERS`
    #[inline]
    pub fn validate(&self) -> Result<(), GossipError> {
        if self.probe_interval_ms == 0 {
            return Err(GossipError::Config(
                "probe_interval_ms must be > 0".to_string(),
            ));
        }

        if self.ping_timeout_ms == 0 {
            return Err(GossipError::Config(
                "ping_timeout_ms must be > 0".to_string(),
            ));
        }

        if self.suspect_timeout_ms <= self.ping_timeout_ms {
            return Err(GossipError::Config(
                "suspect_timeout_ms must be > ping_timeout_ms".to_string(),
            ));
        }

        if self.fanout == 0 {
            return Err(GossipError::Config("fanout must be > 0".to_string()));
        }

        if self.fanout > MAX_PEERS {
            return Err(GossipError::Config(format!(
                "fanout must be <= MAX_PEERS ({})",
                MAX_PEERS
            )));
        }

        if self.max_piggyback_updates == 0 {
            return Err(GossipError::Config(
                "max_piggyback_updates must be > 0".to_string(),
            ));
        }

        if self.max_piggyback_updates > MAX_PIGGYBACK_UPDATES {
            return Err(GossipError::Config(format!(
                "max_piggyback_updates must be <= MAX_PIGGYBACK_UPDATES ({})",
                MAX_PIGGYBACK_UPDATES
            )));
        }

        if self.seed_peers.len() > MAX_SEED_PEERS {
            return Err(GossipError::Config(format!(
                "seed_peers.len() must be <= MAX_SEED_PEERS ({})",
                MAX_SEED_PEERS
            )));
        }

        Ok(())
    }

    /// Set the probe interval (builder pattern).
    ///
    /// # Panics
    /// Panics if `ms == 0`
    #[inline]
    pub fn with_probe_interval(mut self, ms: u64) -> Self {
        assert!(ms > 0, "probe_interval_ms must be > 0");
        self.probe_interval_ms = ms;
        self
    }

    /// Set the ping timeout (builder pattern).
    ///
    /// # Panics
    /// Panics if `ms == 0`
    #[inline]
    pub fn with_ping_timeout(mut self, ms: u64) -> Self {
        assert!(ms > 0, "ping_timeout_ms must be > 0");
        self.ping_timeout_ms = ms;
        self
    }

    /// Set the suspect timeout (builder pattern).
    ///
    /// # Panics
    /// Panics if `ms == 0`
    #[inline]
    pub fn with_suspect_timeout(mut self, ms: u64) -> Self {
        assert!(ms > 0, "suspect_timeout_ms must be > 0");
        self.suspect_timeout_ms = ms;
        self
    }

    /// Set the fanout (builder pattern).
    ///
    /// # Panics
    /// Panics if `fanout == 0` or `fanout > MAX_PEERS`
    #[inline]
    pub fn with_fanout(mut self, fanout: usize) -> Self {
        assert!(fanout > 0, "fanout must be > 0");
        assert!(fanout <= MAX_PEERS, "fanout must be <= MAX_PEERS");
        self.fanout = fanout;
        self
    }

    /// Set the maximum piggyback updates (builder pattern).
    ///
    /// # Panics
    /// Panics if `max == 0` or `max > MAX_PIGGYBACK_UPDATES`
    #[inline]
    pub fn with_max_piggyback_updates(mut self, max: usize) -> Self {
        assert!(max > 0, "max_piggyback_updates must be > 0");
        assert!(
            max <= MAX_PIGGYBACK_UPDATES,
            "max_piggyback_updates must be <= MAX_PIGGYBACK_UPDATES"
        );
        self.max_piggyback_updates = max;
        self
    }

    /// Set the seed peers (builder pattern).
    ///
    /// # Panics
    /// Panics if `peers.len() > MAX_SEED_PEERS`
    #[inline]
    pub fn with_seed_peers(mut self, peers: Vec<SeedPeer>) -> Self {
        assert!(
            peers.len() <= MAX_SEED_PEERS,
            "seed_peers.len() must be <= MAX_SEED_PEERS"
        );
        self.seed_peers = peers;
        self
    }

    /// Add a single seed peer (builder pattern).
    ///
    /// # Panics
    /// Panics if adding would exceed MAX_SEED_PEERS
    #[inline]
    pub fn with_seed_peer(mut self, actor_id: ActorId, addr: SocketAddr) -> Self {
        assert!(
            self.seed_peers.len() < MAX_SEED_PEERS,
            "cannot add more seed peers, MAX_SEED_PEERS reached"
        );
        self.seed_peers.push(SeedPeer::new(actor_id, addr));
        self
    }

    /// Create a configuration optimized for LAN environments.
    ///
    /// Uses faster timeouts suitable for low-latency networks.
    #[inline]
    pub fn for_lan() -> Self {
        Self {
            probe_interval_ms: 500,
            ping_timeout_ms: 200,
            suspect_timeout_ms: 1000,
            fanout: 3,
            max_piggyback_updates: MAX_PIGGYBACK_UPDATES,
            seed_peers: Vec::new(),
        }
    }

    /// Create a configuration optimized for WAN environments.
    ///
    /// Uses longer timeouts to accommodate higher latency.
    #[inline]
    pub fn for_wan() -> Self {
        Self {
            probe_interval_ms: 2000,
            ping_timeout_ms: 2000,
            suspect_timeout_ms: 10000,
            fanout: 4,
            max_piggyback_updates: MAX_PIGGYBACK_UPDATES,
            seed_peers: Vec::new(),
        }
    }

    /// Create a configuration optimized for testing.
    ///
    /// Uses very short timeouts for fast test execution.
    #[inline]
    pub fn for_testing() -> Self {
        Self {
            probe_interval_ms: 50,
            ping_timeout_ms: 25,
            suspect_timeout_ms: 100,
            fanout: 2,
            max_piggyback_updates: 8,
            seed_peers: Vec::new(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GossipConfig::default();

        assert_eq!(config.probe_interval_ms, PROBE_INTERVAL_MS);
        assert_eq!(config.ping_timeout_ms, PING_TIMEOUT_MS);
        assert_eq!(config.suspect_timeout_ms, SUSPECT_TIMEOUT_MS);
        assert_eq!(config.fanout, GOSSIP_FANOUT);
        assert_eq!(config.max_piggyback_updates, MAX_PIGGYBACK_UPDATES);
    }

    #[test]
    fn test_default_validates() {
        let config = GossipConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let config = GossipConfig::new()
            .with_probe_interval(500)
            .with_ping_timeout(200)
            .with_suspect_timeout(2000)
            .with_fanout(5)
            .with_max_piggyback_updates(8);

        assert_eq!(config.probe_interval_ms, 500);
        assert_eq!(config.ping_timeout_ms, 200);
        assert_eq!(config.suspect_timeout_ms, 2000);
        assert_eq!(config.fanout, 5);
        assert_eq!(config.max_piggyback_updates, 8);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_probe_interval() {
        let mut config = GossipConfig::default();
        config.probe_interval_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_ping_timeout() {
        let mut config = GossipConfig::default();
        config.ping_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_suspect_not_greater_than_ping() {
        let mut config = GossipConfig::default();
        config.suspect_timeout_ms = config.ping_timeout_ms;
        assert!(config.validate().is_err());

        config.suspect_timeout_ms = config.ping_timeout_ms - 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_fanout() {
        let mut config = GossipConfig::default();
        config.fanout = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_fanout_exceeds_max() {
        let mut config = GossipConfig::default();
        config.fanout = MAX_PEERS + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_piggyback() {
        let mut config = GossipConfig::default();
        config.max_piggyback_updates = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_piggyback_exceeds_max() {
        let mut config = GossipConfig::default();
        config.max_piggyback_updates = MAX_PIGGYBACK_UPDATES + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    #[should_panic(expected = "probe_interval_ms must be > 0")]
    fn test_with_probe_interval_zero_panics() {
        let _ = GossipConfig::default().with_probe_interval(0);
    }

    #[test]
    #[should_panic(expected = "ping_timeout_ms must be > 0")]
    fn test_with_ping_timeout_zero_panics() {
        let _ = GossipConfig::default().with_ping_timeout(0);
    }

    #[test]
    #[should_panic(expected = "fanout must be > 0")]
    fn test_with_fanout_zero_panics() {
        let _ = GossipConfig::default().with_fanout(0);
    }

    #[test]
    #[should_panic(expected = "fanout must be <= MAX_PEERS")]
    fn test_with_fanout_exceeds_max_panics() {
        let _ = GossipConfig::default().with_fanout(MAX_PEERS + 1);
    }

    #[test]
    fn test_for_lan() {
        let config = GossipConfig::for_lan();
        assert!(config.validate().is_ok());
        assert!(config.ping_timeout_ms < GossipConfig::default().ping_timeout_ms);
    }

    #[test]
    fn test_for_wan() {
        let config = GossipConfig::for_wan();
        assert!(config.validate().is_ok());
        assert!(config.ping_timeout_ms > GossipConfig::default().ping_timeout_ms);
    }

    #[test]
    fn test_for_testing() {
        let config = GossipConfig::for_testing();
        assert!(config.validate().is_ok());
        assert!(config.probe_interval_ms < 100);
    }

    #[test]
    fn test_config_equality() {
        let config1 = GossipConfig::default();
        let config2 = GossipConfig::default();
        let config3 = GossipConfig::default().with_fanout(5);

        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_config_clone() {
        let config1 = GossipConfig::default().with_fanout(10);
        let config2 = config1.clone();

        assert_eq!(config1, config2);
    }
}
