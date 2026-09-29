// `[dataplane]` section: shard count and shard settings of the new data plane
// (design note §14). Sockets and limits come from `[transport]`.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{ConfigError, NexusConfig};

/// Settings of the `[dataplane]` section. Every field has a default, so the
/// section may be left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataplaneSettings {
    /// Number of shards (one thread and one media port each),
    /// 1..=`nexus_dataplane::MAX_SHARDS_SUPPORTED` (16).
    pub shards: u16,
    /// Idle iterations before a shard parks; 0 parks as soon as it is idle.
    pub busy_poll_rounds: u32,
    /// Packet buffers per shard (2,048 bytes each). Unset: 1,024 plus a
    /// cross-shard credit per peer (`nexus_dataplane::default_pool_buffers`);
    /// set, it must be at least `min_pool_buffers(shards)`.
    pub pool_buffers: Option<u32>,
    /// No authenticated traffic for this long closes the session.
    pub consent_timeout_ms: u32,
    /// Silence of the selected address before a rebind is accepted.
    pub rebind_silence_ms: u32,
    /// Pin shard `i` to core `i` (best effort).
    pub cpu_affinity: bool,
    /// Run shard threads as SCHED_FIFO (Linux, best effort).
    pub realtime_priority: bool,
    /// SCHED_FIFO priority when `realtime_priority` is set (1..=99).
    pub realtime_priority_level: u32,
}

impl Default for DataplaneSettings {
    fn default() -> Self {
        Self {
            shards: 1,
            busy_poll_rounds: 0,
            pool_buffers: None,
            consent_timeout_ms: 30_000,
            rebind_silence_ms: 2_000,
            cpu_affinity: false,
            realtime_priority: false,
            realtime_priority_level: 80,
        }
    }
}

impl NexusConfig {
    /// The data plane's configuration: `[dataplane]` plus the media address,
    /// socket buffers and session limit of `[transport]`, with the signaling,
    /// API and metrics ports reserved.
    pub fn to_dataplane_config(&self) -> Result<nexus_dataplane::DataplaneConfig, ConfigError> {
        let settings = &self.dataplane;
        let max_shards = nexus_dataplane::MAX_SHARDS_SUPPORTED;
        if !(1..=max_shards).contains(&settings.shards) {
            return Err(ConfigError::invalid(
                "dataplane.shards",
                &format!(
                    "must be in 1..={max_shards} (pools and cross-shard rings grow with shards²)"
                ),
            ));
        }
        let realtime_priority = if settings.realtime_priority {
            let level = u8::try_from(settings.realtime_priority_level).map_err(|_| {
                ConfigError::invalid("dataplane.realtime_priority_level", "must be in 1..=99")
            })?;
            Some(level)
        } else {
            None
        };
        let max_sessions = self
            .transport
            .max_webrtc_sessions
            .div_ceil(u32::from(settings.shards));

        let mut config = nexus_dataplane::DataplaneConfig {
            shards: settings.shards,
            bind_addr: self.transport.media_bind_addr,
            recv_buffer_bytes: self.transport.recv_buffer_size_bytes,
            send_buffer_bytes: self.transport.send_buffer_size_bytes,
            busy_poll_rounds: settings.busy_poll_rounds,
            cpu_affinity: settings.cpu_affinity,
            realtime_priority,
            reserved_ports: self.reserved_ports()?,
            rng_seed: None,
            ..Default::default()
        };
        config.shard.pool_buffers = settings
            .pool_buffers
            .unwrap_or_else(|| nexus_dataplane::default_pool_buffers(settings.shards));
        config.shard.max_sessions = max_sessions;
        config.shard.consent_timeout = Duration::from_millis(settings.consent_timeout_ms.into());
        config.shard.rebind_silence = Duration::from_millis(settings.rebind_silence_ms.into());

        assert_eq!(config.shards, settings.shards);
        assert!(
            u64::from(max_sessions) * u64::from(settings.shards)
                >= u64::from(self.transport.max_webrtc_sessions)
        );
        Ok(config)
    }

    /// Ports the media sockets must not take: signaling, the API when it is
    /// enabled, and metrics. Port 0 (ephemeral) is never reserved.
    pub fn reserved_ports(&self) -> Result<Vec<u16>, ConfigError> {
        let mut ports = vec![self.transport.signaling_bind_addr.port()];
        if self.api.enabled {
            ports.push(parse_port("api.bind_addr", &self.api.bind_addr)?);
        }
        ports.push(parse_port("metrics.bind_addr", &self.metrics.bind_addr)?);
        ports.retain(|&p| p != 0);
        ports.sort_unstable();
        ports.dedup();
        assert!(ports.len() <= 3);
        Ok(ports)
    }

    /// Checks the `[dataplane]` section through the data plane's own rules.
    pub(super) fn validate_dataplane(&self) -> Result<(), ConfigError> {
        self.to_dataplane_config()?
            .validate()
            .map_err(|e| ConfigError::invalid("dataplane", e.0))
    }
}

fn parse_port(field: &str, addr: &str) -> Result<u16, ConfigError> {
    SocketAddr::from_str(addr)
        .map(|a| a.port())
        .map_err(|_| ConfigError::invalid(field, "must be a socket address (ip:port)"))
}
