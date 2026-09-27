//! Configuration: `ShardConfig` for one shard's tables and timers,
//! `DataplaneConfig` for the process (sockets, threads; filled from the
//! `[dataplane]` and `[transport]` sections in 1.5b, note §14).

use std::net::SocketAddr;
use std::time::Duration;

use crate::ids::ShardId;
use crate::shard::io::{RECV_BATCH, SEND_BATCH};

/// Settings of one shard.
#[derive(Clone, Debug)]
pub struct ShardConfig {
    /// This shard's index.
    pub shard: ShardId,
    /// Buffers in the shard's pool, 2,048 bytes each (note §10.3).
    pub pool_buffers: u32,
    /// Most sessions the shard holds.
    pub max_sessions: u32,
    /// No authenticated traffic for this long → `ConsentLost` (note §8.5).
    pub consent_timeout: Duration,
    /// Silence of the selected address before a rebind is accepted (note §8.4).
    pub rebind_silence: Duration,
    /// Seed of the shard's random numbers (rewrite offsets).
    pub rng_seed: u64,
    /// DTLS datagrams all sessions together may pass to the control plane
    /// per housekeeping sweep (1 s): many sessions that never finish DTLS
    /// cannot fill the event channel every shard shares.
    pub dtls_budget_per_sweep: u32,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shard: ShardId::new(0),
            pool_buffers: 1_024,
            max_sessions: 1_000,
            consent_timeout: Duration::from_secs(30),
            rebind_silence: Duration::from_secs(2),
            rng_seed: 0x6E65_7875_735F_7366,
            dtls_budget_per_sweep: 1_024,
        }
    }
}

/// An invalid shard setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

impl ShardConfig {
    /// Most buffers a pool may have (indices are `u32`, memory stays sane).
    pub const MAX_POOL_BUFFERS: u32 = 1 << 20;

    /// Checks every field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let min_pool = (RECV_BATCH + SEND_BATCH) as u32;
        if self.pool_buffers < min_pool {
            return Err(ConfigError(
                "pool_buffers must cover a receive and a send batch",
            ));
        }
        if self.pool_buffers > Self::MAX_POOL_BUFFERS {
            return Err(ConfigError("pool_buffers too large"));
        }
        if self.max_sessions == 0 {
            return Err(ConfigError("max_sessions must be positive"));
        }
        if self.consent_timeout.is_zero() || self.rebind_silence.is_zero() {
            return Err(ConfigError("timeouts must be positive"));
        }
        if self.dtls_budget_per_sweep == 0 {
            return Err(ConfigError("dtls_budget_per_sweep must be positive"));
        }
        if self.rebind_silence >= self.consent_timeout {
            return Err(ConfigError("rebind_silence must be below consent_timeout"));
        }
        Ok(())
    }
}

/// Settings of the data plane: shard count, sockets, threads (note §14).
#[derive(Clone, Debug)]
pub struct DataplaneConfig {
    /// Number of shards; 1 in Phase 1.
    pub shards: u16,
    /// Base address: shard `i` binds `ip:(port + i)`; port 0 gives every
    /// shard its own ephemeral port (note §13.3).
    pub bind_addr: SocketAddr,
    /// Socket receive buffer (SO_RCVBUF) requested per shard.
    pub recv_buffer_bytes: u32,
    /// Socket send buffer (SO_SNDBUF) requested per shard.
    pub send_buffer_bytes: u32,
    /// Idle iterations before a shard parks (note §3.3).
    pub busy_poll_rounds: u32,
    /// Pin shard `i` to core `i` (best effort).
    pub cpu_affinity: bool,
    /// SCHED_FIFO priority 1..=99 for shard threads (Linux, best effort).
    pub realtime_priority: Option<u8>,
    /// Ports the shards must not use (signaling, API, metrics).
    pub reserved_ports: Vec<u16>,
    /// Seed of the shards' random numbers; `None` picks one per process.
    pub rng_seed: Option<u64>,
    /// Template for every shard (`shard` and `rng_seed` are set per shard).
    pub shard: ShardConfig,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            shards: 1,
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 10_000)),
            recv_buffer_bytes: 8 << 20,
            send_buffer_bytes: 8 << 20,
            busy_poll_rounds: 0,
            cpu_affinity: false,
            realtime_priority: None,
            reserved_ports: Vec::new(),
            rng_seed: None,
            shard: ShardConfig::default(),
        }
    }
}

impl DataplaneConfig {
    /// Most shards Phase 1 runs.
    pub const MAX_SHARDS_PHASE_1: u16 = 1;

    /// Settings that are valid but risky; `validate` logs each one.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        // Shard 0 is pinned to core 0, where interrupts and often the
        // control plane run; a SCHED_FIFO thread that busy-polls there can
        // starve them.
        if self.realtime_priority.is_some() && self.busy_poll_rounds > 0 && self.cpu_affinity {
            warnings.push(
                "realtime_priority with busy_poll_rounds > 0 and cpu_affinity: shard 0 \
                 busy-polls as SCHED_FIFO on core 0 and can starve other work there",
            );
        }
        warnings
    }

    /// Checks every field, including the shard template, and logs the
    /// `warnings`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for warning in self.warnings() {
            tracing::warn!("{warning}");
        }
        if self.shards == 0 || self.shards > Self::MAX_SHARDS_PHASE_1 {
            return Err(ConfigError("shards must be 1 in Phase 1"));
        }
        let port = self.bind_addr.port();
        if port != 0 {
            let last = u32::from(port) + u32::from(self.shards) - 1;
            if last > u32::from(u16::MAX) {
                return Err(ConfigError("media port range exceeds 65535"));
            }
            let conflict = (u32::from(port)..=last)
                .any(|p| self.reserved_ports.iter().any(|&r| u32::from(r) == p));
            if conflict {
                return Err(ConfigError(
                    "media port range overlaps the signaling, API or metrics port",
                ));
            }
        }
        let max = i32::MAX as u32;
        if !(1..=max).contains(&self.recv_buffer_bytes)
            || !(1..=max).contains(&self.send_buffer_bytes)
        {
            return Err(ConfigError("socket buffer sizes must be in 1..=i32::MAX"));
        }
        if self
            .realtime_priority
            .is_some_and(|p| !(1..=99).contains(&p))
        {
            return Err(ConfigError("realtime_priority must be in 1..=99"));
        }
        self.shard.validate()
    }

    /// Settings of shard `index`: the template with its id and seed.
    pub fn shard_config(&self, index: u8, process_seed: u64) -> ShardConfig {
        assert!(u16::from(index) < self.shards);
        let seed = self.rng_seed.unwrap_or(process_seed);
        ShardConfig {
            shard: ShardId::new(index),
            // Distinct per shard, deterministic for a given seed.
            rng_seed: seed ^ (u64::from(index) + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            ..self.shard.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert_eq!(ShardConfig::default().validate(), Ok(()));
    }

    #[test]
    fn invalid_settings_are_refused() {
        let bad = [
            ShardConfig {
                pool_buffers: 10,
                ..Default::default()
            },
            ShardConfig {
                max_sessions: 0,
                ..Default::default()
            },
            ShardConfig {
                rebind_silence: Duration::ZERO,
                ..Default::default()
            },
            ShardConfig {
                rebind_silence: Duration::from_secs(60),
                ..Default::default()
            },
            ShardConfig {
                dtls_budget_per_sweep: 0,
                ..Default::default()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn default_dataplane_is_valid() {
        assert_eq!(DataplaneConfig::default().validate(), Ok(()));
    }

    #[test]
    fn invalid_dataplane_settings_are_refused() {
        let base = DataplaneConfig {
            reserved_ports: vec![8080, 8081, 9090],
            ..Default::default()
        };
        let bad = [
            DataplaneConfig {
                shards: 0,
                ..base.clone()
            },
            DataplaneConfig {
                shards: 2,
                ..base.clone()
            },
            DataplaneConfig {
                bind_addr: "0.0.0.0:8081".parse().unwrap(),
                ..base.clone()
            },
            DataplaneConfig {
                recv_buffer_bytes: 0,
                ..base.clone()
            },
            DataplaneConfig {
                send_buffer_bytes: u32::MAX,
                ..base.clone()
            },
            DataplaneConfig {
                realtime_priority: Some(0),
                ..base.clone()
            },
            DataplaneConfig {
                realtime_priority: Some(100),
                ..base.clone()
            },
            DataplaneConfig {
                shard: ShardConfig {
                    max_sessions: 0,
                    ..Default::default()
                },
                ..base.clone()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "{config:?}");
        }
        let ephemeral = DataplaneConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            reserved_ports: vec![0],
            ..base.clone()
        };
        assert_eq!(ephemeral.validate(), Ok(()), "port 0 is never a conflict");
        let top = DataplaneConfig {
            bind_addr: "0.0.0.0:65535".parse().unwrap(),
            ..base
        };
        assert_eq!(top.validate(), Ok(()));
    }

    #[test]
    fn realtime_busy_poll_on_core_zero_warns() {
        let risky = DataplaneConfig {
            realtime_priority: Some(50),
            busy_poll_rounds: 256,
            cpu_affinity: true,
            ..Default::default()
        };
        assert_eq!(risky.validate(), Ok(()), "a warning, not an error");
        assert_eq!(risky.warnings().len(), 1);
        for fine in [
            DataplaneConfig {
                busy_poll_rounds: 0,
                ..risky.clone()
            },
            DataplaneConfig {
                realtime_priority: None,
                ..risky.clone()
            },
            DataplaneConfig {
                cpu_affinity: false,
                ..risky.clone()
            },
        ] {
            assert!(fine.warnings().is_empty(), "{fine:?}");
        }
    }

    #[test]
    fn shard_seeds_differ_and_follow_the_config() {
        let config = DataplaneConfig {
            rng_seed: Some(7),
            ..Default::default()
        };
        let a = config.shard_config(0, 1);
        let b = config.shard_config(0, 2);
        assert_eq!(a.rng_seed, b.rng_seed, "a configured seed wins");
        let random = DataplaneConfig::default();
        assert_ne!(
            random.shard_config(0, 1).rng_seed,
            random.shard_config(0, 2).rng_seed
        );
    }
}
