//! Configuration: `ShardConfig` for one shard's tables and timers,
//! `DataplaneConfig` for the process (sockets, threads; filled from the
//! `[dataplane]` and `[transport]` sections in 1.5b, note §14).

use std::net::SocketAddr;
use std::time::Duration;

use crate::ids::{ShardId, MAX_SHARDS};
use crate::pool::BUF_SIZE;
use crate::shard::io::{RECV_BATCH, SEND_BATCH};
use crate::xs::XS_CREDIT;

/// Most shards a data plane runs. The fixed memory grows with the square
/// of the shard count: each pool holds `(shards − 1) × XS_CREDIT` buffers
/// for loans to its peers, and the mesh has a pair of rings per ordered
/// pair of shards (≈ 512 MB of pools at 16 shards, ≈ 8 GB at 64). Plan
/// 2.6 may retune `XS_CREDIT` and raise the cap.
pub const MAX_SHARDS_SUPPORTED: u16 = 16;
const _: () = assert!(MAX_SHARDS_SUPPORTED as usize <= MAX_SHARDS);

/// Smallest pool for `shards` shards: a receive and a send batch, plus a
/// full credit of loans to every peer, so lent buffers can never starve a
/// receive batch.
pub fn min_pool_buffers(shards: u16) -> u32 {
    assert!((1..=MAX_SHARDS_SUPPORTED).contains(&shards));
    let min = (RECV_BATCH + SEND_BATCH) as u32 + u32::from(shards - 1) * XS_CREDIT;
    debug_assert!(min <= ShardConfig::MAX_POOL_BUFFERS);
    min
}

/// Default pool for `shards` shards: 1,024 buffers of local headroom plus a
/// full credit to every peer (2 MB per shard at 1 shard, 8 MB at 4).
pub fn default_pool_buffers(shards: u16) -> u32 {
    assert!((1..=MAX_SHARDS_SUPPORTED).contains(&shards));
    let default = 1_024 + u32::from(shards - 1) * XS_CREDIT;
    debug_assert!(default >= min_pool_buffers(shards));
    default
}

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
            pool_buffers: default_pool_buffers(1),
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
    /// Number of shards, `1..=MAX_SHARDS_SUPPORTED`.
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
    /// Pin shard `i` to core `i` of the core list (best effort).
    pub cpu_affinity: bool,
    /// SCHED_FIFO priority 1..=99 for shard threads (Linux, best effort).
    pub realtime_priority: Option<u8>,
    /// Ports the shards must not use (signaling, API, metrics).
    pub reserved_ports: Vec<u16>,
    /// Seed of the shards' random numbers; `None` picks one per process.
    pub rng_seed: Option<u64>,
    /// Template for every shard (`shard` and `rng_seed` are set per shard);
    /// its `pool_buffers` must be at least `min_pool_buffers(shards)`.
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

/// Memory a data plane allocates at start, whatever its load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedMemory {
    /// One shard's packet pool.
    pub pool_bytes_per_shard: u64,
    /// Every cross-shard ring together (an estimate, `xs::mesh_bytes`).
    pub ring_bytes: u64,
}

impl FixedMemory {
    /// Pools of `shards` shards plus the rings.
    pub fn total(&self, shards: u16) -> u64 {
        self.pool_bytes_per_shard * u64::from(shards) + self.ring_bytes
    }
}

impl DataplaneConfig {
    /// Settings that are valid but risky; `validate` logs each one.
    pub fn warnings(&self) -> Vec<&'static str> {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        self.warnings_for(cores)
    }

    /// `warnings` on a machine with `cores` cores.
    pub fn warnings_for(&self, cores: usize) -> Vec<&'static str> {
        assert!(cores > 0);
        let mut warnings = Vec::new();
        // Shard i is pinned to core i, so shard 0 is on core 0, where
        // interrupts and often the control plane run; a SCHED_FIFO thread
        // that busy-polls there can starve them.
        if self.realtime_priority.is_some() && self.busy_poll_rounds > 0 && self.cpu_affinity {
            warnings.push(
                "realtime_priority with busy_poll_rounds > 0 and cpu_affinity: shard i \
                 busy-polls as SCHED_FIFO on core i, shard 0 on core 0, and can starve \
                 other work there",
            );
        }
        // More SCHED_FIFO busy-pollers than cores: the ones beyond the core
        // list run unpinned, sharing cores, and can starve every other thread.
        let over = usize::from(self.shards) > cores;
        if over && self.realtime_priority.is_some() && self.busy_poll_rounds > 0 {
            warnings.push(
                "realtime_priority with busy_poll_rounds > 0 and more shards than cores: \
                 SCHED_FIFO shards busy-poll unpinned on shared cores and can starve every \
                 other thread",
            );
        }
        if over {
            warnings.push(
                "more shards than cores: shards share cores, and with cpu_affinity the \
                 shards beyond the core list run unpinned",
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
        if self.shards == 0 {
            return Err(ConfigError("shards must be at least 1"));
        }
        if self.shards > MAX_SHARDS_SUPPORTED {
            // `ConfigError` holds a static string: the value is the
            // constant's, never repeated here (the binary formats it).
            return Err(ConfigError(
                "shards above MAX_SHARDS_SUPPORTED (pools and cross-shard rings grow with \
                 shards²)",
            ));
        }
        self.validate_ports()?;
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
        if self.shard.pool_buffers < min_pool_buffers(self.shards) {
            return Err(ConfigError(
                "pool_buffers below RECV_BATCH + SEND_BATCH + (shards - 1) × XS_CREDIT",
            ));
        }
        self.shard.validate()
    }

    /// The media port range `port..port + shards` fits and avoids the
    /// reserved ports (port 0: every shard gets an ephemeral port).
    fn validate_ports(&self) -> Result<(), ConfigError> {
        let port = self.bind_addr.port();
        if port == 0 {
            return Ok(());
        }
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
        Ok(())
    }

    /// Pool and ring memory this configuration allocates at start.
    pub fn fixed_memory(&self) -> FixedMemory {
        assert!((1..=MAX_SHARDS_SUPPORTED).contains(&self.shards));
        FixedMemory {
            pool_bytes_per_shard: u64::from(self.shard.pool_buffers) * BUF_SIZE as u64,
            ring_bytes: crate::xs::mesh_bytes(self.shards),
        }
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
                shards: MAX_SHARDS_SUPPORTED + 1,
                ..base.clone()
            },
            DataplaneConfig {
                shards: 65,
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

    /// `shards` shards with the default pool for that count.
    fn with_shards(shards: u16) -> DataplaneConfig {
        let mut config = DataplaneConfig {
            shards,
            reserved_ports: vec![8080, 8081, 9090],
            ..Default::default()
        };
        config.shard.pool_buffers = default_pool_buffers(shards);
        config
    }

    #[test]
    fn several_shards_are_accepted_up_to_the_cap() {
        for shards in 2..=4 {
            assert_eq!(with_shards(shards).validate(), Ok(()), "{shards} shards");
        }
        assert_eq!(with_shards(MAX_SHARDS_SUPPORTED).validate(), Ok(()));
        for shards in [MAX_SHARDS_SUPPORTED + 1, 65] {
            let config = DataplaneConfig {
                shards,
                ..with_shards(MAX_SHARDS_SUPPORTED)
            };
            assert!(config.validate().is_err(), "{shards} shards");
        }
    }

    #[test]
    fn the_pool_must_cover_a_credit_per_peer() {
        assert_eq!(min_pool_buffers(1), 320);
        assert_eq!(min_pool_buffers(2), 1_344);
        assert_eq!(default_pool_buffers(1), 1_024);
        assert_eq!(default_pool_buffers(4), 4_096);
        let mut config = with_shards(2);
        config.shard.pool_buffers = 1_343;
        assert!(config.validate().is_err(), "below the minimum");
        config.shard.pool_buffers = 1_344;
        assert_eq!(config.validate(), Ok(()));
        // A one-shard pool is too small for two shards.
        config.shard.pool_buffers = default_pool_buffers(1);
        assert!(config.validate().is_err());
        for shards in 1..=MAX_SHARDS_SUPPORTED {
            assert_eq!(with_shards(shards).validate(), Ok(()), "{shards} shards");
        }
    }

    #[test]
    fn the_port_range_of_every_shard_is_checked() {
        let range = |port: u16, reserved: u16| DataplaneConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            reserved_ports: vec![reserved],
            ..with_shards(4)
        };
        assert!(range(10_000, 10_003).validate().is_err(), "shard 3's port");
        assert_eq!(range(10_000, 10_004).validate(), Ok(()));
        assert_eq!(range(10_001, 10_000).validate(), Ok(()));
        let top = DataplaneConfig {
            bind_addr: "0.0.0.0:65535".parse().unwrap(),
            ..with_shards(2)
        };
        assert!(top.validate().is_err(), "shard 1 would need port 65536");
    }

    #[test]
    fn fixed_memory_follows_the_shard_count() {
        let one = with_shards(1).fixed_memory();
        assert_eq!(one.pool_bytes_per_shard, 2 << 20);
        assert_eq!(one.ring_bytes, 0);
        assert_eq!(one.total(1), 2 << 20);
        let four = with_shards(4).fixed_memory();
        assert_eq!(four.pool_bytes_per_shard, 8 << 20);
        assert_eq!(four.ring_bytes, 12 * (crate::xs::mesh_bytes(2) / 2));
        assert_eq!(four.total(4), (32 << 20) + four.ring_bytes);
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
        assert_eq!(risky.warnings_for(4).len(), 1);
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
            assert!(fine.warnings_for(4).is_empty(), "{fine:?}");
        }
    }

    #[test]
    fn more_shards_than_cores_warns() {
        assert!(with_shards(4).warnings_for(4).is_empty());
        let over = with_shards(8);
        assert_eq!(over.validate(), Ok(()), "a warning, not an error");
        assert_eq!(over.warnings_for(4).len(), 1);
        assert_eq!(over.warnings_for(8).len(), 0);
        let realtime = DataplaneConfig {
            realtime_priority: Some(50),
            busy_poll_rounds: 256,
            ..over.clone()
        };
        assert_eq!(realtime.warnings_for(8).len(), 0);
        let got = realtime.warnings_for(4);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].contains("SCHED_FIFO shards busy-poll unpinned"));
        let parked = DataplaneConfig {
            busy_poll_rounds: 0,
            ..realtime
        };
        assert_eq!(
            parked.warnings_for(4).len(),
            1,
            "parking shards do not starve cores"
        );
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
