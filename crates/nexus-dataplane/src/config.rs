//! Shard configuration. The process-level `DataplaneConfig` (sockets,
//! threads, `[dataplane]` section) comes in 1.3.

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
        if self.rebind_silence >= self.consent_timeout {
            return Err(ConfigError("rebind_silence must be below consent_timeout"));
        }
        Ok(())
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
        ];
        for config in bad {
            assert!(config.validate().is_err());
        }
    }
}
