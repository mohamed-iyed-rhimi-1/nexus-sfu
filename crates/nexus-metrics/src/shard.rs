//! Data-plane shard metrics (design note §5.4).
//!
//! The shards publish their counters and gauges once per second
//! (`nexus_dataplane::ShardStats`). This module does not copy them: the server
//! installs a source that reads a shard's latest snapshot, and the exporter calls it
//! when `/metrics` is rendered.

use std::sync::OnceLock;

use nexus_dataplane::ShardStatsSnapshot;

/// Reads shard `i`'s latest published stats.
pub type ShardStatsSource = Box<dyn Fn(usize) -> ShardStatsSnapshot + Send + Sync>;

/// The shards whose stats are exported, and where to read them.
pub struct ShardMetrics {
    shards: usize,
    source: OnceLock<ShardStatsSource>,
}

impl ShardMetrics {
    /// Metrics for `shards` shards; nothing is exported until `set_source`.
    pub fn new(shards: usize) -> Self {
        assert!(shards > 0, "shards must be > 0");
        Self {
            shards,
            source: OnceLock::new(),
        }
    }

    /// Number of shards.
    pub fn shards(&self) -> usize {
        self.shards
    }

    /// Installs the stats source (once; a second call is refused and returns false).
    pub fn set_source(&self, source: ShardStatsSource) -> bool {
        self.source.set(source).is_ok()
    }

    /// Shard `index`'s latest stats; `None` before a source is installed.
    pub fn snapshot(&self, index: usize) -> Option<ShardStatsSnapshot> {
        assert!(index < self.shards, "shard index out of range");
        self.source.get().map(|source| source(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_snapshot_before_a_source_and_one_source_only() {
        let metrics = ShardMetrics::new(2);
        assert!(metrics.snapshot(1).is_none());
        let source: ShardStatsSource = Box::new(|i| {
            let mut s = ShardStatsSnapshot::default();
            s.counters.rx_datagrams = 10 + i as u64;
            s
        });
        assert!(metrics.set_source(source));
        assert!(!metrics.set_source(Box::new(|_| ShardStatsSnapshot::default())));
        assert_eq!(metrics.snapshot(1).unwrap().counters.rx_datagrams, 11);
    }
}
