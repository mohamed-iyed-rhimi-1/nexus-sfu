//! Migration metrics tracking
//!
//! Lock-free atomic counters for migration statistics.

use std::sync::atomic::{AtomicU64, Ordering};

/// Migration metrics collector
pub struct MigrationMetrics {
    /// Total migrations started
    pub migrations_started: AtomicU64,
    /// Total migrations completed successfully
    pub migrations_completed: AtomicU64,
    /// Total migrations failed
    pub migrations_failed: AtomicU64,
    /// Total migrations aborted (timeout)
    pub migrations_aborted: AtomicU64,
    /// Sum of migration latencies (nanos)
    pub migration_latency_sum_nanos: AtomicU64,
    /// Count of latency samples
    pub migration_latency_count: AtomicU64,
    /// Packets lost during migration
    pub packets_lost_during_migration: AtomicU64,
    /// Packets duplicated during migration
    pub packets_duplicated_during_migration: AtomicU64,
    /// Sequence number gaps detected
    pub sequence_gaps_detected: AtomicU64,
}

impl MigrationMetrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            migrations_started: AtomicU64::new(0),
            migrations_completed: AtomicU64::new(0),
            migrations_failed: AtomicU64::new(0),
            migrations_aborted: AtomicU64::new(0),
            migration_latency_sum_nanos: AtomicU64::new(0),
            migration_latency_count: AtomicU64::new(0),
            packets_lost_during_migration: AtomicU64::new(0),
            packets_duplicated_during_migration: AtomicU64::new(0),
            sequence_gaps_detected: AtomicU64::new(0),
        }
    }

    /// Record migration start
    pub fn record_start(&self) {
        self.migrations_started.fetch_add(1, Ordering::Relaxed);
    }

    /// Record migration completion
    ///
    /// # Assertions
    /// - latency_nanos > 0
    pub fn record_completion(&self, latency_nanos: u64) {
        assert!(latency_nanos > 0, "latency must be > 0");
        self.migrations_completed.fetch_add(1, Ordering::Relaxed);
        self.migration_latency_sum_nanos
            .fetch_add(latency_nanos, Ordering::Relaxed);
        self.migration_latency_count
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record migration failure
    pub fn record_failure(&self) {
        self.migrations_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record migration abort
    pub fn record_abort(&self) {
        self.migrations_aborted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record packet loss
    pub fn record_packet_loss(&self, count: u64) {
        self.packets_lost_during_migration
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Record packet duplication
    pub fn record_packet_duplication(&self, count: u64) {
        self.packets_duplicated_during_migration
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Record sequence gap
    pub fn record_sequence_gap(&self) {
        self.sequence_gaps_detected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get average migration latency (nanos)
    pub fn average_latency_nanos(&self) -> u64 {
        let sum = self
            .migration_latency_sum_nanos
            .load(Ordering::Relaxed);
        let count = self.migration_latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        sum / count
    }

    /// Get success rate (0-100)
    pub fn success_rate_percent(&self) -> u8 {
        let completed = self.migrations_completed.load(Ordering::Relaxed);
        let failed = self.migrations_failed.load(Ordering::Relaxed);
        let aborted = self.migrations_aborted.load(Ordering::Relaxed);
        let total = completed + failed + aborted;

        if total == 0 {
            return 100;
        }

        ((completed * 100) / total) as u8
    }
}

impl Default for MigrationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time assertions
const _: () = {
    assert!(std::mem::size_of::<MigrationMetrics>() <= 128);
};

/// Forwarding metrics for bandwidth and quality tracking
pub struct ForwardingMetrics {
    /// Layer switches total
    pub layer_switches: AtomicU64,
    /// Layer upgrades (to higher quality)
    pub layer_upgrades: AtomicU64,
    /// Layer downgrades (to lower quality)
    pub layer_downgrades: AtomicU64,
    /// Allocated bandwidth (bps)
    pub allocated_bandwidth_bps: AtomicU64,
    /// Used bandwidth (bps)
    pub used_bandwidth_bps: AtomicU64,
    /// Utilization percent × 100 (for precision)
    pub utilization_percent_x100: AtomicU64,
    /// Quality score (0-100)
    pub quality_score: AtomicU64,
}

impl ForwardingMetrics {
    /// Create new forwarding metrics
    pub fn new() -> Self {
        Self {
            layer_switches: AtomicU64::new(0),
            layer_upgrades: AtomicU64::new(0),
            layer_downgrades: AtomicU64::new(0),
            allocated_bandwidth_bps: AtomicU64::new(0),
            used_bandwidth_bps: AtomicU64::new(0),
            utilization_percent_x100: AtomicU64::new(0),
            quality_score: AtomicU64::new(0),
        }
    }

    /// Record layer switch
    pub fn record_layer_switch(&self, old_layer: u8, new_layer: u8) {
        self.layer_switches.fetch_add(1, Ordering::Relaxed);
        
        if new_layer > old_layer {
            self.layer_upgrades.fetch_add(1, Ordering::Relaxed);
        } else if new_layer < old_layer {
            self.layer_downgrades.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update bandwidth utilization
    ///
    /// # Assertions
    /// - utilization_percent_x100 <= 10000 (100% × 100)
    pub fn update_bandwidth(&self, allocated: u64, used: u64) {
        self.allocated_bandwidth_bps.store(allocated, Ordering::Relaxed);
        self.used_bandwidth_bps.store(used, Ordering::Relaxed);
        
        if allocated > 0 {
            let utilization = (used * 10000) / allocated;
            assert!(
                utilization <= 10000,
                "Utilization exceeds 100%: {}",
                utilization
            );
            self.utilization_percent_x100.store(utilization, Ordering::Relaxed);
        } else {
            self.utilization_percent_x100.store(0, Ordering::Relaxed);
        }
    }

    /// Calculate and store quality score
    ///
    /// Quality score = (current_layer / max_layer) × 100
    ///
    /// # Assertions
    /// - quality_score <= 100
    pub fn calculate_quality_score(&self, current_layer: u8, max_layer: u8) -> u32 {
        if max_layer == 0 {
            return 0;
        }
        
        let score = ((current_layer as u32) * 100) / (max_layer as u32);
        assert!(score <= 100, "Quality score exceeds 100: {}", score);
        
        self.quality_score.store(score as u64, Ordering::Relaxed);
        score
    }

    /// Get current quality score
    pub fn quality_score(&self) -> u32 {
        self.quality_score.load(Ordering::Relaxed) as u32
    }

    /// Get utilization percent (0-100)
    pub fn utilization_percent(&self) -> f64 {
        let util_x100 = self.utilization_percent_x100.load(Ordering::Relaxed);
        (util_x100 as f64) / 100.0
    }
}

impl Default for ForwardingMetrics {
    fn default() -> Self {
        Self::new()
    }
}
