//! SFU metrics collector
//!
//! Lock-free atomic counters for packet forwarding, bandwidth, and entity counts.
//! All hot-path operations use Ordering::Relaxed for maximum performance.

use std::sync::atomic::{AtomicU64, Ordering};

/// SFU metrics collector
///
/// # TigerStyle Compliance
/// - Lock-free atomic counters for hot path
/// - Pre-allocated latency histogram
/// - Explicitly-sized types (u64, u32)
pub struct SfuMetrics {
    // Packet metrics
    packets_received_total: AtomicU64,
    packets_forwarded_total: AtomicU64,
    packets_dropped_total: AtomicU64,

    // Bandwidth metrics (bytes)
    bytes_received_total: AtomicU64,
    bytes_forwarded_total: AtomicU64,

    // Latency tracking (nanoseconds)
    forwarding_latency_sum_nanos: AtomicU64,
    forwarding_latency_count: AtomicU64,

    // Latency histogram buckets (pre-allocated)
    // Buckets: <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, >500ms
    latency_bucket_1ms: AtomicU64,
    latency_bucket_5ms: AtomicU64,
    latency_bucket_10ms: AtomicU64,
    latency_bucket_50ms: AtomicU64,
    latency_bucket_100ms: AtomicU64,
    latency_bucket_500ms: AtomicU64,
    latency_bucket_inf: AtomicU64,

    // Entity counts (gauges)
    active_tracks: AtomicU64,
    active_participants: AtomicU64,
    active_rooms: AtomicU64,
}

impl SfuMetrics {
    pub fn new() -> Self {
        Self {
            packets_received_total: AtomicU64::new(0),
            packets_forwarded_total: AtomicU64::new(0),
            packets_dropped_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            bytes_forwarded_total: AtomicU64::new(0),
            forwarding_latency_sum_nanos: AtomicU64::new(0),
            forwarding_latency_count: AtomicU64::new(0),
            latency_bucket_1ms: AtomicU64::new(0),
            latency_bucket_5ms: AtomicU64::new(0),
            latency_bucket_10ms: AtomicU64::new(0),
            latency_bucket_50ms: AtomicU64::new(0),
            latency_bucket_100ms: AtomicU64::new(0),
            latency_bucket_500ms: AtomicU64::new(0),
            latency_bucket_inf: AtomicU64::new(0),
            active_tracks: AtomicU64::new(0),
            active_participants: AtomicU64::new(0),
            active_rooms: AtomicU64::new(0),
        }
    }

    /// Record packet received
    ///
    /// # Assertions
    /// - bytes > 0
    #[inline(always)]
    pub fn record_packet_received(&self, bytes: u32) {
        assert!(bytes > 0, "bytes must be > 0");
        self.packets_received_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_received_total.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record packet forwarded
    ///
    /// # Assertions
    /// - bytes > 0
    /// - latency_nanos > 0
    #[inline(always)]
    pub fn record_packet_forwarded(&self, bytes: u32, latency_nanos: u64) {
        assert!(bytes > 0, "bytes must be > 0");
        assert!(latency_nanos > 0, "latency_nanos must be > 0");
        
        self.packets_forwarded_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded_total.fetch_add(bytes as u64, Ordering::Relaxed);

        // Update latency stats
        self.forwarding_latency_sum_nanos.fetch_add(latency_nanos, Ordering::Relaxed);
        self.forwarding_latency_count.fetch_add(1, Ordering::Relaxed);

        // Update histogram bucket
        let latency_ms = latency_nanos / 1_000_000;
        if latency_ms < 1 {
            self.latency_bucket_1ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 5 {
            self.latency_bucket_5ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 10 {
            self.latency_bucket_10ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 50 {
            self.latency_bucket_50ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 100 {
            self.latency_bucket_100ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 500 {
            self.latency_bucket_500ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_bucket_inf.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record packet dropped
    #[inline(always)]
    pub fn record_packet_dropped(&self) {
        self.packets_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Set active track count
    pub fn set_active_tracks(&self, count: u64) {
        self.active_tracks.store(count, Ordering::Relaxed);
    }

    /// Set active participant count
    pub fn set_active_participants(&self, count: u64) {
        self.active_participants.store(count, Ordering::Relaxed);
    }

    /// Set active room count
    pub fn set_active_rooms(&self, count: u64) {
        self.active_rooms.store(count, Ordering::Relaxed);
    }

    /// Get average forwarding latency (milliseconds)
    pub fn avg_forwarding_latency_ms(&self) -> f64 {
        let sum = self.forwarding_latency_sum_nanos.load(Ordering::Relaxed);
        let count = self.forwarding_latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1_000_000.0
    }

    /// Get P50 latency estimate (milliseconds)
    ///
    /// Calculated from histogram buckets
    pub fn p50_latency_ms(&self) -> f64 {
        let total = self.forwarding_latency_count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        let p50_target = total / 2;
        let mut cumulative = 0u64;

        cumulative += self.latency_bucket_1ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 0.5;
        }

        cumulative += self.latency_bucket_5ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 3.0;
        }

        cumulative += self.latency_bucket_10ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 7.5;
        }

        cumulative += self.latency_bucket_50ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 30.0;
        }

        cumulative += self.latency_bucket_100ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 75.0;
        }

        cumulative += self.latency_bucket_500ms.load(Ordering::Relaxed);
        if cumulative >= p50_target {
            return 300.0;
        }

        500.0
    }

    /// Get P99 latency estimate (milliseconds)
    pub fn p99_latency_ms(&self) -> f64 {
        let total = self.forwarding_latency_count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        let p99_target = (total * 99) / 100;
        let mut cumulative = 0u64;

        cumulative += self.latency_bucket_1ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 1.0;
        }

        cumulative += self.latency_bucket_5ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 5.0;
        }

        cumulative += self.latency_bucket_10ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 10.0;
        }

        cumulative += self.latency_bucket_50ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 50.0;
        }

        cumulative += self.latency_bucket_100ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 100.0;
        }

        cumulative += self.latency_bucket_500ms.load(Ordering::Relaxed);
        if cumulative >= p99_target {
            return 500.0;
        }

        1000.0
    }

    // Getters for Prometheus
    pub fn packets_received_total(&self) -> u64 {
        self.packets_received_total.load(Ordering::Relaxed)
    }

    pub fn packets_forwarded_total(&self) -> u64 {
        self.packets_forwarded_total.load(Ordering::Relaxed)
    }

    pub fn packets_dropped_total(&self) -> u64 {
        self.packets_dropped_total.load(Ordering::Relaxed)
    }

    pub fn bytes_received_total(&self) -> u64 {
        self.bytes_received_total.load(Ordering::Relaxed)
    }

    pub fn bytes_forwarded_total(&self) -> u64 {
        self.bytes_forwarded_total.load(Ordering::Relaxed)
    }

    pub fn active_tracks(&self) -> u64 {
        self.active_tracks.load(Ordering::Relaxed)
    }

    pub fn active_participants(&self) -> u64 {
        self.active_participants.load(Ordering::Relaxed)
    }

    pub fn active_rooms(&self) -> u64 {
        self.active_rooms.load(Ordering::Relaxed)
    }

    /// Get histogram bucket counts for Prometheus export
    pub fn latency_bucket_counts(&self) -> [(f64, u64); 7] {
        [
            (0.001, self.latency_bucket_1ms.load(Ordering::Relaxed)),
            (0.005, self.latency_bucket_5ms.load(Ordering::Relaxed)),
            (0.010, self.latency_bucket_10ms.load(Ordering::Relaxed)),
            (0.050, self.latency_bucket_50ms.load(Ordering::Relaxed)),
            (0.100, self.latency_bucket_100ms.load(Ordering::Relaxed)),
            (0.500, self.latency_bucket_500ms.load(Ordering::Relaxed)),
            (f64::INFINITY, self.latency_bucket_inf.load(Ordering::Relaxed)),
        ]
    }

    /// Get latency sum in seconds for Prometheus
    pub fn forwarding_latency_sum_seconds(&self) -> f64 {
        self.forwarding_latency_sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    /// Get latency count for Prometheus
    pub fn forwarding_latency_count(&self) -> u64 {
        self.forwarding_latency_count.load(Ordering::Relaxed)
    }
}

impl Default for SfuMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time size assertion
const _: () = {
    assert!(std::mem::size_of::<SfuMetrics>() <= 256);
};
