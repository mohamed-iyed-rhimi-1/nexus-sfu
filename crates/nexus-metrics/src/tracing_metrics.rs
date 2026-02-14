//! Tracing-derived metrics integration.
//!
//! Provides metrics derived from tracing spans for hot-path latency
//! and packet rate monitoring.
//!
//! # Requirements Coverage
//!
//! - Requirement 12.5: Integrate tracing with metrics for forwarding latency
//!   histogram and packet rate counters
//!
//! # TigerStyle Compliance
//!
//! - Lock-free atomic counters
//! - Pre-allocated histogram buckets
//! - Explicitly-sized types

use std::sync::atomic::{AtomicU64, Ordering};

/// Tracing-derived metrics for hot-path operations.
///
/// These metrics are populated from the global HOT_PATH_METRICS
/// in the tracing module and exported to Prometheus.
pub struct TracingMetrics {
    // Receive latency tracking
    recv_latency_sum_ns: AtomicU64,
    recv_count: AtomicU64,

    // Forward latency tracking (primary metric)
    forward_latency_sum_ns: AtomicU64,
    forward_count: AtomicU64,

    // Send latency tracking
    send_latency_sum_ns: AtomicU64,
    send_count: AtomicU64,

    // Latency histogram buckets for forwarding (microseconds)
    // Buckets: <10us, <50us, <100us, <500us, <1ms, <5ms, <10ms, >10ms
    forward_bucket_10us: AtomicU64,
    forward_bucket_50us: AtomicU64,
    forward_bucket_100us: AtomicU64,
    forward_bucket_500us: AtomicU64,
    forward_bucket_1ms: AtomicU64,
    forward_bucket_5ms: AtomicU64,
    forward_bucket_10ms: AtomicU64,
    forward_bucket_inf: AtomicU64,

    // Packet rate tracking (packets per second)
    last_forward_count: AtomicU64,
    last_sample_time_ns: AtomicU64,
    packet_rate_pps: AtomicU64,
}

impl TracingMetrics {
    /// Create new tracing metrics.
    pub fn new() -> Self {
        Self {
            recv_latency_sum_ns: AtomicU64::new(0),
            recv_count: AtomicU64::new(0),
            forward_latency_sum_ns: AtomicU64::new(0),
            forward_count: AtomicU64::new(0),
            send_latency_sum_ns: AtomicU64::new(0),
            send_count: AtomicU64::new(0),
            forward_bucket_10us: AtomicU64::new(0),
            forward_bucket_50us: AtomicU64::new(0),
            forward_bucket_100us: AtomicU64::new(0),
            forward_bucket_500us: AtomicU64::new(0),
            forward_bucket_1ms: AtomicU64::new(0),
            forward_bucket_5ms: AtomicU64::new(0),
            forward_bucket_10ms: AtomicU64::new(0),
            forward_bucket_inf: AtomicU64::new(0),
            last_forward_count: AtomicU64::new(0),
            last_sample_time_ns: AtomicU64::new(0),
            packet_rate_pps: AtomicU64::new(0),
        }
    }

    /// Record a forward latency sample.
    ///
    /// Updates both the sum/count and the histogram bucket.
    ///
    /// # Arguments
    ///
    /// * `latency_ns` - Latency in nanoseconds
    #[inline(always)]
    pub fn record_forward_latency(&self, latency_ns: u64) {
        self.forward_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.forward_count.fetch_add(1, Ordering::Relaxed);

        // Update histogram bucket (convert to microseconds)
        let latency_us = latency_ns / 1000;
        if latency_us < 10 {
            self.forward_bucket_10us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 50 {
            self.forward_bucket_50us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 100 {
            self.forward_bucket_100us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 500 {
            self.forward_bucket_500us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 1000 {
            self.forward_bucket_1ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 5000 {
            self.forward_bucket_5ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 10000 {
            self.forward_bucket_10ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.forward_bucket_inf.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a receive latency sample.
    #[inline(always)]
    pub fn record_recv_latency(&self, latency_ns: u64) {
        self.recv_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.recv_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a send latency sample.
    #[inline(always)]
    pub fn record_send_latency(&self, latency_ns: u64) {
        self.send_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.send_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update packet rate calculation.
    ///
    /// Should be called periodically (e.g., every second) to update
    /// the packets-per-second rate.
    pub fn update_packet_rate(&self) {
        let current_count = self.forward_count.load(Ordering::Relaxed);
        let last_count = self.last_forward_count.swap(current_count, Ordering::Relaxed);

        let current_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let last_time_ns = self.last_sample_time_ns.swap(current_time_ns, Ordering::Relaxed);

        // Calculate rate if we have a valid time delta
        if last_time_ns > 0 && current_time_ns > last_time_ns {
            let delta_ns = current_time_ns - last_time_ns;
            let delta_count = current_count.saturating_sub(last_count);

            // Convert to packets per second
            if delta_ns > 0 {
                let rate = (delta_count as u128 * 1_000_000_000) / delta_ns as u128;
                self.packet_rate_pps.store(rate as u64, Ordering::Relaxed);
            }
        }
    }

    /// Get average forward latency in microseconds.
    pub fn avg_forward_latency_us(&self) -> f64 {
        let sum = self.forward_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.forward_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get average receive latency in microseconds.
    pub fn avg_recv_latency_us(&self) -> f64 {
        let sum = self.recv_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.recv_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get average send latency in microseconds.
    pub fn avg_send_latency_us(&self) -> f64 {
        let sum = self.send_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.send_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get current packet rate in packets per second.
    pub fn packet_rate_pps(&self) -> u64 {
        self.packet_rate_pps.load(Ordering::Relaxed)
    }

    /// Get total forward count.
    pub fn forward_count(&self) -> u64 {
        self.forward_count.load(Ordering::Relaxed)
    }

    /// Get total receive count.
    pub fn recv_count(&self) -> u64 {
        self.recv_count.load(Ordering::Relaxed)
    }

    /// Get total send count.
    pub fn send_count(&self) -> u64 {
        self.send_count.load(Ordering::Relaxed)
    }

    /// Get forward latency sum in seconds (for Prometheus).
    pub fn forward_latency_sum_seconds(&self) -> f64 {
        self.forward_latency_sum_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    /// Get histogram bucket counts for Prometheus export.
    ///
    /// Returns array of (bucket_upper_bound_seconds, cumulative_count).
    pub fn forward_latency_bucket_counts(&self) -> [(f64, u64); 8] {
        // Cumulative counts for Prometheus histogram
        let b10us = self.forward_bucket_10us.load(Ordering::Relaxed);
        let b50us = self.forward_bucket_50us.load(Ordering::Relaxed);
        let b100us = self.forward_bucket_100us.load(Ordering::Relaxed);
        let b500us = self.forward_bucket_500us.load(Ordering::Relaxed);
        let b1ms = self.forward_bucket_1ms.load(Ordering::Relaxed);
        let b5ms = self.forward_bucket_5ms.load(Ordering::Relaxed);
        let b10ms = self.forward_bucket_10ms.load(Ordering::Relaxed);
        let binf = self.forward_bucket_inf.load(Ordering::Relaxed);

        // Prometheus histograms are cumulative
        let c10us = b10us;
        let c50us = c10us + b50us;
        let c100us = c50us + b100us;
        let c500us = c100us + b500us;
        let c1ms = c500us + b1ms;
        let c5ms = c1ms + b5ms;
        let c10ms = c5ms + b10ms;
        let cinf = c10ms + binf;

        [
            (0.000010, c10us),   // 10us
            (0.000050, c50us),   // 50us
            (0.000100, c100us),  // 100us
            (0.000500, c500us),  // 500us
            (0.001000, c1ms),    // 1ms
            (0.005000, c5ms),    // 5ms
            (0.010000, c10ms),   // 10ms
            (f64::INFINITY, cinf),
        ]
    }

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> TracingMetricsSnapshot {
        TracingMetricsSnapshot {
            recv_latency_sum_ns: self.recv_latency_sum_ns.load(Ordering::Relaxed),
            recv_count: self.recv_count.load(Ordering::Relaxed),
            forward_latency_sum_ns: self.forward_latency_sum_ns.load(Ordering::Relaxed),
            forward_count: self.forward_count.load(Ordering::Relaxed),
            send_latency_sum_ns: self.send_latency_sum_ns.load(Ordering::Relaxed),
            send_count: self.send_count.load(Ordering::Relaxed),
            packet_rate_pps: self.packet_rate_pps.load(Ordering::Relaxed),
            forward_bucket_10us: self.forward_bucket_10us.load(Ordering::Relaxed),
            forward_bucket_50us: self.forward_bucket_50us.load(Ordering::Relaxed),
            forward_bucket_100us: self.forward_bucket_100us.load(Ordering::Relaxed),
            forward_bucket_500us: self.forward_bucket_500us.load(Ordering::Relaxed),
            forward_bucket_1ms: self.forward_bucket_1ms.load(Ordering::Relaxed),
            forward_bucket_5ms: self.forward_bucket_5ms.load(Ordering::Relaxed),
            forward_bucket_10ms: self.forward_bucket_10ms.load(Ordering::Relaxed),
            forward_bucket_inf: self.forward_bucket_inf.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.recv_latency_sum_ns.store(0, Ordering::Relaxed);
        self.recv_count.store(0, Ordering::Relaxed);
        self.forward_latency_sum_ns.store(0, Ordering::Relaxed);
        self.forward_count.store(0, Ordering::Relaxed);
        self.send_latency_sum_ns.store(0, Ordering::Relaxed);
        self.send_count.store(0, Ordering::Relaxed);
        self.forward_bucket_10us.store(0, Ordering::Relaxed);
        self.forward_bucket_50us.store(0, Ordering::Relaxed);
        self.forward_bucket_100us.store(0, Ordering::Relaxed);
        self.forward_bucket_500us.store(0, Ordering::Relaxed);
        self.forward_bucket_1ms.store(0, Ordering::Relaxed);
        self.forward_bucket_5ms.store(0, Ordering::Relaxed);
        self.forward_bucket_10ms.store(0, Ordering::Relaxed);
        self.forward_bucket_inf.store(0, Ordering::Relaxed);
        self.last_forward_count.store(0, Ordering::Relaxed);
        self.last_sample_time_ns.store(0, Ordering::Relaxed);
        self.packet_rate_pps.store(0, Ordering::Relaxed);
    }
}

impl Default for TracingMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of tracing metrics for export.
#[derive(Clone, Debug, Default)]
pub struct TracingMetricsSnapshot {
    pub recv_latency_sum_ns: u64,
    pub recv_count: u64,
    pub forward_latency_sum_ns: u64,
    pub forward_count: u64,
    pub send_latency_sum_ns: u64,
    pub send_count: u64,
    pub packet_rate_pps: u64,
    pub forward_bucket_10us: u64,
    pub forward_bucket_50us: u64,
    pub forward_bucket_100us: u64,
    pub forward_bucket_500us: u64,
    pub forward_bucket_1ms: u64,
    pub forward_bucket_5ms: u64,
    pub forward_bucket_10ms: u64,
    pub forward_bucket_inf: u64,
}

impl TracingMetricsSnapshot {
    /// Get average forward latency in microseconds.
    pub fn avg_forward_latency_us(&self) -> f64 {
        if self.forward_count == 0 {
            return 0.0;
        }
        (self.forward_latency_sum_ns as f64 / self.forward_count as f64) / 1000.0
    }

    /// Get average receive latency in microseconds.
    pub fn avg_recv_latency_us(&self) -> f64 {
        if self.recv_count == 0 {
            return 0.0;
        }
        (self.recv_latency_sum_ns as f64 / self.recv_count as f64) / 1000.0
    }

    /// Get average send latency in microseconds.
    pub fn avg_send_latency_us(&self) -> f64 {
        if self.send_count == 0 {
            return 0.0;
        }
        (self.send_latency_sum_ns as f64 / self.send_count as f64) / 1000.0
    }
}

// Compile-time size assertion
const _: () = {
    assert!(std::mem::size_of::<TracingMetrics>() <= 256);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_metrics_new() {
        let metrics = TracingMetrics::new();
        assert_eq!(metrics.forward_count(), 0);
        assert_eq!(metrics.recv_count(), 0);
        assert_eq!(metrics.send_count(), 0);
    }

    #[test]
    fn test_record_forward_latency() {
        let metrics = TracingMetrics::new();

        // Record 5us latency (should go in <10us bucket)
        metrics.record_forward_latency(5000);
        assert_eq!(metrics.forward_count(), 1);
        assert_eq!(metrics.forward_bucket_10us.load(Ordering::Relaxed), 1);

        // Record 75us latency (should go in <100us bucket)
        metrics.record_forward_latency(75000);
        assert_eq!(metrics.forward_count(), 2);
        assert_eq!(metrics.forward_bucket_100us.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_avg_latency() {
        let metrics = TracingMetrics::new();

        // Record 1us and 3us (average should be 2us)
        metrics.record_forward_latency(1000);
        metrics.record_forward_latency(3000);

        let avg = metrics.avg_forward_latency_us();
        assert!((avg - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_histogram_buckets() {
        let metrics = TracingMetrics::new();

        // Record samples in different buckets
        metrics.record_forward_latency(5_000);      // 5us -> <10us
        metrics.record_forward_latency(30_000);     // 30us -> <50us
        metrics.record_forward_latency(75_000);     // 75us -> <100us
        metrics.record_forward_latency(300_000);    // 300us -> <500us
        metrics.record_forward_latency(750_000);    // 750us -> <1ms
        metrics.record_forward_latency(3_000_000);  // 3ms -> <5ms
        metrics.record_forward_latency(7_000_000);  // 7ms -> <10ms
        metrics.record_forward_latency(15_000_000); // 15ms -> >10ms

        let buckets = metrics.forward_latency_bucket_counts();

        // Verify cumulative counts
        assert_eq!(buckets[0].1, 1); // <10us: 1
        assert_eq!(buckets[1].1, 2); // <50us: 1+1=2
        assert_eq!(buckets[2].1, 3); // <100us: 2+1=3
        assert_eq!(buckets[3].1, 4); // <500us: 3+1=4
        assert_eq!(buckets[4].1, 5); // <1ms: 4+1=5
        assert_eq!(buckets[5].1, 6); // <5ms: 5+1=6
        assert_eq!(buckets[6].1, 7); // <10ms: 6+1=7
        assert_eq!(buckets[7].1, 8); // +Inf: 7+1=8
    }

    #[test]
    fn test_snapshot() {
        let metrics = TracingMetrics::new();

        metrics.record_forward_latency(1000);
        metrics.record_recv_latency(2000);
        metrics.record_send_latency(3000);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.forward_count, 1);
        assert_eq!(snapshot.recv_count, 1);
        assert_eq!(snapshot.send_count, 1);
    }

    #[test]
    fn test_reset() {
        let metrics = TracingMetrics::new();

        metrics.record_forward_latency(1000);
        metrics.record_recv_latency(2000);
        metrics.record_send_latency(3000);

        metrics.reset();

        assert_eq!(metrics.forward_count(), 0);
        assert_eq!(metrics.recv_count(), 0);
        assert_eq!(metrics.send_count(), 0);
    }
}
