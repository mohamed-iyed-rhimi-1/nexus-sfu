use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Signaling metrics.
///
/// # TigerStyle Compliance
/// - Lock-free atomic counters
/// - Explicitly-sized types
pub struct SignalMetrics {
    /// Total connections accepted.
    pub total_connections: AtomicU64,
    /// Connections using 0-RTT.
    pub connections_0rtt: AtomicU64,
    /// Total disconnections.
    pub total_disconnections: AtomicU64,
    /// Total bidirectional streams.
    pub total_bi_streams: AtomicU64,
    /// Total unidirectional streams.
    pub total_uni_streams: AtomicU64,
    /// Total connection migrations.
    pub total_migrations: AtomicU64,
    /// Connection errors.
    pub connection_errors: AtomicU64,
    /// Total 0-RTT rejections.
    pub zero_rtt_rejections: AtomicU64,
    /// Total 0-RTT replay attempts detected.
    pub zero_rtt_replay_attempts: AtomicU64,
    /// Total client stats reports received.
    pub total_client_stats_reports: AtomicU64,
    /// Sum of RTT values (for averaging).
    pub total_rtt_us: AtomicU64,
    /// Sum of packets lost (for totaling).
    pub total_packets_lost: AtomicU64,
    /// Sum of jitter values (for averaging).
    pub total_jitter_us: AtomicU64,
    /// Server start time for calculating uptime.
    start_time: Instant,
}

impl SignalMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            connections_0rtt: AtomicU64::new(0),
            total_disconnections: AtomicU64::new(0),
            total_bi_streams: AtomicU64::new(0),
            total_uni_streams: AtomicU64::new(0),
            total_migrations: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            zero_rtt_rejections: AtomicU64::new(0),
            zero_rtt_replay_attempts: AtomicU64::new(0),
            total_client_stats_reports: AtomicU64::new(0),
            total_rtt_us: AtomicU64::new(0),
            total_packets_lost: AtomicU64::new(0),
            total_jitter_us: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn record_connection(&self, used_0rtt: bool) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        if used_0rtt {
            self.connections_0rtt.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_disconnection(&self) {
        self.total_disconnections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bi_stream(&self) {
        self.total_bi_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_uni_stream(&self) {
        self.total_uni_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_migration(&self) {
        self.total_migrations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_zero_rtt_rejection(&self) {
        self.zero_rtt_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_zero_rtt_replay_attempt(&self) {
        self.zero_rtt_replay_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record client stats from a stats report.
    ///
    /// # Arguments
    /// * `connection_id` - The connection ID (for logging/debugging)
    /// * `rtt_us` - Round-trip time in microseconds
    /// * `packets_lost` - Number of packets lost
    /// * `jitter_us` - Jitter in microseconds
    pub fn record_client_stats(
        &self,
        _connection_id: u64,
        rtt_us: u32,
        packets_lost: u32,
        jitter_us: u32,
    ) {
        self.total_client_stats_reports.fetch_add(1, Ordering::Relaxed);
        self.total_rtt_us.fetch_add(rtt_us as u64, Ordering::Relaxed);
        self.total_packets_lost.fetch_add(packets_lost as u64, Ordering::Relaxed);
        self.total_jitter_us.fetch_add(jitter_us as u64, Ordering::Relaxed);
    }

    /// Get average RTT in microseconds across all client reports.
    pub fn average_rtt_us(&self) -> u64 {
        let reports = self.total_client_stats_reports.load(Ordering::Relaxed);
        if reports == 0 {
            return 0;
        }
        self.total_rtt_us.load(Ordering::Relaxed) / reports
    }

    /// Get total packets lost across all client reports.
    pub fn total_packets_lost(&self) -> u64 {
        self.total_packets_lost.load(Ordering::Relaxed)
    }

    /// Get average jitter in microseconds across all client reports.
    pub fn average_jitter_us(&self) -> u64 {
        let reports = self.total_client_stats_reports.load(Ordering::Relaxed);
        if reports == 0 {
            return 0;
        }
        self.total_jitter_us.load(Ordering::Relaxed) / reports
    }

    /// Get total number of client stats reports received.
    pub fn client_stats_reports(&self) -> u64 {
        self.total_client_stats_reports.load(Ordering::Relaxed)
    }

    /// Get 0-RTT success rate (0.0 to 1.0).
    pub fn zero_rtt_success_rate(&self) -> f64 {
        let total = self.total_connections.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let zero_rtt = self.connections_0rtt.load(Ordering::Relaxed);
        zero_rtt as f64 / total as f64
    }

    /// Get 0-RTT rejection rate (0.0 to 1.0).
    pub fn zero_rtt_rejection_rate(&self) -> f64 {
        let total_0rtt = self.connections_0rtt.load(Ordering::Relaxed);
        if total_0rtt == 0 {
            return 0.0;
        }
        let rejections = self.zero_rtt_rejections.load(Ordering::Relaxed);
        rejections as f64 / total_0rtt as f64
    }

    /// Get average connection time in milliseconds.
    pub fn average_connection_time_ms(&self) -> u64 {
        let total = self.total_connections.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        // This is a simplified calculation
        // In production, track actual connection times
        let uptime_ms = self.start_time.elapsed().as_millis() as u64;
        uptime_ms / total
    }

    /// Get current active connections.
    pub fn active_connections(&self) -> u64 {
        let total = self.total_connections.load(Ordering::Relaxed);
        let disconnected = self.total_disconnections.load(Ordering::Relaxed);
        total.saturating_sub(disconnected)
    }

    /// Get server uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

impl Default for SignalMetrics {
    fn default() -> Self {
        Self::new()
    }
}
