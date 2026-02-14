//! Metrics collection and aggregation
//!
//! Collects performance metrics from headless clients and computes
//! aggregated statistics including percentiles, rates, and throughput.

use std::time::{Duration, Instant};

/// Per-client metrics
#[derive(Clone, Debug, Default)]
pub struct ClientMetrics {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets lost
    pub packets_lost: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Latency samples collected during the test
    pub latency_samples: Vec<Duration>,
    /// Jitter samples collected during the test
    pub jitter_samples: Vec<Duration>,
    /// Time to receive first frame (None if not yet received)
    pub time_to_first_frame: Option<Duration>,
    /// Time taken to establish connection (None if not connected)
    pub connection_time: Option<Duration>,
    /// Whether this client successfully connected
    pub connection_successful: bool,
}

/// Aggregated metrics across all clients
#[derive(Clone, Debug)]
pub struct AggregatedMetrics {
    /// P50 (median) latency
    pub latency_p50: Duration,
    /// P95 latency
    pub latency_p95: Duration,
    /// P99 latency
    pub latency_p99: Duration,
    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss_rate: f64,
    /// Average jitter
    pub jitter_avg: Duration,
    /// Throughput in packets per second
    pub throughput_pps: f64,
    /// Throughput in bytes per second
    pub throughput_bps: f64,
    /// Connection success rate (0.0 to 1.0)
    pub connection_success_rate: f64,
    /// Average time to first frame
    pub avg_time_to_first_frame: Duration,
    /// Total number of clients
    pub total_clients: u32,
    /// Number of successfully connected clients
    pub successful_clients: u32,
    /// Number of failed clients
    pub failed_clients: u32,
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        Self {
            latency_p50: Duration::ZERO,
            latency_p95: Duration::ZERO,
            latency_p99: Duration::ZERO,
            packet_loss_rate: 0.0,
            jitter_avg: Duration::ZERO,
            throughput_pps: 0.0,
            throughput_bps: 0.0,
            connection_success_rate: 0.0,
            avg_time_to_first_frame: Duration::ZERO,
            total_clients: 0,
            successful_clients: 0,
            failed_clients: 0,
        }
    }
}

/// Calculate percentile from a sorted slice of durations.
///
/// **Property 8: Percentile Calculation Correctness**
/// For any non-empty list of latency samples, the computed percentile at P%
/// SHALL be greater than or equal to at least P% of samples.
///
/// Uses nearest-rank method: percentile P means at least P% of values are <= result.
pub fn calculate_percentile(sorted_samples: &[Duration], percentile: f64) -> Duration {
    if sorted_samples.is_empty() {
        return Duration::ZERO;
    }

    // Clamp percentile to valid range
    let percentile = percentile.clamp(0.0, 100.0);

    // Nearest-rank method: index = ceil(P/100 * N) - 1
    // This ensures at least P% of values are <= the result
    let n = sorted_samples.len();
    let rank = (percentile / 100.0 * n as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(n - 1);

    sorted_samples[index]
}

/// Calculate packet loss rate.
///
/// **Property 9: Packet Loss Rate Calculation**
/// For any packet statistics with received >= 0 and lost >= 0,
/// the packet loss rate SHALL equal lost / (received + lost) when total > 0,
/// and 0.0 when total == 0.
pub fn calculate_packet_loss_rate(received: u64, lost: u64) -> f64 {
    let total = received + lost;
    if total == 0 {
        0.0
    } else {
        lost as f64 / total as f64
    }
}

/// Calculate throughput in packets per second.
///
/// **Property 10: Throughput Calculation**
/// For any packet count P and duration D > 0,
/// throughput in packets/sec SHALL equal P/D.
pub fn calculate_throughput_pps(packets: u64, duration: Duration) -> f64 {
    let secs = duration.as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        packets as f64 / secs
    }
}

/// Calculate throughput in bytes per second.
///
/// **Property 10: Throughput Calculation**
/// For any byte count B and duration D > 0,
/// throughput in bytes/sec SHALL equal B/D.
pub fn calculate_throughput_bps(bytes: u64, duration: Duration) -> f64 {
    let secs = duration.as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        bytes as f64 / secs
    }
}

/// Calculate connection success rate.
///
/// **Property 11: Connection Success Rate Calculation**
/// For any test with S successful connections and F failed connections,
/// the connection success rate SHALL equal S / (S + F) when total > 0,
/// and 0.0 when total == 0.
pub fn calculate_connection_success_rate(successful: u32, failed: u32) -> f64 {
    let total = successful + failed;
    if total == 0 {
        0.0
    } else {
        successful as f64 / total as f64
    }
}

/// Metrics collector that aggregates from all clients
pub struct MetricsCollector {
    /// Per-client metrics indexed by client ID
    client_metrics: Vec<ClientMetrics>,
    /// Sampling interval for metrics collection
    sample_interval: Duration,
    /// Test start time
    start_time: Instant,
    /// Test duration (set when test completes)
    test_duration: Option<Duration>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(sample_interval: Duration) -> Self {
        Self {
            client_metrics: Vec::new(),
            sample_interval,
            start_time: Instant::now(),
            test_duration: None,
        }
    }

    /// Register a client for metrics collection
    pub fn register_client(&mut self, _client_id: usize) {
        self.client_metrics.push(ClientMetrics::default());
    }

    /// Record a latency sample for a client
    pub fn record_latency(&mut self, client_id: usize, latency: Duration) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.latency_samples.push(latency);
        }
    }

    /// Record jitter sample for a client
    pub fn record_jitter(&mut self, client_id: usize, jitter: Duration) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.jitter_samples.push(jitter);
        }
    }

    /// Record packet statistics for a client
    pub fn record_packets(&mut self, client_id: usize, received: u64, lost: u64) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.packets_received = received;
            metrics.packets_lost = lost;
        }
    }

    /// Record bytes received for a client
    pub fn record_bytes(&mut self, client_id: usize, bytes: u64) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.bytes_received = bytes;
        }
    }

    /// Record time to first frame for a client
    pub fn record_first_frame(&mut self, client_id: usize, ttff: Duration) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.time_to_first_frame = Some(ttff);
        }
    }

    /// Record connection time for a client
    pub fn record_connection_time(&mut self, client_id: usize, connection_time: Duration) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.connection_time = Some(connection_time);
        }
    }

    /// Mark a client as successfully connected
    pub fn mark_connected(&mut self, client_id: usize) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.connection_successful = true;
        }
    }

    /// Mark a client as failed
    pub fn mark_failed(&mut self, client_id: usize) {
        if let Some(metrics) = self.client_metrics.get_mut(client_id) {
            metrics.connection_successful = false;
        }
    }

    /// Set the test duration (call when test completes)
    pub fn set_duration(&mut self, duration: Duration) {
        self.test_duration = Some(duration);
    }

    /// Get the sample interval
    pub fn sample_interval(&self) -> Duration {
        self.sample_interval
    }

    /// Get the elapsed time since test start
    pub fn elapsed(&self) -> Duration {
        self.test_duration.unwrap_or_else(|| self.start_time.elapsed())
    }

    /// Get access to client metrics
    pub fn client_metrics(&self) -> &[ClientMetrics] {
        &self.client_metrics
    }

    /// Compute aggregated metrics from all clients
    pub fn aggregate(&self) -> AggregatedMetrics {
        let total_clients = self.client_metrics.len() as u32;

        if total_clients == 0 {
            return AggregatedMetrics::default();
        }

        // Count successful and failed clients
        let successful_clients = self
            .client_metrics
            .iter()
            .filter(|m| m.connection_successful)
            .count() as u32;
        let failed_clients = total_clients - successful_clients;

        // Collect all latency samples and sort them
        let mut all_latencies: Vec<Duration> = self
            .client_metrics
            .iter()
            .flat_map(|m| m.latency_samples.iter().copied())
            .collect();
        all_latencies.sort();

        // Calculate latency percentiles
        let latency_p50 = calculate_percentile(&all_latencies, 50.0);
        let latency_p95 = calculate_percentile(&all_latencies, 95.0);
        let latency_p99 = calculate_percentile(&all_latencies, 99.0);

        // Aggregate packet statistics
        let total_received: u64 = self.client_metrics.iter().map(|m| m.packets_received).sum();
        let total_lost: u64 = self.client_metrics.iter().map(|m| m.packets_lost).sum();
        let total_bytes: u64 = self.client_metrics.iter().map(|m| m.bytes_received).sum();

        // Calculate packet loss rate
        let packet_loss_rate = calculate_packet_loss_rate(total_received, total_lost);

        // Calculate average jitter
        let all_jitter: Vec<Duration> = self
            .client_metrics
            .iter()
            .flat_map(|m| m.jitter_samples.iter().copied())
            .collect();
        let jitter_avg = if all_jitter.is_empty() {
            Duration::ZERO
        } else {
            let total_nanos: u128 = all_jitter.iter().map(|d| d.as_nanos()).sum();
            Duration::from_nanos((total_nanos / all_jitter.len() as u128) as u64)
        };

        // Calculate throughput
        let duration = self.elapsed();
        let total_packets = total_received + total_lost;
        let throughput_pps = calculate_throughput_pps(total_packets, duration);
        let throughput_bps = calculate_throughput_bps(total_bytes, duration);

        // Calculate connection success rate
        let connection_success_rate =
            calculate_connection_success_rate(successful_clients, failed_clients);

        // Calculate average time to first frame
        let ttff_samples: Vec<Duration> = self
            .client_metrics
            .iter()
            .filter_map(|m| m.time_to_first_frame)
            .collect();
        let avg_time_to_first_frame = if ttff_samples.is_empty() {
            Duration::ZERO
        } else {
            let total_nanos: u128 = ttff_samples.iter().map(|d| d.as_nanos()).sum();
            Duration::from_nanos((total_nanos / ttff_samples.len() as u128) as u64)
        };

        AggregatedMetrics {
            latency_p50,
            latency_p95,
            latency_p99,
            packet_loss_rate,
            jitter_avg,
            throughput_pps,
            throughput_bps,
            connection_success_rate,
            avg_time_to_first_frame,
            total_clients,
            successful_clients,
            failed_clients,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile_empty() {
        assert_eq!(calculate_percentile(&[], 50.0), Duration::ZERO);
    }

    #[test]
    fn test_percentile_single_element() {
        let samples = [Duration::from_millis(100)];
        assert_eq!(calculate_percentile(&samples, 50.0), Duration::from_millis(100));
        assert_eq!(calculate_percentile(&samples, 99.0), Duration::from_millis(100));
    }

    #[test]
    fn test_percentile_multiple_elements() {
        // 10 elements: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ms
        let samples: Vec<Duration> = (1..=10).map(|i| Duration::from_millis(i)).collect();

        // P50 should be >= 50% of samples (index 4 = 5ms)
        let p50 = calculate_percentile(&samples, 50.0);
        assert_eq!(p50, Duration::from_millis(5));

        // P90 should be >= 90% of samples (index 8 = 9ms)
        let p90 = calculate_percentile(&samples, 90.0);
        assert_eq!(p90, Duration::from_millis(9));

        // P100 should be the max
        let p100 = calculate_percentile(&samples, 100.0);
        assert_eq!(p100, Duration::from_millis(10));
    }

    #[test]
    fn test_packet_loss_rate_zero_total() {
        assert_eq!(calculate_packet_loss_rate(0, 0), 0.0);
    }

    #[test]
    fn test_packet_loss_rate_no_loss() {
        assert_eq!(calculate_packet_loss_rate(100, 0), 0.0);
    }

    #[test]
    fn test_packet_loss_rate_all_lost() {
        assert_eq!(calculate_packet_loss_rate(0, 100), 1.0);
    }

    #[test]
    fn test_packet_loss_rate_partial() {
        // 90 received, 10 lost = 10% loss
        let rate = calculate_packet_loss_rate(90, 10);
        assert!((rate - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_throughput_pps_zero_duration() {
        assert_eq!(calculate_throughput_pps(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn test_throughput_pps() {
        // 1000 packets in 10 seconds = 100 pps
        let pps = calculate_throughput_pps(1000, Duration::from_secs(10));
        assert!((pps - 100.0).abs() < 1e-10);
    }

    #[test]
    fn test_throughput_bps_zero_duration() {
        assert_eq!(calculate_throughput_bps(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn test_throughput_bps() {
        // 10000 bytes in 10 seconds = 1000 bps
        let bps = calculate_throughput_bps(10000, Duration::from_secs(10));
        assert!((bps - 1000.0).abs() < 1e-10);
    }

    #[test]
    fn test_connection_success_rate_zero_total() {
        assert_eq!(calculate_connection_success_rate(0, 0), 0.0);
    }

    #[test]
    fn test_connection_success_rate_all_success() {
        assert_eq!(calculate_connection_success_rate(100, 0), 1.0);
    }

    #[test]
    fn test_connection_success_rate_all_failed() {
        assert_eq!(calculate_connection_success_rate(0, 100), 0.0);
    }

    #[test]
    fn test_connection_success_rate_partial() {
        // 80 successful, 20 failed = 80% success
        let rate = calculate_connection_success_rate(80, 20);
        assert!((rate - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_metrics_collector_aggregate_empty() {
        let collector = MetricsCollector::new(Duration::from_secs(1));
        let metrics = collector.aggregate();
        assert_eq!(metrics.total_clients, 0);
    }

    #[test]
    fn test_metrics_collector_aggregate() {
        let mut collector = MetricsCollector::new(Duration::from_secs(1));

        // Register 2 clients
        collector.register_client(0);
        collector.register_client(1);

        // Record data for client 0 (successful)
        collector.mark_connected(0);
        collector.record_latency(0, Duration::from_millis(10));
        collector.record_latency(0, Duration::from_millis(20));
        collector.record_packets(0, 100, 5);
        collector.record_bytes(0, 10000);

        // Record data for client 1 (failed)
        collector.mark_failed(1);

        // Set test duration
        collector.set_duration(Duration::from_secs(10));

        let metrics = collector.aggregate();

        assert_eq!(metrics.total_clients, 2);
        assert_eq!(metrics.successful_clients, 1);
        assert_eq!(metrics.failed_clients, 1);
        assert!((metrics.connection_success_rate - 0.5).abs() < 1e-10);
        assert!(metrics.latency_p50 > Duration::ZERO);
    }
}
