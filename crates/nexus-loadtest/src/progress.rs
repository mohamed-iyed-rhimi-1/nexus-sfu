//! Console progress display
//!
//! Provides real-time progress bar and live metrics display during test execution.
//!
//! **Validates: Requirements 7.1** - Console output format with real-time progress

use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::config::OutputFormat;
use crate::metrics::AggregatedMetrics;

/// Progress display for console output
///
/// Shows a real-time progress bar with elapsed time and live metrics
/// during test execution.
pub struct ProgressDisplay {
    /// Multi-progress container for multiple progress bars
    multi_progress: MultiProgress,
    /// Main progress bar showing test duration
    progress_bar: ProgressBar,
    /// Status bar showing live metrics
    status_bar: ProgressBar,
    /// Test start time
    start_time: Instant,
    /// Total test duration
    total_duration: Duration,
    /// Whether progress display is enabled
    enabled: bool,
}

impl ProgressDisplay {
    /// Create a new progress display
    ///
    /// Progress display is only enabled when output format is Console.
    pub fn new(output_format: OutputFormat, duration: Duration) -> Self {
        let enabled = output_format == OutputFormat::Console;
        let multi_progress = MultiProgress::new();

        let progress_bar = if enabled {
            let pb = multi_progress.add(ProgressBar::new(duration.as_secs()));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}s ({eta})")
                    .expect("Invalid progress bar template")
                    .progress_chars("█▓▒░  "),
            );
            pb.set_message("Running test...");
            pb
        } else {
            ProgressBar::hidden()
        };

        let status_bar = if enabled {
            let sb = multi_progress.add(ProgressBar::new_spinner());
            sb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .expect("Invalid status bar template"),
            );
            sb.set_message("Initializing...");
            sb
        } else {
            ProgressBar::hidden()
        };

        Self {
            multi_progress,
            progress_bar,
            status_bar,
            start_time: Instant::now(),
            total_duration: duration,
            enabled,
        }
    }

    /// Check if progress display is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the initial message when test starts
    pub fn set_connecting(&self, client_count: u32) {
        if self.enabled {
            self.status_bar
                .set_message(format!("Connecting {} clients...", client_count));
        }
    }

    /// Update status when clients are connected
    pub fn set_connected(&self, successful: u32, failed: u32) {
        if self.enabled {
            self.status_bar.set_message(format!(
                "Connected: {} successful, {} failed",
                successful, failed
            ));
        }
    }

    /// Update status when publishing starts
    pub fn set_publishing(&self) {
        if self.enabled {
            self.status_bar.set_message("Starting media publishing...");
        }
    }

    /// Update progress with current elapsed time and metrics
    ///
    /// This should be called periodically during test execution.
    pub fn update(&self, metrics: &AggregatedMetrics) {
        if !self.enabled {
            return;
        }

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs().min(self.total_duration.as_secs());
        self.progress_bar.set_position(elapsed_secs);

        // Format live metrics
        let latency_p50_ms = metrics.latency_p50.as_secs_f64() * 1000.0;
        let latency_p99_ms = metrics.latency_p99.as_secs_f64() * 1000.0;
        let throughput_kpps = metrics.throughput_pps / 1000.0;
        let throughput_mbps = (metrics.throughput_bps * 8.0) / 1_000_000.0;

        let status_msg = format!(
            "Clients: {} | Throughput: {:.1}K pps ({:.1} Mbps) | Latency P50: {:.1}ms P99: {:.1}ms | Loss: {:.2}%",
            metrics.total_clients,
            throughput_kpps,
            throughput_mbps,
            latency_p50_ms,
            latency_p99_ms,
            metrics.packet_loss_rate * 100.0
        );
        self.status_bar.set_message(status_msg);
    }

    /// Update progress for stress test with room information
    pub fn update_stress(&self, metrics: &AggregatedMetrics, active_rooms: usize, failed_rooms: usize) {
        if !self.enabled {
            return;
        }

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs().min(self.total_duration.as_secs());
        self.progress_bar.set_position(elapsed_secs);

        // Format live metrics with room info
        let latency_p50_ms = metrics.latency_p50.as_secs_f64() * 1000.0;
        let throughput_kpps = metrics.throughput_pps / 1000.0;

        let status_msg = format!(
            "Rooms: {} active, {} failed | Clients: {} | Throughput: {:.1}K pps | Latency P50: {:.1}ms | Loss: {:.2}%",
            active_rooms,
            failed_rooms,
            metrics.total_clients,
            throughput_kpps,
            latency_p50_ms,
            metrics.packet_loss_rate * 100.0
        );
        self.status_bar.set_message(status_msg);
    }

    /// Mark the test as complete
    pub fn finish(&self, metrics: &AggregatedMetrics) {
        if !self.enabled {
            return;
        }

        self.progress_bar.set_position(self.total_duration.as_secs());
        self.progress_bar.finish_with_message("Test complete");

        // Show final summary
        let latency_p50_ms = metrics.latency_p50.as_secs_f64() * 1000.0;
        let latency_p99_ms = metrics.latency_p99.as_secs_f64() * 1000.0;
        let ttff_ms = metrics.avg_time_to_first_frame.as_secs_f64() * 1000.0;

        let final_msg = format!(
            "✓ Complete | Clients: {}/{} | P50: {:.1}ms | P99: {:.1}ms | TTFF: {:.1}ms | Loss: {:.2}%",
            metrics.successful_clients,
            metrics.total_clients,
            latency_p50_ms,
            latency_p99_ms,
            ttff_ms,
            metrics.packet_loss_rate * 100.0
        );
        self.status_bar.finish_with_message(final_msg);
    }

    /// Mark the test as failed
    pub fn finish_with_error(&self, error: &str) {
        if !self.enabled {
            return;
        }

        self.progress_bar.abandon_with_message("Test failed");
        self.status_bar
            .finish_with_message(format!("✗ Error: {}", error));
    }

    /// Get the multi-progress container for additional progress bars
    #[allow(dead_code)]
    pub fn multi_progress(&self) -> &MultiProgress {
        &self.multi_progress
    }
}

impl Default for ProgressDisplay {
    fn default() -> Self {
        Self::new(OutputFormat::Console, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_display_enabled_for_console() {
        let display = ProgressDisplay::new(OutputFormat::Console, Duration::from_secs(60));
        assert!(display.is_enabled());
    }

    #[test]
    fn test_progress_display_disabled_for_json() {
        let display = ProgressDisplay::new(OutputFormat::Json, Duration::from_secs(60));
        assert!(!display.is_enabled());
    }

    #[test]
    fn test_progress_display_disabled_for_prometheus() {
        let display = ProgressDisplay::new(OutputFormat::Prometheus, Duration::from_secs(60));
        assert!(!display.is_enabled());
    }

    #[test]
    fn test_progress_display_update_with_metrics() {
        let display = ProgressDisplay::new(OutputFormat::Console, Duration::from_secs(60));
        let metrics = AggregatedMetrics::default();
        
        // Should not panic
        display.update(&metrics);
    }

    #[test]
    fn test_progress_display_finish() {
        let display = ProgressDisplay::new(OutputFormat::Console, Duration::from_secs(60));
        let metrics = AggregatedMetrics::default();
        
        // Should not panic
        display.finish(&metrics);
    }

    #[test]
    fn test_progress_display_disabled_operations() {
        let display = ProgressDisplay::new(OutputFormat::Json, Duration::from_secs(60));
        let metrics = AggregatedMetrics::default();
        
        // All operations should be no-ops when disabled
        display.set_connecting(10);
        display.set_connected(8, 2);
        display.set_publishing();
        display.update(&metrics);
        display.update_stress(&metrics, 3, 1);
        display.finish(&metrics);
        display.finish_with_error("test error");
    }
}
