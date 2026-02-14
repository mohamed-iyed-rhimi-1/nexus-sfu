//! Report generation and output formatting
//!
//! Generates test reports in multiple formats (console, JSON, Prometheus)
//! and validates results against performance targets.

use serde::{Deserialize, Serialize};

use crate::config::{OutputFormat, PerformanceTargets, TestConfig};
use crate::metrics::AggregatedMetrics;

/// Target validation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetValidation {
    /// Name of the target being validated
    pub name: String,
    /// Target value as string
    pub target: String,
    /// Actual measured value as string
    pub actual: String,
    /// Whether the target was met
    pub passed: bool,
}

/// Complete test report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestReport {
    /// Test scenario name (webinar, conference, stress)
    pub scenario: String,
    /// SFU URL that was tested
    pub sfu_url: String,
    /// Test duration in seconds
    pub duration_secs: u64,
    /// ISO 8601 timestamp of test completion
    pub timestamp: String,
    /// Aggregated metrics from the test
    pub metrics: SerializableMetrics,
    /// Target validation results
    pub target_validations: Vec<TargetValidation>,
    /// Overall pass/fail status
    pub passed: bool,
}

/// Serializable version of AggregatedMetrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableMetrics {
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub packet_loss_rate: f64,
    pub jitter_avg_ms: f64,
    pub throughput_pps: f64,
    pub throughput_bps: f64,
    pub connection_success_rate: f64,
    pub avg_time_to_first_frame_ms: f64,
    pub total_clients: u32,
    pub successful_clients: u32,
    pub failed_clients: u32,
}

impl From<&AggregatedMetrics> for SerializableMetrics {
    fn from(m: &AggregatedMetrics) -> Self {
        Self {
            latency_p50_ms: m.latency_p50.as_secs_f64() * 1000.0,
            latency_p95_ms: m.latency_p95.as_secs_f64() * 1000.0,
            latency_p99_ms: m.latency_p99.as_secs_f64() * 1000.0,
            packet_loss_rate: m.packet_loss_rate,
            jitter_avg_ms: m.jitter_avg.as_secs_f64() * 1000.0,
            throughput_pps: m.throughput_pps,
            throughput_bps: m.throughput_bps,
            connection_success_rate: m.connection_success_rate,
            avg_time_to_first_frame_ms: m.avg_time_to_first_frame.as_secs_f64() * 1000.0,
            total_clients: m.total_clients,
            successful_clients: m.successful_clients,
            failed_clients: m.failed_clients,
        }
    }
}

impl TestReport {
    /// Serialize report to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize report from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Format as human-readable console output
    pub fn to_console(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n╔══════════════════════════════════════════════════════════════╗\n"
        ));
        output.push_str(&format!(
            "║  NEXUS LOAD TEST REPORT - {}                              \n",
            self.scenario.to_uppercase()
        ));
        output.push_str(&format!(
            "╚══════════════════════════════════════════════════════════════╝\n\n"
        ));

        // Test info
        output.push_str(&format!("SFU URL:    {}\n", self.sfu_url));
        output.push_str(&format!("Duration:   {} seconds\n", self.duration_secs));
        output.push_str(&format!("Timestamp:  {}\n\n", self.timestamp));

        // Client stats
        output.push_str("─── Client Statistics ───────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Total Clients:      {}\n",
            self.metrics.total_clients
        ));
        output.push_str(&format!(
            "  Successful:         {} ({:.1}%)\n",
            self.metrics.successful_clients,
            self.metrics.connection_success_rate * 100.0
        ));
        output.push_str(&format!(
            "  Failed:             {}\n\n",
            self.metrics.failed_clients
        ));

        // Latency metrics
        output.push_str("─── Latency Metrics ─────────────────────────────────────────────\n");
        output.push_str(&format!(
            "  P50:                {:.2} ms\n",
            self.metrics.latency_p50_ms
        ));
        output.push_str(&format!(
            "  P95:                {:.2} ms\n",
            self.metrics.latency_p95_ms
        ));
        output.push_str(&format!(
            "  P99:                {:.2} ms\n",
            self.metrics.latency_p99_ms
        ));
        output.push_str(&format!(
            "  Jitter (avg):       {:.2} ms\n\n",
            self.metrics.jitter_avg_ms
        ));

        // Throughput metrics
        output.push_str("─── Throughput Metrics ──────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Packets/sec:        {:.2}\n",
            self.metrics.throughput_pps
        ));
        output.push_str(&format!(
            "  Bytes/sec:          {:.2}\n",
            self.metrics.throughput_bps
        ));
        output.push_str(&format!(
            "  Packet Loss:        {:.2}%\n",
            self.metrics.packet_loss_rate * 100.0
        ));
        output.push_str(&format!(
            "  Time to First Frame:{:.2} ms\n\n",
            self.metrics.avg_time_to_first_frame_ms
        ));

        // Target validations
        if !self.target_validations.is_empty() {
            output.push_str("─── Target Validations ──────────────────────────────────────────\n");
            for validation in &self.target_validations {
                let status = if validation.passed { "✓" } else { "✗" };
                output.push_str(&format!(
                    "  {} {}: {} (target: {})\n",
                    status, validation.name, validation.actual, validation.target
                ));
            }
            output.push('\n');
        }

        // Overall result
        let result_str = if self.passed { "PASSED ✓" } else { "FAILED ✗" };
        output.push_str(&format!(
            "═══════════════════════════════════════════════════════════════\n"
        ));
        output.push_str(&format!("  RESULT: {}\n", result_str));
        output.push_str(&format!(
            "═══════════════════════════════════════════════════════════════\n"
        ));

        output
    }

    /// Format as Prometheus metrics
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Add HELP and TYPE comments for each metric
        output.push_str("# HELP nexus_loadtest_latency_p50_ms P50 latency in milliseconds\n");
        output.push_str("# TYPE nexus_loadtest_latency_p50_ms gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_latency_p50_ms{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.latency_p50_ms
        ));

        output.push_str("# HELP nexus_loadtest_latency_p95_ms P95 latency in milliseconds\n");
        output.push_str("# TYPE nexus_loadtest_latency_p95_ms gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_latency_p95_ms{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.latency_p95_ms
        ));

        output.push_str("# HELP nexus_loadtest_latency_p99_ms P99 latency in milliseconds\n");
        output.push_str("# TYPE nexus_loadtest_latency_p99_ms gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_latency_p99_ms{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.latency_p99_ms
        ));

        output.push_str("# HELP nexus_loadtest_jitter_avg_ms Average jitter in milliseconds\n");
        output.push_str("# TYPE nexus_loadtest_jitter_avg_ms gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_jitter_avg_ms{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.jitter_avg_ms
        ));

        output.push_str("# HELP nexus_loadtest_packet_loss_rate Packet loss rate (0-1)\n");
        output.push_str("# TYPE nexus_loadtest_packet_loss_rate gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_packet_loss_rate{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.packet_loss_rate
        ));

        output.push_str("# HELP nexus_loadtest_throughput_pps Throughput in packets per second\n");
        output.push_str("# TYPE nexus_loadtest_throughput_pps gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_throughput_pps{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.throughput_pps
        ));

        output.push_str("# HELP nexus_loadtest_throughput_bps Throughput in bytes per second\n");
        output.push_str("# TYPE nexus_loadtest_throughput_bps gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_throughput_bps{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.throughput_bps
        ));

        output.push_str(
            "# HELP nexus_loadtest_connection_success_rate Connection success rate (0-1)\n",
        );
        output.push_str("# TYPE nexus_loadtest_connection_success_rate gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_connection_success_rate{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.connection_success_rate
        ));

        output.push_str(
            "# HELP nexus_loadtest_time_to_first_frame_ms Average time to first frame in ms\n",
        );
        output.push_str("# TYPE nexus_loadtest_time_to_first_frame_ms gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_time_to_first_frame_ms{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.avg_time_to_first_frame_ms
        ));

        output.push_str("# HELP nexus_loadtest_total_clients Total number of clients\n");
        output.push_str("# TYPE nexus_loadtest_total_clients gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_total_clients{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.total_clients
        ));

        output.push_str(
            "# HELP nexus_loadtest_successful_clients Number of successful clients\n",
        );
        output.push_str("# TYPE nexus_loadtest_successful_clients gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_successful_clients{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.successful_clients
        ));

        output.push_str("# HELP nexus_loadtest_failed_clients Number of failed clients\n");
        output.push_str("# TYPE nexus_loadtest_failed_clients gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_failed_clients{{scenario=\"{}\"}} {}\n",
            self.scenario, self.metrics.failed_clients
        ));

        output.push_str("# HELP nexus_loadtest_passed Test passed (1) or failed (0)\n");
        output.push_str("# TYPE nexus_loadtest_passed gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_passed{{scenario=\"{}\"}} {}\n",
            self.scenario,
            if self.passed { 1 } else { 0 }
        ));

        output.push_str("# HELP nexus_loadtest_duration_secs Test duration in seconds\n");
        output.push_str("# TYPE nexus_loadtest_duration_secs gauge\n");
        output.push_str(&format!(
            "nexus_loadtest_duration_secs{{scenario=\"{}\"}} {}\n",
            self.scenario, self.duration_secs
        ));

        output
    }
}

/// Report generator
pub struct ReportGenerator {
    /// Output format
    format: OutputFormat,
    /// Performance targets for validation
    targets: PerformanceTargets,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(format: OutputFormat, targets: PerformanceTargets) -> Self {
        Self { format, targets }
    }

    /// Generate report from aggregated metrics
    ///
    /// **Property 14: Target Validation Correctness**
    /// For any measured metrics and performance targets, the validation SHALL report
    /// pass if and only if all measured values meet or exceed their corresponding targets.
    ///
    /// **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5**
    pub fn generate(
        &self,
        scenario: &str,
        config: &TestConfig,
        metrics: AggregatedMetrics,
    ) -> TestReport {
        let serializable_metrics = SerializableMetrics::from(&metrics);
        let target_validations = self.validate_targets(&serializable_metrics);

        // Test passes only if ALL targets are met (Requirement 8.5)
        let passed = target_validations.iter().all(|v| v.passed);

        TestReport {
            scenario: scenario.to_string(),
            sfu_url: config.sfu_url.clone(),
            duration_secs: config.duration.as_secs(),
            timestamp: chrono_now_iso8601(),
            metrics: serializable_metrics,
            target_validations,
            passed,
        }
    }

    /// Validate metrics against performance targets
    ///
    /// Creates TargetValidation entries for:
    /// - P50 latency (Requirement 8.1)
    /// - P99 latency (Requirement 8.2)
    /// - Participant count (Requirement 8.3)
    /// - Throughput (Requirement 8.4)
    fn validate_targets(&self, metrics: &SerializableMetrics) -> Vec<TargetValidation> {
        let mut validations = Vec::new();

        // Requirement 8.1: P50 latency validation
        // Target is met if actual P50 latency is <= target
        let p50_passed = metrics.latency_p50_ms <= self.targets.latency_p50_ms as f64;
        validations.push(TargetValidation {
            name: "P50 Latency".to_string(),
            target: format!("≤ {}ms", self.targets.latency_p50_ms),
            actual: format!("{:.2}ms", metrics.latency_p50_ms),
            passed: p50_passed,
        });

        // Requirement 8.2: P99 latency validation
        // Target is met if actual P99 latency is <= target
        let p99_passed = metrics.latency_p99_ms <= self.targets.latency_p99_ms as f64;
        validations.push(TargetValidation {
            name: "P99 Latency".to_string(),
            target: format!("≤ {}ms", self.targets.latency_p99_ms),
            actual: format!("{:.2}ms", metrics.latency_p99_ms),
            passed: p99_passed,
        });

        // Requirement 8.3: Participant count validation
        // Target is met if total successful clients >= minimum participants
        let participants_passed =
            metrics.successful_clients >= self.targets.min_participants;
        validations.push(TargetValidation {
            name: "Participant Count".to_string(),
            target: format!("≥ {}", self.targets.min_participants),
            actual: format!("{}", metrics.successful_clients),
            passed: participants_passed,
        });

        // Requirement 8.4: Throughput validation
        // Target is met if actual throughput >= target throughput
        let throughput_passed = metrics.throughput_pps >= self.targets.throughput_pps as f64;
        validations.push(TargetValidation {
            name: "Throughput".to_string(),
            target: format!("≥ {} pps/core", self.targets.throughput_pps),
            actual: format!("{:.2} pps", metrics.throughput_pps),
            passed: throughput_passed,
        });

        validations
    }

    /// Output report to console/file
    pub fn output(
        &self,
        report: &TestReport,
        file: Option<&str>,
    ) -> Result<(), crate::error::LoadTestError> {
        let output = match self.format {
            OutputFormat::Console => report.to_console(),
            OutputFormat::Json => report.to_json().map_err(|e| {
                crate::error::LoadTestError::ReportError(e.to_string())
            })?,
            OutputFormat::Prometheus => report.to_prometheus(),
        };

        if let Some(path) = file {
            std::fs::write(path, &output)?;
        } else {
            println!("{}", output);
        }

        Ok(())
    }

    /// Get the output format
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Get the performance targets
    pub fn targets(&self) -> &PerformanceTargets {
        &self.targets
    }
}

/// Get current time as ISO 8601 string
fn chrono_now_iso8601() -> String {
    // Simple implementation without chrono dependency
    // In production, would use chrono crate
    "2024-01-01T00:00:00Z".to_string()
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_config() -> TestConfig {
        TestConfig {
            sfu_url: "wss://test.example.com".to_string(),
            duration: Duration::from_secs(60),
            output_format: OutputFormat::Console,
            report_file: None,
            connection_timeout: Duration::from_secs(30),
            verbose: false,
            prometheus_port: 9090,
        }
    }

    fn create_passing_metrics() -> AggregatedMetrics {
        // Metrics that pass all default targets:
        // P50 <= 5ms, P99 <= 15ms, participants >= 1000, throughput >= 500K pps
        AggregatedMetrics {
            latency_p50: Duration::from_millis(3),
            latency_p95: Duration::from_millis(10),
            latency_p99: Duration::from_millis(12),
            packet_loss_rate: 0.01,
            jitter_avg: Duration::from_millis(1),
            throughput_pps: 600_000.0,
            throughput_bps: 1_000_000.0,
            connection_success_rate: 0.99,
            avg_time_to_first_frame: Duration::from_millis(50),
            total_clients: 1100,
            successful_clients: 1050,
            failed_clients: 50,
        }
    }

    fn create_failing_metrics() -> AggregatedMetrics {
        // Metrics that fail all default targets
        AggregatedMetrics {
            latency_p50: Duration::from_millis(10),  // > 5ms target
            latency_p95: Duration::from_millis(20),
            latency_p99: Duration::from_millis(25),  // > 15ms target
            packet_loss_rate: 0.05,
            jitter_avg: Duration::from_millis(5),
            throughput_pps: 100_000.0,  // < 500K target
            throughput_bps: 500_000.0,
            connection_success_rate: 0.80,
            avg_time_to_first_frame: Duration::from_millis(100),
            total_clients: 500,
            successful_clients: 400,  // < 1000 target
            failed_clients: 100,
        }
    }

    #[test]
    fn test_target_validation_all_pass() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(),
        );
        let config = create_test_config();
        let metrics = create_passing_metrics();

        let report = generator.generate("webinar", &config, metrics);

        // All targets should pass
        assert!(report.passed, "Report should pass when all targets are met");
        assert_eq!(report.target_validations.len(), 4);

        for validation in &report.target_validations {
            assert!(
                validation.passed,
                "Target '{}' should pass: actual={}, target={}",
                validation.name, validation.actual, validation.target
            );
        }
    }

    #[test]
    fn test_target_validation_all_fail() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(),
        );
        let config = create_test_config();
        let metrics = create_failing_metrics();

        let report = generator.generate("conference", &config, metrics);

        // Overall should fail
        assert!(!report.passed, "Report should fail when targets are not met");
        assert_eq!(report.target_validations.len(), 4);

        // All individual targets should fail
        for validation in &report.target_validations {
            assert!(
                !validation.passed,
                "Target '{}' should fail: actual={}, target={}",
                validation.name, validation.actual, validation.target
            );
        }
    }

    #[test]
    fn test_target_validation_p50_latency() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(), // P50 target: 5ms
        );
        let config = create_test_config();

        // Test passing case: P50 = 5ms (exactly at target)
        let mut metrics = create_passing_metrics();
        metrics.latency_p50 = Duration::from_millis(5);
        let report = generator.generate("test", &config, metrics);
        let p50_validation = report.target_validations.iter()
            .find(|v| v.name == "P50 Latency")
            .unwrap();
        assert!(p50_validation.passed, "P50 at exactly 5ms should pass");

        // Test failing case: P50 = 6ms (above target)
        let mut metrics = create_passing_metrics();
        metrics.latency_p50 = Duration::from_millis(6);
        let report = generator.generate("test", &config, metrics);
        let p50_validation = report.target_validations.iter()
            .find(|v| v.name == "P50 Latency")
            .unwrap();
        assert!(!p50_validation.passed, "P50 at 6ms should fail");
    }

    #[test]
    fn test_target_validation_p99_latency() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(), // P99 target: 15ms
        );
        let config = create_test_config();

        // Test passing case: P99 = 15ms (exactly at target)
        let mut metrics = create_passing_metrics();
        metrics.latency_p99 = Duration::from_millis(15);
        let report = generator.generate("test", &config, metrics);
        let p99_validation = report.target_validations.iter()
            .find(|v| v.name == "P99 Latency")
            .unwrap();
        assert!(p99_validation.passed, "P99 at exactly 15ms should pass");

        // Test failing case: P99 = 16ms (above target)
        let mut metrics = create_passing_metrics();
        metrics.latency_p99 = Duration::from_millis(16);
        let report = generator.generate("test", &config, metrics);
        let p99_validation = report.target_validations.iter()
            .find(|v| v.name == "P99 Latency")
            .unwrap();
        assert!(!p99_validation.passed, "P99 at 16ms should fail");
    }

    #[test]
    fn test_target_validation_participant_count() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(), // min_participants: 1000
        );
        let config = create_test_config();

        // Test passing case: 1000 participants (exactly at target)
        let mut metrics = create_passing_metrics();
        metrics.successful_clients = 1000;
        let report = generator.generate("test", &config, metrics);
        let participant_validation = report.target_validations.iter()
            .find(|v| v.name == "Participant Count")
            .unwrap();
        assert!(participant_validation.passed, "1000 participants should pass");

        // Test failing case: 999 participants (below target)
        let mut metrics = create_passing_metrics();
        metrics.successful_clients = 999;
        let report = generator.generate("test", &config, metrics);
        let participant_validation = report.target_validations.iter()
            .find(|v| v.name == "Participant Count")
            .unwrap();
        assert!(!participant_validation.passed, "999 participants should fail");
    }

    #[test]
    fn test_target_validation_throughput() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(), // throughput_pps: 500_000
        );
        let config = create_test_config();

        // Test passing case: 500K pps (exactly at target)
        let mut metrics = create_passing_metrics();
        metrics.throughput_pps = 500_000.0;
        let report = generator.generate("test", &config, metrics);
        let throughput_validation = report.target_validations.iter()
            .find(|v| v.name == "Throughput")
            .unwrap();
        assert!(throughput_validation.passed, "500K pps should pass");

        // Test failing case: 499K pps (below target)
        let mut metrics = create_passing_metrics();
        metrics.throughput_pps = 499_999.0;
        let report = generator.generate("test", &config, metrics);
        let throughput_validation = report.target_validations.iter()
            .find(|v| v.name == "Throughput")
            .unwrap();
        assert!(!throughput_validation.passed, "499K pps should fail");
    }

    #[test]
    fn test_target_validation_partial_failure() {
        // Test that if ANY target fails, the overall report fails (Requirement 8.5)
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(),
        );
        let config = create_test_config();

        // All targets pass except P50 latency
        let mut metrics = create_passing_metrics();
        metrics.latency_p50 = Duration::from_millis(10); // Fails P50 target

        let report = generator.generate("test", &config, metrics);

        // Overall should fail
        assert!(!report.passed, "Report should fail when any target fails");

        // Count passed/failed validations
        let passed_count = report.target_validations.iter().filter(|v| v.passed).count();
        let failed_count = report.target_validations.iter().filter(|v| !v.passed).count();

        assert_eq!(passed_count, 3, "3 targets should pass");
        assert_eq!(failed_count, 1, "1 target should fail");
    }

    #[test]
    fn test_target_validation_custom_targets() {
        // Test with custom performance targets
        let custom_targets = PerformanceTargets {
            latency_p50_ms: 10,
            latency_p99_ms: 30,
            min_participants: 500,
            throughput_pps: 100_000,
        };
        let generator = ReportGenerator::new(OutputFormat::Console, custom_targets);
        let config = create_test_config();

        // Metrics that would fail default targets but pass custom targets
        let metrics = AggregatedMetrics {
            latency_p50: Duration::from_millis(8),   // < 10ms custom target
            latency_p95: Duration::from_millis(20),
            latency_p99: Duration::from_millis(25),  // < 30ms custom target
            packet_loss_rate: 0.02,
            jitter_avg: Duration::from_millis(2),
            throughput_pps: 150_000.0,  // > 100K custom target
            throughput_bps: 500_000.0,
            connection_success_rate: 0.90,
            avg_time_to_first_frame: Duration::from_millis(75),
            total_clients: 600,
            successful_clients: 550,  // > 500 custom target
            failed_clients: 50,
        };

        let report = generator.generate("stress", &config, metrics);

        assert!(report.passed, "Report should pass with custom targets");
        for validation in &report.target_validations {
            assert!(
                validation.passed,
                "Target '{}' should pass with custom targets",
                validation.name
            );
        }
    }

    #[test]
    fn test_report_contains_all_validations() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(),
        );
        let config = create_test_config();
        let metrics = create_passing_metrics();

        let report = generator.generate("webinar", &config, metrics);

        // Verify all 4 target validations are present
        let validation_names: Vec<&str> = report.target_validations.iter()
            .map(|v| v.name.as_str())
            .collect();

        assert!(validation_names.contains(&"P50 Latency"), "Should have P50 Latency validation");
        assert!(validation_names.contains(&"P99 Latency"), "Should have P99 Latency validation");
        assert!(validation_names.contains(&"Participant Count"), "Should have Participant Count validation");
        assert!(validation_names.contains(&"Throughput"), "Should have Throughput validation");
    }

    #[test]
    fn test_report_metadata() {
        let generator = ReportGenerator::new(
            OutputFormat::Console,
            PerformanceTargets::default(),
        );
        let config = TestConfig {
            sfu_url: "wss://sfu.example.com:8443".to_string(),
            duration: Duration::from_secs(120),
            ..create_test_config()
        };
        let metrics = create_passing_metrics();

        let report = generator.generate("conference", &config, metrics);

        assert_eq!(report.scenario, "conference");
        assert_eq!(report.sfu_url, "wss://sfu.example.com:8443");
        assert_eq!(report.duration_secs, 120);
        assert!(!report.timestamp.is_empty());
    }
}
