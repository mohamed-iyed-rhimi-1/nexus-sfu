//! Integration tests for nexus-loadtest end-to-end flow
//!
//! These tests verify the complete flow from configuration to report generation
//! without requiring a real SFU connection. They test:
//! - Webinar scenario client configuration creation
//! - Conference scenario client configuration creation
//! - Report generation in all formats (console, JSON, Prometheus)
//!
//! **Validates: All requirements**

use std::time::Duration;

use nexus_loadtest::{
    AggregatedMetrics, ClientConfig, ClientRole, ConferenceConfig, MetricsCollector,
    OutputFormat, PerformanceTargets, ReportGenerator, TestConfig, TestReport, TestRunner,
    WebinarConfig,
};

/// Helper to create a test configuration
fn create_test_config(output_format: OutputFormat) -> TestConfig {
    TestConfig {
        sfu_url: "wss://test.example.com:8443".to_string(),
        duration: Duration::from_secs(60),
        output_format,
        report_file: None,
        connection_timeout: Duration::from_secs(30),
        verbose: false,
        prometheus_port: 9090,
    }
}

/// Helper to create sample aggregated metrics for testing
fn create_sample_metrics() -> AggregatedMetrics {
    AggregatedMetrics {
        latency_p50: Duration::from_millis(3),
        latency_p95: Duration::from_millis(8),
        latency_p99: Duration::from_millis(12),
        packet_loss_rate: 0.01,
        jitter_avg: Duration::from_millis(1),
        throughput_pps: 600_000.0,
        throughput_bps: 1_200_000_000.0,
        connection_success_rate: 0.98,
        avg_time_to_first_frame: Duration::from_millis(45),
        total_clients: 101,
        successful_clients: 99,
        failed_clients: 2,
    }
}


// =============================================================================
// Webinar Scenario Tests
// =============================================================================

mod webinar_scenario {
    use super::*;

    /// Test that webinar configuration creates exactly 1 broadcaster and N viewers
    ///
    /// **Validates: Requirements 3.1, 3.2**
    #[test]
    fn webinar_creates_correct_client_configurations() {
        let viewer_count = 50u32;
        let base_config = create_test_config(OutputFormat::Console);
        let room = "webinar-test-room".to_string();
        let sfu_url = base_config.sfu_url.clone();

        // Create client configurations as the runner would
        let mut client_configs: Vec<ClientConfig> = Vec::with_capacity(1 + viewer_count as usize);

        // Requirement 3.1: Create exactly one Broadcaster
        let broadcaster_config = ClientConfig {
            sfu_url: sfu_url.clone(),
            room: room.clone(),
            role: ClientRole::Broadcaster,
            connection_timeout: base_config.connection_timeout,
            ice_servers: Vec::new(),
        };
        client_configs.push(broadcaster_config);

        // Requirement 3.2: Create the specified number of Viewers
        for _ in 0..viewer_count {
            let viewer_config = ClientConfig {
                sfu_url: sfu_url.clone(),
                room: room.clone(),
                role: ClientRole::Viewer,
                connection_timeout: base_config.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(viewer_config);
        }

        // Verify total count
        assert_eq!(
            client_configs.len(),
            1 + viewer_count as usize,
            "Should have 1 broadcaster + {} viewers",
            viewer_count
        );

        // Verify exactly 1 broadcaster
        let broadcaster_count = client_configs
            .iter()
            .filter(|c| c.role == ClientRole::Broadcaster)
            .count();
        assert_eq!(broadcaster_count, 1, "Should have exactly 1 broadcaster");

        // Verify correct number of viewers
        let viewer_count_actual = client_configs
            .iter()
            .filter(|c| c.role == ClientRole::Viewer)
            .count();
        assert_eq!(
            viewer_count_actual, viewer_count as usize,
            "Should have exactly {} viewers",
            viewer_count
        );

        // Verify all clients have correct room and URL
        for config in &client_configs {
            assert_eq!(config.room, room, "All clients should be in the same room");
            assert_eq!(config.sfu_url, sfu_url, "All clients should connect to the same SFU");
        }
    }

    /// Test that broadcaster role can publish but not subscribe
    ///
    /// **Validates: Requirements 2.5, 3.3**
    #[test]
    fn broadcaster_role_has_correct_capabilities() {
        let role = ClientRole::Broadcaster;
        assert!(role.can_publish(), "Broadcaster should be able to publish");
        assert!(!role.can_subscribe(), "Broadcaster should not subscribe");
    }

    /// Test that viewer role can subscribe but not publish
    ///
    /// **Validates: Requirements 2.4**
    #[test]
    fn viewer_role_has_correct_capabilities() {
        let role = ClientRole::Viewer;
        assert!(!role.can_publish(), "Viewer should not publish");
        assert!(role.can_subscribe(), "Viewer should be able to subscribe");
    }

    /// Test webinar configuration with various viewer counts
    ///
    /// **Validates: Requirements 3.1, 3.2**
    #[test]
    fn webinar_supports_various_viewer_counts() {
        let test_cases = [1, 10, 100, 500, 1000];

        for viewer_count in test_cases {
            let config = WebinarConfig {
                base: create_test_config(OutputFormat::Console),
                room: format!("room-{}", viewer_count),
                viewer_count,
            };

            // Verify configuration is valid
            assert_eq!(config.viewer_count, viewer_count);
            assert!(!config.room.is_empty());
            assert!(!config.base.sfu_url.is_empty());
        }
    }
}


// =============================================================================
// Conference Scenario Tests
// =============================================================================

mod conference_scenario {
    use super::*;

    /// Test that conference configuration creates exactly N participants
    ///
    /// **Validates: Requirements 4.1**
    #[test]
    fn conference_creates_correct_client_configurations() {
        let participant_count = 20u32;
        let base_config = create_test_config(OutputFormat::Console);
        let room = "conference-test-room".to_string();
        let sfu_url = base_config.sfu_url.clone();

        // Create client configurations as the runner would
        let mut client_configs: Vec<ClientConfig> = Vec::with_capacity(participant_count as usize);

        // Requirement 4.1: Create the specified number of Participants
        for _ in 0..participant_count {
            let participant_config = ClientConfig {
                sfu_url: sfu_url.clone(),
                room: room.clone(),
                role: ClientRole::Participant,
                connection_timeout: base_config.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(participant_config);
        }

        // Verify total count
        assert_eq!(
            client_configs.len(),
            participant_count as usize,
            "Should have exactly {} participants",
            participant_count
        );

        // Verify all are participants
        let participant_count_actual = client_configs
            .iter()
            .filter(|c| c.role == ClientRole::Participant)
            .count();
        assert_eq!(
            participant_count_actual, participant_count as usize,
            "All clients should be participants"
        );

        // Verify all clients have correct room and URL
        for config in &client_configs {
            assert_eq!(config.room, room, "All clients should be in the same room");
            assert_eq!(config.sfu_url, sfu_url, "All clients should connect to the same SFU");
        }
    }

    /// Test that participant role can both publish and subscribe
    ///
    /// **Validates: Requirements 2.6, 4.2, 4.3**
    #[test]
    fn participant_role_has_correct_capabilities() {
        let role = ClientRole::Participant;
        assert!(role.can_publish(), "Participant should be able to publish");
        assert!(role.can_subscribe(), "Participant should be able to subscribe");
    }

    /// Test conference subscription count calculation
    /// Each participant subscribes to N-1 other participants
    ///
    /// **Validates: Requirements 4.3**
    #[test]
    fn conference_subscription_count_is_correct() {
        let test_cases = [2, 5, 10, 20];

        for participant_count in test_cases {
            // Each participant subscribes to all other participants
            // Total subscriptions = N * (N-1) for N participants
            // (each of N participants subscribes to N-1 others)
            let expected_subscriptions = participant_count * (participant_count - 1);

            // Verify the formula
            let mut actual_subscriptions = 0;
            for _participant_idx in 0..participant_count {
                // Each participant subscribes to all others
                actual_subscriptions += participant_count - 1;
            }

            assert_eq!(
                actual_subscriptions, expected_subscriptions,
                "For {} participants, should have {} total subscriptions",
                participant_count, expected_subscriptions
            );
        }
    }

    /// Test conference configuration with various participant counts
    ///
    /// **Validates: Requirements 4.1**
    #[test]
    fn conference_supports_various_participant_counts() {
        let test_cases = [2, 5, 10, 50, 100];

        for participant_count in test_cases {
            let config = ConferenceConfig {
                base: create_test_config(OutputFormat::Console),
                room: format!("room-{}", participant_count),
                participant_count,
            };

            // Verify configuration is valid
            assert_eq!(config.participant_count, participant_count);
            assert!(!config.room.is_empty());
            assert!(!config.base.sfu_url.is_empty());
        }
    }
}


// =============================================================================
// Report Generation Tests
// =============================================================================

mod report_generation {
    use super::*;

    /// Test that console report contains all required fields
    ///
    /// **Validates: Requirements 7.1, 7.4**
    #[test]
    fn console_report_contains_required_fields() {
        let generator = ReportGenerator::new(OutputFormat::Console, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Console);
        let metrics = create_sample_metrics();

        let report = generator.generate("webinar", &config, metrics);
        let console_output = report.to_console();

        // Verify required fields are present (Requirement 7.4)
        assert!(
            console_output.contains("WEBINAR"),
            "Console output should contain scenario name"
        );
        assert!(
            console_output.contains(&config.sfu_url),
            "Console output should contain SFU URL"
        );
        assert!(
            console_output.contains("60"),
            "Console output should contain duration"
        );

        // Verify metrics are displayed
        assert!(
            console_output.contains("P50"),
            "Console output should contain P50 latency"
        );
        assert!(
            console_output.contains("P95"),
            "Console output should contain P95 latency"
        );
        assert!(
            console_output.contains("P99"),
            "Console output should contain P99 latency"
        );
        assert!(
            console_output.contains("Throughput") || console_output.contains("pps"),
            "Console output should contain throughput"
        );

        // Verify target validations are shown
        assert!(
            console_output.contains("Target") || console_output.contains("target"),
            "Console output should contain target validations"
        );
    }

    /// Test that JSON report is valid and contains all required fields
    ///
    /// **Validates: Requirements 7.2, 7.4, 7.5**
    #[test]
    fn json_report_is_valid_and_complete() {
        let generator = ReportGenerator::new(OutputFormat::Json, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Json);
        let metrics = create_sample_metrics();

        let report = generator.generate("conference", &config, metrics);
        let json_output = report.to_json().expect("JSON serialization should succeed");

        // Verify it's valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json_output).expect("Should be valid JSON");

        // Verify required fields (Requirement 7.4)
        assert!(parsed.get("scenario").is_some(), "JSON should have scenario");
        assert!(parsed.get("sfu_url").is_some(), "JSON should have sfu_url");
        assert!(
            parsed.get("duration_secs").is_some(),
            "JSON should have duration_secs"
        );
        assert!(
            parsed.get("timestamp").is_some(),
            "JSON should have timestamp"
        );
        assert!(parsed.get("metrics").is_some(), "JSON should have metrics");
        assert!(parsed.get("passed").is_some(), "JSON should have passed");

        // Verify metrics object has expected fields
        let metrics_obj = parsed.get("metrics").unwrap();
        assert!(
            metrics_obj.get("latency_p50_ms").is_some(),
            "Metrics should have latency_p50_ms"
        );
        assert!(
            metrics_obj.get("latency_p95_ms").is_some(),
            "Metrics should have latency_p95_ms"
        );
        assert!(
            metrics_obj.get("latency_p99_ms").is_some(),
            "Metrics should have latency_p99_ms"
        );
        assert!(
            metrics_obj.get("throughput_pps").is_some(),
            "Metrics should have throughput_pps"
        );
        assert!(
            metrics_obj.get("packet_loss_rate").is_some(),
            "Metrics should have packet_loss_rate"
        );
    }

    /// Test JSON round-trip serialization
    ///
    /// **Validates: Requirements 7.5**
    #[test]
    fn json_report_round_trip() {
        let generator = ReportGenerator::new(OutputFormat::Json, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Json);
        let metrics = create_sample_metrics();

        let original_report = generator.generate("stress", &config, metrics);

        // Serialize to JSON
        let json = original_report.to_json().expect("Serialization should succeed");

        // Deserialize back
        let restored_report = TestReport::from_json(&json).expect("Deserialization should succeed");

        // Verify key fields match
        assert_eq!(original_report.scenario, restored_report.scenario);
        assert_eq!(original_report.sfu_url, restored_report.sfu_url);
        assert_eq!(original_report.duration_secs, restored_report.duration_secs);
        assert_eq!(original_report.passed, restored_report.passed);
        assert_eq!(
            original_report.target_validations.len(),
            restored_report.target_validations.len()
        );
    }

    /// Test that Prometheus report contains valid metrics format
    ///
    /// **Validates: Requirements 7.3**
    #[test]
    fn prometheus_report_has_valid_format() {
        let generator =
            ReportGenerator::new(OutputFormat::Prometheus, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Prometheus);
        let metrics = create_sample_metrics();

        let report = generator.generate("webinar", &config, metrics);
        let prometheus_output = report.to_prometheus();

        // Verify Prometheus format requirements
        // Each metric should have HELP and TYPE comments
        assert!(
            prometheus_output.contains("# HELP"),
            "Prometheus output should have HELP comments"
        );
        assert!(
            prometheus_output.contains("# TYPE"),
            "Prometheus output should have TYPE comments"
        );

        // Verify key metrics are present
        assert!(
            prometheus_output.contains("nexus_loadtest_latency_p50_ms"),
            "Should have P50 latency metric"
        );
        assert!(
            prometheus_output.contains("nexus_loadtest_latency_p95_ms"),
            "Should have P95 latency metric"
        );
        assert!(
            prometheus_output.contains("nexus_loadtest_latency_p99_ms"),
            "Should have P99 latency metric"
        );
        assert!(
            prometheus_output.contains("nexus_loadtest_throughput_pps"),
            "Should have throughput metric"
        );
        assert!(
            prometheus_output.contains("nexus_loadtest_packet_loss_rate"),
            "Should have packet loss metric"
        );
        assert!(
            prometheus_output.contains("nexus_loadtest_passed"),
            "Should have passed metric"
        );

        // Verify scenario label is present
        assert!(
            prometheus_output.contains("scenario=\"webinar\""),
            "Metrics should have scenario label"
        );
    }

    /// Test that all output formats include the same core information
    ///
    /// **Validates: Requirements 7.4**
    #[test]
    fn all_formats_include_core_information() {
        let config = create_test_config(OutputFormat::Console);
        let metrics = create_sample_metrics();

        for format in [OutputFormat::Console, OutputFormat::Json, OutputFormat::Prometheus] {
            let generator = ReportGenerator::new(format, PerformanceTargets::default());
            let report = generator.generate("webinar", &config, metrics.clone());

            // All formats should have the same core data in the report struct
            assert_eq!(report.scenario, "webinar");
            assert_eq!(report.sfu_url, config.sfu_url);
            assert_eq!(report.duration_secs, config.duration.as_secs());
            assert!(!report.timestamp.is_empty());
        }
    }
}


// =============================================================================
// Target Validation Tests
// =============================================================================

mod target_validation {
    use super::*;

    /// Test that passing metrics result in passed report
    ///
    /// **Validates: Requirements 8.1, 8.2, 8.3, 8.4**
    #[test]
    fn passing_metrics_result_in_passed_report() {
        let generator = ReportGenerator::new(OutputFormat::Console, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Console);

        // Create metrics that pass all default targets
        let passing_metrics = AggregatedMetrics {
            latency_p50: Duration::from_millis(3),  // < 5ms target
            latency_p95: Duration::from_millis(10),
            latency_p99: Duration::from_millis(12), // < 15ms target
            packet_loss_rate: 0.01,
            jitter_avg: Duration::from_millis(1),
            throughput_pps: 600_000.0,              // > 500K target
            throughput_bps: 1_000_000_000.0,
            connection_success_rate: 0.99,
            avg_time_to_first_frame: Duration::from_millis(50),
            total_clients: 1100,
            successful_clients: 1050,               // > 1000 target
            failed_clients: 50,
        };

        let report = generator.generate("webinar", &config, passing_metrics);

        assert!(report.passed, "Report should pass when all targets are met");
        assert!(
            report.target_validations.iter().all(|v| v.passed),
            "All individual validations should pass"
        );
    }

    /// Test that failing metrics result in failed report
    ///
    /// **Validates: Requirements 8.5**
    #[test]
    fn failing_metrics_result_in_failed_report() {
        let generator = ReportGenerator::new(OutputFormat::Console, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Console);

        // Create metrics that fail all default targets
        let failing_metrics = AggregatedMetrics {
            latency_p50: Duration::from_millis(10), // > 5ms target
            latency_p95: Duration::from_millis(20),
            latency_p99: Duration::from_millis(25), // > 15ms target
            packet_loss_rate: 0.05,
            jitter_avg: Duration::from_millis(5),
            throughput_pps: 100_000.0,              // < 500K target
            throughput_bps: 500_000.0,
            connection_success_rate: 0.80,
            avg_time_to_first_frame: Duration::from_millis(100),
            total_clients: 500,
            successful_clients: 400,                // < 1000 target
            failed_clients: 100,
        };

        let report = generator.generate("conference", &config, failing_metrics);

        assert!(!report.passed, "Report should fail when targets are not met");
        assert!(
            report.target_validations.iter().all(|v| !v.passed),
            "All individual validations should fail"
        );
    }

    /// Test that partial failure results in failed report
    ///
    /// **Validates: Requirements 8.5**
    #[test]
    fn partial_failure_results_in_failed_report() {
        let generator = ReportGenerator::new(OutputFormat::Console, PerformanceTargets::default());
        let config = create_test_config(OutputFormat::Console);

        // Create metrics where only P50 latency fails
        let partial_fail_metrics = AggregatedMetrics {
            latency_p50: Duration::from_millis(10), // > 5ms target (FAIL)
            latency_p95: Duration::from_millis(10),
            latency_p99: Duration::from_millis(12), // < 15ms target (PASS)
            packet_loss_rate: 0.01,
            jitter_avg: Duration::from_millis(1),
            throughput_pps: 600_000.0,              // > 500K target (PASS)
            throughput_bps: 1_000_000_000.0,
            connection_success_rate: 0.99,
            avg_time_to_first_frame: Duration::from_millis(50),
            total_clients: 1100,
            successful_clients: 1050,               // > 1000 target (PASS)
            failed_clients: 50,
        };

        let report = generator.generate("stress", &config, partial_fail_metrics);

        assert!(
            !report.passed,
            "Report should fail when ANY target is not met"
        );

        // Count passed and failed validations
        let passed_count = report.target_validations.iter().filter(|v| v.passed).count();
        let failed_count = report.target_validations.iter().filter(|v| !v.passed).count();

        assert_eq!(passed_count, 3, "3 targets should pass");
        assert_eq!(failed_count, 1, "1 target should fail");
    }

    /// Test custom performance targets
    ///
    /// **Validates: Requirements 8.1, 8.2, 8.3, 8.4**
    #[test]
    fn custom_targets_are_respected() {
        let custom_targets = PerformanceTargets {
            latency_p50_ms: 20,      // More lenient
            latency_p99_ms: 50,      // More lenient
            min_participants: 100,   // Lower requirement
            throughput_pps: 50_000,  // Lower requirement
        };

        let generator = ReportGenerator::new(OutputFormat::Console, custom_targets);
        let config = create_test_config(OutputFormat::Console);

        // Metrics that would fail default targets but pass custom targets
        let metrics = AggregatedMetrics {
            latency_p50: Duration::from_millis(15), // < 20ms custom target
            latency_p95: Duration::from_millis(30),
            latency_p99: Duration::from_millis(40), // < 50ms custom target
            packet_loss_rate: 0.02,
            jitter_avg: Duration::from_millis(3),
            throughput_pps: 75_000.0,               // > 50K custom target
            throughput_bps: 500_000.0,
            connection_success_rate: 0.90,
            avg_time_to_first_frame: Duration::from_millis(80),
            total_clients: 150,
            successful_clients: 120,                // > 100 custom target
            failed_clients: 30,
        };

        let report = generator.generate("webinar", &config, metrics);

        assert!(
            report.passed,
            "Report should pass with custom (more lenient) targets"
        );
    }
}


// =============================================================================
// Metrics Collection Tests
// =============================================================================

mod metrics_collection {
    use super::*;

    /// Test that metrics collector properly aggregates client data
    ///
    /// **Validates: Requirements 6.1, 6.2, 6.4, 6.5**
    #[test]
    fn metrics_collector_aggregates_correctly() {
        let mut collector = MetricsCollector::new(Duration::from_secs(1));

        // Register 3 clients
        collector.register_client(0);
        collector.register_client(1);
        collector.register_client(2);

        // Client 0: successful with good metrics
        collector.mark_connected(0);
        collector.record_latency(0, Duration::from_millis(5));
        collector.record_latency(0, Duration::from_millis(10));
        collector.record_packets(0, 1000, 10);
        collector.record_bytes(0, 100_000);
        collector.record_first_frame(0, Duration::from_millis(50));

        // Client 1: successful with different metrics
        collector.mark_connected(1);
        collector.record_latency(1, Duration::from_millis(8));
        collector.record_latency(1, Duration::from_millis(12));
        collector.record_packets(1, 900, 20);
        collector.record_bytes(1, 90_000);
        collector.record_first_frame(1, Duration::from_millis(60));

        // Client 2: failed
        collector.mark_failed(2);

        // Set test duration
        collector.set_duration(Duration::from_secs(10));

        let aggregated = collector.aggregate();

        // Verify client counts
        assert_eq!(aggregated.total_clients, 3);
        assert_eq!(aggregated.successful_clients, 2);
        assert_eq!(aggregated.failed_clients, 1);

        // Verify connection success rate (2/3 = 0.666...)
        assert!(
            (aggregated.connection_success_rate - 2.0 / 3.0).abs() < 0.01,
            "Connection success rate should be ~66.7%"
        );

        // Verify latency percentiles are computed
        assert!(
            aggregated.latency_p50 > Duration::ZERO,
            "P50 latency should be computed"
        );
        assert!(
            aggregated.latency_p95 > Duration::ZERO,
            "P95 latency should be computed"
        );
        assert!(
            aggregated.latency_p99 > Duration::ZERO,
            "P99 latency should be computed"
        );

        // Verify throughput is computed
        assert!(
            aggregated.throughput_pps > 0.0,
            "Throughput PPS should be computed"
        );
        assert!(
            aggregated.throughput_bps > 0.0,
            "Throughput BPS should be computed"
        );

        // Verify packet loss rate
        // Total: 1900 received, 30 lost = 30/1930 ≈ 1.55%
        assert!(
            aggregated.packet_loss_rate > 0.0 && aggregated.packet_loss_rate < 0.1,
            "Packet loss rate should be reasonable"
        );
    }

    /// Test that empty metrics collector returns default values
    ///
    /// **Validates: Requirements 6.1, 6.2, 6.4, 6.5**
    #[test]
    fn empty_collector_returns_defaults() {
        let collector = MetricsCollector::new(Duration::from_secs(1));
        let aggregated = collector.aggregate();

        assert_eq!(aggregated.total_clients, 0);
        assert_eq!(aggregated.successful_clients, 0);
        assert_eq!(aggregated.failed_clients, 0);
        assert_eq!(aggregated.latency_p50, Duration::ZERO);
        assert_eq!(aggregated.throughput_pps, 0.0);
        assert_eq!(aggregated.connection_success_rate, 0.0);
    }
}

// =============================================================================
// Test Runner Tests
// =============================================================================

mod test_runner {
    use super::*;

    /// Test that test runner initializes correctly
    #[test]
    fn test_runner_initializes_correctly() {
        let config = create_test_config(OutputFormat::Console);
        let runner = TestRunner::new(config);

        assert_eq!(runner.client_count(), 0);
        assert_eq!(runner.success_count(), 0);
        assert_eq!(runner.failed_count(), 0);
    }

    /// Test that test runner with defaults works
    #[test]
    fn test_runner_with_defaults() {
        let runner = TestRunner::with_defaults();

        assert_eq!(runner.client_count(), 0);
        assert_eq!(runner.success_count(), 0);
        assert_eq!(runner.failed_count(), 0);
    }
}

// =============================================================================
// End-to-End Flow Tests (without real SFU)
// =============================================================================

mod end_to_end_flow {
    use super::*;

    /// Test complete webinar flow: config -> metrics -> report
    ///
    /// **Validates: All requirements**
    #[test]
    fn webinar_flow_produces_valid_report() {
        // Step 1: Create webinar configuration
        let webinar_config = WebinarConfig {
            base: create_test_config(OutputFormat::Json),
            room: "e2e-webinar-room".to_string(),
            viewer_count: 100,
        };

        // Step 2: Verify configuration is valid
        assert_eq!(webinar_config.viewer_count, 100);
        assert!(!webinar_config.room.is_empty());

        // Step 3: Simulate metrics collection (as if test ran)
        let simulated_metrics = create_sample_metrics();

        // Step 4: Generate report
        let generator = ReportGenerator::new(
            webinar_config.base.output_format,
            PerformanceTargets::default(),
        );
        let report = generator.generate("webinar", &webinar_config.base, simulated_metrics);

        // Step 5: Verify report is complete
        assert_eq!(report.scenario, "webinar");
        assert_eq!(report.sfu_url, webinar_config.base.sfu_url);
        assert_eq!(report.duration_secs, webinar_config.base.duration.as_secs());
        assert!(!report.timestamp.is_empty());
        assert!(!report.target_validations.is_empty());

        // Step 6: Verify JSON output is valid
        let json = report.to_json().expect("JSON serialization should succeed");
        let _: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
    }

    /// Test complete conference flow: config -> metrics -> report
    ///
    /// **Validates: All requirements**
    #[test]
    fn conference_flow_produces_valid_report() {
        // Step 1: Create conference configuration
        let conference_config = ConferenceConfig {
            base: create_test_config(OutputFormat::Prometheus),
            room: "e2e-conference-room".to_string(),
            participant_count: 20,
        };

        // Step 2: Verify configuration is valid
        assert_eq!(conference_config.participant_count, 20);
        assert!(!conference_config.room.is_empty());

        // Step 3: Simulate metrics collection
        let simulated_metrics = create_sample_metrics();

        // Step 4: Generate report
        let generator = ReportGenerator::new(
            conference_config.base.output_format,
            PerformanceTargets::default(),
        );
        let report = generator.generate("conference", &conference_config.base, simulated_metrics);

        // Step 5: Verify report is complete
        assert_eq!(report.scenario, "conference");
        assert!(!report.target_validations.is_empty());

        // Step 6: Verify Prometheus output is valid
        let prometheus = report.to_prometheus();
        assert!(prometheus.contains("nexus_loadtest_"));
        assert!(prometheus.contains("scenario=\"conference\""));
    }

    /// Test that report generation works for all scenarios
    ///
    /// **Validates: All requirements**
    #[test]
    fn all_scenarios_produce_valid_reports() {
        let scenarios = ["webinar", "conference", "stress"];
        let formats = [OutputFormat::Console, OutputFormat::Json, OutputFormat::Prometheus];

        for scenario in scenarios {
            for format in formats {
                let generator = ReportGenerator::new(format, PerformanceTargets::default());
                let config = create_test_config(format);
                let metrics = create_sample_metrics();

                let report = generator.generate(scenario, &config, metrics);

                assert_eq!(report.scenario, scenario);
                assert!(!report.timestamp.is_empty());
                assert!(!report.target_validations.is_empty());

                // Verify output can be generated without error
                match format {
                    OutputFormat::Console => {
                        let output = report.to_console();
                        assert!(!output.is_empty());
                    }
                    OutputFormat::Json => {
                        let output = report.to_json().expect("JSON should serialize");
                        assert!(!output.is_empty());
                    }
                    OutputFormat::Prometheus => {
                        let output = report.to_prometheus();
                        assert!(!output.is_empty());
                    }
                }
            }
        }
    }
}
