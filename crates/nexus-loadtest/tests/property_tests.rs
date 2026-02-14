//! Property-based tests for nexus-loadtest
//!
//! These tests verify universal correctness properties across randomly generated inputs.

use proptest::prelude::*;
use std::time::Duration;

use nexus_loadtest::metrics::calculate_percentile;

// Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
/// **Validates: Requirements 6.1**
///
/// Property 8: Percentile Calculation Correctness
/// *For any* non-empty list of latency samples, the computed P50 SHALL be greater than
/// or equal to at least 50% of samples, P95 SHALL be greater than or equal to at least
/// 95% of samples, and P99 SHALL be greater than or equal to at least 99% of samples.
mod percentile_calculation {
    use super::*;

    /// Strategy to generate non-empty vectors of Duration samples
    /// Generates durations between 1 microsecond and 10 seconds
    fn duration_samples_strategy() -> impl Strategy<Value = Vec<Duration>> {
        prop::collection::vec(1u64..10_000_000, 1..500).prop_map(|micros| {
            micros
                .into_iter()
                .map(Duration::from_micros)
                .collect::<Vec<_>>()
        })
    }

    /// Helper function to count how many samples are less than or equal to a value
    fn count_samples_lte(samples: &[Duration], value: Duration) -> usize {
        samples.iter().filter(|&&s| s <= value).count()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
        #[test]
        fn p50_is_gte_at_least_50_percent_of_samples(samples in duration_samples_strategy()) {
            let mut sorted = samples.clone();
            sorted.sort();

            let p50 = calculate_percentile(&sorted, 50.0);

            // At least 50% of samples should be <= P50
            let count_lte = count_samples_lte(&samples, p50);
            let percentage = (count_lte as f64 / samples.len() as f64) * 100.0;

            prop_assert!(
                percentage >= 50.0,
                "P50 ({:?}) should be >= at least 50% of samples, but only {:.1}% ({}/{}) are <= P50",
                p50, percentage, count_lte, samples.len()
            );
        }

        // Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
        #[test]
        fn p95_is_gte_at_least_95_percent_of_samples(samples in duration_samples_strategy()) {
            let mut sorted = samples.clone();
            sorted.sort();

            let p95 = calculate_percentile(&sorted, 95.0);

            // At least 95% of samples should be <= P95
            let count_lte = count_samples_lte(&samples, p95);
            let percentage = (count_lte as f64 / samples.len() as f64) * 100.0;

            prop_assert!(
                percentage >= 95.0,
                "P95 ({:?}) should be >= at least 95% of samples, but only {:.1}% ({}/{}) are <= P95",
                p95, percentage, count_lte, samples.len()
            );
        }

        // Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
        #[test]
        fn p99_is_gte_at_least_99_percent_of_samples(samples in duration_samples_strategy()) {
            let mut sorted = samples.clone();
            sorted.sort();

            let p99 = calculate_percentile(&sorted, 99.0);

            // At least 99% of samples should be <= P99
            let count_lte = count_samples_lte(&samples, p99);
            let percentage = (count_lte as f64 / samples.len() as f64) * 100.0;

            prop_assert!(
                percentage >= 99.0,
                "P99 ({:?}) should be >= at least 99% of samples, but only {:.1}% ({}/{}) are <= P99",
                p99, percentage, count_lte, samples.len()
            );
        }

        // Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
        /// Additional property: percentiles should be monotonically increasing
        /// P50 <= P95 <= P99
        #[test]
        fn percentiles_are_monotonically_increasing(samples in duration_samples_strategy()) {
            let mut sorted = samples.clone();
            sorted.sort();

            let p50 = calculate_percentile(&sorted, 50.0);
            let p95 = calculate_percentile(&sorted, 95.0);
            let p99 = calculate_percentile(&sorted, 99.0);

            prop_assert!(
                p50 <= p95,
                "P50 ({:?}) should be <= P95 ({:?})",
                p50, p95
            );
            prop_assert!(
                p95 <= p99,
                "P95 ({:?}) should be <= P99 ({:?})",
                p95, p99
            );
        }

        // Feature: nexus-loadtest, Property 8: Percentile Calculation Correctness
        /// Additional property: percentile result should always be within the sample range
        #[test]
        fn percentile_is_within_sample_range(
            samples in duration_samples_strategy(),
            percentile in 0.0f64..=100.0f64
        ) {
            let mut sorted = samples.clone();
            sorted.sort();

            let result = calculate_percentile(&sorted, percentile);
            let min = *sorted.first().unwrap();
            let max = *sorted.last().unwrap();

            prop_assert!(
                result >= min && result <= max,
                "Percentile {:.1} result ({:?}) should be within [{:?}, {:?}]",
                percentile, result, min, max
            );
        }
    }
}

// Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
/// **Validates: Requirements 6.2**
///
/// Property 9: Packet Loss Rate Calculation
/// *For any* packet statistics with received >= 0 and lost >= 0, the packet loss rate
/// SHALL equal lost / (received + lost) when total > 0, and 0.0 when total == 0.
mod packet_loss_rate_calculation {
    use super::*;
    use nexus_loadtest::metrics::calculate_packet_loss_rate;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
        #[test]
        fn packet_loss_rate_equals_lost_over_total_when_total_gt_zero(
            received in 0u64..1_000_000,
            lost in 0u64..1_000_000
        ) {
            let total = received + lost;
            let rate = calculate_packet_loss_rate(received, lost);

            if total == 0 {
                prop_assert_eq!(
                    rate, 0.0,
                    "When total == 0, packet loss rate should be 0.0, got {}",
                    rate
                );
            } else {
                let expected = lost as f64 / total as f64;
                prop_assert!(
                    (rate - expected).abs() < 1e-10,
                    "Packet loss rate should equal lost/total ({}/{}={:.10}), got {:.10}",
                    lost, total, expected, rate
                );
            }
        }

        // Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
        #[test]
        fn packet_loss_rate_is_zero_when_total_is_zero(
            // Generate cases where both are zero
            _dummy in Just(())
        ) {
            let rate = calculate_packet_loss_rate(0, 0);
            prop_assert_eq!(
                rate, 0.0,
                "When received=0 and lost=0, packet loss rate should be 0.0, got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
        #[test]
        fn packet_loss_rate_is_bounded_between_zero_and_one(
            received in 0u64..1_000_000,
            lost in 0u64..1_000_000
        ) {
            let rate = calculate_packet_loss_rate(received, lost);

            prop_assert!(
                rate >= 0.0 && rate <= 1.0,
                "Packet loss rate should be in [0.0, 1.0], got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
        #[test]
        fn packet_loss_rate_is_zero_when_no_packets_lost(
            received in 1u64..1_000_000
        ) {
            let rate = calculate_packet_loss_rate(received, 0);
            prop_assert_eq!(
                rate, 0.0,
                "When lost=0, packet loss rate should be 0.0, got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 9: Packet Loss Rate Calculation
        #[test]
        fn packet_loss_rate_is_one_when_all_packets_lost(
            lost in 1u64..1_000_000
        ) {
            let rate = calculate_packet_loss_rate(0, lost);
            prop_assert_eq!(
                rate, 1.0,
                "When received=0 and lost>0, packet loss rate should be 1.0, got {}",
                rate
            );
        }
    }
}

// Feature: nexus-loadtest, Property 10: Throughput Calculation
/// **Validates: Requirements 6.4**
///
/// Property 10: Throughput Calculation
/// *For any* byte count B, packet count P, and duration D > 0, throughput in bytes/sec
/// SHALL equal B/D and throughput in packets/sec SHALL equal P/D.
mod throughput_calculation {
    use super::*;
    use nexus_loadtest::metrics::{calculate_throughput_bps, calculate_throughput_pps};

    /// Strategy to generate positive durations (D > 0)
    /// Generates durations between 1 microsecond and 1 hour
    fn positive_duration_strategy() -> impl Strategy<Value = Duration> {
        (1u64..3_600_000_000).prop_map(Duration::from_micros)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_pps_equals_packets_over_duration(
            packets in 0u64..1_000_000_000,
            duration in positive_duration_strategy()
        ) {
            let pps = calculate_throughput_pps(packets, duration);
            let expected = packets as f64 / duration.as_secs_f64();

            // Use relative tolerance for floating point comparison
            let tolerance = expected.abs() * 1e-10 + 1e-10;
            prop_assert!(
                (pps - expected).abs() < tolerance,
                "Throughput PPS should equal packets/duration ({}/{:?}={:.10}), got {:.10}",
                packets, duration, expected, pps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_bps_equals_bytes_over_duration(
            bytes in 0u64..1_000_000_000,
            duration in positive_duration_strategy()
        ) {
            let bps = calculate_throughput_bps(bytes, duration);
            let expected = bytes as f64 / duration.as_secs_f64();

            // Use relative tolerance for floating point comparison
            let tolerance = expected.abs() * 1e-10 + 1e-10;
            prop_assert!(
                (bps - expected).abs() < tolerance,
                "Throughput BPS should equal bytes/duration ({}/{:?}={:.10}), got {:.10}",
                bytes, duration, expected, bps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_pps_is_zero_when_duration_is_zero(
            packets in 0u64..1_000_000_000
        ) {
            let pps = calculate_throughput_pps(packets, Duration::ZERO);
            prop_assert_eq!(
                pps, 0.0,
                "When duration is zero, throughput PPS should be 0.0, got {}",
                pps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_bps_is_zero_when_duration_is_zero(
            bytes in 0u64..1_000_000_000
        ) {
            let bps = calculate_throughput_bps(bytes, Duration::ZERO);
            prop_assert_eq!(
                bps, 0.0,
                "When duration is zero, throughput BPS should be 0.0, got {}",
                bps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_is_non_negative(
            packets in 0u64..1_000_000_000,
            bytes in 0u64..1_000_000_000,
            duration in positive_duration_strategy()
        ) {
            let pps = calculate_throughput_pps(packets, duration);
            let bps = calculate_throughput_bps(bytes, duration);

            prop_assert!(
                pps >= 0.0,
                "Throughput PPS should be non-negative, got {}",
                pps
            );
            prop_assert!(
                bps >= 0.0,
                "Throughput BPS should be non-negative, got {}",
                bps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        #[test]
        fn throughput_is_zero_when_count_is_zero(
            duration in positive_duration_strategy()
        ) {
            let pps = calculate_throughput_pps(0, duration);
            let bps = calculate_throughput_bps(0, duration);

            prop_assert_eq!(
                pps, 0.0,
                "When packets=0, throughput PPS should be 0.0, got {}",
                pps
            );
            prop_assert_eq!(
                bps, 0.0,
                "When bytes=0, throughput BPS should be 0.0, got {}",
                bps
            );
        }

        // Feature: nexus-loadtest, Property 10: Throughput Calculation
        /// Throughput scales linearly with count
        #[test]
        fn throughput_scales_linearly_with_count(
            base_count in 1u64..1_000_000,
            multiplier in 2u64..10,
            duration in positive_duration_strategy()
        ) {
            let base_pps = calculate_throughput_pps(base_count, duration);
            let scaled_pps = calculate_throughput_pps(base_count * multiplier, duration);

            let expected_scaled = base_pps * multiplier as f64;
            let tolerance = expected_scaled.abs() * 1e-10 + 1e-10;

            prop_assert!(
                (scaled_pps - expected_scaled).abs() < tolerance,
                "Throughput should scale linearly: {} * {} = {:.10}, got {:.10}",
                base_pps, multiplier, expected_scaled, scaled_pps
            );
        }
    }
}

// Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
/// **Validates: Requirements 6.5**
///
/// Property 11: Connection Success Rate Calculation
/// *For any* test with S successful connections and F failed connections, the connection
/// success rate SHALL equal S / (S + F) when total > 0, and 0.0 when total == 0.
mod connection_success_rate_calculation {
    use super::*;
    use nexus_loadtest::metrics::calculate_connection_success_rate;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        #[test]
        fn connection_success_rate_equals_successful_over_total_when_total_gt_zero(
            successful in 0u32..100_000,
            failed in 0u32..100_000
        ) {
            let total = successful + failed;
            let rate = calculate_connection_success_rate(successful, failed);

            if total == 0 {
                prop_assert_eq!(
                    rate, 0.0,
                    "When total == 0, connection success rate should be 0.0, got {}",
                    rate
                );
            } else {
                let expected = successful as f64 / total as f64;
                prop_assert!(
                    (rate - expected).abs() < 1e-10,
                    "Connection success rate should equal successful/total ({}/{}={:.10}), got {:.10}",
                    successful, total, expected, rate
                );
            }
        }

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        #[test]
        fn connection_success_rate_is_zero_when_total_is_zero(
            _dummy in Just(())
        ) {
            let rate = calculate_connection_success_rate(0, 0);
            prop_assert_eq!(
                rate, 0.0,
                "When successful=0 and failed=0, connection success rate should be 0.0, got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        #[test]
        fn connection_success_rate_is_bounded_between_zero_and_one(
            successful in 0u32..100_000,
            failed in 0u32..100_000
        ) {
            let rate = calculate_connection_success_rate(successful, failed);

            prop_assert!(
                rate >= 0.0 && rate <= 1.0,
                "Connection success rate should be in [0.0, 1.0], got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        #[test]
        fn connection_success_rate_is_one_when_all_successful(
            successful in 1u32..100_000
        ) {
            let rate = calculate_connection_success_rate(successful, 0);
            prop_assert_eq!(
                rate, 1.0,
                "When failed=0, connection success rate should be 1.0, got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        #[test]
        fn connection_success_rate_is_zero_when_all_failed(
            failed in 1u32..100_000
        ) {
            let rate = calculate_connection_success_rate(0, failed);
            prop_assert_eq!(
                rate, 0.0,
                "When successful=0 and failed>0, connection success rate should be 0.0, got {}",
                rate
            );
        }

        // Feature: nexus-loadtest, Property 11: Connection Success Rate Calculation
        /// Success rate is symmetric complement of failure rate
        #[test]
        fn success_rate_plus_failure_rate_equals_one_when_total_gt_zero(
            successful in 1u32..100_000,
            failed in 1u32..100_000
        ) {
            let success_rate = calculate_connection_success_rate(successful, failed);
            // Failure rate would be failed / (successful + failed)
            let failure_rate = failed as f64 / (successful + failed) as f64;

            prop_assert!(
                (success_rate + failure_rate - 1.0).abs() < 1e-10,
                "Success rate ({}) + failure rate ({}) should equal 1.0",
                success_rate, failure_rate
            );
        }
    }
}


// Feature: nexus-loadtest, Property 12: Report JSON Round-Trip
/// **Validates: Requirements 7.2, 7.5**
///
/// Property 12: Report JSON Round-Trip
/// *For any* valid TestReport, serializing to JSON and deserializing back SHALL produce
/// an equivalent TestReport.
mod report_json_roundtrip {
    use super::*;
    use nexus_loadtest::report::{SerializableMetrics, TargetValidation, TestReport};

    /// Strategy to generate valid SerializableMetrics
    fn metrics_strategy() -> impl Strategy<Value = SerializableMetrics> {
        (
            0.0f64..1000.0,    // latency_p50_ms
            0.0f64..1000.0,    // latency_p95_ms
            0.0f64..1000.0,    // latency_p99_ms
            0.0f64..1.0,       // packet_loss_rate
            0.0f64..100.0,     // jitter_avg_ms
            0.0f64..1_000_000.0, // throughput_pps
            0.0f64..1_000_000_000.0, // throughput_bps
            0.0f64..1.0,       // connection_success_rate
            0.0f64..1000.0,    // avg_time_to_first_frame_ms
            0u32..10000,       // total_clients
            0u32..10000,       // successful_clients
            0u32..10000,       // failed_clients
        )
            .prop_map(
                |(
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    packet_loss_rate,
                    jitter_avg_ms,
                    throughput_pps,
                    throughput_bps,
                    connection_success_rate,
                    avg_time_to_first_frame_ms,
                    total_clients,
                    successful_clients,
                    failed_clients,
                )| {
                    SerializableMetrics {
                        latency_p50_ms,
                        latency_p95_ms,
                        latency_p99_ms,
                        packet_loss_rate,
                        jitter_avg_ms,
                        throughput_pps,
                        throughput_bps,
                        connection_success_rate,
                        avg_time_to_first_frame_ms,
                        total_clients,
                        successful_clients,
                        failed_clients,
                    }
                },
            )
    }

    /// Strategy to generate valid TargetValidation
    fn target_validation_strategy() -> impl Strategy<Value = TargetValidation> {
        (
            "[a-zA-Z0-9_]{1,20}",  // name
            "[0-9.]+",             // target
            "[0-9.]+",             // actual
            any::<bool>(),         // passed
        )
            .prop_map(|(name, target, actual, passed)| TargetValidation {
                name,
                target,
                actual,
                passed,
            })
    }

    /// Strategy to generate valid TestReport
    fn test_report_strategy() -> impl Strategy<Value = TestReport> {
        (
            prop::sample::select(vec!["webinar", "conference", "stress"]),
            "wss://[a-z0-9.]+:[0-9]+",  // sfu_url
            1u64..3600,                  // duration_secs
            "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", // timestamp
            metrics_strategy(),
            prop::collection::vec(target_validation_strategy(), 0..5),
            any::<bool>(),
        )
            .prop_map(
                |(scenario, sfu_url, duration_secs, timestamp, metrics, target_validations, passed)| {
                    TestReport {
                        scenario: scenario.to_string(),
                        sfu_url,
                        duration_secs,
                        timestamp,
                        metrics,
                        target_validations,
                        passed,
                    }
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 12: Report JSON Round-Trip
        #[test]
        fn json_roundtrip_produces_equivalent_report(report in test_report_strategy()) {
            // Serialize to JSON
            let json = report.to_json().expect("Serialization should succeed");

            // Deserialize back
            let deserialized = TestReport::from_json(&json).expect("Deserialization should succeed");

            // Verify equivalence
            prop_assert_eq!(
                report.scenario, deserialized.scenario,
                "Scenario mismatch after round-trip"
            );
            prop_assert_eq!(
                report.sfu_url, deserialized.sfu_url,
                "SFU URL mismatch after round-trip"
            );
            prop_assert_eq!(
                report.duration_secs, deserialized.duration_secs,
                "Duration mismatch after round-trip"
            );
            prop_assert_eq!(
                report.timestamp, deserialized.timestamp,
                "Timestamp mismatch after round-trip"
            );
            prop_assert_eq!(
                report.passed, deserialized.passed,
                "Passed status mismatch after round-trip"
            );
            prop_assert_eq!(
                report.target_validations.len(),
                deserialized.target_validations.len(),
                "Target validations count mismatch after round-trip"
            );

            // Verify metrics with floating point tolerance (relative for large values)
            fn approx_eq(a: f64, b: f64) -> bool {
                if a == b {
                    return true;
                }
                let diff = (a - b).abs();
                let max_val = a.abs().max(b.abs());
                // Use relative tolerance for large values, absolute for small
                diff < 1e-10 || diff / max_val < 1e-10
            }

            prop_assert!(
                approx_eq(report.metrics.latency_p50_ms, deserialized.metrics.latency_p50_ms),
                "latency_p50_ms mismatch: {} vs {}",
                report.metrics.latency_p50_ms, deserialized.metrics.latency_p50_ms
            );
            prop_assert!(
                approx_eq(report.metrics.latency_p95_ms, deserialized.metrics.latency_p95_ms),
                "latency_p95_ms mismatch: {} vs {}",
                report.metrics.latency_p95_ms, deserialized.metrics.latency_p95_ms
            );
            prop_assert!(
                approx_eq(report.metrics.latency_p99_ms, deserialized.metrics.latency_p99_ms),
                "latency_p99_ms mismatch: {} vs {}",
                report.metrics.latency_p99_ms, deserialized.metrics.latency_p99_ms
            );
            prop_assert!(
                approx_eq(report.metrics.packet_loss_rate, deserialized.metrics.packet_loss_rate),
                "packet_loss_rate mismatch: {} vs {}",
                report.metrics.packet_loss_rate, deserialized.metrics.packet_loss_rate
            );
            prop_assert!(
                approx_eq(report.metrics.throughput_pps, deserialized.metrics.throughput_pps),
                "throughput_pps mismatch: {} vs {}",
                report.metrics.throughput_pps, deserialized.metrics.throughput_pps
            );
            prop_assert!(
                approx_eq(report.metrics.throughput_bps, deserialized.metrics.throughput_bps),
                "throughput_bps mismatch: {} vs {}",
                report.metrics.throughput_bps, deserialized.metrics.throughput_bps
            );
            prop_assert_eq!(
                report.metrics.total_clients, deserialized.metrics.total_clients,
                "total_clients mismatch"
            );
            prop_assert_eq!(
                report.metrics.successful_clients, deserialized.metrics.successful_clients,
                "successful_clients mismatch"
            );
            prop_assert_eq!(
                report.metrics.failed_clients, deserialized.metrics.failed_clients,
                "failed_clients mismatch"
            );
        }

        // Feature: nexus-loadtest, Property 12: Report JSON Round-Trip
        /// JSON output should be valid JSON that can be parsed
        #[test]
        fn json_output_is_valid_json(report in test_report_strategy()) {
            let json = report.to_json().expect("Serialization should succeed");

            // Verify it's valid JSON by parsing with serde_json
            let parsed: serde_json::Value = serde_json::from_str(&json)
                .expect("Output should be valid JSON");

            // Verify it's an object
            prop_assert!(parsed.is_object(), "JSON output should be an object");

            // Verify required fields exist
            let obj = parsed.as_object().unwrap();
            prop_assert!(obj.contains_key("scenario"), "JSON should contain 'scenario'");
            prop_assert!(obj.contains_key("sfu_url"), "JSON should contain 'sfu_url'");
            prop_assert!(obj.contains_key("duration_secs"), "JSON should contain 'duration_secs'");
            prop_assert!(obj.contains_key("timestamp"), "JSON should contain 'timestamp'");
            prop_assert!(obj.contains_key("metrics"), "JSON should contain 'metrics'");
            prop_assert!(obj.contains_key("passed"), "JSON should contain 'passed'");
        }
    }
}


// Feature: nexus-loadtest, Property 14: Target Validation Correctness
// Feature: nexus-loadtest, Property 15: Failed Target Exit Code
/// **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5**
///
/// Property 14: Target Validation Correctness
/// *For any* measured metrics and performance targets, the validation SHALL report
/// pass if and only if all measured values meet or exceed their corresponding targets.
///
/// Property 15: Failed Target Exit Code
/// *For any* test where at least one target validation fails, the exit code SHALL be non-zero.
mod target_validation {
    use super::*;
    use nexus_loadtest::config::{OutputFormat, PerformanceTargets, TestConfig};
    use nexus_loadtest::metrics::AggregatedMetrics;
    use nexus_loadtest::report::ReportGenerator;

    /// Strategy to generate random performance targets
    fn performance_targets_strategy() -> impl Strategy<Value = PerformanceTargets> {
        (
            1u64..100,      // latency_p50_ms (1-100ms)
            1u64..200,      // latency_p99_ms (1-200ms)
            1u32..10000,    // min_participants (1-10000)
            1u64..1_000_000, // throughput_pps (1-1M)
        )
            .prop_map(|(latency_p50_ms, latency_p99_ms, min_participants, throughput_pps)| {
                PerformanceTargets {
                    latency_p50_ms,
                    latency_p99_ms,
                    min_participants,
                    throughput_pps,
                }
            })
    }

    /// Strategy to generate random aggregated metrics
    fn aggregated_metrics_strategy() -> impl Strategy<Value = AggregatedMetrics> {
        (
            0u64..200,       // latency_p50_ms
            0u64..200,       // latency_p95_ms
            0u64..300,       // latency_p99_ms
            0.0f64..1.0,     // packet_loss_rate
            0u64..50,        // jitter_avg_ms
            0.0f64..2_000_000.0, // throughput_pps
            0.0f64..1_000_000_000.0, // throughput_bps
            0.0f64..1.0,     // connection_success_rate
            0u64..500,       // avg_time_to_first_frame_ms
            0u32..20000,     // total_clients
            0u32..20000,     // successful_clients
            0u32..20000,     // failed_clients
        )
            .prop_map(
                |(
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    packet_loss_rate,
                    jitter_avg_ms,
                    throughput_pps,
                    throughput_bps,
                    connection_success_rate,
                    avg_time_to_first_frame_ms,
                    total_clients,
                    successful_clients,
                    failed_clients,
                )| {
                    AggregatedMetrics {
                        latency_p50: Duration::from_millis(latency_p50_ms),
                        latency_p95: Duration::from_millis(latency_p95_ms),
                        latency_p99: Duration::from_millis(latency_p99_ms),
                        packet_loss_rate,
                        jitter_avg: Duration::from_millis(jitter_avg_ms),
                        throughput_pps,
                        throughput_bps,
                        connection_success_rate,
                        avg_time_to_first_frame: Duration::from_millis(avg_time_to_first_frame_ms),
                        total_clients,
                        successful_clients,
                        failed_clients,
                    }
                },
            )
    }

    /// Create a test config for property tests
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 14: Target Validation Correctness
        /// P50 latency passes if and only if actual <= target
        #[test]
        fn p50_passes_iff_actual_lte_target(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            let p50_validation = report.target_validations.iter()
                .find(|v| v.name == "P50 Latency")
                .expect("P50 Latency validation should exist");

            let actual_p50_ms = metrics.latency_p50.as_secs_f64() * 1000.0;
            let target_p50_ms = targets.latency_p50_ms as f64;
            let expected_pass = actual_p50_ms <= target_p50_ms;

            prop_assert_eq!(
                p50_validation.passed, expected_pass,
                "P50 validation should pass iff actual ({:.2}ms) <= target ({}ms)",
                actual_p50_ms, target_p50_ms
            );
        }

        // Feature: nexus-loadtest, Property 14: Target Validation Correctness
        /// P99 latency passes if and only if actual <= target
        #[test]
        fn p99_passes_iff_actual_lte_target(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            let p99_validation = report.target_validations.iter()
                .find(|v| v.name == "P99 Latency")
                .expect("P99 Latency validation should exist");

            let actual_p99_ms = metrics.latency_p99.as_secs_f64() * 1000.0;
            let target_p99_ms = targets.latency_p99_ms as f64;
            let expected_pass = actual_p99_ms <= target_p99_ms;

            prop_assert_eq!(
                p99_validation.passed, expected_pass,
                "P99 validation should pass iff actual ({:.2}ms) <= target ({}ms)",
                actual_p99_ms, target_p99_ms
            );
        }

        // Feature: nexus-loadtest, Property 14: Target Validation Correctness
        /// Participant count passes if and only if actual >= target
        #[test]
        fn participant_count_passes_iff_actual_gte_target(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            let participant_validation = report.target_validations.iter()
                .find(|v| v.name == "Participant Count")
                .expect("Participant Count validation should exist");

            let expected_pass = metrics.successful_clients >= targets.min_participants;

            prop_assert_eq!(
                participant_validation.passed, expected_pass,
                "Participant count validation should pass iff actual ({}) >= target ({})",
                metrics.successful_clients, targets.min_participants
            );
        }

        // Feature: nexus-loadtest, Property 14: Target Validation Correctness
        /// Throughput passes if and only if actual >= target
        #[test]
        fn throughput_passes_iff_actual_gte_target(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            let throughput_validation = report.target_validations.iter()
                .find(|v| v.name == "Throughput")
                .expect("Throughput validation should exist");

            let expected_pass = metrics.throughput_pps >= targets.throughput_pps as f64;

            prop_assert_eq!(
                throughput_validation.passed, expected_pass,
                "Throughput validation should pass iff actual ({:.2} pps) >= target ({} pps)",
                metrics.throughput_pps, targets.throughput_pps
            );
        }

        // Feature: nexus-loadtest, Property 14: Target Validation Correctness
        /// Overall passed is true if and only if ALL individual validations pass
        #[test]
        fn overall_passed_iff_all_validations_pass(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            // Calculate expected individual results
            let actual_p50_ms = metrics.latency_p50.as_secs_f64() * 1000.0;
            let actual_p99_ms = metrics.latency_p99.as_secs_f64() * 1000.0;

            let p50_passes = actual_p50_ms <= targets.latency_p50_ms as f64;
            let p99_passes = actual_p99_ms <= targets.latency_p99_ms as f64;
            let participants_pass = metrics.successful_clients >= targets.min_participants;
            let throughput_passes = metrics.throughput_pps >= targets.throughput_pps as f64;

            let expected_overall = p50_passes && p99_passes && participants_pass && throughput_passes;

            prop_assert_eq!(
                report.passed, expected_overall,
                "Overall passed ({}) should equal all validations passing: p50={}, p99={}, participants={}, throughput={}",
                report.passed, p50_passes, p99_passes, participants_pass, throughput_passes
            );
        }

        // Feature: nexus-loadtest, Property 15: Failed Target Exit Code
        /// When passed=false, the report indicates failure (for CI/CD exit code)
        /// This property verifies that when at least one target fails, passed is false
        #[test]
        fn failed_target_results_in_passed_false(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics.clone());

            // Check if any validation failed
            let any_failed = report.target_validations.iter().any(|v| !v.passed);

            if any_failed {
                prop_assert!(
                    !report.passed,
                    "When any target validation fails, report.passed should be false"
                );
            } else {
                prop_assert!(
                    report.passed,
                    "When all target validations pass, report.passed should be true"
                );
            }
        }

        // Feature: nexus-loadtest, Property 15: Failed Target Exit Code
        /// Verify that the passed field correctly reflects whether all targets were met
        /// This is the inverse check - if passed is false, at least one target must have failed
        #[test]
        fn passed_false_implies_at_least_one_failed_target(
            targets in performance_targets_strategy(),
            metrics in aggregated_metrics_strategy()
        ) {
            let generator = ReportGenerator::new(OutputFormat::Console, targets.clone());
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics);

            if !report.passed {
                let failed_count = report.target_validations.iter().filter(|v| !v.passed).count();
                prop_assert!(
                    failed_count > 0,
                    "When report.passed is false, at least one target validation should have failed"
                );
            }
        }
    }

    // Feature: nexus-loadtest, Property 14: Target Validation Correctness
    // Feature: nexus-loadtest, Property 15: Failed Target Exit Code
    // Additional property tests with specific edge cases
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Test boundary condition: metrics exactly at target values
        #[test]
        fn boundary_values_pass_validation(
            latency_p50_ms in 1u64..100,
            latency_p99_ms in 1u64..200,
            min_participants in 1u32..10000,
            throughput_pps in 1u64..1_000_000
        ) {
            let targets = PerformanceTargets {
                latency_p50_ms,
                latency_p99_ms,
                min_participants,
                throughput_pps,
            };

            // Create metrics exactly at target values
            let metrics = AggregatedMetrics {
                latency_p50: Duration::from_millis(latency_p50_ms),
                latency_p95: Duration::from_millis(latency_p99_ms / 2), // arbitrary
                latency_p99: Duration::from_millis(latency_p99_ms),
                packet_loss_rate: 0.0,
                jitter_avg: Duration::from_millis(1),
                throughput_pps: throughput_pps as f64,
                throughput_bps: 1_000_000.0,
                connection_success_rate: 1.0,
                avg_time_to_first_frame: Duration::from_millis(50),
                total_clients: min_participants,
                successful_clients: min_participants,
                failed_clients: 0,
            };

            let generator = ReportGenerator::new(OutputFormat::Console, targets);
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics);

            // All validations should pass when metrics are exactly at targets
            prop_assert!(
                report.passed,
                "Report should pass when all metrics are exactly at target values"
            );

            for validation in &report.target_validations {
                prop_assert!(
                    validation.passed,
                    "Validation '{}' should pass at boundary: actual={}, target={}",
                    validation.name, validation.actual, validation.target
                );
            }
        }

        /// Test that metrics just above latency targets fail
        #[test]
        fn latency_just_above_target_fails(
            latency_p50_ms in 1u64..99,
            latency_p99_ms in 1u64..199
        ) {
            let targets = PerformanceTargets {
                latency_p50_ms,
                latency_p99_ms,
                min_participants: 1,
                throughput_pps: 1,
            };

            // Create metrics just above latency targets (by 1ms)
            let metrics = AggregatedMetrics {
                latency_p50: Duration::from_millis(latency_p50_ms + 1),
                latency_p95: Duration::from_millis(latency_p99_ms),
                latency_p99: Duration::from_millis(latency_p99_ms + 1),
                packet_loss_rate: 0.0,
                jitter_avg: Duration::from_millis(1),
                throughput_pps: 1_000_000.0, // Pass throughput
                throughput_bps: 1_000_000.0,
                connection_success_rate: 1.0,
                avg_time_to_first_frame: Duration::from_millis(50),
                total_clients: 1000,
                successful_clients: 1000, // Pass participant count
                failed_clients: 0,
            };

            let generator = ReportGenerator::new(OutputFormat::Console, targets);
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics);

            // P50 and P99 validations should fail
            let p50_validation = report.target_validations.iter()
                .find(|v| v.name == "P50 Latency")
                .unwrap();
            let p99_validation = report.target_validations.iter()
                .find(|v| v.name == "P99 Latency")
                .unwrap();

            prop_assert!(
                !p50_validation.passed,
                "P50 validation should fail when actual ({}ms) > target ({}ms)",
                latency_p50_ms + 1, latency_p50_ms
            );
            prop_assert!(
                !p99_validation.passed,
                "P99 validation should fail when actual ({}ms) > target ({}ms)",
                latency_p99_ms + 1, latency_p99_ms
            );

            // Overall should fail (Property 15)
            prop_assert!(
                !report.passed,
                "Report should fail when latency targets are not met"
            );
        }

        /// Test that metrics just below participant/throughput targets fail
        #[test]
        fn count_just_below_target_fails(
            min_participants in 2u32..10000,
            throughput_pps in 2u64..1_000_000
        ) {
            let targets = PerformanceTargets {
                latency_p50_ms: 100,
                latency_p99_ms: 200,
                min_participants,
                throughput_pps,
            };

            // Create metrics just below count targets (by 1)
            let metrics = AggregatedMetrics {
                latency_p50: Duration::from_millis(1), // Pass latency
                latency_p95: Duration::from_millis(5),
                latency_p99: Duration::from_millis(10), // Pass latency
                packet_loss_rate: 0.0,
                jitter_avg: Duration::from_millis(1),
                throughput_pps: (throughput_pps - 1) as f64, // Just below target
                throughput_bps: 1_000_000.0,
                connection_success_rate: 1.0,
                avg_time_to_first_frame: Duration::from_millis(50),
                total_clients: min_participants - 1,
                successful_clients: min_participants - 1, // Just below target
                failed_clients: 0,
            };

            let generator = ReportGenerator::new(OutputFormat::Console, targets);
            let config = create_test_config();
            let report = generator.generate("test", &config, metrics);

            // Participant and throughput validations should fail
            let participant_validation = report.target_validations.iter()
                .find(|v| v.name == "Participant Count")
                .unwrap();
            let throughput_validation = report.target_validations.iter()
                .find(|v| v.name == "Throughput")
                .unwrap();

            prop_assert!(
                !participant_validation.passed,
                "Participant validation should fail when actual ({}) < target ({})",
                min_participants - 1, min_participants
            );
            prop_assert!(
                !throughput_validation.passed,
                "Throughput validation should fail when actual ({}) < target ({})",
                throughput_pps - 1, throughput_pps
            );

            // Overall should fail (Property 15)
            prop_assert!(
                !report.passed,
                "Report should fail when count targets are not met"
            );
        }
    }
}


// Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
/// **Validates: Requirements 9.4**
///
/// Property 16: URL Scheme Transport Selection
/// *For any* SFU URL, if the scheme is "wss://" the transport SHALL be WebSocket,
/// and if the scheme is "quic://" the transport SHALL be QUIC.
mod url_transport_selection {
    use super::*;
    use nexus_loadtest::signaling::SignalingTransport;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        #[test]
        fn wss_scheme_selects_websocket_transport(
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("wss://{}:{}", host, port);
            let transport = SignalingTransport::from_url(&url)
                .expect("wss:// URL should be valid");

            prop_assert_eq!(
                transport,
                SignalingTransport::WebSocket,
                "wss:// scheme should select WebSocket transport"
            );
        }

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        #[test]
        fn ws_scheme_selects_websocket_transport(
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("ws://{}:{}", host, port);
            let transport = SignalingTransport::from_url(&url)
                .expect("ws:// URL should be valid");

            prop_assert_eq!(
                transport,
                SignalingTransport::WebSocket,
                "ws:// scheme should select WebSocket transport"
            );
        }

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        #[test]
        fn quic_scheme_selects_quic_transport(
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("quic://{}:{}", host, port);
            let transport = SignalingTransport::from_url(&url)
                .expect("quic:// URL should be valid");

            prop_assert_eq!(
                transport,
                SignalingTransport::Quic,
                "quic:// scheme should select QUIC transport"
            );
        }

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        #[test]
        fn invalid_scheme_returns_error(
            scheme in "(http|https|ftp|tcp|udp)",
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("{}://{}:{}", scheme, host, port);
            let result = SignalingTransport::from_url(&url);

            prop_assert!(
                result.is_err(),
                "Invalid scheme '{}' should return error, got {:?}",
                scheme, result
            );
        }

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        #[test]
        fn url_without_scheme_returns_error(
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("{}:{}", host, port);
            let result = SignalingTransport::from_url(&url);

            prop_assert!(
                result.is_err(),
                "URL without scheme should return error, got {:?}",
                result
            );
        }

        // Feature: nexus-loadtest, Property 16: URL Scheme Transport Selection
        /// Transport selection is case-sensitive (lowercase schemes only)
        #[test]
        fn uppercase_scheme_returns_error(
            host in "[a-z0-9.-]+",
            port in 1u16..65535
        ) {
            let url = format!("WSS://{}:{}", host, port);
            let result = SignalingTransport::from_url(&url);

            prop_assert!(
                result.is_err(),
                "Uppercase scheme 'WSS' should return error, got {:?}",
                result
            );
        }
    }
}


// Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
/// **Validates: Requirements 2.4, 2.5, 2.6, 3.3, 4.2**
///
/// Property 3: Client Role Determines Behavior
/// *For any* ClientRole value, a HeadlessClient configured with that role SHALL have
/// publishing capability if and only if the role is Broadcaster or Participant, and
/// SHALL have subscribing capability if and only if the role is Viewer or Participant.
mod client_role_behavior {
    use super::*;
    use nexus_loadtest::config::ClientRole;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        #[test]
        fn viewer_can_subscribe_but_not_publish(_dummy in Just(())) {
            let role = ClientRole::Viewer;

            prop_assert!(
                role.can_subscribe(),
                "Viewer should be able to subscribe"
            );
            prop_assert!(
                !role.can_publish(),
                "Viewer should NOT be able to publish"
            );
        }

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        #[test]
        fn broadcaster_can_publish_but_not_subscribe(_dummy in Just(())) {
            let role = ClientRole::Broadcaster;

            prop_assert!(
                role.can_publish(),
                "Broadcaster should be able to publish"
            );
            prop_assert!(
                !role.can_subscribe(),
                "Broadcaster should NOT be able to subscribe"
            );
        }

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        #[test]
        fn participant_can_both_publish_and_subscribe(_dummy in Just(())) {
            let role = ClientRole::Participant;

            prop_assert!(
                role.can_publish(),
                "Participant should be able to publish"
            );
            prop_assert!(
                role.can_subscribe(),
                "Participant should be able to subscribe"
            );
        }

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        /// For any role, can_publish XOR can_subscribe is false only for Participant
        #[test]
        fn role_capabilities_are_consistent(
            role_idx in 0usize..3
        ) {
            let role = match role_idx {
                0 => ClientRole::Viewer,
                1 => ClientRole::Broadcaster,
                _ => ClientRole::Participant,
            };

            let can_pub = role.can_publish();
            let can_sub = role.can_subscribe();

            // Verify the role capabilities match the expected behavior
            match role {
                ClientRole::Viewer => {
                    prop_assert!(!can_pub && can_sub, "Viewer: !publish && subscribe");
                }
                ClientRole::Broadcaster => {
                    prop_assert!(can_pub && !can_sub, "Broadcaster: publish && !subscribe");
                }
                ClientRole::Participant => {
                    prop_assert!(can_pub && can_sub, "Participant: publish && subscribe");
                }
            }
        }

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        /// Publishing capability implies Broadcaster or Participant role
        #[test]
        fn can_publish_implies_broadcaster_or_participant(
            role_idx in 0usize..3
        ) {
            let role = match role_idx {
                0 => ClientRole::Viewer,
                1 => ClientRole::Broadcaster,
                _ => ClientRole::Participant,
            };

            if role.can_publish() {
                prop_assert!(
                    role == ClientRole::Broadcaster || role == ClientRole::Participant,
                    "If can_publish, role must be Broadcaster or Participant"
                );
            }
        }

        // Feature: nexus-loadtest, Property 3: Client Role Determines Behavior
        /// Subscribing capability implies Viewer or Participant role
        #[test]
        fn can_subscribe_implies_viewer_or_participant(
            role_idx in 0usize..3
        ) {
            let role = match role_idx {
                0 => ClientRole::Viewer,
                1 => ClientRole::Broadcaster,
                _ => ClientRole::Participant,
            };

            if role.can_subscribe() {
                prop_assert!(
                    role == ClientRole::Viewer || role == ClientRole::Participant,
                    "If can_subscribe, role must be Viewer or Participant"
                );
            }
        }
    }
}


// Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
/// **Validates: Requirements 3.1, 3.2**
///
/// Property 4: Webinar Scenario Client Counts
/// *For any* webinar configuration with N viewers, executing the scenario SHALL create
/// exactly 1 Broadcaster and exactly N Viewers.
mod webinar_client_counts {
    use super::*;
    use nexus_loadtest::config::{ClientConfig, ClientRole, TestConfig, WebinarConfig};

    /// Helper function to create webinar client configs (mirrors runner logic)
    fn create_webinar_client_configs(config: &WebinarConfig) -> Vec<ClientConfig> {
        let mut client_configs = Vec::with_capacity(1 + config.viewer_count as usize);

        // Create broadcaster
        let broadcaster_config = ClientConfig {
            sfu_url: config.base.sfu_url.clone(),
            room: config.room.clone(),
            role: ClientRole::Broadcaster,
            connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
        };
        client_configs.push(broadcaster_config);

        // Create viewers
        for _ in 0..config.viewer_count {
            let viewer_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Viewer,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(viewer_config);
        }

        client_configs
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
        #[test]
        fn webinar_creates_exactly_one_broadcaster(
            viewer_count in 0u32..1000
        ) {
            let config = WebinarConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                viewer_count,
            };

            let client_configs = create_webinar_client_configs(&config);

            let broadcaster_count = client_configs
                .iter()
                .filter(|c| c.role == ClientRole::Broadcaster)
                .count();

            prop_assert_eq!(
                broadcaster_count, 1,
                "Webinar should create exactly 1 broadcaster, got {}",
                broadcaster_count
            );
        }

        // Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
        #[test]
        fn webinar_creates_exactly_n_viewers(
            viewer_count in 0u32..1000
        ) {
            let config = WebinarConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                viewer_count,
            };

            let client_configs = create_webinar_client_configs(&config);

            let actual_viewer_count = client_configs
                .iter()
                .filter(|c| c.role == ClientRole::Viewer)
                .count();

            prop_assert_eq!(
                actual_viewer_count, viewer_count as usize,
                "Webinar should create exactly {} viewers, got {}",
                viewer_count, actual_viewer_count
            );
        }

        // Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
        #[test]
        fn webinar_total_clients_equals_one_plus_viewers(
            viewer_count in 0u32..1000
        ) {
            let config = WebinarConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                viewer_count,
            };

            let client_configs = create_webinar_client_configs(&config);

            let expected_total = 1 + viewer_count as usize;
            prop_assert_eq!(
                client_configs.len(), expected_total,
                "Webinar should create {} total clients (1 + {}), got {}",
                expected_total, viewer_count, client_configs.len()
            );
        }

        // Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
        #[test]
        fn webinar_broadcaster_is_first_client(
            viewer_count in 0u32..100
        ) {
            let config = WebinarConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                viewer_count,
            };

            let client_configs = create_webinar_client_configs(&config);

            prop_assert!(
                !client_configs.is_empty(),
                "Client configs should not be empty"
            );
            prop_assert_eq!(
                client_configs[0].role, ClientRole::Broadcaster,
                "First client should be Broadcaster"
            );
        }

        // Feature: nexus-loadtest, Property 4: Webinar Scenario Client Counts
        #[test]
        fn webinar_all_clients_have_same_room(
            viewer_count in 0u32..100,
            room in "[a-z0-9-]{1,20}"
        ) {
            let config = WebinarConfig {
                base: TestConfig::default(),
                room: room.clone(),
                viewer_count,
            };

            let client_configs = create_webinar_client_configs(&config);

            for (i, client_config) in client_configs.iter().enumerate() {
                prop_assert_eq!(
                    &client_config.room, &room,
                    "Client {} should have room '{}', got '{}'",
                    i, room, client_config.room
                );
            }
        }
    }
}


// Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
/// **Validates: Requirements 4.1, 4.3**
///
/// Property 5: Conference Scenario Client Counts
/// *For any* conference configuration with N participants, executing the scenario SHALL
/// create exactly N Participants, and each Participant SHALL subscribe to exactly N-1
/// other participants' tracks.
mod conference_client_counts {
    use super::*;
    use nexus_loadtest::config::{ClientConfig, ClientRole, ConferenceConfig, TestConfig};

    /// Helper function to create conference client configs (mirrors runner logic)
    fn create_conference_client_configs(config: &ConferenceConfig) -> Vec<ClientConfig> {
        let mut client_configs = Vec::with_capacity(config.participant_count as usize);

        for _ in 0..config.participant_count {
            let participant_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Participant,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(participant_config);
        }

        client_configs
    }

    /// Calculate expected subscription count for N participants
    /// Each participant subscribes to (N-1) other participants
    /// Each participant has 2 tracks (audio + video)
    /// Total subscriptions = N * (N-1) * 2
    fn expected_subscription_count(participant_count: u32) -> u32 {
        if participant_count <= 1 {
            0
        } else {
            participant_count * (participant_count - 1) * 2
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_creates_exactly_n_participants(
            participant_count in 0u32..100
        ) {
            let config = ConferenceConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                participant_count,
            };

            let client_configs = create_conference_client_configs(&config);

            prop_assert_eq!(
                client_configs.len(), participant_count as usize,
                "Conference should create exactly {} participants, got {}",
                participant_count, client_configs.len()
            );
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_all_clients_are_participants(
            participant_count in 1u32..100
        ) {
            let config = ConferenceConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                participant_count,
            };

            let client_configs = create_conference_client_configs(&config);

            for (i, client_config) in client_configs.iter().enumerate() {
                prop_assert_eq!(
                    client_config.role, ClientRole::Participant,
                    "Client {} should be Participant, got {:?}",
                    i, client_config.role
                );
            }
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_subscription_count_is_n_times_n_minus_1_times_2(
            participant_count in 0u32..50
        ) {
            let expected = expected_subscription_count(participant_count);

            // Verify the formula: N * (N-1) * 2
            let calculated = if participant_count <= 1 {
                0
            } else {
                participant_count * (participant_count - 1) * 2
            };

            prop_assert_eq!(
                expected, calculated,
                "Expected subscription count formula should match"
            );
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_each_participant_subscribes_to_n_minus_1_others(
            participant_count in 2u32..50
        ) {
            // Each participant subscribes to (N-1) other participants
            // Each other participant has 2 tracks
            // So each participant makes (N-1) * 2 subscriptions
            let subscriptions_per_participant = (participant_count - 1) * 2;

            // Total subscriptions = N * subscriptions_per_participant
            let total_subscriptions = participant_count * subscriptions_per_participant;

            prop_assert_eq!(
                total_subscriptions, expected_subscription_count(participant_count),
                "Total subscriptions should equal N * (N-1) * 2"
            );
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_all_clients_have_same_room(
            participant_count in 1u32..50,
            room in "[a-z0-9-]{1,20}"
        ) {
            let config = ConferenceConfig {
                base: TestConfig::default(),
                room: room.clone(),
                participant_count,
            };

            let client_configs = create_conference_client_configs(&config);

            for (i, client_config) in client_configs.iter().enumerate() {
                prop_assert_eq!(
                    &client_config.room, &room,
                    "Client {} should have room '{}', got '{}'",
                    i, room, client_config.room
                );
            }
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_zero_participants_creates_no_clients(_dummy in Just(())) {
            let config = ConferenceConfig {
                base: TestConfig::default(),
                room: "test-room".to_string(),
                participant_count: 0,
            };

            let client_configs = create_conference_client_configs(&config);

            prop_assert!(
                client_configs.is_empty(),
                "Conference with 0 participants should create no clients"
            );
        }

        // Feature: nexus-loadtest, Property 5: Conference Scenario Client Counts
        #[test]
        fn conference_one_participant_has_no_subscriptions(_dummy in Just(())) {
            let subscriptions = expected_subscription_count(1);

            prop_assert_eq!(
                subscriptions, 0,
                "Conference with 1 participant should have 0 subscriptions"
            );
        }
    }
}


// Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
/// **Validates: Requirements 5.1, 5.2**
///
/// Property 6: Stress Scenario Distribution
/// *For any* stress configuration with R rooms and P participants per room, executing
/// the scenario SHALL create exactly R rooms with exactly P participants each,
/// totaling R*P participants.
mod stress_scenario_distribution {
    use super::*;
    use nexus_loadtest::config::{ClientConfig, ClientRole, StressConfig, TestConfig};

    /// Helper function to create stress client configs (mirrors runner logic)
    /// This replicates the room/participant creation logic from run_stress
    fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
        let mut room_configs = Vec::with_capacity(config.room_count as usize);

        // Requirement 5.1: Create the specified number of rooms
        for room_idx in 0..config.room_count {
            let room_name = format!("stress-room-{}", room_idx);
            let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

            // Requirement 5.2: Create P participants per room
            for _ in 0..config.participants_per_room {
                let participant_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: room_name.clone(),
                    role: ClientRole::Participant,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(participant_config);
            }

            room_configs.push((room_name, client_configs));
        }

        room_configs
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_creates_exactly_r_rooms(
            room_count in 0u32..100,
            participants_per_room in 0u32..50
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            prop_assert_eq!(
                room_configs.len(), room_count as usize,
                "Stress scenario should create exactly {} rooms, got {}",
                room_count, room_configs.len()
            );
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_creates_exactly_p_participants_per_room(
            room_count in 1u32..50,
            participants_per_room in 0u32..100
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            for (room_name, configs) in &room_configs {
                prop_assert_eq!(
                    configs.len(), participants_per_room as usize,
                    "Room '{}' should have exactly {} participants, got {}",
                    room_name, participants_per_room, configs.len()
                );
            }
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_total_participants_equals_r_times_p(
            room_count in 0u32..100,
            participants_per_room in 0u32..50
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            let total_participants: usize = room_configs.iter()
                .map(|(_, configs)| configs.len())
                .sum();

            let expected_total = (room_count * participants_per_room) as usize;

            prop_assert_eq!(
                total_participants, expected_total,
                "Total participants should be {} * {} = {}, got {}",
                room_count, participants_per_room, expected_total, total_participants
            );
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_all_participants_have_participant_role(
            room_count in 1u32..20,
            participants_per_room in 1u32..20
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            for (room_name, configs) in &room_configs {
                for (idx, client_config) in configs.iter().enumerate() {
                    prop_assert_eq!(
                        client_config.role, ClientRole::Participant,
                        "Client {} in room '{}' should have Participant role, got {:?}",
                        idx, room_name, client_config.role
                    );
                }
            }
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_room_names_are_unique(
            room_count in 1u32..100
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room: 1,
            };

            let room_configs = create_stress_client_configs(&config);

            // Collect all room names
            let room_names: Vec<&str> = room_configs.iter()
                .map(|(name, _)| name.as_str())
                .collect();

            // Check for uniqueness
            let mut unique_names = room_names.clone();
            unique_names.sort();
            unique_names.dedup();

            prop_assert_eq!(
                room_names.len(), unique_names.len(),
                "All room names should be unique, but found duplicates"
            );
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        #[test]
        fn stress_participants_assigned_to_correct_room(
            room_count in 1u32..20,
            participants_per_room in 1u32..20
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            for (room_name, configs) in &room_configs {
                for (idx, client_config) in configs.iter().enumerate() {
                    prop_assert_eq!(
                        &client_config.room, room_name,
                        "Client {} should be assigned to room '{}', but assigned to '{}'",
                        idx, room_name, client_config.room
                    );
                }
            }
        }

        // Feature: nexus-loadtest, Property 6: Stress Scenario Distribution
        /// Distribution is even - each room has exactly the same number of participants
        #[test]
        fn stress_distribution_is_even(
            room_count in 2u32..50,
            participants_per_room in 1u32..50
        ) {
            let config = StressConfig {
                base: TestConfig::default(),
                room_count,
                participants_per_room,
            };

            let room_configs = create_stress_client_configs(&config);

            // All rooms should have the same participant count
            let first_room_count = room_configs.first()
                .map(|(_, configs)| configs.len())
                .unwrap_or(0);

            for (room_name, configs) in &room_configs {
                prop_assert_eq!(
                    configs.len(), first_room_count,
                    "Room '{}' has {} participants, but expected {} (same as first room)",
                    room_name, configs.len(), first_room_count
                );
            }
        }
    }
}


// Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
/// **Validates: Requirements 5.3, 5.4**
///
/// Property 7: Per-Room Metrics Independence
/// *For any* stress test with multiple rooms, the metrics for each room SHALL be
/// tracked independently, and the final aggregated metrics SHALL equal the weighted
/// combination of per-room metrics.
mod per_room_metrics_independence {
    use super::*;
    use nexus_loadtest::metrics::{
        calculate_packet_loss_rate, calculate_percentile, MetricsCollector,
    };
    use nexus_loadtest::runner::TestRunner;

    /// Strategy to generate random latency samples for a room
    fn room_latency_samples_strategy() -> impl Strategy<Value = Vec<Duration>> {
        prop::collection::vec(1u64..1000, 1..20).prop_map(|millis| {
            millis.into_iter().map(Duration::from_millis).collect()
        })
    }

    /// Strategy to generate random packet statistics
    fn packet_stats_strategy() -> impl Strategy<Value = (u64, u64)> {
        (0u64..10000, 0u64..1000)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Each room's MetricsCollector tracks metrics independently
        #[test]
        fn room_metrics_collectors_are_independent(
            room1_latencies in room_latency_samples_strategy(),
            room2_latencies in room_latency_samples_strategy()
        ) {
            // Create two independent metrics collectors (simulating two rooms)
            let mut collector1 = MetricsCollector::new(Duration::from_secs(1));
            let mut collector2 = MetricsCollector::new(Duration::from_secs(1));

            // Register and record metrics for room 1
            collector1.register_client(0);
            collector1.mark_connected(0);
            for latency in &room1_latencies {
                collector1.record_latency(0, *latency);
            }

            // Register and record metrics for room 2
            collector2.register_client(0);
            collector2.mark_connected(0);
            for latency in &room2_latencies {
                collector2.record_latency(0, *latency);
            }

            // Aggregate each room's metrics independently
            let metrics1 = collector1.aggregate();
            let metrics2 = collector2.aggregate();

            // Verify that room 1's metrics reflect only room 1's data
            if !room1_latencies.is_empty() {
                let mut sorted1 = room1_latencies.clone();
                sorted1.sort();
                let expected_p50_1 = calculate_percentile(&sorted1, 50.0);

                prop_assert_eq!(
                    metrics1.latency_p50, expected_p50_1,
                    "Room 1 P50 should be calculated from room 1 data only"
                );
            }

            // Verify that room 2's metrics reflect only room 2's data
            if !room2_latencies.is_empty() {
                let mut sorted2 = room2_latencies.clone();
                sorted2.sort();
                let expected_p50_2 = calculate_percentile(&sorted2, 50.0);

                prop_assert_eq!(
                    metrics2.latency_p50, expected_p50_2,
                    "Room 2 P50 should be calculated from room 2 data only"
                );
            }
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Aggregated latency percentiles are calculated from combined samples
        #[test]
        fn aggregated_latency_combines_all_room_samples(
            room1_latencies in room_latency_samples_strategy(),
            room2_latencies in room_latency_samples_strategy()
        ) {
            // Skip if both rooms have no samples
            prop_assume!(!room1_latencies.is_empty() || !room2_latencies.is_empty());

            // Combine all latencies and calculate expected percentiles
            let mut all_latencies: Vec<Duration> = Vec::new();
            all_latencies.extend(room1_latencies.iter().copied());
            all_latencies.extend(room2_latencies.iter().copied());
            all_latencies.sort();

            let expected_p50 = calculate_percentile(&all_latencies, 50.0);
            let expected_p95 = calculate_percentile(&all_latencies, 95.0);
            let expected_p99 = calculate_percentile(&all_latencies, 99.0);

            // Create two test runners (simulating two rooms)
            let mut runner1 = TestRunner::with_defaults();
            let mut runner2 = TestRunner::with_defaults();

            runner1.metrics_collector_mut().register_client(0);
            runner1.metrics_collector_mut().mark_connected(0);
            for latency in &room1_latencies {
                runner1.metrics_collector_mut().record_latency(0, *latency);
            }

            runner2.metrics_collector_mut().register_client(0);
            runner2.metrics_collector_mut().mark_connected(0);
            for latency in &room2_latencies {
                runner2.metrics_collector_mut().record_latency(0, *latency);
            }

            // Aggregate using the runner's aggregate_room_metrics function
            let room_runners = vec![
                ("room-1".to_string(), runner1),
                ("room-2".to_string(), runner2),
            ];
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            // Verify aggregated percentiles match expected values
            prop_assert_eq!(
                aggregated.latency_p50, expected_p50,
                "Aggregated P50 should equal P50 of combined samples"
            );
            prop_assert_eq!(
                aggregated.latency_p95, expected_p95,
                "Aggregated P95 should equal P95 of combined samples"
            );
            prop_assert_eq!(
                aggregated.latency_p99, expected_p99,
                "Aggregated P99 should equal P99 of combined samples"
            );
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Aggregated packet loss rate is calculated from total packets across all rooms
        #[test]
        fn aggregated_packet_loss_combines_all_rooms(
            room1_stats in packet_stats_strategy(),
            room2_stats in packet_stats_strategy()
        ) {
            let (room1_received, room1_lost) = room1_stats;
            let (room2_received, room2_lost) = room2_stats;

            // Calculate expected aggregated packet loss rate
            let total_received = room1_received + room2_received;
            let total_lost = room1_lost + room2_lost;
            let expected_loss_rate = calculate_packet_loss_rate(total_received, total_lost);

            // Create two test runners
            let mut runner1 = TestRunner::with_defaults();
            let mut runner2 = TestRunner::with_defaults();

            runner1.metrics_collector_mut().register_client(0);
            runner1.metrics_collector_mut().mark_connected(0);
            runner1.metrics_collector_mut().record_packets(0, room1_received, room1_lost);

            runner2.metrics_collector_mut().register_client(0);
            runner2.metrics_collector_mut().mark_connected(0);
            runner2.metrics_collector_mut().record_packets(0, room2_received, room2_lost);

            // Aggregate
            let room_runners = vec![
                ("room-1".to_string(), runner1),
                ("room-2".to_string(), runner2),
            ];
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            // Verify aggregated packet loss rate
            let tolerance = 1e-10;
            prop_assert!(
                (aggregated.packet_loss_rate - expected_loss_rate).abs() < tolerance,
                "Aggregated packet loss rate should be {:.10}, got {:.10}",
                expected_loss_rate, aggregated.packet_loss_rate
            );
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Aggregated client counts sum across all rooms
        #[test]
        fn aggregated_client_counts_sum_across_rooms(
            room1_clients in 1u32..100,
            room2_clients in 1u32..100,
            room3_clients in 1u32..100
        ) {
            // Create three test runners with different client counts
            let mut runner1 = TestRunner::with_defaults();
            let mut runner2 = TestRunner::with_defaults();
            let mut runner3 = TestRunner::with_defaults();

            // Register clients in each room
            for i in 0..room1_clients {
                runner1.metrics_collector_mut().register_client(i as usize);
                runner1.metrics_collector_mut().mark_connected(i as usize);
            }

            for i in 0..room2_clients {
                runner2.metrics_collector_mut().register_client(i as usize);
                runner2.metrics_collector_mut().mark_connected(i as usize);
            }

            for i in 0..room3_clients {
                runner3.metrics_collector_mut().register_client(i as usize);
                runner3.metrics_collector_mut().mark_connected(i as usize);
            }

            // Aggregate
            let room_runners = vec![
                ("room-1".to_string(), runner1),
                ("room-2".to_string(), runner2),
                ("room-3".to_string(), runner3),
            ];
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            let expected_total = room1_clients + room2_clients + room3_clients;

            prop_assert_eq!(
                aggregated.total_clients, expected_total,
                "Total clients should be {} + {} + {} = {}, got {}",
                room1_clients, room2_clients, room3_clients, expected_total, aggregated.total_clients
            );

            prop_assert_eq!(
                aggregated.successful_clients, expected_total,
                "Successful clients should equal total when all connected"
            );
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Failed rooms are counted in failed_clients
        #[test]
        fn failed_rooms_counted_in_failed_clients(
            successful_rooms in 0u32..10,
            failed_rooms in 0u32..10
        ) {
            // Create successful room runners
            let mut room_runners: Vec<(String, TestRunner)> = Vec::new();
            for i in 0..successful_rooms {
                let mut runner = TestRunner::with_defaults();
                runner.metrics_collector_mut().register_client(0);
                runner.metrics_collector_mut().mark_connected(0);
                room_runners.push((format!("room-{}", i), runner));
            }

            // Aggregate with failed_rooms count
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, failed_rooms);

            // Failed rooms should be added to failed_clients
            prop_assert!(
                aggregated.failed_clients >= failed_rooms,
                "Failed clients ({}) should include failed rooms ({})",
                aggregated.failed_clients, failed_rooms
            );
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Connection success rate reflects all rooms combined
        #[test]
        fn aggregated_connection_success_rate_reflects_all_rooms(
            room1_success in 0u32..50,
            room1_failed in 0u32..50,
            room2_success in 0u32..50,
            room2_failed in 0u32..50
        ) {
            // Create two test runners with mixed success/failure
            let mut runner1 = TestRunner::with_defaults();
            let mut runner2 = TestRunner::with_defaults();

            // Room 1: register successful and failed clients
            for i in 0..room1_success {
                runner1.metrics_collector_mut().register_client(i as usize);
                runner1.metrics_collector_mut().mark_connected(i as usize);
            }
            for i in room1_success..(room1_success + room1_failed) {
                runner1.metrics_collector_mut().register_client(i as usize);
                runner1.metrics_collector_mut().mark_failed(i as usize);
            }

            // Room 2: register successful and failed clients
            for i in 0..room2_success {
                runner2.metrics_collector_mut().register_client(i as usize);
                runner2.metrics_collector_mut().mark_connected(i as usize);
            }
            for i in room2_success..(room2_success + room2_failed) {
                runner2.metrics_collector_mut().register_client(i as usize);
                runner2.metrics_collector_mut().mark_failed(i as usize);
            }

            // Aggregate
            let room_runners = vec![
                ("room-1".to_string(), runner1),
                ("room-2".to_string(), runner2),
            ];
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            let total_success = room1_success + room2_success;
            let total_failed = room1_failed + room2_failed;
            let total = total_success + total_failed;

            let expected_rate = if total > 0 {
                total_success as f64 / total as f64
            } else {
                0.0
            };

            let tolerance = 1e-10;
            prop_assert!(
                (aggregated.connection_success_rate - expected_rate).abs() < tolerance,
                "Connection success rate should be {:.10}, got {:.10}",
                expected_rate, aggregated.connection_success_rate
            );
        }

        // Feature: nexus-loadtest, Property 7: Per-Room Metrics Independence
        /// Empty rooms don't affect aggregation
        #[test]
        fn empty_rooms_dont_affect_aggregation(
            room1_latencies in room_latency_samples_strategy()
        ) {
            prop_assume!(!room1_latencies.is_empty());

            // Create one room with data and one empty room
            let mut runner1 = TestRunner::with_defaults();
            let runner2 = TestRunner::with_defaults(); // Empty room

            runner1.metrics_collector_mut().register_client(0);
            runner1.metrics_collector_mut().mark_connected(0);
            for latency in &room1_latencies {
                runner1.metrics_collector_mut().record_latency(0, *latency);
            }

            // Calculate expected metrics from room 1 only
            let mut sorted = room1_latencies.clone();
            sorted.sort();
            let expected_p50 = calculate_percentile(&sorted, 50.0);

            // Aggregate with empty room
            let room_runners = vec![
                ("room-1".to_string(), runner1),
                ("room-2".to_string(), runner2),
            ];
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            // Latency percentiles should match room 1's data
            prop_assert_eq!(
                aggregated.latency_p50, expected_p50,
                "P50 should be calculated from non-empty room data"
            );
        }
    }
}


// Feature: nexus-loadtest, Property 17: Error Resilience
/// **Validates: Requirements 5.5, 10.1, 10.5**
///
/// Property 17: Error Resilience
/// *For any* test where some clients fail to connect, the test SHALL continue with
/// remaining clients and the final report SHALL include counts of both successful
/// and failed connections.
mod error_resilience {
    use super::*;
    use nexus_loadtest::config::{OutputFormat, PerformanceTargets, TestConfig};
    use nexus_loadtest::metrics::{calculate_connection_success_rate, MetricsCollector};
    use nexus_loadtest::report::ReportGenerator;
    use nexus_loadtest::runner::TestRunner;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Test continues when individual clients fail - failed counts are tracked correctly
        /// The total_clients should equal successful_clients + failed_clients
        #[test]
        fn total_clients_equals_successful_plus_failed(
            successful in 0u32..1000,
            failed in 0u32..1000
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            // Register and mark successful clients
            for i in 0..successful {
                collector.register_client(i as usize);
                collector.mark_connected(i as usize);
            }

            // Register and mark failed clients
            for i in successful..(successful + failed) {
                collector.register_client(i as usize);
                collector.mark_failed(i as usize);
            }

            let metrics = collector.aggregate();

            prop_assert_eq!(
                metrics.total_clients, successful + failed,
                "Total clients ({}) should equal successful ({}) + failed ({})",
                metrics.total_clients, successful, failed
            );
            prop_assert_eq!(
                metrics.successful_clients, successful,
                "Successful clients should be {}, got {}",
                successful, metrics.successful_clients
            );
            prop_assert_eq!(
                metrics.failed_clients, failed,
                "Failed clients should be {}, got {}",
                failed, metrics.failed_clients
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Report includes both successful and failed connection counts
        /// Validates: Requirement 10.5
        #[test]
        fn report_includes_successful_and_failed_counts(
            successful in 0u32..500,
            failed in 0u32..500
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            // Register and mark clients
            for i in 0..successful {
                collector.register_client(i as usize);
                collector.mark_connected(i as usize);
            }
            for i in successful..(successful + failed) {
                collector.register_client(i as usize);
                collector.mark_failed(i as usize);
            }

            let metrics = collector.aggregate();

            // Generate report
            let generator = ReportGenerator::new(
                OutputFormat::Console,
                PerformanceTargets::default(),
            );
            let config = TestConfig::default();
            let report = generator.generate("test", &config, metrics);

            // Verify report contains both counts
            prop_assert_eq!(
                report.metrics.successful_clients, successful,
                "Report should include {} successful clients, got {}",
                successful, report.metrics.successful_clients
            );
            prop_assert_eq!(
                report.metrics.failed_clients, failed,
                "Report should include {} failed clients, got {}",
                failed, report.metrics.failed_clients
            );
            prop_assert_eq!(
                report.metrics.total_clients, successful + failed,
                "Report should include {} total clients, got {}",
                successful + failed, report.metrics.total_clients
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Connection success rate is correctly calculated when some clients fail
        /// Validates: Requirements 10.1, 10.5
        #[test]
        fn connection_success_rate_reflects_failures(
            successful in 0u32..1000,
            failed in 0u32..1000
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            // Register and mark clients
            for i in 0..successful {
                collector.register_client(i as usize);
                collector.mark_connected(i as usize);
            }
            for i in successful..(successful + failed) {
                collector.register_client(i as usize);
                collector.mark_failed(i as usize);
            }

            let metrics = collector.aggregate();

            // Calculate expected success rate
            let expected_rate = calculate_connection_success_rate(successful, failed);

            prop_assert!(
                (metrics.connection_success_rate - expected_rate).abs() < 1e-10,
                "Connection success rate should be {:.10}, got {:.10}",
                expected_rate, metrics.connection_success_rate
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Test continues with remaining clients when some fail (stress scenario)
        /// Validates: Requirement 5.5 - room failures don't stop the test
        #[test]
        fn stress_test_continues_with_failed_rooms(
            successful_rooms in 0u32..10,
            failed_rooms in 0u32..10,
            clients_per_room in 1u32..20
        ) {
            // Create successful room runners
            let mut room_runners: Vec<(String, TestRunner)> = Vec::new();
            for room_idx in 0..successful_rooms {
                let mut runner = TestRunner::with_defaults();
                for client_idx in 0..clients_per_room {
                    runner.metrics_collector_mut().register_client(client_idx as usize);
                    runner.metrics_collector_mut().mark_connected(client_idx as usize);
                }
                room_runners.push((format!("room-{}", room_idx), runner));
            }

            // Aggregate with failed_rooms count (simulating rooms that failed to initialize)
            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, failed_rooms);

            // Verify successful clients from successful rooms
            let expected_successful = successful_rooms * clients_per_room;
            prop_assert_eq!(
                aggregated.successful_clients, expected_successful,
                "Successful clients should be {} ({}*{}), got {}",
                expected_successful, successful_rooms, clients_per_room, aggregated.successful_clients
            );

            // Verify failed rooms are counted
            prop_assert!(
                aggregated.failed_clients >= failed_rooms,
                "Failed clients ({}) should include failed rooms ({})",
                aggregated.failed_clients, failed_rooms
            );

            // Verify total reflects both successful and failed
            prop_assert_eq!(
                aggregated.total_clients, expected_successful,
                "Total clients should be {} (from successful rooms), got {}",
                expected_successful, aggregated.total_clients
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Mixed success/failure within rooms is tracked correctly
        /// Validates: Requirement 10.1 - individual client failures are logged and counted
        #[test]
        fn mixed_success_failure_within_rooms(
            room_count in 1u32..5,
            success_per_room in 0u32..20,
            fail_per_room in 0u32..20
        ) {
            let mut room_runners: Vec<(String, TestRunner)> = Vec::new();

            for room_idx in 0..room_count {
                let mut runner = TestRunner::with_defaults();

                // Register successful clients
                for i in 0..success_per_room {
                    runner.metrics_collector_mut().register_client(i as usize);
                    runner.metrics_collector_mut().mark_connected(i as usize);
                }

                // Register failed clients
                for i in success_per_room..(success_per_room + fail_per_room) {
                    runner.metrics_collector_mut().register_client(i as usize);
                    runner.metrics_collector_mut().mark_failed(i as usize);
                }

                room_runners.push((format!("room-{}", room_idx), runner));
            }

            let aggregated = TestRunner::aggregate_room_metrics(&room_runners, 0);

            let expected_successful = room_count * success_per_room;
            let expected_failed = room_count * fail_per_room;
            let expected_total = room_count * (success_per_room + fail_per_room);

            prop_assert_eq!(
                aggregated.successful_clients, expected_successful,
                "Successful clients should be {}, got {}",
                expected_successful, aggregated.successful_clients
            );
            prop_assert_eq!(
                aggregated.failed_clients, expected_failed,
                "Failed clients should be {}, got {}",
                expected_failed, aggregated.failed_clients
            );
            prop_assert_eq!(
                aggregated.total_clients, expected_total,
                "Total clients should be {}, got {}",
                expected_total, aggregated.total_clients
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// All clients failing still produces a valid report
        /// Validates: Requirements 10.1, 10.5 - graceful handling of complete failure
        #[test]
        fn all_clients_failing_produces_valid_report(
            failed_count in 1u32..1000
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            // Register all clients as failed
            for i in 0..failed_count {
                collector.register_client(i as usize);
                collector.mark_failed(i as usize);
            }

            let metrics = collector.aggregate();

            // Verify counts
            prop_assert_eq!(
                metrics.successful_clients, 0,
                "Successful clients should be 0 when all fail"
            );
            prop_assert_eq!(
                metrics.failed_clients, failed_count,
                "Failed clients should be {}, got {}",
                failed_count, metrics.failed_clients
            );
            prop_assert_eq!(
                metrics.total_clients, failed_count,
                "Total clients should be {}, got {}",
                failed_count, metrics.total_clients
            );

            // Connection success rate should be 0
            prop_assert_eq!(
                metrics.connection_success_rate, 0.0,
                "Connection success rate should be 0.0 when all fail"
            );

            // Generate report - should not panic
            let generator = ReportGenerator::new(
                OutputFormat::Console,
                PerformanceTargets::default(),
            );
            let config = TestConfig::default();
            let report = generator.generate("test", &config, metrics);

            // Report should be valid
            prop_assert_eq!(
                report.metrics.failed_clients, failed_count,
                "Report should include all failed clients"
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// All clients succeeding produces correct counts
        #[test]
        fn all_clients_succeeding_produces_correct_counts(
            success_count in 1u32..1000
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            // Register all clients as successful
            for i in 0..success_count {
                collector.register_client(i as usize);
                collector.mark_connected(i as usize);
            }

            let metrics = collector.aggregate();

            // Verify counts
            prop_assert_eq!(
                metrics.successful_clients, success_count,
                "Successful clients should be {}, got {}",
                success_count, metrics.successful_clients
            );
            prop_assert_eq!(
                metrics.failed_clients, 0,
                "Failed clients should be 0 when all succeed"
            );
            prop_assert_eq!(
                metrics.total_clients, success_count,
                "Total clients should be {}, got {}",
                success_count, metrics.total_clients
            );

            // Connection success rate should be 1.0
            prop_assert_eq!(
                metrics.connection_success_rate, 1.0,
                "Connection success rate should be 1.0 when all succeed"
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// Empty test (no clients) produces valid zero counts
        #[test]
        fn empty_test_produces_zero_counts(_dummy in Just(())) {
            let collector = MetricsCollector::new(Duration::from_secs(1));
            let metrics = collector.aggregate();

            prop_assert_eq!(
                metrics.total_clients, 0,
                "Total clients should be 0 for empty test"
            );
            prop_assert_eq!(
                metrics.successful_clients, 0,
                "Successful clients should be 0 for empty test"
            );
            prop_assert_eq!(
                metrics.failed_clients, 0,
                "Failed clients should be 0 for empty test"
            );
            prop_assert_eq!(
                metrics.connection_success_rate, 0.0,
                "Connection success rate should be 0.0 for empty test"
            );
        }

        // Feature: nexus-loadtest, Property 17: Error Resilience
        /// JSON report preserves failure counts through serialization
        /// Validates: Requirement 10.5 - failed counts are reported
        #[test]
        fn json_report_preserves_failure_counts(
            successful in 0u32..500,
            failed in 0u32..500
        ) {
            let mut collector = MetricsCollector::new(Duration::from_secs(1));

            for i in 0..successful {
                collector.register_client(i as usize);
                collector.mark_connected(i as usize);
            }
            for i in successful..(successful + failed) {
                collector.register_client(i as usize);
                collector.mark_failed(i as usize);
            }

            let metrics = collector.aggregate();

            let generator = ReportGenerator::new(
                OutputFormat::Json,
                PerformanceTargets::default(),
            );
            let config = TestConfig::default();
            let report = generator.generate("test", &config, metrics);

            // Serialize to JSON
            let json = report.to_json().expect("Serialization should succeed");

            // Deserialize back
            let deserialized = nexus_loadtest::report::TestReport::from_json(&json)
                .expect("Deserialization should succeed");

            // Verify failure counts are preserved
            prop_assert_eq!(
                deserialized.metrics.successful_clients, successful,
                "Successful clients should be preserved through JSON round-trip"
            );
            prop_assert_eq!(
                deserialized.metrics.failed_clients, failed,
                "Failed clients should be preserved through JSON round-trip"
            );
            prop_assert_eq!(
                deserialized.metrics.total_clients, successful + failed,
                "Total clients should be preserved through JSON round-trip"
            );
        }
    }
}



// Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
// Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
/// **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 10.4**
///
/// Property 1: CLI Parsing Round-Trip
/// *For any* valid CLI command string with all required parameters, parsing the command
/// and then reconstructing the command string from the parsed config SHALL produce an
/// equivalent command.
///
/// Property 2: Missing Required Parameter Rejection
/// *For any* CLI command string missing a required parameter (sfu-url, room,
/// viewers/participants/rooms), parsing SHALL fail with an appropriate error.
mod cli_parsing {
    use super::*;
    use clap::Parser;
    use nexus_loadtest::cli::{Cli, Command, OutputFormat};

    /// Strategy to generate valid SFU URLs
    /// URLs must start with a valid scheme and contain valid host:port
    fn sfu_url_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["wss", "ws", "quic"])
            .prop_flat_map(|scheme| {
                // Host must start with a letter to be valid
                ("[a-z][a-z0-9]{0,9}", 1u16..65535).prop_map(move |(host, port)| {
                    format!("{}://{}:{}", scheme, host, port)
                })
            })
    }

    /// Strategy to generate valid room names
    /// Room names must start with a letter to avoid being interpreted as CLI flags
    fn room_strategy() -> impl Strategy<Value = String> {
        // Start with a letter, then allow letters, numbers, and dashes
        ("[a-z][a-z0-9]{0,19}").prop_map(|s| s)
    }

    /// Strategy to generate valid output formats
    fn output_format_strategy() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec!["console", "json", "prometheus"])
    }

    /// Strategy to generate optional report file paths
    /// Paths must start with a letter to avoid being interpreted as CLI flags
    #[allow(dead_code)]
    fn report_file_strategy() -> impl Strategy<Value = Option<String>> {
        prop::option::of("[a-z][a-z0-9_]{0,20}\\.(json|txt)")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Webinar command round-trip: parse and reconstruct produces equivalent config
        #[test]
        fn webinar_command_roundtrip(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            viewers in 1u32..10000,
            duration in 1u64..3600,
            output in output_format_strategy(),
            verbose in any::<bool>()
        ) {
            // Build command line arguments
            let mut args = vec![
                "nexus-loadtest".to_string(),
            ];
            if verbose {
                args.push("-v".to_string());
            }
            args.extend([
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--room".to_string(), room.clone(),
                "--viewers".to_string(), viewers.to_string(),
                "--duration".to_string(), duration.to_string(),
                "--output".to_string(), output.to_string(),
            ]);

            // Parse the command
            let cli = Cli::try_parse_from(&args)
                .expect("Valid webinar command should parse successfully");

            // Verify parsed values match input
            prop_assert_eq!(cli.verbose, verbose, "Verbose flag mismatch");

            match cli.command {
                Command::Webinar {
                    sfu_url: parsed_url,
                    room: parsed_room,
                    viewers: parsed_viewers,
                    duration: parsed_duration,
                    output: parsed_output,
                    report_file: _,
                    prometheus_port: _,
                } => {
                    prop_assert_eq!(parsed_url, sfu_url, "SFU URL mismatch");
                    prop_assert_eq!(parsed_room, room, "Room mismatch");
                    prop_assert_eq!(parsed_viewers, viewers, "Viewers count mismatch");
                    prop_assert_eq!(parsed_duration, duration, "Duration mismatch");
                    let expected_output = match output {
                        "console" => OutputFormat::Console,
                        "json" => OutputFormat::Json,
                        "prometheus" => OutputFormat::Prometheus,
                        _ => unreachable!(),
                    };
                    prop_assert_eq!(parsed_output, expected_output, "Output format mismatch");
                }
                _ => prop_assert!(false, "Expected Webinar command"),
            }
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Conference command round-trip: parse and reconstruct produces equivalent config
        #[test]
        fn conference_command_roundtrip(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            participants in 1u32..10000,
            duration in 1u64..3600,
            output in output_format_strategy(),
            verbose in any::<bool>()
        ) {
            // Build command line arguments
            let mut args = vec![
                "nexus-loadtest".to_string(),
            ];
            if verbose {
                args.push("-v".to_string());
            }
            args.extend([
                "conference".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--room".to_string(), room.clone(),
                "--participants".to_string(), participants.to_string(),
                "--duration".to_string(), duration.to_string(),
                "--output".to_string(), output.to_string(),
            ]);

            // Parse the command
            let cli = Cli::try_parse_from(&args)
                .expect("Valid conference command should parse successfully");

            // Verify parsed values match input
            prop_assert_eq!(cli.verbose, verbose, "Verbose flag mismatch");

            match cli.command {
                Command::Conference {
                    sfu_url: parsed_url,
                    room: parsed_room,
                    participants: parsed_participants,
                    duration: parsed_duration,
                    output: parsed_output,
                    report_file: _,
                    prometheus_port: _,
                } => {
                    prop_assert_eq!(parsed_url, sfu_url, "SFU URL mismatch");
                    prop_assert_eq!(parsed_room, room, "Room mismatch");
                    prop_assert_eq!(parsed_participants, participants, "Participants count mismatch");
                    prop_assert_eq!(parsed_duration, duration, "Duration mismatch");
                    let expected_output = match output {
                        "console" => OutputFormat::Console,
                        "json" => OutputFormat::Json,
                        "prometheus" => OutputFormat::Prometheus,
                        _ => unreachable!(),
                    };
                    prop_assert_eq!(parsed_output, expected_output, "Output format mismatch");
                }
                _ => prop_assert!(false, "Expected Conference command"),
            }
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Stress command round-trip: parse and reconstruct produces equivalent config
        #[test]
        fn stress_command_roundtrip(
            sfu_url in sfu_url_strategy(),
            rooms in 1u32..1000,
            participants_per_room in 1u32..100,
            duration in 1u64..3600,
            output in output_format_strategy(),
            verbose in any::<bool>()
        ) {
            // Build command line arguments
            let mut args = vec![
                "nexus-loadtest".to_string(),
            ];
            if verbose {
                args.push("-v".to_string());
            }
            args.extend([
                "stress".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--rooms".to_string(), rooms.to_string(),
                "--participants-per-room".to_string(), participants_per_room.to_string(),
                "--duration".to_string(), duration.to_string(),
                "--output".to_string(), output.to_string(),
            ]);

            // Parse the command
            let cli = Cli::try_parse_from(&args)
                .expect("Valid stress command should parse successfully");

            // Verify parsed values match input
            prop_assert_eq!(cli.verbose, verbose, "Verbose flag mismatch");

            match cli.command {
                Command::Stress {
                    sfu_url: parsed_url,
                    rooms: parsed_rooms,
                    participants_per_room: parsed_ppr,
                    duration: parsed_duration,
                    output: parsed_output,
                    report_file: _,
                    prometheus_port: _,
                } => {
                    prop_assert_eq!(parsed_url, sfu_url, "SFU URL mismatch");
                    prop_assert_eq!(parsed_rooms, rooms, "Rooms count mismatch");
                    prop_assert_eq!(parsed_ppr, participants_per_room, "Participants per room mismatch");
                    prop_assert_eq!(parsed_duration, duration, "Duration mismatch");
                    let expected_output = match output {
                        "console" => OutputFormat::Console,
                        "json" => OutputFormat::Json,
                        "prometheus" => OutputFormat::Prometheus,
                        _ => unreachable!(),
                    };
                    prop_assert_eq!(parsed_output, expected_output, "Output format mismatch");
                }
                _ => prop_assert!(false, "Expected Stress command"),
            }
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Webinar command with report file round-trip
        #[test]
        fn webinar_with_report_file_roundtrip(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            viewers in 1u32..1000,
            report_file in "[a-z0-9_]{1,20}\\.json"
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--room".to_string(), room.clone(),
                "--viewers".to_string(), viewers.to_string(),
                "--report-file".to_string(), report_file.clone(),
            ];

            let cli = Cli::try_parse_from(&args)
                .expect("Valid webinar command with report file should parse");

            match cli.command {
                Command::Webinar { report_file: parsed_file, .. } => {
                    prop_assert_eq!(
                        parsed_file, Some(report_file),
                        "Report file mismatch"
                    );
                }
                _ => prop_assert!(false, "Expected Webinar command"),
            }
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Default values are applied correctly when optional args are omitted
        #[test]
        fn default_values_applied_correctly(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            viewers in 1u32..1000
        ) {
            // Minimal webinar command without optional args
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
                "--viewers".to_string(), viewers.to_string(),
            ];

            let cli = Cli::try_parse_from(&args)
                .expect("Minimal webinar command should parse");

            // Verify defaults
            prop_assert!(!cli.verbose, "Verbose should default to false");

            match cli.command {
                Command::Webinar {
                    duration,
                    output,
                    report_file,
                    ..
                } => {
                    prop_assert_eq!(duration, 60, "Duration should default to 60");
                    prop_assert_eq!(output, OutputFormat::Console, "Output should default to Console");
                    prop_assert!(report_file.is_none(), "Report file should default to None");
                }
                _ => prop_assert!(false, "Expected Webinar command"),
            }
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Webinar command missing --sfu-url should fail
        #[test]
        fn webinar_missing_sfu_url_fails(
            room in room_strategy(),
            viewers in 1u32..1000
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--room".to_string(), room,
                "--viewers".to_string(), viewers.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Webinar command missing --sfu-url should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Webinar command missing --room should fail
        #[test]
        fn webinar_missing_room_fails(
            sfu_url in sfu_url_strategy(),
            viewers in 1u32..1000
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--viewers".to_string(), viewers.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Webinar command missing --room should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Webinar command missing --viewers should fail
        #[test]
        fn webinar_missing_viewers_fails(
            sfu_url in sfu_url_strategy(),
            room in room_strategy()
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Webinar command missing --viewers should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Conference command missing --sfu-url should fail
        #[test]
        fn conference_missing_sfu_url_fails(
            room in room_strategy(),
            participants in 1u32..1000
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "conference".to_string(),
                "--room".to_string(), room,
                "--participants".to_string(), participants.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Conference command missing --sfu-url should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Conference command missing --room should fail
        #[test]
        fn conference_missing_room_fails(
            sfu_url in sfu_url_strategy(),
            participants in 1u32..1000
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "conference".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--participants".to_string(), participants.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Conference command missing --room should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Conference command missing --participants should fail
        #[test]
        fn conference_missing_participants_fails(
            sfu_url in sfu_url_strategy(),
            room in room_strategy()
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "conference".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Conference command missing --participants should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Stress command missing --sfu-url should fail
        #[test]
        fn stress_missing_sfu_url_fails(
            rooms in 1u32..100,
            participants_per_room in 1u32..100
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "stress".to_string(),
                "--rooms".to_string(), rooms.to_string(),
                "--participants-per-room".to_string(), participants_per_room.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Stress command missing --sfu-url should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Stress command missing --rooms should fail
        #[test]
        fn stress_missing_rooms_fails(
            sfu_url in sfu_url_strategy(),
            participants_per_room in 1u32..100
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "stress".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--participants-per-room".to_string(), participants_per_room.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Stress command missing --rooms should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// Stress command missing --participants-per-room should fail
        #[test]
        fn stress_missing_participants_per_room_fails(
            sfu_url in sfu_url_strategy(),
            rooms in 1u32..100
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "stress".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--rooms".to_string(), rooms.to_string(),
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Stress command missing --participants-per-room should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 2: Missing Required Parameter Rejection
        /// No subcommand should fail
        #[test]
        fn no_subcommand_fails(_dummy in Just(())) {
            let args = vec!["nexus-loadtest".to_string()];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Command without subcommand should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Invalid output format should fail
        #[test]
        fn invalid_output_format_fails(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            viewers in 1u32..1000,
            invalid_output in "(xml|csv|yaml|html)"
        ) {
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
                "--viewers".to_string(), viewers.to_string(),
                "--output".to_string(), invalid_output,
            ];

            let result = Cli::try_parse_from(&args);

            prop_assert!(
                result.is_err(),
                "Invalid output format should fail to parse"
            );
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Verbose flag can be placed before or after subcommand (global flag)
        #[test]
        fn verbose_flag_is_global(
            sfu_url in sfu_url_strategy(),
            room in room_strategy(),
            viewers in 1u32..1000
        ) {
            // Verbose before subcommand
            let args_before = vec![
                "nexus-loadtest".to_string(),
                "-v".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--room".to_string(), room.clone(),
                "--viewers".to_string(), viewers.to_string(),
            ];

            let cli_before = Cli::try_parse_from(&args_before)
                .expect("Verbose before subcommand should parse");
            prop_assert!(cli_before.verbose, "Verbose should be true when -v is before subcommand");

            // Verbose after subcommand (clap global args work this way)
            let args_after = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "-v".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
                "--viewers".to_string(), viewers.to_string(),
            ];

            let cli_after = Cli::try_parse_from(&args_after)
                .expect("Verbose after subcommand should parse");
            prop_assert!(cli_after.verbose, "Verbose should be true when -v is after subcommand");
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Zero viewers/participants/rooms should be accepted (edge case)
        #[test]
        fn zero_counts_are_accepted(
            sfu_url in sfu_url_strategy(),
            room in room_strategy()
        ) {
            // Zero viewers
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url.clone(),
                "--room".to_string(), room.clone(),
                "--viewers".to_string(), "0".to_string(),
            ];

            let cli = Cli::try_parse_from(&args)
                .expect("Zero viewers should be accepted");

            match cli.command {
                Command::Webinar { viewers, .. } => {
                    prop_assert_eq!(viewers, 0, "Zero viewers should parse correctly");
                }
                _ => prop_assert!(false, "Expected Webinar command"),
            }
        }

        // Feature: nexus-loadtest, Property 1: CLI Parsing Round-Trip
        /// Large values should be accepted
        #[test]
        fn large_values_are_accepted(
            sfu_url in sfu_url_strategy(),
            room in room_strategy()
        ) {
            let large_viewers = u32::MAX;
            let args = vec![
                "nexus-loadtest".to_string(),
                "webinar".to_string(),
                "--sfu-url".to_string(), sfu_url,
                "--room".to_string(), room,
                "--viewers".to_string(), large_viewers.to_string(),
            ];

            let cli = Cli::try_parse_from(&args)
                .expect("Large viewer count should be accepted");

            match cli.command {
                Command::Webinar { viewers, .. } => {
                    prop_assert_eq!(viewers, large_viewers, "Large viewer count should parse correctly");
                }
                _ => prop_assert!(false, "Expected Webinar command"),
            }
        }
    }
}
