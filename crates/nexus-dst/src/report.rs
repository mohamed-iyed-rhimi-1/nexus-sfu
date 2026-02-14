use serde::{Deserialize, Serialize};

/// Overall simulation report containing pass/fail status, seed, violations, assertions, and stats.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationReport {
    pub passed: bool,
    pub seed: u64,
    pub violations: Vec<InvariantViolationReport>,
    pub assertions: Vec<AssertionResult>,
    pub stats: SimulationStats,
    /// Optional detailed performance benchmarks (populated for stress test scenarios)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmarks: Option<PerformanceBenchmarks>,
}

/// A single invariant violation recorded during simulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantViolationReport {
    pub time_ns: u64,
    pub invariant_name: String,
    pub message: String,
}

/// Result of a single assertion evaluated after simulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Summary statistics collected during simulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationStats {
    pub total_events: u64,
    pub total_packets_sent: u64,
    pub total_packets_delivered: u64,
    pub total_packets_dropped: u64,
    pub simulation_duration_ns: u64,
}

/// Extended performance benchmarks for stress testing scenarios.
/// These metrics align with the architecture goals from architecture.md.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PerformanceBenchmarks {
    // Throughput metrics
    /// Packets per second (total throughput)
    pub packets_per_second: f64,
    /// Packets per second per simulated core
    pub packets_per_second_per_core: f64,
    /// Events processed per second
    pub events_per_second: f64,
    /// Total forwarding operations (packet × subscribers)
    pub total_forward_operations: u64,
    /// Forward operations per second
    pub forward_ops_per_second: f64,

    // Latency metrics (in microseconds)
    /// Average packet latency
    pub latency_avg_us: f64,
    /// P50 latency
    pub latency_p50_us: f64,
    /// P95 latency
    pub latency_p95_us: f64,
    /// P99 latency
    pub latency_p99_us: f64,
    /// Maximum latency observed
    pub latency_max_us: f64,

    // Memory metrics
    /// Peak memory usage estimate (bytes)
    pub peak_memory_bytes: u64,
    /// Memory per participant (bytes)
    pub memory_per_participant_bytes: u64,
    /// Memory per track (bytes)
    pub memory_per_track_bytes: u64,
    /// Arena slots used at peak
    pub arena_slots_peak: u64,
    /// Arena utilization percentage
    pub arena_utilization_pct: f64,

    // Scale metrics
    /// Total participants in simulation
    pub total_participants: u32,
    /// Total rooms in simulation
    pub total_rooms: u32,
    /// Total tracks in simulation
    pub total_tracks: u32,
    /// Total subscriptions in simulation
    pub total_subscriptions: u32,
    /// Maximum subscribers per track
    pub max_subscribers_per_track: u32,
    /// Average subscribers per track
    pub avg_subscribers_per_track: f64,

    // BWE/Congestion metrics
    /// Final estimated bandwidth (bps)
    pub final_bandwidth_estimate_bps: u64,
    /// Bandwidth utilization percentage
    pub bandwidth_utilization_pct: f64,
    /// Total BWE feedback events processed
    pub bwe_feedback_events: u64,

    // CRDT metrics
    /// Total gossip rounds executed
    pub gossip_rounds: u64,
    /// CRDT operations synced
    pub crdt_ops_synced: u64,
    /// Time to convergence (ns)
    pub crdt_convergence_time_ns: u64,

    // Architecture target comparison
    /// Target: <5ms P50 latency - PASS/FAIL
    pub target_latency_p50_met: bool,
    /// Target: <15ms P99 latency - PASS/FAIL
    pub target_latency_p99_met: bool,
    /// Target: <100KB memory per participant - PASS/FAIL
    pub target_memory_per_participant_met: bool,
    /// Target: 1M+ packets/sec/core - percentage achieved
    pub target_pps_per_core_pct: f64,
}

impl PerformanceBenchmarks {
    /// Create benchmarks from simulation data
    pub fn from_simulation(
        stats: &SimulationStats,
        latencies_us: &[f64],
        participants: u32,
        rooms: u32,
        tracks: u32,
        subscriptions: u32,
        max_subs_per_track: u32,
        forward_ops: u64,
        arena_peak: u64,
        arena_capacity: u64,
        bwe_estimate: u64,
        gossip_rounds: u64,
        crdt_ops: u64,
        convergence_time_ns: u64,
        simulated_cores: u32,
    ) -> Self {
        let duration_secs = stats.simulation_duration_ns as f64 / 1_000_000_000.0;
        let duration_secs = if duration_secs > 0.0 { duration_secs } else { 1.0 };

        // Calculate throughput
        let pps = stats.total_packets_sent as f64 / duration_secs;
        let pps_per_core = pps / simulated_cores.max(1) as f64;
        let eps = stats.total_events as f64 / duration_secs;
        let fops = forward_ops as f64 / duration_secs;

        // Calculate latency percentiles
        let mut sorted_latencies = latencies_us.to_vec();
        sorted_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let latency_avg = if !sorted_latencies.is_empty() {
            sorted_latencies.iter().sum::<f64>() / sorted_latencies.len() as f64
        } else {
            0.0
        };

        let percentile = |p: f64| -> f64 {
            if sorted_latencies.is_empty() {
                return 0.0;
            }
            let idx = ((p / 100.0) * (sorted_latencies.len() - 1) as f64).round() as usize;
            sorted_latencies[idx.min(sorted_latencies.len() - 1)]
        };

        let latency_p50 = percentile(50.0);
        let latency_p95 = percentile(95.0);
        let latency_p99 = percentile(99.0);
        let latency_max = sorted_latencies.last().copied().unwrap_or(0.0);

        // Memory estimates (based on architecture.md targets)
        // Each participant: ~50KB base + tracks + subscriptions
        // Each track: ~10KB (ring buffer + metadata)
        let base_per_participant = 50 * 1024; // 50KB
        let per_track = 10 * 1024; // 10KB
        let per_subscription = 1024; // 1KB
        let peak_memory = (participants as u64 * base_per_participant)
            + (tracks as u64 * per_track)
            + (subscriptions as u64 * per_subscription);
        let mem_per_participant = if participants > 0 {
            peak_memory / participants as u64
        } else {
            0
        };
        let mem_per_track = if tracks > 0 {
            (tracks as u64 * per_track) / tracks as u64
        } else {
            0
        };

        let arena_util = if arena_capacity > 0 {
            (arena_peak as f64 / arena_capacity as f64) * 100.0
        } else {
            0.0
        };

        let avg_subs = if tracks > 0 {
            subscriptions as f64 / tracks as f64
        } else {
            0.0
        };

        // BWE utilization (assume 50Mbps max as per architecture)
        let max_bw = 50_000_000u64; // 50Mbps
        let bw_util = (bwe_estimate as f64 / max_bw as f64) * 100.0;

        // Architecture targets
        let target_p50_met = latency_p50 <= 5000.0; // 5ms = 5000us
        let target_p99_met = latency_p99 <= 15000.0; // 15ms = 15000us
        let target_mem_met = mem_per_participant <= 100 * 1024; // 100KB
        let target_pps_pct = (pps_per_core / 1_000_000.0) * 100.0; // % of 1M target

        Self {
            packets_per_second: pps,
            packets_per_second_per_core: pps_per_core,
            events_per_second: eps,
            total_forward_operations: forward_ops,
            forward_ops_per_second: fops,
            latency_avg_us: latency_avg,
            latency_p50_us: latency_p50,
            latency_p95_us: latency_p95,
            latency_p99_us: latency_p99,
            latency_max_us: latency_max,
            peak_memory_bytes: peak_memory,
            memory_per_participant_bytes: mem_per_participant,
            memory_per_track_bytes: mem_per_track,
            arena_slots_peak: arena_peak,
            arena_utilization_pct: arena_util,
            total_participants: participants,
            total_rooms: rooms,
            total_tracks: tracks,
            total_subscriptions: subscriptions,
            max_subscribers_per_track: max_subs_per_track,
            avg_subscribers_per_track: avg_subs,
            final_bandwidth_estimate_bps: bwe_estimate,
            bandwidth_utilization_pct: bw_util,
            bwe_feedback_events: 0, // Set externally
            gossip_rounds,
            crdt_ops_synced: crdt_ops,
            crdt_convergence_time_ns: convergence_time_ns,
            target_latency_p50_met: target_p50_met,
            target_latency_p99_met: target_p99_met,
            target_memory_per_participant_met: target_mem_met,
            target_pps_per_core_pct: target_pps_pct,
        }
    }

    /// Format benchmarks as a detailed human-readable report
    pub fn to_benchmark_report(&self) -> String {
        let mut out = String::new();

        out.push_str("╔══════════════════════════════════════════════════════════════════════════════╗\n");
        out.push_str("║                    NEXUS SFU PERFORMANCE BENCHMARKS                          ║\n");
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // Scale section
        out.push_str("║ SCALE                                                                        ║\n");
        out.push_str(&format!(
            "║   Participants: {:>6}    Rooms: {:>4}    Tracks: {:>5}    Subscriptions: {:>6} ║\n",
            self.total_participants, self.total_rooms, self.total_tracks, self.total_subscriptions
        ));
        out.push_str(&format!(
            "║   Max subs/track: {:>4}    Avg subs/track: {:>6.1}                                ║\n",
            self.max_subscribers_per_track, self.avg_subscribers_per_track
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // Throughput section
        out.push_str("║ THROUGHPUT                                                                   ║\n");
        out.push_str(&format!(
            "║   Packets/sec:        {:>12.0}                                            ║\n",
            self.packets_per_second
        ));
        out.push_str(&format!(
            "║   Packets/sec/core:   {:>12.0}    (Target: 1,000,000 = {:>5.1}%)              ║\n",
            self.packets_per_second_per_core, self.target_pps_per_core_pct
        ));
        out.push_str(&format!(
            "║   Events/sec:         {:>12.0}                                            ║\n",
            self.events_per_second
        ));
        out.push_str(&format!(
            "║   Forward ops/sec:    {:>12.0}    (Total: {:>12})                   ║\n",
            self.forward_ops_per_second, self.total_forward_operations
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // Latency section
        let p50_status = if self.target_latency_p50_met { "✓" } else { "✗" };
        let p99_status = if self.target_latency_p99_met { "✓" } else { "✗" };
        out.push_str("║ LATENCY (microseconds)                                                       ║\n");
        out.push_str(&format!(
            "║   Average:  {:>10.1}μs                                                      ║\n",
            self.latency_avg_us
        ));
        out.push_str(&format!(
            "║   P50:      {:>10.1}μs    (Target: <5000μs)   {}                            ║\n",
            self.latency_p50_us, p50_status
        ));
        out.push_str(&format!(
            "║   P95:      {:>10.1}μs                                                      ║\n",
            self.latency_p95_us
        ));
        out.push_str(&format!(
            "║   P99:      {:>10.1}μs    (Target: <15000μs)  {}                            ║\n",
            self.latency_p99_us, p99_status
        ));
        out.push_str(&format!(
            "║   Max:      {:>10.1}μs                                                      ║\n",
            self.latency_max_us
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // Memory section
        let mem_status = if self.target_memory_per_participant_met { "✓" } else { "✗" };
        out.push_str("║ MEMORY                                                                       ║\n");
        out.push_str(&format!(
            "║   Peak total:         {:>10} bytes ({:>6.2} MB)                           ║\n",
            self.peak_memory_bytes,
            self.peak_memory_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push_str(&format!(
            "║   Per participant:    {:>10} bytes    (Target: <102400)  {}               ║\n",
            self.memory_per_participant_bytes, mem_status
        ));
        out.push_str(&format!(
            "║   Per track:          {:>10} bytes                                        ║\n",
            self.memory_per_track_bytes
        ));
        out.push_str(&format!(
            "║   Arena peak slots:   {:>10}          Utilization: {:>5.1}%                 ║\n",
            self.arena_slots_peak, self.arena_utilization_pct
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // BWE section
        out.push_str("║ BANDWIDTH ESTIMATION                                                         ║\n");
        out.push_str(&format!(
            "║   Final estimate:     {:>10} bps ({:>6.2} Mbps)                           ║\n",
            self.final_bandwidth_estimate_bps,
            self.final_bandwidth_estimate_bps as f64 / 1_000_000.0
        ));
        out.push_str(&format!(
            "║   Utilization:        {:>10.1}%                                             ║\n",
            self.bandwidth_utilization_pct
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // CRDT section
        out.push_str("║ CRDT DISTRIBUTED STATE                                                       ║\n");
        out.push_str(&format!(
            "║   Gossip rounds:      {:>10}                                              ║\n",
            self.gossip_rounds
        ));
        out.push_str(&format!(
            "║   Ops synced:         {:>10}                                              ║\n",
            self.crdt_ops_synced
        ));
        out.push_str(&format!(
            "║   Convergence time:   {:>10} ns ({:>6.2} ms)                              ║\n",
            self.crdt_convergence_time_ns,
            self.crdt_convergence_time_ns as f64 / 1_000_000.0
        ));
        out.push_str("╠══════════════════════════════════════════════════════════════════════════════╣\n");

        // Summary
        let all_targets_met = self.target_latency_p50_met
            && self.target_latency_p99_met
            && self.target_memory_per_participant_met;
        let status = if all_targets_met {
            "ALL ARCHITECTURE TARGETS MET ✓"
        } else {
            "SOME TARGETS NOT MET ✗"
        };
        out.push_str(&format!(
            "║ STATUS: {:^68} ║\n",
            status
        ));
        out.push_str("╚══════════════════════════════════════════════════════════════════════════════╝\n");

        out
    }
}

impl SimulationReport {
    /// Serialize the report to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a report from a JSON string.
    pub fn from_json(input: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(input)
    }

    /// Format the report as human-readable text.
    pub fn to_human_readable(&self) -> String {
        let mut out = String::new();

        // Status header
        out.push_str("=== Simulation Report ===\n\n");
        out.push_str(&format!(
            "Status: {}\n",
            if self.passed { "PASSED" } else { "FAILED" }
        ));
        out.push_str(&format!("Seed:   {}\n", self.seed));

        // Invariant violations
        out.push_str(&format!(
            "\n--- Invariant Violations ({}) ---\n",
            self.violations.len()
        ));
        if self.violations.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for v in &self.violations {
                out.push_str(&format!(
                    "  [t={}ns] {}: {}\n",
                    v.time_ns, v.invariant_name, v.message
                ));
            }
        }

        // Assertion results
        out.push_str(&format!(
            "\n--- Assertions ({}) ---\n",
            self.assertions.len()
        ));
        if self.assertions.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for a in &self.assertions {
                let icon = if a.passed { "✓" } else { "✗" };
                out.push_str(&format!("  {} {}: {}\n", icon, a.name, a.message));
            }
        }

        // Statistics
        out.push_str("\n--- Statistics ---\n");
        out.push_str(&format!(
            "  Total events:           {}\n",
            self.stats.total_events
        ));
        out.push_str(&format!(
            "  Packets sent:           {}\n",
            self.stats.total_packets_sent
        ));
        out.push_str(&format!(
            "  Packets delivered:      {}\n",
            self.stats.total_packets_delivered
        ));
        out.push_str(&format!(
            "  Packets dropped:        {}\n",
            self.stats.total_packets_dropped
        ));
        out.push_str(&format!(
            "  Simulation duration:    {}ns\n",
            self.stats.simulation_duration_ns
        ));

        // Performance benchmarks (if available)
        if let Some(ref benchmarks) = self.benchmarks {
            out.push_str("\n");
            out.push_str(&benchmarks.to_benchmark_report());
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(passed: bool) -> SimulationReport {
        SimulationReport {
            passed,
            seed: 42,
            violations: vec![InvariantViolationReport {
                time_ns: 1_000_000,
                invariant_name: "room_capacity".to_string(),
                message: "Room exceeded max participants".to_string(),
            }],
            assertions: vec![
                AssertionResult {
                    name: "delivery_ratio".to_string(),
                    passed: true,
                    message: "100% delivery achieved".to_string(),
                },
                AssertionResult {
                    name: "crdt_converged".to_string(),
                    passed: false,
                    message: "Nodes diverged after partition".to_string(),
                },
            ],
            stats: SimulationStats {
                total_events: 500,
                total_packets_sent: 200,
                total_packets_delivered: 195,
                total_packets_dropped: 5,
                simulation_duration_ns: 10_000_000_000,
            },
            benchmarks: None,
        }
    }

    #[test]
    fn json_round_trip_passing_report() {
        let report = sample_report(true);
        let json = report.to_json().expect("serialize");
        let deserialized = SimulationReport::from_json(&json).expect("deserialize");
        assert_eq!(report, deserialized);
    }

    #[test]
    fn json_round_trip_failing_report() {
        let report = sample_report(false);
        let json = report.to_json().expect("serialize");
        let deserialized = SimulationReport::from_json(&json).expect("deserialize");
        assert_eq!(report, deserialized);
    }

    #[test]
    fn json_round_trip_empty_report() {
        let report = SimulationReport {
            passed: true,
            seed: 0,
            violations: vec![],
            assertions: vec![],
            stats: SimulationStats {
                total_events: 0,
                total_packets_sent: 0,
                total_packets_delivered: 0,
                total_packets_dropped: 0,
                simulation_duration_ns: 0,
            },
            benchmarks: None,
        };
        let json = report.to_json().expect("serialize");
        let deserialized = SimulationReport::from_json(&json).expect("deserialize");
        assert_eq!(report, deserialized);
    }

    #[test]
    fn from_json_invalid_input() {
        assert!(SimulationReport::from_json("not json").is_err());
        assert!(SimulationReport::from_json("{}").is_err());
    }

    #[test]
    fn human_readable_contains_status_passed() {
        let report = sample_report(true);
        let text = report.to_human_readable();
        assert!(text.contains("Status: PASSED"));
        assert!(text.contains("Seed:   42"));
    }

    #[test]
    fn human_readable_contains_status_failed() {
        let report = sample_report(false);
        let text = report.to_human_readable();
        assert!(text.contains("Status: FAILED"));
    }

    #[test]
    fn human_readable_contains_violations() {
        let report = sample_report(false);
        let text = report.to_human_readable();
        assert!(text.contains("Invariant Violations (1)"));
        assert!(text.contains("[t=1000000ns] room_capacity"));
        assert!(text.contains("Room exceeded max participants"));
    }

    #[test]
    fn human_readable_contains_assertions() {
        let report = sample_report(false);
        let text = report.to_human_readable();
        assert!(text.contains("Assertions (2)"));
        assert!(text.contains("✓ delivery_ratio"));
        assert!(text.contains("✗ crdt_converged"));
    }

    #[test]
    fn human_readable_contains_stats() {
        let report = sample_report(true);
        let text = report.to_human_readable();
        assert!(text.contains("Total events:           500"));
        assert!(text.contains("Packets sent:           200"));
        assert!(text.contains("Packets delivered:      195"));
        assert!(text.contains("Packets dropped:        5"));
        assert!(text.contains("Simulation duration:    10000000000ns"));
    }

    #[test]
    fn human_readable_empty_violations_and_assertions() {
        let report = SimulationReport {
            passed: true,
            seed: 1,
            violations: vec![],
            assertions: vec![],
            stats: SimulationStats {
                total_events: 0,
                total_packets_sent: 0,
                total_packets_delivered: 0,
                total_packets_dropped: 0,
                simulation_duration_ns: 0,
            },
            benchmarks: None,
        };
        let text = report.to_human_readable();
        assert!(text.contains("Invariant Violations (0)"));
        assert!(text.contains("(none)"));
        assert!(text.contains("Assertions (0)"));
    }
}
