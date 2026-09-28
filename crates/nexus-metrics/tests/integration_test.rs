use nexus_dataplane::ShardStatsSnapshot;
use nexus_metrics::{CrdtMetrics, MetricsCollector, SfuMetrics};

#[test]
fn test_sfu_metrics_packet_recording() {
    let metrics = SfuMetrics::new();

    // Record packets
    metrics.record_packet_received(1500);
    metrics.record_packet_forwarded(1500, 1_000_000); // 1ms

    assert_eq!(metrics.packets_received_total(), 1);
    assert_eq!(metrics.packets_forwarded_total(), 1);
    assert_eq!(metrics.bytes_received_total(), 1500);
    assert_eq!(metrics.bytes_forwarded_total(), 1500);
}

#[test]
fn test_sfu_metrics_latency_percentiles() {
    let metrics = SfuMetrics::new();

    // Record 100 packets with varying latencies
    for i in 0..100 {
        let latency_ms = (i % 10) + 1;
        metrics.record_packet_forwarded(1000, latency_ms * 1_000_000);
    }

    let p50 = metrics.p50_latency_ms();
    let p99 = metrics.p99_latency_ms();

    assert!(p50 > 0.0);
    assert!(p99 > p50);
}

#[test]
fn test_crdt_metrics_gossip() {
    let metrics = CrdtMetrics::new();

    metrics.record_gossip_sent();
    metrics.record_gossip_sent();
    metrics.record_gossip_received();

    assert_eq!(metrics.gossip_messages_sent_total(), 2);
    assert_eq!(metrics.gossip_messages_received_total(), 1);
}

#[test]
fn test_metrics_collector_creation() {
    let collector = MetricsCollector::new(4).expect("Failed to create collector");

    // Verify all subsystems initialized
    assert_eq!(collector.sfu.packets_received_total(), 0);
    assert_eq!(collector.shards.shards(), 4);
    assert_eq!(collector.crdt.active_peers(), 0);
}

#[test]
fn test_prometheus_export() {
    let collector = MetricsCollector::new(2).expect("Failed to create collector");

    // Record some metrics
    collector.sfu.record_packet_received(1500);
    collector.sfu.set_active_tracks(10);
    collector.crdt.set_active_peers(3);

    // Export to Prometheus format
    let output = collector.export_prometheus().expect("Failed to export");

    // Verify output contains expected metrics
    assert!(output.contains("nexus_sfu_packets_received_total"));
    assert!(output.contains("nexus_sfu_active_tracks"));
    assert!(output.contains("nexus_crdt_active_peers"));
    assert!(!output.contains("nexus_actor_"), "actor metrics are gone");
    assert!(!output.contains("nexus_worker_"), "worker metrics are gone");
    // No stats source yet: the shard families are registered but have no series.
    assert!(
        !output.contains("nexus_shard_rx_datagrams_total{"),
        "{output}"
    );
}

/// Per-shard series come from the stats source the server installs (note §5.4).
#[test]
fn test_shard_stats_are_exported_per_shard() {
    let collector = MetricsCollector::new(2).expect("Failed to create collector");
    let installed = collector.shards.set_source(Box::new(|shard| {
        let mut stats = ShardStatsSnapshot::default();
        stats.counters.rx_datagrams = 100 + shard as u64;
        stats.counters.drop_srtp_auth = 3;
        stats.gauges.sessions = 7;
        stats
    }));
    assert!(installed);
    let output = collector.export_prometheus().expect("Failed to export");
    assert!(
        output.contains("nexus_shard_rx_datagrams_total{shard=\"0\"} 100"),
        "{output}"
    );
    assert!(
        output.contains("nexus_shard_rx_datagrams_total{shard=\"1\"} 101"),
        "{output}"
    );
    assert!(
        output.contains("nexus_shard_drop_srtp_auth_total{shard=\"1\"} 3"),
        "{output}"
    );
    assert!(
        output.contains("nexus_shard_sessions{shard=\"0\"} 7"),
        "{output}"
    );
    // A second render reports the same totals (counters are reset, then set).
    let again = collector.export_prometheus().expect("Failed to export");
    assert!(
        again.contains("nexus_shard_rx_datagrams_total{shard=\"0\"} 100"),
        "{again}"
    );
}

#[test]
#[should_panic(expected = "shards must be > 0")]
fn test_metrics_collector_zero_shards() {
    let _ = MetricsCollector::new(0);
}

#[test]
#[should_panic(expected = "bytes must be > 0")]
fn test_sfu_metrics_zero_bytes() {
    let metrics = SfuMetrics::new();
    metrics.record_packet_received(0);
}
