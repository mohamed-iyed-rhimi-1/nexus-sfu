use nexus_metrics::{ActorMetrics, CrdtMetrics, MetricsCollector, SfuMetrics, WorkerPoolMetrics};

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
fn test_worker_metrics_cpu_usage() {
    let metrics = WorkerPoolMetrics::new(4);

    metrics.worker(0).set_cpu_usage_percent(50.5);
    metrics.worker(1).set_cpu_usage_percent(75.2);

    // Use approximate comparison for floating point
    assert!((metrics.worker(0).cpu_usage_percent() - 50.5).abs() < 0.1);
    assert!((metrics.worker(1).cpu_usage_percent() - 75.2).abs() < 0.1);
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
fn test_actor_metrics_counts() {
    let metrics = ActorMetrics::new();

    metrics.set_room_actors(5);
    metrics.set_participant_actors(20);
    metrics.set_track_actors(100);

    assert_eq!(metrics.total_actors(), 125);
}

#[test]
fn test_metrics_collector_creation() {
    let collector = MetricsCollector::new(4).expect("Failed to create collector");

    // Verify all subsystems initialized
    assert_eq!(collector.sfu.packets_received_total(), 0);
    assert_eq!(collector.workers.workers().len(), 4);
    assert_eq!(collector.crdt.active_peers(), 0);
    assert_eq!(collector.actors.total_actors(), 0);
}

#[test]
fn test_prometheus_export() {
    let collector = MetricsCollector::new(2).expect("Failed to create collector");

    // Record some metrics
    collector.sfu.record_packet_received(1500);
    collector.sfu.set_active_tracks(10);
    collector.crdt.set_active_peers(3);
    collector.actors.set_room_actors(2);

    // Export to Prometheus format
    let output = collector.export_prometheus().expect("Failed to export");

    // Verify output contains expected metrics
    assert!(output.contains("nexus_sfu_packets_received_total"));
    assert!(output.contains("nexus_sfu_active_tracks"));
    assert!(output.contains("nexus_crdt_active_peers"));
    assert!(output.contains("nexus_actor_rooms"));
}

#[test]
#[should_panic(expected = "num_workers must be > 0")]
fn test_metrics_collector_zero_workers() {
    let _ = MetricsCollector::new(0);
}

#[test]
#[should_panic(expected = "bytes must be > 0")]
fn test_sfu_metrics_zero_bytes() {
    let metrics = SfuMetrics::new();
    metrics.record_packet_received(0);
}

#[test]
#[should_panic(expected = "cpu percent must be <= 100.0")]
fn test_worker_metrics_invalid_cpu() {
    let metrics = WorkerPoolMetrics::new(1);
    metrics.worker(0).set_cpu_usage_percent(150.0);
}
