//! Basic usage example for nexus-metrics

use nexus_metrics::MetricsCollector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a metrics collector for one data-plane shard
    let collector = MetricsCollector::new(1)?;

    // Record some SFU metrics
    collector.sfu.record_packet_received(1500);
    collector.sfu.record_packet_forwarded(1500, 1_000_000); // 1ms latency
    collector.sfu.set_active_tracks(10);
    collector.sfu.set_active_participants(5);
    collector.sfu.set_active_rooms(2);

    // Shard stats come from the data plane: the server installs a source that
    // reads each shard's published snapshot (here, a fixed one).
    collector.shards.set_source(Box::new(|_| {
        let mut stats = nexus_dataplane::ShardStatsSnapshot::default();
        stats.counters.rx_datagrams = 1_000;
        stats.gauges.sessions = 5;
        stats
    }));

    // Record CRDT metrics
    collector.crdt.record_gossip_sent();
    collector.crdt.record_gossip_received();
    collector.crdt.set_active_peers(3);

    // Export to Prometheus format
    let prometheus_output = collector.export_prometheus()?;

    println!("Prometheus Metrics Output:");
    println!("{}", prometheus_output);

    // Show some derived metrics
    println!("\nDerived Metrics:");
    println!(
        "Average forwarding latency: {:.2}ms",
        collector.sfu.avg_forwarding_latency_ms()
    );
    println!("P50 latency: {:.2}ms", collector.sfu.p50_latency_ms());
    println!("P99 latency: {:.2}ms", collector.sfu.p99_latency_ms());

    Ok(())
}
