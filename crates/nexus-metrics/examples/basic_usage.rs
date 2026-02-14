//! Basic usage example for nexus-metrics

use nexus_metrics::MetricsCollector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create metrics collector with 4 workers
    let collector = MetricsCollector::new(4)?;

    // Record some SFU metrics
    collector.sfu.record_packet_received(1500);
    collector.sfu.record_packet_forwarded(1500, 1_000_000); // 1ms latency
    collector.sfu.set_active_tracks(10);
    collector.sfu.set_active_participants(5);
    collector.sfu.set_active_rooms(2);

    // Record worker metrics
    collector.workers.worker(0).set_cpu_usage_percent(45.5);
    collector.workers.worker(0).set_packet_queue_depth(100);
    collector.workers.worker(0).record_packet_processed();

    // Record CRDT metrics
    collector.crdt.record_gossip_sent();
    collector.crdt.record_gossip_received();
    collector.crdt.set_active_peers(3);

    // Record actor metrics
    collector.actors.set_room_actors(2);
    collector.actors.set_participant_actors(5);
    collector.actors.set_track_actors(10);
    collector.actors.record_message_processed();

    // Export to Prometheus format
    let prometheus_output = collector.export_prometheus()?;

    println!("Prometheus Metrics Output:");
    println!("{}", prometheus_output);

    // Show some derived metrics
    println!("\nDerived Metrics:");
    println!("Average forwarding latency: {:.2}ms", collector.sfu.avg_forwarding_latency_ms());
    println!("P50 latency: {:.2}ms", collector.sfu.p50_latency_ms());
    println!("P99 latency: {:.2}ms", collector.sfu.p99_latency_ms());
    println!("Total actors: {}", collector.actors.total_actors());
    println!("Total packets processed: {}", collector.workers.total_packets_processed());

    Ok(())
}
