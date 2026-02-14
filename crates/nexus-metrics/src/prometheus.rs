//! Prometheus exporter
//!
//! Converts internal metrics to Prometheus text format.

use prometheus::{
    Encoder, TextEncoder, Registry, Counter, Gauge, Histogram, HistogramOpts, Opts,
    IntGaugeVec, IntCounterVec, opts,
};

use crate::{ActorMetrics, CrdtMetrics, SfuMetrics, WorkerPoolMetrics};

/// Prometheus metrics registry
pub struct PrometheusExporter {
    registry: Registry,

    // SFU metrics
    sfu_packets_received: Counter,
    sfu_packets_forwarded: Counter,
    sfu_packets_dropped: Counter,
    sfu_bytes_received: Counter,
    sfu_bytes_forwarded: Counter,
    sfu_forwarding_latency: prometheus::Histogram,
    sfu_active_tracks: Gauge,
    sfu_active_participants: Gauge,
    sfu_active_rooms: Gauge,

    // Worker metrics (per-worker with labels)
    worker_cpu_usage: IntGaugeVec,
    worker_packet_queue_depth: IntGaugeVec,
    worker_track_count: IntGaugeVec,
    worker_packets_processed: IntCounterVec,
    worker_migrations_sent: IntCounterVec,
    worker_migrations_received: IntCounterVec,

    // CRDT metrics
    crdt_gossip_sent: Counter,
    crdt_gossip_received: Counter,
    crdt_state_syncs: Counter,
    crdt_state_sync_latency: Histogram,
    crdt_active_peers: Gauge,
    crdt_peer_failures: Counter,
    crdt_merges: Counter,
    crdt_conflicts: Counter,

    // Actor metrics
    actor_rooms: Gauge,
    actor_participants: Gauge,
    actor_tracks: Gauge,
    actor_message_queue_depth: Gauge,
    actor_messages_processed: Counter,
    actor_messages_dropped: Counter,
    actor_restarts: Counter,
    actor_failures: Counter,
}

impl PrometheusExporter {
    /// Create new Prometheus exporter
    ///
    /// # Assertions
    /// - All metric registrations succeed
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        // SFU metrics
        let sfu_packets_received = Counter::with_opts(Opts::new(
            "nexus_sfu_packets_received_total",
            "Total packets received"
        ))?;
        registry.register(Box::new(sfu_packets_received.clone()))?;

        let sfu_packets_forwarded = Counter::with_opts(Opts::new(
            "nexus_sfu_packets_forwarded_total",
            "Total packets forwarded"
        ))?;
        registry.register(Box::new(sfu_packets_forwarded.clone()))?;

        let sfu_packets_dropped = Counter::with_opts(Opts::new(
            "nexus_sfu_packets_dropped_total",
            "Total packets dropped"
        ))?;
        registry.register(Box::new(sfu_packets_dropped.clone()))?;

        let sfu_bytes_received = Counter::with_opts(Opts::new(
            "nexus_sfu_bytes_received_total",
            "Total bytes received"
        ))?;
        registry.register(Box::new(sfu_bytes_received.clone()))?;

        let sfu_bytes_forwarded = Counter::with_opts(Opts::new(
            "nexus_sfu_bytes_forwarded_total",
            "Total bytes forwarded"
        ))?;
        registry.register(Box::new(sfu_bytes_forwarded.clone()))?;

        let sfu_forwarding_latency = Histogram::with_opts(
            HistogramOpts::new(
                "nexus_sfu_forwarding_latency_seconds",
                "Packet forwarding latency"
            ).buckets(vec![0.001, 0.005, 0.010, 0.050, 0.100, 0.500, 1.0])
        )?;
        registry.register(Box::new(sfu_forwarding_latency.clone()))?;

        let sfu_active_tracks = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_tracks",
            "Number of active tracks"
        ))?;
        registry.register(Box::new(sfu_active_tracks.clone()))?;

        let sfu_active_participants = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_participants",
            "Number of active participants"
        ))?;
        registry.register(Box::new(sfu_active_participants.clone()))?;

        let sfu_active_rooms = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_rooms",
            "Number of active rooms"
        ))?;
        registry.register(Box::new(sfu_active_rooms.clone()))?;

        // Worker metrics
        let worker_cpu_usage = IntGaugeVec::new(
            opts!("nexus_worker_cpu_usage_percent", "Worker CPU usage percentage"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_cpu_usage.clone()))?;

        let worker_packet_queue_depth = IntGaugeVec::new(
            opts!("nexus_worker_packet_queue_depth", "Worker packet queue depth"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_packet_queue_depth.clone()))?;

        let worker_track_count = IntGaugeVec::new(
            opts!("nexus_worker_track_count", "Worker track count"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_track_count.clone()))?;

        let worker_packets_processed = IntCounterVec::new(
            opts!("nexus_worker_packets_processed_total", "Worker packets processed"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_packets_processed.clone()))?;

        let worker_migrations_sent = IntCounterVec::new(
            opts!("nexus_worker_migrations_sent_total", "Worker migrations sent"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_migrations_sent.clone()))?;

        let worker_migrations_received = IntCounterVec::new(
            opts!("nexus_worker_migrations_received_total", "Worker migrations received"),
            &["worker_id"]
        )?;
        registry.register(Box::new(worker_migrations_received.clone()))?;

        // CRDT metrics
        let crdt_gossip_sent = Counter::with_opts(Opts::new(
            "nexus_crdt_gossip_messages_sent_total",
            "Gossip messages sent"
        ))?;
        registry.register(Box::new(crdt_gossip_sent.clone()))?;

        let crdt_gossip_received = Counter::with_opts(Opts::new(
            "nexus_crdt_gossip_messages_received_total",
            "Gossip messages received"
        ))?;
        registry.register(Box::new(crdt_gossip_received.clone()))?;

        let crdt_state_syncs = Counter::with_opts(Opts::new(
            "nexus_crdt_state_syncs_total",
            "State synchronizations completed"
        ))?;
        registry.register(Box::new(crdt_state_syncs.clone()))?;

        let crdt_state_sync_latency = Histogram::with_opts(
            HistogramOpts::new(
                "nexus_crdt_state_sync_latency_seconds",
                "State synchronization latency"
            ).buckets(vec![0.001, 0.005, 0.010, 0.050, 0.100, 0.500, 1.0])
        )?;
        registry.register(Box::new(crdt_state_sync_latency.clone()))?;

        let crdt_active_peers = Gauge::with_opts(Opts::new(
            "nexus_crdt_active_peers",
            "Number of active peers"
        ))?;
        registry.register(Box::new(crdt_active_peers.clone()))?;

        let crdt_peer_failures = Counter::with_opts(Opts::new(
            "nexus_crdt_peer_failures_total",
            "Peer failures detected"
        ))?;
        registry.register(Box::new(crdt_peer_failures.clone()))?;

        let crdt_merges = Counter::with_opts(Opts::new(
            "nexus_crdt_merges_total",
            "CRDT merge operations"
        ))?;
        registry.register(Box::new(crdt_merges.clone()))?;

        let crdt_conflicts = Counter::with_opts(Opts::new(
            "nexus_crdt_conflicts_total",
            "CRDT conflicts resolved"
        ))?;
        registry.register(Box::new(crdt_conflicts.clone()))?;

        // Actor metrics
        let actor_rooms = Gauge::with_opts(Opts::new(
            "nexus_actor_rooms",
            "Number of room actors"
        ))?;
        registry.register(Box::new(actor_rooms.clone()))?;

        let actor_participants = Gauge::with_opts(Opts::new(
            "nexus_actor_participants",
            "Number of participant actors"
        ))?;
        registry.register(Box::new(actor_participants.clone()))?;

        let actor_tracks = Gauge::with_opts(Opts::new(
            "nexus_actor_tracks",
            "Number of track actors"
        ))?;
        registry.register(Box::new(actor_tracks.clone()))?;

        let actor_message_queue_depth = Gauge::with_opts(Opts::new(
            "nexus_actor_message_queue_depth",
            "Total message queue depth"
        ))?;
        registry.register(Box::new(actor_message_queue_depth.clone()))?;

        let actor_messages_processed = Counter::with_opts(Opts::new(
            "nexus_actor_messages_processed_total",
            "Messages processed"
        ))?;
        registry.register(Box::new(actor_messages_processed.clone()))?;

        let actor_messages_dropped = Counter::with_opts(Opts::new(
            "nexus_actor_messages_dropped_total",
            "Messages dropped"
        ))?;
        registry.register(Box::new(actor_messages_dropped.clone()))?;

        let actor_restarts = Counter::with_opts(Opts::new(
            "nexus_actor_restarts_total",
            "Actor restarts"
        ))?;
        registry.register(Box::new(actor_restarts.clone()))?;

        let actor_failures = Counter::with_opts(Opts::new(
            "nexus_actor_failures_total",
            "Actor failures"
        ))?;
        registry.register(Box::new(actor_failures.clone()))?;

        Ok(Self {
            registry,
            sfu_packets_received,
            sfu_packets_forwarded,
            sfu_packets_dropped,
            sfu_bytes_received,
            sfu_bytes_forwarded,
            sfu_forwarding_latency,
            sfu_active_tracks,
            sfu_active_participants,
            sfu_active_rooms,
            worker_cpu_usage,
            worker_packet_queue_depth,
            worker_track_count,
            worker_packets_processed,
            worker_migrations_sent,
            worker_migrations_received,
            crdt_gossip_sent,
            crdt_gossip_received,
            crdt_state_syncs,
            crdt_state_sync_latency,
            crdt_active_peers,
            crdt_peer_failures,
            crdt_merges,
            crdt_conflicts,
            actor_rooms,
            actor_participants,
            actor_tracks,
            actor_message_queue_depth,
            actor_messages_processed,
            actor_messages_dropped,
            actor_restarts,
            actor_failures,
        })
    }

    /// Update metrics from collectors
    pub fn update(
        &self,
        sfu: &SfuMetrics,
        workers: &WorkerPoolMetrics,
        crdt: &CrdtMetrics,
        actors: &ActorMetrics,
    ) {
        // Update SFU metrics
        self.sfu_packets_received.reset();
        self.sfu_packets_received.inc_by(sfu.packets_received_total() as f64);

        self.sfu_packets_forwarded.reset();
        self.sfu_packets_forwarded.inc_by(sfu.packets_forwarded_total() as f64);

        self.sfu_packets_dropped.reset();
        self.sfu_packets_dropped.inc_by(sfu.packets_dropped_total() as f64);

        self.sfu_bytes_received.reset();
        self.sfu_bytes_received.inc_by(sfu.bytes_received_total() as f64);

        self.sfu_bytes_forwarded.reset();
        self.sfu_bytes_forwarded.inc_by(sfu.bytes_forwarded_total() as f64);

        // Update latency histogram by observing bucket counts
        // Clear histogram first
        // Note: Prometheus histograms are cumulative, so we need to reconstruct observations
        // For simplicity, we'll observe the average latency for the count
        let latency_sum = sfu.forwarding_latency_sum_seconds();
        let latency_count = sfu.forwarding_latency_count();
        if latency_count > 0 {
            let avg_latency = latency_sum / latency_count as f64;
            // Observe the average latency once per count to maintain sum/count
            for _ in 0..latency_count {
                self.sfu_forwarding_latency.observe(avg_latency);
            }
        }

        self.sfu_active_tracks.set(sfu.active_tracks() as f64);
        self.sfu_active_participants.set(sfu.active_participants() as f64);
        self.sfu_active_rooms.set(sfu.active_rooms() as f64);

        // Update worker metrics
        for worker in workers.workers() {
            let worker_id_str = worker.worker_id().to_string();
            
            // CPU usage (scaled to integer percentage * 100)
            let cpu_scaled = (worker.cpu_usage_percent() * 100.0) as i64;
            self.worker_cpu_usage.with_label_values(&[&worker_id_str]).set(cpu_scaled);
            
            // Queue depth
            self.worker_packet_queue_depth.with_label_values(&[&worker_id_str])
                .set(worker.packet_queue_depth() as i64);
            
            // Track count
            self.worker_track_count.with_label_values(&[&worker_id_str])
                .set(worker.track_count() as i64);
            
            // Packets processed (reset and set)
            self.worker_packets_processed.with_label_values(&[&worker_id_str]).reset();
            self.worker_packets_processed.with_label_values(&[&worker_id_str])
                .inc_by(worker.packets_processed_total());
            
            // Migrations sent
            self.worker_migrations_sent.with_label_values(&[&worker_id_str]).reset();
            self.worker_migrations_sent.with_label_values(&[&worker_id_str])
                .inc_by(worker.migrations_sent());
            
            // Migrations received
            self.worker_migrations_received.with_label_values(&[&worker_id_str]).reset();
            self.worker_migrations_received.with_label_values(&[&worker_id_str])
                .inc_by(worker.migrations_received());
        }

        // Update CRDT metrics
        self.crdt_gossip_sent.reset();
        self.crdt_gossip_sent.inc_by(crdt.gossip_messages_sent_total() as f64);

        self.crdt_gossip_received.reset();
        self.crdt_gossip_received.inc_by(crdt.gossip_messages_received_total() as f64);

        self.crdt_state_syncs.reset();
        self.crdt_state_syncs.inc_by(crdt.state_syncs_total() as f64);

        // Update state sync latency histogram
        let sync_latency_ms = crdt.avg_state_sync_latency_ms();
        let sync_count = crdt.state_syncs_total();
        if sync_count > 0 {
            let avg_latency_seconds = sync_latency_ms / 1000.0;
            // Observe the average latency for each sync
            for _ in 0..sync_count {
                self.crdt_state_sync_latency.observe(avg_latency_seconds);
            }
        }

        self.crdt_active_peers.set(crdt.active_peers() as f64);

        self.crdt_peer_failures.reset();
        self.crdt_peer_failures.inc_by(crdt.peer_failures_total() as f64);

        self.crdt_merges.reset();
        self.crdt_merges.inc_by(crdt.crdt_merges_total() as f64);

        self.crdt_conflicts.reset();
        self.crdt_conflicts.inc_by(crdt.crdt_conflicts_total() as f64);

        // Update actor metrics
        self.actor_rooms.set(actors.room_actors() as f64);
        self.actor_participants.set(actors.participant_actors() as f64);
        self.actor_tracks.set(actors.track_actors() as f64);
        self.actor_message_queue_depth.set(actors.message_queue_depth() as f64);

        self.actor_messages_processed.reset();
        self.actor_messages_processed.inc_by(actors.messages_processed_total() as f64);

        self.actor_messages_dropped.reset();
        self.actor_messages_dropped.inc_by(actors.messages_dropped_total() as f64);

        self.actor_restarts.reset();
        self.actor_restarts.inc_by(actors.actor_restarts_total() as f64);

        self.actor_failures.reset();
        self.actor_failures.inc_by(actors.actor_failures_total() as f64);
    }

    /// Render metrics in Prometheus text format
    pub fn render(&self) -> Result<String, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).unwrap_or_default())
    }
}
