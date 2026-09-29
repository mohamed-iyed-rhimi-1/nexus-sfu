//! Prometheus exporter
//!
//! Converts internal metrics to Prometheus text format.

use prometheus::{
    opts, Counter, Encoder, Gauge, Histogram, HistogramOpts, IntCounterVec, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

use nexus_dataplane::ShardCounters;

use crate::{CrdtMetrics, SfuMetrics, ShardMetrics};

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

    // Shard metrics (label `shard`): one counter per `ShardCounters` field, in the
    // order of `ShardCounters::NAMES`, and the six gauges.
    shard_counters: Vec<IntCounterVec>,
    shard_sessions: IntGaugeVec,
    shard_tracks: IntGaugeVec,
    shard_subscriptions: IntGaugeVec,
    shard_rx_pps: IntGaugeVec,
    shard_mirrors: IntGaugeVec,
    shard_xs_in_flight: IntGaugeVec,

    // CRDT metrics
    crdt_gossip_sent: Counter,
    crdt_gossip_received: Counter,
    crdt_state_syncs: Counter,
    crdt_state_sync_latency: Histogram,
    crdt_active_peers: Gauge,
    crdt_peer_failures: Counter,
    crdt_merges: Counter,
    crdt_conflicts: Counter,
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
            "Total packets received",
        ))?;
        registry.register(Box::new(sfu_packets_received.clone()))?;

        let sfu_packets_forwarded = Counter::with_opts(Opts::new(
            "nexus_sfu_packets_forwarded_total",
            "Total packets forwarded",
        ))?;
        registry.register(Box::new(sfu_packets_forwarded.clone()))?;

        let sfu_packets_dropped = Counter::with_opts(Opts::new(
            "nexus_sfu_packets_dropped_total",
            "Total packets dropped",
        ))?;
        registry.register(Box::new(sfu_packets_dropped.clone()))?;

        let sfu_bytes_received = Counter::with_opts(Opts::new(
            "nexus_sfu_bytes_received_total",
            "Total bytes received",
        ))?;
        registry.register(Box::new(sfu_bytes_received.clone()))?;

        let sfu_bytes_forwarded = Counter::with_opts(Opts::new(
            "nexus_sfu_bytes_forwarded_total",
            "Total bytes forwarded",
        ))?;
        registry.register(Box::new(sfu_bytes_forwarded.clone()))?;

        let sfu_forwarding_latency = Histogram::with_opts(
            HistogramOpts::new(
                "nexus_sfu_forwarding_latency_seconds",
                "Packet forwarding latency",
            )
            .buckets(vec![0.001, 0.005, 0.010, 0.050, 0.100, 0.500, 1.0]),
        )?;
        registry.register(Box::new(sfu_forwarding_latency.clone()))?;

        let sfu_active_tracks = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_tracks",
            "Number of active tracks",
        ))?;
        registry.register(Box::new(sfu_active_tracks.clone()))?;

        let sfu_active_participants = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_participants",
            "Number of active participants",
        ))?;
        registry.register(Box::new(sfu_active_participants.clone()))?;

        let sfu_active_rooms = Gauge::with_opts(Opts::new(
            "nexus_sfu_active_rooms",
            "Number of active rooms",
        ))?;
        registry.register(Box::new(sfu_active_rooms.clone()))?;

        // Shard metrics
        let mut shard_counters = Vec::with_capacity(ShardCounters::NAMES.len());
        for name in ShardCounters::NAMES {
            let counter = IntCounterVec::new(
                opts!(
                    format!("nexus_shard_{name}_total"),
                    format!("Shard counter `{name}` (nexus-dataplane ShardCounters)")
                ),
                &["shard"],
            )?;
            registry.register(Box::new(counter.clone()))?;
            shard_counters.push(counter);
        }
        let shard_gauge = |name: &str, help: &str| -> Result<IntGaugeVec, prometheus::Error> {
            let gauge = IntGaugeVec::new(opts!(format!("nexus_shard_{name}"), help), &["shard"])?;
            registry.register(Box::new(gauge.clone()))?;
            Ok(gauge)
        };
        let shard_sessions = shard_gauge("sessions", "Sessions on the shard")?;
        let shard_tracks = shard_gauge("tracks", "Published tracks on the shard")?;
        let shard_subscriptions = shard_gauge("subscriptions", "Subscriptions on the shard")?;
        let shard_rx_pps = shard_gauge("rx_pps", "Datagrams received per second")?;
        let shard_mirrors = shard_gauge("mirrors", "Tracks from other shards mirrored here")?;
        let shard_xs_in_flight = shard_gauge(
            "xs_in_flight",
            "Loans outstanding to other shards, per peer (a buffer lent to 3 shards counts 3)",
        )?;

        // CRDT metrics
        let crdt_gossip_sent = Counter::with_opts(Opts::new(
            "nexus_crdt_gossip_messages_sent_total",
            "Gossip messages sent",
        ))?;
        registry.register(Box::new(crdt_gossip_sent.clone()))?;

        let crdt_gossip_received = Counter::with_opts(Opts::new(
            "nexus_crdt_gossip_messages_received_total",
            "Gossip messages received",
        ))?;
        registry.register(Box::new(crdt_gossip_received.clone()))?;

        let crdt_state_syncs = Counter::with_opts(Opts::new(
            "nexus_crdt_state_syncs_total",
            "State synchronizations completed",
        ))?;
        registry.register(Box::new(crdt_state_syncs.clone()))?;

        let crdt_state_sync_latency = Histogram::with_opts(
            HistogramOpts::new(
                "nexus_crdt_state_sync_latency_seconds",
                "State synchronization latency",
            )
            .buckets(vec![0.001, 0.005, 0.010, 0.050, 0.100, 0.500, 1.0]),
        )?;
        registry.register(Box::new(crdt_state_sync_latency.clone()))?;

        let crdt_active_peers = Gauge::with_opts(Opts::new(
            "nexus_crdt_active_peers",
            "Number of active peers",
        ))?;
        registry.register(Box::new(crdt_active_peers.clone()))?;

        let crdt_peer_failures = Counter::with_opts(Opts::new(
            "nexus_crdt_peer_failures_total",
            "Peer failures detected",
        ))?;
        registry.register(Box::new(crdt_peer_failures.clone()))?;

        let crdt_merges = Counter::with_opts(Opts::new(
            "nexus_crdt_merges_total",
            "CRDT merge operations",
        ))?;
        registry.register(Box::new(crdt_merges.clone()))?;

        let crdt_conflicts = Counter::with_opts(Opts::new(
            "nexus_crdt_conflicts_total",
            "CRDT conflicts resolved",
        ))?;
        registry.register(Box::new(crdt_conflicts.clone()))?;

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
            shard_counters,
            shard_sessions,
            shard_tracks,
            shard_subscriptions,
            shard_rx_pps,
            shard_mirrors,
            shard_xs_in_flight,
            crdt_gossip_sent,
            crdt_gossip_received,
            crdt_state_syncs,
            crdt_state_sync_latency,
            crdt_active_peers,
            crdt_peer_failures,
            crdt_merges,
            crdt_conflicts,
        })
    }

    /// Update metrics from collectors
    pub fn update(&self, sfu: &SfuMetrics, shards: &ShardMetrics, crdt: &CrdtMetrics) {
        // Update SFU metrics
        self.sfu_packets_received.reset();
        self.sfu_packets_received
            .inc_by(sfu.packets_received_total() as f64);

        self.sfu_packets_forwarded.reset();
        self.sfu_packets_forwarded
            .inc_by(sfu.packets_forwarded_total() as f64);

        self.sfu_packets_dropped.reset();
        self.sfu_packets_dropped
            .inc_by(sfu.packets_dropped_total() as f64);

        self.sfu_bytes_received.reset();
        self.sfu_bytes_received
            .inc_by(sfu.bytes_received_total() as f64);

        self.sfu_bytes_forwarded.reset();
        self.sfu_bytes_forwarded
            .inc_by(sfu.bytes_forwarded_total() as f64);

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
        self.sfu_active_participants
            .set(sfu.active_participants() as f64);
        self.sfu_active_rooms.set(sfu.active_rooms() as f64);

        self.update_shards(shards);

        // Update CRDT metrics
        self.crdt_gossip_sent.reset();
        self.crdt_gossip_sent
            .inc_by(crdt.gossip_messages_sent_total() as f64);

        self.crdt_gossip_received.reset();
        self.crdt_gossip_received
            .inc_by(crdt.gossip_messages_received_total() as f64);

        self.crdt_state_syncs.reset();
        self.crdt_state_syncs
            .inc_by(crdt.state_syncs_total() as f64);

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
        self.crdt_peer_failures
            .inc_by(crdt.peer_failures_total() as f64);

        self.crdt_merges.reset();
        self.crdt_merges.inc_by(crdt.crdt_merges_total() as f64);

        self.crdt_conflicts.reset();
        self.crdt_conflicts
            .inc_by(crdt.crdt_conflicts_total() as f64);
    }

    /// Copies each shard's latest published stats (nothing before the server
    /// installed the stats source).
    fn update_shards(&self, shards: &ShardMetrics) {
        for index in 0..shards.shards() {
            let Some(stats) = shards.snapshot(index) else {
                return;
            };
            let label = index.to_string();
            let labels = [label.as_str()];
            let values = stats.counters.values();
            debug_assert_eq!(values.len(), self.shard_counters.len());
            for (counter, value) in self.shard_counters.iter().zip(values) {
                let child = counter.with_label_values(&labels);
                child.reset();
                child.inc_by(value);
            }
            let gauges = [
                (&self.shard_sessions, stats.gauges.sessions),
                (&self.shard_tracks, stats.gauges.tracks),
                (&self.shard_subscriptions, stats.gauges.subscriptions),
                (&self.shard_rx_pps, stats.gauges.rx_pps),
                (&self.shard_mirrors, stats.gauges.mirrors),
                (&self.shard_xs_in_flight, stats.gauges.xs_in_flight),
            ];
            for (gauge, value) in gauges {
                gauge
                    .with_label_values(&labels)
                    .set(i64::try_from(value).unwrap_or(i64::MAX));
            }
        }
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
