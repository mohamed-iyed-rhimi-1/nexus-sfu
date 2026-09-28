//! Nexus SFU Metrics
//!
//! Production-ready metrics infrastructure with Prometheus export.
//!
//! # TigerStyle Compliance
//! - Lock-free atomic counters for hot paths
//! - Pre-allocated data structures
//! - Explicitly-sized types
//! - Comprehensive assertions

#![deny(warnings)]

mod crdt;
mod prometheus;
mod sfu;
mod shard;
mod tracing_metrics;

pub use crdt::CrdtMetrics;
pub use prometheus::PrometheusExporter;
pub use sfu::SfuMetrics;
pub use shard::{ShardMetrics, ShardStatsSource};
pub use tracing_metrics::{TracingMetrics, TracingMetricsSnapshot};

use std::sync::Arc;

/// Global metrics collector
///
/// Aggregates all subsystem metrics for Prometheus export.
pub struct MetricsCollector {
    pub sfu: Arc<SfuMetrics>,
    /// Data-plane shards (design note §5.4).
    pub shards: Arc<ShardMetrics>,
    pub crdt: Arc<CrdtMetrics>,
    pub tracing: Arc<TracingMetrics>,
    exporter: Arc<PrometheusExporter>,
}

impl MetricsCollector {
    /// A collector for `shards` data-plane shards.
    ///
    /// # Assertions
    /// - shards > 0
    pub fn new(shards: u32) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(shards > 0, "shards must be > 0");

        let sfu = Arc::new(SfuMetrics::new());
        let shards = Arc::new(ShardMetrics::new(shards as usize));
        let crdt = Arc::new(CrdtMetrics::new());
        let tracing = Arc::new(TracingMetrics::new());
        let exporter = Arc::new(PrometheusExporter::new()?);

        Ok(Self {
            sfu,
            shards,
            crdt,
            tracing,
            exporter,
        })
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Update Prometheus metrics from internal collectors
        self.exporter.update(&self.sfu, &self.shards, &self.crdt);

        self.exporter.render()
    }

    /// Get the tracing metrics collector.
    pub fn tracing_metrics(&self) -> &Arc<TracingMetrics> {
        &self.tracing
    }

    /// Update packet rate calculation.
    /// Should be called periodically (e.g., every second).
    pub fn update_packet_rate(&self) {
        self.tracing.update_packet_rate();
    }
}
