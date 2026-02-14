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

mod actor;
mod crdt;
mod prometheus;
mod sfu;
mod tracing_metrics;
mod worker;

pub use actor::ActorMetrics;
pub use crdt::CrdtMetrics;
pub use prometheus::PrometheusExporter;
pub use sfu::SfuMetrics;
pub use tracing_metrics::{TracingMetrics, TracingMetricsSnapshot};
pub use worker::{WorkerMetrics, WorkerPoolMetrics};

use std::sync::Arc;

/// Global metrics collector
///
/// Aggregates all subsystem metrics for Prometheus export.
pub struct MetricsCollector {
    pub sfu: Arc<SfuMetrics>,
    pub workers: Arc<WorkerPoolMetrics>,
    pub crdt: Arc<CrdtMetrics>,
    pub actors: Arc<ActorMetrics>,
    pub tracing: Arc<TracingMetrics>,
    exporter: Arc<PrometheusExporter>,
}

impl MetricsCollector {
    /// Create new metrics collector
    ///
    /// # Assertions
    /// - num_workers > 0
    pub fn new(num_workers: u32) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(num_workers > 0, "num_workers must be > 0");

        let sfu = Arc::new(SfuMetrics::new());
        let workers = Arc::new(WorkerPoolMetrics::new(num_workers));
        let crdt = Arc::new(CrdtMetrics::new());
        let actors = Arc::new(ActorMetrics::new());
        let tracing = Arc::new(TracingMetrics::new());
        let exporter = Arc::new(PrometheusExporter::new()?);

        Ok(Self {
            sfu,
            workers,
            crdt,
            actors,
            tracing,
            exporter,
        })
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Update Prometheus metrics from internal collectors
        self.exporter.update(
            &self.sfu,
            &self.workers,
            &self.crdt,
            &self.actors,
        );

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
