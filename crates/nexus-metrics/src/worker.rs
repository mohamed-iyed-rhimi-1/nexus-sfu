//! Worker metrics collector
//!
//! Tracks per-worker statistics: CPU usage, packet queue depth, track count, migrations.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum workers supported
const MAX_WORKERS: usize = 64;

/// Per-worker metrics
pub struct WorkerMetrics {
    worker_id: u32,

    // CPU usage (percentage * 100 for precision)
    cpu_usage_percent_scaled: AtomicU32,

    // Packet queue depth
    packet_queue_depth: AtomicU32,

    // Track count on this worker
    track_count: AtomicU32,

    // Packets processed
    packets_processed_total: AtomicU64,

    // Migration metrics
    migrations_sent: AtomicU64,
    migrations_received: AtomicU64,
}

impl WorkerMetrics {
    /// Create new worker metrics
    ///
    /// # Assertions
    /// - worker_id < MAX_WORKERS
    pub fn new(worker_id: u32) -> Self {
        assert!(
            (worker_id as usize) < MAX_WORKERS,
            "worker_id must be < {}",
            MAX_WORKERS
        );

        Self {
            worker_id,
            cpu_usage_percent_scaled: AtomicU32::new(0),
            packet_queue_depth: AtomicU32::new(0),
            track_count: AtomicU32::new(0),
            packets_processed_total: AtomicU64::new(0),
            migrations_sent: AtomicU64::new(0),
            migrations_received: AtomicU64::new(0),
        }
    }

    pub fn worker_id(&self) -> u32 {
        self.worker_id
    }

    /// Set CPU usage percentage
    ///
    /// # Assertions
    /// - percent <= 100.0
    pub fn set_cpu_usage_percent(&self, percent: f32) {
        assert!(percent <= 100.0, "cpu percent must be <= 100.0");
        let scaled = (percent * 100.0) as u32;
        self.cpu_usage_percent_scaled.store(scaled, Ordering::Relaxed);
    }

    /// Get CPU usage percentage
    pub fn cpu_usage_percent(&self) -> f32 {
        self.cpu_usage_percent_scaled.load(Ordering::Relaxed) as f32 / 100.0
    }

    /// Set packet queue depth
    pub fn set_packet_queue_depth(&self, depth: u32) {
        self.packet_queue_depth.store(depth, Ordering::Relaxed);
    }

    pub fn packet_queue_depth(&self) -> u32 {
        self.packet_queue_depth.load(Ordering::Relaxed)
    }

    /// Set track count
    pub fn set_track_count(&self, count: u32) {
        self.track_count.store(count, Ordering::Relaxed);
    }

    pub fn track_count(&self) -> u32 {
        self.track_count.load(Ordering::Relaxed)
    }

    /// Record packet processed
    #[inline(always)]
    pub fn record_packet_processed(&self) {
        self.packets_processed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn packets_processed_total(&self) -> u64 {
        self.packets_processed_total.load(Ordering::Relaxed)
    }

    /// Record migration sent
    pub fn record_migration_sent(&self) {
        self.migrations_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn migrations_sent(&self) -> u64 {
        self.migrations_sent.load(Ordering::Relaxed)
    }

    /// Record migration received
    pub fn record_migration_received(&self) {
        self.migrations_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn migrations_received(&self) -> u64 {
        self.migrations_received.load(Ordering::Relaxed)
    }
}

/// Worker pool metrics aggregator
pub struct WorkerPoolMetrics {
    workers: Vec<WorkerMetrics>,
}

impl WorkerPoolMetrics {
    /// Create new worker pool metrics
    ///
    /// # Assertions
    /// - num_workers > 0
    /// - num_workers <= MAX_WORKERS
    pub fn new(num_workers: u32) -> Self {
        assert!(num_workers > 0, "num_workers must be > 0");
        assert!(
            (num_workers as usize) <= MAX_WORKERS,
            "num_workers must be <= {}",
            MAX_WORKERS
        );

        let workers = (0..num_workers).map(WorkerMetrics::new).collect();

        Self { workers }
    }

    /// Get worker metrics by ID
    ///
    /// # Assertions
    /// - worker_id < num_workers
    pub fn worker(&self, worker_id: u32) -> &WorkerMetrics {
        let idx = worker_id as usize;
        assert!(idx < self.workers.len(), "worker_id out of bounds");
        &self.workers[idx]
    }

    /// Get all workers
    pub fn workers(&self) -> &[WorkerMetrics] {
        &self.workers
    }

    /// Get total packets processed across all workers
    pub fn total_packets_processed(&self) -> u64 {
        self.workers.iter().map(|w| w.packets_processed_total()).sum()
    }

    /// Get total track count across all workers
    pub fn total_track_count(&self) -> u32 {
        self.workers.iter().map(|w| w.track_count()).sum()
    }
}
