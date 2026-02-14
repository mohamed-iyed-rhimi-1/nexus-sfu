//! CRDT and gossip metrics collector
//!
//! Tracks state synchronization, gossip messages, and peer health.

use std::sync::atomic::{AtomicU64, Ordering};

/// CRDT metrics collector
pub struct CrdtMetrics {
    // Gossip message counts
    gossip_messages_sent_total: AtomicU64,
    gossip_messages_received_total: AtomicU64,

    // State sync metrics
    state_syncs_total: AtomicU64,
    state_sync_latency_sum_nanos: AtomicU64,
    state_sync_latency_count: AtomicU64,

    // Peer metrics
    active_peers: AtomicU64,
    peer_failures_total: AtomicU64,

    // CRDT operation counts
    crdt_merges_total: AtomicU64,
    crdt_conflicts_total: AtomicU64,
}

impl CrdtMetrics {
    pub fn new() -> Self {
        Self {
            gossip_messages_sent_total: AtomicU64::new(0),
            gossip_messages_received_total: AtomicU64::new(0),
            state_syncs_total: AtomicU64::new(0),
            state_sync_latency_sum_nanos: AtomicU64::new(0),
            state_sync_latency_count: AtomicU64::new(0),
            active_peers: AtomicU64::new(0),
            peer_failures_total: AtomicU64::new(0),
            crdt_merges_total: AtomicU64::new(0),
            crdt_conflicts_total: AtomicU64::new(0),
        }
    }

    /// Record gossip message sent
    #[inline(always)]
    pub fn record_gossip_sent(&self) {
        self.gossip_messages_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record gossip message received
    #[inline(always)]
    pub fn record_gossip_received(&self) {
        self.gossip_messages_received_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record state sync completion
    ///
    /// # Assertions
    /// - latency_nanos > 0
    pub fn record_state_sync(&self, latency_nanos: u64) {
        assert!(latency_nanos > 0, "latency_nanos must be > 0");
        self.state_syncs_total.fetch_add(1, Ordering::Relaxed);
        self.state_sync_latency_sum_nanos.fetch_add(latency_nanos, Ordering::Relaxed);
        self.state_sync_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Set active peer count
    pub fn set_active_peers(&self, count: u64) {
        self.active_peers.store(count, Ordering::Relaxed);
    }

    /// Record peer failure
    pub fn record_peer_failure(&self) {
        self.peer_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record CRDT merge
    #[inline(always)]
    pub fn record_crdt_merge(&self) {
        self.crdt_merges_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record CRDT conflict
    pub fn record_crdt_conflict(&self) {
        self.crdt_conflicts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average state sync latency (milliseconds)
    pub fn avg_state_sync_latency_ms(&self) -> f64 {
        let sum = self.state_sync_latency_sum_nanos.load(Ordering::Relaxed);
        let count = self.state_sync_latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1_000_000.0
    }

    // Getters for Prometheus
    pub fn gossip_messages_sent_total(&self) -> u64 {
        self.gossip_messages_sent_total.load(Ordering::Relaxed)
    }

    pub fn gossip_messages_received_total(&self) -> u64 {
        self.gossip_messages_received_total.load(Ordering::Relaxed)
    }

    pub fn state_syncs_total(&self) -> u64 {
        self.state_syncs_total.load(Ordering::Relaxed)
    }

    pub fn active_peers(&self) -> u64 {
        self.active_peers.load(Ordering::Relaxed)
    }

    pub fn peer_failures_total(&self) -> u64 {
        self.peer_failures_total.load(Ordering::Relaxed)
    }

    pub fn crdt_merges_total(&self) -> u64 {
        self.crdt_merges_total.load(Ordering::Relaxed)
    }

    pub fn crdt_conflicts_total(&self) -> u64 {
        self.crdt_conflicts_total.load(Ordering::Relaxed)
    }
}

impl Default for CrdtMetrics {
    fn default() -> Self {
        Self::new()
    }
}
