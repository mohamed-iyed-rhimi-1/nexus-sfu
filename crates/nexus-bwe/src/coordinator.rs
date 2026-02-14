//! Bandwidth Coordinator - Bridge between GCC and TrackActor system
//!
//! Runs periodically (every 100ms) to collect track information, invoke GCC allocation,
//! and dispatch layer selection commands to actors via messages.

use crate::allocation::TrackAllocation;
use crate::gcc::CongestionController;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub type TrackId = u64;
pub type Ssrc = u32;

const MAX_TRACKS: usize = 100;
const MAX_LAYER_SWITCH_ENTRIES: usize = 1000;

/// Bandwidth coordinator that bridges GCC and distributed TrackActor system
pub struct BandwidthCoordinator {
    gcc: CongestionController,
    track_allocations: Vec<TrackAllocation>,
    last_allocation_us: AtomicU64,
    allocation_interval_us: u64,
    hysteresis_interval_us: u64,
    layer_switch_times: HashMap<TrackId, u64>,
}

impl BandwidthCoordinator {
    /// Create new coordinator with GCC parameters
    pub fn new(min_bps: u64, max_bps: u64, initial_bps: u64) -> Self {
        let allocation_interval_us = 100_000; // 100ms
        let hysteresis_interval_us = 2_000_000; // 2s

        assert!(
            allocation_interval_us > 0,
            "Allocation interval must be positive"
        );
        assert!(
            hysteresis_interval_us >= allocation_interval_us,
            "Hysteresis interval must be >= allocation interval"
        );

        Self {
            gcc: CongestionController::new(min_bps, max_bps, initial_bps),
            track_allocations: Vec::with_capacity(MAX_TRACKS),
            last_allocation_us: AtomicU64::new(0),
            allocation_interval_us,
            hysteresis_interval_us,
            layer_switch_times: HashMap::with_capacity(MAX_LAYER_SWITCH_ENTRIES),
        }
    }

    /// Forward transport feedback to GCC
    pub fn on_transport_feedback(
        &mut self,
        feedback: &crate::feedback::TransportFeedback,
        timestamp_us: u64,
    ) {
        self.gcc.on_transport_feedback(feedback, timestamp_us);
    }

    /// Forward receiver report to GCC
    pub fn on_receiver_report(
        &mut self,
        _ssrc: Ssrc,
        fraction_lost: u8,
        rtt_us: Option<u64>,
        timestamp_us: u64,
    ) {
        self.gcc
            .on_receiver_report(fraction_lost, rtt_us, timestamp_us);
    }

    /// Check if allocation should run (every 100ms)
    /// Returns true for the first allocation (when last_allocation_us is 0)
    /// or when enough time has passed since the last allocation.
    pub fn should_allocate(&self, timestamp_us: u64) -> bool {
        let last = self.last_allocation_us.load(Ordering::Relaxed);
        // Allow first allocation (last == 0) or when interval has passed
        last == 0 || timestamp_us.saturating_sub(last) >= self.allocation_interval_us
    }

    /// Collect track information from actor state
    pub fn collect_track_info<F>(&mut self, get_track_info: F) -> &mut [TrackAllocation]
    where
        F: FnOnce() -> Vec<TrackAllocation>,
    {
        self.track_allocations.clear();
        let allocations = get_track_info();

        assert!(
            allocations.len() <= MAX_TRACKS,
            "Track count exceeds maximum of {}",
            MAX_TRACKS
        );

        self.track_allocations.extend(allocations);
        &mut self.track_allocations
    }

    /// Allocate bandwidth and return layer updates with hysteresis
    pub fn allocate_and_dispatch(&mut self, timestamp_us: u64) -> Vec<(TrackId, u8)> {
        // Update last allocation time
        self.last_allocation_us
            .store(timestamp_us, Ordering::Relaxed);

        // Call GCC allocation
        self.gcc.allocate_bandwidth(&mut self.track_allocations);

        let mut updates = Vec::with_capacity(self.track_allocations.len());

        for allocation in &self.track_allocations {
            let track_id = allocation.track_id;
            let new_layer = allocation.selected_layer;

            // Check hysteresis
            let last_switch = self.layer_switch_times.get(&track_id).copied().unwrap_or(0);
            let time_since_switch = timestamp_us.saturating_sub(last_switch);

            if time_since_switch >= self.hysteresis_interval_us {
                // Enough time elapsed, allow switch
                updates.push((track_id, new_layer));
                self.layer_switch_times.insert(track_id, timestamp_us);
            }
            // Otherwise skip update (too soon)
        }

        // LRU eviction if map exceeds limit
        if self.layer_switch_times.len() > MAX_LAYER_SWITCH_ENTRIES {
            self.evict_oldest_entries();
        }

        assert!(
            self.layer_switch_times.len() <= MAX_LAYER_SWITCH_ENTRIES,
            "Layer switch times exceeded maximum after eviction"
        );

        updates
    }

    /// Generate REMB packet for given SSRC
    pub fn generate_remb(&self, ssrc: Ssrc) -> Vec<u8> {
        let target_bitrate = self.gcc.target_bitrate_bps();
        crate::remb::RembGenerator::new(ssrc).generate(target_bitrate, ssrc)
    }

    /// Get current GCC target bitrate
    pub fn target_bitrate(&self) -> u64 {
        self.gcc.target_bitrate_bps()
    }

    /// Evict oldest entries from layer switch times map
    fn evict_oldest_entries(&mut self) {
        // Find oldest 10% of entries and remove them
        let evict_count = MAX_LAYER_SWITCH_ENTRIES / 10;
        let mut entries: Vec<_> = self
            .layer_switch_times
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        entries.sort_by_key(|(_, time)| *time);

        for (track_id, _) in entries.iter().take(evict_count) {
            self.layer_switch_times.remove(track_id);
        }
    }
}
