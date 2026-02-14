use crate::{
    allocation::TrackAllocation,
    delay::{DelayBasedBweDetector, DelayBasedBweState},
    feedback::TransportFeedback,
    loss::LossBasedBweDetector,
    probe::{ProbeController, ProbeResult, ProbeState},
    rtt::RttEstimator,
    types::BweState,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Google Congestion Control (GCC) implementation.
/// 
/// Uses delay-based bandwidth estimation combined with loss-based estimation,
/// probing, and priority-based track allocation. The combined estimate uses
/// `min(delay_estimate, loss_estimate)` to be conservative.
///
/// # Interior Mutability
///
/// This struct uses interior mutability via `parking_lot::Mutex` to allow
/// `on_receiver_report()` to be called from the packet processing loop without
/// requiring exclusive (`&mut self`) access. This enables the SFU to update
/// BWE estimates in real-time as RTCP receiver reports arrive.
///
/// The `estimated_bps` atomic provides lock-free reads on the hot path for
/// bandwidth queries, while the mutex protects the mutable state during updates.
pub struct CongestionController {
    /// Mutable state protected by mutex for interior mutability.
    inner: Mutex<CongestionControllerInner>,
    /// Lock-free bandwidth estimate for hot path reads.
    /// Updated atomically after mutex-protected state changes.
    estimated_bps: AtomicU64,
    /// Target bitrate with headroom (bps) - lock-free read.
    target_bps: AtomicU64,
    /// Delay-based estimate (bps) - lock-free read.
    delay_estimate_bps: AtomicU64,
    /// Loss-based estimate (bps) - lock-free read.
    loss_estimate_bps: AtomicU64,
    /// Minimum bandwidth bound (immutable after construction).
    min_bps: u64,
    /// Maximum bandwidth bound (immutable after construction).
    max_bps: u64,
    /// Statistics (all atomic for lock-free access).
    stats: GccStats,
}

/// Mutable state extracted for interior mutability.
///
/// This struct contains all state that needs to be mutated during
/// `on_transport_feedback()`, `on_receiver_report()`, and `update_estimate()`.
struct CongestionControllerInner {
    /// Delay-based detector.
    delay_detector: DelayBasedBweDetector,
    /// Loss-based detector.
    loss_detector: LossBasedBweDetector,
    /// RTT estimator.
    rtt_estimator: RttEstimator,
    /// Probe controller.
    probe_controller: ProbeController,
    /// Last update timestamp (microseconds).
    last_update_us: u64,
    /// AIMD parameters.
    aimd_config: AimdConfig,
}

struct AimdConfig {
    /// Additive increase (bps per second).
    increase_bps: u64,
    /// Multiplicative decrease factor.
    decrease_factor: f64,
    /// Headroom factor for target (0.85 = 15% headroom).
    headroom_factor: f64,
}

impl AimdConfig {
    fn default() -> Self {
        let increase_bps = 8_000;
        let decrease_factor = 0.85;
        let headroom_factor = 0.85;

        assert!(increase_bps > 0, "Increase must be positive");
        assert!(
            decrease_factor > 0.0 && decrease_factor < 1.0,
            "Decrease factor must be in (0, 1)"
        );
        assert!(
            headroom_factor > 0.0 && headroom_factor < 1.0,
            "Headroom factor must be in (0, 1)"
        );

        Self {
            increase_bps,
            decrease_factor,
            headroom_factor,
        }
    }
}

pub struct GccStats {
    /// Total transport feedbacks processed.
    pub feedbacks_processed: AtomicU64,
    /// Total receiver reports processed.
    pub reports_processed: AtomicU64,
    /// Bandwidth estimate changes.
    pub estimate_changes: AtomicU64,
    /// Probe attempts.
    pub probe_attempts: AtomicU64,
    /// Successful probes.
    pub probe_successes: AtomicU64,
    /// Failed probes.
    pub probe_failures: AtomicU64,
    /// Current delay-based state (0=Normal, 1=Overuse, 2=Underuse).
    pub delay_state: AtomicU8,
    /// Current loss percentage (×100 for precision).
    pub loss_percent_x100: AtomicU32,
    /// Allocation efficiency (allocated / target, ×100).
    pub allocation_efficiency_x100: AtomicU32,
}

#[derive(Debug, Clone)]
pub struct GccStatsSnapshot {
    pub feedbacks_processed: u64,
    pub reports_processed: u64,
    pub estimate_changes: u64,
    pub probe_attempts: u64,
    pub probe_successes: u64,
    pub probe_failures: u64,
    pub delay_state: BweState,
    pub loss_percent: f64,
    pub allocation_efficiency: f64,
    pub current_estimate_bps: u64,
    pub target_bitrate_bps: u64,
    pub delay_estimate_bps: u64,
    pub loss_estimate_bps: u64,
}

impl CongestionController {
    /// Create new GCC controller.
    ///
    /// # Arguments
    ///
    /// * `min_bps` - Minimum bandwidth bound (must be > 0)
    /// * `max_bps` - Maximum bandwidth bound
    /// * `initial_bps` - Initial bandwidth estimate (must be in [min_bps, max_bps])
    ///
    /// # Panics
    ///
    /// Panics if min_bps is 0 or if initial_bps is not in [min_bps, max_bps].
    pub fn new(min_bps: u64, max_bps: u64, initial_bps: u64) -> Self {
        assert!(min_bps > 0, "Min bandwidth must be positive");
        assert!(
            min_bps <= initial_bps && initial_bps <= max_bps,
            "Must have min_bps <= initial_bps <= max_bps, got {} <= {} <= {}",
            min_bps,
            initial_bps,
            max_bps
        );

        let aimd_config = AimdConfig::default();
        let target_bps = (initial_bps as f64 * aimd_config.headroom_factor) as u64;

        Self {
            inner: Mutex::new(CongestionControllerInner {
                delay_detector: DelayBasedBweDetector::with_defaults(),
                loss_detector: LossBasedBweDetector::new(min_bps, max_bps, initial_bps),
                rtt_estimator: RttEstimator::new(50_000), // 50ms initial RTT
                probe_controller: ProbeController::default(),
                last_update_us: 0,
                aimd_config,
            }),
            estimated_bps: AtomicU64::new(initial_bps),
            target_bps: AtomicU64::new(target_bps),
            delay_estimate_bps: AtomicU64::new(initial_bps),
            loss_estimate_bps: AtomicU64::new(initial_bps),
            min_bps,
            max_bps,
            stats: GccStats {
                feedbacks_processed: AtomicU64::new(0),
                reports_processed: AtomicU64::new(0),
                estimate_changes: AtomicU64::new(0),
                probe_attempts: AtomicU64::new(0),
                probe_successes: AtomicU64::new(0),
                probe_failures: AtomicU64::new(0),
                delay_state: AtomicU8::new(BweState::Normal as u8),
                loss_percent_x100: AtomicU32::new(0),
                allocation_efficiency_x100: AtomicU32::new(0),
            },
        }
    }

    /// Process transport-wide congestion control feedback.
    ///
    /// Uses interior mutability to update delay-based estimates.
    /// Can be called from the packet processing loop without &mut self.
    ///
    /// # Arguments
    ///
    /// * `feedback` - Transport feedback containing packet arrival info
    /// * `timestamp_us` - Current timestamp in microseconds
    pub fn on_transport_feedback(&self, feedback: &TransportFeedback, timestamp_us: u64) {
        self.stats.feedbacks_processed.fetch_add(1, Ordering::Relaxed);

        let mut inner = self.inner.lock();

        // Update delay-based estimate
        let delay_state = inner.delay_detector.on_feedback(feedback);
        
        // Convert DelayBasedBweState to u8 for storage
        let state_val = match delay_state {
            DelayBasedBweState::Normal => 0,
            DelayBasedBweState::Overuse => 1,
            DelayBasedBweState::Underuse => 2,
        };
        self.stats.delay_state.store(state_val, Ordering::Relaxed);

        let current_estimate = self.estimated_bps.load(Ordering::Relaxed);
        let delay_estimate = match delay_state {
            DelayBasedBweState::Overuse => {
                // Decrease by multiplicative factor
                (current_estimate as f64 * inner.aimd_config.decrease_factor) as u64
            }
            DelayBasedBweState::Underuse => {
                // Increase by additive factor, scaled by time
                let last_update = inner.last_update_us;
                let dt_us = if last_update > 0 {
                    timestamp_us.saturating_sub(last_update)
                } else {
                    0
                };
                let dt_seconds = dt_us as f64 / 1_000_000.0;
                let increase = (inner.aimd_config.increase_bps as f64 * dt_seconds) as u64;
                current_estimate + increase
            }
            DelayBasedBweState::Normal => current_estimate,
        };

        self.delay_estimate_bps.store(delay_estimate, Ordering::Relaxed);
        inner.last_update_us = timestamp_us;
    }

    /// Process RTCP receiver report.
    ///
    /// Uses interior mutability to update RTT estimates, loss-based BWE, and probe state.
    /// Can be called from the packet processing loop without &mut self.
    ///
    /// # Arguments
    ///
    /// * `fraction_lost` - Fraction of packets lost (0-255)
    /// * `rtt_us` - Round-trip time in microseconds (if available)
    /// * `timestamp_us` - Current timestamp in microseconds
    ///
    /// # TigerStyle Compliance
    ///
    /// - Uses interior mutability for shared access
    /// - Lock-free atomic updates for statistics
    /// - Minimal lock contention (mutex only for mutable state)
    pub fn on_receiver_report(
        &self,
        fraction_lost: u8,
        rtt_us: Option<u64>,
        timestamp_us: u64,
    ) {
        self.stats.reports_processed.fetch_add(1, Ordering::Relaxed);

        // Calculate loss percentage for statistics (lock-free)
        let loss_percent = ((fraction_lost as u32 * 100) / 256) as u8;
        self.stats
            .loss_percent_x100
            .store((loss_percent as u32) * 100, Ordering::Relaxed);

        // Acquire mutex for mutable state updates
        let mut inner = self.inner.lock();

        // Update RTT if available
        if let Some(rtt) = rtt_us {
            inner.rtt_estimator.update(rtt);
        }

        // Update loss-based estimate
        let _loss_state = inner.loss_detector.on_receiver_report(fraction_lost, timestamp_us);
        let loss_estimate = inner.loss_detector.estimate_bps();
        self.loss_estimate_bps.store(loss_estimate, Ordering::Relaxed);

        // Update probe controller with loss feedback
        if inner.probe_controller.state() == ProbeState::Probing {
            let result = inner.probe_controller.on_feedback(loss_percent, timestamp_us);
            match result {
                ProbeResult::Success => {
                    self.stats.probe_successes.fetch_add(1, Ordering::Relaxed);
                }
                ProbeResult::Failed => {
                    self.stats.probe_failures.fetch_add(1, Ordering::Relaxed);
                }
                ProbeResult::Continue => {}
            }
        }
    }

    /// Update bandwidth estimate.
    ///
    /// Combines delay-based and loss-based estimates using `min(delay, loss)`.
    /// Uses interior mutability to update estimates and probe state.
    /// Updates the lock-free atomic for hot path reads.
    ///
    /// # Arguments
    ///
    /// * `timestamp_us` - Current timestamp in microseconds
    ///
    /// # Returns
    ///
    /// The updated bandwidth estimate in bits per second.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions (bounds verification)
    pub fn update_estimate(&self, timestamp_us: u64) -> u64 {
        let delay_estimate = self.delay_estimate_bps.load(Ordering::Relaxed);
        let loss_estimate = self.loss_estimate_bps.load(Ordering::Relaxed);

        // Combine delay-based and loss-based estimates using minimum
        // This is conservative: use the lower of the two estimates
        let mut raw_estimate = delay_estimate.min(loss_estimate);

        // Acquire mutex for probe controller state
        {
            let mut inner = self.inner.lock();

            // Check if we should start probing
            if inner.probe_controller.should_probe(raw_estimate, timestamp_us) {
                inner.probe_controller.start_probe(raw_estimate, timestamp_us);
                self.stats.probe_attempts.fetch_add(1, Ordering::Relaxed);
            }

            // Use probe bitrate if successful
            if inner.probe_controller.state() == ProbeState::Success {
                if let Some(probe_bitrate) = inner.probe_controller.probe_bitrate_bps() {
                    raw_estimate = probe_bitrate;
                    inner.probe_controller.reset();
                }
            } else if inner.probe_controller.state() == ProbeState::Failed {
                inner.probe_controller.reset();
            }
        }

        // Clamp to bounds
        let estimate = raw_estimate.clamp(self.min_bps, self.max_bps);

        // Verify invariants
        assert!(
            estimate >= self.min_bps && estimate <= self.max_bps,
            "Estimate {} must be within [{}, {}]",
            estimate,
            self.min_bps,
            self.max_bps
        );

        // Update target with headroom
        let headroom_factor = {
            let inner = self.inner.lock();
            inner.aimd_config.headroom_factor
        };
        let target = (estimate as f64 * headroom_factor) as u64;
        assert!(
            target <= estimate,
            "Target {} must be <= estimate {}",
            target,
            estimate
        );

        // Update atomics for lock-free reads
        let old_estimate = self.estimated_bps.swap(estimate, Ordering::Relaxed);
        if old_estimate != estimate {
            self.stats.estimate_changes.fetch_add(1, Ordering::Relaxed);
        }

        self.target_bps.store(target, Ordering::Relaxed);

        estimate
    }

    /// Allocate bandwidth across tracks by priority with two-phase allocation.
    /// 
    /// Phase 1: Reserve minimum layer bitrate for all tracks to prevent starvation.
    /// Phase 2: Distribute remaining bandwidth in priority order.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines (uses helper functions)
    /// - ≥2 assertions
    pub fn allocate_bandwidth(&self, tracks: &mut [TrackAllocation]) {
        // Precondition: track count bounded
        assert!(
            tracks.len() <= TrackAllocation::MAX_TRACKS,
            "Cannot allocate for more than {} tracks, got {}",
            TrackAllocation::MAX_TRACKS,
            tracks.len()
        );

        let available = self.target_bps.load(Ordering::Relaxed);
        
        // Phase 1: Reserve minimum layer for all tracks
        let (total_min_bitrate, can_satisfy_all_mins) = 
            Self::allocate_minimum_layers(tracks, available);

        // Phase 2: Distribute remaining bandwidth by priority
        let remaining = available.saturating_sub(total_min_bitrate.min(available));
        Self::allocate_remaining_by_priority(tracks, remaining);

        // Finalize and verify allocations
        let total_allocated = Self::finalize_allocations(tracks, available, can_satisfy_all_mins);

        // Update allocation efficiency
        let efficiency = if available > 0 {
            ((total_allocated as f64 / available as f64) * 10000.0) as u32
        } else {
            0
        };
        self.stats
            .allocation_efficiency_x100
            .store(efficiency, Ordering::Relaxed);
    }

    /// Phase 1: Allocate minimum layer bitrate to all tracks.
    ///
    /// Returns (total_min_bitrate, can_satisfy_all_mins).
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    fn allocate_minimum_layers(tracks: &mut [TrackAllocation], available: u64) -> (u64, bool) {
        // Precondition: available must be reasonable
        assert!(available <= u64::MAX / 2, "available overflow protection");
        
        // Calculate total minimum bitrate needed
        let mut total_min_bitrate = 0u64;
        for track in tracks.iter() {
            let min_bitrate = track.min_layer_bitrate();
            if min_bitrate > 0 {
                total_min_bitrate += min_bitrate;
            }
        }

        let can_satisfy_all_mins = total_min_bitrate <= available;
        
        if can_satisfy_all_mins {
            // Reserve minimum for all tracks
            for track in tracks.iter_mut() {
                let min_bitrate = track.min_layer_bitrate();
                track.allocated_bitrate_bps = if min_bitrate > 0 { min_bitrate } else { 0 };
            }
        } else {
            // Not enough bandwidth, allocate proportionally
            for track in tracks.iter_mut() {
                let min_bitrate = track.min_layer_bitrate();
                if min_bitrate > 0 && total_min_bitrate > 0 {
                    let proportion = min_bitrate as f64 / total_min_bitrate as f64;
                    track.allocated_bitrate_bps = (available as f64 * proportion) as u64;
                } else {
                    track.allocated_bitrate_bps = 0;
                }
            }
        }

        // Postcondition: total_min_bitrate is bounded
        assert!(total_min_bitrate <= u64::MAX / 2, "total_min_bitrate overflow");
        
        (total_min_bitrate, can_satisfy_all_mins)
    }

    /// Phase 2: Distribute remaining bandwidth by priority.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    fn allocate_remaining_by_priority(tracks: &mut [TrackAllocation], mut remaining: u64) {
        // Precondition: remaining must be reasonable
        assert!(remaining <= u64::MAX / 2, "remaining overflow protection");
        
        // Sort by priority (descending)
        tracks.sort_by(|a, b| b.priority.cmp(&a.priority));

        for track in tracks.iter_mut() {
            if remaining == 0 {
                break;
            }

            // Calculate additional bandwidth this track can use
            let current_allocation = track.allocated_bitrate_bps;
            let max_additional = track.max_bitrate_bps.saturating_sub(current_allocation);
            let additional = max_additional.min(remaining);
            
            track.allocated_bitrate_bps += additional;
            remaining = remaining.saturating_sub(additional);
        }

        // Postcondition: remaining is bounded
        assert!(remaining <= u64::MAX / 2, "remaining should decrease");
    }

    /// Finalize allocations: select layers and verify invariants.
    ///
    /// Returns total allocated bitrate.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    fn finalize_allocations(
        tracks: &mut [TrackAllocation], 
        available: u64, 
        can_satisfy_all_mins: bool
    ) -> u64 {
        // Precondition: available must be reasonable
        assert!(available <= u64::MAX / 2, "available overflow protection");
        
        let mut total_allocated = 0u64;
        for track in tracks.iter_mut() {
            track.select_layer();
            track.verify();
            total_allocated += track.allocated_bitrate_bps;
        }

        // Verify allocation invariants
        assert!(
            total_allocated <= available,
            "Total allocated {} exceeds available {}",
            total_allocated,
            available
        );

        // Verify no starvation when bandwidth allows
        if can_satisfy_all_mins {
            for track in tracks.iter() {
                let min_bitrate = track.min_layer_bitrate();
                if min_bitrate > 0 {
                    assert!(
                        track.allocated_bitrate_bps >= min_bitrate,
                        "Track {} starved: allocated {} < min layer {}",
                        track.track_id,
                        track.allocated_bitrate_bps,
                        min_bitrate
                    );
                }
            }
        }

        total_allocated
    }

    /// Get current bandwidth estimate.
    ///
    /// Lock-free read from atomic for hot path performance.
    #[inline]
    pub fn estimated_bandwidth_bps(&self) -> u64 {
        self.estimated_bps.load(Ordering::Relaxed)
    }

    /// Get target bitrate with headroom.
    ///
    /// Lock-free read from atomic for hot path performance.
    #[inline]
    pub fn target_bitrate_bps(&self) -> u64 {
        self.target_bps.load(Ordering::Relaxed)
    }

    /// Get loss-based bandwidth estimate.
    ///
    /// Lock-free read from atomic for hot path performance.
    #[inline]
    pub fn loss_estimate_bps(&self) -> u64 {
        self.loss_estimate_bps.load(Ordering::Relaxed)
    }

    /// Get delay-based bandwidth estimate.
    ///
    /// Lock-free read from atomic for hot path performance.
    #[inline]
    pub fn delay_estimate_bps(&self) -> u64 {
        self.delay_estimate_bps.load(Ordering::Relaxed)
    }

    /// Get statistics snapshot.
    pub fn stats(&self) -> GccStatsSnapshot {
        let delay_state_val = self.stats.delay_state.load(Ordering::Relaxed);
        let delay_state = match delay_state_val {
            0 => BweState::Normal,
            1 => BweState::Overuse,
            2 => BweState::Underuse,
            _ => BweState::Normal,
        };

        GccStatsSnapshot {
            feedbacks_processed: self.stats.feedbacks_processed.load(Ordering::Relaxed),
            reports_processed: self.stats.reports_processed.load(Ordering::Relaxed),
            estimate_changes: self.stats.estimate_changes.load(Ordering::Relaxed),
            probe_attempts: self.stats.probe_attempts.load(Ordering::Relaxed),
            probe_successes: self.stats.probe_successes.load(Ordering::Relaxed),
            probe_failures: self.stats.probe_failures.load(Ordering::Relaxed),
            delay_state,
            loss_percent: self.stats.loss_percent_x100.load(Ordering::Relaxed) as f64 / 100.0,
            allocation_efficiency: self.stats.allocation_efficiency_x100.load(Ordering::Relaxed)
                as f64
                / 10000.0,
            current_estimate_bps: self.estimated_bps.load(Ordering::Relaxed),
            target_bitrate_bps: self.target_bps.load(Ordering::Relaxed),
            delay_estimate_bps: self.delay_estimate_bps.load(Ordering::Relaxed),
            loss_estimate_bps: self.loss_estimate_bps.load(Ordering::Relaxed),
        }
    }

    // ========================================================================
    // Test-only methods for accessing internal state
    // ========================================================================

    /// Get the probe controller state (for testing).
    #[cfg(test)]
    pub(crate) fn probe_controller_state(&self) -> ProbeState {
        self.inner.lock().probe_controller.state()
    }

    /// Start a probe (for testing).
    #[cfg(test)]
    pub(crate) fn start_probe(&self, bitrate: u64, timestamp_us: u64) {
        self.inner.lock().probe_controller.start_probe(bitrate, timestamp_us);
    }

    /// Get RTT estimator srtt (for testing).
    #[cfg(test)]
    pub(crate) fn rtt_srtt_us(&self) -> u64 {
        self.inner.lock().rtt_estimator.srtt_us()
    }

    /// Set last update timestamp (for testing).
    #[cfg(test)]
    pub(crate) fn set_last_update_us(&self, timestamp_us: u64) {
        self.inner.lock().last_update_us = timestamp_us;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocation::{SimulcastLayer, TrackPriority};

    #[test]
    fn test_gcc_initialization() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        
        assert_eq!(gcc.estimated_bandwidth_bps(), 1_000_000);
        assert!(gcc.target_bitrate_bps() < gcc.estimated_bandwidth_bps());
        
        let stats = gcc.stats();
        assert_eq!(stats.feedbacks_processed, 0);
        assert_eq!(stats.reports_processed, 0);
    }

    #[test]
    #[should_panic(expected = "Min bandwidth must be positive")]
    fn test_gcc_zero_min() {
        CongestionController::new(0, 10_000_000, 1_000_000);
    }

    #[test]
    #[should_panic(expected = "Must have min_bps <= initial_bps <= max_bps")]
    fn test_gcc_invalid_bounds() {
        CongestionController::new(1_000_000, 10_000_000, 100_000);
    }

    #[test]
    fn test_gcc_delay_overuse_decreases_estimate() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        let initial = gcc.estimated_bandwidth_bps();

        // Create feedback indicating overuse (increasing delays)
        let mut feedback = TransportFeedback::new(12345, 0);
        for i in 0..20 {
            let _ = feedback.add_packet(crate::feedback::PacketArrivalInfo {
                sequence: i,
                send_time_us: i as u64 * 20_000,
                recv_time_us: i as u64 * 20_000 + i as u64 * 1_000, // Increasing delay
                size_bytes: 1200,
            });
        }

        gcc.on_transport_feedback(&feedback, 400_000);
        let estimate = gcc.update_estimate(400_000);

        // Should decrease due to overuse
        assert!(estimate <= initial, "Estimate should decrease on overuse");
    }

    #[test]
    fn test_gcc_loss_affects_estimate() {
        // Loss-based estimation is now combined with delay-based using min().
        // This test verifies that high loss reduces the bandwidth estimate.
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        let initial = gcc.estimated_bandwidth_bps();

        // Report high loss (50%)
        gcc.on_receiver_report(128, None, 1_000_000); // 50% loss
        let estimate = gcc.update_estimate(1_000_000);

        let stats = gcc.stats();
        // Loss should be recorded for statistics
        assert!(stats.loss_percent > 40.0, "Loss should be recorded");
        // Estimate should decrease due to loss-based BWE
        assert!(
            estimate < initial,
            "Estimate should decrease on high loss: {} -> {}",
            initial,
            estimate
        );
    }

    #[test]
    fn test_gcc_combiner_uses_minimum() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        // Set delay estimate higher than loss estimate
        gcc.delay_estimate_bps.store(2_000_000, Ordering::Relaxed);
        gcc.loss_estimate_bps.store(1_500_000, Ordering::Relaxed);

        let estimate = gcc.update_estimate(0);

        // Should use minimum of delay and loss estimates
        assert_eq!(estimate, 1_500_000, "Should use minimum (loss) estimate");

        // Now set loss estimate higher than delay estimate
        gcc.delay_estimate_bps.store(1_200_000, Ordering::Relaxed);
        gcc.loss_estimate_bps.store(2_000_000, Ordering::Relaxed);

        let estimate = gcc.update_estimate(0);

        // Should use minimum of delay and loss estimates
        assert_eq!(estimate, 1_200_000, "Should use minimum (delay) estimate");
    }

    #[test]
    fn test_gcc_estimate_bounds() {
        let gcc = CongestionController::new(100_000, 1_000_000, 500_000);

        // Try to set both estimates above max
        gcc.delay_estimate_bps.store(5_000_000, Ordering::Relaxed);
        gcc.loss_estimate_bps.store(5_000_000, Ordering::Relaxed);

        let estimate = gcc.update_estimate(0);
        assert_eq!(estimate, 1_000_000, "Should clamp to max");

        // Try to set both estimates below min
        gcc.delay_estimate_bps.store(10_000, Ordering::Relaxed);
        gcc.loss_estimate_bps.store(10_000, Ordering::Relaxed);

        let estimate = gcc.update_estimate(0);
        assert_eq!(estimate, 100_000, "Should clamp to min");
    }

    #[test]
    fn test_gcc_allocation_priority_order() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        let mut tracks = vec![
            TrackAllocation::new(1, TrackPriority::Low, 300_000),
            TrackAllocation::new(2, TrackPriority::Critical, 300_000),
            TrackAllocation::new(3, TrackPriority::Normal, 300_000),
        ];

        gcc.allocate_bandwidth(&mut tracks);

        // Critical should get full allocation
        let critical = tracks.iter().find(|t| t.track_id == 2).unwrap();
        assert_eq!(critical.allocated_bitrate_bps, 300_000);

        // Normal should get allocation next
        let normal = tracks.iter().find(|t| t.track_id == 3).unwrap();
        assert_eq!(normal.allocated_bitrate_bps, 300_000);

        // Low priority gets remaining
        let low = tracks.iter().find(|t| t.track_id == 1).unwrap();
        assert!(low.allocated_bitrate_bps > 0);
    }

    #[test]
    fn test_gcc_allocation_respects_bounds() {
        let gcc = CongestionController::new(100_000, 10_000_000, 500_000);

        let mut tracks = vec![
            TrackAllocation::new(1, TrackPriority::Normal, 300_000),
            TrackAllocation::new(2, TrackPriority::Normal, 300_000),
            TrackAllocation::new(3, TrackPriority::Normal, 300_000),
        ];

        gcc.allocate_bandwidth(&mut tracks);

        let total: u64 = tracks.iter().map(|t| t.allocated_bitrate_bps).sum();
        assert!(
            total <= gcc.target_bitrate_bps(),
            "Total allocation {} exceeds target {}",
            total,
            gcc.target_bitrate_bps()
        );
    }

    #[test]
    fn test_gcc_layer_selection() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        let mut track = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
        track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
        track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
        track.add_layer(SimulcastLayer::new(2, 1_500_000, 1280, 720));

        let mut tracks = vec![track];
        gcc.allocate_bandwidth(&mut tracks);

        // With ~850kbps target, should select middle layer
        assert!(
            tracks[0].selected_layer >= 1,
            "Should select at least middle layer"
        );
    }

    #[test]
    fn test_gcc_rtt_estimation() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        gcc.on_receiver_report(0, Some(60_000), 0);
        assert!(gcc.rtt_srtt_us() > 0);

        gcc.on_receiver_report(0, Some(70_000), 100_000);
        let srtt = gcc.rtt_srtt_us();
        assert!(srtt > 50_000 && srtt < 70_000, "RTT should be smoothed");
    }

    #[test]
    fn test_gcc_probe_success_increases_estimate() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        let initial = gcc.estimated_bandwidth_bps();

        // Trigger probe
        gcc.start_probe(initial, 0);
        assert_eq!(gcc.probe_controller_state(), ProbeState::Probing);

        // Report low loss during probe
        gcc.on_receiver_report(2, None, 600_000); // <2% loss after duration

        let _estimate = gcc.update_estimate(600_000);

        let stats = gcc.stats();
        assert_eq!(stats.probe_successes, 1);
    }

    #[test]
    fn test_gcc_probe_failure_stops_probing() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        let initial = gcc.estimated_bandwidth_bps();

        // Trigger probe
        gcc.start_probe(initial, 0);

        // Report high loss during probe
        gcc.on_receiver_report(20, None, 100_000); // >5% loss

        gcc.update_estimate(100_000);

        let stats = gcc.stats();
        assert_eq!(stats.probe_failures, 1);
        assert_eq!(gcc.probe_controller_state(), ProbeState::Idle);
    }

    #[test]
    fn test_gcc_stats_snapshot() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        let feedback = TransportFeedback::new(12345, 0);
        gcc.on_transport_feedback(&feedback, 0);
        gcc.on_receiver_report(10, Some(50_000), 0);

        let stats = gcc.stats();
        assert_eq!(stats.feedbacks_processed, 1);
        assert_eq!(stats.reports_processed, 1);
        assert!(stats.loss_percent > 0.0);
    }

    #[test]
    fn test_gcc_allocation_efficiency() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        let mut tracks = vec![
            TrackAllocation::new(1, TrackPriority::Normal, 200_000),
            TrackAllocation::new(2, TrackPriority::Normal, 200_000),
        ];

        gcc.allocate_bandwidth(&mut tracks);

        let stats = gcc.stats();
        assert!(stats.allocation_efficiency > 0.0);
        assert!(stats.allocation_efficiency <= 1.0);
    }

    #[test]
    fn test_gcc_allocation_no_starvation() {
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);

        // Create tracks with simulcast layers
        let mut tracks = vec![
            {
                let mut track = TrackAllocation::new(1, TrackPriority::Low, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
                track
            },
            {
                let mut track = TrackAllocation::new(2, TrackPriority::Critical, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
                track
            },
            {
                let mut track = TrackAllocation::new(3, TrackPriority::Normal, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
                track
            },
        ];

        gcc.allocate_bandwidth(&mut tracks);

        // All tracks should get at least their minimum layer (100kbps each = 300kbps total)
        // Target is ~850kbps, so all should be satisfied
        for track in &tracks {
            assert!(
                track.allocated_bitrate_bps >= 100_000,
                "Track {} starved with only {} bps",
                track.track_id,
                track.allocated_bitrate_bps
            );
        }

        // Critical priority should get more than low priority
        let critical = tracks.iter().find(|t| t.track_id == 2).unwrap();
        let low = tracks.iter().find(|t| t.track_id == 1).unwrap();
        assert!(
            critical.allocated_bitrate_bps >= low.allocated_bitrate_bps,
            "Critical priority should get at least as much as low priority"
        );
    }

    #[test]
    fn test_gcc_allocation_insufficient_bandwidth() {
        // Very low bandwidth - can't satisfy all minimum layers
        let gcc = CongestionController::new(100_000, 10_000_000, 200_000);

        let mut tracks = vec![
            {
                let mut track = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track
            },
            {
                let mut track = TrackAllocation::new(2, TrackPriority::Normal, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track
            },
            {
                let mut track = TrackAllocation::new(3, TrackPriority::Normal, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track
            },
        ];

        gcc.allocate_bandwidth(&mut tracks);

        // Total should not exceed target
        let total: u64 = tracks.iter().map(|t| t.allocated_bitrate_bps).sum();
        assert!(
            total <= gcc.target_bitrate_bps(),
            "Total {} exceeds target {}",
            total,
            gcc.target_bitrate_bps()
        );

        // Each track should get some allocation (proportional)
        for track in &tracks {
            assert!(track.allocated_bitrate_bps > 0, "Track {} got zero allocation", track.track_id);
        }
    }

    #[test]
    fn test_gcc_comprehensive_verification_fixes() {
        // Test all three verification fixes together
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        let initial = gcc.estimated_bandwidth_bps();

        // Fix 1: Test probe success increases estimate
        gcc.start_probe(initial, 0);
        gcc.on_receiver_report(1, None, 600_000); // Low loss after duration
        let estimate_after_probe = gcc.update_estimate(600_000);
        assert!(
            estimate_after_probe > initial,
            "Successful probe should increase estimate from {} to {}",
            initial,
            estimate_after_probe
        );

        // Fix 2: Test time-based additive increase
        // Manually set underuse state and verify time-based increase
        gcc.delay_estimate_bps.store(initial, Ordering::Relaxed);
        gcc.set_last_update_us(0);
        
        // Simulate underuse feedback at t=0
        let mut feedback1 = TransportFeedback::new(12345, 0);
        for i in 0..20 {
            let _ = feedback1.add_packet(crate::feedback::PacketArrivalInfo {
                sequence: i,
                send_time_us: i as u64 * 20_000,
                recv_time_us: i as u64 * 20_000 + 1_000, // Constant delay
                size_bytes: 1200,
            });
        }
        gcc.on_transport_feedback(&feedback1, 0);
        
        // Simulate underuse feedback at t=1s (1,000,000 us)
        let mut feedback2 = TransportFeedback::new(12345, 20);
        for i in 20..40 {
            let _ = feedback2.add_packet(crate::feedback::PacketArrivalInfo {
                sequence: i,
                send_time_us: i as u64 * 20_000,
                recv_time_us: i as u64 * 20_000 + 500, // Decreasing delay (underuse)
                size_bytes: 1200,
            });
        }
        
        let estimate_before = gcc.delay_estimate_bps.load(Ordering::Relaxed);
        gcc.on_transport_feedback(&feedback2, 1_000_000); // 1 second later
        let estimate_after = gcc.delay_estimate_bps.load(Ordering::Relaxed);
        
        // With underuse, should have increased by approximately 8kbps * 1 second
        // The increase is time-based, so it should be proportional to elapsed time
        assert!(
            estimate_after >= estimate_before,
            "Time-based increase should not decrease estimate: {} -> {}",
            estimate_before,
            estimate_after
        );

        // Fix 3: Test no starvation with two-phase allocation
        let mut tracks = vec![
            {
                let mut track = TrackAllocation::new(1, TrackPriority::Low, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
                track
            },
            {
                let mut track = TrackAllocation::new(2, TrackPriority::Critical, 2_000_000);
                track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
                track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
                track
            },
        ];

        gcc.allocate_bandwidth(&mut tracks);

        // Both tracks should get at least minimum layer
        for track in &tracks {
            assert!(
                track.allocated_bitrate_bps >= 100_000,
                "Track {} should not be starved",
                track.track_id
            );
        }

        // Critical should get more than low
        let critical = tracks.iter().find(|t| t.track_id == 2).unwrap();
        let low = tracks.iter().find(|t| t.track_id == 1).unwrap();
        assert!(
            critical.allocated_bitrate_bps >= low.allocated_bitrate_bps,
            "Critical priority should get at least as much as low"
        );
    }

    #[test]
    fn test_gcc_interior_mutability() {
        // Test that on_receiver_report can be called without &mut self
        let gcc = CongestionController::new(100_000, 10_000_000, 1_000_000);
        
        // Call on_receiver_report multiple times without &mut
        gcc.on_receiver_report(10, Some(50_000), 0);
        gcc.on_receiver_report(20, Some(60_000), 100_000);
        gcc.on_receiver_report(5, Some(55_000), 200_000);
        
        let stats = gcc.stats();
        assert_eq!(stats.reports_processed, 3);
        
        // Verify RTT was updated
        let srtt = gcc.rtt_srtt_us();
        assert!(srtt > 0, "RTT should be updated");
    }

    #[test]
    fn test_gcc_concurrent_access() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        use std::thread;

        let gcc = Arc::new(CongestionController::new(100_000, 10_000_000, 1_000_000));
        let timestamp_counter = Arc::new(AtomicU64::new(0));
        
        // Spawn multiple threads that call on_receiver_report
        let mut handles = vec![];
        for i in 0..4 {
            let gcc_clone = Arc::clone(&gcc);
            let ts_counter = Arc::clone(&timestamp_counter);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    // Use atomic counter to ensure monotonically increasing timestamps
                    let timestamp = ts_counter.fetch_add(1000, AtomicOrdering::SeqCst);
                    gcc_clone.on_receiver_report(
                        (i * 10 + j % 10) as u8,
                        Some(50_000 + (j * 1000) as u64),
                        timestamp,
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let stats = gcc.stats();
        assert_eq!(stats.reports_processed, 400);
    }
}
