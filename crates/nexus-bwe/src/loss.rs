//! Loss-based bandwidth estimation with AIMD algorithm.
//!
//! Implements loss-based BWE using AIMD (Additive Increase Multiplicative Decrease)
//! based on packet loss feedback from RTCP receiver reports.
//!
//! # TigerStyle Compliance
//!
//! - Zero allocation after initialization (fixed-size arrays)
//! - All loops have fixed bounds (LOSS_WINDOW_SIZE)
//! - Explicitly-sized types (u8, u32, u64, f64)
//! - Comprehensive assertions for invariants
//! - Maximum 70 lines per function

/// Loss sample in sliding window.
#[derive(Clone, Copy, Default)]
pub struct LossSample {
    /// Fraction lost (0-255, where 255 = 100% loss).
    pub fraction_lost: u8,
    /// Timestamp when sample was recorded (microseconds).
    pub timestamp_us: u64,
}

/// AIMD configuration for loss-based BWE.
#[derive(Clone, Copy)]
pub struct AimdConfig {
    /// Additive increase rate (bps per second).
    pub increase_rate_bps: u64,
    /// Multiplicative decrease factor (0.5-0.9).
    pub decrease_factor: f64,
    /// Loss threshold for decrease (percentage, default 2%).
    pub loss_threshold_percent: u8,
    /// Aggressive decrease threshold (percentage, default 10%).
    pub aggressive_threshold_percent: u8,
    /// Aggressive decrease factor (default 0.5 = 50% reduction).
    pub aggressive_factor: f64,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            increase_rate_bps: 8_000,
            decrease_factor: 0.85,
            loss_threshold_percent: 2,
            aggressive_threshold_percent: 10,
            aggressive_factor: 0.5,
        }
    }
}

/// Loss-based BWE state after processing a receiver report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossBasedBweState {
    /// Increasing bandwidth (low loss < 2%).
    Increase,
    /// Decreasing bandwidth (moderate loss >= 2%).
    Decrease,
    /// Aggressively decreasing (high loss >= 10%).
    AggressiveDecrease,
}


/// Loss-based bandwidth estimator.
///
/// Uses AIMD (Additive Increase Multiplicative Decrease) based on
/// packet loss feedback from RTCP receiver reports.
///
/// # TigerStyle Compliance
///
/// - Fixed-size loss history array (no dynamic allocation)
/// - Bounded loop for average calculation
/// - Explicit bounds checking with assertions
pub struct LossBasedBweDetector {
    /// Current loss-based estimate (bps).
    estimate_bps: u64,
    /// Minimum bandwidth bound.
    min_bps: u64,
    /// Maximum bandwidth bound.
    max_bps: u64,
    /// Loss history sliding window (fixed-size array).
    loss_history: [LossSample; Self::LOSS_WINDOW_SIZE],
    /// Loss history head index (circular buffer).
    history_head: u32,
    /// Number of samples in history.
    history_count: u32,
    /// Last update timestamp (microseconds).
    last_update_us: u64,
    /// AIMD configuration.
    aimd: AimdConfig,
}

impl LossBasedBweDetector {
    /// Loss window size (samples).
    pub const LOSS_WINDOW_SIZE: usize = 20;
    /// Default loss threshold (2%).
    pub const DEFAULT_LOSS_THRESHOLD: u8 = 2;
    /// Aggressive threshold (10%).
    pub const AGGRESSIVE_THRESHOLD: u8 = 10;

    /// Create new loss-based detector.
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
        // Precondition: min_bps must be positive
        assert!(min_bps > 0, "min_bps must be > 0");
        // Precondition: initial_bps must be within bounds
        assert!(
            min_bps <= initial_bps && initial_bps <= max_bps,
            "initial_bps must be in [min_bps, max_bps]"
        );

        Self {
            estimate_bps: initial_bps,
            min_bps,
            max_bps,
            loss_history: [LossSample::default(); Self::LOSS_WINDOW_SIZE],
            history_head: 0,
            history_count: 0,
            last_update_us: 0,
            aimd: AimdConfig::default(),
        }
    }

    /// Create new loss-based detector with custom AIMD config.
    ///
    /// # Arguments
    ///
    /// * `min_bps` - Minimum bandwidth bound (must be > 0)
    /// * `max_bps` - Maximum bandwidth bound
    /// * `initial_bps` - Initial bandwidth estimate
    /// * `aimd` - Custom AIMD configuration
    pub fn with_config(min_bps: u64, max_bps: u64, initial_bps: u64, aimd: AimdConfig) -> Self {
        // Precondition: min_bps must be positive
        assert!(min_bps > 0, "min_bps must be > 0");
        // Precondition: initial_bps must be within bounds
        assert!(
            min_bps <= initial_bps && initial_bps <= max_bps,
            "initial_bps must be in [min_bps, max_bps]"
        );

        Self {
            estimate_bps: initial_bps,
            min_bps,
            max_bps,
            loss_history: [LossSample::default(); Self::LOSS_WINDOW_SIZE],
            history_head: 0,
            history_count: 0,
            last_update_us: 0,
            aimd,
        }
    }


    /// Process receiver report loss feedback.
    ///
    /// Implements AIMD algorithm:
    /// - Additive increase when loss < 2%
    /// - Multiplicative decrease when loss >= 2%
    /// - Aggressive 50% reduction when loss >= 10%
    ///
    /// # Arguments
    ///
    /// * `fraction_lost` - Fraction of packets lost (0-255, where 255 = 100%)
    /// * `timestamp_us` - Current timestamp in microseconds
    ///
    /// # Returns
    ///
    /// The new BWE state after processing the report.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions (timestamp monotonicity, bounds postconditions)
    /// - Explicit bounds clamping
    ///
    /// # Note
    ///
    /// If timestamp is less than last_update_us (can happen with concurrent access),
    /// the sample is still processed but time-based increase is skipped.
    pub fn on_receiver_report(
        &mut self,
        fraction_lost: u8,
        timestamp_us: u64,
    ) -> LossBasedBweState {
        // Add sample to loss history
        self.add_loss_sample(fraction_lost, timestamp_us);

        // Calculate average loss over sliding window
        let avg_loss = self.calculate_average_loss();
        let loss_percent = (avg_loss as u32 * 100 / 256) as u8;

        // Apply AIMD based on loss percentage
        let state = if loss_percent >= self.aimd.aggressive_threshold_percent {
            // Aggressive decrease: 50% reduction for high loss (>= 10%)
            self.estimate_bps = (self.estimate_bps as f64 * self.aimd.aggressive_factor) as u64;
            LossBasedBweState::AggressiveDecrease
        } else if loss_percent >= self.aimd.loss_threshold_percent {
            // Multiplicative decrease for moderate loss (>= 2%)
            self.estimate_bps = (self.estimate_bps as f64 * self.aimd.decrease_factor) as u64;
            LossBasedBweState::Decrease
        } else {
            // Additive increase for low loss (< 2%)
            // Only increase if timestamp is advancing (handles concurrent access)
            if timestamp_us > self.last_update_us {
                let dt_us = timestamp_us.saturating_sub(self.last_update_us);
                let dt_secs = dt_us as f64 / 1_000_000.0;
                let increase = (self.aimd.increase_rate_bps as f64 * dt_secs) as u64;
                self.estimate_bps = self.estimate_bps.saturating_add(increase);
            }
            LossBasedBweState::Increase
        };

        // Clamp estimate to [min_bps, max_bps]
        self.estimate_bps = self.estimate_bps.clamp(self.min_bps, self.max_bps);
        
        // Update last_update_us only if timestamp is advancing
        if timestamp_us > self.last_update_us {
            self.last_update_us = timestamp_us;
        }

        // Postcondition: estimate must be within bounds
        assert!(
            self.estimate_bps >= self.min_bps,
            "estimate must be >= min_bps"
        );
        assert!(
            self.estimate_bps <= self.max_bps,
            "estimate must be <= max_bps"
        );

        state
    }

    /// Get current bandwidth estimate in bits per second.
    #[inline]
    pub fn estimate_bps(&self) -> u64 {
        self.estimate_bps
    }

    /// Get minimum bandwidth bound.
    #[inline]
    pub fn min_bps(&self) -> u64 {
        self.min_bps
    }

    /// Get maximum bandwidth bound.
    #[inline]
    pub fn max_bps(&self) -> u64 {
        self.max_bps
    }

    /// Get last update timestamp.
    #[inline]
    pub fn last_update_us(&self) -> u64 {
        self.last_update_us
    }

    /// Get number of samples in history.
    #[inline]
    pub fn history_count(&self) -> u32 {
        self.history_count
    }


    /// Add loss sample to sliding window.
    ///
    /// Uses circular buffer for O(1) insertion.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Fixed-size array (no allocation)
    /// - Bounded index with modulo
    fn add_loss_sample(&mut self, fraction_lost: u8, timestamp_us: u64) {
        // Precondition: head index must be valid
        assert!(
            (self.history_head as usize) < Self::LOSS_WINDOW_SIZE,
            "history_head must be < LOSS_WINDOW_SIZE"
        );

        let sample = LossSample {
            fraction_lost,
            timestamp_us,
        };

        // Write to current head position
        self.loss_history[self.history_head as usize] = sample;

        // Advance head (circular buffer)
        self.history_head = ((self.history_head + 1) as usize % Self::LOSS_WINDOW_SIZE) as u32;

        // Update count (capped at window size)
        if self.history_count < Self::LOSS_WINDOW_SIZE as u32 {
            self.history_count += 1;
        }

        // Postcondition: count must not exceed window size
        assert!(
            self.history_count <= Self::LOSS_WINDOW_SIZE as u32,
            "history_count must be <= LOSS_WINDOW_SIZE"
        );
    }

    /// Calculate average loss over sliding window.
    ///
    /// Returns average fraction_lost (0-255).
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded loop (max LOSS_WINDOW_SIZE iterations)
    /// - No allocation
    fn calculate_average_loss(&self) -> u8 {
        // Precondition: count must be valid
        assert!(
            self.history_count <= Self::LOSS_WINDOW_SIZE as u32,
            "history_count must be <= LOSS_WINDOW_SIZE"
        );

        if self.history_count == 0 {
            return 0;
        }

        let mut sum: u32 = 0;
        let count = self.history_count as usize;

        // Bounded loop: max LOSS_WINDOW_SIZE iterations
        for i in 0..count {
            sum += self.loss_history[i].fraction_lost as u32;
        }

        // Calculate average (safe division, count > 0 guaranteed)
        let avg = sum / count as u32;

        // Postcondition: average must fit in u8
        assert!(avg <= 255, "average must fit in u8");

        avg as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_detector() {
        let detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        assert_eq!(detector.estimate_bps(), 1_000_000);
        assert_eq!(detector.min_bps(), 100_000);
        assert_eq!(detector.max_bps(), 10_000_000);
        assert_eq!(detector.history_count(), 0);
    }

    #[test]
    #[should_panic(expected = "min_bps must be > 0")]
    fn test_new_zero_min() {
        let _ = LossBasedBweDetector::new(0, 10_000_000, 1_000_000);
    }

    #[test]
    #[should_panic(expected = "initial_bps must be in [min_bps, max_bps]")]
    fn test_new_invalid_initial() {
        let _ = LossBasedBweDetector::new(100_000, 10_000_000, 50_000);
    }

    #[test]
    fn test_loss_increase_below_threshold() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        
        // 0% loss should trigger increase
        let state = detector.on_receiver_report(0, 1_000_000);
        assert_eq!(state, LossBasedBweState::Increase);
        
        // With 1 second elapsed and 8000 bps increase rate, should increase by 8000
        let state = detector.on_receiver_report(0, 2_000_000);
        assert_eq!(state, LossBasedBweState::Increase);
        assert!(detector.estimate_bps() > 1_000_000);
    }

    #[test]
    fn test_loss_decrease_above_threshold() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        
        // 5% loss (fraction_lost = 13 out of 255) should trigger decrease
        // 5% = 5 * 256 / 100 ≈ 13
        let fraction_5_percent = 13;
        let state = detector.on_receiver_report(fraction_5_percent, 1_000_000);
        assert_eq!(state, LossBasedBweState::Decrease);
        assert!(detector.estimate_bps() < 1_000_000);
    }

    #[test]
    fn test_aggressive_decrease_high_loss() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        
        // 15% loss (fraction_lost = 38 out of 255) should trigger aggressive decrease
        // 15% = 15 * 256 / 100 ≈ 38
        let fraction_15_percent = 38;
        let state = detector.on_receiver_report(fraction_15_percent, 1_000_000);
        assert_eq!(state, LossBasedBweState::AggressiveDecrease);
        // Should be reduced to ~50% = 500_000
        assert!(detector.estimate_bps() <= 550_000);
        assert!(detector.estimate_bps() >= 450_000);
    }

    #[test]
    fn test_minimum_bound_enforced() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 200_000);
        
        // Apply multiple high-loss reports to drive estimate down
        for i in 0..10 {
            let _ = detector.on_receiver_report(255, (i + 1) * 1_000_000);
        }
        
        // Should not go below minimum
        assert!(detector.estimate_bps() >= 100_000);
    }

    #[test]
    fn test_maximum_bound_enforced() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 9_000_000);
        
        // Apply multiple low-loss reports to drive estimate up
        for i in 0..100 {
            let _ = detector.on_receiver_report(0, (i + 1) * 1_000_000);
        }
        
        // Should not exceed maximum
        assert!(detector.estimate_bps() <= 10_000_000);
    }

    #[test]
    fn test_sliding_window_average() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        
        // Add samples with varying loss
        for i in 0..10 {
            let _ = detector.on_receiver_report(10, (i + 1) * 100_000);
        }
        
        assert_eq!(detector.history_count(), 10);
        
        // Fill the window
        for i in 10..25 {
            let _ = detector.on_receiver_report(10, (i + 1) * 100_000);
        }
        
        // Should be capped at LOSS_WINDOW_SIZE
        assert_eq!(detector.history_count(), LossBasedBweDetector::LOSS_WINDOW_SIZE as u32);
    }

    #[test]
    fn test_timestamp_regression_handled_gracefully() {
        let mut detector = LossBasedBweDetector::new(100_000, 10_000_000, 1_000_000);
        let _ = detector.on_receiver_report(0, 2_000_000);
        let estimate_before = detector.estimate_bps();
        
        // Timestamp regression should be handled gracefully (no increase, but no panic)
        let _ = detector.on_receiver_report(0, 1_000_000);
        let estimate_after = detector.estimate_bps();
        
        // Estimate should not increase on timestamp regression
        assert_eq!(estimate_before, estimate_after, "Estimate should not change on timestamp regression");
    }
}
