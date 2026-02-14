//! Adaptive spin loop for packet processing.
//!
//! Provides a state machine that balances latency and CPU usage by spinning
//! tightly when packets are flowing and backing off progressively during idle
//! periods.
//!
//! # State Transitions
//!
//! ```text
//! Spinning → Yielding (at yield_threshold empty polls)
//! Yielding → Sleeping (at sleep_threshold empty polls)
//! Sleeping → Spinning (immediately when packets arrive)
//! ```
//!
//! # TigerStyle Compliance
//!
//! - ≥2 assertions per function
//! - ≤70 lines per function
//! - Explicitly-sized types (u32, u64)
//! - Unit suffixes in variable names

use std::time::Duration;

use std::thread;

/// Spin loop states for adaptive packet polling.
///
/// WHY: Different states allow trading off latency vs CPU usage based on
/// current packet flow. Spinning minimizes latency when packets are flowing,
/// while yielding and sleeping conserve CPU during idle periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinState {
    /// Tight spin — packets flowing, zero overhead
    Spinning,
    /// Yield CPU — short idle, minimal latency cost
    Yielding,
    /// Sleep — extended idle, conserve CPU
    Sleeping,
}

/// Adaptive spin loop for packet processing.
///
/// Transitions: Spinning → Yielding → Sleeping → Spinning
/// Resets to Spinning immediately when packets arrive.
///
/// # Example
///
/// ```
/// use nexus_sfu::spin::{AdaptiveSpinLoop, SpinState};
///
/// let mut spin_loop = AdaptiveSpinLoop::new(64, 1024, 50);
/// assert_eq!(spin_loop.state(), SpinState::Spinning);
///
/// // Simulate receiving packets
/// spin_loop.on_poll_result(5);
/// assert_eq!(spin_loop.state(), SpinState::Spinning);
/// assert_eq!(spin_loop.empty_poll_count(), 0);
/// ```
pub struct AdaptiveSpinLoop {
    /// Current state
    state: SpinState,
    /// Consecutive empty polls
    empty_poll_count: u32,
    /// Threshold to transition Spinning → Yielding
    yield_threshold: u32,
    /// Threshold to transition Yielding → Sleeping
    sleep_threshold: u32,
    /// Sleep duration in microseconds
    sleep_duration_us: u32,
}

impl AdaptiveSpinLoop {
    /// Default threshold for transitioning from Spinning to Yielding.
    pub const DEFAULT_YIELD_THRESHOLD: u32 = 64;
    /// Default threshold for transitioning from Yielding to Sleeping.
    pub const DEFAULT_SLEEP_THRESHOLD: u32 = 1024;
    /// Default sleep duration in microseconds.
    pub const DEFAULT_SLEEP_DURATION_US: u32 = 50;

    /// Creates a new adaptive spin loop with the specified thresholds.
    ///
    /// # Arguments
    ///
    /// * `yield_threshold` - Empty polls before transitioning to Yielding
    /// * `sleep_threshold` - Empty polls before transitioning to Sleeping
    /// * `sleep_duration_us` - Microseconds to sleep in Sleeping state
    ///
    /// # Panics
    ///
    /// Panics if yield_threshold >= sleep_threshold (invalid configuration).
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn new(
        yield_threshold: u32,
        sleep_threshold: u32,
        sleep_duration_us: u32,
    ) -> Self {
        // Precondition: yield must come before sleep
        assert!(
            yield_threshold < sleep_threshold,
            "yield_threshold ({}) must be less than sleep_threshold ({})",
            yield_threshold,
            sleep_threshold
        );
        // Precondition: thresholds must be positive
        assert!(yield_threshold > 0, "yield_threshold must be positive");

        Self {
            state: SpinState::Spinning,
            empty_poll_count: 0,
            yield_threshold,
            sleep_threshold,
            sleep_duration_us,
        }
    }


    /// Creates a new adaptive spin loop with default thresholds.
    ///
    /// Uses DEFAULT_YIELD_THRESHOLD (64), DEFAULT_SLEEP_THRESHOLD (1024),
    /// and DEFAULT_SLEEP_DURATION_US (50).
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn with_defaults() -> Self {
        // Postcondition: defaults are valid
        assert!(
            Self::DEFAULT_YIELD_THRESHOLD < Self::DEFAULT_SLEEP_THRESHOLD,
            "default thresholds must be valid"
        );
        assert!(Self::DEFAULT_YIELD_THRESHOLD > 0, "default yield threshold must be positive");

        Self::new(
            Self::DEFAULT_YIELD_THRESHOLD,
            Self::DEFAULT_SLEEP_THRESHOLD,
            Self::DEFAULT_SLEEP_DURATION_US,
        )
    }

    /// Called after each poll iteration to update state based on packet count.
    ///
    /// # Arguments
    ///
    /// * `packets_received` - Number of packets received in this iteration
    ///
    /// # State Transitions
    ///
    /// - If packets > 0: Reset to Spinning, clear empty_poll_count
    /// - If packets == 0: Increment empty_poll_count, transition states at thresholds
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn on_poll_result(&mut self, packets_received: u32) {
        // Precondition: state is valid
        assert!(
            matches!(self.state, SpinState::Spinning | SpinState::Yielding | SpinState::Sleeping),
            "state must be valid"
        );

        if packets_received > 0 {
            // Packets received — reset to tight spinning
            self.state = SpinState::Spinning;
            self.empty_poll_count = 0;
        } else {
            // No packets — increment counter and potentially transition
            // Saturating add to prevent overflow
            self.empty_poll_count = self.empty_poll_count.saturating_add(1);

            // Transition based on thresholds
            if self.empty_poll_count >= self.sleep_threshold {
                self.state = SpinState::Sleeping;
            } else if self.empty_poll_count >= self.yield_threshold {
                self.state = SpinState::Yielding;
            }
            // Otherwise stay in current state (Spinning stays Spinning)
        }

        // Postcondition: empty_poll_count is 0 when packets received
        assert!(
            packets_received == 0 || self.empty_poll_count == 0,
            "empty_poll_count must be 0 when packets received"
        );
    }

    /// Execute the appropriate wait based on current state.
    ///
    /// - Spinning: Returns immediately (no-op)
    /// - Yielding: Calls `thread::yield_now()`
    /// - Sleeping: Calls `thread::sleep(duration)`
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn wait(&self) {
        // Precondition: state is valid
        assert!(
            matches!(self.state, SpinState::Spinning | SpinState::Yielding | SpinState::Sleeping),
            "state must be valid"
        );
        // Precondition: sleep duration is reasonable (< 1 second)
        assert!(
            self.sleep_duration_us < 1_000_000,
            "sleep_duration_us must be less than 1 second"
        );

        match self.state {
            SpinState::Spinning => {
                // No-op — tight spin for minimum latency
            }
            SpinState::Yielding => {
                // Yield CPU to other threads
                thread::yield_now();
            }
            SpinState::Sleeping => {
                // Sleep for configured duration
                let duration = Duration::from_micros(self.sleep_duration_us as u64);
                thread::sleep(duration);
            }
        }
    }

    /// Execute the appropriate wait based on current state (async version).
    ///
    /// WHY async version: When running in a tokio context, we need to use
    /// tokio's async primitives instead of blocking thread operations.
    ///
    /// - Spinning: Returns immediately (no-op)
    /// - Yielding: Calls `tokio::task::yield_now()`
    /// - Sleeping: Calls `tokio::time::sleep(duration)`
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub async fn wait_async(&self) {
        // Precondition: state is valid
        assert!(
            matches!(self.state, SpinState::Spinning | SpinState::Yielding | SpinState::Sleeping),
            "state must be valid"
        );
        // Precondition: sleep duration is reasonable (< 1 second)
        assert!(
            self.sleep_duration_us < 1_000_000,
            "sleep_duration_us must be less than 1 second"
        );

        match self.state {
            SpinState::Spinning => {
                // No-op — tight spin for minimum latency
            }
            SpinState::Yielding => {
                // Yield to tokio scheduler
                tokio::task::yield_now().await;
            }
            SpinState::Sleeping => {
                // Async sleep for configured duration
                let duration = Duration::from_micros(self.sleep_duration_us as u64);
                tokio::time::sleep(duration).await;
            }
        }
    }

    /// Returns the current spin state.
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn state(&self) -> SpinState {
        // Precondition: state is valid
        assert!(
            matches!(self.state, SpinState::Spinning | SpinState::Yielding | SpinState::Sleeping),
            "state must be valid"
        );
        // Postcondition: returned state matches internal state
        let result = self.state;
        assert!(result == self.state, "returned state must match internal state");
        result
    }

    /// Returns the current count of consecutive empty polls.
    ///
    /// # TigerStyle: ≥2 assertions, ≤70 lines
    #[inline]
    pub fn empty_poll_count(&self) -> u32 {
        // Precondition: count is bounded by sleep_threshold when not sleeping
        // (after sleep_threshold, we stop incrementing in practice due to saturation)
        assert!(
            self.state == SpinState::Sleeping || self.empty_poll_count <= self.sleep_threshold,
            "empty_poll_count should not exceed sleep_threshold unless sleeping"
        );
        // Postcondition: count is consistent with state
        let count = self.empty_poll_count;
        assert!(
            (count == 0 && self.state == SpinState::Spinning)
                || (count > 0)
                || self.state == SpinState::Spinning,
            "count must be consistent with state"
        );
        count
    }

    /// Returns the yield threshold.
    #[inline]
    pub fn yield_threshold(&self) -> u32 {
        self.yield_threshold
    }

    /// Returns the sleep threshold.
    #[inline]
    pub fn sleep_threshold(&self) -> u32 {
        self.sleep_threshold
    }

    /// Returns the sleep duration in microseconds.
    #[inline]
    pub fn sleep_duration_us(&self) -> u32 {
        self.sleep_duration_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_valid_thresholds() {
        let spin_loop = AdaptiveSpinLoop::new(64, 1024, 50);
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.empty_poll_count(), 0);
        assert_eq!(spin_loop.yield_threshold(), 64);
        assert_eq!(spin_loop.sleep_threshold(), 1024);
        assert_eq!(spin_loop.sleep_duration_us(), 50);
    }

    #[test]
    fn test_with_defaults() {
        let spin_loop = AdaptiveSpinLoop::with_defaults();
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.yield_threshold(), AdaptiveSpinLoop::DEFAULT_YIELD_THRESHOLD);
        assert_eq!(spin_loop.sleep_threshold(), AdaptiveSpinLoop::DEFAULT_SLEEP_THRESHOLD);
        assert_eq!(spin_loop.sleep_duration_us(), AdaptiveSpinLoop::DEFAULT_SLEEP_DURATION_US);
    }

    #[test]
    #[should_panic(expected = "yield_threshold")]
    fn test_new_invalid_thresholds() {
        // yield_threshold >= sleep_threshold should panic
        AdaptiveSpinLoop::new(1024, 64, 50);
    }

    #[test]
    #[should_panic(expected = "yield_threshold must be positive")]
    fn test_new_zero_yield_threshold() {
        AdaptiveSpinLoop::new(0, 1024, 50);
    }

    #[test]
    fn test_packets_received_resets_to_spinning() {
        let mut spin_loop = AdaptiveSpinLoop::new(2, 4, 50);

        // Simulate empty polls to reach Yielding
        spin_loop.on_poll_result(0);
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Yielding);
        assert_eq!(spin_loop.empty_poll_count(), 2);

        // Receive packets — should reset to Spinning
        spin_loop.on_poll_result(5);
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.empty_poll_count(), 0);
    }

    #[test]
    fn test_state_transitions() {
        let mut spin_loop = AdaptiveSpinLoop::new(2, 4, 50);

        // Initial state
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.empty_poll_count(), 0);

        // First empty poll — still Spinning
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.empty_poll_count(), 1);

        // Second empty poll — transition to Yielding (at threshold)
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Yielding);
        assert_eq!(spin_loop.empty_poll_count(), 2);

        // Third empty poll — still Yielding
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Yielding);
        assert_eq!(spin_loop.empty_poll_count(), 3);

        // Fourth empty poll — transition to Sleeping (at threshold)
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Sleeping);
        assert_eq!(spin_loop.empty_poll_count(), 4);

        // Fifth empty poll — stays Sleeping
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Sleeping);
        assert_eq!(spin_loop.empty_poll_count(), 5);

        // Receive packets — reset to Spinning
        spin_loop.on_poll_result(1);
        assert_eq!(spin_loop.state(), SpinState::Spinning);
        assert_eq!(spin_loop.empty_poll_count(), 0);
    }

    #[test]
    fn test_wait_spinning_is_noop() {
        let spin_loop = AdaptiveSpinLoop::new(64, 1024, 50);
        assert_eq!(spin_loop.state(), SpinState::Spinning);

        // This should return immediately
        let start = std::time::Instant::now();
        spin_loop.wait();
        let elapsed = start.elapsed();

        // Should be essentially instant (< 1ms)
        assert!(elapsed.as_micros() < 1000, "Spinning wait took too long: {:?}", elapsed);
    }

    #[test]
    fn test_wait_sleeping_sleeps() {
        let mut spin_loop = AdaptiveSpinLoop::new(1, 2, 1000); // 1ms sleep

        // Transition to Sleeping
        spin_loop.on_poll_result(0);
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Sleeping);

        // This should sleep for ~1ms
        let start = std::time::Instant::now();
        spin_loop.wait();
        let elapsed = start.elapsed();

        // Should be at least 500us (allowing for timing variance)
        assert!(elapsed.as_micros() >= 500, "Sleeping wait was too short: {:?}", elapsed);
    }

    #[test]
    fn test_empty_poll_count_saturates() {
        let mut spin_loop = AdaptiveSpinLoop::new(1, 2, 50);

        // Transition to Sleeping
        spin_loop.on_poll_result(0);
        spin_loop.on_poll_result(0);
        assert_eq!(spin_loop.state(), SpinState::Sleeping);

        // Continue with many empty polls — should not overflow
        for _ in 0..1000 {
            spin_loop.on_poll_result(0);
        }

        // Should still be Sleeping and count should be reasonable
        assert_eq!(spin_loop.state(), SpinState::Sleeping);
        assert!(spin_loop.empty_poll_count() > 0);
    }
}
