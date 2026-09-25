//! Tiered spin loop for packet processing.
//!
//! Uses three tiers to balance latency vs. CPU usage:
//! 1. `spin_loop()` hint (PAUSE/YIELD) for first N idle polls — sub-μs wake
//! 2. `thread::yield_now()` for moderate idle — gives OS a chance to schedule
//! 3. `thread::sleep(1μs)` for sustained idle — saves CPU under no load

/// Spin tier thresholds.
const SPIN_TIER1_THRESHOLD: u64 = 1024; // Pure spin for first 1K polls
const SPIN_TIER2_THRESHOLD: u64 = 65_536; // yield_now up to 64K polls

/// Tiered spin loop with backoff.
pub struct SpinLoop {
    /// Consecutive empty polls.
    empty_polls: u64,
}

impl Default for SpinLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl SpinLoop {
    #[inline]
    pub fn new() -> Self {
        Self { empty_polls: 0 }
    }

    /// Call after each poll. Resets counter on activity, backs off on idle.
    #[inline]
    pub fn on_poll_result(&mut self, packets: u32) {
        if packets > 0 {
            self.empty_polls = 0;
        } else {
            self.empty_polls = self.empty_polls.saturating_add(1);
            if self.empty_polls < SPIN_TIER1_THRESHOLD {
                std::hint::spin_loop();
            } else if self.empty_polls < SPIN_TIER2_THRESHOLD {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(1));
            }
        }
    }

    #[inline]
    pub fn empty_polls(&self) -> u64 {
        self.empty_polls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resets_on_activity() {
        let mut s = SpinLoop::new();
        s.on_poll_result(0);
        s.on_poll_result(0);
        assert_eq!(s.empty_polls(), 2);
        s.on_poll_result(1);
        assert_eq!(s.empty_polls(), 0);
    }

    #[test]
    fn test_tiered_backoff_thresholds() {
        let mut s = SpinLoop::new();
        // Stays in tier 1 (spin) up to threshold
        for _ in 0..SPIN_TIER1_THRESHOLD {
            s.on_poll_result(0);
        }
        assert_eq!(s.empty_polls(), SPIN_TIER1_THRESHOLD);
        // Resets on activity
        s.on_poll_result(1);
        assert_eq!(s.empty_polls(), 0);
    }
}
