//! Pure spin loop for packet processing.
//!
//! Uses `std::hint::spin_loop()` (PAUSE on x86, YIELD on ARM) to
//! busy-wait with minimal power draw. No yielding, no sleeping —
//! the architecture demands deterministic sub-microsecond wake.

/// Pure spin loop. Calls `std::hint::spin_loop()` on idle iterations.
pub struct SpinLoop {
    /// Consecutive empty polls (diagnostic only).
    empty_polls: u64,
}

impl SpinLoop {
    #[inline]
    pub fn new() -> Self {
        Self { empty_polls: 0 }
    }

    /// Call after each poll. Resets counter on activity, spins on idle.
    #[inline]
    pub fn on_poll_result(&mut self, packets: u32) {
        if packets > 0 {
            self.empty_polls = 0;
        } else {
            self.empty_polls = self.empty_polls.saturating_add(1);
            std::hint::spin_loop();
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
}
