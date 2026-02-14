/// A deterministic virtual clock that advances only when explicitly ticked.
/// No wall-clock time is ever read. Provides nanosecond-precision timestamps.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    now_ns: u64,
}

impl VirtualClock {
    /// Create a new virtual clock starting at time zero.
    pub fn new() -> Self {
        Self { now_ns: 0 }
    }

    /// Return the current virtual time in nanoseconds.
    pub fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Advance the clock to the given absolute nanosecond timestamp.
    ///
    /// # Panics
    /// Panics if `target_ns` is less than the current time (clock must be monotonic).
    pub fn advance_to(&mut self, target_ns: u64) {
        assert!(
            target_ns >= self.now_ns,
            "VirtualClock cannot go backwards: current={}, target={}",
            self.now_ns,
            target_ns,
        );
        self.now_ns = target_ns;
    }

    /// Advance the clock forward by the given number of nanoseconds.
    pub fn advance_by(&mut self, delta_ns: u64) {
        self.now_ns = self.now_ns.checked_add(delta_ns).expect(
            "VirtualClock overflow: advance_by would exceed u64::MAX",
        );
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clock_starts_at_zero() {
        let clock = VirtualClock::new();
        assert_eq!(clock.now_ns(), 0);
    }

    #[test]
    fn advance_to_sets_time() {
        let mut clock = VirtualClock::new();
        clock.advance_to(1_000_000);
        assert_eq!(clock.now_ns(), 1_000_000);
    }

    #[test]
    fn advance_to_same_time_is_ok() {
        let mut clock = VirtualClock::new();
        clock.advance_to(500);
        clock.advance_to(500);
        assert_eq!(clock.now_ns(), 500);
    }

    #[test]
    #[should_panic(expected = "VirtualClock cannot go backwards")]
    fn advance_to_backwards_panics() {
        let mut clock = VirtualClock::new();
        clock.advance_to(1000);
        clock.advance_to(999);
    }

    #[test]
    fn advance_by_adds_delta() {
        let mut clock = VirtualClock::new();
        clock.advance_by(100);
        assert_eq!(clock.now_ns(), 100);
        clock.advance_by(200);
        assert_eq!(clock.now_ns(), 300);
    }

    #[test]
    fn advance_by_zero_is_noop() {
        let mut clock = VirtualClock::new();
        clock.advance_to(42);
        clock.advance_by(0);
        assert_eq!(clock.now_ns(), 42);
    }

    #[test]
    fn clock_does_not_advance_without_explicit_call() {
        let clock = VirtualClock::new();
        // Reading the clock multiple times should not change it
        assert_eq!(clock.now_ns(), 0);
        assert_eq!(clock.now_ns(), 0);
        assert_eq!(clock.now_ns(), 0);
    }

    #[test]
    fn default_is_same_as_new() {
        let clock = VirtualClock::default();
        assert_eq!(clock.now_ns(), 0);
    }
}
