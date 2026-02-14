//! Feature-gated clock abstraction for deterministic simulation.
//!
//! Under normal builds, delegates to `SystemTime::now()` and `Instant::now()`.
//! Under `sim` feature, reads from a static atomic set by the DST engine's
//! `VirtualClock`, enabling fully deterministic time control.

#[cfg(not(feature = "sim"))]
use std::time::Duration;

// =============================================================================
// Production clock (non-sim)
// =============================================================================

/// Get current time in microseconds since UNIX epoch.
#[cfg(not(feature = "sim"))]
#[inline(always)]
pub fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// Get current time in nanoseconds since UNIX epoch.
#[cfg(not(feature = "sim"))]
#[inline(always)]
pub fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// A monotonic instant for measuring elapsed time.
/// In production, wraps `std::time::Instant`.
#[cfg(not(feature = "sim"))]
#[derive(Clone, Copy, Debug)]
pub struct ClockInstant(std::time::Instant);

#[cfg(not(feature = "sim"))]
impl ClockInstant {
    /// Capture the current instant.
    #[inline(always)]
    pub fn now() -> Self {
        Self(std::time::Instant::now())
    }

    /// Duration elapsed since this instant was captured.
    #[inline(always)]
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

// =============================================================================
// Simulation clock (sim feature)
// =============================================================================

#[cfg(feature = "sim")]
mod sim_clock {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Global simulation time in nanoseconds, set by the DST engine.
    static SIM_TIME_NS: AtomicU64 = AtomicU64::new(0);

    /// Set the simulation time. Called by the DST engine before each step.
    pub fn set_time_ns(ns: u64) {
        SIM_TIME_NS.store(ns, Ordering::Release);
    }

    /// Get current simulation time in microseconds.
    #[inline(always)]
    pub fn now_us() -> u64 {
        SIM_TIME_NS.load(Ordering::Acquire) / 1000
    }

    /// Get current simulation time in nanoseconds.
    #[inline(always)]
    pub fn now_ns() -> u64 {
        SIM_TIME_NS.load(Ordering::Acquire)
    }

    /// A monotonic instant backed by the simulation clock.
    #[derive(Clone, Copy, Debug)]
    pub struct ClockInstant(u64);

    impl ClockInstant {
        /// Capture the current simulation instant.
        #[inline(always)]
        pub fn now() -> Self {
            Self(SIM_TIME_NS.load(Ordering::Acquire))
        }

        /// Duration elapsed since this instant was captured.
        #[inline(always)]
        pub fn elapsed(&self) -> Duration {
            let current = SIM_TIME_NS.load(Ordering::Acquire);
            Duration::from_nanos(current.saturating_sub(self.0))
        }
    }
}

#[cfg(feature = "sim")]
pub use sim_clock::*;
