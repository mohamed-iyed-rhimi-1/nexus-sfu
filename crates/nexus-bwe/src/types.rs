//! Common types for bandwidth estimation.

use std::sync::atomic::{AtomicU64, Ordering};

/// Bandwidth estimation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BweState {
    /// Normal operation - no congestion detected.
    Normal,

    /// Overuse detected - delay increasing.
    Overuse,

    /// Underuse detected - delay decreasing.
    Underuse,
}

/// Bandwidth estimate with timestamp.
#[derive(Clone, Copy, Debug)]
pub struct BandwidthEstimate {
    /// Estimated bandwidth in bits per second.
    pub estimate_bps: u64,

    /// Timestamp when estimate was calculated (microseconds).
    pub timestamp_us: u64,

    /// Current BWE state.
    pub state: BweState,
}

impl BandwidthEstimate {
    /// Create new bandwidth estimate.
    ///
    /// # Assertions
    /// - estimate_bps > 0
    /// - timestamp_us > 0
    pub fn new(estimate_bps: u64, timestamp_us: u64, state: BweState) -> Self {
        assert!(estimate_bps > 0, "estimate_bps must be > 0");
        assert!(timestamp_us > 0, "timestamp_us must be > 0");

        Self {
            estimate_bps,
            timestamp_us,
            state,
        }
    }
}

/// Thread-safe bandwidth estimate storage.
#[allow(dead_code)] // Reserved for lock-free BWE sharing across threads
pub struct AtomicBandwidthEstimate {
    estimate_bps: AtomicU64,
    timestamp_us: AtomicU64,
}

#[allow(dead_code)] // Reserved for lock-free BWE sharing across threads
impl AtomicBandwidthEstimate {
    /// Create new atomic estimate.
    pub fn new(initial_bps: u64) -> Self {
        assert!(initial_bps > 0, "initial_bps must be > 0");

        Self {
            estimate_bps: AtomicU64::new(initial_bps),
            timestamp_us: AtomicU64::new(0),
        }
    }

    /// Load current estimate.
    #[inline]
    pub fn load(&self) -> u64 {
        self.estimate_bps.load(Ordering::Acquire)
    }

    /// Store new estimate.
    #[inline]
    pub fn store(&self, estimate_bps: u64, timestamp_us: u64) {
        assert!(estimate_bps > 0, "estimate_bps must be > 0");
        self.estimate_bps.store(estimate_bps, Ordering::Release);
        self.timestamp_us.store(timestamp_us, Ordering::Release);
    }
}
