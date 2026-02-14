use std::sync::atomic::{AtomicU64, Ordering};

/// RTT estimator with exponential smoothing following RFC 6298.
/// 
/// Maintains smoothed RTT (SRTT) and RTT variance (RTTVAR) for timeout
/// calculation and congestion control. Uses lock-free atomics for thread-safe
/// updates without allocation.
pub struct RttEstimator {
    /// Smoothed RTT in microseconds (SRTT).
    srtt_us: AtomicU64,
    /// RTT variance in microseconds (RTTVAR).
    rttvar_us: AtomicU64,
    /// Minimum RTT observed.
    min_rtt_us: AtomicU64,
    /// Maximum RTT observed.
    max_rtt_us: AtomicU64,
    /// Smoothing factor (alpha = 0.125 per RFC 6298).
    alpha: f64,
    /// Variance factor (beta = 0.25 per RFC 6298).
    beta: f64,
}

impl RttEstimator {
    /// Minimum RTT bound (1ms).
    const MIN_RTT_US: u64 = 1_000;
    /// Maximum RTT bound (5s).
    const MAX_RTT_US: u64 = 5_000_000;
    /// Minimum RTO (200ms).
    const MIN_RTO_US: u64 = 200_000;
    /// Maximum RTO (60s).
    const MAX_RTO_US: u64 = 60_000_000;

    /// Create new RTT estimator with initial RTT sample.
    pub fn new(initial_rtt_us: u64) -> Self {
        assert!(initial_rtt_us > 0, "Initial RTT must be positive");
        assert!(
            (Self::MIN_RTT_US..=Self::MAX_RTT_US).contains(&initial_rtt_us),
            "Initial RTT must be within bounds [{}, {}], got {}",
            Self::MIN_RTT_US,
            Self::MAX_RTT_US,
            initial_rtt_us
        );

        let alpha = 0.125;
        let beta = 0.25;
        assert!(alpha > 0.0 && alpha < 1.0, "Alpha must be in (0, 1)");
        assert!(beta > 0.0 && beta < 1.0, "Beta must be in (0, 1)");

        Self {
            srtt_us: AtomicU64::new(initial_rtt_us),
            rttvar_us: AtomicU64::new(initial_rtt_us / 2),
            min_rtt_us: AtomicU64::new(initial_rtt_us),
            max_rtt_us: AtomicU64::new(initial_rtt_us),
            alpha,
            beta,
        }
    }

    /// Update RTT estimate with new sample using RFC 6298 algorithm.
    pub fn update(&self, rtt_sample_us: u64) {
        assert!(rtt_sample_us > 0, "RTT sample must be positive");
        assert!(
            (Self::MIN_RTT_US..=Self::MAX_RTT_US).contains(&rtt_sample_us),
            "RTT sample must be within bounds [{}, {}], got {}",
            Self::MIN_RTT_US,
            Self::MAX_RTT_US,
            rtt_sample_us
        );

        let current_srtt = self.srtt_us.load(Ordering::Relaxed);
        let current_rttvar = self.rttvar_us.load(Ordering::Relaxed);

        // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
        let abs_diff = if rtt_sample_us > current_srtt {
            rtt_sample_us - current_srtt
        } else {
            current_srtt - rtt_sample_us
        };
        let new_rttvar = ((1.0 - self.beta) * current_rttvar as f64 + self.beta * abs_diff as f64) as u64;

        // SRTT = (1 - alpha) * SRTT + alpha * R
        let new_srtt = ((1.0 - self.alpha) * current_srtt as f64 + self.alpha * rtt_sample_us as f64) as u64;

        // Clamp to bounds
        let new_srtt = new_srtt.clamp(Self::MIN_RTT_US, Self::MAX_RTT_US);

        self.srtt_us.store(new_srtt, Ordering::Relaxed);
        self.rttvar_us.store(new_rttvar, Ordering::Relaxed);

        // Update min/max
        let current_min = self.min_rtt_us.load(Ordering::Relaxed);
        if rtt_sample_us < current_min {
            self.min_rtt_us.store(rtt_sample_us, Ordering::Relaxed);
        }

        let current_max = self.max_rtt_us.load(Ordering::Relaxed);
        if rtt_sample_us > current_max {
            self.max_rtt_us.store(rtt_sample_us, Ordering::Relaxed);
        }

        // Verify invariants
        let final_srtt = self.srtt_us.load(Ordering::Relaxed);
        let final_min = self.min_rtt_us.load(Ordering::Relaxed);
        let final_max = self.max_rtt_us.load(Ordering::Relaxed);
        assert!(
            final_srtt >= final_min,
            "SRTT {} must be >= min RTT {}",
            final_srtt,
            final_min
        );
        assert!(
            final_srtt <= final_max,
            "SRTT {} must be <= max RTT {}",
            final_srtt,
            final_max
        );
    }

    /// Get smoothed RTT in microseconds.
    pub fn srtt_us(&self) -> u64 {
        self.srtt_us.load(Ordering::Relaxed)
    }

    /// Get RTT variance in microseconds.
    pub fn rttvar_us(&self) -> u64 {
        self.rttvar_us.load(Ordering::Relaxed)
    }

    /// Get minimum RTT observed.
    pub fn min_rtt_us(&self) -> u64 {
        self.min_rtt_us.load(Ordering::Relaxed)
    }

    /// Get maximum RTT observed.
    pub fn max_rtt_us(&self) -> u64 {
        self.max_rtt_us.load(Ordering::Relaxed)
    }

    /// Calculate retransmission timeout: RTO = SRTT + 4*RTTVAR.
    pub fn rto_us(&self) -> u64 {
        let srtt = self.srtt_us.load(Ordering::Relaxed);
        let rttvar = self.rttvar_us.load(Ordering::Relaxed);
        let rto = srtt + 4 * rttvar;
        rto.clamp(Self::MIN_RTO_US, Self::MAX_RTO_US)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_estimator_initialization() {
        let estimator = RttEstimator::new(50_000);
        assert_eq!(estimator.srtt_us(), 50_000);
        assert_eq!(estimator.min_rtt_us(), 50_000);
        assert_eq!(estimator.max_rtt_us(), 50_000);
        assert!(estimator.rto_us() >= RttEstimator::MIN_RTO_US);
    }

    #[test]
    #[should_panic(expected = "Initial RTT must be positive")]
    fn test_rtt_estimator_zero_initial() {
        RttEstimator::new(0);
    }

    #[test]
    fn test_rtt_estimator_update() {
        let estimator = RttEstimator::new(50_000);
        estimator.update(60_000);
        
        let srtt = estimator.srtt_us();
        assert!(srtt > 50_000 && srtt < 60_000, "SRTT should be between old and new");
        assert_eq!(estimator.min_rtt_us(), 50_000);
        assert_eq!(estimator.max_rtt_us(), 60_000);
    }

    #[test]
    fn test_rtt_estimator_smoothing() {
        let estimator = RttEstimator::new(50_000);
        
        // Add samples with variance
        for _ in 0..10 {
            estimator.update(55_000);
        }
        
        let srtt = estimator.srtt_us();
        assert!(srtt > 50_000 && srtt <= 55_000, "SRTT should converge toward samples");
    }

    #[test]
    fn test_rtt_estimator_bounds() {
        let estimator = RttEstimator::new(50_000);
        
        // Update with min bound
        estimator.update(RttEstimator::MIN_RTT_US);
        assert_eq!(estimator.min_rtt_us(), RttEstimator::MIN_RTT_US);
        
        // Update with max bound
        estimator.update(RttEstimator::MAX_RTT_US);
        assert_eq!(estimator.max_rtt_us(), RttEstimator::MAX_RTT_US);
        
        let srtt = estimator.srtt_us();
        assert!(srtt >= estimator.min_rtt_us());
        assert!(srtt <= estimator.max_rtt_us());
    }

    #[test]
    fn test_rtt_estimator_rto_calculation() {
        let estimator = RttEstimator::new(50_000);
        let rto = estimator.rto_us();
        
        assert!(rto >= RttEstimator::MIN_RTO_US);
        assert!(rto <= RttEstimator::MAX_RTO_US);
        assert!(rto >= estimator.srtt_us());
    }

    #[test]
    #[should_panic(expected = "RTT sample must be positive")]
    fn test_rtt_estimator_zero_sample() {
        let estimator = RttEstimator::new(50_000);
        estimator.update(0);
    }
}
