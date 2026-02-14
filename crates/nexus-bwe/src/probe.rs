use std::sync::atomic::{AtomicU64, Ordering};

/// Probe controller for bandwidth discovery.
/// 
/// Implements periodic probing to discover available network capacity by
/// temporarily increasing send rate and monitoring loss/delay feedback.
pub struct ProbeController {
    /// Current probe state.
    state: ProbeState,
    /// Probe bitrate in bps.
    probe_bitrate_bps: AtomicU64,
    /// Probe start time (microseconds).
    probe_start_us: AtomicU64,
    /// Last probe time (microseconds).
    last_probe_us: AtomicU64,
    /// Probe duration (microseconds).
    probe_duration_us: u64,
    /// Probe interval (microseconds).
    probe_interval_us: u64,
    /// Maximum probe multiplier (default 2.0x current estimate).
    max_probe_multiplier: f64,
    /// Statistics.
    stats: ProbeStats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeState {
    Idle,
    Probing,
    Success,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Continue,
    Success,
    Failed,
}

struct ProbeStats {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
}

impl ProbeController {
    /// Default probe duration (500ms).
    const DEFAULT_PROBE_DURATION_US: u64 = 500_000;
    /// Default probe interval (5s).
    const DEFAULT_PROBE_INTERVAL_US: u64 = 5_000_000;
    /// Probe multiplier (1.5x current estimate).
    const PROBE_MULTIPLIER: f64 = 1.5;
    /// Success loss threshold (2%).
    const SUCCESS_LOSS_THRESHOLD: u8 = 2;
    /// Failure loss threshold (5%).
    const FAILURE_LOSS_THRESHOLD: u8 = 5;
    /// Minimum probe duration (500ms).
    const MIN_PROBE_DURATION_US: u64 = 500_000;
    /// Maximum probe duration (2s).
    const MAX_PROBE_DURATION_US: u64 = 2_000_000;
    /// Minimum probe interval (5s).
    const MIN_PROBE_INTERVAL_US: u64 = 5_000_000;
    /// Maximum probe interval (30s).
    const MAX_PROBE_INTERVAL_US: u64 = 30_000_000;

    /// Create new probe controller.
    pub fn new(probe_duration_us: u64, probe_interval_us: u64) -> Self {
        assert!(probe_duration_us > 0, "Probe duration must be positive");
        assert!(
            (Self::MIN_PROBE_DURATION_US..=Self::MAX_PROBE_DURATION_US).contains(&probe_duration_us),
            "Probe duration must be within [{}, {}], got {}",
            Self::MIN_PROBE_DURATION_US,
            Self::MAX_PROBE_DURATION_US,
            probe_duration_us
        );
        assert!(
            probe_interval_us > probe_duration_us,
            "Probe interval {} must be > probe duration {}",
            probe_interval_us,
            probe_duration_us
        );
        assert!(
            (Self::MIN_PROBE_INTERVAL_US..=Self::MAX_PROBE_INTERVAL_US).contains(&probe_interval_us),
            "Probe interval must be within [{}, {}], got {}",
            Self::MIN_PROBE_INTERVAL_US,
            Self::MAX_PROBE_INTERVAL_US,
            probe_interval_us
        );

        let max_probe_multiplier = 2.0;
        assert!(
            max_probe_multiplier > 1.0 && max_probe_multiplier <= 3.0,
            "Max probe multiplier must be in (1.0, 3.0], got {}",
            max_probe_multiplier
        );

        Self {
            state: ProbeState::Idle,
            probe_bitrate_bps: AtomicU64::new(0),
            probe_start_us: AtomicU64::new(0),
            last_probe_us: AtomicU64::new(0),
            probe_duration_us,
            probe_interval_us,
            max_probe_multiplier,
            stats: ProbeStats {
                attempts: AtomicU64::new(0),
                successes: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            },
        }
    }

    /// Check if probe should be started.
    pub fn should_probe(&self, current_estimate_bps: u64, timestamp_us: u64) -> bool {
        if self.state != ProbeState::Idle {
            return false;
        }

        let last_probe = self.last_probe_us.load(Ordering::Relaxed);
        let elapsed = timestamp_us.saturating_sub(last_probe);
        
        elapsed >= self.probe_interval_us && current_estimate_bps > 0
    }

    /// Start bandwidth probe.
    pub fn start_probe(&mut self, current_estimate_bps: u64, timestamp_us: u64) {
        assert!(
            self.state == ProbeState::Idle,
            "Cannot start probe in state {:?}",
            self.state
        );
        assert!(current_estimate_bps > 0, "Current estimate must be positive");

        // Calculate probe bitrate: 1.5x current, capped at 2x
        let probe_bitrate = (current_estimate_bps as f64 * Self::PROBE_MULTIPLIER) as u64;
        let max_probe = (current_estimate_bps as f64 * self.max_probe_multiplier) as u64;
        let probe_bitrate = probe_bitrate.min(max_probe);

        assert!(
            probe_bitrate <= current_estimate_bps * 2,
            "Probe bitrate {} exceeds 2x current estimate {}",
            probe_bitrate,
            current_estimate_bps
        );

        self.probe_bitrate_bps.store(probe_bitrate, Ordering::Relaxed);
        self.probe_start_us.store(timestamp_us, Ordering::Relaxed);
        self.last_probe_us.store(timestamp_us, Ordering::Relaxed);
        self.state = ProbeState::Probing;
        self.stats.attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Process feedback during probe.
    pub fn on_feedback(&mut self, loss_percent: u8, timestamp_us: u64) -> ProbeResult {
        if self.state != ProbeState::Probing {
            return ProbeResult::Continue;
        }

        assert!(loss_percent <= 100, "Loss percent must be <= 100, got {}", loss_percent);

        let probe_start = self.probe_start_us.load(Ordering::Relaxed);
        let elapsed = timestamp_us.saturating_sub(probe_start);

        // Check for failure (high loss)
        if loss_percent > Self::FAILURE_LOSS_THRESHOLD {
            self.state = ProbeState::Failed;
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
            self.probe_bitrate_bps.store(0, Ordering::Relaxed);
            return ProbeResult::Failed;
        }

        // Check for success (low loss after duration)
        if elapsed >= self.probe_duration_us && loss_percent < Self::SUCCESS_LOSS_THRESHOLD {
            self.state = ProbeState::Success;
            self.stats.successes.fetch_add(1, Ordering::Relaxed);
            return ProbeResult::Success;
        }

        ProbeResult::Continue
    }

    /// Reset probe state to idle.
    pub fn reset(&mut self) {
        self.state = ProbeState::Idle;
        self.probe_bitrate_bps.store(0, Ordering::Relaxed);
        self.probe_start_us.store(0, Ordering::Relaxed);
    }

    /// Get current probe bitrate if probing or successful.
    pub fn probe_bitrate_bps(&self) -> Option<u64> {
        if self.state == ProbeState::Probing || self.state == ProbeState::Success {
            Some(self.probe_bitrate_bps.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Get current probe state.
    pub fn state(&self) -> ProbeState {
        self.state
    }

    /// Get probe statistics.
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.stats.attempts.load(Ordering::Relaxed),
            self.stats.successes.load(Ordering::Relaxed),
            self.stats.failures.load(Ordering::Relaxed),
        )
    }
}

impl Default for ProbeController {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_PROBE_DURATION_US,
            Self::DEFAULT_PROBE_INTERVAL_US,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_controller_initialization() {
        let controller = ProbeController::default();
        assert_eq!(controller.state(), ProbeState::Idle);
        assert_eq!(controller.probe_bitrate_bps(), None);
    }

    #[test]
    #[should_panic(expected = "Probe duration must be positive")]
    fn test_probe_controller_zero_duration() {
        ProbeController::new(0, 5_000_000);
    }

    #[test]
    #[should_panic(expected = "Probe interval")]
    fn test_probe_controller_invalid_interval() {
        ProbeController::new(1_000_000, 500_000);
    }

    #[test]
    fn test_probe_controller_should_probe() {
        let controller = ProbeController::default();
        
        // Should not probe immediately
        assert!(!controller.should_probe(1_000_000, 0));
        
        // Should probe after interval
        assert!(controller.should_probe(1_000_000, 6_000_000));
    }

    #[test]
    fn test_probe_controller_start_probe() {
        let mut controller = ProbeController::default();
        let current_estimate = 1_000_000;
        
        controller.start_probe(current_estimate, 0);
        
        assert_eq!(controller.state(), ProbeState::Probing);
        let probe_bitrate = controller.probe_bitrate_bps().unwrap();
        assert!(probe_bitrate > current_estimate);
        assert!(probe_bitrate <= current_estimate * 2);
    }

    #[test]
    fn test_probe_controller_success() {
        let mut controller = ProbeController::default();
        controller.start_probe(1_000_000, 0);
        
        // Low loss during probe
        let result = controller.on_feedback(1, 100_000);
        assert_eq!(result, ProbeResult::Continue);
        
        // Low loss after duration
        let result = controller.on_feedback(1, 600_000);
        assert_eq!(result, ProbeResult::Success);
        assert_eq!(controller.state(), ProbeState::Success);
        
        let (attempts, successes, failures) = controller.stats();
        assert_eq!(attempts, 1);
        assert_eq!(successes, 1);
        assert_eq!(failures, 0);
    }

    #[test]
    fn test_probe_controller_failure() {
        let mut controller = ProbeController::default();
        controller.start_probe(1_000_000, 0);
        
        // High loss during probe
        let result = controller.on_feedback(10, 100_000);
        assert_eq!(result, ProbeResult::Failed);
        assert_eq!(controller.state(), ProbeState::Failed);
        
        let (attempts, successes, failures) = controller.stats();
        assert_eq!(attempts, 1);
        assert_eq!(successes, 0);
        assert_eq!(failures, 1);
    }

    #[test]
    fn test_probe_controller_reset() {
        let mut controller = ProbeController::default();
        controller.start_probe(1_000_000, 0);
        
        controller.reset();
        assert_eq!(controller.state(), ProbeState::Idle);
        assert_eq!(controller.probe_bitrate_bps(), None);
    }

    #[test]
    #[should_panic(expected = "Cannot start probe")]
    fn test_probe_controller_double_start() {
        let mut controller = ProbeController::default();
        controller.start_probe(1_000_000, 0);
        controller.start_probe(1_000_000, 0);
    }
}
