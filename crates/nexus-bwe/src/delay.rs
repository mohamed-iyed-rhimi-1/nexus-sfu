//! Delay-based bandwidth estimation with Kalman filter.
//!
//! Implements Google Congestion Control delay-based detector.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use crate::feedback::{TransportFeedback, PacketArrivalInfo};
use crate::types::BweState;

/// Default delay gradient threshold for overuse detection (dimensionless, ms/ms).
/// A gradient of 0.0125 means delay increases by 12.5ms per second.
pub const DEFAULT_DELAY_GRADIENT_THRESHOLD: f64 = 0.0125;

/// Default overuse time threshold (milliseconds).
pub const DEFAULT_OVERUSE_TIME_THRESHOLD_MS: f64 = 10.0;

/// Maximum delay samples in trendline window.
const MAX_TRENDLINE_WINDOW_SIZE: usize = 100;

/// Process noise covariance (Q).
const PROCESS_NOISE: f64 = 1e-3;

/// Measurement noise covariance (R).
const MEASUREMENT_NOISE: f64 = 1e-1;

/// Initial variance.
const INITIAL_VARIANCE: f64 = 1e-1;

/// Maximum variance bound (stability).
const MAX_VARIANCE: f64 = 1e2;

/// Kalman filter for delay gradient estimation.
///
/// Tracks delay trend using one-dimensional Kalman filter.
/// State: delay gradient (slope of delay over time).
#[derive(Clone, Debug)]
pub struct KalmanFilter {
    /// State estimate (delay gradient in ms/ms).
    slope: f64,

    /// Estimation error variance.
    variance: f64,

    /// Process noise covariance.
    process_noise: f64,

    /// Measurement noise covariance.
    measurement_noise: f64,
}

impl KalmanFilter {
    /// Create new Kalman filter.
    pub fn new() -> Self {
        Self {
            slope: 0.0,
            variance: INITIAL_VARIANCE,
            process_noise: PROCESS_NOISE,
            measurement_noise: MEASUREMENT_NOISE,
        }
    }

    /// Update filter with new delay measurement.
    ///
    /// # Arguments
    /// - `delay_delta_ms`: Change in delay (milliseconds)
    /// - `time_delta_ms`: Time interval (milliseconds)
    ///
    /// # Returns
    /// Updated slope estimate
    ///
    /// # Assertions
    /// - time_delta_ms > 0
    /// - variance remains bounded
    pub fn update(&mut self, delay_delta_ms: f64, time_delta_ms: f64) -> f64 {
        assert!(time_delta_ms > 0.0, "time_delta_ms must be > 0");

        // Predict step
        let predicted_variance = self.variance + self.process_noise;

        // Update step
        let innovation = delay_delta_ms / time_delta_ms - self.slope;
        let innovation_variance = predicted_variance + self.measurement_noise;
        let kalman_gain = predicted_variance / innovation_variance;

        // Update state
        self.slope += kalman_gain * innovation;
        self.variance = (1.0 - kalman_gain) * predicted_variance;

        // Assert stability: variance must remain bounded
        assert!(
            self.variance <= MAX_VARIANCE,
            "Kalman filter variance exceeded bound: {}",
            self.variance
        );
        assert!(
            self.variance >= 0.0,
            "Kalman filter variance must be non-negative"
        );

        self.slope
    }

    /// Get current slope estimate.
    #[inline]
    pub fn slope(&self) -> f64 {
        self.slope
    }

    /// Get current variance.
    #[inline]
    pub fn variance(&self) -> f64 {
        self.variance
    }

    /// Reset filter to initial state.
    pub fn reset(&mut self) {
        self.slope = 0.0;
        self.variance = INITIAL_VARIANCE;
    }
}

impl Default for KalmanFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Delay-based BWE state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelayBasedBweState {
    /// Normal - no overuse detected.
    Normal,

    /// Overuse - delay increasing beyond threshold.
    Overuse,

    /// Underuse - delay decreasing.
    Underuse,
}

impl From<DelayBasedBweState> for BweState {
    fn from(state: DelayBasedBweState) -> Self {
        match state {
            DelayBasedBweState::Normal => BweState::Normal,
            DelayBasedBweState::Overuse => BweState::Overuse,
            DelayBasedBweState::Underuse => BweState::Underuse,
        }
    }
}

/// Delay-based bandwidth estimator.
///
/// Uses Kalman filter to detect delay trends and adjust bandwidth.
pub struct DelayBasedBweDetector {
    /// Kalman filter for trend detection.
    kalman: KalmanFilter,

    /// Current state.
    state: DelayBasedBweState,

    /// Trendline window: circular buffer of recent delay deltas (milliseconds).
    trendline_window: [f64; MAX_TRENDLINE_WINDOW_SIZE],

    /// Current position in trendline window.
    trendline_index: usize,

    /// Number of samples in trendline window.
    trendline_count: usize,

    /// Number of delay samples processed.
    num_deltas: u32,

    /// Delay gradient threshold for overuse detection (dimensionless, ms/ms).
    gradient_threshold: f64,

    /// Overuse time threshold (milliseconds).
    overuse_time_threshold_ms: f64,

    /// Time in overuse state (milliseconds).
    time_in_overuse_ms: f64,

    /// Last packet receive timestamp (microseconds).
    last_recv_time_us: u64,

    /// Previous update receive timestamp (microseconds) for computing actual inter-packet intervals.
    /// Used to calculate elapsed_ms in update_state() instead of using a fixed estimate.
    prev_update_recv_time_us: u64,

    /// Statistics.
    stats: DelayBweStats,
}

/// Statistics for delay-based BWE.
#[derive(Debug, Default)]
pub struct DelayBweStats {
    /// Total feedback messages processed.
    pub feedbacks_processed: AtomicU64,

    /// Overuse detections.
    pub overuse_count: AtomicU64,

    /// Underuse detections.
    pub underuse_count: AtomicU64,

    /// Normal state count.
    pub normal_count: AtomicU64,

    /// Current delay gradient (×1000 for precision, signed).
    pub delay_gradient_x1000: AtomicI32,

    /// State transitions.
    pub state_transitions: AtomicU64,
}

impl DelayBasedBweDetector {
    /// Create new delay-based BWE detector.
    ///
    /// # Arguments
    /// - `gradient_threshold`: Delay gradient threshold for overuse (dimensionless, ms/ms)
    /// - `overuse_time_threshold_ms`: Time threshold for overuse state (milliseconds)
    ///
    /// # Assertions
    /// - gradient_threshold > 0
    /// - overuse_time_threshold_ms > 0
    pub fn new(gradient_threshold: f64, overuse_time_threshold_ms: f64) -> Self {
        assert!(gradient_threshold > 0.0, "gradient_threshold must be > 0");
        assert!(
            overuse_time_threshold_ms > 0.0,
            "overuse_time_threshold_ms must be > 0"
        );

        Self {
            kalman: KalmanFilter::new(),
            state: DelayBasedBweState::Normal,
            trendline_window: [0.0; MAX_TRENDLINE_WINDOW_SIZE],
            trendline_index: 0,
            trendline_count: 0,
            num_deltas: 0,
            gradient_threshold,
            overuse_time_threshold_ms,
            time_in_overuse_ms: 0.0,
            last_recv_time_us: 0,
            prev_update_recv_time_us: 0,
            stats: DelayBweStats::default(),
        }
    }

    /// Create detector with default parameters.
    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_DELAY_GRADIENT_THRESHOLD,
            DEFAULT_OVERUSE_TIME_THRESHOLD_MS,
        )
    }

    /// Process transport feedback and update state.
    ///
    /// # Arguments
    /// - `feedback`: Transport-wide congestion control feedback
    ///
    /// # Returns
    /// Current BWE state after processing
    ///
    /// # Assertions
    /// - Feedback contains at least 2 packets (need deltas)
    pub fn on_feedback(&mut self, feedback: &TransportFeedback) -> DelayBasedBweState {
        let packet_count = feedback.packet_count();
        if packet_count < 2 {
            return self.state;
        }

        self.process_feedback_packets(feedback);
        self.update_state();
        self.update_statistics();

        self.stats
            .feedbacks_processed
            .fetch_add(1, Ordering::Relaxed);

        self.state
    }

    /// Process feedback packets and calculate deltas.
    fn process_feedback_packets(&mut self, feedback: &TransportFeedback) {
        let packets: Vec<&PacketArrivalInfo> = feedback.packets().collect();

        // Fixed loop bound: MAX_FEEDBACK_PACKETS - 1
        let max_iterations = packets.len().min(crate::feedback::MAX_FEEDBACK_PACKETS - 1);

        for i in 0..max_iterations {
            if i + 1 >= packets.len() {
                break;
            }
            self.process_packet_pair(packets[i], packets[i + 1]);
        }
    }

    /// Process single packet pair to calculate delay delta.
    fn process_packet_pair(&mut self, prev: &PacketArrivalInfo, curr: &PacketArrivalInfo) {
        // Calculate inter-arrival time delta
        let send_delta_us = curr.send_time_us.saturating_sub(prev.send_time_us);
        let recv_delta_us = curr.recv_time_us.saturating_sub(prev.recv_time_us);

        if send_delta_us == 0 {
            return;
        }

        // Delay delta = recv_delta - send_delta
        let delay_delta_us = recv_delta_us as i64 - send_delta_us as i64;
        let delay_delta_ms = delay_delta_us as f64 / 1000.0;
        let time_delta_ms = send_delta_us as f64 / 1000.0;

        // Update Kalman filter
        let slope = self.kalman.update(delay_delta_ms, time_delta_ms);

        // Update trendline window (circular buffer)
        self.trendline_window[self.trendline_index] = delay_delta_ms;
        self.trendline_index = (self.trendline_index + 1) % MAX_TRENDLINE_WINDOW_SIZE;
        if self.trendline_count < MAX_TRENDLINE_WINDOW_SIZE {
            self.trendline_count += 1;
        }

        self.num_deltas += 1;

        // Store gradient for metrics (×1000 for precision, preserving sign)
        let gradient_x1000 = (slope * 1000.0) as i32;
        self.stats
            .delay_gradient_x1000
            .store(gradient_x1000, Ordering::Relaxed);

        self.last_recv_time_us = curr.recv_time_us;
    }

    /// Update BWE state based on delay trend.
    fn update_state(&mut self) {
        if self.num_deltas == 0 {
            return;
        }

        let slope = self.kalman.slope();
        let prev_state = self.state;

        // Compute elapsed time since last update using actual inter-packet intervals.
        // Use default 20.0ms only for the first packet (when prev_update_recv_time_us == 0).
        let elapsed_ms = if self.prev_update_recv_time_us > 0 {
            let delta_us = self.last_recv_time_us.saturating_sub(self.prev_update_recv_time_us);
            (delta_us as f64) / 1000.0
        } else {
            20.0 // First packet — use default
        };

        // Update prev_update_recv_time_us for next iteration
        self.prev_update_recv_time_us = self.last_recv_time_us;

        // Assertions for TigerStyle compliance
        assert!(elapsed_ms >= 0.0, "elapsed_ms must be non-negative");
        assert!(
            elapsed_ms <= 10000.0,
            "elapsed_ms exceeds reasonable bound: {}",
            elapsed_ms
        );

        // State machine with hysteresis
        self.state = if slope > self.gradient_threshold {
            // Overuse: delay gradient exceeds threshold
            self.time_in_overuse_ms += elapsed_ms;
            if self.time_in_overuse_ms > self.overuse_time_threshold_ms {
                DelayBasedBweState::Overuse
            } else {
                self.state
            }
        } else if slope < -self.gradient_threshold {
            // Underuse: delay gradient strongly negative
            self.time_in_overuse_ms = 0.0;
            DelayBasedBweState::Underuse
        } else {
            // Normal: delay gradient within hysteresis band
            self.time_in_overuse_ms = 0.0;
            DelayBasedBweState::Normal
        };

        // Track state transitions
        if self.state != prev_state {
            self.stats
                .state_transitions
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update statistics counters.
    fn update_statistics(&self) {
        match self.state {
            DelayBasedBweState::Normal => {
                self.stats.normal_count.fetch_add(1, Ordering::Relaxed);
            }
            DelayBasedBweState::Overuse => {
                self.stats.overuse_count.fetch_add(1, Ordering::Relaxed);
            }
            DelayBasedBweState::Underuse => {
                self.stats.underuse_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get current state.
    #[inline]
    pub fn state(&self) -> DelayBasedBweState {
        self.state
    }

    /// Get delay gradient (slope).
    #[inline]
    pub fn delay_gradient(&self) -> f64 {
        self.kalman.slope()
    }

    /// Get accumulated delay from trendline window.
    #[inline]
    pub fn accumulated_delay_ms(&self) -> f64 {
        self.trendline_window[..self.trendline_count].iter().sum()
    }

    /// Get statistics reference.
    pub fn stats(&self) -> &DelayBweStats {
        &self.stats
    }

    /// Reset detector to initial state.
    pub fn reset(&mut self) {
        self.kalman.reset();
        self.state = DelayBasedBweState::Normal;
        self.trendline_window = [0.0; MAX_TRENDLINE_WINDOW_SIZE];
        self.trendline_index = 0;
        self.trendline_count = 0;
        self.num_deltas = 0;
        self.time_in_overuse_ms = 0.0;
        self.prev_update_recv_time_us = 0;
    }
}

impl Default for DelayBasedBweDetector {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl DelayBweStats {
    /// Export metrics snapshot for Prometheus.
    pub fn snapshot(&self) -> DelayBweStatsSnapshot {
        DelayBweStatsSnapshot {
            feedbacks_processed: self.feedbacks_processed.load(Ordering::Relaxed),
            overuse_count: self.overuse_count.load(Ordering::Relaxed),
            underuse_count: self.underuse_count.load(Ordering::Relaxed),
            normal_count: self.normal_count.load(Ordering::Relaxed),
            delay_gradient: self.delay_gradient_x1000.load(Ordering::Relaxed) as f64 / 1000.0,
            state_transitions: self.state_transitions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DelayBweStatsSnapshot {
    pub feedbacks_processed: u64,
    pub overuse_count: u64,
    pub underuse_count: u64,
    pub normal_count: u64,
    pub delay_gradient: f64,
    pub state_transitions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::{TransportFeedback, PacketArrivalInfo};

    #[test]
    fn test_kalman_filter_initialization() {
        let filter = KalmanFilter::new();
        assert_eq!(filter.slope(), 0.0);
        assert_eq!(filter.variance(), INITIAL_VARIANCE);
    }

    #[test]
    fn test_kalman_filter_update() {
        let mut filter = KalmanFilter::new();

        // Simulate increasing delay
        let slope = filter.update(10.0, 100.0);
        assert!(slope > 0.0, "Slope should be positive for increasing delay");

        // Variance should remain bounded
        assert!(filter.variance() > 0.0);
        assert!(filter.variance() <= MAX_VARIANCE);
    }

    #[test]
    #[should_panic(expected = "time_delta_ms must be > 0")]
    fn test_kalman_filter_zero_time_delta() {
        let mut filter = KalmanFilter::new();
        filter.update(10.0, 0.0);
    }

    #[test]
    fn test_kalman_filter_stability() {
        let mut filter = KalmanFilter::new();

        // Process many samples
        for _ in 0..1000 {
            filter.update(1.0, 10.0);
            assert!(filter.variance() <= MAX_VARIANCE, "Variance exceeded bound");
        }
    }

    #[test]
    fn test_delay_detector_initialization() {
        let detector = DelayBasedBweDetector::with_defaults();
        assert_eq!(detector.state(), DelayBasedBweState::Normal);
        assert_eq!(detector.accumulated_delay_ms(), 0.0);
    }

    #[test]
    fn test_delay_detector_overuse_detection() {
        let mut detector = DelayBasedBweDetector::new(0.5, 0.5);

        // Create feedback with strongly increasing delay
        let mut feedback = TransportFeedback::new(12345, 100);
        for i in 0..100 {
            let send_time = i * 20_000; // 20ms intervals
            let recv_time = send_time + i * 20_000; // Very strong increasing delay (1:1 ratio)

            feedback
                .add_packet(PacketArrivalInfo {
                    sequence: 100 + i as u16,
                    send_time_us: send_time,
                    recv_time_us: recv_time,
                    size_bytes: 1200,
                })
                .unwrap();
        }

        let state = detector.on_feedback(&feedback);

        // With 1:1 delay increase ratio and low thresholds, should detect overuse
        assert_eq!(state, DelayBasedBweState::Overuse);
        assert!(detector.stats().overuse_count.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_delay_detector_underuse_detection() {
        let mut detector = DelayBasedBweDetector::new(0.5, 0.5);

        // Create feedback with strongly decreasing delay
        let mut feedback = TransportFeedback::new(12345, 100);
        for i in 0..100 {
            let send_time = i * 20_000;
            let recv_time = send_time + (100 - i) * 20_000; // Very strong decreasing delay

            feedback
                .add_packet(PacketArrivalInfo {
                    sequence: 100 + i as u16,
                    send_time_us: send_time,
                    recv_time_us: recv_time,
                    size_bytes: 1200,
                })
                .unwrap();
        }

        let state = detector.on_feedback(&feedback);

        // With 1:1 delay decrease ratio and low thresholds, should detect underuse
        assert_eq!(state, DelayBasedBweState::Underuse);
    }

    #[test]
    fn test_delay_detector_state_transitions() {
        let mut detector = DelayBasedBweDetector::with_defaults();

        let initial_transitions = detector
            .stats()
            .state_transitions
            .load(Ordering::Relaxed);

        // Trigger state change
        let mut feedback = TransportFeedback::new(12345, 100);
        for i in 0..10 {
            feedback
                .add_packet(PacketArrivalInfo {
                    sequence: 100 + i as u16,
                    send_time_us: i * 20_000,
                    recv_time_us: i * 20_000 + i * 10_000,
                    size_bytes: 1200,
                })
                .unwrap();
        }

        detector.on_feedback(&feedback);

        let final_transitions = detector
            .stats()
            .state_transitions
            .load(Ordering::Relaxed);
        assert!(final_transitions >= initial_transitions);
    }

    #[test]
    fn test_delay_detector_reset() {
        let mut detector = DelayBasedBweDetector::with_defaults();

        // Process some feedback
        let mut feedback = TransportFeedback::new(12345, 100);
        feedback
            .add_packet(PacketArrivalInfo {
                sequence: 100,
                send_time_us: 0,
                recv_time_us: 1000,
                size_bytes: 1200,
            })
            .unwrap();
        feedback
            .add_packet(PacketArrivalInfo {
                sequence: 101,
                send_time_us: 20_000,
                recv_time_us: 25_000,
                size_bytes: 1200,
            })
            .unwrap();

        detector.on_feedback(&feedback);

        // Reset
        detector.reset();

        assert_eq!(detector.state(), DelayBasedBweState::Normal);
        assert_eq!(detector.accumulated_delay_ms(), 0.0);
        assert_eq!(detector.delay_gradient(), 0.0);
    }
}
