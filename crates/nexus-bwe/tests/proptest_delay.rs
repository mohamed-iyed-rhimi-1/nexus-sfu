use proptest::prelude::*;
use nexus_bwe::{KalmanFilter, DelayBasedBweDetector, DelayBasedBweState};

proptest! {
    #[test]
    fn test_kalman_filter_variance_bounded(
        delay_delta in -100.0..100.0f64,
        time_delta in 1.0..1000.0f64,
    ) {
        let mut filter = KalmanFilter::new();

        // Process 100 samples
        for _ in 0..100 {
            filter.update(delay_delta, time_delta);

            // Variance must remain bounded
            prop_assert!(filter.variance() > 0.0);
            prop_assert!(filter.variance() <= 1e2);
        }
    }

    #[test]
    fn test_delay_detector_state_valid(
        gradient_threshold in 0.001..1.0f64,
        overuse_threshold_ms in 1.0..50.0f64,
    ) {
        let detector = DelayBasedBweDetector::new(gradient_threshold, overuse_threshold_ms);

        // State must always be valid
        let state = detector.state();
        prop_assert!(matches!(
            state,
            DelayBasedBweState::Normal | DelayBasedBweState::Overuse | DelayBasedBweState::Underuse
        ));
    }
}
