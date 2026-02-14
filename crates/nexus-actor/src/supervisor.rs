//! Actor supervision for health monitoring and restart
//!
//! Provides supervision capabilities:
//! - Periodic health checks
//! - Restart policy enforcement
//! - Failure tracking

use std::time::{Duration, Instant};

use crate::registry::ActorId;
use crate::types::*;

/// Default health check interval
const DEFAULT_CHECK_INTERVAL_MS: u64 = 1000;

/// Maximum consecutive degraded checks before failure
const MAX_DEGRADED_CHECKS: u32 = 3;

/// Actor supervisor for health monitoring and restart
pub struct ActorSupervisor {
    /// Actor being supervised
    actor_id: ActorId,

    /// Restart policy
    policy: RestartPolicy,

    /// Worker hosting this actor
    worker_id: WorkerId,

    /// Health check interval
    check_interval: Duration,

    /// Last health check time
    last_check: Instant,

    /// Consecutive failures
    failure_count: u32,

    /// Consecutive degraded checks
    degraded_count: u32,
}

impl ActorSupervisor {
    /// Create new supervisor with policy
    ///
    /// # Arguments
    /// - actor_id: ID of actor being supervised
    /// - policy: Restart policy to enforce
    /// - worker_id: Worker hosting this actor
    pub fn new(actor_id: ActorId, policy: RestartPolicy, worker_id: WorkerId) -> Self {
        Self {
            actor_id,
            policy,
            worker_id,
            check_interval: Duration::from_millis(DEFAULT_CHECK_INTERVAL_MS),
            last_check: Instant::now(),
            failure_count: 0,
            degraded_count: 0,
        }
    }

    /// Create supervisor with default settings
    pub fn with_defaults(actor_id: ActorId, worker_id: WorkerId) -> Self {
        Self::new(actor_id, RestartPolicy::Limited(3), worker_id)
    }

    /// Check if health check is due
    pub fn should_check_health(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.last_check) >= self.check_interval
    }

    /// Record health check result
    ///
    /// Returns true if actor is healthy, false if failed.
    pub fn record_health(&mut self, health: ActorHealth) -> bool {
        self.last_check = Instant::now();

        match health {
            ActorHealth::Healthy => {
                self.failure_count = 0;
                self.degraded_count = 0;
                true
            }
            ActorHealth::Degraded => {
                self.degraded_count += 1;
                if self.degraded_count >= MAX_DEGRADED_CHECKS {
                    self.failure_count += 1;
                    false
                } else {
                    true
                }
            }
            ActorHealth::Failed => {
                self.failure_count += 1;
                false
            }
        }
    }

    /// Determine if actor should be restarted based on restart count
    pub fn should_restart(&self, restart_count: u32) -> bool {
        match self.policy {
            RestartPolicy::Never => false,
            RestartPolicy::Once => restart_count == 0,
            RestartPolicy::Limited(max) => restart_count < max,
            RestartPolicy::Always => true,
        }
    }

    /// Get actor ID
    pub fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Get worker ID
    pub fn worker_id(&self) -> WorkerId {
        self.worker_id
    }

    /// Get current failure count
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Get current degraded count
    pub fn degraded_count(&self) -> u32 {
        self.degraded_count
    }

    /// Reset failure counters
    pub fn reset_counters(&mut self) {
        self.failure_count = 0;
        self.degraded_count = 0;
    }

    /// Get restart policy
    pub fn policy(&self) -> RestartPolicy {
        self.policy
    }

    /// Set restart policy
    pub fn set_policy(&mut self, policy: RestartPolicy) {
        self.policy = policy;
    }

    /// Get check interval
    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }

    /// Set check interval
    pub fn set_check_interval(&mut self, interval: Duration) {
        self.check_interval = interval;
    }
}

impl Default for ActorSupervisor {
    fn default() -> Self {
        // Note: Default implementation requires ActorId, so this is mainly for compatibility
        // In practice, use new() or with_defaults() with proper ActorId
        Self::new(
            crate::registry::ActorId::track(1),
            RestartPolicy::Limited(3),
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ActorId;

    #[test]
    fn test_supervisor_new() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Once, 0);

        assert_eq!(supervisor.policy(), RestartPolicy::Once);
        assert_eq!(supervisor.failure_count(), 0);
        assert_eq!(supervisor.worker_id(), 0);
    }

    #[test]
    fn test_supervisor_defaults() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        assert_eq!(supervisor.policy(), RestartPolicy::Limited(3));
        assert_eq!(
            supervisor.check_interval(),
            Duration::from_millis(DEFAULT_CHECK_INTERVAL_MS)
        );
    }

    #[test]
    fn test_restart_policy_never() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Never, 0);

        assert!(!supervisor.should_restart(0));
        assert!(!supervisor.should_restart(5));
    }

    #[test]
    fn test_restart_policy_once() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Once, 0);

        // First restart should be allowed
        assert!(supervisor.should_restart(0));

        // Second restart should not be allowed
        assert!(!supervisor.should_restart(1));
    }

    #[test]
    fn test_restart_policy_limited() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Limited(3), 0);

        // First 3 restarts should be allowed
        assert!(supervisor.should_restart(0));
        assert!(supervisor.should_restart(1));
        assert!(supervisor.should_restart(2));

        // Fourth restart should not be allowed
        assert!(!supervisor.should_restart(3));
    }

    #[test]
    fn test_restart_policy_always() {
        let actor_id = ActorId::track(1);
        let supervisor = ActorSupervisor::new(actor_id, RestartPolicy::Always, 0);

        // Many restarts should be allowed
        for i in 0..100 {
            assert!(supervisor.should_restart(i));
        }
    }

    #[test]
    fn test_record_health_healthy() {
        let actor_id = ActorId::track(1);
        let mut supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        let result = supervisor.record_health(ActorHealth::Healthy);
        assert!(result);
        assert_eq!(supervisor.failure_count(), 0);
        assert_eq!(supervisor.degraded_count(), 0);
    }

    #[test]
    fn test_record_health_degraded() {
        let actor_id = ActorId::track(1);
        let mut supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        // First degraded check
        let result = supervisor.record_health(ActorHealth::Degraded);
        assert!(result);
        assert_eq!(supervisor.degraded_count(), 1);

        // Second degraded check
        let result = supervisor.record_health(ActorHealth::Degraded);
        assert!(result);
        assert_eq!(supervisor.degraded_count(), 2);

        // Third degraded check should trigger failure
        let result = supervisor.record_health(ActorHealth::Degraded);
        assert!(!result);
        assert_eq!(supervisor.failure_count(), 1);
    }

    #[test]
    fn test_record_health_failed() {
        let actor_id = ActorId::track(1);
        let mut supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        let result = supervisor.record_health(ActorHealth::Failed);
        assert!(!result);
        assert_eq!(supervisor.failure_count(), 1);
    }

    #[test]
    fn test_reset_counters() {
        let actor_id = ActorId::track(1);
        let mut supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        supervisor.record_health(ActorHealth::Failed);
        supervisor.record_health(ActorHealth::Degraded);

        assert!(supervisor.failure_count() > 0 || supervisor.degraded_count() > 0);

        supervisor.reset_counters();

        assert_eq!(supervisor.failure_count(), 0);
        assert_eq!(supervisor.degraded_count(), 0);
    }

    #[test]
    fn test_should_check_health() {
        let actor_id = ActorId::track(1);
        let mut supervisor = ActorSupervisor::with_defaults(actor_id, 0);

        // Set a very short check interval for testing
        supervisor.set_check_interval(Duration::from_millis(1));
        
        // Wait a bit longer than the interval
        std::thread::sleep(Duration::from_millis(5));

        // Should check after interval has passed
        assert!(supervisor.should_check_health());
    }
}
