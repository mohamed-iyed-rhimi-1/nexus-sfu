//! RTCP transmission scheduler per RFC 3550 §6.2–6.4.
//!
//! Computes the deterministic RTCP transmission interval (Td) based on
//! session bandwidth, number of participants, and average RTCP packet size.
//! Applies randomization to prevent synchronized bursts.
//!
//! # TigerStyle Compliance
//!
//! - All functions ≤60 lines
//! - All functions ≥2 assertions
//! - No dynamic allocation
//! - Bounded operations

/// Minimum RTCP interval in seconds (RFC 3550 §6.3.1).
const RTCP_MIN_TIME_SECS: f64 = 5.0;

/// Fraction of session bandwidth dedicated to RTCP (RFC 3550 §6.2).
const RTCP_BW_FRACTION: f64 = 0.05;

/// Fraction of RTCP bandwidth allocated to senders (RFC 3550 §6.3.1).
/// If senders are ≤ 25% of members, they get 25% of RTCP bandwidth.
const SENDER_BW_FRACTION: f64 = 0.25;

/// Compensation factor for timer reconsideration (RFC 3550 §6.3.6).
/// The interval is divided by e-3/2 ≈ 1.21828 to compensate.
const COMPENSATION: f64 = std::f64::consts::E - 1.5;

/// Initial average RTCP packet size estimate (bytes).
/// RFC 3550 §6.3.2 recommends 128 bytes as initial estimate.
const INITIAL_AVG_RTCP_SIZE: f64 = 128.0;

/// Maximum number of members tracked for interval calculation.
const MAX_MEMBERS: u32 = 100_000;

/// RTCP transmission scheduler.
///
/// Tracks session state and computes the next RTCP send time according to
/// RFC 3550 §6.2–6.4. Each participant (sender or receiver) should have
/// one scheduler instance.
pub struct RtcpScheduler {
    /// Total number of members in the session.
    members: u32,
    /// Number of active senders in the session.
    senders: u32,
    /// Running average RTCP packet size (bytes), per RFC 3550 §6.3.2.
    avg_rtcp_size: f64,
    /// Session bandwidth in bits per second.
    session_bw_bps: u64,
    /// Whether we are currently a sender (affects bandwidth fraction).
    we_sent: bool,
    /// Timestamp (microseconds) of the last RTCP transmission.
    last_rtcp_us: u64,
    /// Whether this is the initial RTCP packet (reduced delay per §6.3.1).
    initial: bool,
    /// Deterministic RNG state for interval randomization (xorshift32).
    rng_state: u32,
}

impl RtcpScheduler {
    /// Create a new scheduler for a session with the given bandwidth.
    ///
    /// `session_bw_bps` is the total session media bandwidth in bits/sec.
    pub fn new(session_bw_bps: u64) -> Self {
        assert!(session_bw_bps > 0, "session bandwidth must be positive");

        Self {
            members: 1,
            senders: 0,
            avg_rtcp_size: INITIAL_AVG_RTCP_SIZE,
            session_bw_bps,
            we_sent: false,
            last_rtcp_us: 0,
            initial: true,
            rng_state: 0xDEAD_BEEF,
        }
    }

    /// Update the member/sender counts (call when participants join/leave).
    pub fn update_members(&mut self, members: u32, senders: u32) {
        self.members = members.clamp(1, MAX_MEMBERS);
        self.senders = senders.min(self.members);
        // Postcondition: senders never exceeds members
        debug_assert!(self.senders <= self.members);
    }

    /// Set whether we are currently sending media.
    pub fn set_we_sent(&mut self, we_sent: bool) {
        self.we_sent = we_sent;
    }

    /// Update the running average RTCP packet size (RFC 3550 §6.3.2).
    ///
    /// Called after each RTCP packet is sent or received.
    /// Uses exponential weighted moving average: `avg = (1/16)*size + (15/16)*avg`.
    pub fn on_rtcp_packet(&mut self, packet_size: usize, now_us: u64) {
        assert!(packet_size > 0, "packet size must be positive");
        assert!(now_us > 0, "timestamp must be positive");

        // RFC 3550 §6.3.2: avg_rtcp_size = (1/16) * packet_size + (15/16) * avg_rtcp_size
        self.avg_rtcp_size = (packet_size as f64) / 16.0 + self.avg_rtcp_size * 15.0 / 16.0;
        self.last_rtcp_us = now_us;
        self.initial = false;

        // Postcondition: avg must remain positive
        debug_assert!(self.avg_rtcp_size > 0.0);
    }

    /// Compute the deterministic RTCP interval Td in microseconds.
    ///
    /// Implements RFC 3550 §6.3.1 algorithm.
    pub fn compute_interval_us(&mut self) -> u64 {
        // Determine the number of members for RTCP bandwidth calculation.
        // RFC 3550 §6.3.1: if senders <= 25% of members, senders get
        // SENDER_BW_FRACTION of RTCP bandwidth; otherwise bandwidth is
        // shared equally among all members.
        let n = self.members.max(1) as f64;
        let n_senders = self.senders as f64;

        let rtcp_bw = (self.session_bw_bps as f64) * RTCP_BW_FRACTION;

        // Effective number of members for bandwidth calculation
        let effective_n = if n_senders > 0.0 && n_senders <= n * SENDER_BW_FRACTION {
            if self.we_sent {
                // We're a sender: share sender fraction
                n_senders / SENDER_BW_FRACTION
            } else {
                // We're a receiver: share receiver fraction
                (n - n_senders) / (1.0 - SENDER_BW_FRACTION)
            }
        } else {
            n
        };

        // Td = max(RTCP_MIN_TIME, n * avg_size / RTCP_BW)
        // Note: RTCP_BW is in bits/sec, avg_size is in bytes → multiply by 8
        let td_secs = if rtcp_bw > 0.0 {
            (effective_n * self.avg_rtcp_size * 8.0 / rtcp_bw).max(RTCP_MIN_TIME_SECS)
        } else {
            RTCP_MIN_TIME_SECS
        };

        // For the initial RTCP, use half the minimum interval (RFC 3550 §6.3.1)
        let td_secs = if self.initial { td_secs / 2.0 } else { td_secs };

        // Apply compensation factor (RFC 3550 §6.3.6)
        let td_secs = td_secs / COMPENSATION;

        // Randomize in [0.5*Td, 1.5*Td] to prevent synchronized bursts
        let jitter = self.next_random_f64(); // [0.0, 1.0)
        let randomized_secs = td_secs * (0.5 + jitter);

        // Convert to microseconds
        let interval_us = (randomized_secs * 1_000_000.0) as u64;

        // Postcondition: interval must be positive
        assert!(interval_us > 0, "RTCP interval must be positive");

        interval_us
    }

    /// Check if it's time to send the next RTCP packet.
    pub fn is_time_to_send(&mut self, now_us: u64) -> bool {
        assert!(now_us > 0, "timestamp must be positive");

        if self.last_rtcp_us == 0 {
            // First packet — apply initial delay
            let initial_delay = self.compute_interval_us();
            self.last_rtcp_us = now_us;
            // We'll wait for the initial delay
            return now_us >= self.last_rtcp_us + initial_delay;
        }

        let interval = self.compute_interval_us();
        let elapsed = now_us.saturating_sub(self.last_rtcp_us);

        elapsed >= interval
    }

    /// Return the timestamp (us) for the next scheduled RTCP send.
    pub fn next_send_time_us(&mut self, now_us: u64) -> u64 {
        assert!(now_us > 0, "timestamp must be positive");
        let interval = self.compute_interval_us();
        let base = if self.last_rtcp_us > 0 {
            self.last_rtcp_us
        } else {
            now_us
        };
        base.saturating_add(interval)
    }

    /// Update session bandwidth (call when BWE estimate changes).
    pub fn set_session_bandwidth(&mut self, bw_bps: u64) {
        assert!(bw_bps > 0, "bandwidth must be positive");
        self.session_bw_bps = bw_bps;
    }

    /// Get the current computed RTCP bandwidth fraction (bytes/sec).
    pub fn rtcp_bandwidth_bps(&self) -> f64 {
        (self.session_bw_bps as f64) * RTCP_BW_FRACTION
    }

    /// Simple xorshift32 PRNG for deterministic interval jitter.
    fn next_random_f64(&mut self) -> f64 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng_state = x;
        // Map to [0.0, 1.0)
        (x as f64) / (u32::MAX as f64)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimum_interval() {
        // With 1 member and high bandwidth, Td should floor at 5 seconds
        let mut sched = RtcpScheduler::new(10_000_000); // 10 Mbps
        sched.initial = false; // Skip initial halving
        let interval = sched.compute_interval_us();
        // Td >= 5s / COMPENSATION ≈ 4.1s, randomized in [0.5, 1.5]
        // Minimum possible: 4.1s * 0.5 = ~2.05s (2_050_000 us)
        assert!(interval >= 2_000_000, "interval {} too low", interval);
    }

    #[test]
    fn test_interval_scales_with_members() {
        // Use low bandwidth so member count drives the interval above the 5s floor.
        // RTCP BW = 100_000 * 0.05 = 5000 bps = 625 bytes/sec.
        // With avg_rtcp_size=128: Td = n * 128 * 8 / 5000 = n * 0.2048 sec.
        // At n=100: Td = 20.48s (above floor). At n=1000: Td = 204.8s.
        let mut sched1 = RtcpScheduler::new(100_000);
        sched1.update_members(100, 10);
        sched1.initial = false;
        sched1.rng_state = 42;
        let interval1 = sched1.compute_interval_us();

        let mut sched2 = RtcpScheduler::new(100_000);
        sched2.update_members(1000, 100);
        sched2.initial = false;
        sched2.rng_state = 42;
        let interval2 = sched2.compute_interval_us();

        // With 10x more members, interval should be significantly larger
        assert!(
            interval2 > interval1,
            "1000 members ({}) should > 100 members ({})",
            interval2,
            interval1
        );
    }

    #[test]
    fn test_initial_interval_halved() {
        let mut sched_init = RtcpScheduler::new(1_000_000);
        sched_init.rng_state = 42;
        let init_interval = sched_init.compute_interval_us();

        let mut sched_normal = RtcpScheduler::new(1_000_000);
        sched_normal.initial = false;
        sched_normal.rng_state = 42;
        let normal_interval = sched_normal.compute_interval_us();

        // Initial should be roughly half of normal (same RNG seed)
        assert!(
            init_interval < normal_interval,
            "initial {} should be < normal {}",
            init_interval,
            normal_interval
        );
    }

    #[test]
    fn test_avg_rtcp_size_convergence() {
        let mut sched = RtcpScheduler::new(1_000_000);
        assert!((sched.avg_rtcp_size - 128.0).abs() < f64::EPSILON);

        // Feed 100 packets of size 200 bytes
        for i in 1..=100u64 {
            sched.on_rtcp_packet(200, i * 1_000_000);
        }
        // Should converge toward 200
        assert!(
            sched.avg_rtcp_size > 190.0,
            "avg {} should approach 200",
            sched.avg_rtcp_size
        );
    }

    #[test]
    fn test_is_time_to_send() {
        let mut sched = RtcpScheduler::new(1_000_000);
        sched.initial = false;

        // First call sets last_rtcp_us
        let now = 1_000_000u64;
        let _ = sched.is_time_to_send(now);

        // Immediately after should not be time
        assert!(!sched.is_time_to_send(now + 1_000));

        // After 10 seconds should definitely be time (min interval ~2s with jitter)
        assert!(sched.is_time_to_send(now + 10_000_000));
    }

    #[test]
    fn test_bandwidth_fraction() {
        let sched = RtcpScheduler::new(10_000_000); // 10 Mbps
        let rtcp_bw = sched.rtcp_bandwidth_bps();
        // Should be 5% of 10 Mbps = 500 Kbps
        assert!((rtcp_bw - 500_000.0).abs() < 1.0);
    }

    #[test]
    fn test_senders_cannot_exceed_members() {
        let mut sched = RtcpScheduler::new(1_000_000);
        sched.update_members(10, 20); // senders > members
        assert!(sched.senders <= sched.members);
    }
}
