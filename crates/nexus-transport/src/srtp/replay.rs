//! Replay protection using sliding window.
//!
//! RFC 3711 Section 3.3.2 - Replay protection prevents
//! attackers from re-injecting captured packets.
//!
//! Uses a 64-bit sliding window bitmap for efficient
//! O(1) duplicate detection.

use super::error::SrtpError;

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

const _: () = assert!(
    super::REPLAY_WINDOW_SIZE <= 64,
    "window size must fit in u64 bitmap"
);

/// Replay protection state.
///
/// Implements RFC 3711 sliding window algorithm.
/// Uses a 64-bit bitmap for efficient packet tracking.
#[derive(Debug, Clone)]
pub struct ReplayProtection {
    /// Highest received packet index.
    highest: u64,
    
    /// Sliding window bitmap (64 packets).
    /// Bit i is set if packet (highest - i) was received.
    window: u64,
    
    /// Window size (default 64).
    window_size: u64,
    
    /// Whether replay protection is enabled.
    enabled: bool,
    
    /// Statistics: total packets checked.
    packets_checked: u64,
    
    /// Statistics: replays detected.
    replays_detected: u64,
}

impl ReplayProtection {
    /// Create new replay protection with default window size.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            window: 0,
            window_size: super::REPLAY_WINDOW_SIZE,
            enabled: true,
            packets_checked: 0,
            replays_detected: 0,
        }
    }
    
    /// Create with custom window size.
    ///
    /// Window size is clamped to 64 (bitmap size).
    ///
    /// # TigerStyle
    /// - Size clamped to 64 maximum
    pub const fn with_window_size(size: u64) -> Self {
        let size = if size > 64 { 64 } else { size };
        Self {
            highest: 0,
            window: 0,
            window_size: size,
            enabled: true,
            packets_checked: 0,
            replays_detected: 0,
        }
    }
    
    /// Create disabled (for testing).
    pub const fn disabled() -> Self {
        Self {
            highest: 0,
            window: 0,
            window_size: super::REPLAY_WINDOW_SIZE,
            enabled: false,
            packets_checked: 0,
            replays_detected: 0,
        }
    }
    
    /// Check if packet index is valid (not a replay).
    ///
    /// Does NOT update state - call `accept()` after successful decryption.
    ///
    /// # TigerStyle
    /// - ≥2 assertions
    pub fn check(&mut self, index: u64) -> Result<(), SrtpError> {
        self.packets_checked += 1;
        
        if !self.enabled {
            return Ok(());
        }
        
        // First packet - always accept
        if self.is_first_packet() {
            return Ok(());
        }
        
        // Validate index against window
        self.validate_index(index)
    }
    
    /// Check if this is the first packet.
    #[inline]
    fn is_first_packet(&self) -> bool {
        self.highest == 0 && self.window == 0
    }
    
    /// Validate index against replay window.
    fn validate_index(&mut self, index: u64) -> Result<(), SrtpError> {
        // Packet is newer than highest - always OK
        if index > self.highest {
            return Ok(());
        }
        
        // Packet is too old (outside window)
        let delta = self.highest - index;
        if delta >= self.window_size {
            self.replays_detected += 1;
            return Err(SrtpError::ReplayDetected);
        }
        
        // Check if already received (bit set in window)
        self.check_window_bit(delta)
    }
    
    /// Check if bit is set in replay window.
    #[inline]
    fn check_window_bit(&mut self, delta: u64) -> Result<(), SrtpError> {
        assert!(delta < 64, "delta must be within bitmap size");
        
        let bit = 1u64 << delta;
        if (self.window & bit) != 0 {
            self.replays_detected += 1;
            return Err(SrtpError::ReplayDetected);
        }
        
        Ok(())
    }
    
    /// Accept packet (update state after successful decryption).
    ///
    /// Must be called after `check()` returns Ok and packet is authenticated.
    ///
    /// # TigerStyle
    /// - Window shift bounded to 64
    pub fn accept(&mut self, index: u64) {
        if !self.enabled {
            return;
        }
        
        // First packet
        if self.is_first_packet() {
            self.accept_first_packet(index);
            return;
        }
        
        if index > self.highest {
            // New packet is ahead - shift window
            self.accept_newer_packet(index);
        } else {
            // Packet within window - set corresponding bit
            self.accept_older_packet(index);
        }
    }
    
    /// Accept the first packet.
    #[inline]
    fn accept_first_packet(&mut self, index: u64) {
        assert!(self.highest == 0 && self.window == 0);
        
        self.highest = index;
        self.window = 1; // Mark index 0 (current) as received
    }
    
    /// Accept packet newer than highest.
    fn accept_newer_packet(&mut self, index: u64) {
        assert!(index > self.highest);
        
        let shift = index - self.highest;
        if shift >= 64 {
            // Completely new window
            self.window = 1;
        } else {
            // Shift and set bit 0
            self.window = (self.window << shift) | 1;
        }
        self.highest = index;
    }
    
    /// Accept packet within replay window.
    fn accept_older_packet(&mut self, index: u64) {
        assert!(index <= self.highest);
        
        let delta = self.highest - index;
        if delta < 64 {
            self.window |= 1u64 << delta;
        }
    }
    
    /// Combined check and accept (for convenience).
    ///
    /// Only use when authentication is guaranteed (e.g., after AEAD decrypt).
    pub fn check_and_accept(&mut self, index: u64) -> Result<(), SrtpError> {
        self.check(index)?;
        self.accept(index);
        Ok(())
    }
    
    /// Get highest received index.
    #[inline]
    pub const fn highest(&self) -> u64 {
        self.highest
    }
    
    /// Get statistics.
    #[inline]
    pub const fn stats(&self) -> (u64, u64) {
        (self.packets_checked, self.replays_detected)
    }
    
    /// Reset state.
    pub fn reset(&mut self) {
        self.highest = 0;
        self.window = 0;
        self.packets_checked = 0;
        self.replays_detected = 0;
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic Replay Protection Tests
    // ========================================================================

    #[test]
    fn test_first_packet() {
        let mut rp = ReplayProtection::new();
        assert!(rp.check(1).is_ok());
        rp.accept(1);
        assert_eq!(rp.highest(), 1);
    }

    #[test]
    fn test_sequential_packets() {
        let mut rp = ReplayProtection::new();
        
        for i in 1..=100 {
            assert!(rp.check(i).is_ok());
            rp.accept(i);
        }
        
        assert_eq!(rp.highest(), 100);
        let (checked, replays) = rp.stats();
        assert_eq!(checked, 100);
        assert_eq!(replays, 0);
    }

    #[test]
    fn test_replay_detected() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 10
        rp.check_and_accept(10).unwrap();
        
        // Accept packet 15
        rp.check_and_accept(15).unwrap();
        
        // Try to replay packet 10 (within window)
        assert_eq!(rp.check(10), Err(SrtpError::ReplayDetected));
    }

    #[test]
    fn test_old_packet_outside_window() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 100
        rp.check_and_accept(100).unwrap();
        
        // Packet 30 is outside window (100 - 30 = 70 >= 64)
        assert_eq!(rp.check(30), Err(SrtpError::ReplayDetected));
    }

    #[test]
    fn test_old_packet_inside_window() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 100
        rp.check_and_accept(100).unwrap();
        
        // Packet 50 is inside window (100 - 50 = 50 < 64) and not seen
        assert!(rp.check(50).is_ok());
        rp.accept(50);
        
        // Now it's a replay
        assert_eq!(rp.check(50), Err(SrtpError::ReplayDetected));
    }

    #[test]
    fn test_out_of_order_packets() {
        let mut rp = ReplayProtection::new();
        
        // Receive packets out of order
        rp.check_and_accept(5).unwrap();
        rp.check_and_accept(3).unwrap();
        rp.check_and_accept(8).unwrap();
        rp.check_and_accept(1).unwrap();
        rp.check_and_accept(10).unwrap();
        
        assert_eq!(rp.highest(), 10);
        
        // All should be replays now
        assert!(rp.check(5).is_err());
        assert!(rp.check(3).is_err());
        assert!(rp.check(8).is_err());
    }

    #[test]
    fn test_window_slide() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 1
        rp.check_and_accept(1).unwrap();
        
        // Jump far ahead (beyond window)
        rp.check_and_accept(100).unwrap();
        
        // Packet 1 is now too old
        assert_eq!(rp.check(1), Err(SrtpError::ReplayDetected));
        
        // But packet 50 is in new window and not received
        assert!(rp.check(50).is_ok());
    }

    #[test]
    fn test_disabled() {
        let mut rp = ReplayProtection::disabled();
        
        // Accept same packet multiple times
        assert!(rp.check_and_accept(5).is_ok());
        assert!(rp.check_and_accept(5).is_ok());
        assert!(rp.check_and_accept(5).is_ok());
    }

    #[test]
    fn test_reset() {
        let mut rp = ReplayProtection::new();
        
        rp.check_and_accept(100).unwrap();
        assert_eq!(rp.highest(), 100);
        
        rp.reset();
        assert_eq!(rp.highest(), 0);
        
        // Can accept 100 again
        assert!(rp.check_and_accept(100).is_ok());
    }

    #[test]
    fn test_large_jump() {
        let mut rp = ReplayProtection::new();
        
        rp.check_and_accept(1).unwrap();
        
        // Jump by exactly 64 (window boundary)
        rp.check_and_accept(65).unwrap();
        
        // Packet 1 should be outside window now (65 - 1 = 64 >= 64)
        assert!(rp.check(1).is_err());
        
        // Packet 2 is at boundary (65 - 2 = 63 < 64), so it's inside window and not seen
        assert!(rp.check(2).is_ok());
    }

    // ========================================================================
    // Sliding Window Tests (64 packets)
    // ========================================================================

    #[test]
    fn test_window_size_constant() {
        assert_eq!(super::super::REPLAY_WINDOW_SIZE, 64,
            "REPLAY_WINDOW_SIZE should be 64");
    }

    #[test]
    fn test_window_size_clamping() {
        // Window size should be clamped to 64
        let rp = ReplayProtection::with_window_size(100);
        assert_eq!(rp.window_size, 64);
        
        // Smaller sizes are allowed
        let rp = ReplayProtection::with_window_size(32);
        assert_eq!(rp.window_size, 32);
    }

    #[test]
    fn test_full_window_tracking() {
        let mut rp = ReplayProtection::new();
        
        // Fill the entire window (accept every packet from 1 to 64)
        for i in 1..=64 {
            assert!(rp.check_and_accept(i).is_ok(), 
                "Packet {} should be accepted", i);
        }
        
        assert_eq!(rp.highest(), 64);
        
        // All 64 packets should now be replays
        for i in 1..=64 {
            assert!(rp.check(i).is_err(),
                "Packet {} should be detected as replay", i);
        }
    }

    // ========================================================================
    // Sequence Number Rollover Tests (16-bit, wraps at 65536)
    // ========================================================================

    #[test]
    fn test_large_sequence_numbers() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet near u16 max
        let near_max = 65535u64;
        rp.check_and_accept(near_max).unwrap();
        
        assert_eq!(rp.highest(), near_max);
        
        // Packet after rollover
        rp.check_and_accept(65536).unwrap();
        assert_eq!(rp.highest(), 65536);
    }

    // ========================================================================
    // Duplicate Packet Detection Tests
    // ========================================================================

    #[test]
    fn test_immediate_duplicate() {
        let mut rp = ReplayProtection::new();
        
        rp.check_and_accept(42).unwrap();
        
        // Immediate duplicate
        assert_eq!(rp.check(42), Err(SrtpError::ReplayDetected));
    }

    #[test]
    fn test_duplicate_after_other_packets() {
        let mut rp = ReplayProtection::new();
        
        rp.check_and_accept(10).unwrap();
        rp.check_and_accept(11).unwrap();
        rp.check_and_accept(12).unwrap();
        
        // Duplicate of earlier packet
        assert_eq!(rp.check(10), Err(SrtpError::ReplayDetected));
        assert_eq!(rp.check(11), Err(SrtpError::ReplayDetected));
        assert_eq!(rp.check(12), Err(SrtpError::ReplayDetected));
    }

    // ========================================================================
    // Window Advancement Tests
    // ========================================================================

    #[test]
    fn test_window_slides_forward() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 1
        rp.check_and_accept(1).unwrap();
        
        // Accept packet 70 (beyond window from 1)
        rp.check_and_accept(70).unwrap();
        
        // Packet 1 should now be too old
        assert!(rp.check(1).is_err());
        
        // Packet 7 is at edge (70 - 7 = 63 < 64)
        assert!(rp.check(7).is_ok());
    }

    #[test]
    fn test_window_completely_new() {
        let mut rp = ReplayProtection::new();
        
        // Accept packet 1
        rp.check_and_accept(1).unwrap();
        
        // Jump far beyond (completely new window)
        rp.check_and_accept(200).unwrap();
        
        // Old window completely replaced
        for i in 1..100 {
            assert!(rp.check(i).is_err(),
                "Packet {} should be too old", i);
        }
        
        // Only 137-200 are in new window (200 - 63 = 137)
        for i in 137..200 {
            assert!(rp.check(i).is_ok(),
                "Packet {} should be in window and unset", i);
        }
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats_tracking() {
        let mut rp = ReplayProtection::new();
        
        // Check 10 packets, accept all
        for i in 1..=10 {
            rp.check_and_accept(i).unwrap();
        }
        
        let (checked, replays) = rp.stats();
        assert_eq!(checked, 10);
        assert_eq!(replays, 0);
        
        // Try 5 replays
        for i in 1..=5 {
            let _ = rp.check(i);
        }
        
        let (checked, replays) = rp.stats();
        assert_eq!(checked, 15);
        assert_eq!(replays, 5);
    }

    // ========================================================================
    // Default Implementation Test
    // ========================================================================

    #[test]
    fn test_default() {
        let rp = ReplayProtection::default();
        
        assert_eq!(rp.highest(), 0);
        assert!(rp.enabled);
        assert_eq!(rp.window_size, super::super::REPLAY_WINDOW_SIZE);
    }

    // ========================================================================
    // Thread Safety Conceptual Tests
    // ========================================================================

    #[test]
    fn test_replay_protection_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        
        // Compile-time check that ReplayProtection is Send + Sync
        assert_send::<ReplayProtection>();
        assert_sync::<ReplayProtection>();
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_packet_zero_index() {
        let mut rp = ReplayProtection::new();
        
        // Packet index 0 should be valid
        assert!(rp.check(0).is_ok());
        rp.accept(0);
        
        assert_eq!(rp.highest(), 0);
        
        // Packet 1 should also work
        assert!(rp.check(1).is_ok());
    }

    #[test]
    fn test_sparse_packet_acceptance() {
        let mut rp = ReplayProtection::new();
        
        // Accept sparse packets
        rp.check_and_accept(1).unwrap();
        rp.check_and_accept(10).unwrap();
        rp.check_and_accept(20).unwrap();
        rp.check_and_accept(30).unwrap();
        
        // All accepted packets should be replays
        assert!(rp.check(1).is_err());
        assert!(rp.check(10).is_err());
        assert!(rp.check(20).is_err());
        assert!(rp.check(30).is_err());
        
        // Unaccepted packets in window should be valid
        assert!(rp.check(25).is_ok());
        assert!(rp.check(28).is_ok());
    }
}
