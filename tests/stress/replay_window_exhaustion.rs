//! Stress test: Replay window exhaustion.
//!
//! Tests the SRTP replay protection system under stress:
//! 1. Window boundary behavior
//! 2. Out-of-order packet handling at scale
//! 3. Replay attack detection at high volume
//!
//! # TigerStyle Compliance
//!
//! - Bounded replay window
//! - No false positives
//! - No false negatives

use nexus_sfu::srtp::{SrtpContext, KeyMaterial, SrtpPolicy, ReplayProtection};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_key_material() -> KeyMaterial {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create key material")
}

fn build_rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 12 + payload.len() + 32]; // Room for tag
    packet[0] = 0x80; // V=2
    packet[1] = 0x60; // PT=96
    packet[2..4].copy_from_slice(&seq.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
    packet[12..12 + payload.len()].copy_from_slice(payload);
    packet
}

// ============================================================================
// Replay Protection Unit Tests
// ============================================================================

#[test]
fn test_replay_protection_basic() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // First packet always accepted
    rp.check_and_accept(1).unwrap();
    
    // Replay should be rejected
    assert!(rp.check_and_accept(1).is_err());
}

#[test]
fn test_replay_protection_sequential() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // Sequential packets should all be accepted
    for i in 1..=100u64 {
        rp.check_and_accept(i).unwrap();
    }
    
    let (accepted, rejected) = rp.stats();
    assert_eq!(accepted, 100);
    assert_eq!(rejected, 0);
}

#[test]
fn test_replay_protection_window_boundary() {
    let window_size = 64u16;
    let mut rp = ReplayProtection::with_window_size(window_size);
    
    // Accept packet 100
    rp.check_and_accept(100).unwrap();
    
    // Packets within window should work
    rp.check_and_accept(99).unwrap();
    rp.check_and_accept(50).unwrap();
    rp.check_and_accept(37).unwrap(); // 100 - 64 + 1 = 37
    
    // Packets outside window should be rejected
    assert!(rp.check_and_accept(36).is_err(), "Should reject packet outside window");
}

#[test]
fn test_replay_protection_window_slides() {
    let window_size = 64u16;
    let mut rp = ReplayProtection::with_window_size(window_size);
    
    // Accept packet 1
    rp.check_and_accept(1).unwrap();
    
    // Jump forward
    rp.check_and_accept(100).unwrap();
    
    // Old packet 1 is now outside window
    assert!(rp.check_and_accept(1).is_err(), "Old packet should be rejected");
    
    // But packet 50 should still work
    rp.check_and_accept(50).unwrap();
}

#[test]
fn test_replay_protection_stress_sequential() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // Process 10000 sequential packets
    for i in 1..=10000u64 {
        rp.check_and_accept(i).unwrap();
    }
    
    let (accepted, rejected) = rp.stats();
    assert_eq!(accepted, 10000);
    assert_eq!(rejected, 0);
}

#[test]
fn test_replay_protection_stress_random_order() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // Process packets in chunks with random-ish order
    for chunk in 0..100u64 {
        let base = chunk * 50;
        
        // Process packets within chunk in reverse order
        for i in (0..50u64).rev() {
            // Skip even numbers to simulate packet loss
            if i % 2 == 0 {
                continue;
            }
            rp.check_and_accept(base + i + 1).unwrap();
        }
        
        // Now send the even numbers
        for i in 0..50u64 {
            if i % 2 != 0 {
                continue;
            }
            // Some will be outside window and rejected
            let _ = rp.check_and_accept(base + i + 1);
        }
    }
    
    // Should have processed many packets without panicking
    let (accepted, _) = rp.stats();
    assert!(accepted > 0);
}

// ============================================================================
// SRTP Replay Detection Integration Tests
// ============================================================================

#[test]
fn test_srtp_replay_detection_stress() {
    let material = create_test_key_material();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut replay_attempts = 0u64;
    let mut replay_detected = 0u64;
    
    // Send 500 packets, save copies, try to replay
    for seq in 1..=500u16 {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        
        // Save copy for replay attempt
        let saved = packet[..plen].to_vec();
        
        // First receive succeeds
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        // Try replay every 10th packet
        if seq % 10 == 0 {
            replay_attempts += 1;
            let mut replay = saved;
            if recv_ctx.unprotect_rtp(&mut replay, plen).is_err() {
                replay_detected += 1;
            }
        }
    }
    
    // All replay attempts should be detected
    assert_eq!(replay_detected, replay_attempts, "All replays should be detected");
}

#[test]
fn test_srtp_out_of_order_stress() {
    let material = create_test_key_material();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Prepare 100 packets
    let mut protected: Vec<(Vec<u8>, usize)> = Vec::with_capacity(100);
    
    for seq in 1..=100u16 {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        protected.push((packet[..plen].to_vec(), plen));
    }
    
    // Receive in reverse order (within window)
    // Only last 64 will be in window when receiving packet 100 first
    let mut received = 0;
    for i in (0..100).rev() {
        let (ref packet, len) = protected[i];
        let mut p = packet.clone();
        if recv_ctx.unprotect_rtp(&mut p, len).is_ok() {
            received += 1;
        }
    }
    
    // Some should succeed (within window), some fail (outside window)
    assert!(received >= 64, "At least window_size packets should succeed");
    assert!(received <= 100, "At most all packets should succeed");
}

#[test]
fn test_srtp_late_packet_handling() {
    let material = create_test_key_material();
    let mut policy = SrtpPolicy::aes_128_gcm();
    policy.window_size = 64;
    let mut send_ctx = SrtpContext::new(&material, policy).unwrap();
    let mut recv_ctx = SrtpContext::new(&material, policy).unwrap();
    
    // Send packets 1-100
    let mut protected: Vec<(Vec<u8>, usize)> = Vec::new();
    for seq in 1..=100u16 {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        protected.push((packet[..plen].to_vec(), plen));
    }
    
    // Receive packet 100 first (sets high water mark)
    let (ref p100, len100) = protected[99];
    let mut packet = p100.clone();
    recv_ctx.unprotect_rtp(&mut packet, len100).unwrap();
    
    // Packets 37-99 should work (within window of 64 from 100)
    for i in 36..99 {
        let (ref p, len) = protected[i];
        let mut packet = p.clone();
        assert!(recv_ctx.unprotect_rtp(&mut packet, len).is_ok(), 
            "Packet {} should be within window", i + 1);
    }
    
    // Packets 1-36 should fail (outside window)
    for i in 0..36 {
        let (ref p, len) = protected[i];
        let mut packet = p.clone();
        assert!(recv_ctx.unprotect_rtp(&mut packet, len).is_err(),
            "Packet {} should be outside window", i + 1);
    }
}

// ============================================================================
// Replay Window Disabled Tests
// ============================================================================

#[test]
fn test_replay_disabled_allows_duplicates() {
    let material = create_test_key_material();
    let policy = SrtpPolicy::aes_128_gcm().with_replay_disabled();
    let mut send_ctx = SrtpContext::new(&material, policy).unwrap();
    let mut recv_ctx = SrtpContext::new(&material, policy).unwrap();
    
    let mut packet = build_rtp_packet(1, 0x12345678, b"test");
    let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
    let saved = packet[..plen].to_vec();
    
    // First receive
    recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    
    // Second receive should also work (replay disabled)
    let mut replay = saved.clone();
    assert!(recv_ctx.unprotect_rtp(&mut replay, plen).is_ok());
    
    // Third receive should also work
    let mut replay = saved;
    assert!(recv_ctx.unprotect_rtp(&mut replay, plen).is_ok());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_replay_protection_sequence_zero() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // Sequence 0 should work
    rp.check_and_accept(0).unwrap();
    
    // Replay should fail
    assert!(rp.check_and_accept(0).is_err());
}

#[test]
fn test_replay_protection_large_jump() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    rp.check_and_accept(1).unwrap();
    
    // Large jump forward
    rp.check_and_accept(1000000).unwrap();
    
    // Old packets now completely outside window
    assert!(rp.check_and_accept(1).is_err());
    assert!(rp.check_and_accept(999900).is_err());
    
    // Recent should work
    rp.check_and_accept(999999).unwrap();
    rp.check_and_accept(999937).unwrap();
}

#[test]
fn test_replay_protection_fill_entire_window() {
    let window_size = 64u16;
    let mut rp = ReplayProtection::with_window_size(window_size);
    
    // Set high water mark
    rp.check_and_accept(100).unwrap();
    
    // Fill entire window with packets in random order
    let mut packets: Vec<u64> = (37..100).collect();
    
    // Shuffle-like pattern
    for i in (0..packets.len()).step_by(2) {
        if i + 1 < packets.len() {
            packets.swap(i, i + 1);
        }
    }
    
    for seq in packets {
        rp.check_and_accept(seq).unwrap();
    }
    
    // All slots in window should be filled
    // Trying any again should fail
    for seq in 37..=100u64 {
        assert!(rp.check_and_accept(seq).is_err());
    }
}

// ============================================================================
// Stats Accuracy Tests
// ============================================================================

#[test]
fn test_replay_protection_stats_accurate() {
    let mut rp = ReplayProtection::with_window_size(64);
    
    // Accept 50 unique packets
    for i in 1..=50u64 {
        rp.check_and_accept(i).unwrap();
    }
    
    // Try 20 replays
    for i in 1..=20u64 {
        let _ = rp.check_and_accept(i);
    }
    
    let (accepted, rejected) = rp.stats();
    assert_eq!(accepted, 50);
    assert_eq!(rejected, 20);
}
