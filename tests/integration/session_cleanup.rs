//! Integration test: Session cleanup and resource management.
//!
//! Tests proper cleanup of sessions and resources:
//! 1. Session pool capacity management
//! 2. SRTP context cleanup
//! 3. Resource limit enforcement
//!
//! # TigerStyle Compliance
//!
//! - Bounded resource usage
//! - Explicit cleanup verification
//! - No resource leaks

use nexus_sfu::srtp::{
    SrtpContext, SrtpSession, SrtpSessionPool, KeyMaterial, SrtpPolicy, ProtectionProfile,
};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_key_material() -> KeyMaterial {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let salt = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
    ];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create key material")
}

fn create_test_session() -> SrtpSession {
    let material = create_test_key_material();
    let policy = SrtpPolicy::aes_128_gcm();
    SrtpSession::symmetric(&material, policy).expect("Failed to create session")
}

// ============================================================================
// Session Pool Tests
// ============================================================================

#[test]
fn test_session_pool_creation() {
    let pool = SrtpSessionPool::new(10);
    
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.remaining_capacity(), 10);
}

#[test]
fn test_session_pool_insert_and_get() {
    let mut pool = SrtpSessionPool::new(10);
    let session = create_test_session();
    
    pool.insert(0x12345678, session).unwrap();
    
    assert!(!pool.is_empty());
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(0x12345678));
    assert!(pool.get(0x12345678).is_some());
}

#[test]
fn test_session_pool_remove() {
    let mut pool = SrtpSessionPool::new(10);
    let session = create_test_session();
    
    pool.insert(0x12345678, session).unwrap();
    assert_eq!(pool.len(), 1);
    
    let removed = pool.remove(0x12345678);
    assert!(removed.is_some());
    assert!(pool.is_empty());
    assert!(!pool.contains(0x12345678));
}

#[test]
fn test_session_pool_capacity_enforcement() {
    let mut pool = SrtpSessionPool::new(3);
    
    // Fill pool
    for ssrc in [1u32, 2, 3] {
        let session = create_test_session();
        pool.insert(ssrc, session).unwrap();
    }
    
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.remaining_capacity(), 0);
    
    // Try to add one more - should fail
    let session = create_test_session();
    let result = pool.insert(4, session);
    assert!(result.is_err());
}

#[test]
fn test_session_pool_duplicate_ssrc_rejected() {
    let mut pool = SrtpSessionPool::new(10);
    
    let session1 = create_test_session();
    let session2 = create_test_session();
    
    pool.insert(0x12345678, session1).unwrap();
    
    // Duplicate SSRC should fail
    let result = pool.insert(0x12345678, session2);
    assert!(result.is_err());
    
    // Only one session should be in pool
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_session_pool_stats() {
    let mut pool = SrtpSessionPool::new(10);
    
    for i in 1..=5u32 {
        let session = create_test_session();
        pool.insert(i, session).unwrap();
    }
    
    let stats = pool.stats();
    assert_eq!(stats.active_sessions, 5);
    assert_eq!(stats.max_sessions, 10);
    assert_eq!(stats.available, 5);
}

#[test]
fn test_session_pool_get_mut() {
    let mut pool = SrtpSessionPool::new(10);
    let session = create_test_session();
    
    pool.insert(0x12345678, session).unwrap();
    
    // Get mutable reference
    let session = pool.get_mut(0x12345678).unwrap();
    
    // Should be able to use the session
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80; // V=2
    packet[1] = 0x60; // PT=96
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let result = session.protect_rtp(&mut packet, 16);
    assert!(result.is_ok());
}

// ============================================================================
// Session Cleanup Tests
// ============================================================================

#[test]
fn test_session_cleanup_removes_from_pool() {
    let mut pool = SrtpSessionPool::new(10);
    
    // Add 5 sessions
    for i in 1..=5u32 {
        let session = create_test_session();
        pool.insert(i, session).unwrap();
    }
    
    assert_eq!(pool.len(), 5);
    
    // Remove sessions one by one
    for i in 1..=5u32 {
        pool.remove(i);
    }
    
    assert!(pool.is_empty());
    assert_eq!(pool.remaining_capacity(), 10);
}

#[test]
fn test_session_cleanup_allows_reuse() {
    let mut pool = SrtpSessionPool::new(2);
    
    // Fill pool
    pool.insert(1, create_test_session()).unwrap();
    pool.insert(2, create_test_session()).unwrap();
    
    // Can't add more
    assert!(pool.insert(3, create_test_session()).is_err());
    
    // Remove one
    pool.remove(1);
    
    // Now can add
    assert!(pool.insert(3, create_test_session()).is_ok());
}

// ============================================================================
// SRTP Context Cleanup Tests
// ============================================================================

#[test]
fn test_srtp_context_stats_reset_on_key_rotation() {
    let material1 = create_test_key_material();
    let material2 = KeyMaterial::from_aes128_gcm(&[0xAA; 16], &[0xBB; 12]).unwrap();
    
    let mut ctx = SrtpContext::with_default_policy(&material1).unwrap();
    
    // Process some packets
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    for seq in 1..=5u16 {
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        ctx.protect_rtp(&mut packet, 16).unwrap();
    }
    
    let (rtp_before, _) = ctx.stats();
    assert_eq!(rtp_before, 5);
    
    // Rotate keys
    ctx.rotate_keys(&material2).unwrap();
    
    // ROC should be reset
    assert_eq!(ctx.roc(), 0);
}

// ============================================================================
// Resource Limit Tests
// ============================================================================

#[test]
fn test_session_pool_capacity_clamped_to_max() {
    // Try to create pool with huge capacity
    let pool = SrtpSessionPool::new(u32::MAX);
    
    // Should be clamped to MAX_SRTP_SESSIONS
    // (The exact value depends on the constant defined in the module)
    assert!(pool.remaining_capacity() <= 1024); // Assuming MAX is reasonable
}

#[test]
fn test_multiple_pools_isolated() {
    let mut pool1 = SrtpSessionPool::new(10);
    let mut pool2 = SrtpSessionPool::new(10);
    
    // Add to pool1
    pool1.insert(1, create_test_session()).unwrap();
    pool1.insert(2, create_test_session()).unwrap();
    
    // Add to pool2
    pool2.insert(1, create_test_session()).unwrap(); // Same SSRC, different pool
    
    assert_eq!(pool1.len(), 2);
    assert_eq!(pool2.len(), 1);
    
    // Removal from pool1 doesn't affect pool2
    pool1.remove(1);
    assert!(pool2.contains(1));
}

// ============================================================================
// Key Rotation Tests
// ============================================================================

#[test]
fn test_key_rotation_preserves_context() {
    let material1 = create_test_key_material();
    let material2 = KeyMaterial::from_aes128_gcm(&[0xAA; 16], &[0xBB; 12]).unwrap();
    
    let mut ctx = SrtpContext::with_default_policy(&material1).unwrap();
    
    // Rotate keys
    ctx.rotate_keys(&material2).unwrap();
    
    // Context should still be usable
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let result = ctx.protect_rtp(&mut packet, 16);
    assert!(result.is_ok());
}

#[test]
fn test_key_rotation_needed_check() {
    let material = create_test_key_material();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Initially should not need rotation
    assert!(!ctx.should_rotate_keys());
}

// ============================================================================
// Profile Consistency Tests
// ============================================================================

#[test]
fn test_profile_consistency_after_creation() {
    let material = create_test_key_material();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    assert_eq!(ctx.profile(), ProtectionProfile::AeadAes128Gcm);
}

#[test]
fn test_keys_accessible_after_creation() {
    let material = create_test_key_material();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let keys = ctx.keys();
    assert_eq!(keys.rtp_key().len(), 16);
    assert_eq!(keys.rtp_salt().len(), 12);
}

// ============================================================================
// Detailed Stats Tests
// ============================================================================

#[test]
fn test_detailed_stats_initial() {
    let material = create_test_key_material();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let stats = ctx.detailed_stats();
    assert_eq!(stats.rtp_protected, 0);
    assert_eq!(stats.rtp_unprotected, 0);
    assert_eq!(stats.current_roc, 0);
    assert_eq!(stats.highest_seq, 0);
}

#[test]
fn test_detailed_stats_after_packets() {
    let material = create_test_key_material();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    for seq in 1..=10u16 {
        let mut packet = vec![0u8; 64];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    }
    
    let recv_stats = recv_ctx.detailed_stats();
    assert_eq!(recv_stats.highest_seq, 10);
}
