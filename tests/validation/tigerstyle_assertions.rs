//! Validation test: TigerStyle assertions verification.
//!
//! Tests that TigerStyle assertions work correctly:
//! 1. Precondition assertions fail on invalid input
//! 2. Postcondition assertions verify correct output
//! 3. Invariant assertions maintain consistency
//!
//! # TigerStyle Principles
//!
//! - Every function has ≥2 assertions
//! - All assertions are meaningful
//! - Assertions catch bugs early

use nexus_webrtc::sdp::{
    SdpParser, SessionDescription, MediaDescription, MediaType, TransportProtocol,
    MAX_MEDIA_SECTIONS, MAX_SDP_SIZE,
};
use nexus_webrtc::sdp::attributes::{DtlsFingerprint, RtpCodec};
use nexus_webrtc::sdp::media::Mid;
use nexus_sfu::srtp::{SrtpContext, SrtpSession, SrtpSessionPool, KeyMaterial, SrtpPolicy};
use nexus_sfu::ice::{IceAgent, IceRole};
use std::panic;

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_key_material() -> KeyMaterial {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create key material")
}

fn valid_fingerprint() -> DtlsFingerprint {
    DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap()
}

// ============================================================================
// Precondition Tests
// ============================================================================

#[test]
fn test_srtp_protect_precondition_positive_length() {
    let material = create_test_key_material();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Zero-length packet should trigger assertion
    let mut packet = vec![0u8; 64];
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        ctx.protect_rtp(&mut packet, 0)
    }));
    
    assert!(result.is_err(), "Zero-length packet should trigger precondition assertion");
}

#[test]
fn test_srtp_protect_precondition_buffer_size() {
    let material = create_test_key_material();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Buffer too small for auth tag
    let mut packet = vec![0u8; 16]; // No room for 16-byte tag
    packet[0] = 0x80;
    
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        ctx.protect_rtp(&mut packet, 16)
    }));
    
    assert!(result.is_err(), "Buffer without room for tag should trigger assertion");
}

// ============================================================================
// Postcondition Tests
// ============================================================================

#[test]
fn test_srtp_protect_postcondition_size_increase() {
    let material = create_test_key_material();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let original_len = 16;
    let protected_len = ctx.protect_rtp(&mut packet, original_len).unwrap();
    
    // Postcondition: protected packet MUST be larger
    assert!(protected_len > original_len, "Protected packet must be larger");
    
    // Postcondition: size increase MUST equal auth tag size
    assert_eq!(protected_len - original_len, 16, "Size increase must equal auth tag");
}

#[test]
fn test_srtp_unprotect_postcondition_size_decrease() {
    let material = create_test_key_material();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let original_len = 16;
    let protected_len = send_ctx.protect_rtp(&mut packet, original_len).unwrap();
    let unprotected_len = recv_ctx.unprotect_rtp(&mut packet, protected_len).unwrap();
    
    // Postcondition: unprotected packet MUST be smaller than protected
    assert!(unprotected_len < protected_len, "Unprotected must be smaller");
    
    // Postcondition: unprotected size MUST match original
    assert_eq!(unprotected_len, original_len, "Unprotected must match original");
}

// ============================================================================
// Invariant Tests
// ============================================================================

#[test]
fn test_session_pool_invariant_capacity() {
    let capacity = 50u32;
    let mut pool = SrtpSessionPool::new(capacity);
    
    // Invariant: len + remaining_capacity == max_capacity
    assert_eq!(pool.len() + pool.remaining_capacity(), capacity);
    
    // Add sessions
    for i in 0..25u32 {
        let material = create_test_key_material();
        let session = SrtpSession::symmetric(&material, SrtpPolicy::aes_128_gcm()).unwrap();
        pool.insert(i, session).unwrap();
        
        // Invariant must hold after each insert
        assert_eq!(pool.len() + pool.remaining_capacity(), capacity);
    }
    
    // Remove sessions
    for i in 0..10u32 {
        pool.remove(i);
        
        // Invariant must hold after each remove
        assert_eq!(pool.len() + pool.remaining_capacity(), capacity);
    }
}

#[test]
fn test_sdp_media_count_invariant() {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    
    // Invariant: media_count must equal number of non-None media entries
    for i in 0..5 {
        let mut media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.mid = Some(Mid::new(&i.to_string()));
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        sdp.add_media(media).unwrap();
        
        // Count actual non-None entries
        let actual_count = sdp.media.iter().filter(|m| m.is_some()).count();
        assert_eq!(sdp.media_count as usize, actual_count, "media_count invariant");
    }
}

#[test]
fn test_srtp_context_roc_invariant() {
    let material = create_test_key_material();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Invariant: ROC starts at 0
    assert_eq!(ctx.roc(), 0);
    
    // Process packets
    for seq in 1..=100u16 {
        let mut packet = vec![0u8; 64];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        
        ctx.protect_rtp(&mut packet, 16).unwrap();
        
        // Invariant: ROC should remain 0 for seq < 65536
        assert_eq!(ctx.roc(), 0, "ROC should be 0 before rollover");
    }
}

// ============================================================================
// Bounds Assertion Tests
// ============================================================================

#[test]
fn test_media_sections_bounded() {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    
    // Fill to capacity
    for i in 0..MAX_MEDIA_SECTIONS {
        let mut media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.mid = Some(Mid::new(&i.to_string()));
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        sdp.add_media(media).unwrap();
    }
    
    // Bound assertion: cannot exceed MAX_MEDIA_SECTIONS
    let mut extra = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    extra.mid = Some(Mid::new("extra"));
    let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
    extra.add_codec(codec).unwrap();
    
    let result = sdp.add_media(extra);
    assert!(result.is_err(), "Adding beyond MAX_MEDIA_SECTIONS must fail");
}

// ============================================================================
// Error Path Assertion Tests
// ============================================================================

#[test]
fn test_key_material_validation() {
    // Key too short
    let result = KeyMaterial::from_aes128_gcm(&[0u8; 8], &[0u8; 12]);
    assert!(result.is_err(), "Short key must be rejected");
    
    // Salt too short
    let result = KeyMaterial::from_aes128_gcm(&[0u8; 16], &[0u8; 8]);
    assert!(result.is_err(), "Short salt must be rejected");
    
    // Key too long for AES-128
    let result = KeyMaterial::from_aes128_gcm(&[0u8; 32], &[0u8; 12]);
    assert!(result.is_err(), "Long key for AES-128 must be rejected");
}

#[test]
fn test_sdp_parser_validation() {
    // Invalid version
    let result = SdpParser::parse("v=1\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
    assert!(result.is_err(), "Invalid version must be rejected");
    
    // Malformed line
    let result = SdpParser::parse("v=0\nmalformed line\n");
    assert!(result.is_err(), "Malformed line must be rejected");
}

// ============================================================================
// Stats Consistency Tests
// ============================================================================

#[test]
fn test_stats_increment_correctly() {
    let material = create_test_key_material();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let (initial_send, _) = send_ctx.stats();
    let (initial_recv, _) = recv_ctx.stats();
    
    assert_eq!(initial_send, 0, "Initial send count must be 0");
    assert_eq!(initial_recv, 0, "Initial recv count must be 0");
    
    // Process packets
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
    
    let (final_send, _) = send_ctx.stats();
    let (final_recv, _) = recv_ctx.stats();
    
    assert_eq!(final_send, 10, "Send count must equal packets sent");
    assert_eq!(final_recv, 10, "Recv count must equal packets received");
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_key_derivation_deterministic() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    
    let material1 = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let material2 = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    
    let ctx1 = SrtpContext::with_default_policy(&material1).unwrap();
    let ctx2 = SrtpContext::with_default_policy(&material2).unwrap();
    
    // Same input must produce same keys
    assert_eq!(ctx1.keys().rtp_key(), ctx2.keys().rtp_key(), "Key derivation must be deterministic");
    assert_eq!(ctx1.keys().rtp_salt(), ctx2.keys().rtp_salt(), "Salt derivation must be deterministic");
}

#[test]
fn test_srtp_protect_deterministic_iv() {
    let material = create_test_key_material();
    
    let mut ctx1 = SrtpContext::with_default_policy(&material).unwrap();
    let mut ctx2 = SrtpContext::with_default_policy(&material).unwrap();
    
    // Same packet, same context state, should produce same ciphertext
    let mut packet1 = vec![0u8; 64];
    let mut packet2 = vec![0u8; 64];
    
    for packet in [&mut packet1, &mut packet2] {
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&1u16.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..28].fill(0xAA);
    }
    
    let len1 = ctx1.protect_rtp(&mut packet1, 28).unwrap();
    let len2 = ctx2.protect_rtp(&mut packet2, 28).unwrap();
    
    assert_eq!(len1, len2, "Same input must produce same length");
    assert_eq!(&packet1[..len1], &packet2[..len2], "Same input must produce same ciphertext");
}
