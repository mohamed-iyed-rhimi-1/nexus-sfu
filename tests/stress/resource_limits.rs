//! Stress test: Resource limits and bounded operations.
//!
//! Tests system behavior under stress conditions:
//! 1. Maximum media section handling
//! 2. Maximum candidate handling
//! 3. Session pool saturation
//!
//! # TigerStyle Compliance
//!
//! - All operations bounded
//! - Graceful degradation under load
//! - No panics on resource exhaustion

use nexus_webrtc::sdp::{
    SdpParser, SessionDescription, MediaDescription, MediaType, TransportProtocol,
    MAX_MEDIA_SECTIONS,
};
use nexus_webrtc::sdp::attributes::{DtlsFingerprint, RtpCodec, IceCandidate};
use nexus_webrtc::sdp::media::Mid;
use nexus_sfu::srtp::{SrtpSession, SrtpSessionPool, KeyMaterial, SrtpPolicy};
use nexus_sfu::ice::{IceAgent, IceRole};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_key_material() -> KeyMaterial {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create key material")
}

fn create_test_session() -> SrtpSession {
    let material = create_test_key_material();
    let policy = SrtpPolicy::aes_128_gcm();
    SrtpSession::symmetric(&material, policy).expect("Failed to create session")
}

fn valid_fingerprint() -> DtlsFingerprint {
    DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap()
}

// ============================================================================
// Media Section Limit Tests
// ============================================================================

#[test]
fn test_max_media_sections_accepted() {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    
    // Add exactly MAX_MEDIA_SECTIONS
    for i in 0..MAX_MEDIA_SECTIONS {
        let mut media = MediaDescription::new(
            if i % 2 == 0 { MediaType::Audio } else { MediaType::Video },
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.mid = Some(Mid::new(&i.to_string()));
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        sdp.add_media(media).unwrap();
    }
    
    assert_eq!(sdp.media_count as usize, MAX_MEDIA_SECTIONS);
    
    // Roundtrip should work
    let serialized = sdp.to_sdp();
    let parsed = SdpParser::parse(&serialized).unwrap();
    assert_eq!(parsed.media_count as usize, MAX_MEDIA_SECTIONS);
}

#[test]
fn test_exceed_max_media_sections_rejected() {
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
    
    // Try to add one more
    let mut extra = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    extra.mid = Some(Mid::new("extra"));
    let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
    extra.add_codec(codec).unwrap();
    
    let result = sdp.add_media(extra);
    assert!(result.is_err(), "Should reject exceeding max media sections");
}

#[test]
fn test_parsing_too_many_media_sections_rejected() {
    let mut sdp_string = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
    sdp_string.push_str("a=ice-ufrag:testufrag\na=ice-pwd:testpwd1234567890123456\n");
    sdp_string.push_str("a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n");
    
    // Add one more than max
    for i in 0..=MAX_MEDIA_SECTIONS {
        sdp_string.push_str(&format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:{}\n", i));
    }
    
    let result = SdpParser::parse(&sdp_string);
    assert!(result.is_err(), "Parser should reject too many media sections");
}

// ============================================================================
// Session Pool Stress Tests
// ============================================================================

#[test]
fn test_session_pool_fill_to_capacity() {
    let capacity = 100u32;
    let mut pool = SrtpSessionPool::new(capacity);
    
    // Fill pool
    for i in 0..capacity {
        let session = create_test_session();
        pool.insert(i, session).unwrap();
    }
    
    assert_eq!(pool.len(), capacity);
    assert_eq!(pool.remaining_capacity(), 0);
    
    // Verify all sessions accessible
    for i in 0..capacity {
        assert!(pool.contains(i));
        assert!(pool.get(i).is_some());
    }
}

#[test]
fn test_session_pool_at_capacity_rejects_new() {
    let capacity = 50u32;
    let mut pool = SrtpSessionPool::new(capacity);
    
    // Fill pool
    for i in 0..capacity {
        pool.insert(i, create_test_session()).unwrap();
    }
    
    // All new inserts should fail
    for i in capacity..(capacity + 10) {
        let result = pool.insert(i, create_test_session());
        assert!(result.is_err(), "Should reject insert at capacity");
    }
    
    // Pool should still be at capacity
    assert_eq!(pool.len(), capacity);
}

#[test]
fn test_session_pool_remove_and_refill() {
    let capacity = 100u32;
    let mut pool = SrtpSessionPool::new(capacity);
    
    // Fill pool
    for i in 0..capacity {
        pool.insert(i, create_test_session()).unwrap();
    }
    
    // Remove all
    for i in 0..capacity {
        pool.remove(i);
    }
    
    assert!(pool.is_empty());
    
    // Refill with different SSRCs
    for i in capacity..(capacity * 2) {
        pool.insert(i, create_test_session()).unwrap();
    }
    
    assert_eq!(pool.len(), capacity);
}

// ============================================================================
// SRTP High Volume Tests
// ============================================================================

#[test]
fn test_srtp_many_packets() {
    let material = create_test_key_material();
    let mut send_ctx = nexus_sfu::srtp::SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = nexus_sfu::srtp::SrtpContext::with_default_policy(&material).unwrap();
    
    // Process 1000 packets
    for seq in 1..=1000u16 {
        let mut packet = vec![0u8; 64];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..28].fill(seq as u8); // Payload
        
        let plen = send_ctx.protect_rtp(&mut packet, 28).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    }
    
    let (rtp, _) = recv_ctx.stats();
    assert_eq!(rtp, 1000);
}

#[test]
fn test_srtp_sequence_rollover_stress() {
    let material = create_test_key_material();
    let mut send_ctx = nexus_sfu::srtp::SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = nexus_sfu::srtp::SrtpContext::with_default_policy(&material).unwrap();
    
    // Start near rollover
    let start_seq = 65500u16;
    
    // Process packets across rollover (65500 -> 65535 -> 0 -> 100)
    for i in 0..=200u16 {
        let seq = start_seq.wrapping_add(i);
        
        let mut packet = vec![0u8; 64];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        packet[4..8].copy_from_slice(&(1000 + i as u32).to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    }
    
    let (rtp, _) = recv_ctx.stats();
    assert_eq!(rtp, 201);
}

// ============================================================================
// ICE Agent Stress Tests
// ============================================================================

#[test]
fn test_ice_agent_creation_many() {
    // Create many ICE agents to ensure no resource leaks
    let agents: Vec<IceAgent> = (0..100)
        .map(|i| {
            let role = if i % 2 == 0 { IceRole::Controlling } else { IceRole::Controlled };
            IceAgent::new(role).expect("Failed to create ICE agent")
        })
        .collect();
    
    assert_eq!(agents.len(), 100);
    
    // All agents should have valid credentials
    for agent in &agents {
        let (ufrag, pwd) = agent.local_credentials();
        assert!(ufrag.len() >= 4);
        assert!(pwd.len() >= 22);
    }
}

// ============================================================================
// SDP Size Limits Tests
// ============================================================================

#[test]
fn test_sdp_reasonable_size() {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    
    // Add maximum media sections with codecs
    for i in 0..MAX_MEDIA_SECTIONS {
        let mut media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.mid = Some(Mid::new(&i.to_string()));
        media.rtcp_mux = true;
        
        // Add multiple codecs per media
        for pt in [111u8, 112, 113] {
            if let Ok(codec) = RtpCodec::parse(pt, "opus/48000/2") {
                let _ = media.add_codec(codec);
            }
        }
        
        sdp.add_media(media).unwrap();
    }
    
    let serialized = sdp.to_sdp();
    
    // SDP should be reasonable size (< 64KB)
    assert!(serialized.len() < 65536, "SDP too large: {} bytes", serialized.len());
}

// ============================================================================
// Memory Bounds Tests
// ============================================================================

#[test]
fn test_session_pool_memory_bounded() {
    // Create pool and fill it
    let mut pool = SrtpSessionPool::new(100);
    
    for i in 0..100u32 {
        pool.insert(i, create_test_session()).unwrap();
    }
    
    // Remove all sessions
    for i in 0..100u32 {
        pool.remove(i);
    }
    
    // Pool should be empty
    assert!(pool.is_empty());
    
    // Can be refilled (memory was properly released)
    for i in 100..200u32 {
        pool.insert(i, create_test_session()).unwrap();
    }
    
    assert_eq!(pool.len(), 100);
}

// ============================================================================
// Concurrent-Like Pattern Tests
// ============================================================================

#[test]
fn test_alternating_insert_remove() {
    let mut pool = SrtpSessionPool::new(50);
    
    // Alternating pattern
    for round in 0..10u32 {
        let base = round * 10;
        
        // Insert 10
        for i in 0..10u32 {
            pool.insert(base + i, create_test_session()).unwrap();
        }
        
        // Remove 5
        for i in 0..5u32 {
            pool.remove(base + i);
        }
    }
    
    // Should have 5 from each round = 50
    assert_eq!(pool.len(), 50);
}
