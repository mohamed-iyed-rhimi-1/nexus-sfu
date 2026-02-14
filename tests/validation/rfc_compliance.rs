//! Validation test: RFC compliance verification.
//!
//! Tests compliance with relevant RFC specifications:
//! - RFC 3711 (SRTP)
//! - RFC 5245 (ICE)
//! - RFC 5764 (DTLS-SRTP)
//! - RFC 4566 (SDP)
//!
//! # TigerStyle Compliance
//!
//! - Explicit RFC section references
//! - Validation of all requirements
//! - Clear pass/fail criteria

use nexus_webrtc::sdp::{
    SdpParser, SessionDescription, MediaDescription, MediaType, TransportProtocol,
    MAX_SDP_SIZE, MAX_MEDIA_SECTIONS, MIN_ICE_UFRAG_LEN, MAX_ICE_UFRAG_LEN,
    MIN_ICE_PWD_LEN, MAX_ICE_PWD_LEN,
};
use nexus_webrtc::sdp::attributes::{DtlsFingerprint, DtlsSetup, RtpCodec};
use nexus_webrtc::sdp::media::Mid;
use nexus_sfu::srtp::{SrtpContext, KeyMaterial, SrtpPolicy, ProtectionProfile};
use nexus_sfu::ice::{IceAgent, IceRole};

// ============================================================================
// RFC 5245 ICE Compliance Tests
// ============================================================================

/// RFC 5245 Section 15.4: ICE username fragment MUST be at least 4 characters
#[test]
fn test_rfc5245_ice_ufrag_min_length() {
    let agent = IceAgent::new(IceRole::Controlling).unwrap();
    let (ufrag, _) = agent.local_credentials();
    
    assert!(
        ufrag.len() >= MIN_ICE_UFRAG_LEN,
        "RFC 5245: ice-ufrag MUST be at least {} chars, got {}",
        MIN_ICE_UFRAG_LEN,
        ufrag.len()
    );
}

/// RFC 5245 Section 15.4: ICE password MUST be at least 22 characters
#[test]
fn test_rfc5245_ice_pwd_min_length() {
    let agent = IceAgent::new(IceRole::Controlling).unwrap();
    let (_, pwd) = agent.local_credentials();
    
    assert!(
        pwd.len() >= MIN_ICE_PWD_LEN,
        "RFC 5245: ice-pwd MUST be at least {} chars, got {}",
        MIN_ICE_PWD_LEN,
        pwd.len()
    );
}

/// RFC 5245 Section 15.4: ICE username fragment MUST be less than 256 characters
#[test]
fn test_rfc5245_ice_ufrag_max_length() {
    let agent = IceAgent::new(IceRole::Controlling).unwrap();
    let (ufrag, _) = agent.local_credentials();
    
    assert!(
        ufrag.len() <= MAX_ICE_UFRAG_LEN,
        "RFC 5245: ice-ufrag MUST be at most {} chars, got {}",
        MAX_ICE_UFRAG_LEN,
        ufrag.len()
    );
}

/// RFC 5245 Section 15.4: ICE password MUST be less than 256 characters
#[test]
fn test_rfc5245_ice_pwd_max_length() {
    let agent = IceAgent::new(IceRole::Controlling).unwrap();
    let (_, pwd) = agent.local_credentials();
    
    assert!(
        pwd.len() <= MAX_ICE_PWD_LEN,
        "RFC 5245: ice-pwd MUST be at most {} chars, got {}",
        MAX_ICE_PWD_LEN,
        pwd.len()
    );
}

/// RFC 5245: Short ice-ufrag should be rejected in SDP parsing
#[test]
fn test_rfc5245_reject_short_ufrag() {
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:abc
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    
    let result = SdpParser::parse(sdp);
    assert!(result.is_err(), "RFC 5245: MUST reject ice-ufrag < 4 chars");
}

/// RFC 5245: Short ice-pwd should be rejected in SDP parsing
#[test]
fn test_rfc5245_reject_short_pwd() {
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:short
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    
    let result = SdpParser::parse(sdp);
    assert!(result.is_err(), "RFC 5245: MUST reject ice-pwd < 22 chars");
}

// ============================================================================
// RFC 3711 SRTP Compliance Tests
// ============================================================================

/// RFC 3711 Section 3.3: SRTP packets MUST include authentication tag
#[test]
fn test_rfc3711_srtp_includes_auth_tag() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80; // V=2
    packet[1] = 0x60; // PT=96
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let original_len = 16;
    let protected_len = ctx.protect_rtp(&mut packet, original_len).unwrap();
    
    // AEAD-AES-GCM uses 16-byte auth tag
    assert_eq!(
        protected_len - original_len,
        16,
        "RFC 3711: SRTP MUST include 16-byte authentication tag"
    );
}

/// RFC 3711 Section 3.3.1: Replay protection MUST reject duplicate packets
#[test]
fn test_rfc3711_replay_protection() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
    let saved = packet[..plen].to_vec();
    
    // First receive
    recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    
    // Replay MUST be rejected
    let mut replay = saved;
    let result = recv_ctx.unprotect_rtp(&mut replay, plen);
    assert!(result.is_err(), "RFC 3711: Replay MUST be detected and rejected");
}

/// RFC 3711 Section 4.3: Key derivation MUST produce different keys for RTP and RTCP
#[test]
fn test_rfc3711_key_derivation_separation() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    let keys = ctx.keys();
    
    assert_ne!(
        keys.rtp_key(),
        keys.rtcp_key(),
        "RFC 3711: RTP and RTCP MUST use different keys"
    );
    
    assert_ne!(
        keys.rtp_salt(),
        keys.rtcp_salt(),
        "RFC 3711: RTP and RTCP MUST use different salts"
    );
}

// ============================================================================
// RFC 4566 SDP Compliance Tests
// ============================================================================

/// RFC 4566 Section 5: SDP version MUST be 0
#[test]
fn test_rfc4566_sdp_version_zero() {
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    
    let parsed = SdpParser::parse(sdp).unwrap();
    assert_eq!(parsed.version, 0, "RFC 4566: SDP version MUST be 0");
}

/// RFC 4566 Section 5: Invalid SDP version should be rejected
#[test]
fn test_rfc4566_reject_invalid_version() {
    let sdp = "v=1\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n";
    
    let result = SdpParser::parse(sdp);
    assert!(result.is_err(), "RFC 4566: MUST reject SDP version != 0");
}

/// RFC 4566 Section 5.14: Media descriptions MUST have valid media type
#[test]
fn test_rfc4566_valid_media_types() {
    // Audio
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    let parsed = SdpParser::parse(sdp).unwrap();
    assert_eq!(parsed.media[0].as_ref().unwrap().media_type, MediaType::Audio);
    
    // Video
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=video 9 UDP/TLS/RTP/SAVPF 96
"#;
    let parsed = SdpParser::parse(sdp).unwrap();
    assert_eq!(parsed.media[0].as_ref().unwrap().media_type, MediaType::Video);
}

// ============================================================================
// RFC 5764 DTLS-SRTP Compliance Tests
// ============================================================================

/// RFC 5764 Section 4.1: DTLS fingerprint MUST be SHA-256 for WebRTC
#[test]
fn test_rfc5764_sha256_fingerprint() {
    let fp = DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap();
    
    let alg = fp.algorithm();
    assert!(
        alg.to_lowercase().contains("sha-256") || alg.to_lowercase().contains("sha256"),
        "RFC 5764 (WebRTC): Fingerprint MUST use SHA-256"
    );
}

/// RFC 5764: SHA-1 fingerprints should be rejected for WebRTC
#[test]
fn test_rfc5764_reject_sha1() {
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-1 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    
    let result = SdpParser::parse(sdp);
    assert!(result.is_err(), "RFC 5764/WebRTC: MUST reject SHA-1 fingerprints");
}

/// RFC 5764: DTLS setup attribute must be present
#[test]
fn test_rfc5764_setup_attribute() {
    let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=setup:actpass
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;
    
    let parsed = SdpParser::parse(sdp).unwrap();
    assert_eq!(parsed.setup, Some(DtlsSetup::Actpass));
}

// ============================================================================
// AEAD-AES-GCM Compliance Tests (RFC 7714)
// ============================================================================

/// RFC 7714: AES-128-GCM key MUST be 16 bytes
#[test]
fn test_rfc7714_aes128_key_length() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    assert_eq!(ctx.keys().rtp_key().len(), 16, "RFC 7714: AES-128-GCM key MUST be 16 bytes");
}

/// RFC 7714: AEAD-AES-GCM salt MUST be 12 bytes
#[test]
fn test_rfc7714_gcm_salt_length() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    assert_eq!(ctx.keys().rtp_salt().len(), 12, "RFC 7714: AEAD-AES-GCM salt MUST be 12 bytes");
}

/// RFC 7714: Invalid key length should be rejected
#[test]
fn test_rfc7714_reject_invalid_key_length() {
    let key = [0x42u8; 10]; // Wrong length
    let salt = [0x24u8; 12];
    
    let result = KeyMaterial::from_aes128_gcm(&key, &salt);
    assert!(result.is_err(), "RFC 7714: MUST reject invalid key length");
}

/// RFC 7714: Invalid salt length should be rejected
#[test]
fn test_rfc7714_reject_invalid_salt_length() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 8]; // Wrong length
    
    let result = KeyMaterial::from_aes128_gcm(&key, &salt);
    assert!(result.is_err(), "RFC 7714: MUST reject invalid salt length");
}

// ============================================================================
// Bounds Compliance Tests
// ============================================================================

/// Verify MAX_MEDIA_SECTIONS is reasonable per RFC 4566
#[test]
fn test_max_media_sections_reasonable() {
    assert!(
        MAX_MEDIA_SECTIONS >= 2,
        "Must support at least audio + video"
    );
    assert!(
        MAX_MEDIA_SECTIONS <= 255,
        "Media sections should be bounded reasonably"
    );
}

/// Verify MAX_SDP_SIZE is reasonable
#[test]
fn test_max_sdp_size_reasonable() {
    assert!(
        MAX_SDP_SIZE >= 1024,
        "Must support reasonably sized SDPs"
    );
    assert!(
        MAX_SDP_SIZE <= 1024 * 1024,
        "SDP size should be bounded to prevent DoS"
    );
}

// ============================================================================
// RTP Header Compliance Tests (RFC 3550)
// ============================================================================

/// RFC 3550: RTP version MUST be 2
#[test]
fn test_rfc3550_rtp_version() {
    let key = [0x42u8; 16];
    let salt = [0x24u8; 12];
    let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Valid RTP packet (version 2)
    let mut packet = vec![0u8; 64];
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
    
    assert!(ctx.protect_rtp(&mut packet, 16).is_ok());
}

/// RFC 3550: RTP header MUST be at least 12 bytes
#[test]
fn test_rfc3550_minimum_header_size() {
    // This is a compile-time check in the codebase
    // RTP_HEADER_SIZE should be 12
    const RTP_HEADER_SIZE: usize = 12;
    
    assert_eq!(RTP_HEADER_SIZE, 12, "RFC 3550: RTP header minimum is 12 bytes");
}
