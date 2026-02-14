//! Common test utilities for nexus-sfu testing.
//!
//! This module provides shared utilities, fixtures, and helpers
//! used across integration, stress, and validation tests.
//!
//! # TigerStyle Compliance
//!
//! - All helpers are pure functions where possible
//! - Deterministic test data generation
//! - Bounded resource usage

use nexus_webrtc::sdp::{
    SessionDescription, MediaDescription, MediaType, TransportProtocol,
};
use nexus_webrtc::sdp::attributes::{DtlsFingerprint, DtlsSetup, RtpCodec, Direction};
use nexus_webrtc::sdp::media::Mid;
use nexus_sfu::srtp::{SrtpContext, SrtpSession, KeyMaterial, SrtpPolicy};
use nexus_sfu::ice::{IceAgent, IceRole};

// ============================================================================
// Key Material Fixtures
// ============================================================================

/// Create test key material with fixed values for deterministic testing.
pub fn test_key_material() -> KeyMaterial {
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

/// Create alternate key material for bidirectional testing.
pub fn alt_key_material() -> KeyMaterial {
    let key = [0xAA; 16];
    let salt = [0xBB; 12];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create alt key material")
}

/// Create key material from a seed value.
pub fn seeded_key_material(seed: u8) -> KeyMaterial {
    let key = [seed; 16];
    let salt = [seed.wrapping_add(0x10); 12];
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create seeded key material")
}

// ============================================================================
// SRTP Context Fixtures
// ============================================================================

/// Create default SRTP context for testing.
pub fn test_srtp_context() -> SrtpContext {
    let material = test_key_material();
    SrtpContext::with_default_policy(&material).expect("Failed to create SRTP context")
}

/// Create SRTP session for bidirectional testing.
pub fn test_srtp_session() -> SrtpSession {
    let material = test_key_material();
    let policy = SrtpPolicy::aes_128_gcm();
    SrtpSession::symmetric(&material, policy).expect("Failed to create SRTP session")
}

/// Create bidirectional SRTP session pair.
pub fn test_srtp_session_pair() -> (SrtpSession, SrtpSession) {
    let send_material = test_key_material();
    let recv_material = alt_key_material();
    let policy = SrtpPolicy::aes_128_gcm();
    
    let alice = SrtpSession::new(&send_material, &recv_material, policy)
        .expect("Failed to create Alice session");
    let bob = SrtpSession::new(&recv_material, &send_material, policy)
        .expect("Failed to create Bob session");
    
    (alice, bob)
}

// ============================================================================
// ICE Agent Fixtures
// ============================================================================

/// Create controlling ICE agent.
pub fn test_ice_controlling() -> IceAgent {
    IceAgent::new(IceRole::Controlling).expect("Failed to create controlling agent")
}

/// Create controlled ICE agent.
pub fn test_ice_controlled() -> IceAgent {
    IceAgent::new(IceRole::Controlled).expect("Failed to create controlled agent")
}

// ============================================================================
// SDP Fixtures
// ============================================================================

/// Create valid DTLS fingerprint for testing.
pub fn valid_fingerprint() -> DtlsFingerprint {
    DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).expect("Failed to parse fingerprint")
}

/// Create basic audio offer SDP.
pub fn audio_offer_sdp() -> SessionDescription {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_session_name("Test Audio Offer");
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    sdp.setup = Some(DtlsSetup::Actpass);
    
    let mut audio = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    audio.mid = Some(Mid::new("0"));
    audio.direction = Direction::SendRecv;
    audio.rtcp_mux = true;
    
    let opus = RtpCodec::parse(111, "opus/48000/2").expect("Failed to parse Opus codec");
    audio.add_codec(opus).expect("Failed to add codec");
    
    sdp.add_media(audio).expect("Failed to add media");
    sdp
}

/// Create basic video offer SDP.
pub fn video_offer_sdp() -> SessionDescription {
    let mut sdp = SessionDescription::new(12346);
    sdp.set_session_name("Test Video Offer");
    sdp.set_ice_credentials("videofrag", "videopwd1234567890123456");
    sdp.set_fingerprint(valid_fingerprint());
    sdp.setup = Some(DtlsSetup::Actpass);
    
    let mut video = MediaDescription::new(
        MediaType::Video,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    video.mid = Some(Mid::new("0"));
    video.direction = Direction::SendRecv;
    video.rtcp_mux = true;
    
    let vp8 = RtpCodec::parse(96, "VP8/90000").expect("Failed to parse VP8 codec");
    video.add_codec(vp8).expect("Failed to add codec");
    
    sdp.add_media(video).expect("Failed to add media");
    sdp
}

/// Create bundled audio+video offer SDP.
pub fn bundled_offer_sdp() -> SessionDescription {
    let mut sdp = SessionDescription::new(12347);
    sdp.set_session_name("Test Bundled Offer");
    sdp.set_ice_credentials("bundlefrag", "bundlepwd12345678901234");
    sdp.set_fingerprint(valid_fingerprint());
    sdp.setup = Some(DtlsSetup::Actpass);
    
    // Audio
    let mut audio = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    audio.mid = Some(Mid::new("0"));
    audio.direction = Direction::SendRecv;
    audio.rtcp_mux = true;
    let opus = RtpCodec::parse(111, "opus/48000/2").expect("Failed to parse Opus");
    audio.add_codec(opus).expect("Failed to add Opus");
    sdp.add_media(audio).expect("Failed to add audio");
    
    // Video
    let mut video = MediaDescription::new(
        MediaType::Video,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    video.mid = Some(Mid::new("1"));
    video.direction = Direction::SendRecv;
    video.rtcp_mux = true;
    let vp8 = RtpCodec::parse(96, "VP8/90000").expect("Failed to parse VP8");
    video.add_codec(vp8).expect("Failed to add VP8");
    sdp.add_media(video).expect("Failed to add video");
    
    sdp
}

// ============================================================================
// RTP Packet Builders
// ============================================================================

/// Build a minimal RTP packet for testing.
pub fn build_rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 12 + payload.len() + 32]; // Room for auth tag
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0x60; // M=0, PT=96
    packet[2..4].copy_from_slice(&seq.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
    packet[12..12 + payload.len()].copy_from_slice(payload);
    packet
}

/// Build RTP packet with custom payload type.
pub fn build_rtp_packet_pt(seq: u16, ssrc: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 12 + payload.len() + 32];
    packet[0] = 0x80;
    packet[1] = pt;
    packet[2..4].copy_from_slice(&seq.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
    packet[12..12 + payload.len()].copy_from_slice(payload);
    packet
}

/// Build RTP packet with marker bit set.
pub fn build_rtp_packet_marker(seq: u16, ssrc: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = build_rtp_packet_pt(seq, ssrc, pt, payload);
    packet[1] |= 0x80; // Set marker bit
    packet
}

// ============================================================================
// Test Constants
// ============================================================================

/// Default SSRC for testing.
pub const TEST_SSRC: u32 = 0x12345678;

/// Alternate SSRC for testing.
pub const ALT_SSRC: u32 = 0x87654321;

/// Default payload type for audio.
pub const AUDIO_PT: u8 = 111;

/// Default payload type for video.
pub const VIDEO_PT: u8 = 96;

// ============================================================================
// Assertion Helpers
// ============================================================================

/// Assert that two byte slices are equal with descriptive message.
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8], context: &str) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{}: length mismatch ({} vs {})",
        context,
        actual.len(),
        expected.len()
    );
    
    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            a, e,
            "{}: byte {} differs (got {:#04x}, expected {:#04x})",
            context, i, a, e
        );
    }
}

/// Assert that a result is Ok and return the value.
pub fn unwrap_ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    result.unwrap_or_else(|e| panic!("{}: expected Ok, got Err({:?})", context, e))
}

/// Assert that a result is Err.
pub fn assert_err<T: std::fmt::Debug, E>(result: Result<T, E>, context: &str) {
    assert!(result.is_err(), "{}: expected Err, got Ok({:?})", context, result.ok());
}
