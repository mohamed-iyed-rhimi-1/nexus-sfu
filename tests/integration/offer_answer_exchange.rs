//! Integration test: SDP offer/answer exchange.
//!
//! Tests the complete SDP negotiation flow:
//! 1. Create offer with local capabilities
//! 2. Parse and process remote answer
//! 3. Validate negotiated parameters
//!
//! # TigerStyle Compliance
//!
//! - All operations bounded
//! - Explicit error handling
//! - Clear test isolation

use nexus_webrtc::sdp::{
    SdpParser, SessionDescription, MediaDescription, MediaType, TransportProtocol,
};
use nexus_webrtc::sdp::attributes::{DtlsFingerprint, DtlsSetup, RtpCodec, Direction};
use nexus_webrtc::sdp::media::Mid;

// ============================================================================
// Test Helpers
// ============================================================================

fn create_audio_offer() -> SessionDescription {
    let mut sdp = SessionDescription::new(12345);
    sdp.set_session_name("Test Offer");
    sdp.set_ice_credentials("offerufrag", "offerpwd1234567890123456");
    
    let fp = DtlsFingerprint::parse(
        "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    ).unwrap();
    sdp.set_fingerprint(fp);
    sdp.setup = Some(DtlsSetup::Actpass);
    
    let mut audio = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    audio.mid = Some(Mid::new("0"));
    audio.direction = Direction::SendRecv;
    audio.rtcp_mux = true;
    
    // Add Opus codec
    let opus = RtpCodec::parse(111, "opus/48000/2").unwrap();
    audio.add_codec(opus).unwrap();
    
    sdp.add_media(audio).unwrap();
    sdp
}

fn create_video_offer() -> SessionDescription {
    let mut sdp = SessionDescription::new(12346);
    sdp.set_session_name("Video Offer");
    sdp.set_ice_credentials("videofrag", "videopwd1234567890123456");
    
    let fp = DtlsFingerprint::parse(
        "sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
    ).unwrap();
    sdp.set_fingerprint(fp);
    sdp.setup = Some(DtlsSetup::Actpass);
    
    let mut video = MediaDescription::new(
        MediaType::Video,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    video.mid = Some(Mid::new("1"));
    video.direction = Direction::SendRecv;
    video.rtcp_mux = true;
    
    // Add VP8 codec
    let vp8 = RtpCodec::parse(96, "VP8/90000").unwrap();
    video.add_codec(vp8).unwrap();
    
    sdp.add_media(video).unwrap();
    sdp
}

fn create_bundled_offer() -> SessionDescription {
    let mut sdp = SessionDescription::new(12347);
    sdp.set_session_name("Bundled Offer");
    sdp.set_ice_credentials("bundlefrag", "bundlepwd12345678901234");
    
    let fp = DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap();
    sdp.set_fingerprint(fp);
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
    let opus = RtpCodec::parse(111, "opus/48000/2").unwrap();
    audio.add_codec(opus).unwrap();
    sdp.add_media(audio).unwrap();
    
    // Video
    let mut video = MediaDescription::new(
        MediaType::Video,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    video.mid = Some(Mid::new("1"));
    video.direction = Direction::SendRecv;
    video.rtcp_mux = true;
    let vp8 = RtpCodec::parse(96, "VP8/90000").unwrap();
    video.add_codec(vp8).unwrap();
    sdp.add_media(video).unwrap();
    
    sdp
}

// ============================================================================
// Basic Offer/Answer Tests
// ============================================================================

#[test]
fn test_audio_offer_creation() {
    let offer = create_audio_offer();
    
    assert_eq!(offer.media_count, 1);
    assert!(offer.ice_ufrag.is_some());
    assert!(offer.ice_pwd.is_some());
    assert!(offer.fingerprint.is_some());
    
    let media = offer.media[0].as_ref().unwrap();
    assert_eq!(media.media_type, MediaType::Audio);
    assert_eq!(media.direction, Direction::SendRecv);
    assert!(media.rtcp_mux);
}

#[test]
fn test_video_offer_creation() {
    let offer = create_video_offer();
    
    assert_eq!(offer.media_count, 1);
    
    let media = offer.media[0].as_ref().unwrap();
    assert_eq!(media.media_type, MediaType::Video);
}

#[test]
fn test_bundled_offer_creation() {
    let offer = create_bundled_offer();
    
    assert_eq!(offer.media_count, 2);
    
    let audio = offer.media[0].as_ref().unwrap();
    let video = offer.media[1].as_ref().unwrap();
    
    assert_eq!(audio.media_type, MediaType::Audio);
    assert_eq!(video.media_type, MediaType::Video);
}

// ============================================================================
// Offer/Answer Roundtrip Tests
// ============================================================================

#[test]
fn test_offer_serialize_parse_roundtrip() {
    let original_offer = create_audio_offer();
    
    // Serialize
    let sdp_string = original_offer.to_sdp();
    
    // Parse back
    let parsed = SdpParser::parse(&sdp_string).unwrap();
    
    // Verify key fields preserved
    assert_eq!(parsed.media_count, original_offer.media_count);
    assert!(parsed.ice_ufrag.is_some());
    assert!(parsed.fingerprint.is_some());
    
    let original_media = original_offer.media[0].as_ref().unwrap();
    let parsed_media = parsed.media[0].as_ref().unwrap();
    
    assert_eq!(parsed_media.media_type, original_media.media_type);
    assert_eq!(parsed_media.direction, original_media.direction);
}

#[test]
fn test_bundled_offer_roundtrip() {
    let original = create_bundled_offer();
    let sdp_string = original.to_sdp();
    let parsed = SdpParser::parse(&sdp_string).unwrap();
    
    assert_eq!(parsed.media_count, 2);
    
    // Both media sections should be preserved
    for i in 0..2 {
        assert!(parsed.media[i].is_some());
    }
}

// ============================================================================
// Answer Creation Tests
// ============================================================================

#[test]
fn test_create_answer_to_offer() {
    let offer = create_audio_offer();
    let offer_sdp = offer.to_sdp();
    
    // Parse the offer
    let parsed_offer = SdpParser::parse(&offer_sdp).unwrap();
    
    // Create answer based on offer
    let mut answer = SessionDescription::new(parsed_offer.origin.session_id + 1);
    answer.set_ice_credentials("answerufrag", "answerpwd123456789012345");
    
    // Use different fingerprint for answer
    let fp = DtlsFingerprint::parse(
        "sha-256 FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00"
    ).unwrap();
    answer.set_fingerprint(fp);
    
    // Answer should be active (offer was actpass)
    answer.setup = Some(DtlsSetup::Active);
    
    // Mirror media sections
    for i in 0..parsed_offer.media_count as usize {
        if let Some(ref offer_media) = parsed_offer.media[i] {
            let mut answer_media = MediaDescription::new(
                offer_media.media_type,
                9,
                TransportProtocol::UdpTlsRtpSavpf,
            );
            answer_media.mid = offer_media.mid.clone();
            answer_media.rtcp_mux = offer_media.rtcp_mux;
            
            // Set appropriate direction (sendrecv -> sendrecv)
            answer_media.direction = match offer_media.direction {
                Direction::SendOnly => Direction::RecvOnly,
                Direction::RecvOnly => Direction::SendOnly,
                other => other,
            };
            
            // Copy first codec (simplified negotiation)
            if let Some(ref codec) = offer_media.codecs[0] {
                answer_media.add_codec(codec.clone()).unwrap();
            }
            
            answer.add_media(answer_media).unwrap();
        }
    }
    
    // Serialize and parse answer
    let answer_sdp = answer.to_sdp();
    let parsed_answer = SdpParser::parse(&answer_sdp).unwrap();
    
    // Verify answer
    assert_eq!(parsed_answer.media_count, parsed_offer.media_count);
    assert_eq!(parsed_answer.setup, Some(DtlsSetup::Active));
}

// ============================================================================
// Direction Negotiation Tests
// ============================================================================

#[test]
fn test_direction_negotiation_sendrecv() {
    // Offer: sendrecv -> Answer: sendrecv
    let mut offer = create_audio_offer();
    offer.media[0].as_mut().unwrap().direction = Direction::SendRecv;
    
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    assert_eq!(parsed.media[0].as_ref().unwrap().direction, Direction::SendRecv);
}

#[test]
fn test_direction_negotiation_sendonly() {
    let mut offer = create_audio_offer();
    offer.media[0].as_mut().unwrap().direction = Direction::SendOnly;
    
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    assert_eq!(parsed.media[0].as_ref().unwrap().direction, Direction::SendOnly);
}

#[test]
fn test_direction_negotiation_recvonly() {
    let mut offer = create_audio_offer();
    offer.media[0].as_mut().unwrap().direction = Direction::RecvOnly;
    
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    assert_eq!(parsed.media[0].as_ref().unwrap().direction, Direction::RecvOnly);
}

#[test]
fn test_direction_negotiation_inactive() {
    let mut offer = create_audio_offer();
    offer.media[0].as_mut().unwrap().direction = Direction::Inactive;
    
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    assert_eq!(parsed.media[0].as_ref().unwrap().direction, Direction::Inactive);
}

// ============================================================================
// DTLS Role Negotiation Tests
// ============================================================================

#[test]
fn test_dtls_setup_actpass_to_active() {
    let mut offer = create_audio_offer();
    offer.setup = Some(DtlsSetup::Actpass);
    
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    // Verify offer has actpass
    assert_eq!(parsed.setup, Some(DtlsSetup::Actpass));
    
    // Answer should be active
    // (This is the expected behavior per RFC 5763)
}

#[test]
fn test_dtls_setup_actpass_to_passive() {
    let mut offer = create_audio_offer();
    offer.setup = Some(DtlsSetup::Actpass);
    
    // Create answer with passive
    let mut answer = SessionDescription::new(99999);
    answer.set_ice_credentials("answerufrag", "answerpwd123456789012345");
    let fp = DtlsFingerprint::parse(
        "sha-256 FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00"
    ).unwrap();
    answer.set_fingerprint(fp);
    answer.setup = Some(DtlsSetup::Passive);
    
    let mut audio = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    audio.mid = Some(Mid::new("0"));
    let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
    audio.add_codec(codec).unwrap();
    answer.add_media(audio).unwrap();
    
    let answer_sdp = answer.to_sdp();
    let parsed = SdpParser::parse(&answer_sdp).unwrap();
    
    assert_eq!(parsed.setup, Some(DtlsSetup::Passive));
}

// ============================================================================
// ICE Credential Exchange Tests
// ============================================================================

#[test]
fn test_ice_credentials_in_offer() {
    let offer = create_audio_offer();
    let offer_sdp = offer.to_sdp();
    
    // Verify SDP string contains ICE credentials
    assert!(offer_sdp.contains("ice-ufrag:"));
    assert!(offer_sdp.contains("ice-pwd:"));
}

#[test]
fn test_ice_credentials_parsed_correctly() {
    let offer = create_audio_offer();
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    let ufrag = parsed.ice_ufrag.as_ref().unwrap();
    assert_eq!(ufrag.as_str(), "offerufrag");
}

// ============================================================================
// Fingerprint Handling Tests
// ============================================================================

#[test]
fn test_fingerprint_preserved_in_roundtrip() {
    let offer = create_audio_offer();
    let offer_sdp = offer.to_sdp();
    let parsed = SdpParser::parse(&offer_sdp).unwrap();
    
    assert!(parsed.fingerprint.is_some());
    
    let fp = parsed.fingerprint.as_ref().unwrap();
    // Should be sha-256
    assert!(fp.algorithm().contains("sha-256") || fp.algorithm().contains("SHA-256"));
}

// ============================================================================
// Media Section Limit Tests
// ============================================================================

#[test]
fn test_max_media_sections_in_offer() {
    use nexus_webrtc::sdp::MAX_MEDIA_SECTIONS;
    
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    let fp = DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap();
    sdp.set_fingerprint(fp);
    
    // Add maximum allowed media sections
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
    
    assert_eq!(sdp.media_count as usize, MAX_MEDIA_SECTIONS);
    
    // Serialize and parse
    let sdp_string = sdp.to_sdp();
    let parsed = SdpParser::parse(&sdp_string).unwrap();
    
    assert_eq!(parsed.media_count as usize, MAX_MEDIA_SECTIONS);
}

#[test]
fn test_exceed_max_media_sections_rejected() {
    use nexus_webrtc::sdp::MAX_MEDIA_SECTIONS;
    
    let mut sdp = SessionDescription::new(12345);
    sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
    let fp = DtlsFingerprint::parse(
        "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
    ).unwrap();
    sdp.set_fingerprint(fp);
    
    // Add maximum allowed
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
    
    // Try to add one more - should fail
    let mut extra = MediaDescription::new(
        MediaType::Audio,
        9,
        TransportProtocol::UdpTlsRtpSavpf,
    );
    extra.mid = Some(Mid::new("extra"));
    let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
    extra.add_codec(codec).unwrap();
    
    let result = sdp.add_media(extra);
    assert!(result.is_err());
}
