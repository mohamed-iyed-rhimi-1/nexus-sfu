//! Cross-implementation SRTP interop test.
//!
//! Protects with nexus-transport SRTP, unprotects with webrtc-rs SRTP (and vice versa).
//! This catches any subtle differences in KDF, encryption, or auth tag computation.

use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};

/// Fixed test key material (16-byte key + 14-byte salt).
const MASTER_KEY: [u8; 16] = [
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
];
const MASTER_SALT: [u8; 14] = [
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB,
    0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
];

/// Build a minimal valid RTP packet: V=2, PT=96, seq=seq_num, ts=160, ssrc=0x12345678
fn build_rtp_packet(seq_num: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len() + 16);
    // V=2, P=0, X=0, CC=0
    pkt.push(0x80);
    // M=0, PT=96
    pkt.push(96);
    // Sequence number
    pkt.push((seq_num >> 8) as u8);
    pkt.push(seq_num as u8);
    // Timestamp
    pkt.extend_from_slice(&160u32.to_be_bytes());
    // SSRC
    pkt.extend_from_slice(&0x12345678u32.to_be_bytes());
    // Payload
    pkt.extend_from_slice(payload);
    pkt
}

fn make_nexus_context() -> SrtpContext {
    let mut material = [0u8; 30];
    material[..16].copy_from_slice(&MASTER_KEY);
    material[16..30].copy_from_slice(&MASTER_SALT);
    let km = KeyMaterial::from_dtls_export(&material, ProtectionProfile::Aes128CmHmacSha1_80)
        .expect("key material");
    let policy = SrtpPolicy {
        profile: ProtectionProfile::Aes128CmHmacSha1_80,
        ..SrtpPolicy::default()
    };
    SrtpContext::new(&km, policy).expect("srtp context")
}

fn make_webrtc_context() -> webrtc_srtp::context::Context {
    webrtc_srtp::context::Context::new(
        &MASTER_KEY,
        &MASTER_SALT,
        webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
    )
    .expect("webrtc context")
}

#[test]
fn test_nexus_protect_webrtc_unprotect() {
    let mut nexus_ctx = make_nexus_context();
    let mut webrtc_ctx = make_webrtc_context();

    let payload = b"Hello, SRTP interop!";
    let plain_rtp = build_rtp_packet(1, payload);

    // Protect with nexus
    let mut buf = vec![0u8; plain_rtp.len() + 16]; // room for auth tag
    buf[..plain_rtp.len()].copy_from_slice(&plain_rtp);
    let protected_len = nexus_ctx
        .protect_rtp(&mut buf, plain_rtp.len())
        .expect("nexus protect_rtp failed");
    let protected = &buf[..protected_len];

    // Unprotect with webrtc-rs
    let decrypted = webrtc_ctx
        .decrypt_rtp(protected)
        .expect("webrtc-rs decrypt_rtp failed — auth tag mismatch!");

    assert_eq!(
        &decrypted[..],
        &plain_rtp[..],
        "decrypted packet must match original"
    );
}

#[test]
fn test_webrtc_protect_nexus_unprotect() {
    let mut nexus_ctx = make_nexus_context();
    let mut webrtc_ctx = make_webrtc_context();

    let payload = b"Hello, SRTP interop!";
    let plain_rtp = build_rtp_packet(1, payload);

    // Protect with webrtc-rs
    let protected = webrtc_ctx
        .encrypt_rtp(&plain_rtp)
        .expect("webrtc-rs encrypt_rtp failed");

    // Unprotect with nexus
    let mut buf = protected.to_vec();
    let decrypted_len = nexus_ctx
        .unprotect_rtp(&mut buf, protected.len())
        .expect("nexus unprotect_rtp failed — auth tag mismatch!");

    assert_eq!(
        &buf[..decrypted_len],
        &plain_rtp[..],
        "decrypted packet must match original"
    );
}

#[test]
fn test_interop_sequential_packets() {
    let mut nexus_protect = make_nexus_context();
    let mut webrtc_unprotect = make_webrtc_context();

    let payload = [0xAA; 160]; // simulated audio frame

    for seq in 0u16..100 {
        let plain_rtp = build_rtp_packet(seq, &payload);
        let mut buf = vec![0u8; plain_rtp.len() + 16];
        buf[..plain_rtp.len()].copy_from_slice(&plain_rtp);

        let protected_len = nexus_protect
            .protect_rtp(&mut buf, plain_rtp.len())
            .unwrap_or_else(|e| panic!("protect seq={seq} failed: {e:?}"));

        let decrypted = webrtc_unprotect
            .decrypt_rtp(&buf[..protected_len])
            .unwrap_or_else(|e| panic!("decrypt seq={seq} failed: {e:?}"));

        assert_eq!(&decrypted[..], &plain_rtp[..], "mismatch at seq={seq}");
    }
}
