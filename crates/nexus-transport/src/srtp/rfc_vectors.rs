//! Known-answer tests for the SRTP transforms.
//!
//! - RFC 3711 Appendix B.2: AES-CM keystream.
//! - libsrtp `srtp_driver` AES_CM_128_HMAC_SHA1_80 packet (master key in,
//!   so it covers the KDF, AES-CM and HMAC-SHA1 together).
//! - RFC 7714 §16.1 / §16.2: AEAD_AES_128_GCM SRTP and SRTCP packets
//!   (session keys given directly, no KDF).
//! - AEAD KDF cross-checked against webrtc-srtp (RFC 7714 has no KDF vector).
//!
//! The AES-GCM SRTCP layout and AEAD KDF tests caught two interop bugs,
//! fixed in Phase 0.

use super::{
    AesCmHmacCipher, AesGcmCipher, KeyDerivation, KeyMaterial, PacketIndex, ProtectionProfile,
    SrtpCipher, SrtpContext, SrtpInbound, SrtpKeys, SrtpOutbound, SrtpPolicy,
};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Session keys built directly (the RFC vectors give session, not master, keys).
fn session_keys(profile: ProtectionProfile, key: &[u8], salt: &[u8], auth: &[u8]) -> SrtpKeys {
    assert_eq!(key.len(), profile.key_len());
    assert_eq!(salt.len(), profile.salt_len());
    let mut keys = SrtpKeys {
        rtp_key: [0; 32],
        rtp_key_len: key.len(),
        rtp_salt: [0; 14],
        rtp_salt_len: salt.len(),
        rtp_auth: [0; 20],
        rtp_auth_len: auth.len(),
        rtcp_key: [0; 32],
        rtcp_key_len: key.len(),
        rtcp_salt: [0; 14],
        rtcp_salt_len: salt.len(),
        rtcp_auth: [0; 20],
        rtcp_auth_len: auth.len(),
        profile,
    };
    keys.rtp_key[..key.len()].copy_from_slice(key);
    keys.rtcp_key[..key.len()].copy_from_slice(key);
    keys.rtp_salt[..salt.len()].copy_from_slice(salt);
    keys.rtcp_salt[..salt.len()].copy_from_slice(salt);
    keys.rtp_auth[..auth.len()].copy_from_slice(auth);
    keys.rtcp_auth[..auth.len()].copy_from_slice(auth);
    keys
}

// ============================================================================
// RFC 3711 Appendix B.2 — AES-CM keystream
// ============================================================================

/// Session key 2B7E1516..., session salt F0F1...FCFD, SSRC 0, index 0.
/// A zero payload encrypts to the keystream itself.
#[test]
fn rfc3711_b2_aes_cm_keystream() {
    let key = unhex("2B7E151628AED2A6ABF7158809CF4F3C");
    let salt = unhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");
    let keystream = unhex(
        "E03EAD0935C95E80E166B16DD92B4EB4
         D23513162B02D0F72A43A2FE4A5F97AB
         41E95B3BB0A2E8DD477901E4FCA894C0",
    );
    let keys = session_keys(
        ProtectionProfile::Aes128CmHmacSha1_80,
        &key,
        &salt,
        &[0u8; 20],
    );
    let cipher = AesCmHmacCipher::new(&keys).expect("cipher");

    let mut packet = [0u8; 12 + 48 + 10];
    packet[0] = 0x80; // V=2, SSRC 0, seq 0
    let len = cipher
        .protect_rtp(&mut packet, 12 + 48, PacketIndex::new(0, 0))
        .expect("protect");
    assert_eq!(len, 12 + 48 + 10);
    assert_eq!(&packet[12..60], &keystream[..], "AES-CM keystream");
}

// ============================================================================
// AES_CM_128_HMAC_SHA1_80 packet (libsrtp test/srtp_driver.c)
// ============================================================================

const CM_MASTER_KEY: &str = "e1f97a0d3e018be0d64fa32c06de4139";
const CM_MASTER_SALT: &str = "0ec675ad498afeebb6960b3aabe6";
const CM_PLAIN: &str = "800f1234decafbadcafebabeabababababababababababababababab";
const CM_PROTECTED: &str = "800f1234decafbadcafebabe\
                            4e55dc4ce79978d88ca4d215949d2402\
                            b78d6acc99ea179b8dbb";

fn cm_material() -> KeyMaterial {
    let mut material = unhex(CM_MASTER_KEY);
    material.extend_from_slice(&unhex(CM_MASTER_SALT));
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    KeyMaterial::from_dtls_export(&material, profile).expect("key material")
}

fn cm_context() -> SrtpContext {
    let km = cm_material();
    let profile = km.profile;
    let policy = SrtpPolicy {
        profile,
        ..SrtpPolicy::default()
    };
    SrtpContext::new(&km, policy).expect("context")
}

#[test]
fn aes_cm_hmac_sha1_80_packet_protect() {
    let plain = unhex(CM_PLAIN);
    let expected = unhex(CM_PROTECTED);
    let mut buf = [0u8; 64];
    buf[..plain.len()].copy_from_slice(&plain);
    let len = cm_context()
        .protect_rtp(&mut buf, plain.len())
        .expect("protect");
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn aes_cm_hmac_sha1_80_packet_unprotect() {
    let plain = unhex(CM_PLAIN);
    let protected = unhex(CM_PROTECTED);
    let mut buf = [0u8; 64];
    buf[..protected.len()].copy_from_slice(&protected);
    let len = cm_context()
        .unprotect_rtp(&mut buf, protected.len())
        .expect("unprotect");
    assert_eq!(&buf[..len], &plain[..]);
}

// ============================================================================
// RFC 7714 §16 — AEAD_AES_128_GCM
// ============================================================================

const GCM_KEY: &str = "000102030405060708090a0b0c0d0e0f";
/// "Quid pro quo"
const GCM_SALT: &str = "517569642070726f2071756f";

fn gcm_keys() -> SrtpKeys {
    session_keys(
        ProtectionProfile::AeadAes128Gcm,
        &unhex(GCM_KEY),
        &unhex(GCM_SALT),
        &[],
    )
}

fn gcm_cipher() -> AesGcmCipher {
    AesGcmCipher::new(&gcm_keys()).expect("cipher")
}

/// §16.1: RTP header 8040f17b 8041f8d3 5501a0b2, ROC 0, seq 0xf17b,
/// payload "Gallia est omnis divisa in partes tres".
const GCM_RTP_PLAIN: &str = "8040f17b8041f8d35501a0b2\
                             47616c6c696120657374206f6d6e69732064697669736120\
                             696e207061727465732074726573";
const GCM_RTP_PROTECTED: &str = "8040f17b8041f8d35501a0b2\
                                 f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f\
                                 42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf\
                                 765ee4390cce";
const GCM_RTP_INDEX: PacketIndex = PacketIndex::new(0, 0xf17b);

#[test]
fn rfc7714_16_1_rtp_encrypt() {
    let plain = unhex(GCM_RTP_PLAIN);
    let expected = unhex(GCM_RTP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..plain.len()].copy_from_slice(&plain);
    let len = gcm_cipher()
        .protect_rtp(&mut buf, plain.len(), GCM_RTP_INDEX)
        .expect("protect");
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn rfc7714_16_1_rtp_decrypt() {
    let plain = unhex(GCM_RTP_PLAIN);
    let protected = unhex(GCM_RTP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..protected.len()].copy_from_slice(&protected);
    let len = gcm_cipher()
        .unprotect_rtp(&mut buf, protected.len(), GCM_RTP_INDEX)
        .expect("unprotect");
    assert_eq!(&buf[..len], &plain[..]);

    // A flipped ciphertext bit must fail authentication.
    buf[..protected.len()].copy_from_slice(&protected);
    buf[20] ^= 1;
    assert!(gcm_cipher()
        .unprotect_rtp(&mut buf, protected.len(), GCM_RTP_INDEX)
        .is_err());
}

/// §16.2: sender report, SRTCP index 0x5d4. Wire layout per RFC 7714 §9
/// (and libsrtp, webrtc-srtp): header | ciphertext | tag | E+index.
const GCM_RTCP_PLAIN: &str = "81c8000d4d617273\
                              4e5450314e5450325254502000\
                              00042a0000e9304c756e61\
                              deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const GCM_RTCP_PROTECTED: &str = "81c8000d4d617273\
                                  63e94885dcdab67ca727d7662f6b7e997ff5c0f7\
                                  6c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275b\
                                  c84aa45896cf4d2fc5abf87245d9eade\
                                  800005d4";
const GCM_RTCP_INDEX: u32 = 0x5d4;

/// Regression (fixed in Phase 0): E+index used to be written before the tag;
/// RFC 7714 §9 (Figure 3), libsrtp and webrtc-srtp put it after.
#[test]
fn rfc7714_16_2_rtcp_encrypt() {
    let plain = unhex(GCM_RTCP_PLAIN);
    let expected = unhex(GCM_RTCP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..plain.len()].copy_from_slice(&plain);
    let len = gcm_cipher()
        .protect_rtcp(&mut buf, plain.len(), GCM_RTCP_INDEX)
        .expect("protect");
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn rfc7714_16_2_rtcp_decrypt() {
    let plain = unhex(GCM_RTCP_PLAIN);
    let protected = unhex(GCM_RTCP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..protected.len()].copy_from_slice(&protected);
    let (len, index) = gcm_cipher()
        .unprotect_rtcp(&mut buf, protected.len())
        .expect("unprotect");
    assert_eq!(index, GCM_RTCP_INDEX);
    assert_eq!(&buf[..len], &plain[..]);
}

// ============================================================================
// AEAD KDF — cross-check against webrtc-srtp
// ============================================================================

/// Regression (fixed in Phase 0): `derive_key_aead` used to XOR the label
/// into byte 6 of the 12-byte salt. RFC 3711 §4.3.1 puts it at byte 7 of the
/// 14-byte PRF input (the 12-byte AEAD salt is zero-padded), as libsrtp and
/// webrtc-srtp do; with byte 6 the RTP salt and all RTCP keys were wrong.
#[test]
fn aead_kdf_matches_webrtc_srtp() {
    use webrtc_srtp::context::Context;
    use webrtc_srtp::protection_profile::ProtectionProfile as WProfile;

    let key: Vec<u8> = (0..16).collect();
    let salt: Vec<u8> = (0x40..0x4c).collect();
    let km = KeyMaterial::from_aes128_gcm(&key, &salt).expect("key material");
    let keys = KeyDerivation::derive_keys(&km).expect("derive");
    // libsrtp-compatible session salt for this master key/salt (label 2 at byte 7).
    assert_eq!(keys.rtp_salt(), &unhex("1fcd5d561e66dc49ec1c3ccb")[..]);

    let cipher = SrtpCipher::new(&keys).expect("cipher");
    let mut theirs =
        Context::new(&key, &salt, WProfile::AeadAes128Gcm, None, None).expect("webrtc ctx");
    let mut plain = vec![0x80u8, 96, 0, 1, 0, 0, 0, 160, 0x12, 0x34, 0x56, 0x78];
    plain.extend_from_slice(&[0xab; 20]);
    let mut buf = [0u8; 128];
    buf[..plain.len()].copy_from_slice(&plain);
    let len = cipher
        .protect_rtp(&mut buf, plain.len(), PacketIndex::new(0, 1))
        .expect("protect");
    let expected = theirs.encrypt_rtp(&plain).expect("webrtc protect");
    assert_eq!(&buf[..len], &expected[..]);
}

// ============================================================================
// The same vectors through SrtpInbound / SrtpOutbound (Phase 1.1)
// ============================================================================

#[test]
fn direction_rfc3711_b2_keystream() {
    let key = unhex("2B7E151628AED2A6ABF7158809CF4F3C");
    let salt = unhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");
    let keys = session_keys(
        ProtectionProfile::Aes128CmHmacSha1_80,
        &key,
        &salt,
        &[0u8; 20],
    );
    let mut packet = [0u8; 12 + 48 + 10];
    packet[0] = 0x80; // V=2, SSRC 0, seq 0: first packet has index 0
    let mut out = SrtpOutbound::from_keys(&keys, 0).expect("outbound");
    out.register(0).expect("register");
    assert_eq!(out.protect_rtp(&mut packet, 60), Some(70));
    let keystream = unhex(
        "E03EAD0935C95E80E166B16DD92B4EB4
         D23513162B02D0F72A43A2FE4A5F97AB
         41E95B3BB0A2E8DD477901E4FCA894C0",
    );
    assert_eq!(&packet[12..60], &keystream[..]);
}

#[test]
fn direction_aes_cm_hmac_sha1_80_packet() {
    let plain = unhex(CM_PLAIN);
    let expected = unhex(CM_PROTECTED);
    let mut buf = [0u8; 64];
    buf[..plain.len()].copy_from_slice(&plain);
    let mut out = SrtpOutbound::new(&cm_material(), 0xcafe_babe).expect("outbound");
    out.register(0xcafe_babe).expect("register");
    let len = out.protect_rtp(&mut buf, plain.len()).expect("protect");
    assert_eq!(&buf[..len], &expected[..]);

    let mut inbound = SrtpInbound::new(&cm_material()).expect("inbound");
    let len = inbound.unprotect_rtp(&mut buf, len, 0).expect("unprotect");
    assert_eq!(&buf[..len], &plain[..]);
}

#[test]
fn direction_rfc7714_16_1_rtp() {
    let plain = unhex(GCM_RTP_PLAIN);
    let expected = unhex(GCM_RTP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..plain.len()].copy_from_slice(&plain);
    let mut out = SrtpOutbound::from_keys(&gcm_keys(), 0).expect("outbound");
    out.register(0x5501_a0b2).expect("register");
    let len = out.protect_rtp(&mut buf, plain.len()).expect("protect");
    assert_eq!(&buf[..len], &expected[..]);

    let mut inbound = SrtpInbound::from_keys(&gcm_keys()).expect("inbound");
    let len = inbound.unprotect_rtp(&mut buf, len, 0).expect("unprotect");
    assert_eq!(&buf[..len], &plain[..]);
}

#[test]
fn direction_rfc7714_16_2_rtcp() {
    let plain = unhex(GCM_RTCP_PLAIN);
    let expected = unhex(GCM_RTCP_PROTECTED);
    let mut buf = [0u8; 128];
    buf[..plain.len()].copy_from_slice(&plain);
    let mut out = SrtpOutbound::from_keys(&gcm_keys(), 0).expect("outbound");
    out.register(0x4d61_7273).expect("register");
    out.set_srtcp_index(0x4d61_7273, GCM_RTCP_INDEX);
    let len = out.protect_rtcp(&mut buf, plain.len()).expect("protect");
    assert_eq!(&buf[..len], &expected[..]);

    let mut inbound = SrtpInbound::from_keys(&gcm_keys()).expect("inbound");
    let len = inbound.unprotect_rtcp(&mut buf, len, 0).expect("unprotect");
    assert_eq!(&buf[..len], &plain[..]);
}
