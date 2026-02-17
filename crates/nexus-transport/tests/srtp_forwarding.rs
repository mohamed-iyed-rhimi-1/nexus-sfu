//! Simulate the full SFU forwarding path:
//! Publisher → SRTP protect → SFU SRTP unprotect → plain RTP → SFU SRTP protect → Subscriber SRTP unprotect
//!
//! Uses webrtc-rs for publisher/subscriber sides and nexus-transport for SFU side.
//! Tests sequence number wrap (ROC increment) which is where the loadtest fails.

use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};

const PUB_KEY: [u8; 16] = [0xA1; 16];
const PUB_SALT: [u8; 14] = [0xA2; 14];
const SUB_KEY: [u8; 16] = [0xB1; 16];
const SUB_SALT: [u8; 14] = [0xB2; 14];

fn build_rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len());
    pkt.push(0x80);
    pkt.push(96);
    pkt.push((seq >> 8) as u8);
    pkt.push(seq as u8);
    pkt.extend_from_slice(&160u32.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn make_nexus_ctx(key: &[u8; 16], salt: &[u8; 14]) -> SrtpContext {
    let mut material = [0u8; 30];
    material[..16].copy_from_slice(key);
    material[16..30].copy_from_slice(salt);
    let km = KeyMaterial::from_dtls_export(&material, ProtectionProfile::Aes128CmHmacSha1_80).unwrap();
    SrtpContext::new(&km, SrtpPolicy { profile: ProtectionProfile::Aes128CmHmacSha1_80, ..SrtpPolicy::default() }).unwrap()
}

fn make_webrtc_ctx(key: &[u8; 16], salt: &[u8; 14]) -> webrtc_srtp::context::Context {
    webrtc_srtp::context::Context::new(
        key, salt,
        webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80,
        None, None,
    ).unwrap()
}

/// Simulate: publisher (webrtc-rs) → SFU (nexus) → subscriber (webrtc-rs)
/// Publisher encrypts with PUB_KEY, SFU decrypts with PUB_KEY, re-encrypts with SUB_KEY,
/// subscriber decrypts with SUB_KEY.
#[test]
fn test_sfu_forwarding_across_seq_wrap() {
    // Publisher side: webrtc-rs encrypt context (publisher sends with PUB_KEY)
    let mut pub_encrypt = make_webrtc_ctx(&PUB_KEY, &PUB_SALT);
    // SFU inbound: nexus decrypt context (SFU receives with PUB_KEY)
    let mut sfu_decrypt = make_nexus_ctx(&PUB_KEY, &PUB_SALT);
    // SFU outbound: nexus encrypt context (SFU sends with SUB_KEY)
    let mut sfu_encrypt = make_nexus_ctx(&SUB_KEY, &SUB_SALT);
    // Subscriber side: webrtc-rs decrypt context (subscriber receives with SUB_KEY)
    let mut sub_decrypt = make_webrtc_ctx(&SUB_KEY, &SUB_SALT);

    let ssrc = 0x12345678u32;
    let payload = [0xAA; 160];

    // Start at seq 65400 to force a wrap within 200 packets
    let start_seq: u16 = 65400;
    let num_packets: u32 = 400; // crosses 65535 → 0

    let mut auth_failures = 0u32;
    let mut success = 0u32;

    for i in 0..num_packets {
        let seq = start_seq.wrapping_add(i as u16);
        let plain_rtp = build_rtp(seq, ssrc, &payload);

        // Step 1: Publisher encrypts
        let protected_pub = pub_encrypt.encrypt_rtp(&plain_rtp)
            .unwrap_or_else(|e| panic!("pub encrypt seq={seq} failed: {e:?}"));

        // Step 2: SFU decrypts
        let mut sfu_buf = protected_pub.to_vec();
        let decrypted_len = match sfu_decrypt.unprotect_rtp(&mut sfu_buf, protected_pub.len()) {
            Ok(len) => len,
            Err(e) => {
                panic!("SFU decrypt seq={seq} (i={i}) failed: {e:?}");
            }
        };
        let decrypted_rtp = &sfu_buf[..decrypted_len];

        // Verify decrypted matches original
        assert_eq!(decrypted_rtp, &plain_rtp[..], "SFU decrypted mismatch at seq={seq}");

        // Step 3: SFU re-encrypts for subscriber
        let mut sub_buf = vec![0u8; decrypted_len + 16];
        sub_buf[..decrypted_len].copy_from_slice(decrypted_rtp);
        let protected_len = sfu_encrypt.protect_rtp(&mut sub_buf, decrypted_len)
            .unwrap_or_else(|e| panic!("SFU encrypt seq={seq} failed: {e:?}"));

        // Step 4: Subscriber decrypts
        match sub_decrypt.decrypt_rtp(&sub_buf[..protected_len]) {
            Ok(decrypted) => {
                assert_eq!(&decrypted[..], &plain_rtp[..], "subscriber mismatch at seq={seq}");
                success += 1;
            }
            Err(e) => {
                auth_failures += 1;
                if auth_failures <= 5 {
                    eprintln!("AUTH FAILURE at seq={seq} (i={i}): {e:?}");
                }
            }
        }
    }

    eprintln!("Results: {success} success, {auth_failures} failures out of {num_packets}");
    assert_eq!(auth_failures, 0, "{auth_failures} auth failures across seq wrap");
}

/// Same test but with multiple SSRCs (audio + video) interleaved
#[test]
fn test_sfu_forwarding_multi_ssrc_wrap() {
    let mut pub_encrypt = make_webrtc_ctx(&PUB_KEY, &PUB_SALT);
    let mut sfu_decrypt = make_nexus_ctx(&PUB_KEY, &PUB_SALT);
    let mut sfu_encrypt = make_nexus_ctx(&SUB_KEY, &SUB_SALT);
    let mut sub_decrypt = make_webrtc_ctx(&SUB_KEY, &SUB_SALT);

    let video_ssrc = 0xAABBCCDD_u32;
    let audio_ssrc = 0x11223344_u32;
    let payload = [0xBB; 160];

    let mut video_seq: u16 = 65500;
    let mut audio_seq: u16 = 100;
    let mut failures = 0u32;

    for i in 0..500u32 {
        // Alternate video and audio
        let (ssrc, seq) = if i % 3 == 0 {
            audio_seq = audio_seq.wrapping_add(1);
            (audio_ssrc, audio_seq)
        } else {
            video_seq = video_seq.wrapping_add(1);
            (video_ssrc, video_seq)
        };

        let plain = build_rtp(seq, ssrc, &payload);
        let protected = pub_encrypt.encrypt_rtp(&plain).unwrap();

        let mut buf = protected.to_vec();
        let dec_len = sfu_decrypt.unprotect_rtp(&mut buf, protected.len()).unwrap();

        let mut sub_buf = vec![0u8; dec_len + 16];
        sub_buf[..dec_len].copy_from_slice(&buf[..dec_len]);
        let prot_len = sfu_encrypt.protect_rtp(&mut sub_buf, dec_len).unwrap();

        if sub_decrypt.decrypt_rtp(&sub_buf[..prot_len]).is_err() {
            failures += 1;
            if failures <= 3 {
                eprintln!("FAIL ssrc={ssrc:#x} seq={seq} i={i}");
            }
        }
    }

    assert_eq!(failures, 0, "{failures} auth failures in multi-SSRC test");
}
