//! Replicate the exact 100-viewer scenario:
//! - 1 publisher, 100 subscribers
//! - Each subscriber has its own SRTP context pair (SFU encrypt + webrtc-rs decrypt)
//! - Publisher starts at random seq, sends enough packets to wrap
//! - Interleave SRTCP Sender Reports between RTP packets

use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};

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

fn make_nexus_ctx(key: &[u8], salt: &[u8]) -> SrtpContext {
    let mut material = vec![0u8; key.len() + salt.len()];
    material[..key.len()].copy_from_slice(key);
    material[key.len()..].copy_from_slice(salt);
    let km = KeyMaterial::from_dtls_export(&material, ProtectionProfile::Aes128CmHmacSha1_80).unwrap();
    SrtpContext::new(&km, SrtpPolicy { profile: ProtectionProfile::Aes128CmHmacSha1_80, ..SrtpPolicy::default() }).unwrap()
}

fn make_webrtc_ctx(key: &[u8], salt: &[u8]) -> webrtc_srtp::context::Context {
    webrtc_srtp::context::Context::new(
        key, salt,
        webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80,
        None, None,
    ).unwrap()
}

#[test]
fn test_100_subscribers_across_wrap() {
    const NUM_SUBSCRIBERS: usize = 100;
    const PUB_KEY: [u8; 16] = [0xAA; 16];
    const PUB_SALT: [u8; 14] = [0xAA; 14];

    // Generate unique keys per subscriber
    let sub_keys: Vec<([u8; 16], [u8; 14])> = (0..NUM_SUBSCRIBERS).map(|i| {
        let mut key = [0u8; 16];
        let mut salt = [0u8; 14];
        key[0] = (i + 1) as u8;
        key[1] = ((i + 1) >> 8) as u8;
        salt[0] = (i + 1) as u8;
        (key, salt)
    }).collect();

    // SFU inbound context (decrypts publisher's packets)
    let mut sfu_inbound = make_nexus_ctx(&PUB_KEY, &PUB_SALT);

    // Per-subscriber: SFU outbound context + subscriber decrypt context
    let mut sfu_outbound: Vec<SrtpContext> = sub_keys.iter()
        .map(|(k, s)| make_nexus_ctx(k, s))
        .collect();
    let mut sub_decrypt: Vec<webrtc_srtp::context::Context> = sub_keys.iter()
        .map(|(k, s)| make_webrtc_ctx(k, s))
        .collect();

    // Publisher encrypt context
    let mut pub_encrypt = make_webrtc_ctx(&PUB_KEY, &PUB_SALT);

    let ssrc = 0xDEADBEEF_u32;
    let payload = [0xCC; 160];
    let start_seq: u16 = 62000; // wraps after ~3536 packets
    let num_packets: u32 = 5000; // well past the wrap

    let mut total_failures = 0u64;

    for i in 0..num_packets {
        let seq = start_seq.wrapping_add(i as u16);
        let plain_rtp = build_rtp(seq, ssrc, &payload);

        // Publisher encrypts
        let protected_pub = pub_encrypt.encrypt_rtp(&plain_rtp).unwrap();

        // SFU decrypts
        let mut sfu_buf = protected_pub.to_vec();
        let dec_len = sfu_inbound.unprotect_rtp(&mut sfu_buf, protected_pub.len()).unwrap();
        let decrypted = &sfu_buf[..dec_len];

        // SFU re-encrypts for each subscriber
        for sub_idx in 0..NUM_SUBSCRIBERS {
            let mut sub_buf = vec![0u8; dec_len + 16];
            sub_buf[..dec_len].copy_from_slice(decrypted);
            let prot_len = sfu_outbound[sub_idx].protect_rtp(&mut sub_buf, dec_len).unwrap();

            // Subscriber decrypts
            match sub_decrypt[sub_idx].decrypt_rtp(&sub_buf[..prot_len]) {
                Ok(dec) => {
                    assert_eq!(&dec[..], &plain_rtp[..]);
                }
                Err(_) => {
                    total_failures += 1;
                    if total_failures <= 3 {
                        eprintln!("FAIL sub={sub_idx} seq={seq} i={i}");
                    }
                }
            }
        }
    }

    eprintln!("{num_packets} packets × {NUM_SUBSCRIBERS} subscribers = {} total, {total_failures} failures",
        num_packets as u64 * NUM_SUBSCRIBERS as u64);
    assert_eq!(total_failures, 0);
}
