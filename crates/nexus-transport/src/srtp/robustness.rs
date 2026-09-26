//! Malformed and random packets through every SRTP entry point a datagram
//! reaches (Phase 1 exit criterion 6): errors, never a panic. Release builds
//! use `panic = "abort"`, so one bad packet would end the process.

use proptest::prelude::*;

use super::{
    KeyMaterial, PacketIndex, ProtectionProfile, SrtpCipher, SrtpContext, SrtpInbound,
    SrtpOutbound, SrtpPolicy, MAX_PACKET_SIZE,
};
use crate::srtp::KeyDerivation;

/// Room for the largest input plus any tag and SRTCP trailer.
const BUF_LEN: usize = MAX_PACKET_SIZE as usize + 64;

const PROFILES: [ProtectionProfile; 2] = [
    ProtectionProfile::Aes128CmHmacSha1_80,
    ProtectionProfile::AeadAes128Gcm,
];

fn material(profile: ProtectionProfile) -> KeyMaterial {
    let len = profile.key_len() + profile.salt_len();
    let bytes: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(13) ^ 0xA5)
        .collect();
    KeyMaterial::from_dtls_export(&bytes, profile).expect("key material")
}

/// All SRTP state a malformed packet can reach, per profile.
struct Targets {
    ctx: SrtpContext,
    cipher: SrtpCipher,
    inbound: SrtpInbound,
    outbound: SrtpOutbound,
}

fn targets(profile: ProtectionProfile) -> Targets {
    let km = material(profile);
    let policy = SrtpPolicy {
        profile,
        ..SrtpPolicy::default()
    };
    Targets {
        ctx: SrtpContext::new(&km, policy).expect("context"),
        cipher: SrtpCipher::new(&KeyDerivation::derive_keys(&km).expect("keys")).expect("cipher"),
        inbound: SrtpInbound::new(&km).expect("inbound"),
        outbound: registered_outbound(&km),
    }
}

/// Outbound context with the SSRCs the malformed packets carry registered,
/// so protect reaches the cipher (0x0102_0304: RTP; 0x5A5A_5A5A: RTCP).
fn registered_outbound(km: &KeyMaterial) -> SrtpOutbound {
    let mut out = SrtpOutbound::new(km, 0).expect("outbound");
    out.register(0x0102_0304).expect("register");
    out.register(0x5A5A_5A5A).expect("register");
    out
}

/// Runs every unprotect entry point on a copy of `packet`; each must refuse it.
fn assert_unprotect_refused(t: &mut Targets, packet: &[u8]) {
    let len = packet.len();
    let mut buf = vec![0u8; BUF_LEN];
    let index = PacketIndex::new(0, 1);
    let mut run = |f: &mut dyn FnMut(&mut [u8]) -> bool, what: &str| {
        buf[..len].copy_from_slice(packet);
        assert!(
            f(&mut buf),
            "{what} accepted a malformed packet (len {len})"
        );
    };
    run(
        &mut |b| t.ctx.unprotect_rtp(b, len).is_err(),
        "ctx.unprotect_rtp",
    );
    run(
        &mut |b| t.ctx.unprotect_rtcp(b, len).is_err(),
        "ctx.unprotect_rtcp",
    );
    run(
        &mut |b| t.cipher.unprotect_rtp(b, len, index).is_err(),
        "cipher.unprotect_rtp",
    );
    run(
        &mut |b| t.cipher.unprotect_rtcp(b, len).is_err(),
        "cipher.unprotect_rtcp",
    );
    run(
        &mut |b| t.inbound.unprotect_rtp(b, len, 0).is_none(),
        "inbound.unprotect_rtp",
    );
    run(
        &mut |b| t.inbound.unprotect_rtcp(b, len, 0).is_none(),
        "inbound.unprotect_rtcp",
    );
}

/// Runs every protect entry point on a copy of `packet`; returns how many
/// accepted it. Only "no panic" is required: a well-formed header protects.
fn protect_all(t: &mut Targets, packet: &[u8]) -> usize {
    let len = packet.len();
    let mut buf = vec![0u8; BUF_LEN];
    let index = PacketIndex::new(0, 1);
    let mut accepted = 0;
    let mut run = |f: &mut dyn FnMut(&mut [u8]) -> bool| {
        buf[..len].copy_from_slice(packet);
        accepted += usize::from(f(&mut buf));
    };
    run(&mut |b| t.ctx.protect_rtp(b, len).is_ok());
    run(&mut |b| t.ctx.protect_rtcp(b, len).is_ok());
    run(&mut |b| t.cipher.protect_rtp(b, len, index).is_ok());
    run(&mut |b| t.cipher.protect_rtcp(b, len, 0).is_ok());
    run(&mut |b| t.outbound.protect_rtp(b, len).is_some());
    run(&mut |b| t.outbound.protect_rtcp(b, len).is_some());
    accepted
}

/// RTP-looking packet: V=2, `csrcs` CSRCs, optional extension of `ext_words`
/// words, total length `len` (truncated or zero-padded).
fn rtp_like(csrcs: u8, ext_words: Option<u16>, len: usize) -> Vec<u8> {
    let mut p = vec![0x5Au8; len.max(16 + 4 * csrcs as usize)];
    p[0] = 0x80 | (csrcs & 0x0F) | if ext_words.is_some() { 0x10 } else { 0 };
    p[1] = 96;
    p[2..4].copy_from_slice(&7u16.to_be_bytes());
    p[8..12].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    if let Some(words) = ext_words {
        let at = 12 + 4 * csrcs as usize;
        p[at..at + 2].copy_from_slice(&[0xBE, 0xDE]);
        p[at + 2..at + 4].copy_from_slice(&words.to_be_bytes());
    }
    p.truncate(len);
    p
}

fn malformed_packets() -> Vec<(&'static str, Vec<u8>)> {
    let mut cases = Vec::new();
    for len in 0..=12 {
        cases.push(("short", rtp_like(0, None, len)));
    }
    cases.push(("extension beyond packet", rtp_like(0, Some(0xFFFF), 60)));
    cases.push(("CSRC count beyond packet", rtp_like(15, None, 40)));
    cases.push(("200-byte extension header", rtp_like(0, Some(49), 260)));
    cases.push(("140-byte header", rtp_like(15, Some(16), 200)));
    cases.push((
        "8,193 bytes",
        rtp_like(0, None, MAX_PACKET_SIZE as usize + 1),
    ));
    cases
}

#[test]
fn malformed_packets_are_refused_without_panic() {
    for profile in PROFILES {
        let mut t = targets(profile);
        for (what, packet) in malformed_packets() {
            assert_unprotect_refused(&mut t, &packet);
            assert_eq!(
                t.inbound.ssrc_count(),
                0,
                "unauthenticated packet took a slot"
            );
            let accepted = protect_all(&mut t, &packet);
            // RTCP protect legitimately accepts 8-11 bytes.
            let bad_len = packet.len() < 8 || packet.len() > MAX_PACKET_SIZE as usize;
            assert!(
                !bad_len || accepted == 0,
                "{profile:?} {what}: protect accepted a bad length"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_bytes_never_panic(
        packet in proptest::collection::vec(any::<u8>(), 0..2048),
        rtp_version in any::<bool>(),
    ) {
        let mut packet = packet;
        if rtp_version && !packet.is_empty() {
            packet[0] = 0x80 | (packet[0] & 0x3F); // reach past the version check
        }
        for profile in PROFILES {
            let mut t = targets(profile);
            assert_unprotect_refused(&mut t, &packet);
            prop_assert_eq!(t.inbound.ssrc_count(), 0);
            protect_all(&mut t, &packet);
        }
    }
}
