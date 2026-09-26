//! SRTP backend comparison (Phase 0.4, design §3.4).
//!
//! Protect and unprotect of one RTP packet (20-byte header with a one-byte
//! extension block, 160- or 1,200-byte payload) for:
//!
//! | Profile | Backend | What it is |
//! |---------|---------|------------|
//! | both | `rustcrypto-ctx` | `SrtpContext` as used today: per-SSRC `HashMap`, ROC, replay |
//! | both | `rustcrypto` | `SrtpCipher` alone, index given (the transform cost) |
//! | CM | `openssl` | EVP `aes-128-ctr` + HMAC-SHA1 from OpenSSL SHA-1 digests |
//! | CM | `openssl-ctr+ring-hmac` | EVP `aes-128-ctr` + `ring` HMAC-SHA1 |
//! | GCM | `openssl` | EVP `aes-128-gcm` |
//! | GCM | `ring` | `LessSafeKey::seal_in_place_separate_tag` / `open_in_place` |
//!
//! Every backend is a full SRTP transform (RFC 3711 IV and HMAC over header,
//! ciphertext and ROC; RFC 7714 IV with the RTP header as AAD), keyed once
//! from session keys derived by the existing `KeyDerivation`. Before timing,
//! each backend's output is checked byte-for-byte against `SrtpContext`
//! (which is itself checked against RFC vectors in
//! `nexus-transport/src/srtp/rfc_vectors.rs`), and unprotect must round-trip
//! and reject a tampered packet.
//!
//! OpenSSL HMAC: the `openssl` crate has no reusable keyed HMAC context, so
//! the HMAC is built from two SHA-1 `Hasher`s that absorbed the ipad/opad
//! block once; each packet clones both (two `EVP_MD_CTX` copies, which
//! allocate). A production OpenSSL backend would use `EVP_MAC_CTX_dup` or
//! `HMAC_Init_ex` reuse through `openssl-sys`, which avoids those copies.
//!
//! Run with: `cargo bench --bench srtp_backends`

use criterion::{black_box, BatchSize, BenchmarkId, Criterion, Throughput};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::hash::{Hasher, MessageDigest};

use nexus_transport::srtp::{
    KeyDerivation, KeyMaterial, PacketIndex, ProtectionProfile, SrtpCipher, SrtpContext, SrtpKeys,
    SrtpPolicy,
};

const SSRC: u32 = 0x1234_5678;
const HEADER_LEN: usize = 20;
const PAYLOADS: [usize; 2] = [160, 1200];
const CM_TAG: usize = 10;
const GCM_TAG: usize = 16;
const BUF_LEN: usize = 1500;

const PROFILES: [(&str, ProtectionProfile); 2] = [
    ("cm_sha1_80", ProtectionProfile::Aes128CmHmacSha1_80),
    ("gcm", ProtectionProfile::AeadAes128Gcm),
];

// =============================================================================
// Packets and keys
// =============================================================================

/// Browser-like RTP packet: one-byte extension block with a transport-wide
/// sequence number. Returns its length.
fn write_rtp(buf: &mut [u8], seq: u16, payload: usize) -> usize {
    assert!(buf.len() >= HEADER_LEN + payload + GCM_TAG);
    buf[0] = 0x90; // V=2, X=1
    buf[1] = 0x60; // PT=96
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    buf[4..8].copy_from_slice(&(seq as u32 * 3000).to_be_bytes());
    buf[8..12].copy_from_slice(&SSRC.to_be_bytes());
    buf[12..16].copy_from_slice(&[0xBE, 0xDE, 0x00, 0x01]);
    buf[16] = 0x31; // id 3, len 2
    buf[17..19].copy_from_slice(&seq.to_be_bytes());
    buf[19] = 0;
    for (i, b) in buf[HEADER_LEN..HEADER_LEN + payload].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31);
    }
    HEADER_LEN + payload
}

/// RTP header length including CSRCs and the extension block.
fn rtp_header_len(pkt: &[u8]) -> usize {
    assert!(pkt.len() >= 12 && pkt[0] >> 6 == 2, "RTP v2 packet");
    let mut len = 12 + 4 * (pkt[0] & 0x0F) as usize;
    if pkt[0] & 0x10 != 0 {
        let words = u16::from_be_bytes([pkt[len + 2], pkt[len + 3]]) as usize;
        len += 4 + 4 * words;
    }
    assert!(len <= pkt.len());
    len
}

fn material(profile: ProtectionProfile) -> KeyMaterial {
    let len = profile.key_len() + profile.salt_len();
    let bytes: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(37) ^ 0x5A)
        .collect();
    KeyMaterial::from_dtls_export(&bytes, profile).expect("key material")
}

fn context(km: &KeyMaterial) -> SrtpContext {
    let policy = SrtpPolicy {
        profile: km.profile,
        ..SrtpPolicy::default()
    };
    SrtpContext::new(km, policy).expect("context")
}

/// RFC 3711 §4.1.1: (salt · 2^16) XOR (SSRC · 2^64) XOR (index · 2^16).
fn cm_iv(salt: &[u8], ssrc: u32, index: PacketIndex) -> [u8; 16] {
    assert_eq!(salt.len(), 14);
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(salt);
    for (b, s) in iv[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
        *b ^= s;
    }
    for (b, s) in iv[8..14].iter_mut().zip(&index.value().to_be_bytes()[2..]) {
        *b ^= s;
    }
    iv
}

/// RFC 7714 §8.1: salt XOR (00 00 || SSRC || ROC || SEQ).
fn gcm_iv(salt: &[u8], ssrc: u32, index: PacketIndex) -> [u8; 12] {
    assert_eq!(salt.len(), 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(salt);
    for (b, s) in iv[2..6].iter_mut().zip(ssrc.to_be_bytes()) {
        *b ^= s;
    }
    for (b, s) in iv[6..12].iter_mut().zip(&index.value().to_be_bytes()[2..]) {
        *b ^= s;
    }
    iv
}

fn ssrc_of(pkt: &[u8]) -> u32 {
    u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]])
}

// =============================================================================
// Backends
// =============================================================================

/// One SRTP transform. `index` is the packet index the caller estimated;
/// `ContextBackend` ignores it and tracks ROC itself.
trait Backend {
    fn protect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> usize;
    fn unprotect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> Option<usize>;
}

/// Today's path: `SrtpContext` (separate sender and receiver, like two peers).
struct ContextBackend {
    tx: SrtpContext,
    rx: SrtpContext,
}

impl Backend for ContextBackend {
    fn protect(&mut self, buf: &mut [u8], len: usize, _: PacketIndex) -> usize {
        self.tx.protect_rtp(buf, len).expect("protect")
    }
    fn unprotect(&mut self, buf: &mut [u8], len: usize, _: PacketIndex) -> Option<usize> {
        self.rx.unprotect_rtp(buf, len).ok()
    }
}

/// `SrtpCipher` alone: RustCrypto transform cost without context bookkeeping.
struct CipherBackend(SrtpCipher);

impl Backend for CipherBackend {
    fn protect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> usize {
        self.0.protect_rtp(buf, len, index).expect("protect")
    }
    fn unprotect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> Option<usize> {
        self.0.unprotect_rtp(buf, len, index).ok()
    }
}

/// HMAC-SHA1 from OpenSSL SHA-1: inner/outer states keyed once, cloned per use.
struct OsslHmac {
    inner: Hasher,
    outer: Hasher,
}

impl OsslHmac {
    fn new(key: &[u8]) -> Self {
        assert!(key.len() <= 64, "HMAC-SHA1 key longer than a block");
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for (i, k) in key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }
        let mut inner = Hasher::new(MessageDigest::sha1()).expect("sha1");
        inner.update(&ipad).expect("ipad");
        let mut outer = Hasher::new(MessageDigest::sha1()).expect("sha1");
        outer.update(&opad).expect("opad");
        Self { inner, outer }
    }

    fn tag(&self, data: &[u8], roc: u32) -> [u8; 20] {
        let mut inner = self.inner.clone();
        inner.update(data).expect("update");
        inner.update(&roc.to_be_bytes()).expect("update");
        let digest = inner.finish().expect("finish");
        let mut outer = self.outer.clone();
        outer.update(&digest).expect("update");
        let mut tag = [0u8; 20];
        tag.copy_from_slice(&outer.finish().expect("finish"));
        tag
    }
}

/// HMAC-SHA1 implementations usable with the OpenSSL CTR backend.
enum Mac {
    Openssl(OsslHmac),
    Ring(ring::hmac::Key),
}

impl Mac {
    fn tag(&self, data: &[u8], roc: u32) -> [u8; 20] {
        match self {
            Mac::Openssl(h) => h.tag(data, roc),
            Mac::Ring(key) => {
                let mut ctx = ring::hmac::Context::with_key(key);
                ctx.update(data);
                ctx.update(&roc.to_be_bytes());
                let mut tag = [0u8; 20];
                tag.copy_from_slice(ctx.sign().as_ref());
                tag
            }
        }
    }
}

/// AES-128-CM via EVP `aes-128-ctr` (key schedule built once; per packet
/// only the IV is set) + HMAC-SHA1-80.
struct OsslCmBackend {
    ctr: CipherCtx,
    salt: [u8; 14],
    mac: Mac,
}

impl OsslCmBackend {
    fn new(keys: &SrtpKeys, ring_mac: bool) -> Self {
        let mut ctr = CipherCtx::new().expect("ctx");
        ctr.encrypt_init(Some(Cipher::aes_128_ctr()), Some(keys.rtp_key()), None)
            .expect("ctr init");
        let auth = &keys.rtp_auth[..keys.rtp_auth_len];
        let mac = if ring_mac {
            Mac::Ring(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                auth,
            ))
        } else {
            Mac::Openssl(OsslHmac::new(auth))
        };
        let mut salt = [0u8; 14];
        salt.copy_from_slice(keys.rtp_salt());
        Self { ctr, salt, mac }
    }

    fn apply_keystream(&mut self, data: &mut [u8], ssrc: u32, index: PacketIndex) {
        let iv = cm_iv(&self.salt, ssrc, index);
        self.ctr.encrypt_init(None, None, Some(&iv)).expect("iv");
        let n = data.len();
        let out = self.ctr.cipher_update_inplace(data, n).expect("ctr");
        assert_eq!(out, n);
    }
}

impl Backend for OsslCmBackend {
    fn protect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> usize {
        let h = rtp_header_len(&buf[..len]);
        let ssrc = ssrc_of(buf);
        self.apply_keystream(&mut buf[h..len], ssrc, index);
        let tag = self.mac.tag(&buf[..len], index.roc());
        buf[len..len + CM_TAG].copy_from_slice(&tag[..CM_TAG]);
        len + CM_TAG
    }

    fn unprotect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> Option<usize> {
        let end = len.checked_sub(CM_TAG)?;
        let h = rtp_header_len(&buf[..end]);
        let tag = self.mac.tag(&buf[..end], index.roc());
        if !openssl::memcmp::eq(&tag[..CM_TAG], &buf[end..len]) {
            return None;
        }
        let ssrc = ssrc_of(buf);
        self.apply_keystream(&mut buf[h..end], ssrc, index);
        Some(end)
    }
}

/// AES-128-GCM via EVP; one context per direction, keyed once.
struct OsslGcmBackend {
    enc: CipherCtx,
    dec: CipherCtx,
    salt: [u8; 12],
}

impl OsslGcmBackend {
    fn new(keys: &SrtpKeys) -> Self {
        let gcm = Cipher::aes_128_gcm();
        let mut enc = CipherCtx::new().expect("ctx");
        enc.encrypt_init(Some(gcm), Some(keys.rtp_key()), None)
            .expect("gcm init");
        let mut dec = CipherCtx::new().expect("ctx");
        dec.decrypt_init(Some(gcm), Some(keys.rtp_key()), None)
            .expect("gcm init");
        let mut salt = [0u8; 12];
        salt.copy_from_slice(keys.rtp_salt());
        Self { enc, dec, salt }
    }
}

impl Backend for OsslGcmBackend {
    fn protect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> usize {
        let h = rtp_header_len(&buf[..len]);
        let iv = gcm_iv(&self.salt, ssrc_of(buf), index);
        let (header, rest) = buf.split_at_mut(h);
        let ctx = &mut self.enc;
        ctx.encrypt_init(None, None, Some(&iv)).expect("iv");
        ctx.cipher_update(header, None).expect("aad");
        let n = len - h;
        assert_eq!(ctx.cipher_update_inplace(rest, n).expect("enc"), n);
        assert_eq!(ctx.cipher_final(&mut []).expect("final"), 0);
        ctx.tag(&mut rest[n..n + GCM_TAG]).expect("tag");
        len + GCM_TAG
    }

    fn unprotect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> Option<usize> {
        let end = len.checked_sub(GCM_TAG)?;
        let h = rtp_header_len(&buf[..end]);
        let iv = gcm_iv(&self.salt, ssrc_of(buf), index);
        let (header, rest) = buf.split_at_mut(h);
        let n = end - h;
        let ctx = &mut self.dec;
        ctx.decrypt_init(None, None, Some(&iv)).expect("iv");
        ctx.set_tag(&rest[n..n + GCM_TAG]).expect("tag");
        ctx.cipher_update(header, None).expect("aad");
        assert_eq!(ctx.cipher_update_inplace(rest, n).expect("dec"), n);
        ctx.cipher_final(&mut []).ok()?;
        Some(end)
    }
}

/// AES-128-GCM via `ring`.
struct RingGcmBackend {
    key: ring::aead::LessSafeKey,
    salt: [u8; 12],
}

impl RingGcmBackend {
    fn new(keys: &SrtpKeys) -> Self {
        let unbound =
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, keys.rtp_key()).expect("key");
        let mut salt = [0u8; 12];
        salt.copy_from_slice(keys.rtp_salt());
        Self {
            key: ring::aead::LessSafeKey::new(unbound),
            salt,
        }
    }
}

impl Backend for RingGcmBackend {
    fn protect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> usize {
        use ring::aead::{Aad, Nonce};
        let h = rtp_header_len(&buf[..len]);
        let nonce = Nonce::assume_unique_for_key(gcm_iv(&self.salt, ssrc_of(buf), index));
        let (header, rest) = buf.split_at_mut(h);
        let n = len - h;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&*header), &mut rest[..n])
            .expect("seal");
        rest[n..n + GCM_TAG].copy_from_slice(tag.as_ref());
        len + GCM_TAG
    }

    fn unprotect(&mut self, buf: &mut [u8], len: usize, index: PacketIndex) -> Option<usize> {
        use ring::aead::{Aad, Nonce};
        let end = len.checked_sub(GCM_TAG)?;
        let h = rtp_header_len(&buf[..end]);
        let nonce = Nonce::assume_unique_for_key(gcm_iv(&self.salt, ssrc_of(buf), index));
        let (header, rest) = buf.split_at_mut(h);
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(&*header), &mut rest[..len - h])
            .ok()?;
        Some(h + plain.len())
    }
}

fn backend_names(profile: ProtectionProfile) -> [&'static str; 4] {
    if profile.is_aead() {
        ["rustcrypto-ctx", "rustcrypto", "openssl", "ring"]
    } else {
        [
            "rustcrypto-ctx",
            "rustcrypto",
            "openssl",
            "openssl-ctr+ring-hmac",
        ]
    }
}

/// A fresh backend, keyed from the same master key material as all others.
fn make_backend(profile: ProtectionProfile, name: &str) -> Box<dyn Backend> {
    let km = material(profile);
    let keys = KeyDerivation::derive_keys(&km).expect("derive");
    match (name, profile.is_aead()) {
        ("rustcrypto-ctx", _) => Box::new(ContextBackend {
            tx: context(&km),
            rx: context(&km),
        }),
        ("rustcrypto", _) => Box::new(CipherBackend(SrtpCipher::new(&keys).expect("cipher"))),
        ("openssl", true) => Box::new(OsslGcmBackend::new(&keys)),
        ("ring", true) => Box::new(RingGcmBackend::new(&keys)),
        ("openssl", false) => Box::new(OsslCmBackend::new(&keys, false)),
        ("openssl-ctr+ring-hmac", false) => Box::new(OsslCmBackend::new(&keys, true)),
        _ => panic!("unknown backend {name} for {profile:?}"),
    }
}

// =============================================================================
// Correctness check (before any timing)
// =============================================================================

/// Assert `backend` matches `SrtpContext` byte for byte (ROC 0) and
/// `SrtpCipher` at ROC 3, round-trips, and rejects a tampered packet.
fn verify(profile: ProtectionProfile, name: &str) {
    let km = material(profile);
    let reference = SrtpCipher::new(&KeyDerivation::derive_keys(&km).expect("keys")).unwrap();
    let is_ctx = name == "rustcrypto-ctx";
    for payload in PAYLOADS {
        for (roc, seq) in [(0u32, 1u16), (0, 2), (0, 0x8000), (3, 0x0102)] {
            if is_ctx && roc != 0 {
                continue; // The context derives ROC itself; covered at ROC 0.
            }
            let index = PacketIndex::new(roc, seq);
            let mut plain = [0u8; BUF_LEN];
            let len = write_rtp(&mut plain, seq, payload);

            let mut expected = plain;
            let expected_len = if roc == 0 {
                // Fresh context: first packet of the SSRC has ROC 0.
                context(&km)
                    .protect_rtp(&mut expected, len)
                    .expect("protect")
            } else {
                reference.protect_rtp(&mut expected, len, index).unwrap()
            };

            // Fresh per case: the context backend tracks ROC and replay.
            let mut backend = make_backend(profile, name);
            let mut ours = plain;
            let ours_len = backend.protect(&mut ours, len, index);
            assert_eq!(ours_len, expected_len, "{name}: protected length");
            assert_eq!(
                ours[..ours_len],
                expected[..expected_len],
                "{name}: protect output differs from SrtpContext (payload {payload}, {index})"
            );

            let mut backend = make_backend(profile, name);
            let mut back = expected;
            let back_len = backend
                .unprotect(&mut back, expected_len, index)
                .unwrap_or_else(|| panic!("{name}: unprotect failed ({index})"));
            assert_eq!(back[..back_len], plain[..len], "{name}: round trip");

            let mut backend = make_backend(profile, name);
            let mut tampered = expected;
            tampered[HEADER_LEN + 3] ^= 0x01;
            let result = backend.unprotect(&mut tampered, expected_len, index);
            assert!(result.is_none(), "{name}: tampered packet accepted");
        }
    }
}

// =============================================================================
// Benchmarks
// =============================================================================

fn bench_backends(c: &mut Criterion) {
    for (profile_name, profile) in PROFILES {
        for name in backend_names(profile) {
            verify(profile, name);
            let id = format!("{profile_name}/{name}");
            bench_protect(c, &id, make_backend(profile, name).as_mut());
            let mut sender = make_backend(profile, name);
            let mut receiver = make_backend(profile, name);
            bench_unprotect(c, &id, sender.as_mut(), receiver.as_mut());
        }
    }
}

fn bench_protect(c: &mut Criterion, id: &str, backend: &mut dyn Backend) {
    let mut protect_seq = 0u16;
    let mut group = c.benchmark_group("protect");
    group.throughput(Throughput::Elements(1));
    for payload in PAYLOADS {
        group.bench_with_input(BenchmarkId::new(id, payload), &payload, |b, &payload| {
            b.iter_batched_ref(
                || {
                    protect_seq = protect_seq.wrapping_add(1);
                    let mut buf = [0u8; BUF_LEN];
                    let len = write_rtp(&mut buf, protect_seq, payload);
                    (buf, len, PacketIndex::new(0, protect_seq))
                },
                |(buf, len, index)| black_box(backend.protect(buf, *len, *index)),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// `sender` builds the packets (untimed), `receiver` unprotects them. Both
/// fresh: for the context backend they see the same increasing sequence
/// numbers, so ROC stays in step across wraps.
fn bench_unprotect(
    c: &mut Criterion,
    id: &str,
    sender: &mut dyn Backend,
    receiver: &mut dyn Backend,
) {
    let mut seq = 0u16;
    let mut group = c.benchmark_group("unprotect");
    group.throughput(Throughput::Elements(1));
    for payload in PAYLOADS {
        group.bench_with_input(BenchmarkId::new(id, payload), &payload, |b, &payload| {
            b.iter_batched_ref(
                || {
                    seq = seq.wrapping_add(1);
                    let index = PacketIndex::new(0, seq);
                    let mut buf = [0u8; BUF_LEN];
                    let len = write_rtp(&mut buf, seq, payload);
                    let len = sender.protect(&mut buf, len, index);
                    (buf, len, index)
                },
                |(buf, len, index)| {
                    let out = receiver.unprotect(buf, *len, *index);
                    black_box(out.expect("unprotect"))
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench_backends(&mut c);
    c.final_summary();
}
