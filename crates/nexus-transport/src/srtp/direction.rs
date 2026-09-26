//! SRTP contexts per direction for the shard (design note §9.1).
//!
//! `SrtpInbound` unprotects what one peer sends; `SrtpOutbound` protects what
//! the SFU sends to that peer. Per-SSRC state lives in fixed arrays scanned
//! linearly, so the packet path never allocates. Every failure returns `None`:
//! these functions are reached by network input and must never panic.
//!
//! - **Inbound.** SSRCs signaled in the SDP are [pinned](SrtpInbound::pin) by
//!   the control path and never evicted: an evicted media SSRC that came back
//!   after a sequence wrap would restart at ROC 0, fail authentication for the
//!   rest of the session, and lose its replay window. Other SSRCs (a receiver's
//!   RTCP SSRCs) take a slot only after a packet from them authenticated, so
//!   unauthenticated packets cannot fill the table; when it is full, the
//!   unpinned entry idle longest is evicted if idle over
//!   [`INBOUND_IDLE_EVICT_S`], else the packet is dropped.
//! - **Outbound** protects only SSRCs [registered](SrtpOutbound::register) by
//!   the control path. Registration enforces the §9.3 rule itself: offsets
//!   from the session's SSRC base strictly increase, so an SSRC is never
//!   registered twice, and a retired SSRC can never send again. Each SSRC keeps
//!   a window of sent packet indices and refuses to protect an index twice.
//!   Together, no (key, SSRC, index) — and so no GCM nonce or CM keystream —
//!   is ever used twice, independently of the shard's own `Subscribe` check.

use super::crypto::SrtpCipher;
use super::error::SrtpError;
use super::index::RocState;
use super::keys::{KeyDerivation, KeyMaterial, SrtpKeys};
use super::replay::ReplayProtection;
use super::types::PacketIndex;
use super::{RTCP_HEADER_SIZE, RTP_HEADER_SIZE, SRTCP_E_FLAG, SRTCP_INDEX_MASK};

/// Inbound SSRC slots: the peer's media SSRCs (≤ 10) plus the SSRCs it sends
/// RTCP from as a receiver.
pub const INBOUND_SSRC_SLOTS: usize = 16;

/// Inbound slots that may be pinned; the rest stay for unsignaled SSRCs.
pub const INBOUND_PINNED_MAX: usize = 12;

/// Outbound SSRC slots: one per subscription (≤ 30) plus the session's
/// `rtcp_ssrc`.
pub const OUTBOUND_SSRC_SLOTS: usize = 32;

/// An unpinned inbound SSRC idle longer than this may be evicted when the
/// table is full.
pub const INBOUND_IDLE_EVICT_S: u32 = 30;

/// Largest outbound SSRC offset from the session base (§9.3: `n < 2^31`).
const MAX_SSRC_OFFSET: u32 = (1 << 31) - 1;

const _: () = assert!(INBOUND_PINNED_MAX < INBOUND_SSRC_SLOTS);

#[derive(Debug, Clone)]
struct SsrcIn {
    ssrc: u32,
    live: bool,
    /// Signaled in the SDP: never evicted.
    pinned: bool,
    roc: RocState,
    rtp_replay: ReplayProtection,
    rtcp_replay: ReplayProtection,
    last_seen_s: u32,
}

impl SsrcIn {
    const EMPTY: Self = Self {
        ssrc: 0,
        live: false,
        pinned: false,
        roc: RocState::new(),
        rtp_replay: ReplayProtection::new(),
        rtcp_replay: ReplayProtection::new(),
        last_seen_s: 0,
    };

    const fn fresh(ssrc: u32, now_s: u32) -> Self {
        Self {
            ssrc,
            live: true,
            last_seen_s: now_s,
            ..Self::EMPTY
        }
    }
}

#[derive(Debug, Clone)]
struct SsrcOut {
    ssrc: u32,
    live: bool,
    roc: RocState,
    /// Indices already protected (the replay window, used on the send side).
    sent: ReplayProtection,
    /// Next SRTCP index for this sender SSRC.
    srtcp_index: u32,
}

impl SsrcOut {
    const EMPTY: Self = Self {
        ssrc: 0,
        live: false,
        roc: RocState::new(),
        sent: ReplayProtection::new(),
        srtcp_index: 0,
    };

    const fn fresh(ssrc: u32) -> Self {
        Self {
            ssrc,
            live: true,
            ..Self::EMPTY
        }
    }
}

/// Reads a big-endian `u32` at `at`; the caller checked the bounds.
fn be_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Offset of the E+index word of an SRTCP packet of `len` bytes: last for
/// AEAD (RFC 7714 §9), before the tag for AES-CM (RFC 3711 §3.4).
fn srtcp_trailer_offset(cipher: &SrtpCipher, len: usize) -> Option<usize> {
    let trailer = match cipher {
        SrtpCipher::AesGcm(_) => 4,
        SrtpCipher::AesCmHmac(_) => cipher.tag_len() + 4,
    };
    let at = len.checked_sub(trailer)?;
    (at >= RTCP_HEADER_SIZE).then_some(at)
}

// ============================================================================
// Inbound
// ============================================================================

/// Unprotects SRTP and SRTCP from one peer.
#[derive(Debug)]
pub struct SrtpInbound {
    cipher: SrtpCipher,
    slots: [SsrcIn; INBOUND_SSRC_SLOTS],
}

impl SrtpInbound {
    /// Builds the context from the peer's master key (control path).
    pub fn new(material: &KeyMaterial) -> Result<Self, SrtpError> {
        Self::from_keys(&KeyDerivation::derive_keys(material)?)
    }

    /// Builds the context from derived session keys.
    pub fn from_keys(keys: &SrtpKeys) -> Result<Self, SrtpError> {
        Ok(Self {
            cipher: SrtpCipher::new(keys)?,
            slots: [SsrcIn::EMPTY; INBOUND_SSRC_SLOTS],
        })
    }

    /// Number of SSRCs holding a slot.
    pub fn ssrc_count(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    /// Number of pinned SSRCs.
    pub fn pinned_count(&self) -> usize {
        self.slots.iter().filter(|s| s.live && s.pinned).count()
    }

    /// Pins `ssrc` (signaled in the SDP, or bound to a track by SSRC
    /// learning) so it is never evicted (command path). An SSRC that already
    /// has a slot keeps its state. Otherwise it takes a free slot, else the
    /// slot of the idlest unpinned SSRC. Refused beyond [`INBOUND_PINNED_MAX`].
    pub fn pin(&mut self, ssrc: u32) -> Result<(), SrtpError> {
        let existing = self.slots.iter().position(|s| s.live && s.ssrc == ssrc);
        if existing.is_some_and(|i| self.slots[i].pinned) {
            return Ok(());
        }
        if self.pinned_count() >= INBOUND_PINNED_MAX {
            return Err(SrtpError::SessionLimitReached);
        }
        let slot = match existing {
            Some(i) => i,
            None => {
                let i = self
                    .slot_to_replace()
                    .ok_or(SrtpError::SessionLimitReached)?;
                self.slots[i] = SsrcIn::fresh(ssrc, 0);
                i
            }
        };
        self.slots[slot].pinned = true;
        assert!(self.pinned_count() <= INBOUND_PINNED_MAX);
        self.debug_check();
        Ok(())
    }

    /// Unpins `ssrc` (its track was removed). The slot keeps its state, so its
    /// replay window still covers old packets, until it is evicted as idle.
    pub fn unpin(&mut self, ssrc: u32) {
        if let Some(state) = self.slots.iter_mut().find(|s| s.live && s.ssrc == ssrc) {
            state.pinned = false;
        }
    }

    /// A free slot, else the slot of the unpinned SSRC seen longest ago.
    fn slot_to_replace(&self) -> Option<usize> {
        let free = self.slots.iter().position(|s| !s.live);
        let oldest = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.pinned)
            .min_by_key(|(_, s)| s.last_seen_s)
            .map(|(i, _)| i);
        free.or(oldest)
    }

    /// Unprotects the SRTP packet `buf[..len]` in place; returns the RTP length.
    pub fn unprotect_rtp(&mut self, buf: &mut [u8], len: usize, now_s: u32) -> Option<usize> {
        if len < RTP_HEADER_SIZE || len > buf.len() {
            return None;
        }
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ssrc = be_u32(buf, 8);
        let slot = self.slot_for(ssrc, now_s)?;

        let state = &mut self.slots[slot];
        let known = state.live && state.ssrc == ssrc;
        let index = if known {
            let index = state.roc.estimate_index(seq).ok()?;
            state.rtp_replay.check(index.value()).ok()?;
            index
        } else {
            PacketIndex::new(0, seq)
        };

        let out = self.cipher.unprotect_rtp(buf, len, index).ok()?;

        // Authenticated: only now does the SSRC get (or keep) its slot.
        let state = &mut self.slots[slot];
        if !known {
            *state = SsrcIn::fresh(ssrc, now_s);
        }
        state.rtp_replay.accept(index.value());
        // Cannot fail: estimate_index succeeded for the same seq.
        let updated = state.roc.update(seq);
        debug_assert!(updated.is_ok());
        state.last_seen_s = now_s;
        debug_assert!(out < len && out >= RTP_HEADER_SIZE);
        self.debug_check();
        Some(out)
    }

    /// Unprotects the SRTCP packet `buf[..len]` in place; returns the RTCP
    /// length. Unencrypted SRTCP (E = 0) is refused: WebRTC always encrypts.
    pub fn unprotect_rtcp(&mut self, buf: &mut [u8], len: usize, now_s: u32) -> Option<usize> {
        if len < RTCP_HEADER_SIZE || len > buf.len() {
            return None;
        }
        let at = srtcp_trailer_offset(&self.cipher, len)?;
        let e_index = be_u32(buf, at);
        if e_index & SRTCP_E_FLAG == 0 {
            return None;
        }
        let index = e_index & SRTCP_INDEX_MASK;
        let ssrc = be_u32(buf, 4);
        let slot = self.slot_for(ssrc, now_s)?;

        let state = &mut self.slots[slot];
        let known = state.live && state.ssrc == ssrc;
        if known {
            state.rtcp_replay.check(u64::from(index)).ok()?;
        }

        let (out, authenticated_index) = self.cipher.unprotect_rtcp(buf, len).ok()?;
        debug_assert!(authenticated_index == index);

        let state = &mut self.slots[slot];
        if !known {
            *state = SsrcIn::fresh(ssrc, now_s);
        }
        state.rtcp_replay.accept(u64::from(index));
        state.last_seen_s = now_s;
        debug_assert!(out >= RTCP_HEADER_SIZE && out < len);
        self.debug_check();
        Some(out)
    }

    /// Frees every unpinned slot idle longer than `idle_s`; returns how many.
    pub fn evict_idle(&mut self, now_s: u32, idle_s: u32) -> usize {
        let mut evicted = 0;
        for state in self.slots.iter_mut() {
            let idle = now_s.saturating_sub(state.last_seen_s);
            if state.live && !state.pinned && idle > idle_s {
                state.live = false;
                evicted += 1;
            }
        }
        evicted
    }

    /// The slot holding `ssrc`, else a free one, else the unpinned one idle
    /// longest if idle over [`INBOUND_IDLE_EVICT_S`]. Nothing is written here.
    fn slot_for(&self, ssrc: u32, now_s: u32) -> Option<usize> {
        let mut free = None;
        let mut idlest: Option<(usize, u32)> = None;
        for (i, state) in self.slots.iter().enumerate() {
            if !state.live {
                free = free.or(Some(i));
                continue;
            }
            if state.ssrc == ssrc {
                return Some(i);
            }
            if state.pinned {
                continue;
            }
            let idle = now_s.saturating_sub(state.last_seen_s);
            if idlest.map_or(true, |(_, most)| idle > most) {
                idlest = Some((i, idle));
            }
        }
        free.or(idlest
            .filter(|&(_, idle)| idle > INBOUND_IDLE_EVICT_S)
            .map(|(i, _)| i))
    }

    fn debug_check(&self) {
        if cfg!(debug_assertions) {
            let live = || self.slots.iter().filter(|s| s.live);
            for (i, a) in live().enumerate() {
                debug_assert!(
                    live().skip(i + 1).all(|b| b.ssrc != a.ssrc),
                    "duplicate SSRC"
                );
            }
            debug_assert!(self.slots.iter().all(|s| s.live || !s.pinned));
        }
    }
}

// ============================================================================
// Outbound
// ============================================================================

/// Protects SRTP and SRTCP sent to one peer.
#[derive(Debug)]
pub struct SrtpOutbound {
    cipher: SrtpCipher,
    slots: [SsrcOut; OUTBOUND_SSRC_SLOTS],
    /// The session's SSRC base (§9.3); SSRCs are `base + offset`.
    ssrc_base: u32,
    /// Smallest offset a new registration may use: one past the last one.
    next_offset: u32,
}

impl SrtpOutbound {
    /// Builds the context from the SFU's master key toward this peer and the
    /// session's SSRC base (control path).
    pub fn new(material: &KeyMaterial, ssrc_base: u32) -> Result<Self, SrtpError> {
        Self::from_keys(&KeyDerivation::derive_keys(material)?, ssrc_base)
    }

    /// Builds the context from derived session keys.
    pub fn from_keys(keys: &SrtpKeys, ssrc_base: u32) -> Result<Self, SrtpError> {
        Ok(Self {
            cipher: SrtpCipher::new(keys)?,
            slots: [SsrcOut::EMPTY; OUTBOUND_SSRC_SLOTS],
            ssrc_base,
            next_offset: 0,
        })
    }

    /// Number of SSRCs holding a slot.
    pub fn ssrc_count(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    /// Authentication tag length of the negotiated profile.
    pub fn tag_len(&self) -> usize {
        self.cipher.tag_len()
    }

    /// Registers `ssrc` for sending (command path, on `Subscribe` and for the
    /// session's `rtcp_ssrc`). Its offset from the SSRC base must be greater
    /// than every offset registered before (`InvalidSsrc` otherwise), so no
    /// SSRC, retired or live, is ever registered twice.
    pub fn register(&mut self, ssrc: u32) -> Result<(), SrtpError> {
        let offset = ssrc.wrapping_sub(self.ssrc_base);
        if offset < self.next_offset || offset > MAX_SSRC_OFFSET {
            return Err(SrtpError::InvalidSsrc);
        }
        let slot = self
            .slots
            .iter()
            .position(|s| !s.live)
            .ok_or(SrtpError::SessionLimitReached)?;
        self.slots[slot] = SsrcOut::fresh(ssrc);
        self.next_offset = offset + 1;
        assert!(
            self.slots
                .iter()
                .filter(|s| s.live && s.ssrc == ssrc)
                .count()
                == 1
        );
        Ok(())
    }

    /// Protects the RTP packet `buf[..len]` in place; returns the SRTP length.
    /// Refuses an unregistered SSRC, and a packet index this SSRC already
    /// sent or one older than the 64-packet window (§9.3).
    pub fn protect_rtp(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < RTP_HEADER_SIZE || len > buf.len() {
            return None;
        }
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let slot = self.slot_of(be_u32(buf, 8))?;

        let state = &mut self.slots[slot];
        let index = state.roc.estimate_index(seq).ok()?;
        state.sent.check(index.value()).ok()?;

        let out = self.cipher.protect_rtp(buf, len, index).ok()?;

        let state = &mut self.slots[slot];
        state.sent.accept(index.value());
        // Cannot fail: estimate_index succeeded for the same seq.
        let updated = state.roc.update(seq);
        debug_assert!(updated.is_ok());
        debug_assert!(out == len + self.cipher.tag_len());
        Some(out)
    }

    /// Protects the RTCP packet `buf[..len]` in place under the registered
    /// sender SSRC in bytes 4-7; returns the SRTCP length.
    pub fn protect_rtcp(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < RTCP_HEADER_SIZE || len > buf.len() {
            return None;
        }
        let slot = self.slot_of(be_u32(buf, 4))?;
        let index = self.slots[slot].srtcp_index;
        if index >= SRTCP_INDEX_MASK {
            return None;
        }

        let out = self.cipher.protect_rtcp(buf, len, index).ok()?;

        self.slots[slot].srtcp_index = index + 1;
        debug_assert!(out == len + 4 + self.cipher.tag_len());
        Some(out)
    }

    /// Frees the slot of `ssrc` (its subscription ended). The SSRC cannot be
    /// registered again: its offset is below every future one.
    pub fn retire(&mut self, ssrc: u32) {
        if let Some(state) = self.slots.iter_mut().find(|s| s.live && s.ssrc == ssrc) {
            state.live = false;
        }
        debug_assert!(self.slot_of(ssrc).is_none());
    }

    /// The slot of a registered `ssrc`.
    fn slot_of(&self, ssrc: u32) -> Option<usize> {
        self.slots.iter().position(|s| s.live && s.ssrc == ssrc)
    }

    /// Sets the next SRTCP index of a registered `ssrc` (RFC 7714 §16.2 vector).
    #[cfg(test)]
    pub(crate) fn set_srtcp_index(&mut self, ssrc: u32, index: u32) {
        let slot = self.slot_of(ssrc).expect("registered SSRC");
        self.slots[slot].srtcp_index = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::{ProtectionProfile, SrtpContext, SrtpError, SrtpPolicy};

    const PROFILES: [ProtectionProfile; 2] = [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ];
    const SSRC: u32 = 0x1234_5678;

    fn master(profile: ProtectionProfile) -> Vec<u8> {
        let len = profile.key_len() + profile.salt_len();
        (0..len).map(|i| (i as u8).wrapping_mul(7) ^ 0x3C).collect()
    }

    fn material(profile: ProtectionProfile) -> KeyMaterial {
        KeyMaterial::from_dtls_export(&master(profile), profile).unwrap()
    }

    fn context(profile: ProtectionProfile) -> SrtpContext {
        let policy = SrtpPolicy {
            profile,
            ..SrtpPolicy::default()
        };
        SrtpContext::new(&material(profile), policy).unwrap()
    }

    fn rtp(buf: &mut [u8], ssrc: u32, seq: u16) -> usize {
        buf[0] = 0x80;
        buf[1] = 111;
        buf[2..4].copy_from_slice(&seq.to_be_bytes());
        buf[4..8].copy_from_slice(&(u32::from(seq) * 960).to_be_bytes());
        buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
        for (i, b) in buf[12..112].iter_mut().enumerate() {
            *b = (i as u8) ^ (seq as u8);
        }
        112
    }

    fn rtcp_rr(buf: &mut [u8], ssrc: u32) -> usize {
        buf[..8].copy_from_slice(&[0x80, 201, 0, 1, 0, 0, 0, 0]);
        buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
        8
    }

    /// Outbound context with base 0 and `ssrcs` registered in order.
    fn outbound(profile: ProtectionProfile, ssrcs: &[u32]) -> SrtpOutbound {
        let mut out = SrtpOutbound::new(&material(profile), 0).unwrap();
        for &ssrc in ssrcs {
            out.register(ssrc).unwrap();
        }
        out
    }

    /// Protects one RTP packet with `out`; `None` if refused.
    fn send(out: &mut SrtpOutbound, ssrc: u32, seq: u16) -> Option<([u8; 256], usize)> {
        let mut buf = [0u8; 256];
        let len = rtp(&mut buf, ssrc, seq);
        out.protect_rtp(&mut buf, len).map(|n| (buf, n))
    }

    /// Wrap from 65,500 with reordering across it: 65534, 0, 65535, 1, ...
    fn wrap_sequence() -> Vec<u16> {
        let mut seqs: Vec<u16> = (65_500..=65_533).collect();
        seqs.extend([65_534, 0, 65_535, 2, 1]);
        seqs.extend(3..40);
        seqs
    }

    #[test]
    fn outbound_matches_srtp_context_across_rollover() {
        for profile in PROFILES {
            let mut out = outbound(profile, &[SSRC]);
            let mut reference = context(profile);
            for seq in wrap_sequence() {
                let (ours, n) =
                    send(&mut out, SSRC, seq).unwrap_or_else(|| panic!("protect {seq}"));
                let mut theirs = [0u8; 256];
                let len = rtp(&mut theirs, SSRC, seq);
                let m = reference.protect_rtp(&mut theirs, len).unwrap();
                assert_eq!(ours[..n], theirs[..m], "{profile:?} seq {seq}");
            }
        }
    }

    #[test]
    fn inbound_decrypts_outbound_and_webrtc_srtp_across_rollover() {
        use webrtc_srtp::context::Context;
        use webrtc_srtp::protection_profile::ProtectionProfile as WProfile;
        for profile in PROFILES {
            let (wprofile, key_len) = match profile {
                ProtectionProfile::AeadAes128Gcm => (WProfile::AeadAes128Gcm, 16),
                _ => (WProfile::Aes128CmHmacSha1_80, 16),
            };
            let m = master(profile);
            let mut webrtc_rx =
                Context::new(&m[..key_len], &m[key_len..], wprofile, None, None).unwrap();
            let mut webrtc_tx =
                Context::new(&m[..key_len], &m[key_len..], wprofile, None, None).unwrap();
            let mut out = outbound(profile, &[SSRC]);
            let mut inbound = SrtpInbound::new(&material(profile)).unwrap();
            let mut inbound_w = SrtpInbound::new(&material(profile)).unwrap();

            for seq in wrap_sequence() {
                let mut plain = [0u8; 256];
                let len = rtp(&mut plain, SSRC, seq);
                let (wire, n) = send(&mut out, SSRC, seq).unwrap();

                let decoded = webrtc_rx
                    .decrypt_rtp(&wire[..n])
                    .expect("webrtc-srtp decrypt");
                assert_eq!(&decoded[..], &plain[..len], "{profile:?} seq {seq}");

                let mut buf = wire;
                let back = inbound.unprotect_rtp(&mut buf, n, 0).expect("inbound");
                assert_eq!(buf[..back], plain[..len], "{profile:?} seq {seq}");

                // And the other way: webrtc-srtp as the sender.
                let theirs = webrtc_tx.encrypt_rtp(&plain[..len]).unwrap();
                let mut buf = [0u8; 256];
                buf[..theirs.len()].copy_from_slice(&theirs);
                let back = inbound_w.unprotect_rtp(&mut buf, theirs.len(), 0);
                assert_eq!(back.map(|b| buf[..b].to_vec()), Some(plain[..len].to_vec()));
            }
        }
    }

    #[test]
    fn outbound_never_sends_an_index_twice() {
        for profile in PROFILES {
            let mut out = outbound(profile, &[SSRC]);
            assert!(send(&mut out, SSRC, 10).is_some());
            assert!(send(&mut out, SSRC, 12).is_some());
            assert!(
                send(&mut out, SSRC, 11).is_some(),
                "reordered, not yet sent"
            );
            assert!(send(&mut out, SSRC, 12).is_none(), "already sent");
            assert!(send(&mut out, SSRC, 10).is_none(), "already sent");
            assert!(send(&mut out, SSRC, 100).is_some());
            assert!(send(&mut out, SSRC, 30).is_none(), "older than the window");
            assert!(
                send(&mut out, SSRC, 40).is_some(),
                "inside the window, unsent"
            );
        }
    }

    #[test]
    fn outbound_refuses_unregistered_ssrcs() {
        let mut out = outbound(PROFILES[1], &[SSRC]);
        assert!(send(&mut out, SSRC + 1, 1).is_none(), "RTP, unregistered");
        let mut buf = [0u8; 64];
        let len = rtcp_rr(&mut buf, SSRC + 1);
        assert!(
            out.protect_rtcp(&mut buf, len).is_none(),
            "RTCP, unregistered"
        );
        assert_eq!(out.ssrc_count(), 1);
    }

    #[test]
    fn outbound_register_is_monotonic_from_the_base() {
        let base = 0xFFFF_FFF0; // offsets wrap past u32::MAX
        let mut out = SrtpOutbound::new(&material(PROFILES[1]), base).unwrap();
        assert_eq!(out.register(base.wrapping_add(5)), Ok(()));
        assert_eq!(
            out.register(base.wrapping_add(5)),
            Err(SrtpError::InvalidSsrc)
        );
        assert_eq!(
            out.register(base.wrapping_add(3)),
            Err(SrtpError::InvalidSsrc)
        );
        assert_eq!(out.register(base.wrapping_add(20)), Ok(())); // SSRC 4
        assert_eq!(
            out.register(base.wrapping_sub(1)),
            Err(SrtpError::InvalidSsrc)
        ); // n ≥ 2^31
    }

    /// Review finding (2026-09-26): after `retire(X)`, protecting X again used
    /// to start a fresh slot at index 0, repeating nonces under the same key.
    #[test]
    fn outbound_retired_ssrc_never_sends_again() {
        for profile in PROFILES {
            let mut out = outbound(profile, &[SSRC]);
            assert!(send(&mut out, SSRC, 0).is_some());
            let mut buf = [0u8; 64];
            let len = rtcp_rr(&mut buf, SSRC);
            assert!(out.protect_rtcp(&mut buf, len).is_some());

            out.retire(SSRC);
            assert!(send(&mut out, SSRC, 0).is_none(), "RTP after retire");
            assert!(send(&mut out, SSRC, 1).is_none(), "RTP after retire");
            let mut buf = [0u8; 64];
            let len = rtcp_rr(&mut buf, SSRC);
            assert!(
                out.protect_rtcp(&mut buf, len).is_none(),
                "RTCP after retire"
            );
            assert_eq!(out.register(SSRC), Err(SrtpError::InvalidSsrc));
            assert_eq!(out.ssrc_count(), 0);
        }
    }

    #[test]
    fn outbound_retire_frees_the_slot() {
        let ssrcs: Vec<u32> = (0..OUTBOUND_SSRC_SLOTS as u32).map(|i| 1000 + i).collect();
        let mut out = outbound(PROFILES[1], &ssrcs);
        assert_eq!(out.ssrc_count(), OUTBOUND_SSRC_SLOTS);
        assert_eq!(out.register(5000), Err(SrtpError::SessionLimitReached));
        out.retire(1000);
        assert_eq!(out.ssrc_count(), OUTBOUND_SSRC_SLOTS - 1);
        assert_eq!(out.register(5000), Ok(()));
        assert!(send(&mut out, 5000, 1).is_some());
    }

    #[test]
    fn outbound_srtcp_index_increases_per_ssrc() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let mut out = outbound(profile, &[1, 2]);
        for (ssrc, expected) in [(1u32, 0u32), (1, 1), (2, 0), (1, 2)] {
            let mut buf = [0u8; 64];
            let len = rtcp_rr(&mut buf, ssrc);
            let n = out.protect_rtcp(&mut buf, len).unwrap();
            let e_index = be_u32(&buf, n - 4);
            assert_eq!(e_index, SRTCP_E_FLAG | expected);
        }
    }

    #[test]
    fn inbound_refuses_replay_and_unauthenticated() {
        for profile in PROFILES {
            let mut out = outbound(profile, &[SSRC]);
            let mut inbound = SrtpInbound::new(&material(profile)).unwrap();

            let (wire, n) = send(&mut out, SSRC, 7).unwrap();
            let mut forged = wire;
            forged[n - 1] ^= 1;
            assert!(inbound.unprotect_rtp(&mut forged, n, 0).is_none());
            assert_eq!(inbound.ssrc_count(), 0, "failed auth took a slot");

            let mut buf = wire;
            assert!(inbound.unprotect_rtp(&mut buf, n, 0).is_some());
            let mut buf = wire;
            assert!(inbound.unprotect_rtp(&mut buf, n, 1).is_none(), "replay");
            assert_eq!(inbound.ssrc_count(), 1);
        }
    }

    #[test]
    fn inbound_table_full_then_idle_eviction() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let mut ssrcs: Vec<u32> = (0..INBOUND_SSRC_SLOTS as u32).map(|i| 100 + i).collect();
        ssrcs.push(999);
        let mut out = outbound(profile, &ssrcs);
        let mut inbound = SrtpInbound::new(&material(profile)).unwrap();
        for i in 0..INBOUND_SSRC_SLOTS as u32 {
            let (mut wire, n) = send(&mut out, 100 + i, 1).unwrap();
            assert!(inbound.unprotect_rtp(&mut wire, n, 0).is_some());
        }
        // SSRC 100 stays active; the others go idle.
        let (mut wire, n) = send(&mut out, 100, 2).unwrap();
        assert!(inbound.unprotect_rtp(&mut wire, n, 25).is_some());

        let (wire17, n17) = send(&mut out, 999, 1).unwrap();
        let mut buf = wire17;
        assert!(
            inbound.unprotect_rtp(&mut buf, n17, 10).is_none(),
            "17th, all fresh"
        );
        let mut buf = wire17;
        assert!(
            inbound.unprotect_rtp(&mut buf, n17, 31).is_some(),
            "evicts one idle > 30 s"
        );
        assert_eq!(inbound.ssrc_count(), INBOUND_SSRC_SLOTS);

        // Sweep: at 50 s everything but 999 (seen at 31) and 100 (at 25) is idle > 30 s.
        assert_eq!(
            inbound.evict_idle(50, INBOUND_IDLE_EVICT_S),
            INBOUND_SSRC_SLOTS - 2
        );
        assert_eq!(inbound.ssrc_count(), 2);
    }

    #[test]
    fn inbound_srtcp_replay_and_e_flag() {
        for profile in PROFILES {
            let mut out = outbound(profile, &[SSRC]);
            let mut inbound = SrtpInbound::new(&material(profile)).unwrap();
            let mut wire = [0u8; 64];
            let len = rtcp_rr(&mut wire, SSRC);
            let n = out.protect_rtcp(&mut wire, len).unwrap();

            let at = srtcp_trailer_offset(&out.cipher, n).unwrap();
            let mut clear_e = wire;
            clear_e[at] &= 0x7F;
            assert!(
                inbound.unprotect_rtcp(&mut clear_e, n, 0).is_none(),
                "E = 0"
            );
            assert_eq!(inbound.ssrc_count(), 0);

            let mut buf = wire;
            assert_eq!(inbound.unprotect_rtcp(&mut buf, n, 0), Some(len));
            assert_eq!(buf[..len], wire[..len]);
            let mut buf = wire;
            assert!(inbound.unprotect_rtcp(&mut buf, n, 0).is_none(), "replay");
        }
    }

    /// Review finding (2026-09-26): an evicted media SSRC that returned after
    /// a sequence wrap restarted at ROC 0 and never authenticated again.
    /// Pinned (signaled) SSRCs are never evicted, so the stream survives.
    #[test]
    fn pinned_ssrc_survives_churn_and_a_wrap() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let unsignaled: Vec<u32> = (0..40u32).map(|i| 0x2000_0000 + i).collect();
        let mut out = outbound(profile, &[SSRC]);
        let mut inbound = SrtpInbound::new(&material(profile)).unwrap();
        inbound.pin(SSRC).unwrap();

        for seq in 65_000..=65_535u16 {
            let (mut wire, n) = send(&mut out, SSRC, seq).unwrap();
            assert!(inbound.unprotect_rtp(&mut wire, n, 0).is_some());
        }
        // 40 unsignaled SSRCs churn through the table over 400 s.
        for (k, &ssrc) in unsignaled.iter().enumerate() {
            let now = 100 + 10 * k as u32;
            inbound.evict_idle(now, INBOUND_IDLE_EVICT_S);
            out.register(ssrc).unwrap();
            let (mut wire, n) = send(&mut out, ssrc, 1).unwrap();
            out.retire(ssrc);
            assert!(
                inbound.unprotect_rtp(&mut wire, n, now).is_some(),
                "ssrc {ssrc:#x}"
            );
        }
        // The pinned stream returns after the wrap: ROC 1 is kept.
        for seq in 0..10u16 {
            let (mut wire, n) = send(&mut out, SSRC, seq).unwrap();
            assert!(
                inbound.unprotect_rtp(&mut wire, n, 1_000).is_some(),
                "seq {seq}"
            );
        }
        assert_eq!(inbound.pinned_count(), 1);
    }

    #[test]
    fn pinned_ssrcs_are_never_evicted() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let pinned: Vec<u32> = (0..INBOUND_PINNED_MAX as u32).map(|i| 10 + i).collect();
        let mut ssrcs = pinned.clone();
        ssrcs.extend([100, 101, 102, 103, 104]);
        let mut out = outbound(profile, &ssrcs);
        let mut inbound = SrtpInbound::new(&material(profile)).unwrap();
        for &ssrc in &pinned {
            inbound.pin(ssrc).unwrap();
        }
        assert_eq!(inbound.pin(99), Err(SrtpError::SessionLimitReached));
        assert_eq!(inbound.pin(10), Ok(()), "pinning again is a no-op");

        // The 4 unpinned slots fill; a 5th SSRC waits until one is idle.
        for (k, ssrc) in [100u32, 101, 102, 103].into_iter().enumerate() {
            let (mut wire, n) = send(&mut out, ssrc, 1).unwrap();
            assert!(inbound.unprotect_rtp(&mut wire, n, k as u32).is_some());
        }
        let (wire, n) = send(&mut out, 104, 1).unwrap();
        let mut buf = wire;
        assert!(
            inbound.unprotect_rtp(&mut buf, n, 20).is_none(),
            "no idle unpinned slot"
        );
        let mut buf = wire;
        assert!(
            inbound.unprotect_rtp(&mut buf, n, 1_000).is_some(),
            "evicts SSRC 100"
        );

        assert_eq!(inbound.evict_idle(10_000, INBOUND_IDLE_EVICT_S), 4);
        assert_eq!(inbound.ssrc_count(), INBOUND_PINNED_MAX);
        assert_eq!(inbound.pinned_count(), INBOUND_PINNED_MAX);

        // Unpinned (track removed): evictable, but keeps state until then.
        inbound.unpin(10);
        assert_eq!(inbound.evict_idle(10_000, INBOUND_IDLE_EVICT_S), 1);
        assert_eq!(inbound.pinned_count(), INBOUND_PINNED_MAX - 1);
    }

    #[test]
    fn contexts_fit_the_memory_budget() {
        // Design §3.11: 25 KB per participant in total; SRTP gets under a third.
        let size = std::mem::size_of::<SrtpInbound>() + std::mem::size_of::<SrtpOutbound>();
        eprintln!("SrtpInbound + SrtpOutbound = {size} bytes");
        assert!(size <= 8 * 1024, "{size} bytes");
    }
}
