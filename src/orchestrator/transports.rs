//! Participant transports on the control plane (design note §6.5): what the
//! orchestrator keeps per data-plane session. Replaces `Arc<WebRtcTransport>`.
//!
//! Each entry holds the session's shard, its ICE credentials, the DTLS handshake, the
//! outbound SSRC allocator (note §9.3) and the timestamps behind the timeouts of note
//! §6.4. The shard holds everything per packet.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nexus_dataplane::{IceParams, SessionId, ShardId};
use nexus_transport::dtls::DtlsCertificate;
use rand::Rng;

use super::dtls::DtlsHandshake;

/// No address selected this long after the session was created: ICE failed.
pub const ICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// DTLS not complete this long after the first selected address. Browsers finish in
/// well under a second; OpenSSL's retransmissions at 1, 2 and 4 s fit.
pub const DTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Most sessions the table holds (the shards' limit is lower).
pub const MAX_TRANSPORTS: usize = 1 << 20;
/// Most peer SSRCs an allocator avoids (a publisher's SDP lists ≤ 8 per m-line).
pub const MAX_PEER_SSRCS: usize = 64;
/// Largest out-SSRC offset from the base (the shard's and `SrtpOutbound`'s rule).
pub const MAX_OUT_SSRC_OFFSET: u32 = (1 << 31) - 1;
/// Tries per allocation before giving up (each skips 0 or a peer SSRC).
const ALLOCATE_TRIES: u32 = MAX_PEER_SSRCS as u32 + 2;

/// ICE characters (RFC 8445 §5.3: ALPHA / DIGIT / "+" / "/").
const ICE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Random local ICE credentials: a 16-character ufrag and a 32-character password.
pub fn random_ice_params() -> IceParams {
    let mut rng = rand::thread_rng();
    let mut params = IceParams {
        local_ufrag: [0; 16],
        local_pwd: [0; 32],
    };
    for b in params
        .local_ufrag
        .iter_mut()
        .chain(params.local_pwd.iter_mut())
    {
        *b = ICE_CHARS[rng.gen_range(0..ICE_CHARS.len())];
    }
    assert!(params.local_ufrag.iter().all(|b| ICE_CHARS.contains(b)));
    params
}

/// Outbound SSRCs of one session (note §9.3): `base + offset`, the offset strictly
/// increasing from 1 (offset 0 is the session's RTCP SSRC), skipping 0 and the peer's
/// own SSRCs. An SSRC is never handed out twice.
#[derive(Clone, Debug)]
pub struct SsrcAllocator {
    base: u32,
    next_offset: u32,
    peer_ssrcs: Vec<u32>,
}

impl SsrcAllocator {
    /// An allocator on `base` (the `out_ssrc_base` of `CreateSession`).
    /// `base` is the session's RTCP SSRC, so it is never 0.
    pub fn new(base: u32) -> Self {
        assert!(base != 0, "SSRC base 0 is the invalid SSRC");
        Self {
            base,
            next_offset: 1,
            peer_ssrcs: Vec::new(),
        }
    }

    /// An allocator on a random, non-zero base.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self::with_draw(|| rng.gen())
    }

    /// An allocator on the first non-zero value of `draw` (bounded; 16 zero draws in
    /// a row from a 32-bit random source do not happen, and fall back to base 1).
    fn with_draw(mut draw: impl FnMut() -> u32) -> Self {
        for _ in 0..16 {
            let base = draw();
            if base != 0 {
                return Self::new(base);
            }
        }
        Self::new(1)
    }

    /// The base, which is also the session's RTCP sender SSRC.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Avoid `ssrc` from now on (the peer announced it). Beyond `MAX_PEER_SSRCS` the
    /// SSRC is ignored: a collision is then left to chance (2^-32 per SSRC).
    pub fn note_peer_ssrc(&mut self, ssrc: u32) {
        if !self.peer_ssrcs.contains(&ssrc) && self.peer_ssrcs.len() < MAX_PEER_SSRCS {
            self.peer_ssrcs.push(ssrc);
        }
    }

    /// The next out SSRC; `None` when the offsets are used up.
    pub fn allocate(&mut self) -> Option<u32> {
        for _ in 0..ALLOCATE_TRIES {
            if self.next_offset > MAX_OUT_SSRC_OFFSET {
                return None;
            }
            let offset = self.next_offset;
            self.next_offset += 1;
            let ssrc = self.base.wrapping_add(offset);
            if ssrc != 0 && !self.peer_ssrcs.contains(&ssrc) {
                assert!(ssrc.wrapping_sub(self.base) == offset && offset >= 1);
                return Some(ssrc);
            }
        }
        // Only reachable if 0 and every noted peer SSRC sit in a row; try again later.
        None
    }
}

/// Which timeout expired (note §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expired {
    /// No address selected within `ICE_CONNECT_TIMEOUT`.
    IceConnect,
    /// DTLS incomplete `DTLS_HANDSHAKE_TIMEOUT` after the first address.
    DtlsHandshake,
}

/// One participant's transport.
#[derive(Debug)]
pub struct TransportEntry {
    /// Owning participant.
    pub participant: u64,
    /// The shard the session lives on.
    pub shard: ShardId,
    /// Local ICE credentials (sent in `CreateSession` and the offers).
    pub ice: IceParams,
    /// The DTLS handshake.
    pub dtls: DtlsHandshake,
    /// Outbound SSRCs.
    pub ssrcs: SsrcAllocator,
    /// When the session was created (the first offer).
    pub created_at: Instant,
    /// When the shard first reported a selected address.
    pub address_selected_at: Option<Instant>,
    /// `InstallSrtp` was pushed.
    pub srtp_installed: bool,
}

impl TransportEntry {
    /// A new entry with random ICE credentials and SSRC base.
    pub fn new(
        participant: u64,
        shard: ShardId,
        certificate: &DtlsCertificate,
        now: Instant,
    ) -> Self {
        Self {
            participant,
            shard,
            ice: random_ice_params(),
            dtls: DtlsHandshake::new(certificate),
            ssrcs: SsrcAllocator::random(),
            created_at: now,
            address_selected_at: None,
            srtp_installed: false,
        }
    }

    /// Records the first selected address; `true` if this was the first.
    pub fn mark_address_selected(&mut self, now: Instant) -> bool {
        let first = self.address_selected_at.is_none();
        if first {
            self.address_selected_at = Some(now);
        }
        assert!(self.address_selected_at.is_some());
        first
    }

    /// Which timeout, if any, has expired at `now`.
    pub fn expired(&self, now: Instant) -> Option<Expired> {
        match self.address_selected_at {
            None if now.saturating_duration_since(self.created_at) >= ICE_CONNECT_TIMEOUT => {
                Some(Expired::IceConnect)
            }
            Some(at)
                if !self.dtls.is_complete()
                    && now.saturating_duration_since(at) >= DTLS_HANDSHAKE_TIMEOUT =>
            {
                Some(Expired::DtlsHandshake)
            }
            _ => None,
        }
    }
}

/// All transports, by session and by participant.
#[derive(Debug, Default)]
pub struct Transports {
    entries: HashMap<SessionId, TransportEntry>,
    by_participant: HashMap<u64, SessionId>,
}

impl Transports {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a session. `false` (nothing changed) if the session or its participant
    /// already has one, or the table is full.
    pub fn insert(&mut self, id: SessionId, entry: TransportEntry) -> bool {
        if self.entries.contains_key(&id)
            || self.by_participant.contains_key(&entry.participant)
            || self.entries.len() >= MAX_TRANSPORTS
        {
            return false;
        }
        self.by_participant.insert(entry.participant, id);
        self.entries.insert(id, entry);
        assert_eq!(self.entries.len(), self.by_participant.len());
        true
    }

    /// Removes a session.
    pub fn remove(&mut self, id: SessionId) -> Option<TransportEntry> {
        let entry = self.entries.remove(&id)?;
        self.by_participant.remove(&entry.participant);
        assert_eq!(self.entries.len(), self.by_participant.len());
        Some(entry)
    }

    /// A session's entry.
    pub fn get(&self, id: SessionId) -> Option<&TransportEntry> {
        self.entries.get(&id)
    }

    /// A session's entry, for update.
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut TransportEntry> {
        self.entries.get_mut(&id)
    }

    /// The session of a participant.
    pub fn session_of(&self, participant: u64) -> Option<SessionId> {
        self.by_participant.get(&participant).copied()
    }

    /// The participant of a session.
    pub fn participant_of(&self, id: SessionId) -> Option<u64> {
        self.entries.get(&id).map(|entry| entry.participant)
    }

    /// Sessions whose ICE-connect or DTLS timeout expired at `now`, in id order.
    pub fn sweep(&self, now: Instant) -> Vec<(SessionId, Expired)> {
        let mut expired: Vec<(SessionId, Expired)> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| entry.expired(now).map(|why| (*id, why)))
            .collect();
        expired.sort_unstable_by_key(|(id, _)| *id);
        expired
    }

    /// Number of sessions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_offsets_increase_and_skip_zero_and_peer_ssrcs() {
        let mut ssrcs = SsrcAllocator::random();
        let base = ssrcs.base();
        let peer: Vec<u32> = (0..8).map(|i| base.wrapping_add(10 + 3 * i)).collect();
        for &p in &peer {
            ssrcs.note_peer_ssrc(p);
        }
        let mut last_offset = 0u32;
        for _ in 0..10_000 {
            let ssrc = ssrcs.allocate().unwrap();
            let offset = ssrc.wrapping_sub(base);
            assert!(offset > last_offset, "strictly increasing, never offset 0");
            assert!(ssrc != 0 && !peer.contains(&ssrc));
            last_offset = offset;
        }
    }

    #[test]
    fn zero_base_is_redrawn() {
        let mut draws = [0u32, 0, 77].into_iter();
        assert_eq!(
            SsrcAllocator::with_draw(|| draws.next().unwrap()).base(),
            77
        );
        assert_eq!(SsrcAllocator::with_draw(|| 0).base(), 1);
        assert!(std::panic::catch_unwind(|| SsrcAllocator::new(0)).is_err());
    }

    #[test]
    fn allocator_skips_zero_when_base_wraps() {
        // base + 1 == 0: the first offset is skipped.
        let mut ssrcs = SsrcAllocator::new(u32::MAX);
        assert_eq!(ssrcs.allocate(), Some(1));
        assert_eq!(ssrcs.base(), u32::MAX);
    }

    #[test]
    fn allocator_is_exhausted_at_the_offset_limit() {
        let mut ssrcs = SsrcAllocator::new(5);
        ssrcs.next_offset = MAX_OUT_SSRC_OFFSET;
        assert_eq!(ssrcs.allocate(), Some(5 + MAX_OUT_SSRC_OFFSET));
        assert_eq!(ssrcs.allocate(), None);
        assert_eq!(ssrcs.allocate(), None);
    }

    #[test]
    fn ice_params_use_ice_chars() {
        let a = random_ice_params();
        let b = random_ice_params();
        assert_ne!(a.local_ufrag, b.local_ufrag);
        for b in a.local_ufrag.iter().chain(a.local_pwd.iter()) {
            assert!(ICE_CHARS.contains(b));
        }
    }

    #[test]
    fn table_and_timeouts() {
        let cert = DtlsCertificate::generate().unwrap();
        let t0 = Instant::now();
        let mut table = Transports::new();
        let (s1, s2) = (SessionId::new(1), SessionId::new(2));
        assert!(table.insert(s1, TransportEntry::new(10, ShardId::new(0), &cert, t0)));
        assert!(!table.insert(s2, TransportEntry::new(10, ShardId::new(0), &cert, t0)));
        assert!(table.insert(s2, TransportEntry::new(11, ShardId::new(0), &cert, t0)));
        assert_eq!(table.session_of(11), Some(s2));
        assert_eq!(table.participant_of(s1), Some(10));

        // s1 selects an address at 5 s; s2 never does.
        assert!(table
            .get_mut(s1)
            .unwrap()
            .mark_address_selected(t0 + Duration::from_secs(5)));
        assert!(!table
            .get_mut(s1)
            .unwrap()
            .mark_address_selected(t0 + Duration::from_secs(6)));
        assert!(table.sweep(t0 + Duration::from_secs(14)).is_empty());
        assert_eq!(
            table.sweep(t0 + Duration::from_secs(15)),
            vec![(s1, Expired::DtlsHandshake)]
        );
        assert_eq!(
            table.sweep(t0 + ICE_CONNECT_TIMEOUT),
            vec![(s1, Expired::DtlsHandshake), (s2, Expired::IceConnect)]
        );
        assert!(table.remove(s1).is_some());
        assert_eq!(table.session_of(10), None);
        assert_eq!(table.len(), 1);
    }
}
