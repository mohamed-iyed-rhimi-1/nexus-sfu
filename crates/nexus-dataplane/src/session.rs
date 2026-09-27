//! Per-session state on a shard (note §7.1).

use std::net::SocketAddr;
use std::time::Instant;

use nexus_transport::srtp::{SrtpInbound, SrtpOutbound};

use crate::command::{IceParams, SelectReason};
use crate::ids::SessionId;
use crate::slab::Key;

/// Most tracks one session publishes (bound + unbound).
pub const MAX_TRACKS_PER_SESSION: usize = 10;

/// Most subscriptions of one session: the outbound SRTP table has 32 slots,
/// one of them the session's RTCP SSRC.
pub const MAX_SUBS_PER_SESSION: usize = 31;

/// Largest offset of an out SSRC from the session's base (note §9.3).
pub const MAX_OUT_SSRC_OFFSET: u32 = (1 << 31) - 1;

/// DTLS datagrams a session may pass to the control plane per housekeeping
/// sweep (1 s) before `PeerSrtpVerified`. A handshake needs a few flights and
/// their retransmissions; a flood from one peer must not fill the event
/// channel all sessions share.
pub const DTLS_BUDGET_PER_SWEEP: u16 = 32;

/// Binding-request transaction ids remembered per session, to refuse an
/// address change on a replayed request.
pub const RECENT_TRANSACTIONS: usize = 16;

/// Slab key of a session.
pub type SessionIdx = Key;
/// Slab key of a published track.
pub type TrackIdx = Key;
/// Slab key of a subscription.
pub type SubIdx = Key;

/// A fixed-capacity list; never allocates.
#[derive(Clone, Copy, Debug)]
pub struct FixedVec<T: Copy + Default, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> FixedVec<T, N> {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            items: [T::default(); N],
            len: 0,
        }
    }

    /// Items in the list.
    pub fn as_slice(&self) -> &[T] {
        &self.items[..self.len]
    }

    /// Items in the list, writable.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items[..self.len]
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Appends; `false` when full.
    pub fn push(&mut self, item: T) -> bool {
        if self.len == N {
            return false;
        }
        self.items[self.len] = item;
        self.len += 1;
        true
    }

    /// Removes the first item matching `pred` (order not kept).
    pub fn swap_remove_where(&mut self, pred: impl Fn(&T) -> bool) -> Option<T> {
        let pos = self.as_slice().iter().position(pred)?;
        let item = self.items[pos];
        self.len -= 1;
        self.items[pos] = self.items[self.len];
        Some(item)
    }
}

/// One participant transport.
pub struct Session {
    /// Control-plane id.
    pub id: SessionId,
    /// Selected address; `None` until nominated.
    pub addr: Option<SocketAddr>,
    /// The address selected before the current one, still in the address map
    /// so in-flight packets authenticate; removed by housekeeping (1.2b).
    pub prev_addr: Option<SocketAddr>,
    /// Last authenticated packet from the selected address (liveness and the
    /// rebind silence rule). Authenticated STUN from other addresses does not
    /// count, or a candidate pair being checked would block rebinding.
    pub last_rx_selected: Instant,
    /// Local ICE credentials.
    pub ice: IceParams,
    /// Unprotects what the peer sends.
    pub srtp_in: Option<Box<SrtpInbound>>,
    /// Protects what the shard sends to the peer.
    pub srtp_out: Option<Box<SrtpOutbound>>,
    /// `PeerSrtpVerified` was sent; DTLS is dropped from now on.
    pub srtp_verified: bool,
    /// `ConsentLost` was delivered (once per session).
    pub consent_lost: bool,
    /// DTLS datagrams left until the next sweep.
    pub dtls_budget: u16,
    /// When the selected address last changed.
    pub last_switch: Option<Instant>,
    /// A nomination refused by the switch interval, applied once it passed.
    pub pending_nomination: Option<SocketAddr>,
    /// An `AddressSelected` the event sink refused; retried by the sweep.
    pub unreported_switch: Option<SelectReason>,
    /// Transaction ids of recent authenticated binding requests (ring).
    recent_transactions: [[u8; 12]; RECENT_TRANSACTIONS],
    recent_len: usize,
    next_transaction: usize,
    /// Base of the session's out SSRCs; also its RTCP sender SSRC.
    pub out_ssrc_base: u32,
    /// Offset of the last accepted out SSRC (0: the RTCP SSRC).
    pub last_out_ssrc_offset: u32,
    /// Bound tracks: SSRC → track, linear scan.
    pub published: FixedVec<(u32, TrackIdx), MAX_TRACKS_PER_SESSION>,
    /// Tracks whose SSRC is not known yet (note §7.2).
    pub unbound: FixedVec<TrackIdx, MAX_TRACKS_PER_SESSION>,
    /// This session's subscriptions, in out-SSRC offset order.
    pub subs: Vec<SubIdx>,
}

impl Session {
    /// A new session; `now` starts its liveness clock.
    pub fn new(id: SessionId, ice: IceParams, out_ssrc_base: u32, now: Instant) -> Self {
        Self {
            id,
            addr: None,
            prev_addr: None,
            last_rx_selected: now,
            ice,
            srtp_in: None,
            srtp_out: None,
            srtp_verified: false,
            consent_lost: false,
            dtls_budget: DTLS_BUDGET_PER_SWEEP,
            last_switch: None,
            pending_nomination: None,
            unreported_switch: None,
            recent_transactions: [[0; 12]; RECENT_TRANSACTIONS],
            recent_len: 0,
            next_transaction: 0,
            out_ssrc_base,
            last_out_ssrc_offset: 0,
            published: FixedVec::new(),
            unbound: FixedVec::new(),
            subs: Vec::new(),
        }
    }

    /// The session's RTCP sender SSRC (offset 0 from the base).
    pub fn rtcp_ssrc(&self) -> u32 {
        self.out_ssrc_base
    }

    /// Tracks the session publishes, bound or not.
    pub fn track_count(&self) -> usize {
        self.published.len() + self.unbound.len()
    }

    /// The bound track with this SSRC.
    pub fn track_of_ssrc(&self, ssrc: u32) -> Option<TrackIdx> {
        self.published
            .as_slice()
            .iter()
            .find(|(s, _)| *s == ssrc)
            .map(|(_, t)| *t)
    }

    /// Records a binding request's transaction id; `true` if it was seen
    /// recently (a retransmission or a replay).
    pub fn note_transaction(&mut self, id: [u8; 12]) -> bool {
        if self.recent_transactions[..self.recent_len].contains(&id) {
            return true;
        }
        self.recent_transactions[self.next_transaction] = id;
        self.next_transaction = (self.next_transaction + 1) % RECENT_TRANSACTIONS;
        self.recent_len = (self.recent_len + 1).min(RECENT_TRANSACTIONS);
        false
    }

    /// Offset of an out SSRC from the session's base.
    pub fn out_ssrc_offset(&self, ssrc: u32) -> u32 {
        ssrc.wrapping_sub(self.out_ssrc_base)
    }
}
