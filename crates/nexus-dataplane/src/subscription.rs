//! Subscriptions and their rewrite state (note §7.1, §11.1).

use std::time::Instant;

use crate::command::{ExtMap, PtMap};
use crate::ids::{MidValue, SubscriptionId};
use crate::session::{MirrorIdx, SessionIdx, TrackIdx};

/// Per-subscription rewrite state (note §11.1).
#[derive(Clone, Copy, Debug)]
pub struct RewriteState {
    /// Announced in the subscriber's SDP; never changes (note §9.3).
    pub out_ssrc: u32,
    /// `sub_seq = pub_seq + seq_offset` (wrapping).
    pub seq_offset: u16,
    /// `sub_ts = pub_ts + ts_offset` (wrapping).
    pub ts_offset: u32,
    /// Offsets were set by the first forwarded packet.
    pub started: bool,
    /// Highest forwarded seq (for rebasing when layers switch).
    pub last_out_seq: u16,
    /// Timestamp of that packet.
    pub last_out_ts: u32,
    /// When it was forwarded.
    pub last_out_at: Option<Instant>,
    /// Input seq of the packet `last_out_seq` came from (gap detection).
    pub last_in_seq: u16,
    /// Current source layer; always 0 in v1.
    pub layer: u8,
}

impl RewriteState {
    /// State before the first packet.
    pub fn new(out_ssrc: u32) -> Self {
        Self {
            out_ssrc,
            seq_offset: 0,
            ts_offset: 0,
            started: false,
            last_out_seq: 0,
            last_out_ts: 0,
            last_out_at: None,
            last_in_seq: 0,
            layer: 0,
        }
    }
}

/// The track a subscription follows: published on this shard, or mirrored
/// from another (plan 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubTrack {
    /// A track published on this shard.
    Local(TrackIdx),
    /// A track published on another shard.
    Mirror(MirrorIdx),
}

/// One subscriber's use of one track.
pub struct Subscription {
    /// Control-plane id.
    pub id: SubscriptionId,
    /// Subscriber session.
    pub session: SessionIdx,
    /// The track.
    pub track: SubTrack,
    /// Rewrite state.
    pub rewrite: RewriteState,
    /// Header extension mapping.
    pub ext_map: ExtMap,
    /// The publisher's `mid` extension id (its element is always dropped).
    pub pub_mid: u8,
    /// The track's RTP clock rate (timestamp rebasing).
    pub clock_rate: u32,
    /// Payload type mapping.
    pub pt_map: PtMap,
    /// The subscriber m-line's mid.
    pub mid: MidValue,
    /// RTP packets sent (for translated SRs).
    pub sent_packets: u32,
    /// RTP payload octets sent (for translated SRs).
    pub sent_octets: u32,
}
