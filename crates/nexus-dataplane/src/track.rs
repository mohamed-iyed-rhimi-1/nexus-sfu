//! Published tracks and their fan-out lists (note §7.1).

use std::time::Instant;

use crate::command::{SubSpec, TrackSpec};
use crate::ids::{CnameValue, ShardId, TrackId};
use crate::rtcp::SrInfo;
use crate::session::{SessionIdx, SubIdx};

/// Simulcast layers per track; 1 in v1 (note §11.5).
pub const MAX_LAYERS: usize = 1;

/// One source layer of a track.
#[derive(Clone, Copy, Debug, Default)]
pub struct Layer {
    /// The layer's SSRC, once known.
    pub ssrc: Option<u32>,
    /// The publisher's last SR on this layer (note §12.2).
    pub last_sr: Option<SrInfo>,
}

/// A publish m-line of a session.
pub struct PublishedTrack {
    /// Control-plane id.
    pub id: TrackId,
    /// Publisher session.
    pub session: SessionIdx,
    /// What the publisher's answer said.
    pub spec: TrackSpec,
    /// Source layers.
    pub layers: [Layer; MAX_LAYERS],
    /// Local subscriptions (grows on command).
    pub subscribers: Vec<SubIdx>,
    /// Last keyframe request sent to the publisher (note §12.3).
    pub last_pli: Option<Instant>,
    /// A request arrived inside the throttle window: one PLI is sent when
    /// the window ends, so a subscriber whose request was throttled (e.g. a
    /// new shard's, right after `AddRemoteShard`'s) still gets a keyframe.
    pub keyframe_pending: bool,
    /// Shards with subscriptions to the track (bit i: shard i), each handed
    /// every packet once (note §7.1, plan 2.2). Never this shard's bit.
    pub remote_shards: u64,
}

impl PublishedTrack {
    /// A track of `session`; its layer SSRC is the spec's, if any.
    pub fn new(id: TrackId, session: SessionIdx, spec: TrackSpec) -> Self {
        Self {
            id,
            session,
            spec,
            layers: [Layer {
                ssrc: spec.ssrc,
                last_sr: None,
            }],
            subscribers: Vec::new(),
            last_pli: None,
            keyframe_pending: false,
            remote_shards: 0,
        }
    }
}

/// A track published on another shard, with subscriptions on this one
/// (plan 2.2). Created by the first such `Subscribe`, freed with its last
/// subscription or by `RemoveTrack`. What it needs of the track comes in
/// the `SubSpec`, so it has no command of its own.
pub struct MirrorTrack {
    /// The track's id.
    pub id: TrackId,
    /// The publisher's shard.
    pub source: ShardId,
    /// Local subscriptions (grows on command).
    pub subscribers: Vec<SubIdx>,
    /// The track's RTP clock rate.
    pub clock_rate: u32,
    /// The publisher's `mid` extension id.
    pub pub_mid: u8,
    /// The track's CNAME, for translated SRs.
    pub cname: CnameValue,
}

impl MirrorTrack {
    /// A mirror of `spec.source` without subscriptions.
    pub fn new(spec: &SubSpec) -> Self {
        Self {
            id: spec.source.track,
            source: spec.source.shard,
            subscribers: Vec::new(),
            clock_rate: spec.clock_rate,
            pub_mid: spec.pub_mid,
            cname: spec.cname,
        }
    }

    /// `spec` describes the track the same way.
    pub fn matches(&self, spec: &SubSpec) -> bool {
        self.clock_rate == spec.clock_rate
            && self.pub_mid == spec.pub_mid
            && self.cname == spec.cname
    }
}
