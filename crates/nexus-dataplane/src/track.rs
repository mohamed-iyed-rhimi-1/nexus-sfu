//! Published tracks and their fan-out lists (note §7.1).

use std::time::Instant;

use crate::command::TrackSpec;
use crate::ids::TrackId;
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
        }
    }
}
