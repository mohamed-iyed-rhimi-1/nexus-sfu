//! Track registry: maps (TransportId, MID) → Track.
//!
//! Tracks are created by the orchestrator at SDP time, keyed by MID.
//! SSRCs are resolved at packet time by extracting the MID RTP header
//! extension from the first packet of each new SSRC.

use dashmap::DashMap;
use nexus_webrtc::webrtc::TransportId;

use crate::types::TrackId;

/// A track created from an SDP m-line, awaiting SSRC resolution.
#[derive(Debug, Clone, Copy)]
pub struct RegisteredTrack {
    pub track_id: TrackId,
    pub worker_id: u32,
    pub kind: u8, // 0=audio, 1=video
}

/// Maps (TransportId, MID) → RegisteredTrack.
///
/// The orchestrator registers tracks at SDP time.
/// The packet loop resolves SSRCs by extracting MID from RTP extensions.
pub struct SsrcResolver {
    /// (TransportId, MID string) → RegisteredTrack.
    tracks: DashMap<(TransportId, String), RegisteredTrack>,
    /// The negotiated RTP extension ID for `urn:ietf:params:rtp-hdrext:sdes:mid`.
    /// Keyed by TransportId since each session may negotiate different IDs.
    mid_ext_ids: DashMap<TransportId, u8>,
}

impl SsrcResolver {
    pub fn new() -> Self {
        Self {
            tracks: DashMap::new(),
            mid_ext_ids: DashMap::new(),
        }
    }

    /// Register the MID extension ID for a transport (from SDP extmap negotiation).
    pub fn set_mid_ext_id(&self, transport_id: TransportId, ext_id: u8) {
        self.mid_ext_ids.insert(transport_id, ext_id);
    }

    /// Get the MID extension ID for a transport.
    pub fn mid_ext_id(&self, transport_id: TransportId) -> Option<u8> {
        self.mid_ext_ids.get(&transport_id).map(|v| *v)
    }

    /// Orchestrator registers a track from an SDP m-line.
    pub fn register(&self, transport_id: TransportId, mid: &str, track: RegisteredTrack) {
        self.tracks.insert((transport_id, mid.to_string()), track);
    }

    /// Packet loop resolves a MID to a track. Returns and removes the entry.
    /// For simulcast, multiple SSRCs share the same MID — we clone instead of remove.
    pub fn resolve(&self, transport_id: TransportId, mid: &str) -> Option<RegisteredTrack> {
        self.tracks.get(&(transport_id, mid.to_string())).map(|v| *v)
    }

    /// Remove all tracks for a transport (on disconnect).
    pub fn remove(&self, transport_id: &TransportId) {
        self.tracks.retain(|k, _| &k.0 != transport_id);
        self.mid_ext_ids.remove(transport_id);
    }
}
