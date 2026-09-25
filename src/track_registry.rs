//! Track registry: maps (TransportId, MID) → Track.
//!
//! Tracks are created by the orchestrator at SDP time, keyed by MID.
//! SSRCs are resolved at packet time by extracting the MID RTP header
//! extension from the first packet of each new SSRC.

use std::hash::{Hash, Hasher};

use dashmap::DashMap;
use nexus_webrtc::webrtc::TransportId;

use crate::types::TrackId;

/// Fixed-size MID key to avoid String allocation on the hot path.
/// WebRTC MIDs are typically 1-3 characters (e.g., "0", "1", "audio").
/// Max 16 bytes covers all practical MID values.
#[derive(Clone, Copy)]
struct MidKey {
    bytes: [u8; 16],
    len: u8,
}

impl MidKey {
    fn from_str(s: &str) -> Self {
        let len = s.len().min(16);
        let mut bytes = [0u8; 16];
        bytes[..len].copy_from_slice(&s.as_bytes()[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }
}

impl PartialEq for MidKey {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.bytes[..self.len as usize] == other.bytes[..other.len as usize]
    }
}

impl Eq for MidKey {}

impl Hash for MidKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes[..self.len as usize].hash(state);
    }
}

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
    /// (TransportId, MidKey) → RegisteredTrack. Zero-alloc on lookup.
    tracks: DashMap<(TransportId, MidKey), RegisteredTrack>,
    /// The negotiated RTP extension ID for `urn:ietf:params:rtp-hdrext:sdes:mid`.
    /// Keyed by TransportId since each session may negotiate different IDs.
    mid_ext_ids: DashMap<TransportId, u8>,
}

impl Default for SsrcResolver {
    fn default() -> Self {
        Self::new()
    }
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
        self.tracks
            .insert((transport_id, MidKey::from_str(mid)), track);
    }

    /// Packet loop resolves a MID to a track. Zero-allocation lookup.
    /// For simulcast, multiple SSRCs share the same MID — we clone instead of remove.
    pub fn resolve(&self, transport_id: TransportId, mid: &str) -> Option<RegisteredTrack> {
        self.tracks
            .get(&(transport_id, MidKey::from_str(mid)))
            .map(|v| *v)
    }

    /// Remove all tracks for a transport (on disconnect).
    pub fn remove(&self, transport_id: &TransportId) {
        self.tracks.retain(|k, _| &k.0 != transport_id);
        self.mid_ext_ids.remove(transport_id);
    }
}
