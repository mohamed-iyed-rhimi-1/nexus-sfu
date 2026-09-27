//! Published tracks as the control plane knows them (design note §6.5).
//!
//! The shard holds the forwarding state; this registry holds what the orchestrator
//! needs to build offers and `SubSpec`s for subscribers: who publishes the track, on
//! which shard, and what the publisher's answer said about it.

use std::collections::HashMap;

use nexus_core::MediaKind;
use nexus_dataplane::{CnameValue, ExtIds, MidValue, SessionId, ShardId, TrackId, TrackSpec};

/// Most tracks the registry holds (every participant of every room). Bounds the map;
/// `insert` refuses beyond it.
pub const MAX_TRACKS: usize = 1 << 20;

/// One published track.
#[derive(Clone, Debug)]
pub struct TrackInfo {
    /// Publishing participant.
    pub publisher: u64,
    /// Publisher's session.
    pub session: SessionId,
    /// Publisher's shard.
    pub shard: ShardId,
    /// What the publisher's answer said (kind, mid, SSRC, codec, extension ids), plus the
    /// SFU-assigned cname `nexus-{publisher}`.
    pub spec: TrackSpec,
    /// Content type from `SetContent` (no data-plane effect in v1).
    pub content_type: u8,
}

impl TrackInfo {
    /// Audio or video.
    pub fn kind(&self) -> MediaKind {
        self.spec.kind
    }

    /// The publisher's m-line mid.
    pub fn mid(&self) -> &MidValue {
        &self.spec.mid
    }

    /// The publisher's extension ids.
    pub fn ext(&self) -> &ExtIds {
        &self.spec.ext
    }

    /// The CNAME subscribers see for this track (`nexus-{publisher}`).
    pub fn cname(&self) -> &CnameValue {
        &self.spec.cname
    }
}

/// `TrackId` → `TrackInfo`.
#[derive(Debug, Default)]
pub struct TrackRegistry {
    tracks: HashMap<TrackId, TrackInfo>,
}

impl TrackRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a track. `false` (nothing changed) if the id exists or the registry is full.
    pub fn insert(&mut self, id: TrackId, info: TrackInfo) -> bool {
        if self.tracks.contains_key(&id) || self.tracks.len() >= MAX_TRACKS {
            return false;
        }
        self.tracks.insert(id, info);
        assert!(self.tracks.contains_key(&id));
        true
    }

    /// Removes a track.
    pub fn remove(&mut self, id: TrackId) -> Option<TrackInfo> {
        let removed = self.tracks.remove(&id);
        debug_assert!(!self.tracks.contains_key(&id));
        removed
    }

    /// Looks a track up.
    pub fn get(&self, id: TrackId) -> Option<&TrackInfo> {
        self.tracks.get(&id)
    }

    /// Looks a track up for update (content type).
    pub fn get_mut(&mut self, id: TrackId) -> Option<&mut TrackInfo> {
        self.tracks.get_mut(&id)
    }

    /// The tracks a participant publishes, in id order.
    pub fn by_publisher(&self, publisher: u64) -> Vec<TrackId> {
        let mut ids: Vec<TrackId> = self
            .tracks
            .iter()
            .filter(|(_, info)| info.publisher == publisher)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Removes every track of a participant and returns their ids, in id order.
    pub fn remove_publisher(&mut self, publisher: u64) -> Vec<TrackId> {
        let ids = self.by_publisher(publisher);
        for id in &ids {
            self.tracks.remove(id);
        }
        debug_assert!(self.by_publisher(publisher).is_empty());
        ids
    }

    /// Number of tracks.
    pub fn len(&self) -> usize {
        self.tracks.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.tracks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_dataplane::CodecParams;

    fn info(publisher: u64, kind: MediaKind) -> TrackInfo {
        TrackInfo {
            publisher,
            session: SessionId::new(publisher),
            shard: ShardId::new(0),
            spec: TrackSpec {
                kind,
                mid: MidValue::new(b"0").unwrap(),
                ssrc: Some(1234),
                codec: CodecParams {
                    pt: 111,
                    clock_rate: 48_000,
                },
                ext: ExtIds::default(),
                cname: CnameValue::new(b"c").unwrap(),
            },
            content_type: 0,
        }
    }

    #[test]
    fn insert_get_remove_by_publisher() {
        let mut registry = TrackRegistry::new();
        assert!(registry.insert(TrackId::new(3), info(7, MediaKind::Video)));
        assert!(registry.insert(TrackId::new(2), info(7, MediaKind::Audio)));
        assert!(registry.insert(TrackId::new(5), info(8, MediaKind::Audio)));
        assert!(!registry.insert(TrackId::new(5), info(9, MediaKind::Audio)));
        assert_eq!(registry.get(TrackId::new(5)).unwrap().publisher, 8);
        assert_eq!(
            registry.by_publisher(7),
            vec![TrackId::new(2), TrackId::new(3)]
        );
        assert_eq!(registry.remove_publisher(7).len(), 2);
        assert_eq!(registry.len(), 1);
        assert!(registry.remove(TrackId::new(5)).is_some());
        assert!(registry.is_empty());
    }
}
