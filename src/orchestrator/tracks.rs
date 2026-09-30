//! Published tracks as the control plane knows them (design note §6.5).
//!
//! The shard holds the forwarding state; this registry holds what the orchestrator
//! needs to build offers and `SubSpec`s for subscribers: who publishes the track, on
//! which shard, and what the publisher's answer said about it.

use std::collections::HashMap;

use nexus_core::MediaKind;
use nexus_dataplane::{
    CnameValue, ExtIds, MidValue, SessionId, ShardId, TrackId, TrackSpec, MAX_SHARDS_SUPPORTED,
};

/// Most tracks the registry holds (every participant of every room). Bounds the map;
/// `insert` refuses beyond it.
pub const MAX_TRACKS: usize = 1 << 20;
/// Shards a track can have subscribers on (the per-shard counts are fixed arrays).
pub const TRACK_SHARDS: usize = MAX_SHARDS_SUPPORTED as usize;
const _: () = assert!(TRACK_SHARDS <= 32, "announced is a u32 mask");

/// One published track.
#[derive(Clone, Debug)]
pub struct TrackInfo {
    /// Publishing participant.
    pub publisher: u64,
    /// Publisher's session.
    pub session: SessionId,
    /// Publisher's shard.
    pub shard: ShardId,
    /// The room the track was published in: only participants of this room may
    /// subscribe to it.
    pub room: u32,
    /// What the publisher's answer said (kind, mid, SSRC, codec, extension ids), plus the
    /// SFU-assigned cname `nexus-{publisher}`.
    pub spec: TrackSpec,
    /// Content type from `SetContent` (no data-plane effect in v1).
    pub content_type: u8,
    /// On-shard subscriptions to the track, by the subscriber's shard (plan 2.4):
    /// +1 when a subscribe m-line goes onto its shard, −1 when it leaves that state.
    pub subscribers: [u32; TRACK_SHARDS],
    /// Shards other than `shard` the track's shard was told about: bit `i` is set
    /// while an `AddRemoteShard` for shard `i` was accepted and no
    /// `RemoveRemoteShard` for it has been sent or queued since.
    pub announced: u32,
}

impl TrackInfo {
    /// A track with no subscribers.
    pub fn new(
        publisher: u64,
        session: SessionId,
        shard: ShardId,
        room: u32,
        spec: TrackSpec,
        content_type: u8,
    ) -> Self {
        Self {
            publisher,
            session,
            shard,
            room,
            spec,
            content_type,
            subscribers: [0; TRACK_SHARDS],
            announced: 0,
        }
    }

    /// On-shard subscriptions on `shard`.
    pub fn subscribers_on(&self, shard: ShardId) -> u32 {
        self.subscribers[usize::from(shard.index())]
    }

    /// Shards other than the track's with subscriptions, in index order.
    pub fn remote_shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        (0..TRACK_SHARDS)
            .filter(|&i| self.subscribers[i] > 0)
            .map(|i| ShardId::new(i as u8))
            .filter(|&s| s != self.shard)
    }

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

    /// One more on-shard subscription on `shard`: whether it is the first there.
    /// `None` for an unknown track.
    pub fn add_subscriber(&mut self, id: TrackId, shard: ShardId) -> Option<bool> {
        let info = self.tracks.get_mut(&id)?;
        let count = &mut info.subscribers[usize::from(shard.index())];
        *count += 1;
        Some(*count == 1)
    }

    /// One on-shard subscription on `shard` fewer: whether it was the last there.
    /// `None` for an unknown (removed) track: its counts went with it.
    pub fn remove_subscriber(&mut self, id: TrackId, shard: ShardId) -> Option<bool> {
        let info = self.tracks.get_mut(&id)?;
        let count = &mut info.subscribers[usize::from(shard.index())];
        assert!(*count > 0, "subscription counted off a shard with none");
        *count -= 1;
        Some(*count == 0)
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

    /// Every track, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (TrackId, &TrackInfo)> {
        self.tracks.iter().map(|(id, info)| (*id, info))
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
        TrackInfo::new(
            publisher,
            SessionId::new(publisher),
            ShardId::new(0),
            1,
            TrackSpec {
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
            0,
        )
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
        for id in registry.by_publisher(7) {
            assert!(registry.remove(id).is_some());
        }
        assert!(registry.by_publisher(7).is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.remove(TrackId::new(5)).is_some());
        assert!(registry.is_empty());
    }

    #[test]
    fn subscribers_are_counted_per_shard() {
        let mut registry = TrackRegistry::new();
        let (track, a, b) = (TrackId::new(3), ShardId::new(0), ShardId::new(2));
        assert!(registry.insert(track, info(7, MediaKind::Video)));
        assert_eq!(registry.add_subscriber(track, b), Some(true));
        assert_eq!(registry.add_subscriber(track, b), Some(false));
        assert_eq!(registry.add_subscriber(track, a), Some(true));
        let remote: Vec<ShardId> = registry.get(track).unwrap().remote_shards().collect();
        assert_eq!(remote, [b], "the track's own shard is not remote");
        assert_eq!(registry.remove_subscriber(track, b), Some(false));
        assert_eq!(registry.remove_subscriber(track, b), Some(true));
        assert_eq!(registry.get(track).unwrap().subscribers_on(b), 0);
        registry.remove(track);
        assert_eq!(
            registry.add_subscriber(track, b),
            None,
            "gone with the track"
        );
        assert_eq!(registry.remove_subscriber(track, b), None);
    }
}
