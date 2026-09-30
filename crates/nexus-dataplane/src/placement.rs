//! Which shard a new session goes to (note §13.2). `RoomAffine` keeps a room's
//! participants on one shard until the room or the shard fills; `SingleShard`
//! (tests) puts everything on shard 0. A session stays on its shard for life.

use std::collections::HashMap;

use nexus_core::RoomId;

use crate::config::MAX_SHARDS_SUPPORTED;
use crate::ids::ShardId;
use crate::shard::stats::ShardStatsSnapshot;

/// A shard's load, from its published stats (up to a second old).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardLoad {
    /// Sessions on the shard. Informational: `RoomAffine` counts its own placements
    /// instead, since the stats lag a burst of joins.
    pub sessions: u32,
    /// Datagrams received per second.
    pub rx_pps: u32,
}

impl From<&ShardStatsSnapshot> for ShardLoad {
    fn from(stats: &ShardStatsSnapshot) -> Self {
        Self {
            sessions: u32::try_from(stats.gauges.sessions).unwrap_or(u32::MAX),
            rx_pps: u32::try_from(stats.gauges.rx_pps).unwrap_or(u32::MAX),
        }
    }
}

/// Chooses a shard for each new session.
pub trait Placement: Send {
    /// Shard for a new session; `room` is `None` outside a room. `loads`
    /// has one entry per shard.
    fn place(&mut self, room: Option<RoomId>, loads: &[ShardLoad]) -> ShardId;

    /// A session placed by `place` closed.
    fn session_closed(&mut self, room: Option<RoomId>, shard: ShardId);
}

/// Phase 1: every session on shard 0.
#[derive(Clone, Copy, Debug, Default)]
pub struct SingleShard;

impl Placement for SingleShard {
    fn place(&mut self, _room: Option<RoomId>, loads: &[ShardLoad]) -> ShardId {
        assert!(!loads.is_empty(), "no shard to place on");
        ShardId::new(0)
    }

    fn session_closed(&mut self, _room: Option<RoomId>, shard: ShardId) {
        debug_assert!(shard.index() == 0);
    }
}

/// Most shards `RoomAffine` places on (the per-room counts are fixed arrays).
const ROOM_SHARDS: usize = MAX_SHARDS_SUPPORTED as usize;

/// `RoomAffine`'s limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomAffineLimits {
    /// Number of shards, 1..=`MAX_SHARDS_SUPPORTED`.
    pub shards: u16,
    /// Sessions a shard accepts (`ShardConfig::max_sessions`); a shard at it is
    /// never chosen while another is under it.
    pub max_sessions: u32,
    /// Sessions of one room on its current shard before the room moves on (≥ 1).
    pub room_shard_max_sessions: u32,
    /// Received datagrams per second above which a room's current shard takes no
    /// more of its sessions; 0 = off.
    pub room_shard_max_pps: u32,
}

/// One room's sessions per shard and the shard its next session goes to.
#[derive(Clone, Copy, Debug)]
struct RoomEntry {
    current: ShardId,
    sessions: [u32; ROOM_SHARDS],
    total: u32,
}

/// Phase 2 placement (plan 2.4): a room's sessions go to its current shard while
/// that shard has fewer than `room_shard_max_sessions` of them, is under its
/// `max_sessions` and under `room_shard_max_pps`; otherwise the least-loaded
/// shard becomes the room's current shard. Earlier sessions stay where they are,
/// and the current shard stays current when the room's count there drops to 0.
///
/// Sessions are counted here (`place` +1, `session_closed` −1), never read back
/// from the stats, which are a second old: a burst of joins spreads by these
/// counts. The stats give only `rx_pps`. Entries go at 0, so the room map is
/// bounded by live sessions.
#[derive(Debug)]
pub struct RoomAffine {
    limits: RoomAffineLimits,
    /// Sessions placed per shard.
    placed: Vec<u32>,
    rooms: HashMap<RoomId, RoomEntry>,
}

impl RoomAffine {
    /// Placement over `limits.shards` shards, none placed yet.
    pub fn new(limits: RoomAffineLimits) -> Self {
        assert!((1..=MAX_SHARDS_SUPPORTED).contains(&limits.shards));
        assert!(limits.max_sessions >= 1 && limits.room_shard_max_sessions >= 1);
        Self {
            limits,
            placed: vec![0; usize::from(limits.shards)],
            rooms: HashMap::new(),
        }
    }

    /// Sessions placed on `shard` and not closed.
    pub fn placed(&self, shard: ShardId) -> u32 {
        self.placed[usize::from(shard.index())]
    }

    /// Rooms with at least one placed session.
    pub fn rooms_tracked(&self) -> usize {
        self.rooms.len()
    }

    /// A room's sessions on `shard`.
    pub fn room_sessions(&self, room: RoomId, shard: ShardId) -> u32 {
        self.rooms
            .get(&room)
            .map_or(0, |e| e.sessions[usize::from(shard.index())])
    }

    /// Whether the room's current shard takes one more of its sessions.
    fn current_fits(&self, entry: &RoomEntry, loads: &[ShardLoad]) -> bool {
        let c = usize::from(entry.current.index());
        let pps_ok =
            self.limits.room_shard_max_pps == 0 || loads[c].rx_pps < self.limits.room_shard_max_pps;
        entry.sessions[c] < self.limits.room_shard_max_sessions
            && self.placed[c] < self.limits.max_sessions
            && pps_ok
    }

    /// The shard with the fewest placed sessions, then the lowest `rx_pps`, then the
    /// lowest index: among those under `max_sessions` and (when the limit is set)
    /// under `room_shard_max_pps`; else among those under `max_sessions`; else among
    /// all (the shard's own limit then refuses the session).
    fn least_loaded(&self, loads: &[ShardLoad]) -> ShardId {
        let key = |i: usize| (self.placed[i], loads[i].rx_pps, i);
        let shards = 0..self.placed.len();
        let has_room = |i: &usize| self.placed[*i] < self.limits.max_sessions;
        let max_pps = self.limits.room_shard_max_pps;
        let quiet = |i: &usize| max_pps == 0 || loads[*i].rx_pps < max_pps;
        let best = shards
            .clone()
            .filter(|i| has_room(i) && quiet(i))
            .min_by_key(|&i| key(i))
            .or_else(|| shards.clone().filter(has_room).min_by_key(|&i| key(i)))
            .or_else(|| shards.min_by_key(|&i| key(i)))
            .expect("at least one shard");
        ShardId::new(u8::try_from(best).expect("shard index fits"))
    }
}

impl Placement for RoomAffine {
    fn place(&mut self, room: Option<RoomId>, loads: &[ShardLoad]) -> ShardId {
        assert_eq!(loads.len(), self.placed.len(), "one load per shard");
        let current = room
            .and_then(|r| self.rooms.get(&r))
            .filter(|entry| self.current_fits(entry, loads))
            .map(|entry| entry.current);
        let shard = current.unwrap_or_else(|| self.least_loaded(loads));
        let s = usize::from(shard.index());
        self.placed[s] += 1;
        if let Some(room) = room {
            let entry = self.rooms.entry(room).or_insert(RoomEntry {
                current: shard,
                sessions: [0; ROOM_SHARDS],
                total: 0,
            });
            entry.current = shard;
            entry.sessions[s] += 1;
            entry.total += 1;
            debug_assert!(entry.total >= entry.sessions[s]);
        }
        shard
    }

    fn session_closed(&mut self, room: Option<RoomId>, shard: ShardId) {
        let s = usize::from(shard.index());
        debug_assert!(self.placed[s] > 0, "closed a session never placed");
        self.placed[s] = self.placed[s].saturating_sub(1);
        let Some(room) = room else {
            return;
        };
        debug_assert!(self.rooms.contains_key(&room), "room never placed");
        let Some(entry) = self.rooms.get_mut(&room) else {
            return;
        };
        debug_assert!(entry.sessions[s] > 0 && entry.total > 0);
        if entry.sessions[s] > 0 {
            entry.sessions[s] -= 1;
            entry.total -= 1;
        }
        debug_assert!(entry.total >= entry.sessions[s]);
        if entry.total == 0 {
            self.rooms.remove(&room);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::stats::Gauges;

    #[test]
    fn single_shard_always_places_on_zero() {
        let mut placement = SingleShard;
        let loads = [ShardLoad {
            sessions: 900,
            rx_pps: 1_000_000,
        }];
        for room in [None, Some(1), Some(7)] {
            assert_eq!(placement.place(room, &loads), ShardId::new(0));
        }
        placement.session_closed(Some(1), ShardId::new(0));
    }

    #[test]
    fn load_comes_from_the_gauges() {
        let stats = ShardStatsSnapshot {
            gauges: Gauges {
                sessions: 3,
                rx_pps: u64::MAX,
                ..Gauges::default()
            },
            ..ShardStatsSnapshot::default()
        };
        let load = ShardLoad::from(&stats);
        assert_eq!(load.sessions, 3);
        assert_eq!(load.rx_pps, u32::MAX, "saturates");
    }

    fn affine(shards: u16, max_sessions: u32, room_cap: u32) -> RoomAffine {
        RoomAffine::new(RoomAffineLimits {
            shards,
            max_sessions,
            room_shard_max_sessions: room_cap,
            room_shard_max_pps: 0,
        })
    }

    fn idle(shards: usize) -> Vec<ShardLoad> {
        vec![ShardLoad::default(); shards]
    }

    fn shard(i: u8) -> ShardId {
        ShardId::new(i)
    }

    #[test]
    fn a_room_stays_on_its_shard_up_to_the_room_cap() {
        let mut p = affine(4, 100, 3);
        let loads = idle(4);
        // Another room makes shard 0 the busiest.
        for _ in 0..2 {
            assert_eq!(p.place(Some(9), &loads), shard(0));
        }
        let first: Vec<ShardId> = (0..3).map(|_| p.place(Some(1), &loads)).collect();
        assert_eq!(first, [shard(1); 3], "a new room goes to the least-loaded");
        // Full on shard 1: the room's current shard moves to the least-loaded (2).
        assert_eq!(p.place(Some(1), &loads), shard(2));
        assert_eq!(p.place(Some(1), &loads), shard(2));
        // Earlier sessions stayed.
        assert_eq!(p.room_sessions(1, shard(1)), 3);
        assert_eq!(p.room_sessions(1, shard(2)), 2);
        // A session leaving shard 1 does not bring the room back: shard 2 is current.
        p.session_closed(Some(1), shard(1));
        assert_eq!(p.place(Some(1), &loads), shard(2));
        assert_eq!(p.room_sessions(1, shard(2)), 3);
        // Shard 2 now holds 3 of the room: the next goes to shard 3 (0 placed).
        assert_eq!(p.place(Some(1), &loads), shard(3));
    }

    #[test]
    fn least_loaded_breaks_ties_by_rx_pps_then_index() {
        let mut p = affine(3, 100, 50);
        let mut loads = idle(3);
        assert_eq!(
            p.place(Some(1), &loads),
            shard(0),
            "all equal: lowest index"
        );
        loads[1].rx_pps = 500;
        loads[2].rx_pps = 100;
        assert_eq!(p.place(Some(2), &loads), shard(2), "fewer pps among equals");
        assert_eq!(p.place(Some(3), &loads), shard(1), "fewer sessions first");
        // The stats' session gauge is ignored: placement counts its own.
        loads[0].sessions = 1_000;
        assert_eq!(p.place(None, &loads), shard(0));
    }

    #[test]
    fn a_shard_at_max_sessions_is_skipped() {
        let mut p = affine(2, 2, 50);
        let loads = idle(2);
        assert_eq!(p.place(Some(1), &loads), shard(0));
        assert_eq!(p.place(Some(2), &loads), shard(1));
        assert_eq!(p.place(Some(1), &loads), shard(0));
        // Room 1's shard is at its max: the room moves although it is under its cap.
        assert_eq!(p.place(Some(1), &loads), shard(1));
        assert_eq!((p.placed(shard(0)), p.placed(shard(1))), (2, 2));
        // Every shard at its max: the least-loaded; its own limit refuses the session.
        assert_eq!(p.place(Some(1), &loads), shard(0), "tie: lowest index");
        assert_eq!(p.place(Some(3), &loads), shard(1));
        assert_eq!((p.placed(shard(0)), p.placed(shard(1))), (3, 3));
    }

    #[test]
    fn the_pps_limit_moves_a_room_only_when_set() {
        let limits = |max_pps| RoomAffineLimits {
            shards: 3,
            max_sessions: 100,
            room_shard_max_sessions: 50,
            room_shard_max_pps: max_pps,
        };
        for max_pps in [0, 80_000] {
            let mut p = RoomAffine::new(limits(max_pps));
            let idle = idle(3);
            // Rooms 1, 2, 3 on shards 0, 1, 2; room 2 leaves: shard 1 has fewest.
            for room in 1..=3 {
                assert_eq!(p.place(Some(room), &idle), shard(room as u8 - 1));
            }
            p.session_closed(Some(2), shard(1));
            let mut loads = idle.clone();
            loads[0].rx_pps = 90_000;
            loads[1].rx_pps = 95_000;
            loads[2].rx_pps = 50_000;
            if max_pps == 0 {
                assert_eq!(p.place(Some(1), &loads), shard(0), "off: the room stays");
                continue;
            }
            // Shard 0 is above the limit: the room moves, to the least-loaded shard
            // under the limit (2), not the one with fewest sessions (1, above it).
            assert_eq!(p.place(Some(1), &loads), shard(2));
            assert_eq!(
                p.place(Some(1), &loads),
                shard(2),
                "current, under the limit"
            );
            // Every shard above it: the rule without the limit (fewest sessions).
            loads[2].rx_pps = 85_000;
            assert_eq!(p.place(Some(1), &loads), shard(1));
            // A new room prefers a shard under the limit too.
            loads[0].rx_pps = 10;
            assert_eq!(p.place(Some(4), &loads), shard(0));
        }
    }

    #[test]
    fn a_mass_join_spreads_by_placements_own_counts() {
        // 100 joins in one tick: the stats (loads) never change meanwhile.
        let loads = idle(4);
        let mut one_room = affine(4, 1_000, 50);
        for _ in 0..100 {
            one_room.place(Some(1), &loads);
        }
        let spread: Vec<u32> = (0..4).map(|i| one_room.placed(shard(i))).collect();
        assert_eq!(spread, [50, 50, 0, 0]);
        let mut many_rooms = affine(4, 1_000, 50);
        for room in 1..=100 {
            many_rooms.place(Some(room), &loads);
        }
        let spread: Vec<u32> = (0..4).map(|i| many_rooms.placed(shard(i))).collect();
        assert_eq!(spread, [25; 4]);
    }

    #[test]
    fn entries_are_freed_at_zero() {
        let mut p = affine(3, 100, 2);
        let loads = idle(3);
        let mut placed = Vec::new();
        for room in [1, 1, 1, 2, 2] {
            placed.push((room, p.place(Some(room), &loads)));
        }
        placed.push((0, p.place(None, &loads)));
        assert_eq!(p.rooms_tracked(), 2);
        for (room, s) in placed {
            let room = (room != 0).then_some(room);
            p.session_closed(room, s);
        }
        assert_eq!(p.rooms_tracked(), 0);
        assert!((0..3).all(|i| p.placed(shard(i)) == 0));
        // A room seen again starts fresh on the least-loaded shard.
        assert_eq!(p.place(Some(1), &loads), shard(0));
    }

    #[test]
    fn one_shard_always_places_on_zero() {
        let mut p = affine(1, 3, 1);
        let loads = idle(1);
        for room in [Some(1), Some(1), None, Some(2), Some(1)] {
            assert_eq!(p.place(room, &loads), shard(0));
        }
        assert_eq!(p.placed(shard(0)), 5, "over max: the shard refuses");
    }

    #[test]
    #[should_panic(expected = "one load per shard")]
    fn loads_must_cover_every_shard() {
        affine(2, 10, 5).place(Some(1), &idle(1));
    }
}
