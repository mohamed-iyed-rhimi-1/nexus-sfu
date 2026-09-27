//! Which shard a new session goes to (note §13.2). Phase 1 has one shard;
//! Phase 2 adds `RoomAffine`. A session stays on its shard for life.

use nexus_core::RoomId;

use crate::ids::ShardId;
use crate::shard::stats::ShardStatsSnapshot;

/// A shard's load, from its published stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardLoad {
    /// Sessions on the shard.
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
}
