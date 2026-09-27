//! Data-plane identifiers allocated by the orchestrator (design note §4).
//!
//! One counter per id type, starting at 1: the shard treats 0 as invalid, and a
//! `TrackId` keeps the value the signaling protocol already uses as `track_id`.

use nexus_dataplane::{SessionId, SubscriptionId, TrackId};

/// Counters for session, track and subscription ids. Owned by the orchestrator's
/// single task, so plain integers suffice.
#[derive(Debug)]
pub struct IdAllocator {
    next_session: u64,
    next_track: u64,
    next_subscription: u64,
}

impl Default for IdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl IdAllocator {
    /// Counters starting at 1.
    pub fn new() -> Self {
        Self {
            next_session: 1,
            next_track: 1,
            next_subscription: 1,
        }
    }

    /// A new session id, never 0 and never repeated.
    pub fn session(&mut self) -> SessionId {
        SessionId::new(Self::bump(&mut self.next_session))
    }

    /// A new track id, never 0 and never repeated.
    pub fn track(&mut self) -> TrackId {
        TrackId::new(Self::bump(&mut self.next_track))
    }

    /// A new subscription id, never 0 and never repeated.
    pub fn subscription(&mut self) -> SubscriptionId {
        SubscriptionId::new(Self::bump(&mut self.next_subscription))
    }

    fn bump(counter: &mut u64) -> u64 {
        let value = *counter;
        assert!(value != 0, "id counter must start at 1");
        // 2^64 ids cannot be used up; a wrap would mean memory corruption.
        *counter = value.checked_add(1).expect("id counter overflow");
        assert!(*counter > value);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_start_at_one_and_increase_per_type() {
        let mut ids = IdAllocator::new();
        assert_eq!(ids.session().get(), 1);
        assert_eq!(ids.session().get(), 2);
        assert_eq!(ids.track().get(), 1);
        assert_eq!(ids.subscription().get(), 1);
        let mut last = ids.track().get();
        for _ in 0..1_000 {
            let next = ids.track().get();
            assert!(next > last);
            last = next;
        }
    }
}
