//! Actor system metrics collector
//!
//! Tracks actor counts, message queues, and supervision events.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Actor metrics collector
pub struct ActorMetrics {
    // Actor counts by type
    room_actors: AtomicU32,
    participant_actors: AtomicU32,
    track_actors: AtomicU32,

    // Message queue metrics
    total_message_queue_depth: AtomicU64,
    messages_processed_total: AtomicU64,
    messages_dropped_total: AtomicU64,

    // Supervision metrics
    actor_restarts_total: AtomicU64,
    actor_failures_total: AtomicU64,
}

impl ActorMetrics {
    pub fn new() -> Self {
        Self {
            room_actors: AtomicU32::new(0),
            participant_actors: AtomicU32::new(0),
            track_actors: AtomicU32::new(0),
            total_message_queue_depth: AtomicU64::new(0),
            messages_processed_total: AtomicU64::new(0),
            messages_dropped_total: AtomicU64::new(0),
            actor_restarts_total: AtomicU64::new(0),
            actor_failures_total: AtomicU64::new(0),
        }
    }

    /// Set room actor count
    pub fn set_room_actors(&self, count: u32) {
        self.room_actors.store(count, Ordering::Relaxed);
    }

    pub fn room_actors(&self) -> u32 {
        self.room_actors.load(Ordering::Relaxed)
    }

    /// Set participant actor count
    pub fn set_participant_actors(&self, count: u32) {
        self.participant_actors.store(count, Ordering::Relaxed);
    }

    pub fn participant_actors(&self) -> u32 {
        self.participant_actors.load(Ordering::Relaxed)
    }

    /// Set track actor count
    pub fn set_track_actors(&self, count: u32) {
        self.track_actors.store(count, Ordering::Relaxed);
    }

    pub fn track_actors(&self) -> u32 {
        self.track_actors.load(Ordering::Relaxed)
    }

    /// Get total actor count
    pub fn total_actors(&self) -> u32 {
        self.room_actors() + self.participant_actors() + self.track_actors()
    }

    /// Set total message queue depth
    pub fn set_message_queue_depth(&self, depth: u64) {
        self.total_message_queue_depth.store(depth, Ordering::Relaxed);
    }

    pub fn message_queue_depth(&self) -> u64 {
        self.total_message_queue_depth.load(Ordering::Relaxed)
    }

    /// Record message processed
    #[inline(always)]
    pub fn record_message_processed(&self) {
        self.messages_processed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn messages_processed_total(&self) -> u64 {
        self.messages_processed_total.load(Ordering::Relaxed)
    }

    /// Record message dropped
    pub fn record_message_dropped(&self) {
        self.messages_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn messages_dropped_total(&self) -> u64 {
        self.messages_dropped_total.load(Ordering::Relaxed)
    }

    /// Record actor restart
    pub fn record_actor_restart(&self) {
        self.actor_restarts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn actor_restarts_total(&self) -> u64 {
        self.actor_restarts_total.load(Ordering::Relaxed)
    }

    /// Record actor failure
    pub fn record_actor_failure(&self) {
        self.actor_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn actor_failures_total(&self) -> u64 {
        self.actor_failures_total.load(Ordering::Relaxed)
    }
}

impl Default for ActorMetrics {
    fn default() -> Self {
        Self::new()
    }
}
