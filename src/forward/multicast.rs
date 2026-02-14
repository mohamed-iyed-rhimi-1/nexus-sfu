//! Hot/Cold Subscriber Management for Nexus SFU MVP.
//!
//! Provides subscriber management with hot/cold separation for optimized
//! packet forwarding. Hot subscribers are actively receiving packets and
//! are iterated on every packet forward. Cold subscribers are inactive
//! and checked periodically for reactivation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SubscriberList                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  ┌─────────────────────┐    ┌─────────────────────┐         │
//! │  │   Hot Subscribers   │    │  Cold Subscribers   │         │
//! │  │   (fast path)       │    │  (checked periodic) │         │
//! │  ├─────────────────────┤    ├─────────────────────┤         │
//! │  │ • Sub 1 (active)    │    │ • Sub 3 (inactive)  │         │
//! │  │ • Sub 2 (active)    │    │ • Sub 5 (inactive)  │         │
//! │  │ • Sub 4 (active)    │    │                     │         │
//! │  └─────────────────────┘    └─────────────────────┘         │
//! │           │                          │                       │
//! │           │ receives packet          │ timeout expired       │
//! │           ▼                          ▼                       │
//! │     update last_active_ns      demote_inactive()            │
//! │                                      │                       │
//! │           ▲                          │                       │
//! │           │ requests packets         │                       │
//! │           │                          ▼                       │
//! │     promote_to_hot() ◄──────── cold subscriber              │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Requirements Coverage
//!
//! - Requirement 8.1: Hot/cold subscriber classification
//! - Requirement 8.2: Mark as hot when receiving packets
//! - Requirement 8.3: Mark as cold after timeout
//! - Requirement 8.4: Iterate only hot subscribers in fast path
//! - Requirement 8.6: Promote cold to hot on packet request
//! - Requirement 8.7: Track statistics for hot/cold transitions

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::types::ParticipantId;

/// Default cold timeout in nanoseconds (5 seconds).
pub const DEFAULT_COLD_TIMEOUT_NS: u64 = 5_000_000_000;

/// Maximum subscribers per track (TigerStyle: fixed loop bound).
pub const MAX_SUBSCRIBERS_PER_TRACK: usize = 1000;

/// Viewport filter for selective forwarding.
///
/// Determines which packets should be forwarded to a subscriber based on
/// their viewport (visible participants) and pinned participants.
///
/// Note: This is a placeholder implementation. Full implementation is in Task 12.
#[derive(Debug, Clone, Default)]
pub struct ViewportFilter {
    /// Set of visible participant IDs.
    visible_participants: HashSet<u32>,
    /// Pinned participants (always forward regardless of viewport).
    pinned_participants: HashSet<u32>,
}

impl ViewportFilter {
    /// Create an empty viewport filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update visible participants.
    ///
    /// # Arguments
    ///
    /// * `participants` - Slice of participant IDs that are visible
    ///
    /// # Assertions
    /// - participants.len() <= 1000
    pub fn set_visible(&mut self, participants: &[u32]) {
        // TigerStyle: Assert preconditions
        assert!(
            participants.len() <= MAX_SUBSCRIBERS_PER_TRACK,
            "visible participants must not exceed {}",
            MAX_SUBSCRIBERS_PER_TRACK
        );

        self.visible_participants.clear();
        self.visible_participants.extend(participants.iter().copied());
    }

    /// Pin a participant (always forward their packets).
    pub fn pin(&mut self, participant_id: u32) {
        self.pinned_participants.insert(participant_id);
    }

    /// Unpin a participant.
    pub fn unpin(&mut self, participant_id: u32) {
        self.pinned_participants.remove(&participant_id);
    }

    /// Check if packets from a source should be forwarded.
    ///
    /// Returns true if:
    /// - Source is pinned, OR
    /// - Source is in the visible set
    ///
    /// # Arguments
    ///
    /// * `source_participant_id` - Participant ID of the packet source
    ///
    /// # Assertions
    /// - source_participant_id != 0
    #[inline(always)]
    pub fn should_forward(&self, source_participant_id: u32) -> bool {
        // TigerStyle: Assert preconditions
        assert!(source_participant_id != 0, "source_participant_id must not be 0");

        // Pinned participants always get forwarded
        if self.pinned_participants.contains(&source_participant_id) {
            return true;
        }

        // Check if in visible set
        self.visible_participants.contains(&source_participant_id)
    }

    /// Check if a participant is pinned.
    pub fn is_pinned(&self, participant_id: u32) -> bool {
        self.pinned_participants.contains(&participant_id)
    }

    /// Check if a participant is visible.
    pub fn is_visible(&self, participant_id: u32) -> bool {
        self.visible_participants.contains(&participant_id)
    }

    /// Get the number of visible participants.
    pub fn visible_count(&self) -> usize {
        self.visible_participants.len()
    }

    /// Get the number of pinned participants.
    pub fn pinned_count(&self) -> usize {
        self.pinned_participants.len()
    }

    /// Clear all viewport state.
    pub fn clear(&mut self) {
        self.visible_participants.clear();
        self.pinned_participants.clear();
    }
}

/// Subscriber with hot/cold classification.
///
/// Represents a participant subscribed to receive packets from a track.
/// Uses atomic fields for lock-free access to hot/cold state and activity time.
///
/// # Thread Safety
///
/// The `is_hot` and `last_active_ns` fields are atomic, allowing concurrent
/// reads and writes without locks. The `viewport` field requires external
/// synchronization for updates (typically via copy-on-write at the list level).
///
/// # Example
///
/// ```
/// use nexus_sfu::forward::multicast::Subscriber;
/// use std::net::SocketAddr;
///
/// let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
/// let subscriber = Subscriber::new(1, 100, addr);
///
/// // Subscriber starts as hot
/// assert!(subscriber.is_hot());
///
/// // Update activity time when packet is received
/// subscriber.touch(1_000_000_000);
/// assert_eq!(subscriber.last_active_ns(), 1_000_000_000);
/// ```
#[derive(Debug)]
pub struct Subscriber {
    /// Unique subscriber ID.
    id: u32,
    /// Participant ID of the subscriber.
    participant_id: ParticipantId,
    /// Destination address for packet delivery.
    dest_addr: SocketAddr,
    /// Whether this subscriber is hot (actively receiving).
    is_hot: AtomicBool,
    /// Last packet receive time in nanoseconds for cold detection.
    last_active_ns: AtomicU64,
    /// Viewport filter for selective forwarding.
    viewport: ViewportFilter,
}

impl Subscriber {
    /// Create a new subscriber.
    ///
    /// The subscriber starts as hot with the current time as last active.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique subscriber ID
    /// * `participant_id` - Participant ID
    /// * `dest_addr` - Destination address for packets
    ///
    /// # Assertions
    /// - id != 0
    /// - participant_id != 0
    pub fn new(id: u32, participant_id: ParticipantId, dest_addr: SocketAddr) -> Self {
        // TigerStyle: Assert preconditions
        assert!(id != 0, "subscriber id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        Self {
            id,
            participant_id,
            dest_addr,
            is_hot: AtomicBool::new(true), // Start as hot
            last_active_ns: AtomicU64::new(0),
            viewport: ViewportFilter::new(),
        }
    }

    /// Create a new subscriber with initial activity time.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique subscriber ID
    /// * `participant_id` - Participant ID
    /// * `dest_addr` - Destination address for packets
    /// * `current_time_ns` - Current time in nanoseconds
    ///
    /// # Assertions
    /// - id != 0
    /// - participant_id != 0
    pub fn with_time(
        id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
        current_time_ns: u64,
    ) -> Self {
        // TigerStyle: Assert preconditions
        assert!(id != 0, "subscriber id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        Self {
            id,
            participant_id,
            dest_addr,
            is_hot: AtomicBool::new(true),
            last_active_ns: AtomicU64::new(current_time_ns),
            viewport: ViewportFilter::new(),
        }
    }

    /// Get the subscriber ID.
    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get the participant ID.
    #[inline(always)]
    pub fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Get the destination address.
    #[inline(always)]
    pub fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }

    /// Check if the subscriber is hot (actively receiving).
    #[inline(always)]
    pub fn is_hot(&self) -> bool {
        self.is_hot.load(Ordering::Acquire)
    }

    /// Get the last active time in nanoseconds.
    #[inline(always)]
    pub fn last_active_ns(&self) -> u64 {
        self.last_active_ns.load(Ordering::Acquire)
    }

    /// Get a reference to the viewport filter.
    #[inline(always)]
    pub fn viewport(&self) -> &ViewportFilter {
        &self.viewport
    }

    /// Get a mutable reference to the viewport filter.
    #[inline(always)]
    pub fn viewport_mut(&mut self) -> &mut ViewportFilter {
        &mut self.viewport
    }

    /// Update the last active time (called when packet is received).
    ///
    /// # Arguments
    ///
    /// * `time_ns` - Current time in nanoseconds
    #[inline(always)]
    pub fn touch(&self, time_ns: u64) {
        self.last_active_ns.store(time_ns, Ordering::Release);
    }

    /// Set the hot/cold state.
    ///
    /// # Arguments
    ///
    /// * `hot` - True for hot, false for cold
    #[inline(always)]
    pub fn set_hot(&self, hot: bool) {
        self.is_hot.store(hot, Ordering::Release);
    }

    /// Atomically transition from cold to hot.
    ///
    /// Returns true if the transition occurred (was cold, now hot).
    /// Returns false if already hot.
    #[inline(always)]
    pub fn promote_to_hot(&self) -> bool {
        self.is_hot
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Atomically transition from hot to cold.
    ///
    /// Returns true if the transition occurred (was hot, now cold).
    /// Returns false if already cold.
    #[inline(always)]
    pub fn demote_to_cold(&self) -> bool {
        self.is_hot
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Check if the subscriber should be demoted to cold based on timeout.
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current time in nanoseconds
    /// * `timeout_ns` - Cold timeout in nanoseconds
    ///
    /// # Returns
    ///
    /// True if the subscriber has been inactive longer than the timeout.
    #[inline(always)]
    pub fn is_inactive(&self, current_time_ns: u64, timeout_ns: u64) -> bool {
        let last_active = self.last_active_ns.load(Ordering::Acquire);
        current_time_ns.saturating_sub(last_active) > timeout_ns
    }

    /// Check if packets from a source should be forwarded to this subscriber.
    ///
    /// # Arguments
    ///
    /// * `source_participant_id` - Participant ID of the packet source
    #[inline(always)]
    pub fn should_forward(&self, source_participant_id: u32) -> bool {
        self.viewport.should_forward(source_participant_id)
    }
}

// Implement Clone manually since AtomicBool and AtomicU64 don't implement Clone
impl Clone for Subscriber {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            participant_id: self.participant_id,
            dest_addr: self.dest_addr,
            is_hot: AtomicBool::new(self.is_hot.load(Ordering::Acquire)),
            last_active_ns: AtomicU64::new(self.last_active_ns.load(Ordering::Acquire)),
            viewport: self.viewport.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === ViewportFilter Tests ===

    #[test]
    fn test_viewport_filter_new() {
        let filter = ViewportFilter::new();
        assert_eq!(filter.visible_count(), 0);
        assert_eq!(filter.pinned_count(), 0);
    }

    #[test]
    fn test_viewport_filter_set_visible() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);

        assert!(filter.is_visible(1));
        assert!(filter.is_visible(2));
        assert!(filter.is_visible(3));
        assert!(!filter.is_visible(4));
        assert_eq!(filter.visible_count(), 3);
    }

    #[test]
    fn test_viewport_filter_pin_unpin() {
        let mut filter = ViewportFilter::new();

        filter.pin(100);
        assert!(filter.is_pinned(100));
        assert_eq!(filter.pinned_count(), 1);

        filter.unpin(100);
        assert!(!filter.is_pinned(100));
        assert_eq!(filter.pinned_count(), 0);
    }

    #[test]
    fn test_viewport_filter_should_forward() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);

        // Visible participants should be forwarded
        assert!(filter.should_forward(1));
        assert!(filter.should_forward(2));

        // Pinned participants should always be forwarded
        assert!(filter.should_forward(100));

        // Non-visible, non-pinned should not be forwarded
        assert!(!filter.should_forward(50));
    }

    #[test]
    fn test_viewport_filter_clear() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);

        filter.clear();

        assert_eq!(filter.visible_count(), 0);
        assert_eq!(filter.pinned_count(), 0);
    }

    #[test]
    #[should_panic(expected = "source_participant_id must not be 0")]
    fn test_viewport_filter_should_forward_zero_id() {
        let filter = ViewportFilter::new();
        let _ = filter.should_forward(0);
    }

    // === Subscriber Tests ===

    #[test]
    fn test_subscriber_new() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::new(1, 100, addr);

        assert_eq!(subscriber.id(), 1);
        assert_eq!(subscriber.participant_id(), 100);
        assert_eq!(subscriber.dest_addr(), addr);
        assert!(subscriber.is_hot());
        assert_eq!(subscriber.last_active_ns(), 0);
    }

    #[test]
    fn test_subscriber_with_time() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::with_time(1, 100, addr, 1_000_000_000);

        assert!(subscriber.is_hot());
        assert_eq!(subscriber.last_active_ns(), 1_000_000_000);
    }

    #[test]
    #[should_panic(expected = "subscriber id must not be 0")]
    fn test_subscriber_zero_id() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let _ = Subscriber::new(0, 100, addr);
    }

    #[test]
    #[should_panic(expected = "participant_id must not be 0")]
    fn test_subscriber_zero_participant() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let _ = Subscriber::new(1, 0, addr);
    }

    #[test]
    fn test_subscriber_touch() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::new(1, 100, addr);

        subscriber.touch(1_000_000_000);
        assert_eq!(subscriber.last_active_ns(), 1_000_000_000);

        subscriber.touch(2_000_000_000);
        assert_eq!(subscriber.last_active_ns(), 2_000_000_000);
    }

    #[test]
    fn test_subscriber_set_hot() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::new(1, 100, addr);

        assert!(subscriber.is_hot());

        subscriber.set_hot(false);
        assert!(!subscriber.is_hot());

        subscriber.set_hot(true);
        assert!(subscriber.is_hot());
    }

    #[test]
    fn test_subscriber_promote_demote() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::new(1, 100, addr);

        // Start hot, demote should succeed
        assert!(subscriber.demote_to_cold());
        assert!(!subscriber.is_hot());

        // Already cold, demote should fail
        assert!(!subscriber.demote_to_cold());

        // Cold, promote should succeed
        assert!(subscriber.promote_to_hot());
        assert!(subscriber.is_hot());

        // Already hot, promote should fail
        assert!(!subscriber.promote_to_hot());
    }

    #[test]
    fn test_subscriber_is_inactive() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::with_time(1, 100, addr, 1_000_000_000);

        // Not inactive yet (within timeout)
        assert!(!subscriber.is_inactive(2_000_000_000, DEFAULT_COLD_TIMEOUT_NS));

        // Inactive (past timeout)
        assert!(subscriber.is_inactive(10_000_000_000, DEFAULT_COLD_TIMEOUT_NS));
    }

    #[test]
    fn test_subscriber_clone() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let subscriber = Subscriber::with_time(1, 100, addr, 1_000_000_000);
        subscriber.set_hot(false);

        let cloned = subscriber.clone();

        assert_eq!(cloned.id(), subscriber.id());
        assert_eq!(cloned.participant_id(), subscriber.participant_id());
        assert_eq!(cloned.dest_addr(), subscriber.dest_addr());
        assert_eq!(cloned.is_hot(), subscriber.is_hot());
        assert_eq!(cloned.last_active_ns(), subscriber.last_active_ns());
    }

    #[test]
    fn test_subscriber_viewport() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let mut subscriber = Subscriber::new(1, 100, addr);

        subscriber.viewport_mut().set_visible(&[1, 2, 3]);
        subscriber.viewport_mut().pin(100);

        assert!(subscriber.should_forward(1));
        assert!(subscriber.should_forward(100));
        assert!(!subscriber.should_forward(50));
    }
}


/// Statistics for subscriber list hot/cold transitions.
///
/// Tracks the number of promotions and demotions for monitoring.
#[derive(Debug, Default)]
pub struct SubscriberListStats {
    /// Number of promotions from cold to hot.
    pub promotions: AtomicU64,
    /// Number of demotions from hot to cold.
    pub demotions: AtomicU64,
    /// Number of subscribers added.
    pub subscribers_added: AtomicU64,
    /// Number of subscribers removed.
    pub subscribers_removed: AtomicU64,
}

impl SubscriberListStats {
    /// Create new statistics with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a promotion from cold to hot.
    #[inline(always)]
    pub fn record_promotion(&self) {
        self.promotions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a demotion from hot to cold.
    #[inline(always)]
    pub fn record_demotion(&self) {
        self.demotions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a subscriber addition.
    #[inline(always)]
    pub fn record_add(&self) {
        self.subscribers_added.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a subscriber removal.
    #[inline(always)]
    pub fn record_remove(&self) {
        self.subscribers_removed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> SubscriberListStatsSnapshot {
        SubscriberListStatsSnapshot {
            promotions: self.promotions.load(Ordering::Relaxed),
            demotions: self.demotions.load(Ordering::Relaxed),
            subscribers_added: self.subscribers_added.load(Ordering::Relaxed),
            subscribers_removed: self.subscribers_removed.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.promotions.store(0, Ordering::Relaxed);
        self.demotions.store(0, Ordering::Relaxed);
        self.subscribers_added.store(0, Ordering::Relaxed);
        self.subscribers_removed.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of subscriber list statistics at a point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriberListStatsSnapshot {
    pub promotions: u64,
    pub demotions: u64,
    pub subscribers_added: u64,
    pub subscribers_removed: u64,
}

/// List of subscribers with hot/cold separation.
///
/// Hot subscribers are actively receiving packets and are iterated on every
/// packet forward. Cold subscribers are inactive and checked periodically
/// for reactivation.
///
/// # Thread Safety
///
/// This struct is designed to be used with copy-on-write semantics via
/// `Arc<ArcSwap<SubscriberList>>`. Updates create a new list and atomically
/// swap it in, allowing lock-free reads on the hot path.
///
/// # Example
///
/// ```
/// use nexus_sfu::forward::multicast::{Subscriber, SubscriberList};
/// use std::net::SocketAddr;
///
/// let mut list = SubscriberList::new(5_000_000_000); // 5 second timeout
///
/// let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
/// list.add(Subscriber::new(1, 100, addr));
///
/// // Subscriber starts as hot
/// assert_eq!(list.counts(), (1, 0));
///
/// // Demote inactive subscribers
/// list.demote_inactive(10_000_000_000);
/// assert_eq!(list.counts(), (0, 1));
/// ```
#[derive(Debug)]
pub struct SubscriberList {
    /// Hot subscribers (iterated on every packet).
    hot: Vec<Subscriber>,
    /// Cold subscribers (checked periodically).
    cold: Vec<Subscriber>,
    /// Timeout for hot->cold transition in nanoseconds.
    cold_timeout_ns: u64,
    /// Statistics for transitions.
    stats: SubscriberListStats,
}

impl SubscriberList {
    /// Create an empty subscriber list with the specified cold timeout.
    ///
    /// # Arguments
    ///
    /// * `cold_timeout_ns` - Timeout in nanoseconds for hot->cold transition
    ///
    /// # Assertions
    /// - cold_timeout_ns > 0
    pub fn new(cold_timeout_ns: u64) -> Self {
        // TigerStyle: Assert preconditions
        assert!(cold_timeout_ns > 0, "cold_timeout_ns must be greater than 0");

        Self {
            hot: Vec::new(),
            cold: Vec::new(),
            cold_timeout_ns,
            stats: SubscriberListStats::new(),
        }
    }

    /// Create an empty subscriber list with default timeout (5 seconds).
    pub fn with_default_timeout() -> Self {
        Self::new(DEFAULT_COLD_TIMEOUT_NS)
    }

    /// Add a subscriber (starts as hot).
    ///
    /// # Arguments
    ///
    /// * `subscriber` - Subscriber to add
    ///
    /// # Assertions
    /// - subscriber.id() != 0
    /// - total subscribers <= MAX_SUBSCRIBERS_PER_TRACK
    pub fn add(&mut self, subscriber: Subscriber) {
        // TigerStyle: Assert preconditions
        assert!(subscriber.id() != 0, "subscriber id must not be 0");
        assert!(
            self.len() < MAX_SUBSCRIBERS_PER_TRACK,
            "subscriber list is at maximum capacity ({})",
            MAX_SUBSCRIBERS_PER_TRACK
        );

        // Ensure subscriber is marked as hot
        subscriber.set_hot(true);
        self.hot.push(subscriber);
        self.stats.record_add();
    }

    /// Remove a subscriber by ID.
    ///
    /// Searches both hot and cold lists.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - ID of subscriber to remove
    ///
    /// # Returns
    ///
    /// The removed subscriber if found.
    pub fn remove(&mut self, subscriber_id: u32) -> Option<Subscriber> {
        // Search hot list first (more likely)
        if let Some(pos) = self.hot.iter().position(|s| s.id() == subscriber_id) {
            self.stats.record_remove();
            return Some(self.hot.remove(pos));
        }

        // Search cold list
        if let Some(pos) = self.cold.iter().position(|s| s.id() == subscriber_id) {
            self.stats.record_remove();
            return Some(self.cold.remove(pos));
        }

        None
    }

    /// Get an iterator over hot subscribers only (fast path).
    ///
    /// This is the primary iteration method used during packet forwarding.
    /// Only hot subscribers are iterated, providing O(hot_count) performance.
    #[inline(always)]
    pub fn iter_hot(&self) -> impl Iterator<Item = &Subscriber> {
        self.hot.iter()
    }

    /// Get an iterator over cold subscribers.
    #[inline(always)]
    pub fn iter_cold(&self) -> impl Iterator<Item = &Subscriber> {
        self.cold.iter()
    }

    /// Get an iterator over all subscribers (hot and cold).
    pub fn iter_all(&self) -> impl Iterator<Item = &Subscriber> {
        self.hot.iter().chain(self.cold.iter())
    }

    /// Get the total number of subscribers.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.hot.len() + self.cold.len()
    }

    /// Check if there are no subscribers.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    /// Get counts of hot and cold subscribers.
    #[inline(always)]
    pub fn counts(&self) -> (usize, usize) {
        (self.hot.len(), self.cold.len())
    }

    /// Get the cold timeout in nanoseconds.
    #[inline(always)]
    pub fn cold_timeout_ns(&self) -> u64 {
        self.cold_timeout_ns
    }

    /// Get the statistics for this list.
    pub fn stats(&self) -> &SubscriberListStats {
        &self.stats
    }

    /// Promote a cold subscriber to hot.
    ///
    /// Called when a cold subscriber requests packets (reactivation).
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - ID of subscriber to promote
    ///
    /// # Returns
    ///
    /// True if the subscriber was found in cold list and promoted.
    pub fn promote_to_hot(&mut self, subscriber_id: u32) -> bool {
        if let Some(pos) = self.cold.iter().position(|s| s.id() == subscriber_id) {
            let subscriber = self.cold.remove(pos);
            subscriber.set_hot(true);
            self.hot.push(subscriber);
            self.stats.record_promotion();
            return true;
        }
        false
    }

    /// Demote inactive hot subscribers to cold.
    ///
    /// Checks all hot subscribers and moves those that have been inactive
    /// longer than the cold timeout to the cold list.
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current time in nanoseconds
    ///
    /// # Returns
    ///
    /// Number of subscribers demoted.
    ///
    /// # Assertions
    /// - current_time_ns > 0
    pub fn demote_inactive(&mut self, current_time_ns: u64) -> usize {
        // TigerStyle: Assert preconditions
        assert!(current_time_ns > 0, "current_time_ns must be greater than 0");

        let mut demoted_count = 0usize;
        let timeout = self.cold_timeout_ns;

        // Iterate in reverse to allow removal without index shifting issues
        // TigerStyle: Fixed loop bound
        let mut i = self.hot.len();
        while i > 0 {
            i -= 1;
            if self.hot[i].is_inactive(current_time_ns, timeout) {
                let subscriber = self.hot.remove(i);
                subscriber.set_hot(false);
                self.cold.push(subscriber);
                demoted_count += 1;
                self.stats.record_demotion();
            }
        }

        demoted_count
    }

    /// Update last_active_ns for a subscriber when they receive a packet.
    ///
    /// This should be called when forwarding a packet to a subscriber.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - ID of subscriber that received packet
    /// * `time_ns` - Current time in nanoseconds
    ///
    /// # Returns
    ///
    /// True if the subscriber was found and updated.
    pub fn touch(&self, subscriber_id: u32, time_ns: u64) -> bool {
        // Search hot list first (more likely)
        for subscriber in &self.hot {
            if subscriber.id() == subscriber_id {
                subscriber.touch(time_ns);
                return true;
            }
        }

        // Search cold list
        for subscriber in &self.cold {
            if subscriber.id() == subscriber_id {
                subscriber.touch(time_ns);
                return true;
            }
        }

        false
    }

    /// Find a subscriber by ID.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - ID of subscriber to find
    ///
    /// # Returns
    ///
    /// Reference to the subscriber if found.
    pub fn find(&self, subscriber_id: u32) -> Option<&Subscriber> {
        // Search hot list first
        if let Some(subscriber) = self.hot.iter().find(|s| s.id() == subscriber_id) {
            return Some(subscriber);
        }

        // Search cold list
        self.cold.iter().find(|s| s.id() == subscriber_id)
    }

    /// Check if a subscriber exists.
    pub fn contains(&self, subscriber_id: u32) -> bool {
        self.find(subscriber_id).is_some()
    }

    /// Get a subscriber's hot/cold status.
    ///
    /// # Returns
    ///
    /// Some(true) if hot, Some(false) if cold, None if not found.
    pub fn is_subscriber_hot(&self, subscriber_id: u32) -> Option<bool> {
        if self.hot.iter().any(|s| s.id() == subscriber_id) {
            return Some(true);
        }
        if self.cold.iter().any(|s| s.id() == subscriber_id) {
            return Some(false);
        }
        None
    }
}

// Implement Clone for SubscriberList (needed for copy-on-write)
impl Clone for SubscriberList {
    fn clone(&self) -> Self {
        Self {
            hot: self.hot.clone(),
            cold: self.cold.clone(),
            cold_timeout_ns: self.cold_timeout_ns,
            stats: SubscriberListStats::new(), // Fresh stats for cloned list
        }
    }
}

#[cfg(test)]
mod subscriber_list_tests {
    use super::*;

    #[test]
    fn test_subscriber_list_new() {
        let list = SubscriberList::new(5_000_000_000);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.counts(), (0, 0));
        assert_eq!(list.cold_timeout_ns(), 5_000_000_000);
    }

    #[test]
    fn test_subscriber_list_with_default_timeout() {
        let list = SubscriberList::with_default_timeout();
        assert_eq!(list.cold_timeout_ns(), DEFAULT_COLD_TIMEOUT_NS);
    }

    #[test]
    #[should_panic(expected = "cold_timeout_ns must be greater than 0")]
    fn test_subscriber_list_zero_timeout() {
        let _ = SubscriberList::new(0);
    }

    #[test]
    fn test_subscriber_list_add() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));

        assert_eq!(list.len(), 1);
        assert_eq!(list.counts(), (1, 0)); // 1 hot, 0 cold
        assert!(list.contains(1));

        let stats = list.stats().snapshot();
        assert_eq!(stats.subscribers_added, 1);
    }

    #[test]
    fn test_subscriber_list_add_multiple() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));
        list.add(Subscriber::new(2, 101, addr));
        list.add(Subscriber::new(3, 102, addr));

        assert_eq!(list.len(), 3);
        assert_eq!(list.counts(), (3, 0));
    }

    #[test]
    fn test_subscriber_list_remove_from_hot() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));
        list.add(Subscriber::new(2, 101, addr));

        let removed = list.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id(), 1);
        assert_eq!(list.len(), 1);
        assert!(!list.contains(1));
        assert!(list.contains(2));

        let stats = list.stats().snapshot();
        assert_eq!(stats.subscribers_removed, 1);
    }

    #[test]
    fn test_subscriber_list_remove_from_cold() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));

        // Demote to cold
        list.demote_inactive(10_000_000_000);
        assert_eq!(list.counts(), (0, 1));

        // Remove from cold
        let removed = list.remove(1);
        assert!(removed.is_some());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_subscriber_list_remove_not_found() {
        let mut list = SubscriberList::new(5_000_000_000);
        let removed = list.remove(999);
        assert!(removed.is_none());
    }

    #[test]
    fn test_subscriber_list_iter_hot() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));
        list.add(Subscriber::with_time(2, 101, addr, 1_000_000_000));
        list.add(Subscriber::with_time(3, 102, addr, 10_000_000_000)); // Recent

        // Demote inactive (1 and 2 should be demoted)
        list.demote_inactive(10_000_000_000);

        // iter_hot should only return subscriber 3
        let hot_ids: Vec<u32> = list.iter_hot().map(|s| s.id()).collect();
        assert_eq!(hot_ids, vec![3]);
    }

    #[test]
    fn test_subscriber_list_promote_to_hot() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));

        // Demote to cold
        list.demote_inactive(10_000_000_000);
        assert_eq!(list.counts(), (0, 1));
        assert_eq!(list.is_subscriber_hot(1), Some(false));

        // Promote back to hot
        assert!(list.promote_to_hot(1));
        assert_eq!(list.counts(), (1, 0));
        assert_eq!(list.is_subscriber_hot(1), Some(true));

        let stats = list.stats().snapshot();
        assert_eq!(stats.promotions, 1);
        assert_eq!(stats.demotions, 1);
    }

    #[test]
    fn test_subscriber_list_promote_not_found() {
        let mut list = SubscriberList::new(5_000_000_000);
        assert!(!list.promote_to_hot(999));
    }

    #[test]
    fn test_subscriber_list_demote_inactive() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        // Add subscribers with different activity times
        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000)); // Old
        list.add(Subscriber::with_time(2, 101, addr, 1_000_000_000)); // Old
        list.add(Subscriber::with_time(3, 102, addr, 9_000_000_000)); // Recent

        assert_eq!(list.counts(), (3, 0));

        // Demote inactive (timeout is 5 seconds)
        let demoted = list.demote_inactive(10_000_000_000);

        assert_eq!(demoted, 2);
        assert_eq!(list.counts(), (1, 2));

        // Subscriber 3 should still be hot
        assert_eq!(list.is_subscriber_hot(3), Some(true));
        assert_eq!(list.is_subscriber_hot(1), Some(false));
        assert_eq!(list.is_subscriber_hot(2), Some(false));
    }

    #[test]
    fn test_subscriber_list_touch() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));

        // Touch updates last_active_ns
        assert!(list.touch(1, 5_000_000_000));

        let subscriber = list.find(1).unwrap();
        assert_eq!(subscriber.last_active_ns(), 5_000_000_000);
    }

    #[test]
    fn test_subscriber_list_touch_not_found() {
        let list = SubscriberList::new(5_000_000_000);
        assert!(!list.touch(999, 5_000_000_000));
    }

    #[test]
    fn test_subscriber_list_find() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));

        let found = list.find(1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), 1);

        let not_found = list.find(999);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_subscriber_list_clone() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));
        list.add(Subscriber::new(2, 101, addr));

        let cloned = list.clone();

        assert_eq!(cloned.len(), 2);
        assert_eq!(cloned.counts(), (2, 0));
        assert_eq!(cloned.cold_timeout_ns(), 5_000_000_000);

        // Stats should be fresh in cloned list
        let stats = cloned.stats().snapshot();
        assert_eq!(stats.subscribers_added, 0);
    }

    #[test]
    fn test_subscriber_list_iter_all() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));
        list.add(Subscriber::with_time(2, 101, addr, 10_000_000_000));

        // Demote subscriber 1
        list.demote_inactive(10_000_000_000);

        // iter_all should return both
        let all_ids: Vec<u32> = list.iter_all().map(|s| s.id()).collect();
        assert_eq!(all_ids.len(), 2);
        assert!(all_ids.contains(&1));
        assert!(all_ids.contains(&2));
    }

    #[test]
    fn test_subscriber_list_stats() {
        let mut list = SubscriberList::new(5_000_000_000);
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();

        // Add subscribers
        list.add(Subscriber::with_time(1, 100, addr, 1_000_000_000));
        list.add(Subscriber::with_time(2, 101, addr, 1_000_000_000));

        // Demote
        list.demote_inactive(10_000_000_000);

        // Promote one back
        list.promote_to_hot(1);

        // Remove one
        list.remove(2);

        let stats = list.stats().snapshot();
        assert_eq!(stats.subscribers_added, 2);
        assert_eq!(stats.subscribers_removed, 1);
        assert_eq!(stats.demotions, 2);
        assert_eq!(stats.promotions, 1);
    }

    #[test]
    fn test_subscriber_list_stats_reset() {
        let stats = SubscriberListStats::new();
        stats.record_add();
        stats.record_promotion();

        stats.reset();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.subscribers_added, 0);
        assert_eq!(snapshot.promotions, 0);
    }
}
