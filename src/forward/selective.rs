//! Viewport-Based Selective Forwarding for Nexus SFU MVP.
//!
//! Provides viewport filtering to reduce unnecessary bandwidth usage by
//! forwarding packets only to subscribers who need them based on their
//! visible participants and pinned participants.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ViewportFilter                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  visible_participants: HashSet<u32>                         │
//! │  pinned_participants: HashSet<u32>                          │
//! │  priorities: HashMap<u32, u8>                               │
//! │                                                              │
//! │  should_forward(source_participant_id) -> bool              │
//! │       │                                                      │
//! │       ├─► Is source pinned? ──────────► YES ──► forward     │
//! │       │                                                      │
//! │       ├─► Is source in visible set? ──► YES ──► forward     │
//! │       │                                                      │
//! │       └─► Otherwise ──────────────────────────► skip        │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Requirements Coverage
//!
//! - Requirement 9.1: Store visible participant list on viewport update
//! - Requirement 9.2: Check if source is in subscriber's viewport
//! - Requirement 9.3: Skip forwarding if source not in viewport
//! - Requirement 9.4: Support priority levels for participants
//! - Requirement 9.5: Always forward pinned participants regardless of viewport
//! - Requirement 9.6: Track statistics for filtered vs forwarded

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of visible participants (TigerStyle: fixed bound).
pub const MAX_VISIBLE_PARTICIPANTS: usize = 1000;

/// Maximum priority level for participants.
pub const MAX_PRIORITY: u8 = 10;

/// Statistics for viewport filtering.
///
/// Tracks the number of packets forwarded vs filtered for monitoring.
#[derive(Debug, Default)]
pub struct ViewportFilterStats {
    /// Number of packets forwarded (passed filter).
    pub packets_forwarded: AtomicU64,
    /// Number of packets filtered (skipped).
    pub packets_filtered: AtomicU64,
    /// Number of packets forwarded due to pinned status.
    pub packets_forwarded_pinned: AtomicU64,
    /// Number of packets forwarded due to visible status.
    pub packets_forwarded_visible: AtomicU64,
}

impl ViewportFilterStats {
    /// Create new statistics with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a forwarded packet.
    #[inline(always)]
    pub fn record_forwarded(&self) {
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a filtered (skipped) packet.
    #[inline(always)]
    pub fn record_filtered(&self) {
        self.packets_filtered.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet forwarded due to pinned status.
    #[inline(always)]
    pub fn record_forwarded_pinned(&self) {
        self.packets_forwarded_pinned.fetch_add(1, Ordering::Relaxed);
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet forwarded due to visible status.
    #[inline(always)]
    pub fn record_forwarded_visible(&self) {
        self.packets_forwarded_visible.fetch_add(1, Ordering::Relaxed);
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> ViewportFilterStatsSnapshot {
        ViewportFilterStatsSnapshot {
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            packets_filtered: self.packets_filtered.load(Ordering::Relaxed),
            packets_forwarded_pinned: self.packets_forwarded_pinned.load(Ordering::Relaxed),
            packets_forwarded_visible: self.packets_forwarded_visible.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.packets_forwarded.store(0, Ordering::Relaxed);
        self.packets_filtered.store(0, Ordering::Relaxed);
        self.packets_forwarded_pinned.store(0, Ordering::Relaxed);
        self.packets_forwarded_visible.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of viewport filter statistics at a point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewportFilterStatsSnapshot {
    pub packets_forwarded: u64,
    pub packets_filtered: u64,
    pub packets_forwarded_pinned: u64,
    pub packets_forwarded_visible: u64,
}

// Implement Clone for ViewportFilterStats (atomics don't implement Clone)
impl Clone for ViewportFilterStats {
    fn clone(&self) -> Self {
        Self {
            packets_forwarded: AtomicU64::new(self.packets_forwarded.load(Ordering::Relaxed)),
            packets_filtered: AtomicU64::new(self.packets_filtered.load(Ordering::Relaxed)),
            packets_forwarded_pinned: AtomicU64::new(self.packets_forwarded_pinned.load(Ordering::Relaxed)),
            packets_forwarded_visible: AtomicU64::new(self.packets_forwarded_visible.load(Ordering::Relaxed)),
        }
    }
}

/// Viewport filter for selective forwarding.
///
/// Determines which packets should be forwarded to a subscriber based on
/// their viewport (visible participants), pinned participants, and priority
/// levels.
///
/// # Decision Logic
///
/// The `should_forward` method checks in order:
/// 1. Is source pinned? → forward
/// 2. Is source in visible set? → forward
/// 3. Otherwise → skip
///
/// # Thread Safety
///
/// This struct is designed to be used with copy-on-write semantics.
/// Updates should create a new filter and atomically swap it in.
///
/// # Example
///
/// ```
/// use nexus_sfu::forward::selective::ViewportFilter;
///
/// let mut filter = ViewportFilter::new();
///
/// // Set visible participants
/// filter.set_visible(&[1, 2, 3]);
///
/// // Pin a speaker
/// filter.pin(100);
///
/// // Set priority for important participant
/// filter.set_priority(1, 5);
///
/// // Check forwarding decisions
/// assert!(filter.should_forward(1));   // Visible
/// assert!(filter.should_forward(100)); // Pinned
/// assert!(!filter.should_forward(50)); // Not visible, not pinned
/// ```
#[derive(Debug, Clone)]
pub struct ViewportFilter {
    /// Set of visible participant IDs.
    visible_participants: HashSet<u32>,
    /// Pinned participants (always forward regardless of viewport).
    pinned_participants: HashSet<u32>,
    /// Priority levels for participants (0-10, higher = more important).
    priorities: HashMap<u32, u8>,
    /// Statistics for filtering decisions.
    stats: ViewportFilterStats,
}

impl Default for ViewportFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewportFilter {
    /// Create an empty viewport filter.
    pub fn new() -> Self {
        Self {
            visible_participants: HashSet::new(),
            pinned_participants: HashSet::new(),
            priorities: HashMap::new(),
            stats: ViewportFilterStats::new(),
        }
    }

    /// Update visible participants.
    ///
    /// Replaces the current visible set with the provided participants.
    ///
    /// # Arguments
    ///
    /// * `participants` - Slice of participant IDs that are visible
    ///
    /// # Assertions
    /// - participants.len() <= 1000
    ///
    /// # Requirements
    /// - Requirement 9.1: Store visible participant list on viewport update
    pub fn set_visible(&mut self, participants: &[u32]) {
        // TigerStyle: Assert preconditions
        assert!(
            participants.len() <= MAX_VISIBLE_PARTICIPANTS,
            "visible participants must not exceed {}, got {}",
            MAX_VISIBLE_PARTICIPANTS,
            participants.len()
        );

        self.visible_participants.clear();
        self.visible_participants.extend(participants.iter().copied());
    }

    /// Pin a participant (always forward their packets).
    ///
    /// Pinned participants have their packets forwarded regardless of
    /// whether they are in the visible set.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Participant ID to pin
    ///
    /// # Requirements
    /// - Requirement 9.5: Always forward pinned participants
    pub fn pin(&mut self, participant_id: u32) {
        self.pinned_participants.insert(participant_id);
    }

    /// Unpin a participant.
    ///
    /// After unpinning, the participant's packets will only be forwarded
    /// if they are in the visible set.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Participant ID to unpin
    pub fn unpin(&mut self, participant_id: u32) {
        self.pinned_participants.remove(&participant_id);
    }

    /// Set priority for a participant.
    ///
    /// Priority levels range from 0 (lowest) to 10 (highest).
    /// Higher priority participants may receive preferential treatment
    /// in bandwidth-constrained scenarios.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Participant ID
    /// * `priority` - Priority level (0-10)
    ///
    /// # Assertions
    /// - priority <= 10
    ///
    /// # Requirements
    /// - Requirement 9.4: Support priority levels for participants
    pub fn set_priority(&mut self, participant_id: u32, priority: u8) {
        // TigerStyle: Assert preconditions
        assert!(
            priority <= MAX_PRIORITY,
            "priority must not exceed {}, got {}",
            MAX_PRIORITY,
            priority
        );

        if priority == 0 {
            // Remove priority entry if set to 0 (default)
            self.priorities.remove(&participant_id);
        } else {
            self.priorities.insert(participant_id, priority);
        }
    }

    /// Check if packets from a source should be forwarded.
    ///
    /// Decision logic:
    /// 1. Is source pinned? → forward
    /// 2. Is source in visible set? → forward
    /// 3. Otherwise → skip
    ///
    /// This method also updates statistics for monitoring.
    ///
    /// # Arguments
    ///
    /// * `source_participant_id` - Participant ID of the packet source
    ///
    /// # Returns
    ///
    /// `true` if the packet should be forwarded, `false` otherwise.
    ///
    /// # Assertions
    /// - source_participant_id != 0
    ///
    /// # Requirements
    /// - Requirement 9.2: Check if source is in subscriber's viewport
    /// - Requirement 9.3: Skip forwarding if source not in viewport
    /// - Requirement 9.5: Always forward pinned participants
    /// - Requirement 9.6: Track statistics for filtered vs forwarded
    #[inline(always)]
    pub fn should_forward(&self, source_participant_id: u32) -> bool {
        // TigerStyle: Assert preconditions
        assert!(
            source_participant_id != 0,
            "source_participant_id must not be 0"
        );

        // Check pinned first (highest priority)
        if self.pinned_participants.contains(&source_participant_id) {
            self.stats.record_forwarded_pinned();
            return true;
        }

        // Check visible set
        if self.visible_participants.contains(&source_participant_id) {
            self.stats.record_forwarded_visible();
            return true;
        }

        // Not in viewport, skip
        self.stats.record_filtered();
        false
    }

    /// Check if packets from a source should be forwarded (without updating stats).
    ///
    /// Use this method when you need to check forwarding decision without
    /// affecting statistics (e.g., for testing or preview).
    ///
    /// # Arguments
    ///
    /// * `source_participant_id` - Participant ID of the packet source
    ///
    /// # Returns
    ///
    /// `true` if the packet should be forwarded, `false` otherwise.
    ///
    /// # Assertions
    /// - source_participant_id != 0
    #[inline(always)]
    pub fn should_forward_no_stats(&self, source_participant_id: u32) -> bool {
        // TigerStyle: Assert preconditions
        assert!(
            source_participant_id != 0,
            "source_participant_id must not be 0"
        );

        // Check pinned first
        if self.pinned_participants.contains(&source_participant_id) {
            return true;
        }

        // Check visible set
        self.visible_participants.contains(&source_participant_id)
    }

    /// Check if a participant is pinned.
    #[inline(always)]
    pub fn is_pinned(&self, participant_id: u32) -> bool {
        self.pinned_participants.contains(&participant_id)
    }

    /// Check if a participant is visible.
    #[inline(always)]
    pub fn is_visible(&self, participant_id: u32) -> bool {
        self.visible_participants.contains(&participant_id)
    }

    /// Get the priority for a participant.
    ///
    /// Returns 0 if no priority is set.
    #[inline(always)]
    pub fn get_priority(&self, participant_id: u32) -> u8 {
        self.priorities.get(&participant_id).copied().unwrap_or(0)
    }

    /// Get the number of visible participants.
    #[inline(always)]
    pub fn visible_count(&self) -> usize {
        self.visible_participants.len()
    }

    /// Get the number of pinned participants.
    #[inline(always)]
    pub fn pinned_count(&self) -> usize {
        self.pinned_participants.len()
    }

    /// Get the number of participants with priority set.
    #[inline(always)]
    pub fn priority_count(&self) -> usize {
        self.priorities.len()
    }

    /// Get a reference to the statistics.
    pub fn stats(&self) -> &ViewportFilterStats {
        &self.stats
    }

    /// Clear all viewport state.
    ///
    /// Resets visible participants, pinned participants, and priorities.
    /// Does not reset statistics.
    pub fn clear(&mut self) {
        self.visible_participants.clear();
        self.pinned_participants.clear();
        self.priorities.clear();
    }

    /// Clear all state including statistics.
    pub fn clear_all(&mut self) {
        self.clear();
        self.stats.reset();
    }

    /// Get all visible participant IDs.
    pub fn visible_participants(&self) -> impl Iterator<Item = &u32> {
        self.visible_participants.iter()
    }

    /// Get all pinned participant IDs.
    pub fn pinned_participants(&self) -> impl Iterator<Item = &u32> {
        self.pinned_participants.iter()
    }

    /// Get all participants with priorities.
    pub fn priorities(&self) -> impl Iterator<Item = (&u32, &u8)> {
        self.priorities.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === ViewportFilterStats Tests ===

    #[test]
    fn test_stats_new() {
        let stats = ViewportFilterStats::new();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 0);
        assert_eq!(snapshot.packets_filtered, 0);
        assert_eq!(snapshot.packets_forwarded_pinned, 0);
        assert_eq!(snapshot.packets_forwarded_visible, 0);
    }

    #[test]
    fn test_stats_record_forwarded() {
        let stats = ViewportFilterStats::new();
        stats.record_forwarded();
        stats.record_forwarded();
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 2);
    }

    #[test]
    fn test_stats_record_filtered() {
        let stats = ViewportFilterStats::new();
        stats.record_filtered();
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_filtered, 1);
    }

    #[test]
    fn test_stats_record_forwarded_pinned() {
        let stats = ViewportFilterStats::new();
        stats.record_forwarded_pinned();
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 1);
        assert_eq!(snapshot.packets_forwarded_pinned, 1);
    }

    #[test]
    fn test_stats_record_forwarded_visible() {
        let stats = ViewportFilterStats::new();
        stats.record_forwarded_visible();
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 1);
        assert_eq!(snapshot.packets_forwarded_visible, 1);
    }

    #[test]
    fn test_stats_reset() {
        let stats = ViewportFilterStats::new();
        stats.record_forwarded();
        stats.record_filtered();
        stats.record_forwarded_pinned();
        
        stats.reset();
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 0);
        assert_eq!(snapshot.packets_filtered, 0);
        assert_eq!(snapshot.packets_forwarded_pinned, 0);
        assert_eq!(snapshot.packets_forwarded_visible, 0);
    }

    // === ViewportFilter Tests ===

    #[test]
    fn test_viewport_filter_new() {
        let filter = ViewportFilter::new();
        assert_eq!(filter.visible_count(), 0);
        assert_eq!(filter.pinned_count(), 0);
        assert_eq!(filter.priority_count(), 0);
    }

    #[test]
    fn test_viewport_filter_default() {
        let filter = ViewportFilter::default();
        assert_eq!(filter.visible_count(), 0);
    }

    #[test]
    fn test_viewport_filter_set_visible() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3, 4, 5]);

        assert_eq!(filter.visible_count(), 5);
        assert!(filter.is_visible(1));
        assert!(filter.is_visible(2));
        assert!(filter.is_visible(3));
        assert!(filter.is_visible(4));
        assert!(filter.is_visible(5));
        assert!(!filter.is_visible(6));
    }

    #[test]
    fn test_viewport_filter_set_visible_replaces() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.set_visible(&[4, 5]);

        assert_eq!(filter.visible_count(), 2);
        assert!(!filter.is_visible(1));
        assert!(filter.is_visible(4));
        assert!(filter.is_visible(5));
    }

    #[test]
    fn test_viewport_filter_set_visible_empty() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.set_visible(&[]);

        assert_eq!(filter.visible_count(), 0);
    }

    #[test]
    #[should_panic(expected = "visible participants must not exceed 1000")]
    fn test_viewport_filter_set_visible_too_many() {
        let mut filter = ViewportFilter::new();
        let participants: Vec<u32> = (1..=1001).collect();
        filter.set_visible(&participants);
    }

    #[test]
    fn test_viewport_filter_pin() {
        let mut filter = ViewportFilter::new();
        
        filter.pin(100);
        assert!(filter.is_pinned(100));
        assert_eq!(filter.pinned_count(), 1);

        filter.pin(200);
        assert!(filter.is_pinned(200));
        assert_eq!(filter.pinned_count(), 2);
    }

    #[test]
    fn test_viewport_filter_unpin() {
        let mut filter = ViewportFilter::new();
        
        filter.pin(100);
        filter.pin(200);
        assert_eq!(filter.pinned_count(), 2);

        filter.unpin(100);
        assert!(!filter.is_pinned(100));
        assert!(filter.is_pinned(200));
        assert_eq!(filter.pinned_count(), 1);
    }

    #[test]
    fn test_viewport_filter_unpin_not_pinned() {
        let mut filter = ViewportFilter::new();
        filter.unpin(100); // Should not panic
        assert_eq!(filter.pinned_count(), 0);
    }

    #[test]
    fn test_viewport_filter_set_priority() {
        let mut filter = ViewportFilter::new();
        
        filter.set_priority(1, 5);
        assert_eq!(filter.get_priority(1), 5);
        assert_eq!(filter.priority_count(), 1);

        filter.set_priority(2, 10);
        assert_eq!(filter.get_priority(2), 10);
        assert_eq!(filter.priority_count(), 2);
    }

    #[test]
    fn test_viewport_filter_set_priority_zero_removes() {
        let mut filter = ViewportFilter::new();
        
        filter.set_priority(1, 5);
        assert_eq!(filter.priority_count(), 1);

        filter.set_priority(1, 0);
        assert_eq!(filter.get_priority(1), 0);
        assert_eq!(filter.priority_count(), 0);
    }

    #[test]
    fn test_viewport_filter_get_priority_default() {
        let filter = ViewportFilter::new();
        assert_eq!(filter.get_priority(999), 0);
    }

    #[test]
    #[should_panic(expected = "priority must not exceed 10")]
    fn test_viewport_filter_set_priority_too_high() {
        let mut filter = ViewportFilter::new();
        filter.set_priority(1, 11);
    }

    #[test]
    fn test_viewport_filter_should_forward_pinned() {
        let mut filter = ViewportFilter::new();
        filter.pin(100);

        // Pinned participant should be forwarded
        assert!(filter.should_forward(100));

        // Check stats
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 1);
        assert_eq!(stats.packets_forwarded_pinned, 1);
    }

    #[test]
    fn test_viewport_filter_should_forward_visible() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);

        // Visible participant should be forwarded
        assert!(filter.should_forward(1));
        assert!(filter.should_forward(2));

        // Check stats
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 2);
        assert_eq!(stats.packets_forwarded_visible, 2);
    }

    #[test]
    fn test_viewport_filter_should_forward_not_in_viewport() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);

        // Not visible, not pinned - should not be forwarded
        assert!(!filter.should_forward(50));

        // Check stats
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_filtered, 1);
    }

    #[test]
    fn test_viewport_filter_should_forward_pinned_takes_precedence() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(1); // Also pinned

        // Should be forwarded as pinned (not visible)
        assert!(filter.should_forward(1));

        // Check stats - should count as pinned
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded_pinned, 1);
        assert_eq!(stats.packets_forwarded_visible, 0);
    }

    #[test]
    #[should_panic(expected = "source_participant_id must not be 0")]
    fn test_viewport_filter_should_forward_zero_id() {
        let filter = ViewportFilter::new();
        let _ = filter.should_forward(0);
    }

    #[test]
    fn test_viewport_filter_should_forward_no_stats() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);

        // Check forwarding without updating stats
        assert!(filter.should_forward_no_stats(1));
        assert!(filter.should_forward_no_stats(100));
        assert!(!filter.should_forward_no_stats(50));

        // Stats should be unchanged
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 0);
        assert_eq!(stats.packets_filtered, 0);
    }

    #[test]
    #[should_panic(expected = "source_participant_id must not be 0")]
    fn test_viewport_filter_should_forward_no_stats_zero_id() {
        let filter = ViewportFilter::new();
        let _ = filter.should_forward_no_stats(0);
    }

    #[test]
    fn test_viewport_filter_clear() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);
        filter.set_priority(1, 5);

        filter.clear();

        assert_eq!(filter.visible_count(), 0);
        assert_eq!(filter.pinned_count(), 0);
        assert_eq!(filter.priority_count(), 0);
    }

    #[test]
    fn test_viewport_filter_clear_preserves_stats() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1]);
        let _ = filter.should_forward(1);

        filter.clear();

        // Stats should be preserved
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 1);
    }

    #[test]
    fn test_viewport_filter_clear_all() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1]);
        let _ = filter.should_forward(1);

        filter.clear_all();

        // Everything should be cleared including stats
        assert_eq!(filter.visible_count(), 0);
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 0);
    }

    #[test]
    fn test_viewport_filter_clone() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);
        filter.set_priority(1, 5);

        let cloned = filter.clone();

        assert_eq!(cloned.visible_count(), 3);
        assert_eq!(cloned.pinned_count(), 1);
        assert_eq!(cloned.priority_count(), 1);
        assert!(cloned.is_visible(1));
        assert!(cloned.is_pinned(100));
        assert_eq!(cloned.get_priority(1), 5);
    }

    #[test]
    fn test_viewport_filter_iterators() {
        let mut filter = ViewportFilter::new();
        filter.set_visible(&[1, 2, 3]);
        filter.pin(100);
        filter.pin(200);
        filter.set_priority(1, 5);
        filter.set_priority(2, 8);

        // Test visible_participants iterator
        let visible: Vec<u32> = filter.visible_participants().copied().collect();
        assert_eq!(visible.len(), 3);
        assert!(visible.contains(&1));
        assert!(visible.contains(&2));
        assert!(visible.contains(&3));

        // Test pinned_participants iterator
        let pinned: Vec<u32> = filter.pinned_participants().copied().collect();
        assert_eq!(pinned.len(), 2);
        assert!(pinned.contains(&100));
        assert!(pinned.contains(&200));

        // Test priorities iterator
        let priorities: Vec<(u32, u8)> = filter.priorities().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(priorities.len(), 2);
    }

    #[test]
    fn test_viewport_filter_complex_scenario() {
        let mut filter = ViewportFilter::new();
        
        // Set up a realistic scenario
        filter.set_visible(&[1, 2, 3, 4, 5]); // 5 visible participants
        filter.pin(100); // Speaker is pinned
        filter.set_priority(100, 10); // Speaker has highest priority
        filter.set_priority(1, 5); // Some visible participant has medium priority

        // Test forwarding decisions
        assert!(filter.should_forward(1));   // Visible
        assert!(filter.should_forward(100)); // Pinned
        assert!(!filter.should_forward(50)); // Not visible, not pinned

        // Verify stats
        let stats = filter.stats().snapshot();
        assert_eq!(stats.packets_forwarded, 2);
        assert_eq!(stats.packets_filtered, 1);
        assert_eq!(stats.packets_forwarded_pinned, 1);
        assert_eq!(stats.packets_forwarded_visible, 1);
    }

    #[test]
    fn test_viewport_filter_max_visible() {
        let mut filter = ViewportFilter::new();
        let participants: Vec<u32> = (1..=1000).collect();
        filter.set_visible(&participants);

        assert_eq!(filter.visible_count(), 1000);
        assert!(filter.is_visible(1));
        assert!(filter.is_visible(1000));
    }
}
