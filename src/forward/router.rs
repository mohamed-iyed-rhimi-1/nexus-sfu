//! SSRC Router Implementation for Nexus SFU MVP.
//!
//! Provides O(1) lookup of tracks by SSRC using a lock-free hash map.
//! This enables efficient packet routing without locks on the hot path.
//!
//! # Design Decisions
//!
//! - **DashMap**: Lock-free concurrent hash map for O(1) lookups
//! - **Collision Detection**: Rejects duplicate SSRC registrations
//! - **Atomic Track ID**: Thread-safe track ID generation

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::types::{Ssrc, TrackId};

/// SSRC router errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrcError {
    /// SSRC already registered.
    AlreadyExists { ssrc: Ssrc },
    /// SSRC not found.
    NotFound { ssrc: Ssrc },
}

impl std::fmt::Display for SsrcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrcError::AlreadyExists { ssrc } => {
                write!(f, "SSRC {} already exists", ssrc)
            }
            SsrcError::NotFound { ssrc } => {
                write!(f, "SSRC {} not found", ssrc)
            }
        }
    }
}

impl std::error::Error for SsrcError {}

/// SSRC to track routing table.
///
/// Provides O(1) lookup of tracks by SSRC using a lock-free hash map.
/// Each SSRC maps to a (track_id, worker_id) tuple for efficient routing.
///
/// # Thread Safety
///
/// All operations are thread-safe and lock-free for reads. Writes use
/// fine-grained locking per bucket (DashMap implementation).
///
/// # Example
///
/// ```
/// use nexus_sfu::forward::SsrcRouter;
///
/// let router = SsrcRouter::new();
///
/// // Register a new SSRC
/// router.register(12345, 1, 0).unwrap();
///
/// // Lookup returns (track_id, worker_id)
/// let result = router.lookup(12345);
/// assert_eq!(result, Some((1, 0)));
///
/// // Unregister when done
/// router.unregister(12345);
/// assert!(router.lookup(12345).is_none());
/// ```
pub struct SsrcRouter {
    /// Lock-free hash map: SSRC -> (track_id, worker_id).
    routes: DashMap<Ssrc, (TrackId, u32)>,
    /// Next track ID for auto-generation.
    next_track_id: AtomicU64,
}

impl SsrcRouter {
    /// Create a new empty SSRC router.
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
            next_track_id: AtomicU64::new(1),
        }
    }

    /// Create a new SSRC router with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity hint for the hash map
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            routes: DashMap::with_capacity(capacity),
            next_track_id: AtomicU64::new(1),
        }
    }

    /// Lookup a track by SSRC.
    ///
    /// Returns the (track_id, worker_id) tuple if found.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC to look up
    ///
    /// # Returns
    ///
    /// `Some((track_id, worker_id))` if found, `None` otherwise.
    ///
    /// # Assertions
    /// - ssrc != 0
    #[inline(always)]
    pub fn lookup(&self, ssrc: Ssrc) -> Option<(TrackId, u32)> {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0");

        self.routes.get(&ssrc).map(|entry| *entry.value())
    }

    /// Lookup worker by track ID.
    ///
    /// Returns the (ssrc, worker_id) tuple if found.
    /// This is a reverse lookup that scans all entries.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to look up
    ///
    /// # Returns
    ///
    /// `Some((ssrc, worker_id))` if found, `None` otherwise.
    ///
    /// # Assertions
    /// - track_id != 0
    ///
    /// # Performance
    ///
    /// O(n) scan of all entries. Use sparingly.
    #[inline]
    pub fn lookup_by_track(&self, track_id: TrackId) -> Option<(Ssrc, u32)> {
        // TigerStyle: Assert preconditions
        assert!(track_id != 0, "track_id must not be 0");

        // Scan all entries to find matching track_id
        self.routes
            .iter()
            .find(|entry| entry.value().0 == track_id)
            .map(|entry| (*entry.key(), entry.value().1))
    }

    /// Lookup SSRC by track ID.
    ///
    /// Returns just the SSRC for a given track ID.
    /// This is a convenience method that wraps lookup_by_track.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to look up
    ///
    /// # Returns
    ///
    /// `Some(ssrc)` if found, `None` otherwise.
    ///
    /// # Assertions
    /// - track_id != 0
    ///
    /// # Performance
    ///
    /// O(n) scan of all entries. Use sparingly.
    #[inline]
    pub fn lookup_ssrc_by_track(&self, track_id: TrackId) -> Option<Ssrc> {
        self.lookup_by_track(track_id).map(|(ssrc, _)| ssrc)
    }

    /// Register a new SSRC mapping.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC to register
    /// * `track_id` - Track ID to map to
    /// * `worker_id` - Worker ID that owns the track
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(SsrcError::AlreadyExists)` if SSRC is already registered.
    ///
    /// # Assertions
    /// - ssrc != 0
    /// - track_id != 0
    pub fn register(&self, ssrc: Ssrc, track_id: TrackId, worker_id: u32) -> Result<(), SsrcError> {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0");
        assert!(track_id != 0, "track_id must not be 0");

        // Check for collision
        if self.routes.contains_key(&ssrc) {
            return Err(SsrcError::AlreadyExists { ssrc });
        }

        // Insert the mapping
        // Note: There's a small race window here, but DashMap handles it gracefully
        self.routes.insert(ssrc, (track_id, worker_id));

        Ok(())
    }

    /// Register a new SSRC with auto-generated track ID.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC to register
    /// * `worker_id` - Worker ID that owns the track
    ///
    /// # Returns
    ///
    /// `Ok(track_id)` on success with the generated track ID,
    /// `Err(SsrcError::AlreadyExists)` if SSRC is already registered.
    ///
    /// # Assertions
    /// - ssrc != 0
    pub fn register_auto(&self, ssrc: Ssrc, worker_id: u32) -> Result<TrackId, SsrcError> {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0");

        // Check for collision first
        if self.routes.contains_key(&ssrc) {
            return Err(SsrcError::AlreadyExists { ssrc });
        }

        // Generate track ID
        let track_id = self.next_track_id.fetch_add(1, Ordering::Relaxed);

        // Insert the mapping
        self.routes.insert(ssrc, (track_id, worker_id));

        Ok(track_id)
    }

    /// Unregister an SSRC mapping.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC to unregister
    ///
    /// # Returns
    ///
    /// The removed (track_id, worker_id) tuple if found.
    pub fn unregister(&self, ssrc: Ssrc) -> Option<(TrackId, u32)> {
        self.routes.remove(&ssrc).map(|(_, v)| v)
    }

    /// Check if an SSRC is registered.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC to check
    ///
    /// # Returns
    ///
    /// `true` if registered, `false` otherwise.
    #[inline(always)]
    pub fn contains(&self, ssrc: Ssrc) -> bool {
        self.routes.contains_key(&ssrc)
    }

    /// Get the number of registered SSRCs.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Check if the router is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Clear all SSRC mappings.
    pub fn clear(&self) {
        self.routes.clear();
    }

    /// Get an iterator over all registered SSRCs.
    ///
    /// Note: This creates a snapshot and may not reflect concurrent modifications.
    pub fn iter(&self) -> impl Iterator<Item = (Ssrc, TrackId, u32)> + '_ {
        self.routes.iter().map(|entry| {
            let ssrc = *entry.key();
            let (track_id, worker_id) = *entry.value();
            (ssrc, track_id, worker_id)
        })
    }

    /// Get all SSRCs for a specific worker.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - Worker ID to filter by
    ///
    /// # Returns
    ///
    /// Vector of (ssrc, track_id) tuples for worker.
    pub fn ssrcs_for_worker(&self, worker_id: u32) -> Vec<(Ssrc, TrackId)> {
        self.routes
            .iter()
            .filter(|entry| entry.value().1 == worker_id)
            .map(|entry| (*entry.key(), entry.value().0))
            .collect()
    }

    /// Get next track ID that will be assigned.
    ///
    /// Note: This is for debugging/testing only. The actual ID may differ
    /// due to concurrent access.
    pub fn peek_next_track_id(&self) -> TrackId {
        self.next_track_id.load(Ordering::Relaxed)
    }

    /// Remove all SSRC entries that map to the given track_id.
    ///
    /// Returns the number of entries removed.
    ///
    /// # Assertions
    /// - track_id must be non-zero
    pub fn remove_by_track(&self, track_id: TrackId) -> u32 {
        assert!(track_id != 0, "track_id must be non-zero");

        let mut removed: u32 = 0;
        self.routes.retain(|_ssrc, &mut (tid, _wid)| {
            if tid == track_id {
                removed += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        removed
    }

    /// Remove a single SSRC entry.
    ///
    /// Returns true if the entry was found and removed.
    ///
    /// # Assertions
    /// - ssrc must be non-zero
    pub fn remove(&self, ssrc: Ssrc) -> bool {
        assert!(ssrc != 0, "ssrc must be non-zero");
        self.routes.remove(&ssrc).is_some()
    }
}

impl Default for SsrcRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrc_router_new() {
        let router = SsrcRouter::new();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
    }

    #[test]
    fn test_ssrc_router_with_capacity() {
        let router = SsrcRouter::with_capacity(100);
        assert!(router.is_empty());
    }

    #[test]
    fn test_ssrc_router_register_lookup() {
        let router = SsrcRouter::new();

        // Register
        let result = router.register(12345, 1, 0);
        assert!(result.is_ok());
        assert_eq!(router.len(), 1);

        // Lookup
        let lookup = router.lookup(12345);
        assert_eq!(lookup, Some((1, 0)));
    }

    #[test]
    fn test_ssrc_router_register_collision() {
        let router = SsrcRouter::new();

        // First registration succeeds
        assert!(router.register(12345, 1, 0).is_ok());

        // Second registration fails
        let result = router.register(12345, 2, 1);
        assert_eq!(result, Err(SsrcError::AlreadyExists { ssrc: 12345 }));
    }

    #[test]
    fn test_ssrc_router_register_auto() {
        let router = SsrcRouter::new();

        // Auto-register generates track IDs
        let track_id1 = router.register_auto(12345, 0).unwrap();
        let track_id2 = router.register_auto(12346, 1).unwrap();

        assert_eq!(track_id1, 1);
        assert_eq!(track_id2, 2);

        // Verify lookups
        assert_eq!(router.lookup(12345), Some((1, 0)));
        assert_eq!(router.lookup(12346), Some((2, 1)));
    }

    #[test]
    fn test_ssrc_router_unregister() {
        let router = SsrcRouter::new();

        router.register(12345, 1, 0).unwrap();
        assert_eq!(router.len(), 1);

        // Unregister
        let removed = router.unregister(12345);
        assert_eq!(removed, Some((1, 0)));
        assert!(router.is_empty());

        // Lookup should fail
        assert!(router.lookup(12345).is_none());

        // Unregister non-existent
        let removed2 = router.unregister(99999);
        assert!(removed2.is_none());
    }

    #[test]
    fn test_ssrc_router_contains() {
        let router = SsrcRouter::new();

        assert!(!router.contains(12345));

        router.register(12345, 1, 0).unwrap();
        assert!(router.contains(12345));

        router.unregister(12345);
        assert!(!router.contains(12345));
    }

    #[test]
    fn test_ssrc_router_clear() {
        let router = SsrcRouter::new();

        router.register(12345, 1, 0).unwrap();
        router.register(12346, 2, 1).unwrap();
        router.register(12347, 3, 0).unwrap();

        assert_eq!(router.len(), 3);

        router.clear();
        assert!(router.is_empty());
    }

    #[test]
    fn test_ssrc_router_iter() {
        let router = SsrcRouter::new();

        router.register(12345, 1, 0).unwrap();
        router.register(12346, 2, 1).unwrap();

        let entries: Vec<_> = router.iter().collect();
        assert_eq!(entries.len(), 2);

        // Check both entries exist (order not guaranteed)
        assert!(entries.contains(&(12345, 1, 0)));
        assert!(entries.contains(&(12346, 2, 1)));
    }

    #[test]
    fn test_ssrc_router_ssrcs_for_worker() {
        let router = SsrcRouter::new();

        router.register(12345, 1, 0).unwrap();
        router.register(12346, 2, 1).unwrap();
        router.register(12347, 3, 0).unwrap();
        router.register(12348, 4, 1).unwrap();

        let worker0_ssrcs = router.ssrcs_for_worker(0);
        assert_eq!(worker0_ssrcs.len(), 2);
        assert!(worker0_ssrcs.contains(&(12345, 1)));
        assert!(worker0_ssrcs.contains(&(12347, 3)));

        let worker1_ssrcs = router.ssrcs_for_worker(1);
        assert_eq!(worker1_ssrcs.len(), 2);
        assert!(worker1_ssrcs.contains(&(12346, 2)));
        assert!(worker1_ssrcs.contains(&(12348, 4)));

        let worker2_ssrcs = router.ssrcs_for_worker(2);
        assert!(worker2_ssrcs.is_empty());
    }

    #[test]
    #[should_panic(expected = "ssrc must not be 0")]
    fn test_ssrc_router_lookup_zero_ssrc() {
        let router = SsrcRouter::new();
        let _ = router.lookup(0);
    }

    #[test]
    #[should_panic(expected = "ssrc must not be 0")]
    fn test_ssrc_router_register_zero_ssrc() {
        let router = SsrcRouter::new();
        let _ = router.register(0, 1, 0);
    }

    #[test]
    #[should_panic(expected = "track_id must not be 0")]
    fn test_ssrc_router_register_zero_track_id() {
        let router = SsrcRouter::new();
        let _ = router.register(12345, 0, 0);
    }

    #[test]
    fn test_ssrc_router_lookup_not_found() {
        let router = SsrcRouter::new();
        assert!(router.lookup(12345).is_none());
    }

    #[test]
    fn test_ssrc_error_display() {
        let err = SsrcError::AlreadyExists { ssrc: 12345 };
        assert!(err.to_string().contains("12345"));
        assert!(err.to_string().contains("already exists"));

        let err = SsrcError::NotFound { ssrc: 67890 };
        assert!(err.to_string().contains("67890"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_ssrc_router_multiple_workers() {
        let router = SsrcRouter::new();

        // Register SSRCs across multiple workers
        for i in 1..=100 {
            let ssrc = 10000 + i;
            let worker_id = (i % 4) as u32;
            router.register(ssrc, i as u64, worker_id).unwrap();
        }

        assert_eq!(router.len(), 100);

        // Verify distribution
        for worker_id in 0..4 {
            let count = router.ssrcs_for_worker(worker_id).len();
            assert!(
                count >= 20 && count <= 30,
                "worker {} has {} SSRCs",
                worker_id,
                count
            );
        }
    }

    #[test]
    fn test_ssrc_router_remove_by_track() {
        let router = SsrcRouter::new();

        // Register multiple SSRCs for the same track
        router.register(12345, 100, 0).unwrap();
        router.register(12346, 100, 0).unwrap();
        router.register(12347, 200, 1).unwrap();
        router.register(12348, 100, 2).unwrap();

        assert_eq!(router.len(), 4);

        // Remove all SSRCs for track 100
        let removed = router.remove_by_track(100);
        assert_eq!(removed, 3);
        assert_eq!(router.len(), 1);

        // Verify only track 200 remains
        assert!(router.lookup(12347).is_some());
        assert!(router.lookup(12345).is_none());
        assert!(router.lookup(12346).is_none());
        assert!(router.lookup(12348).is_none());

        // Remove non-existent track
        let removed2 = router.remove_by_track(999);
        assert_eq!(removed2, 0);
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn test_ssrc_router_remove() {
        let router = SsrcRouter::new();

        router.register(12345, 100, 0).unwrap();
        router.register(12346, 200, 1).unwrap();

        assert_eq!(router.len(), 2);

        // Remove existing SSRC
        let removed = router.remove(12345);
        assert!(removed);
        assert_eq!(router.len(), 1);
        assert!(router.lookup(12345).is_none());

        // Remove non-existent SSRC
        let removed2 = router.remove(99999);
        assert!(!removed2);
        assert_eq!(router.len(), 1);
    }

    #[test]
    #[should_panic(expected = "track_id must be non-zero")]
    fn test_ssrc_router_remove_by_track_zero() {
        let router = SsrcRouter::new();
        router.remove_by_track(0);
    }

    #[test]
    #[should_panic(expected = "ssrc must be non-zero")]
    fn test_ssrc_router_remove_zero() {
        let router = SsrcRouter::new();
        router.remove(0);
    }

    #[test]
    fn test_ssrc_router_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let router = Arc::new(SsrcRouter::new());
        let mut handles = vec![];

        // Spawn multiple threads to register SSRCs
        for t in 0..4 {
            let router_clone = Arc::clone(&router);
            let handle = thread::spawn(move || {
                for i in 0..25 {
                    let ssrc = (t * 1000 + i + 1) as u32;
                    let track_id = (t * 100 + i + 1) as u64;
                    let _ = router_clone.register(ssrc, track_id, t as u32);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all registrations
        assert_eq!(router.len(), 100);
    }
}
