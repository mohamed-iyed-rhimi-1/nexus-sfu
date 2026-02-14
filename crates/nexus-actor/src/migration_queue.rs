//! Migration queue with fixed capacity
//!
//! Provides bounded queue for tracking concurrent migrations.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::*;

/// Migration request in queue
#[derive(Debug)]
pub struct MigrationRequest {
    /// Unique migration identifier
    pub migration_id: MigrationId,
    /// Track being migrated
    pub track_id: TrackId,
    /// Source worker
    pub source_worker_id: WorkerId,
    /// Target worker
    pub target_worker_id: WorkerId,
    /// Request timestamp (nanos since epoch)
    pub request_time: u64,
    /// Retry count
    pub retry_count: u32,
}

/// Migration queue with fixed capacity
pub struct MigrationQueue {
    /// Pending migrations (fixed-size array)
    requests: [Option<MigrationRequest>; MAX_CONCURRENT_MIGRATIONS],
    /// Number of active migrations
    count: u32,
    /// Next migration ID (monotonic counter)
    next_migration_id: AtomicU64,
}

impl MigrationQueue {
    /// Create new migration queue
    pub fn new() -> Self {
        Self {
            requests: std::array::from_fn(|_| None),
            count: 0,
            next_migration_id: AtomicU64::new(1),
        }
    }

    /// Enqueue migration request
    ///
    /// Returns migration_id on success, None if queue is full.
    ///
    /// # Assertions
    /// - count <= MAX_CONCURRENT_MIGRATIONS
    /// - track_id != 0
    /// - source_worker_id != target_worker_id
    pub fn enqueue(
        &mut self,
        track_id: TrackId,
        source_worker_id: WorkerId,
        target_worker_id: WorkerId,
    ) -> Option<MigrationId> {
        assert!(track_id != 0, "track_id must not be 0");
        assert_ne!(
            source_worker_id, target_worker_id,
            "source and target workers must differ"
        );
        assert!(
            self.count <= MAX_CONCURRENT_MIGRATIONS as u32,
            "migration queue count invariant violated"
        );

        if self.count >= MAX_CONCURRENT_MIGRATIONS as u32 {
            return None; // Queue full
        }

        // Find empty slot
        let slot_index = self.requests.iter().position(|r| r.is_none())?;

        let migration_id = self.next_migration_id.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        self.requests[slot_index] = Some(MigrationRequest {
            migration_id,
            track_id,
            source_worker_id,
            target_worker_id,
            request_time: now,
            retry_count: 0,
        });

        self.count += 1;

        // Assert postcondition
        assert!(self.count <= MAX_CONCURRENT_MIGRATIONS as u32);

        Some(migration_id)
    }

    /// Dequeue completed migration
    ///
    /// # Assertions
    /// - count > 0 when removing
    pub fn dequeue(&mut self, migration_id: MigrationId) -> bool {
        let slot_index = self.requests.iter().position(|r| {
            r.as_ref()
                .map(|req| req.migration_id == migration_id)
                .unwrap_or(false)
        });

        if let Some(index) = slot_index {
            self.requests[index] = None;
            assert!(self.count > 0, "migration queue underflow");
            self.count -= 1;
            true
        } else {
            false
        }
    }

    /// Get timed-out migrations
    ///
    /// Returns migrations older than timeout_nanos.
    ///
    /// # Loop Bound
    /// - Iterates up to MAX_CONCURRENT_MIGRATIONS
    pub fn get_timed_out(&self, timeout_nanos: u64) -> Vec<MigrationId> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut timed_out = Vec::with_capacity(MAX_CONCURRENT_MIGRATIONS);

        for req in self.requests.iter().flatten() {
            let elapsed = now.saturating_sub(req.request_time);
            if elapsed > timeout_nanos {
                timed_out.push(req.migration_id);
            }
        }

        timed_out
    }

    /// Get current queue count
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.count >= MAX_CONCURRENT_MIGRATIONS as u32
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get start time for a migration
    ///
    /// Returns the request_time (start timestamp in nanos) for the given migration_id.
    /// Returns None if migration_id is not found.
    ///
    /// # Loop Bound
    /// - Iterates up to MAX_CONCURRENT_MIGRATIONS
    pub fn get_start_time(&self, migration_id: MigrationId) -> Option<u64> {
        assert!(migration_id != 0, "migration_id must not be 0");

        for req in self.requests.iter().flatten() {
            if req.migration_id == migration_id {
                return Some(req.request_time);
            }
        }

        None
    }
}

impl Default for MigrationQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_queue_enqueue_dequeue() {
        let mut queue = MigrationQueue::new();

        let migration_id = queue.enqueue(1, 0, 1).unwrap();
        assert_eq!(queue.count(), 1);
        assert!(!queue.is_empty());

        assert!(queue.dequeue(migration_id));
        assert_eq!(queue.count(), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_migration_queue_capacity() {
        let mut queue = MigrationQueue::new();

        // Fill queue to capacity
        for i in 0..MAX_CONCURRENT_MIGRATIONS {
            let migration_id = queue.enqueue(i as u64 + 1, 0, 1);
            assert!(migration_id.is_some());
        }

        // Queue should be full
        assert_eq!(queue.count(), MAX_CONCURRENT_MIGRATIONS as u32);
        assert!(queue.is_full());

        // Next enqueue should fail
        let overflow = queue.enqueue(999, 0, 1);
        assert!(overflow.is_none());
    }

    #[test]
    fn test_migration_queue_timeout_detection() {
        let mut queue = MigrationQueue::new();

        // Enqueue migration
        let migration_id = queue.enqueue(1, 0, 1).unwrap();

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(100));

        let timeout_nanos = 50_000_000; // 50ms
        let timed_out = queue.get_timed_out(timeout_nanos);

        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], migration_id);
    }

    #[test]
    #[should_panic(expected = "track_id must not be 0")]
    fn test_migration_queue_invalid_track_id() {
        let mut queue = MigrationQueue::new();
        let _ = queue.enqueue(0, 0, 1);
    }

    #[test]
    #[should_panic(expected = "source and target workers must differ")]
    fn test_migration_queue_same_worker() {
        let mut queue = MigrationQueue::new();
        let _ = queue.enqueue(1, 0, 0);
    }

    #[test]
    fn test_migration_queue_get_start_time() {
        let mut queue = MigrationQueue::new();

        // Enqueue migration
        let migration_id = queue.enqueue(1, 0, 1).unwrap();

        // Get start time should return Some
        let start_time = queue.get_start_time(migration_id);
        assert!(start_time.is_some());

        // Start time should be recent (within last second)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let elapsed = now.saturating_sub(start_time.unwrap());
        assert!(elapsed < 1_000_000_000); // Less than 1 second

        // Non-existent migration_id should return None
        let non_existent = queue.get_start_time(999);
        assert!(non_existent.is_none());

        // After dequeue, start time should return None
        queue.dequeue(migration_id);
        let after_dequeue = queue.get_start_time(migration_id);
        assert!(after_dequeue.is_none());
    }
}
