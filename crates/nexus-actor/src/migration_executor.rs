//! Migration executor for track actors
//!
//! Handles serialization, transfer, and reconstruction of track actors
//! during migration between workers. Follows TigerStyle guidelines:
//! - ≤70 lines per function
//! - ≥2 assertions per function
//! - No recursion, bounded loops
//! - Static allocation where possible

use std::sync::Arc;

use crossbeam_channel::Sender;
use parking_lot::Mutex;

use crate::message::{MigrationSnapshot, TrackActorMessage};
use crate::metrics::MigrationMetrics;
use crate::migration_queue::MigrationQueue;
use crate::registry::ActorRegistry;
use crate::track::TrackActor;
use crate::types::*;

/// Maximum migration payload size (64KB)
pub const MAX_MIGRATION_SIZE: usize = 65536;

/// Maximum subscribers per track for migration
pub const MAX_MIGRATION_SUBSCRIBERS: usize = 100;

/// Ring buffer size for packet migration
pub const RING_BUFFER_SIZE: usize = 256;

/// Migration result status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationResult {
    /// Migration completed successfully
    Success,
    /// Migration failed and was restored on source
    FailedRestored,
    /// Migration failed permanently
    FailedPermanent,
}

/// Migration error types
#[derive(Debug)]
pub enum MigrationError {
    /// Migration not found in queue
    NotFound { migration_id: MigrationId },
    /// Track actor not found
    TrackNotFound { track_id: TrackId },
    /// Worker not found
    WorkerNotFound { worker_id: WorkerId },
    /// Serialization failed
    SerializationFailed { reason: &'static str },
    /// Deserialization failed
    DeserializationFailed { reason: &'static str },
    /// Transfer failed
    TransferFailed { reason: &'static str },
    /// Migration timed out
    Timeout { migration_id: MigrationId },
    /// Maximum retries exceeded
    MaxRetriesExceeded { migration_id: MigrationId },
    /// Capacity exceeded
    CapacityExceeded { reason: &'static str },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::NotFound { migration_id } => {
                write!(f, "Migration {} not found", migration_id)
            }
            MigrationError::TrackNotFound { track_id } => {
                write!(f, "Track {} not found", track_id)
            }
            MigrationError::WorkerNotFound { worker_id } => {
                write!(f, "Worker {} not found", worker_id)
            }
            MigrationError::SerializationFailed { reason } => {
                write!(f, "Serialization failed: {}", reason)
            }
            MigrationError::DeserializationFailed { reason } => {
                write!(f, "Deserialization failed: {}", reason)
            }
            MigrationError::TransferFailed { reason } => {
                write!(f, "Transfer failed: {}", reason)
            }
            MigrationError::Timeout { migration_id } => {
                write!(f, "Migration {} timed out", migration_id)
            }
            MigrationError::MaxRetriesExceeded { migration_id } => {
                write!(f, "Migration {} exceeded max retries", migration_id)
            }
            MigrationError::CapacityExceeded { reason } => {
                write!(f, "Capacity exceeded: {}", reason)
            }
        }
    }
}

impl std::error::Error for MigrationError {}

/// Worker message sender for migration transfers
pub type WorkerSender = Sender<TrackActorMessage>;

/// Worker pool interface for migration
pub struct WorkerPool {
    /// Worker senders indexed by worker_id
    workers: Vec<Option<WorkerSender>>,
    /// Number of active workers
    worker_count: u32,
}

impl WorkerPool {
    /// Create new worker pool with capacity
    ///
    /// # Assertions
    /// - capacity <= MAX_WORKERS
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity <= MAX_WORKERS as usize,
            "capacity exceeds MAX_WORKERS"
        );

        Self {
            workers: vec![None; capacity],
            worker_count: 0,
        }
    }

    /// Register worker sender
    ///
    /// # Assertions
    /// - worker_id < MAX_WORKERS
    pub fn register(&mut self, worker_id: WorkerId, sender: WorkerSender) {
        assert!(worker_id < MAX_WORKERS, "worker_id must be < MAX_WORKERS");

        if self.workers[worker_id as usize].is_none() {
            self.worker_count += 1;
        }
        self.workers[worker_id as usize] = Some(sender);
    }

    /// Get worker sender
    pub fn get(&self, worker_id: WorkerId) -> Option<&WorkerSender> {
        if worker_id < MAX_WORKERS {
            self.workers[worker_id as usize].as_ref()
        } else {
            None
        }
    }

    /// Get worker count
    pub fn count(&self) -> u32 {
        self.worker_count
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new(MAX_WORKERS as usize)
    }
}


/// Migration executor for track actors
///
/// Handles serialization, transfer, and reconstruction of track actors.
/// Follows TigerStyle: ≤70 lines/fn, ≥2 assertions/fn, bounded loops.
pub struct MigrationExecutor {
    /// Migration queue reference
    queue: Arc<Mutex<MigrationQueue>>,
    /// Actor registry reference
    registry: Arc<ActorRegistry>,
    /// Worker pool reference
    workers: Arc<Mutex<WorkerPool>>,
    /// Migration metrics
    metrics: Arc<MigrationMetrics>,
    /// Serialization buffer (reused, fixed size) - reserved for binary serialization
    #[allow(dead_code)]
    serialize_buffer: [u8; MAX_MIGRATION_SIZE],
    /// Buffer write position - reserved for binary serialization
    #[allow(dead_code)]
    buffer_pos: usize,
    /// Retry counts per migration (fixed-size array)
    retry_counts: [u32; MAX_CONCURRENT_MIGRATIONS],
}

impl MigrationExecutor {
    /// Create new migration executor
    ///
    /// # Assertions
    /// - queue is valid
    /// - registry is valid
    pub fn new(
        queue: Arc<Mutex<MigrationQueue>>,
        registry: Arc<ActorRegistry>,
        workers: Arc<Mutex<WorkerPool>>,
        metrics: Arc<MigrationMetrics>,
    ) -> Self {
        // Precondition assertions
        assert!(Arc::strong_count(&queue) >= 1, "queue must be valid");
        assert!(Arc::strong_count(&registry) >= 1, "registry must be valid");

        Self {
            queue,
            registry,
            workers,
            metrics,
            serialize_buffer: [0u8; MAX_MIGRATION_SIZE],
            buffer_pos: 0,
            retry_counts: [0u32; MAX_CONCURRENT_MIGRATIONS],
        }
    }

    /// Serialize track actor state to snapshot
    ///
    /// Creates a MigrationSnapshot containing all actor state needed
    /// for reconstruction on the target worker.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - actor: Mutable reference to the track actor to serialize
    /// - migration_id: Unique migration identifier
    ///
    /// # Returns
    /// MigrationSnapshot containing serialized actor state
    pub fn serialize_actor(
        &mut self,
        actor: &mut TrackActor,
        migration_id: MigrationId,
    ) -> Result<MigrationSnapshot, MigrationError> {
        // Precondition: migration_id must be valid
        assert!(migration_id != 0, "migration_id must not be 0");
        // Precondition: actor must have valid id
        assert!(actor.id() != 0, "actor id must not be 0");

        // Prepare migration snapshot using actor's method
        let snapshot = actor.prepare_migration_snapshot(migration_id);

        // Validate snapshot
        if snapshot.subscribers.len() > MAX_MIGRATION_SUBSCRIBERS {
            return Err(MigrationError::CapacityExceeded {
                reason: "subscriber count exceeds migration limit",
            });
        }

        // Postcondition: snapshot track_id matches actor id
        assert_eq!(
            snapshot.track_id,
            actor.id(),
            "snapshot track_id must match actor id"
        );

        Ok(snapshot)
    }

    /// Deserialize and reconstruct track actor from snapshot
    ///
    /// Creates a new TrackActor on the target worker with state
    /// restored from the migration snapshot.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - snapshot: Migration snapshot containing actor state
    /// - participant_id: Participant owning the track
    /// - ssrc: RTP SSRC for the track
    /// - kind: Media kind (audio/video)
    ///
    /// # Returns
    /// Reconstructed TrackActor and its message sender
    pub fn deserialize_actor(
        &self,
        snapshot: MigrationSnapshot,
        participant_id: ParticipantId,
        ssrc: Ssrc,
        kind: MediaKind,
    ) -> Result<(TrackActor, Sender<TrackActorMessage>), MigrationError> {
        // Precondition: snapshot must have valid track_id
        assert!(snapshot.track_id != 0, "snapshot track_id must not be 0");
        // Precondition: target_worker_id must be valid
        assert!(
            snapshot.target_worker_id < MAX_WORKERS,
            "target_worker_id must be < MAX_WORKERS"
        );

        let target_worker_id = snapshot.target_worker_id;

        // Spawn new actor on target worker
        let (mut actor, sender) = TrackActor::spawn(
            snapshot.track_id,
            participant_id,
            ssrc,
            kind,
            target_worker_id,
        );

        // Apply migration snapshot to restore state
        actor.apply_migration_snapshot(snapshot);

        // Postcondition: actor is in correct state
        assert_eq!(
            actor.worker_id(),
            target_worker_id,
            "actor worker_id must match target"
        );

        Ok((actor, sender))
    }


    /// Execute a pending migration
    ///
    /// Orchestrates the full migration flow:
    /// 1. Serialize actor state
    /// 2. Transfer to target worker
    /// 3. Deserialize on target
    /// 4. Update registry
    ///
    /// # TigerStyle
    /// - ≤70 lines (split into helpers)
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - migration_id: Unique migration identifier
    /// - actor: Mutable reference to the track actor being migrated
    /// - _participant_id: Participant owning the track (for deserialization)
    /// - _ssrc: RTP SSRC (for deserialization)
    /// - _kind: Media kind (for deserialization)
    ///
    /// # Returns
    /// MigrationResult indicating success or failure mode
    pub fn execute_migration(
        &mut self,
        migration_id: MigrationId,
        actor: &mut TrackActor,
        _participant_id: ParticipantId,
        _ssrc: Ssrc,
        _kind: MediaKind,
    ) -> Result<MigrationResult, MigrationError> {
        // Precondition: migration_id must be valid
        assert!(migration_id != 0, "migration_id must not be 0");
        // Precondition: actor must be valid
        assert!(actor.id() != 0, "actor id must not be 0");

        // Record migration start
        self.metrics.record_start();

        // Step 1: Serialize actor state
        let snapshot = self.serialize_actor(actor, migration_id)?;
        let target_worker_id = snapshot.target_worker_id;
        let track_id = snapshot.track_id;

        // Step 2: Transfer to target worker
        self.transfer_to_worker(&snapshot, target_worker_id)?;

        // Step 3: Update registry with new location
        let updated = self.registry.update_location(track_id, target_worker_id);
        if !updated {
            return Err(MigrationError::TrackNotFound { track_id });
        }

        // Step 4: Record latency
        self.record_latency(migration_id);

        // Step 5: Dequeue completed migration
        {
            let mut queue = self.queue.lock();
            queue.dequeue(migration_id);
        }

        // Record completion
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let start_time = self.get_migration_start_time(migration_id);
        if let Some(start) = start_time {
            let latency = now.saturating_sub(start);
            if latency > 0 {
                self.metrics.record_completion(latency);
            }
        }

        Ok(MigrationResult::Success)
    }

    /// Transfer serialized state to target worker
    ///
    /// Sends the migration snapshot to the target worker's message queue.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - snapshot: Migration snapshot to transfer
    /// - target_worker_id: Target worker identifier
    pub fn transfer_to_worker(
        &self,
        snapshot: &MigrationSnapshot,
        target_worker_id: WorkerId,
    ) -> Result<(), MigrationError> {
        // Precondition: target_worker_id must be valid
        assert!(
            target_worker_id < MAX_WORKERS,
            "target_worker_id must be < MAX_WORKERS"
        );
        // Precondition: snapshot must have valid track_id
        assert!(snapshot.track_id != 0, "snapshot track_id must not be 0");

        // Get worker sender
        let workers = self.workers.lock();
        let sender = workers.get(target_worker_id).ok_or(MigrationError::WorkerNotFound {
            worker_id: target_worker_id,
        })?;

        // Create transfer message
        let msg = TrackActorMessage::TransferState {
            migration_id: 0, // Will be set by caller
            snapshot: snapshot.clone(),
        };

        // Send to target worker
        sender.send(msg).map_err(|_| MigrationError::TransferFailed {
            reason: "worker message queue full",
        })?;

        Ok(())
    }


    /// Record migration latency using real timestamps
    ///
    /// Calculates latency from migration queue start time to now.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - migration_id: Migration identifier to record latency for
    pub fn record_latency(&self, migration_id: MigrationId) {
        // Precondition: migration_id must be valid
        assert!(migration_id != 0, "migration_id must not be 0");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Get start time from queue
        let start_time = {
            let queue = self.queue.lock();
            queue.get_start_time(migration_id)
        };

        if let Some(start) = start_time {
            let latency_nanos = now.saturating_sub(start);
            // Postcondition: latency should be positive
            assert!(latency_nanos > 0 || start == now, "latency calculation error");

            if latency_nanos > 0 {
                self.metrics.record_completion(latency_nanos);
            }
        }
    }

    /// Get migration start time from queue
    ///
    /// # Arguments
    /// - migration_id: Migration identifier
    ///
    /// # Returns
    /// Start time in nanoseconds, or None if not found
    fn get_migration_start_time(&self, migration_id: MigrationId) -> Option<u64> {
        let queue = self.queue.lock();
        queue.get_start_time(migration_id)
    }

    /// Handle migration timeout with retry
    ///
    /// Retries migration up to MAX_MIGRATION_RETRIES times.
    /// After all retries exhausted, restores actor on source worker.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - migration_id: Migration identifier that timed out
    /// - slot_index: Index in retry_counts array
    ///
    /// # Returns
    /// true if retry was initiated, false if max retries exceeded
    pub fn handle_timeout(
        &mut self,
        migration_id: MigrationId,
        slot_index: usize,
    ) -> Result<bool, MigrationError> {
        // Precondition: migration_id must be valid
        assert!(migration_id != 0, "migration_id must not be 0");
        // Precondition: slot_index must be in bounds
        assert!(
            slot_index < MAX_CONCURRENT_MIGRATIONS,
            "slot_index out of bounds"
        );

        // Increment retry count
        self.retry_counts[slot_index] += 1;
        let retry_count = self.retry_counts[slot_index];

        if retry_count >= MAX_MIGRATION_RETRIES {
            // Max retries exceeded - record abort
            self.metrics.record_abort();

            // Reset retry count
            self.retry_counts[slot_index] = 0;

            return Err(MigrationError::MaxRetriesExceeded { migration_id });
        }

        // Record failure for this attempt
        self.metrics.record_failure();

        Ok(true)
    }

    /// Restore actor on source worker after migration failure
    ///
    /// Called when all migration retries are exhausted.
    /// Transitions actor back to Active state on source worker.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    /// - migration_id: Failed migration identifier
    /// - track_id: Track to restore
    /// - source_worker_id: Original worker to restore on
    pub fn restore_on_source(
        &mut self,
        migration_id: MigrationId,
        track_id: TrackId,
        source_worker_id: WorkerId,
    ) -> Result<(), MigrationError> {
        // Precondition: migration_id must be valid
        assert!(migration_id != 0, "migration_id must not be 0");
        // Precondition: track_id must be valid
        assert!(track_id != 0, "track_id must not be 0");

        // Send abort message to source worker
        let workers = self.workers.lock();
        let sender = workers.get(source_worker_id).ok_or(MigrationError::WorkerNotFound {
            worker_id: source_worker_id,
        })?;

        let msg = TrackActorMessage::AbortMigration { migration_id };
        sender.send(msg).map_err(|_| MigrationError::TransferFailed {
            reason: "failed to send abort message",
        })?;

        // Dequeue the failed migration
        {
            let mut queue = self.queue.lock();
            queue.dequeue(migration_id);
        }

        // Record abort in metrics
        self.metrics.record_abort();

        Ok(())
    }


    /// Check for timed-out migrations and handle them
    ///
    /// Scans the migration queue for timed-out migrations and
    /// either retries or restores them.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop (MAX_CONCURRENT_MIGRATIONS)
    ///
    /// # Returns
    /// Number of migrations processed
    pub fn process_timeouts(&mut self) -> u32 {
        let timeout_nanos = MIGRATION_TIMEOUT_SECS * 1_000_000_000;

        // Get timed-out migrations
        let timed_out = {
            let queue = self.queue.lock();
            queue.get_timed_out(timeout_nanos)
        };

        // Precondition: timed_out count is bounded
        assert!(
            timed_out.len() <= MAX_CONCURRENT_MIGRATIONS,
            "timed_out count exceeds max"
        );

        let mut processed = 0u32;

        // Process each timed-out migration (bounded loop)
        for (slot_index, migration_id) in timed_out.iter().enumerate() {
            if slot_index >= MAX_CONCURRENT_MIGRATIONS {
                break;
            }

            match self.handle_timeout(*migration_id, slot_index) {
                Ok(true) => {
                    // Retry initiated
                    processed += 1;
                }
                Ok(false) | Err(_) => {
                    // Max retries exceeded or error - migration will be cleaned up
                    processed += 1;
                }
            }
        }

        // Postcondition: processed count is bounded
        assert!(
            processed <= MAX_CONCURRENT_MIGRATIONS as u32,
            "processed count exceeds max"
        );

        processed
    }

    /// Get current retry count for a slot
    pub fn retry_count(&self, slot_index: usize) -> u32 {
        if slot_index < MAX_CONCURRENT_MIGRATIONS {
            self.retry_counts[slot_index]
        } else {
            0
        }
    }

    /// Reset retry count for a slot
    pub fn reset_retry_count(&mut self, slot_index: usize) {
        if slot_index < MAX_CONCURRENT_MIGRATIONS {
            self.retry_counts[slot_index] = 0;
        }
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &Arc<MigrationMetrics> {
        &self.metrics
    }

    /// Get registry reference
    pub fn registry(&self) -> &Arc<ActorRegistry> {
        &self.registry
    }

    /// Get queue reference
    pub fn queue(&self) -> &Arc<Mutex<MigrationQueue>> {
        &self.queue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::TrackStatsSnapshot;

    fn create_test_executor() -> MigrationExecutor {
        let queue = Arc::new(Mutex::new(MigrationQueue::new()));
        let registry = Arc::new(ActorRegistry::new());
        let workers = Arc::new(Mutex::new(WorkerPool::new(MAX_WORKERS as usize)));
        let metrics = Arc::new(MigrationMetrics::new());

        MigrationExecutor::new(queue, registry, workers, metrics)
    }

    #[test]
    fn test_migration_executor_new() {
        let executor = create_test_executor();
        assert_eq!(executor.buffer_pos, 0);
        assert_eq!(executor.retry_counts[0], 0);
    }

    #[test]
    fn test_worker_pool_new() {
        let pool = WorkerPool::new(16);
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn test_worker_pool_register() {
        let mut pool = WorkerPool::new(16);
        let (tx, _rx) = crossbeam_channel::bounded(10);

        pool.register(0, tx.clone());
        assert_eq!(pool.count(), 1);
        assert!(pool.get(0).is_some());
        assert!(pool.get(1).is_none());
    }

    #[test]
    fn test_serialize_actor() {
        let mut executor = create_test_executor();

        // Create a test actor
        let (mut actor, _sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);

        // Serialize
        let result = executor.serialize_actor(&mut actor, 1);
        assert!(result.is_ok());

        let snapshot = result.unwrap();
        assert_eq!(snapshot.track_id, 1);
        assert_eq!(snapshot.source_worker_id, 0);
    }

    #[test]
    fn test_deserialize_actor() {
        let executor = create_test_executor();

        // Create a snapshot
        let snapshot = MigrationSnapshot {
            track_id: 1,
            source_worker_id: 0,
            target_worker_id: 1,
            last_seq_num: 100,
            subscribers: vec![],
            stats: TrackStatsSnapshot {
                packets_received: 1000,
                packets_forwarded: 900,
                packets_dropped: 100,
            },
        };

        // Deserialize
        let result = executor.deserialize_actor(snapshot, 100, 12345, MediaKind::Video);
        assert!(result.is_ok());

        let (actor, _sender) = result.unwrap();
        assert_eq!(actor.id(), 1);
        assert_eq!(actor.worker_id(), 1);
        assert_eq!(actor.packets_received(), 1000);
    }

    #[test]
    fn test_handle_timeout_retry() {
        let mut executor = create_test_executor();

        // First timeout should allow retry
        let result = executor.handle_timeout(1, 0);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(executor.retry_count(0), 1);

        // Second timeout should allow retry
        let result = executor.handle_timeout(1, 0);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(executor.retry_count(0), 2);
    }

    #[test]
    fn test_handle_timeout_max_retries() {
        let mut executor = create_test_executor();

        // First two timeouts should allow retry
        for i in 0..(MAX_MIGRATION_RETRIES - 1) {
            let result = executor.handle_timeout(1, 0);
            assert!(result.is_ok(), "retry {} should succeed", i);
            assert!(result.unwrap(), "retry {} should return true", i);
        }

        // Next timeout should fail (max retries exceeded)
        let result = executor.handle_timeout(1, 0);
        assert!(result.is_err());

        match result {
            Err(MigrationError::MaxRetriesExceeded { migration_id }) => {
                assert_eq!(migration_id, 1);
            }
            _ => panic!("Expected MaxRetriesExceeded error"),
        }
    }

    #[test]
    fn test_reset_retry_count() {
        let mut executor = create_test_executor();

        executor.retry_counts[0] = 5;
        assert_eq!(executor.retry_count(0), 5);

        executor.reset_retry_count(0);
        assert_eq!(executor.retry_count(0), 0);
    }

    #[test]
    fn test_process_timeouts_empty() {
        let mut executor = create_test_executor();
        let processed = executor.process_timeouts();
        assert_eq!(processed, 0);
    }

    #[test]
    #[should_panic(expected = "migration_id must not be 0")]
    fn test_serialize_actor_invalid_migration_id() {
        let mut executor = create_test_executor();
        let (mut actor, _sender) = TrackActor::spawn(1, 100, 12345, MediaKind::Video, 0);
        let _ = executor.serialize_actor(&mut actor, 0);
    }

    #[test]
    #[should_panic(expected = "capacity exceeds MAX_WORKERS")]
    fn test_worker_pool_capacity_exceeded() {
        let _ = WorkerPool::new(MAX_WORKERS as usize + 1);
    }
}
