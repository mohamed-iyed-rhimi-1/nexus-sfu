//! TrackActor - Independent actor representing a media track
//!
//! Each TrackActor has:
//! - Independent lifecycle (spawn, migrate, terminate)
//! - Message queue for commands
//! - State machine (Initializing → Active → Migrating → Terminated)
//! - Location tracking (current WorkerId)
//! - Supervision (health monitoring, restart on panic)
//!
//! # Invariants
//! - State transitions are monotonic (no backwards transitions)
//! - Message queue has fixed bound (MAX_ACTOR_QUEUE_SIZE)
//! - Subscriber list uses copy-on-write (lock-free reads)
//! - Statistics are atomic (lock-free updates)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_channel::{bounded, Receiver, Sender};

use crate::message::*;
use crate::metrics::MigrationMetrics;
use crate::types::*;

/// Ring buffer size for packet storage (must be power of 2)
const RING_BUFFER_SIZE: usize = 2048;

/// Maximum messages processed per iteration
const MAX_MESSAGES_PER_ITERATION: u32 = 100;

/// Maximum subscribers per track
const MAX_SUBSCRIBERS: usize = 1000;

/// Maximum hot subscribers (actively receiving packets)
const MAX_HOT_SUBSCRIBERS: usize = 100;

/// Single subscriber information
#[derive(Debug, Clone)]
pub struct Subscriber {
    /// Unique subscriber identifier
    pub id: u32,
    /// Participant who subscribed
    pub participant_id: u64,
    /// Destination address for packets
    pub dest_addr: SocketAddr,
    /// Target quality layer (0 = lowest)
    pub target_layer: u8,
    /// Packets forwarded to this subscriber
    pub packets_forwarded: u64,
}

impl Subscriber {
    /// Create new subscriber
    ///
    /// # Assertions
    /// - id != 0
    /// - participant_id != 0
    pub fn new(id: u32, participant_id: u64, dest_addr: SocketAddr) -> Self {
        assert!(id != 0, "subscriber id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        Self {
            id,
            participant_id,
            dest_addr,
            target_layer: 0,
            packets_forwarded: 0,
        }
    }
}

/// List of subscribers with hot/cold separation
///
/// Hot subscribers receive packets immediately.
/// Cold subscribers are buffered and promoted on demand.
#[derive(Debug, Clone)]
pub struct SubscriberList {
    /// Hot subscribers (actively receiving)
    pub hot: Vec<Subscriber>,
    /// Cold subscribers (buffered)
    pub cold: Vec<Subscriber>,
}

impl SubscriberList {
    /// Create empty subscriber list
    pub fn new() -> Self {
        Self {
            hot: Vec::with_capacity(MAX_HOT_SUBSCRIBERS),
            cold: Vec::with_capacity(MAX_SUBSCRIBERS - MAX_HOT_SUBSCRIBERS),
        }
    }

    /// Add subscriber (starts as hot if room, otherwise cold)
    ///
    /// # Assertions
    /// - Total subscribers < MAX_SUBSCRIBERS
    pub fn add(&mut self, subscriber: Subscriber) {
        let total = self.hot.len() + self.cold.len();
        assert!(total < MAX_SUBSCRIBERS, "subscriber limit reached");

        if self.hot.len() < MAX_HOT_SUBSCRIBERS {
            self.hot.push(subscriber);
        } else {
            self.cold.push(subscriber);
        }
    }

    /// Remove subscriber by id
    ///
    /// Returns true if subscriber was found and removed.
    pub fn remove(&mut self, subscriber_id: u32) -> bool {
        // Check hot first
        if let Some(pos) = self.hot.iter().position(|s| s.id == subscriber_id) {
            self.hot.swap_remove(pos);
            // Promote from cold if available
            if !self.cold.is_empty() {
                self.hot.push(self.cold.swap_remove(0));
            }
            return true;
        }

        // Check cold
        if let Some(pos) = self.cold.iter().position(|s| s.id == subscriber_id) {
            self.cold.swap_remove(pos);
            return true;
        }

        false
    }

    /// Promote subscriber from cold to hot
    pub fn promote(&mut self, subscriber_id: u32) -> bool {
        if self.hot.len() >= MAX_HOT_SUBSCRIBERS {
            return false;
        }

        if let Some(pos) = self.cold.iter().position(|s| s.id == subscriber_id) {
            let subscriber = self.cold.swap_remove(pos);
            self.hot.push(subscriber);
            return true;
        }

        false
    }

    /// Demote subscriber from hot to cold
    pub fn demote(&mut self, subscriber_id: u32) -> bool {
        if let Some(pos) = self.hot.iter().position(|s| s.id == subscriber_id) {
            let subscriber = self.hot.swap_remove(pos);
            self.cold.push(subscriber);
            return true;
        }

        false
    }

    /// Get total subscriber count
    pub fn total_count(&self) -> u32 {
        (self.hot.len() + self.cold.len()) as u32
    }
}

impl Default for SubscriberList {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple ring buffer for packet storage
///
/// Fixed size, overwrites oldest on full.
pub struct PacketRingBuffer {
    /// Packet storage
    slots: Box<[Option<PacketSlot>; RING_BUFFER_SIZE]>,
    /// Write position (wraps around)
    write_pos: u32,
    /// Total packets written
    total_written: u64,
}

impl PacketRingBuffer {
    /// Create new ring buffer
    pub fn new() -> Self {
        // Initialize with None values
        let slots = Box::new(std::array::from_fn(|_| None));

        Self {
            slots,
            write_pos: 0,
            total_written: 0,
        }
    }

    /// Push packet into buffer
    ///
    /// Overwrites oldest packet if buffer is full.
    #[inline]
    pub fn push(&mut self, packet: PacketSlot) {
        let pos = self.write_pos as usize;
        self.slots[pos] = Some(packet);
        self.write_pos = ((self.write_pos + 1) as usize % RING_BUFFER_SIZE) as u32;
        self.total_written += 1;
    }

    /// Get total packets written
    pub fn total_written(&self) -> u64 {
        self.total_written
    }
}

impl Default for PacketRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// TrackActor - Independent actor representing a media track
pub struct TrackActor {
    // === Identity ===
    id: TrackId,
    participant_id: ParticipantId,
    ssrc: Ssrc,
    kind: MediaKind,

    // === Location ===
    /// Current worker (atomic for migration)
    worker_id: Arc<AtomicU32>,

    // === State Machine ===
    /// ActorState as u32
    state: Arc<AtomicU32>,
    /// ActorHealth as u32
    health: Arc<AtomicU32>,

    // === Message Queue ===
    message_rx: Receiver<TrackActorMessage>,
    message_tx: Sender<TrackActorMessage>,

    // === Packet Storage ===
    ring_buffer: PacketRingBuffer,

    // === Subscribers (lock-free) ===
    subscribers: Arc<ArcSwap<SubscriberList>>,

    // === Statistics (atomic) ===
    packets_received: AtomicU64,
    packets_forwarded: AtomicU64,
    packets_dropped: AtomicU64,
    messages_processed: AtomicU64,

    // === Supervision ===
    pub restart_count: AtomicU32,
    last_health_check: AtomicU64,

    // === Migration State ===
    /// Current migration ID (0 if not migrating)
    pub migration_id: AtomicU64,
    /// Next sequence number for packet ordering
    pub next_seq_num: AtomicU64,
    /// Last processed sequence number
    pub last_processed_seq_num: AtomicU64,
    /// Migration start timestamp (nanos since epoch)
    pub migration_start_time: AtomicU64,
    /// Migration retry count
    pub migration_retry_count: AtomicU32,
    
    // === Migration Callback ===
    /// Optional callback sender for migration events
    migration_callback: Option<Sender<MigrationEvent>>,
    
    // === Migration Metrics ===
    /// Shared migration metrics
    migration_metrics: Option<Arc<MigrationMetrics>>,
    
    // === Packet Reordering ===
    /// Reordering buffer for out-of-order packets (max 32 packets)
    reorder_buffer: Vec<Option<(MigrationSeqNum, PacketSlot)>>,
    
    // === Simulcast Layers ===
    /// Simulcast layers (pre-allocated, max 3)
    simulcast_layers: [Option<SimulcastLayer>; 3],
    /// Number of active layers
    layer_count: u8,
    /// Current layer selection
    current_layer: AtomicU8,
    /// Target layer from bandwidth allocation
    target_layer: AtomicU8,
    /// Allocated bitrate from GCC (bps)
    allocated_bitrate_bps: AtomicU64,
}

/// Simulcast layer information
#[derive(Debug, Clone, Copy)]
pub struct SimulcastLayer {
    /// Layer index (0 = lowest quality)
    pub index: u8,
    /// Target bitrate for this layer (bps)
    pub bitrate_bps: u64,
    /// Resolution width
    pub width: u32,
    /// Resolution height
    pub height: u32,
}

/// Maximum reordering window size
const MAX_REORDER_WINDOW: usize = 32;

/// Migration event sent to worker pool
#[derive(Debug, Clone)]
pub enum MigrationEvent {
    /// Snapshot ready for transfer
    SnapshotReady {
        migration_id: MigrationId,
        snapshot: MigrationSnapshot,
    },
    /// Migration completed successfully
    Completed {
        migration_id: MigrationId,
        track_id: TrackId,
    },
    /// Migration failed
    Failed {
        migration_id: MigrationId,
        track_id: TrackId,
        reason: &'static str,
    },
}

impl TrackActor {
    /// Spawn a new TrackActor
    ///
    /// Creates actor in Initializing state, transitions to Active
    /// after successful initialization.
    ///
    /// # Arguments
    /// - id: Unique track identifier
    /// - participant_id: Owner participant
    /// - ssrc: RTP SSRC
    /// - kind: Media type (audio/video)
    /// - worker_id: Initial worker location
    ///
    /// # Returns
    /// Tuple of (TrackActor, Sender<TrackActorMessage>)
    ///
    /// # Assertions
    /// - id != 0
    /// - participant_id != 0
    /// - ssrc != 0
    /// - worker_id < MAX_WORKERS
    pub fn spawn(
        id: TrackId,
        participant_id: ParticipantId,
        ssrc: Ssrc,
        kind: MediaKind,
        worker_id: WorkerId,
    ) -> (Self, Sender<TrackActorMessage>) {
        // TigerStyle: Assert preconditions
        assert!(id != 0, "track id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");
        assert!(ssrc != 0, "ssrc must not be 0");
        assert!(worker_id < MAX_WORKERS, "worker_id must be < MAX_WORKERS");

        let (tx, rx) = bounded(MAX_ACTOR_QUEUE_SIZE);

        let state = Arc::new(AtomicU32::new(ActorState::Initializing as u32));

        let actor = Self {
            id,
            participant_id,
            ssrc,
            kind,
            worker_id: Arc::new(AtomicU32::new(worker_id)),
            state: state.clone(),
            health: Arc::new(AtomicU32::new(ActorHealth::Healthy as u32)),
            message_rx: rx,
            message_tx: tx.clone(),
            ring_buffer: PacketRingBuffer::new(),
            subscribers: Arc::new(ArcSwap::from_pointee(SubscriberList::new())),
            packets_received: AtomicU64::new(0),
            packets_forwarded: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            messages_processed: AtomicU64::new(0),
            restart_count: AtomicU32::new(0),
            last_health_check: AtomicU64::new(0),
            migration_id: AtomicU64::new(0),
            next_seq_num: AtomicU64::new(1),
            last_processed_seq_num: AtomicU64::new(0),
            migration_start_time: AtomicU64::new(0),
            migration_retry_count: AtomicU32::new(0),
            migration_callback: None,
            migration_metrics: None,
            reorder_buffer: vec![None; MAX_REORDER_WINDOW],
            simulcast_layers: [None, None, None],
            layer_count: 0,
            current_layer: AtomicU8::new(0),
            target_layer: AtomicU8::new(0),
            allocated_bitrate_bps: AtomicU64::new(0),
        };

        // Transition to Active state
        state.store(ActorState::Active as u32, Ordering::Release);

        (actor, tx)
    }

    /// Transition actor state with validation
    ///
    /// # Assertions
    /// - Current state matches expected_current
    /// - Transition is valid (follows state machine)
    pub fn transition_state(&self, expected_current: ActorState, new_state: ActorState) {
        let current = self.state.load(Ordering::Acquire);
        let current_state = ActorState::from_u8(current as u8);
        assert_eq!(
            current_state, expected_current,
            "invalid state transition: expected {:?}, got {:?}",
            expected_current, current_state
        );

        // Validate transition
        assert!(
            Self::is_valid_transition(expected_current, new_state),
            "invalid state transition: {:?} -> {:?}",
            expected_current,
            new_state
        );

        self.state.store(new_state as u32, Ordering::Release);
    }

    /// Check if state transition is valid
    pub const fn is_valid_transition(from: ActorState, to: ActorState) -> bool {
        match (from, to) {
            (ActorState::Initializing, ActorState::Active) => true,
            (ActorState::Active, ActorState::Migrating) => true,
            (ActorState::Active, ActorState::Terminated) => true,
            (ActorState::Migrating, ActorState::Active) => true,
            (ActorState::Migrating, ActorState::Terminated) => true,
            _ => false,
        }
    }

    /// Process messages in actor's main loop
    ///
    /// Returns false when actor should terminate.
    ///
    /// # Loop Bound
    /// Processes up to MAX_MESSAGES_PER_ITERATION per call
    pub fn process_messages(&mut self) -> bool {
        let mut processed = 0u32;

        while processed < MAX_MESSAGES_PER_ITERATION {
            match self.message_rx.try_recv() {
                Ok(msg) => {
                    if !self.handle_message(msg) {
                        return false; // Terminate
                    }
                    processed += 1;
                    self.messages_processed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => break, // No more messages
            }
        }

        true
    }

    /// Handle a single message
    ///
    /// Returns false if actor should terminate.
    #[inline(always)]
    pub fn handle_message(&mut self, msg: TrackActorMessage) -> bool {
        match msg {
            TrackActorMessage::Subscribe {
                subscriber_id,
                participant_id,
                dest_addr,
            } => {
                self.handle_subscribe(subscriber_id, participant_id, dest_addr);
                true
            }
            TrackActorMessage::Unsubscribe { subscriber_id } => {
                self.handle_unsubscribe(subscriber_id);
                true
            }
            TrackActorMessage::UpdateQuality {
                subscriber_id,
                target_layer,
            } => {
                self.handle_update_quality(subscriber_id, target_layer);
                true
            }
            TrackActorMessage::PromoteSubscriber { subscriber_id } => {
                self.handle_promote(subscriber_id);
                true
            }
            TrackActorMessage::DemoteSubscriber { subscriber_id } => {
                self.handle_demote(subscriber_id);
                true
            }
            TrackActorMessage::ProcessPacket { packet } => {
                // Generate sequence number and route through sequenced processing
                let seq_num = self.next_seq_num.fetch_add(1, Ordering::Relaxed);
                self.handle_packet_seq(packet, seq_num);
                true
            }
            TrackActorMessage::ProcessPacketSeq { packet, seq_num } => {
                self.handle_packet_seq(packet, seq_num);
                true
            }
            TrackActorMessage::PrepareMigration {
                migration_id,
                target_worker_id,
            } => {
                self.handle_prepare_migration(migration_id, target_worker_id);
                true
            }
            TrackActorMessage::TransferState {
                migration_id,
                snapshot,
            } => {
                self.handle_transfer_state(migration_id, snapshot);
                true
            }
            TrackActorMessage::ResumeMigration { migration_id } => {
                self.handle_resume_migration(migration_id);
                true
            }
            TrackActorMessage::AbortMigration { migration_id } => {
                self.handle_abort_migration(migration_id);
                true
            }
            TrackActorMessage::BeginMigration { target_worker_id } => {
                self.handle_begin_migration(target_worker_id);
                true
            }
            TrackActorMessage::CompleteMigration => {
                self.handle_complete_migration();
                true
            }
            TrackActorMessage::Terminate => {
                self.handle_terminate();
                false
            }
            TrackActorMessage::HealthCheck => {
                self.handle_health_check();
                true
            }
        }
    }

    /// Handle subscribe message
    fn handle_subscribe(&mut self, subscriber_id: u32, participant_id: u64, dest_addr: SocketAddr) {
        assert!(subscriber_id != 0, "subscriber_id must not be 0");
        assert!(participant_id != 0, "participant_id must not be 0");

        let subscriber = Subscriber::new(subscriber_id, participant_id, dest_addr);

        // Copy-on-write update
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();
        new_list.add(subscriber);
        self.subscribers.store(Arc::new(new_list));
    }

    /// Handle unsubscribe message
    fn handle_unsubscribe(&mut self, subscriber_id: u32) {
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();
        new_list.remove(subscriber_id);
        self.subscribers.store(Arc::new(new_list));
    }

    /// Handle quality update
    fn handle_update_quality(&mut self, subscriber_id: u32, target_layer: u8) {
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();

        // Find and update subscriber
        for sub in new_list.hot.iter_mut() {
            if sub.id == subscriber_id {
                sub.target_layer = target_layer;
                break;
            }
        }
        for sub in new_list.cold.iter_mut() {
            if sub.id == subscriber_id {
                sub.target_layer = target_layer;
                break;
            }
        }

        self.subscribers.store(Arc::new(new_list));
    }

    /// Handle promote subscriber
    fn handle_promote(&mut self, subscriber_id: u32) {
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();
        new_list.promote(subscriber_id);
        self.subscribers.store(Arc::new(new_list));
    }

    /// Handle demote subscriber
    fn handle_demote(&mut self, subscriber_id: u32) {
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();
        new_list.demote(subscriber_id);
        self.subscribers.store(Arc::new(new_list));
    }

    /// Handle packet processing
    #[inline(always)]
    fn handle_packet(&mut self, packet: PacketSlot) {
        assert!(packet.len() > 0, "packet must have data");

        self.packets_received.fetch_add(1, Ordering::Relaxed);

        // Store in ring buffer
        self.ring_buffer.push(packet.clone_shallow());

        // Forward to subscribers (message-based, not direct)
        let subscribers = self.subscribers.load();
        if subscribers.hot.is_empty() {
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Count forwarded packets
        // Note: Actual forwarding will be handled by worker's batch sender
        self.packets_forwarded
            .fetch_add(subscribers.hot.len() as u64, Ordering::Relaxed);
    }

    /// Handle begin migration
    fn handle_begin_migration(&mut self, target_worker_id: WorkerId) {
        assert!(
            target_worker_id < MAX_WORKERS,
            "target_worker_id must be < MAX_WORKERS"
        );

        // Transition to Migrating state
        self.transition_state(ActorState::Active, ActorState::Migrating);

        // Store target worker id for migration
        // Worker will handle actual migration protocol
    }

    /// Handle complete migration
    fn handle_complete_migration(&mut self) {
        // Transition back to Active state
        self.transition_state(ActorState::Migrating, ActorState::Active);
    }

    /// Terminate actor gracefully
    fn handle_terminate(&mut self) {
        let current = ActorState::from_u8(self.state.load(Ordering::Acquire) as u8);
        match current {
            ActorState::Active => {
                self.transition_state(ActorState::Active, ActorState::Terminated);
            }
            ActorState::Migrating => {
                self.transition_state(ActorState::Migrating, ActorState::Terminated);
            }
            _ => {
                // Already terminated or initializing, just set terminated
                self.state.store(ActorState::Terminated as u32, Ordering::Release);
            }
        }
    }

    /// Handle health check
    fn handle_health_check(&mut self) {
        // Update last health check timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.last_health_check.store(now, Ordering::Relaxed);
    }

    /// Handle prepare migration
    fn handle_prepare_migration(&mut self, migration_id: MigrationId, target_worker_id: WorkerId) {
        assert!(migration_id != 0, "migration_id must not be 0");
        assert!(
            target_worker_id < MAX_WORKERS,
            "target_worker_id must be < MAX_WORKERS"
        );

        // Record migration start
        if let Some(ref metrics) = self.migration_metrics {
            metrics.record_start();
        }

        // Prepare snapshot with target worker populated
        let mut snapshot = self.prepare_migration_snapshot(migration_id);
        snapshot.target_worker_id = target_worker_id;

        // Send snapshot to worker pool for transfer
        if let Some(ref callback) = self.migration_callback {
            let _ = callback.try_send(MigrationEvent::SnapshotReady {
                migration_id,
                snapshot,
            });
        }
        
        // Packet processing is now frozen (state is Migrating)
    }

    /// Handle transfer state
    fn handle_transfer_state(&mut self, migration_id: MigrationId, snapshot: MigrationSnapshot) {
        assert!(migration_id != 0, "migration_id must not be 0");
        self.apply_migration_snapshot(snapshot);
    }

    /// Handle resume migration
    fn handle_resume_migration(&mut self, migration_id: MigrationId) {
        assert!(migration_id != 0, "migration_id must not be 0");
        let current_migration = self.migration_id.load(Ordering::Acquire);
        assert_eq!(
            current_migration, migration_id,
            "migration_id mismatch"
        );

        // Calculate migration latency
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let start_time = self.migration_start_time.load(Ordering::Relaxed);
        let latency_nanos = now.saturating_sub(start_time);

        // Record completion
        if let Some(ref metrics) = self.migration_metrics {
            if latency_nanos > 0 {
                metrics.record_completion(latency_nanos);
            }
        }

        // Transition back to Active
        self.transition_state(ActorState::Migrating, ActorState::Active);
        self.migration_id.store(0, Ordering::Release);

        // Notify worker pool of completion
        if let Some(ref callback) = self.migration_callback {
            let _ = callback.try_send(MigrationEvent::Completed {
                migration_id,
                track_id: self.id,
            });
        }
    }

    /// Handle abort migration
    fn handle_abort_migration(&mut self, migration_id: MigrationId) {
        assert!(migration_id != 0, "migration_id must not be 0");
        let current_migration = self.migration_id.load(Ordering::Acquire);
        if current_migration == migration_id {
            // Record failure
            if let Some(ref metrics) = self.migration_metrics {
                metrics.record_failure();
            }

            self.transition_state(ActorState::Migrating, ActorState::Active);
            self.migration_id.store(0, Ordering::Release);
            self.migration_retry_count.fetch_add(1, Ordering::Relaxed);

            // Notify worker pool of failure
            if let Some(ref callback) = self.migration_callback {
                let _ = callback.try_send(MigrationEvent::Failed {
                    migration_id,
                    track_id: self.id,
                    reason: "migration aborted",
                });
            }
        }
    }

    // === Migration Methods ===

    /// Add simulcast layer during initialization
    ///
    /// # Assertions
    /// - layer_count < 3
    /// - Layers added in increasing bitrate order
    pub fn add_simulcast_layer(&mut self, layer: SimulcastLayer) {
        assert!(self.layer_count < 3, "Maximum 3 simulcast layers supported");
        
        // Verify increasing bitrate order
        if self.layer_count > 0 {
            let prev_layer = self.simulcast_layers[self.layer_count as usize - 1].unwrap();
            assert!(
                layer.bitrate_bps > prev_layer.bitrate_bps,
                "Layers must be added in increasing bitrate order"
            );
        }
        
        self.simulcast_layers[self.layer_count as usize] = Some(layer);
        self.layer_count += 1;
    }

    /// Set allocated bitrate from bandwidth coordinator
    pub fn set_allocated_bitrate(&self, bitrate_bps: u64) {
        self.allocated_bitrate_bps.store(bitrate_bps, Ordering::Relaxed);
    }

    /// Select best layer for allocated bitrate
    ///
    /// Returns layer index that fits within allocated bitrate.
    /// Returns 0 if no allocation or no layers configured.
    pub fn select_layer(&self) -> u8 {
        let allocated = self.allocated_bitrate_bps.load(Ordering::Relaxed);
        
        if allocated == 0 || self.layer_count == 0 {
            return 0;
        }

        // Find highest layer that fits within allocation
        let mut selected_layer = 0u8;
        for i in 0..self.layer_count {
            if let Some(layer) = self.simulcast_layers[i as usize] {
                if layer.bitrate_bps <= allocated {
                    selected_layer = layer.index;
                } else {
                    break;
                }
            }
        }

        selected_layer
    }

    /// Apply layer selection to forwarding logic
    ///
    /// Updates current layer and adjusts forwarding behavior.
    ///
    /// # Assertions
    /// - target_layer < layer_count
    pub fn apply_layer_selection(&mut self, target_layer: u8) {
        assert!(
            target_layer < self.layer_count,
            "Target layer {} exceeds layer count {}",
            target_layer,
            self.layer_count
        );

        let old_layer = self.current_layer.load(Ordering::Relaxed);
        self.current_layer.store(target_layer, Ordering::Relaxed);

        // Update target layer for all subscribers
        let current = self.subscribers.load_full();
        let mut new_list = (*current).clone();

        for sub in new_list.hot.iter_mut() {
            sub.target_layer = target_layer;
        }
        for sub in new_list.cold.iter_mut() {
            sub.target_layer = target_layer;
        }

        self.subscribers.store(Arc::new(new_list));

        // Log layer switch (metrics would be recorded here)
        if old_layer != target_layer {
            // Layer switch occurred
        }
    }

    /// Get current layer
    pub fn current_layer(&self) -> u8 {
        self.current_layer.load(Ordering::Relaxed)
    }

    /// Get target layer
    pub fn target_layer(&self) -> u8 {
        self.target_layer.load(Ordering::Relaxed)
    }

    /// Get allocated bitrate
    pub fn allocated_bitrate(&self) -> u64 {
        self.allocated_bitrate_bps.load(Ordering::Relaxed)
    }

    /// Get simulcast layer count
    pub fn layer_count(&self) -> u8 {
        self.layer_count
    }

    /// Get simulcast layer by index
    pub fn get_layer(&self, index: u8) -> Option<SimulcastLayer> {
        if index < self.layer_count {
            self.simulcast_layers[index as usize]
        } else {
            None
        }
    }

    // === Migration Methods ===

    /// Calculate subscriber gravity per worker
    ///
    /// Returns array of subscriber counts indexed by worker_id.
    ///
    /// # Loop Bound
    /// - Iterates up to MAX_SUBSCRIBERS
    ///
    /// # Assertions
    /// - Total subscribers matches sum of per-worker counts
    pub fn calculate_subscriber_gravity(&self) -> [u32; MAX_WORKERS as usize] {
        let mut gravity = [0u32; MAX_WORKERS as usize];
        let subscribers = self.subscribers.load();

        // Count hot subscribers per worker
        let mut total_hot = 0u32;
        for sub in subscribers.hot.iter() {
            // Determine worker for this subscriber's destination
            let worker_id = self.hash_to_worker(sub.dest_addr);
            assert!(worker_id < MAX_WORKERS, "worker_id must be < MAX_WORKERS");
            gravity[worker_id as usize] += 1;
            total_hot += 1;
        }

        // Count cold subscribers per worker
        let mut total_cold = 0u32;
        for sub in subscribers.cold.iter() {
            let worker_id = self.hash_to_worker(sub.dest_addr);
            assert!(worker_id < MAX_WORKERS, "worker_id must be < MAX_WORKERS");
            gravity[worker_id as usize] += 1;
            total_cold += 1;
        }

        // Assert total matches
        let total_subscribers = subscribers.total_count();
        assert_eq!(
            total_hot + total_cold,
            total_subscribers,
            "subscriber count mismatch"
        );

        gravity
    }

    /// Find optimal worker based on subscriber gravity
    ///
    /// Returns worker_id with highest subscriber count.
    /// Returns current worker if no better option exists.
    ///
    /// # Assertions
    /// - Returned worker_id < MAX_WORKERS
    pub fn find_optimal_worker(&self) -> WorkerId {
        let gravity = self.calculate_subscriber_gravity();
        let current_worker = self.worker_id();
        let mut max_count = gravity[current_worker as usize];
        let mut optimal_worker = current_worker;

        // Find worker with maximum subscribers
        for worker_id in 0..MAX_WORKERS {
            if gravity[worker_id as usize] > max_count {
                max_count = gravity[worker_id as usize];
                optimal_worker = worker_id;
            }
        }

        assert!(
            optimal_worker < MAX_WORKERS,
            "optimal_worker must be < MAX_WORKERS"
        );
        optimal_worker
    }

    /// Check if migration is beneficial
    ///
    /// Returns true if >80% of subscribers are on a different worker.
    ///
    /// # Assertions
    /// - threshold_percent <= 100
    pub fn should_migrate(&self, threshold_percent: u8) -> bool {
        assert!(threshold_percent <= 100, "threshold must be <= 100");

        let gravity = self.calculate_subscriber_gravity();
        let current_worker = self.worker_id();
        let total_subscribers = self.subscriber_count();

        if total_subscribers == 0 {
            return false;
        }

        let current_worker_subs = gravity[current_worker as usize];
        let other_worker_subs = total_subscribers - current_worker_subs;

        // Calculate percentage on other workers
        let other_percent = (other_worker_subs * 100) / total_subscribers;
        other_percent >= threshold_percent as u32
    }

    /// Prepare migration snapshot
    ///
    /// Freezes actor state and creates snapshot for transfer.
    ///
    /// # Assertions
    /// - Current state is Active
    /// - Not already migrating (migration_id == 0)
    pub fn prepare_migration_snapshot(&mut self, migration_id: MigrationId) -> MigrationSnapshot {
        // Assert preconditions
        assert!(migration_id != 0, "migration_id must not be 0");
        let current_migration = self.migration_id.load(Ordering::Acquire);
        assert_eq!(current_migration, 0, "already migrating");

        // Transition to Migrating state
        self.transition_state(ActorState::Active, ActorState::Migrating);

        // Store migration ID
        self.migration_id.store(migration_id, Ordering::Release);

        // Record start time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.migration_start_time.store(now, Ordering::Release);

        // Snapshot subscribers
        let subscribers = self.subscribers.load();
        let mut subscriber_snapshots = Vec::with_capacity(subscribers.hot.len() + subscribers.cold.len());

        for sub in subscribers.hot.iter() {
            subscriber_snapshots.push(SubscriberSnapshot {
                id: sub.id,
                participant_id: sub.participant_id,
                dest_addr: sub.dest_addr,
                target_layer: sub.target_layer,
                packets_forwarded: sub.packets_forwarded,
            });
        }

        for sub in subscribers.cold.iter() {
            subscriber_snapshots.push(SubscriberSnapshot {
                id: sub.id,
                participant_id: sub.participant_id,
                dest_addr: sub.dest_addr,
                target_layer: sub.target_layer,
                packets_forwarded: sub.packets_forwarded,
            });
        }

        // Snapshot statistics
        let stats = TrackStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
        };

        // Get last processed sequence number
        let last_seq_num = self.last_processed_seq_num.load(Ordering::Acquire);

        MigrationSnapshot {
            track_id: self.id,
            source_worker_id: self.worker_id(),
            target_worker_id: 0, // Set by caller
            last_seq_num,
            subscribers: subscriber_snapshots,
            stats,
        }
    }

    /// Apply migration snapshot on target worker
    ///
    /// Restores actor state from snapshot.
    ///
    /// # Assertions
    /// - snapshot.track_id matches self.id
    /// - Current state is Initializing or Migrating
    pub fn apply_migration_snapshot(&mut self, snapshot: MigrationSnapshot) {
        // Assert preconditions
        assert_eq!(snapshot.track_id, self.id, "track_id mismatch");

        // Restore subscribers
        let mut new_list = SubscriberList::new();
        for sub_snap in snapshot.subscribers {
            let sub = Subscriber {
                id: sub_snap.id,
                participant_id: sub_snap.participant_id,
                dest_addr: sub_snap.dest_addr,
                target_layer: sub_snap.target_layer,
                packets_forwarded: sub_snap.packets_forwarded,
            };
            new_list.add(sub);
        }
        self.subscribers.store(Arc::new(new_list));

        // Restore statistics
        self.packets_received
            .store(snapshot.stats.packets_received, Ordering::Relaxed);
        self.packets_forwarded
            .store(snapshot.stats.packets_forwarded, Ordering::Relaxed);
        self.packets_dropped
            .store(snapshot.stats.packets_dropped, Ordering::Relaxed);

        // Restore sequence number
        self.last_processed_seq_num
            .store(snapshot.last_seq_num, Ordering::Release);

        // Update worker ID
        self.worker_id
            .store(snapshot.target_worker_id, Ordering::Release);
    }

    /// Process packet with sequence number for ordering
    ///
    /// Ensures FIFO ordering with tolerance for minor reordering.
    /// Buffers out-of-order packets up to MAX_REORDER_WINDOW.
    ///
    /// # Assertions
    /// - seq_num > last_processed_seq_num (monotonic)
    /// - Reordering gap <= MAX_REORDER_WINDOW
    pub fn handle_packet_seq(&mut self, packet: PacketSlot, seq_num: MigrationSeqNum) {
        let last_seq = self.last_processed_seq_num.load(Ordering::Acquire);

        // Check if this is the next expected packet
        if seq_num == last_seq + 1 {
            // Process immediately
            self.handle_packet(packet);
            self.last_processed_seq_num.store(seq_num, Ordering::Release);

            // Check reorder buffer for consecutive packets
            self.drain_reorder_buffer();
        } else if seq_num > last_seq + 1 {
            // Future packet - buffer it
            let gap = (seq_num - last_seq - 1) as usize;
            
            if gap >= MAX_REORDER_WINDOW {
                // Gap too large - this indicates packet loss or severe reordering
                // Record sequence gap
                if let Some(ref metrics) = self.migration_metrics {
                    metrics.record_sequence_gap();
                    metrics.record_packet_loss(gap as u64);
                }

                // Process anyway to avoid blocking, but log the gap
                self.handle_packet(packet);
                self.last_processed_seq_num.store(seq_num, Ordering::Release);
                
                // Clear reorder buffer as we've skipped ahead
                for slot in &mut self.reorder_buffer {
                    *slot = None;
                }
            } else {
                // Buffer the packet
                let buffer_index = gap % MAX_REORDER_WINDOW;
                self.reorder_buffer[buffer_index] = Some((seq_num, packet));
            }
        } else {
            // Old packet (seq_num <= last_seq) - drop as duplicate
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
            
            // Record duplicate
            if let Some(ref metrics) = self.migration_metrics {
                metrics.record_packet_duplication(1);
            }
        }
    }

    /// Drain consecutive packets from reorder buffer
    ///
    /// # Loop Bound
    /// - Iterates up to MAX_REORDER_WINDOW
    fn drain_reorder_buffer(&mut self) {
        let mut drained = 0;
        
        while drained < MAX_REORDER_WINDOW {
            let last_seq = self.last_processed_seq_num.load(Ordering::Acquire);
            let next_expected = last_seq + 1;
            
            // Look for next expected packet in buffer
            let mut found = false;
            for slot in &mut self.reorder_buffer {
                if let Some((seq, _)) = slot {
                    if *seq == next_expected {
                        // Found next packet
                        if let Some((_, packet)) = slot.take() {
                            self.handle_packet(packet);
                            self.last_processed_seq_num.store(next_expected, Ordering::Release);
                            found = true;
                            drained += 1;
                            break;
                        }
                    }
                }
            }
            
            if !found {
                break; // No more consecutive packets
            }
        }
    }

    /// Hash destination address to worker ID
    pub fn hash_to_worker(&self, addr: SocketAddr) -> WorkerId {
        // Simple hash based on IP and port
        let hash = match addr {
            SocketAddr::V4(v4) => {
                let ip_bytes = v4.ip().octets();
                let port = v4.port();
                u32::from_be_bytes(ip_bytes).wrapping_add(port as u32)
            }
            SocketAddr::V6(v6) => {
                let ip_bytes = v6.ip().octets();
                let port = v6.port();
                // XOR fold IPv6 to u32
                let mut hash = 0u32;
                for chunk in ip_bytes.chunks(4) {
                    let mut bytes = [0u8; 4];
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    hash ^= u32::from_be_bytes(bytes);
                }
                hash.wrapping_add(port as u32)
            }
        };

        hash % MAX_WORKERS
    }

    // === Public API ===

    /// Get track id
    pub fn id(&self) -> TrackId {
        self.id
    }

    /// Get participant id
    pub fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Get SSRC
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    /// Get media kind
    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    /// Get current worker id
    pub fn worker_id(&self) -> WorkerId {
        self.worker_id.load(Ordering::Acquire)
    }

    /// Get actor state
    pub fn state(&self) -> ActorState {
        ActorState::from_u8(self.state.load(Ordering::Acquire) as u8)
    }

    /// Get actor health
    pub fn health(&self) -> ActorHealth {
        ActorHealth::from_u8(self.health.load(Ordering::Acquire) as u8)
    }

    /// Get message sender for this actor
    pub fn sender(&self) -> Sender<TrackActorMessage> {
        self.message_tx.clone()
    }

    /// Get subscriber count
    pub fn subscriber_count(&self) -> u32 {
        self.subscribers.load().total_count()
    }

    /// Get packets received count
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get packets forwarded count
    pub fn packets_forwarded(&self) -> u64 {
        self.packets_forwarded.load(Ordering::Relaxed)
    }

    /// Get packets dropped count
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    /// Get messages processed count
    pub fn messages_processed(&self) -> u64 {
        self.messages_processed.load(Ordering::Relaxed)
    }

    /// Get last health check timestamp in nanoseconds
    pub fn last_health_check_ns(&self) -> u64 {
        self.last_health_check.load(Ordering::Relaxed)
    }

    /// Get queue depth (pending messages)
    pub fn queue_depth(&self) -> u32 {
        self.message_rx.len() as u32
    }

    /// Set migration callback for worker pool communication
    pub fn set_migration_callback(&mut self, sender: Sender<MigrationEvent>) {
        self.migration_callback = Some(sender);
    }

    /// Set migration metrics for recording
    pub fn set_migration_metrics(&mut self, metrics: Arc<MigrationMetrics>) {
        self.migration_metrics = Some(metrics);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscriber_new() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let sub = Subscriber::new(1, 100, addr);

        assert_eq!(sub.id, 1);
        assert_eq!(sub.participant_id, 100);
        assert_eq!(sub.target_layer, 0);
    }

    #[test]
    fn test_subscriber_list_add_remove() {
        let mut list = SubscriberList::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        list.add(Subscriber::new(1, 100, addr));
        list.add(Subscriber::new(2, 101, addr));

        assert_eq!(list.total_count(), 2);
        assert_eq!(list.hot.len(), 2);

        assert!(list.remove(1));
        assert_eq!(list.total_count(), 1);
        assert!(!list.remove(999));
    }

    #[test]
    fn test_packet_ring_buffer() {
        let mut buffer = PacketRingBuffer::new();

        for i in 0..10 {
            let data = vec![i as u8; 100];
            buffer.push(PacketSlot::new(&data));
        }

        assert_eq!(buffer.total_written(), 10);
    }

    #[test]
    fn test_valid_transitions() {
        assert!(TrackActor::is_valid_transition(
            ActorState::Initializing,
            ActorState::Active
        ));
        assert!(TrackActor::is_valid_transition(
            ActorState::Active,
            ActorState::Migrating
        ));
        assert!(TrackActor::is_valid_transition(
            ActorState::Active,
            ActorState::Terminated
        ));
        assert!(TrackActor::is_valid_transition(
            ActorState::Migrating,
            ActorState::Active
        ));
        assert!(TrackActor::is_valid_transition(
            ActorState::Migrating,
            ActorState::Terminated
        ));

        // Invalid transitions
        assert!(!TrackActor::is_valid_transition(
            ActorState::Active,
            ActorState::Initializing
        ));
        assert!(!TrackActor::is_valid_transition(
            ActorState::Terminated,
            ActorState::Active
        ));
    }
}
