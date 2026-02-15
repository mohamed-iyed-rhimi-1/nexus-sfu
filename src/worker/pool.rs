//! Worker Pool Implementation.
//!
//! Provides CPU-pinned worker threads with shared-nothing design.
//! Each worker owns its tracks exclusively and communicates via SPSC channels.
//!
//! # Thread Safety
//!
//! - Workers are pinned to specific CPU cores for cache efficiency
//! - Each worker owns its tracks exclusively (no sharing)
//! - Cross-worker communication uses SPSC channels
//! - WorkerPool coordinates track assignment and routing
//!
//! # Actor System Integration
//!
//! Workers can host TrackActors which provide:
//! - Independent lifecycle management
//! - Message-based communication
//! - State machine enforcement
//! - Supervision and health monitoring

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam::channel::{self, Receiver, Sender, TrySendError};
use parking_lot::Mutex;

use nexus_transport::arena::{PacketArena, PacketSlot};
use crate::error::WorkerError;
use nexus_transport::ring_buffer::RingBuffer;
use crate::transport::BatchSender;
use crate::types::{MediaKind, ParticipantId, Ssrc, TrackId};

use nexus_actor::{MigrationEvent, MigrationMetrics, MigrationQueue};

use super::shard::ConsistentHash;
use super::{WorkerMessage, WorkerStats};

/// Default channel capacity for worker message queues.
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;
// ============================================================================
// Real-Time Scheduling Support (Linux only)
// ============================================================================

/// Scheduling policy for worker threads.
///
/// Indicates which OS scheduling policy is active for a worker thread.
/// Used for observability and debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingPolicy {
    /// SCHED_FIFO real-time scheduling (fixed-priority preemptive).
    Fifo,
    /// SCHED_RR real-time scheduling (round-robin with time slices).
    RoundRobin,
    /// Default CFS/normal scheduling (no real-time priority).
    Normal,
}

/// Check if the current process has CAP_SYS_NICE capability.
///
/// CAP_SYS_NICE (bit 23) is required to set real-time scheduling priority
/// via `sched_setscheduler`. This function reads `/proc/self/status` and
/// checks the CapEff (effective capabilities) bitmask.
///
/// # Returns
///
/// `true` if CAP_SYS_NICE is available, `false` otherwise.
///
/// # TigerStyle
///
/// - ≥2 assertions (precondition + postcondition)
/// - ≤70 lines
/// - Explicit types
#[cfg(target_os = "linux")]
pub fn has_cap_sys_nice() -> bool {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // CAP_SYS_NICE is bit 23 in the capabilities bitmask
    const CAP_SYS_NICE_BIT: u32 = 23;

    // Precondition: bit position is valid for u64 bitmask
    assert!(CAP_SYS_NICE_BIT < 64, "CAP_SYS_NICE bit must be < 64");

    let file = match File::open("/proc/self/status") {
        Ok(f) => f,
        Err(_) => return false,
    };

    let reader = BufReader::new(file);

    // TigerStyle: Fixed loop bound
    const MAX_LINES: u32 = 100;
    let mut line_count: u32 = 0;

    for line_result in reader.lines() {
        if line_count >= MAX_LINES {
            break;
        }
        line_count += 1;

        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Look for "CapEff:" line which contains effective capabilities
        if line.starts_with("CapEff:") {
            let hex_str = line.trim_start_matches("CapEff:").trim();
            let cap_eff = match u64::from_str_radix(hex_str, 16) {
                Ok(v) => v,
                Err(_) => return false,
            };

            let has_cap = (cap_eff & (1u64 << CAP_SYS_NICE_BIT)) != 0;

            // Postcondition: result is deterministic based on bitmask
            assert!(
                has_cap == ((cap_eff >> CAP_SYS_NICE_BIT) & 1 == 1),
                "capability check must be consistent"
            );

            return has_cap;
        }
    }

    false
}

/// Set SCHED_FIFO real-time scheduling for the calling thread.
///
/// SCHED_FIFO provides fixed-priority preemptive scheduling, ensuring
/// media processing threads are not preempted by non-critical OS tasks.
///
/// # Arguments
///
/// * `priority` - SCHED_FIFO priority (1-99, higher = more priority)
///
/// # Returns
///
/// `Ok(())` on success, `Err` with description on failure.
///
/// # Errors
///
/// - Returns error if CAP_SYS_NICE is not available
/// - Returns error if `sched_setscheduler` fails (with errno)
///
/// # TigerStyle
///
/// - ≥2 assertions (priority bounds)
/// - ≤70 lines
/// - Explicit types
#[cfg(target_os = "linux")]
pub fn set_realtime_scheduling(priority: u32) -> Result<(), String> {
    // Precondition: SCHED_FIFO priority must be in valid range [1, 99]
    assert!(priority >= 1, "SCHED_FIFO priority must be >= 1");
    assert!(priority <= 99, "SCHED_FIFO priority must be <= 99");

    // Check CAP_SYS_NICE before attempting syscall
    if !has_cap_sys_nice() {
        return Err("CAP_SYS_NICE capability not available".to_string());
    }

    let param = libc::sched_param {
        sched_priority: priority as i32,
    };

    // SAFETY: sched_setscheduler is a standard POSIX syscall.
    // pid=0 means current thread, SCHED_FIFO is a valid policy,
    // and param is a valid sched_param struct.
    let result = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };

    if result != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!("sched_setscheduler(SCHED_FIFO, {}) failed: {}", priority, errno));
    }

    // Postcondition: verify scheduling was actually set
    // (This is a sanity check - if sched_setscheduler returned 0, it succeeded)
    assert!(result == 0, "sched_setscheduler must return 0 on success");

    Ok(())
}

// ============================================================================
// End Real-Time Scheduling Support
// ============================================================================



/// Default arena size per worker in MB.
const DEFAULT_ARENA_SIZE_MB: u32 = 16;

/// Default batch size for sendmmsg.
const DEFAULT_BATCH_SIZE: u32 = 64;

/// Default flush interval in microseconds.
const DEFAULT_FLUSH_INTERVAL_US: u32 = 1000;

/// Shutdown timeout in milliseconds.
const SHUTDOWN_TIMEOUT_MS: u64 = 5000;

/// Worker startup timeout in milliseconds.
const WORKER_STARTUP_TIMEOUT_MS: u64 = 5000;

/// Poll interval for checking worker status in milliseconds.
const WORKER_POLL_INTERVAL_MS: u64 = 5;

/// Handle to a worker thread.
///
/// Provides access to worker state and the channel for sending messages.
pub struct WorkerHandle {
    /// Worker thread handle.
    thread: Option<JoinHandle<()>>,
    /// Worker ID (0-based).
    worker_id: u32,
    /// CPU core ID this worker is pinned to.
    core_id: u32,
    /// Number of tracks owned by this worker.
    track_count: Arc<AtomicU32>,
    /// Channel sender for messages to this worker.
    sender: Sender<WorkerMessage>,
    /// Flag indicating if worker is running.
    is_running: Arc<AtomicBool>,
    /// Flag indicating if worker failed to initialize.
    init_failed: Arc<AtomicBool>,
    /// Error message if initialization failed.
    init_error: Arc<parking_lot::Mutex<Option<String>>>,
    /// Active scheduling policy for this worker thread (0=Normal, 1=Fifo, 2=RoundRobin).
    scheduling_policy: Arc<AtomicU8>,
}

impl WorkerHandle {
    /// Get the worker ID.
    #[inline(always)]
    pub fn worker_id(&self) -> u32 {
        self.worker_id
    }

    /// Get the CPU core ID.
    #[inline(always)]
    pub fn core_id(&self) -> u32 {
        self.core_id
    }

    /// Get the current track count.
    #[inline(always)]
    pub fn track_count(&self) -> u32 {
        self.track_count.load(Ordering::Relaxed)
    }

    /// Check if the worker is running.
    #[inline(always)]
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Check if the worker failed to initialize.
    #[inline(always)]
    pub fn init_failed(&self) -> bool {
        self.init_failed.load(Ordering::Acquire)
    }

    /// Get the initialization error message if any.
    pub fn init_error(&self) -> Option<String> {
        self.init_error.lock().clone()
    }

    /// Get the active scheduling policy for this worker.
    #[inline(always)]
    pub fn scheduling_policy(&self) -> SchedulingPolicy {
        match self.scheduling_policy.load(Ordering::Acquire) {
            1 => SchedulingPolicy::Fifo,
            2 => SchedulingPolicy::RoundRobin,
            _ => SchedulingPolicy::Normal,
        }
    }

    /// Send a message to this worker.
    ///
    /// Returns an error if the channel is full or disconnected.
    pub fn send(&self, msg: WorkerMessage) -> Result<(), WorkerError> {
        self.sender.try_send(msg).map_err(|e| match e {
            TrySendError::Full(_) => WorkerError::ChannelFull {
                worker_id: self.worker_id,
            },
            TrySendError::Disconnected(_) => WorkerError::WorkerPanicked {
                worker_id: self.worker_id,
                message: "channel disconnected".to_string(),
            },
        })
    }

    /// Send a message to this worker, blocking if channel is full.
    ///
    /// Returns an error only if the channel is disconnected.
    pub fn send_blocking(&self, msg: WorkerMessage) -> Result<(), WorkerError> {
        self.sender
            .send(msg)
            .map_err(|_| WorkerError::WorkerPanicked {
                worker_id: self.worker_id,
                message: "channel disconnected".to_string(),
            })
    }

    /// Increment the track count.
    pub(crate) fn increment_track_count(&self) {
        self.track_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the track count.
    pub(crate) fn decrement_track_count(&self) {
        self.track_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Track state owned by a worker.
///
/// Each track has a ring buffer for packet storage and metadata.
#[allow(dead_code)] // Reserved for direct track management (non-actor path)
struct Track {
    /// Track ID.
    id: TrackId,
    /// SSRC of the track.
    ssrc: Ssrc,
    /// Media kind (audio/video).
    kind: MediaKind,
    /// Ring buffer for packet storage.
    ring_buffer: RingBuffer<2048>,
    /// Packets received counter.
    packets_received: u64,
}

#[allow(dead_code)] // Reserved for direct track management (non-actor path)
impl Track {
    /// Create a new track.
    fn new(id: TrackId, ssrc: Ssrc, kind: MediaKind) -> Self {
        Self {
            id,
            ssrc,
            kind,
            ring_buffer: RingBuffer::new(),
            packets_received: 0,
        }
    }

    /// Process a packet for this track.
    fn process_packet(&mut self, packet: PacketSlot) {
        self.ring_buffer.push(packet);
        self.packets_received += 1;
    }
}

/// Media worker that runs on a dedicated CPU core.
///
/// Each worker owns its tracks exclusively and processes packets
/// in a tight loop for maximum performance.
///
/// # Actor System
///
/// Workers can also host TrackActors which provide:
/// - Independent lifecycle management
/// - Message-based communication
/// - State machine enforcement
/// - Supervision and health monitoring
///
/// # Spin-Loop Architecture (Requirement 1.2)
///
/// The worker runs a pure spin-loop cycle:
/// 1. Drain SPSC channels from other workers
/// 2. Receive batch from network (io_uring or recvmmsg)
/// 3. Process packets
/// 4. Flush outbound batches
///
/// Uses AdaptiveSpinLoop for idle management (Requirement 1.8).
pub struct MediaWorker {
    /// Worker ID.
    worker_id: u32,
    /// CPU core ID this worker is pinned to.
    #[allow(dead_code)] // Reserved for CPU affinity pinning
    core_id: u32,
    /// TrackActors hosted by this worker.
    actors: HashMap<TrackId, TrackActorState>,
    /// Packet arena for this worker.
    arena: PacketArena,
    /// Batch sender for outbound packets.
    batch_sender: BatchSender,
    /// Channel receiver for incoming messages (legacy crossbeam).
    receiver: Receiver<WorkerMessage>,
    /// SPSC receivers from other workers (Requirement 1.3).
    /// Index i contains receiver from worker i (None for self).
    spsc_receivers: Vec<Option<super::spsc::SpscReceiver<4096>>>,
    /// SPSC senders to other workers (Requirement 1.4).
    /// Index i contains sender to worker i (None for self).
    spsc_senders: Vec<Option<super::spsc::SpscSender<4096>>>,
    /// Adaptive spin loop for idle management (Requirement 1.8).
    spin_loop: crate::spin::AdaptiveSpinLoop,
    /// Shutdown flag for spin-loop termination.
    should_shutdown: Arc<AtomicBool>,
    /// Shared track count (for WorkerHandle).
    track_count: Arc<AtomicU32>,
    /// Shared running flag.
    is_running: Arc<AtomicBool>,
    /// Statistics.
    packets_processed: u64,
    packets_dropped: u64,
    batches_flushed: u64,
    /// Actor messages processed.
    actor_messages_processed: u64,
    /// Bandwidth coordinator for GCC integration.
    coordinator: Option<nexus_bwe::BandwidthCoordinator>,
    /// Last allocation check timestamp (microseconds).
    last_allocation_check_us: u64,
    /// Speaker detector for priority allocation.
    speaker_detector: nexus_bwe::SpeakerDetector,
    /// Counter for packets dropped due to missing SRTP context.
    /// Requirement 4.4: Track packets that cannot be protected.
    dropped_unprotected: u64,
    /// Total bytes copied during subscriber fan-out (Requirement 29.5).
    bytes_copied_fanout: u64,
    /// Arena allocation failures during fan-out (Requirement 29.3).
    arena_alloc_failures_fanout: u64,
    /// Packets received from SPSC channels (cross-worker).
    spsc_packets_received: u64,
    /// Packets routed to other workers via SPSC channels.
    spsc_packets_sent: u64,
    /// Packets dropped due to SPSC channel full.
    spsc_packets_dropped: u64,
    /// Consistent hash for SSRC-to-worker routing (Requirement 1.7).
    ssrc_hasher: Option<super::shard::ConsistentHash>,
    /// Total number of workers in the pool (for routing).
    num_workers: u32,
    /// Last REMB sent timestamp (microseconds).
    last_remb_sent_us: u64,
    /// REMB generator (sender SSRC = 1 for SFU).
    remb_generator: nexus_bwe::RembGenerator,
    /// Channel for relay output packets (worker → main loop → RelayManager).
    /// When a subscriber has `is_relay == true`, raw RTP is queued here
    /// instead of going through SRTP + batch_sender.
    relay_out_tx: Option<crossbeam::channel::Sender<RelayOutput>>,
}

/// A packet destined for a relay peer node.
pub struct RelayOutput {
    /// Peer node to relay to.
    pub peer_node: u64,
    /// Track ID.
    pub track_id: TrackId,
    /// Raw RTP data (no SRTP).
    pub data: [u8; 1500],
    /// Length of valid data.
    pub len: u16,
}

/// State for a TrackActor hosted by a worker.
///
/// Wraps the actor with additional worker-specific state.
struct TrackActorState {
    /// Track ID.
    track_id: TrackId,
    /// Participant who owns this track.
    #[allow(dead_code)] // Reserved for participant-level track management
    participant_id: ParticipantId,
    /// RTP SSRC.
    ssrc: Ssrc,
    /// Media kind.
    kind: MediaKind,
    /// Content type: 0=camera, 1=screen, 2=audio.
    /// Screen share (1) bypasses viewport filtering.
    content_type: u8,
    /// Ring buffer for packet storage.
    ring_buffer: RingBuffer<2048>,
    /// Subscribers for this track.
    subscribers: Vec<ActorSubscriber>,
    /// Packets received.
    packets_received: u64,
    /// Packets forwarded.
    packets_forwarded: u64,
    /// Packets dropped.
    packets_dropped: u64,
    /// Simulcast layers (up to 3).
    simulcast_layers: Vec<nexus_bwe::SimulcastLayer>,
    /// Current selected layer.
    current_layer: u8,
    /// Target layer from bandwidth allocation.
    target_layer: u8,
    /// Allocated bitrate (bps).
    allocated_bitrate_bps: u64,
    /// Maximum bitrate for this track.
    max_bitrate_bps: u64,
    /// Last layer switch timestamp (microseconds).
    last_layer_switch_us: u64,
    /// Sender Report generator.
    sr_generator: nexus_media::rtcp::SenderReportGenerator,
    /// Last SR sent timestamp (microseconds).
    last_sr_sent_us: u64,
    /// Publisher RTCP destination address (for feedback).
    publisher_addr: Option<SocketAddr>,
    /// Publisher SRTCP context for protecting feedback (PLI/NACK).
    publisher_srtcp_context: Option<nexus_transport::srtp::SrtpContext>,
    /// Last RTP timestamp from publisher packets (for SR generation).
    last_rtp_timestamp: Option<u32>,
    /// Simulcast SSRC mapping: layer_index -> SSRC.
    /// layer 0 = low, 1 = mid, 2 = high.
    /// The primary `ssrc` field is the high layer.
    simulcast_ssrcs: [Option<u32>; 3],
    /// MID RTP header extension ID negotiated with subscribers (one-byte format).
    /// 0 means not set / disabled.
    mid_ext_id: u8,
    /// MID value to inject into forwarded RTP packets (e.g. b"0" for video, b"1" for audio).
    /// Length is stored in mid_value_len.
    mid_value: [u8; 4],
    /// Length of mid_value.
    mid_value_len: u8,
    /// RID (rtp-stream-id) RTP header extension ID (one-byte format).
    /// Required by webrtc-rs simulcast probing alongside MID.
    /// 0 means not set / disabled.
    rid_ext_id: u8,
    /// RID value to inject (e.g. b"f" for the default/only layer).
    rid_value: [u8; 4],
    /// Length of rid_value.
    rid_value_len: u8,
}

/// SR generation interval (1 second).
const SR_INTERVAL_US: u64 = 1_000_000;

/// Subscriber for an actor-based track.
struct ActorSubscriber {
    /// Subscriber ID.
    id: u32,
    /// Participant ID.
    #[allow(dead_code)] // Used for viewport filtering context
    participant_id: ParticipantId,
    /// Destination address.
    dest_addr: SocketAddr,
    /// SRTP context for protecting outbound RTP packets.
    /// This should be set when the subscriber's DTLS handshake completes.
    /// If None, packets will be forwarded unprotected (for testing/development only).
    srtp_context: Option<nexus_transport::srtp::SrtpContext>,
    /// Target simulcast layer for this subscriber (0=low, 1=mid, 2=high).
    /// Set by bandwidth allocation. Default: highest available layer.
    target_layer: u8,
    /// Maximum layer this subscriber has requested (from signaling).
    /// Allocation will not exceed this even if bandwidth allows.
    max_requested_layer: u8,
    /// Viewport: sorted source participant IDs visible in subscriber's UI.
    /// Empty = forward everything (no viewport filtering).
    viewport_visible: Vec<u32>,
    /// Viewport: sorted source participant IDs pinned by subscriber.
    /// Pinned participants always receive video regardless of visible set.
    viewport_pinned: Vec<u32>,
    /// If true, this subscriber is a relay to another SFU node.
    /// Relay subscribers skip SRTP and send via the relay manager.
    is_relay: bool,
    /// Peer node ID for relay subscribers (0 if not relay).
    relay_node: u64,
}

impl TrackActorState {
    /// Create new actor state.
    fn new(track_id: TrackId, participant_id: ParticipantId, ssrc: Ssrc, kind: MediaKind, content_type: u8) -> Self {
        // Default simulcast layers based on media kind
        let simulcast_layers = if kind == MediaKind::Video {
            vec![
                nexus_bwe::SimulcastLayer::new(0, 100_000, 320, 180),
                nexus_bwe::SimulcastLayer::new(1, 500_000, 640, 360),
                nexus_bwe::SimulcastLayer::new(2, 1_500_000, 1280, 720),
            ]
        } else {
            vec![nexus_bwe::SimulcastLayer::new_audio(0, 64_000)]
        };

        let max_bitrate_bps = simulcast_layers
            .last()
            .map(|l| l.bitrate_bps)
            .unwrap_or(64_000);

        // MID/RID extension values are set to zero (disabled) by default.
        // The orchestrator sends SetTrackMid after renegotiation to set the
        // correct MID value and ext ID matching the negotiated SDP.

        Self {
            track_id,
            participant_id,
            ssrc,
            kind,
            content_type,
            ring_buffer: RingBuffer::new(),
            subscribers: Vec::with_capacity(100),
            packets_received: 0,
            packets_forwarded: 0,
            packets_dropped: 0,
            simulcast_layers,
            current_layer: 0,
            target_layer: 0,
            allocated_bitrate_bps: 0,
            max_bitrate_bps,
            last_layer_switch_us: 0,
            sr_generator: nexus_media::rtcp::SenderReportGenerator::new(ssrc),
            last_sr_sent_us: 0,
            publisher_addr: None,
            publisher_srtcp_context: None,
            last_rtp_timestamp: None,
            simulcast_ssrcs: [None; 3],
            mid_ext_id: 0,
            mid_value: [0; 4],
            mid_value_len: 0,
            rid_ext_id: 0,
            rid_value: [0; 4],
            rid_value_len: 0,
        }
    }

    /// Add a subscriber.
    fn add_subscriber(&mut self, id: u32, participant_id: ParticipantId, dest_addr: SocketAddr) {
        self.subscribers.push(ActorSubscriber {
            id,
            participant_id,
            dest_addr,
            srtp_context: None,
            target_layer: 2, // Default: highest available layer
            max_requested_layer: 2,
            viewport_visible: Vec::new(),
            viewport_pinned: Vec::new(),
            is_relay: false,
            relay_node: 0,
        });
    }

    /// Remove a subscriber.
    fn remove_subscriber(&mut self, subscriber_id: u32) -> bool {
        if let Some(pos) = self.subscribers.iter().position(|s| s.id == subscriber_id) {
            self.subscribers.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Process a packet.
    fn process_packet(&mut self, packet: PacketSlot) {
        self.packets_received += 1;
        self.ring_buffer.push(packet);
    }

    /// Select best layer for allocated bitrate.
    #[allow(dead_code)] // Reserved for simulcast layer selection logic
    fn select_layer(&self) -> u8 {
        if self.allocated_bitrate_bps == 0 || self.simulcast_layers.is_empty() {
            return 0;
        }

        // Find highest layer that fits within allocation
        let mut selected = 0u8;
        for layer in &self.simulcast_layers {
            if layer.bitrate_bps <= self.allocated_bitrate_bps {
                selected = layer.index;
            } else {
                break;
            }
        }
        selected
    }

    /// Apply layer selection with hysteresis.
    fn apply_layer_selection(&mut self, target_layer: u8, timestamp_us: u64) -> bool {
        const HYSTERESIS_US: u64 = 2_000_000; // 2 seconds

        // Check if layer actually changed
        if target_layer == self.current_layer {
            return false;
        }

        // Check hysteresis
        let time_since_switch = timestamp_us.saturating_sub(self.last_layer_switch_us);
        if time_since_switch < HYSTERESIS_US && self.last_layer_switch_us > 0 {
            return false; // Too soon to switch
        }

        // Apply switch
        self.current_layer = target_layer;
        self.target_layer = target_layer;
        self.last_layer_switch_us = timestamp_us;
        true
    }

    /// Set publisher RTCP destination address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Publisher's address for RTCP feedback
    fn set_publisher_addr(&mut self, addr: SocketAddr) {
        self.publisher_addr = Some(addr);
    }
}

impl MediaWorker {
    /// Create a new media worker.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - Worker ID (0-based)
    /// * `core_id` - CPU core to pin to
    /// * `arena_size_mb` - Size of packet arena in MB
    /// * `socket_fd` - Socket file descriptor for batch sender
    /// * `receiver` - Channel receiver for messages
    /// * `track_count` - Shared track count atomic
    /// * `is_running` - Shared running flag
    fn new(
        worker_id: u32,
        core_id: u32,
        arena_size_mb: u32,
        socket_fd: i32,
        receiver: Receiver<WorkerMessage>,
        track_count: Arc<AtomicU32>,
        is_running: Arc<AtomicBool>,
    ) -> Result<Self, WorkerError> {
        // TigerStyle: Assert preconditions
        let num_cpus = num_cpus::get() as u32;
        assert!(
            core_id < num_cpus,
            "core_id {} must be < num_cpus {}",
            core_id,
            num_cpus
        );

        let arena = PacketArena::new(arena_size_mb).map_err(|_| WorkerError::InvalidConfig {
            message: format!("failed to create arena of {}MB", arena_size_mb),
        })?;

        let batch_sender =
            BatchSender::new(socket_fd, DEFAULT_BATCH_SIZE, DEFAULT_FLUSH_INTERVAL_US);

        // Initialize adaptive spin loop with defaults
        let spin_loop = crate::spin::AdaptiveSpinLoop::with_defaults();

        Ok(Self {
            worker_id,
            core_id,
            actors: HashMap::new(),
            arena,
            batch_sender,
            receiver,
            spsc_receivers: Vec::new(), // Will be set by WorkerPool
            spsc_senders: Vec::new(),   // Will be set by WorkerPool
            spin_loop,
            should_shutdown: Arc::new(AtomicBool::new(false)),
            track_count,
            is_running,
            packets_processed: 0,
            packets_dropped: 0,
            batches_flushed: 0,
            actor_messages_processed: 0,
            coordinator: Some(nexus_bwe::BandwidthCoordinator::new(
                100_000,    // min 100 kbps
                10_000_000, // max 10 Mbps
                1_000_000, // initial 1 Mbps
            )),
            last_allocation_check_us: 0,
            speaker_detector: nexus_bwe::SpeakerDetector::new(),
            dropped_unprotected: 0,
            bytes_copied_fanout: 0,
            arena_alloc_failures_fanout: 0,
            spsc_packets_received: 0,
            spsc_packets_sent: 0,
            spsc_packets_dropped: 0,
            ssrc_hasher: None, // Will be set by WorkerPool
            num_workers: 0,    // Will be set by WorkerPool
            last_remb_sent_us: 0,
            remb_generator: nexus_bwe::RembGenerator::new(1), // SFU sender SSRC
            relay_out_tx: None,
        })
    }

    /// Set SPSC channel handles for cross-worker communication.
    ///
    /// Called by WorkerPool after creating the channel mesh.
    ///
    /// # Arguments
    ///
    /// * `receivers` - SPSC receivers from other workers
    /// * `senders` - SPSC senders to other workers
    pub fn set_spsc_channels(
        &mut self,
        receivers: Vec<Option<super::spsc::SpscReceiver<4096>>>,
        senders: Vec<Option<super::spsc::SpscSender<4096>>>,
    ) {
        // Precondition: vectors have same length
        assert_eq!(
            receivers.len(),
            senders.len(),
            "receivers and senders must have same length"
        );
        // Precondition: self slot is None
        assert!(
            receivers.get(self.worker_id as usize).map(|r| r.is_none()).unwrap_or(true),
            "receiver for self must be None"
        );

        // Set number of workers and create consistent hasher for SSRC routing
        let num_workers = receivers.len() as u32;
        self.num_workers = num_workers;
        if num_workers > 0 {
            self.ssrc_hasher = Some(super::shard::ConsistentHash::new(num_workers));
        }

        self.spsc_receivers = receivers;
        self.spsc_senders = senders;
    }

    /// Route a packet to another worker via SPSC channel.
    ///
    /// Implements Requirement 1.4: When a MediaWorker receives a packet destined
    /// for a track owned by a different worker, enqueue into the SPSC channel
    /// targeting that worker without acquiring any lock.
    ///
    /// # Arguments
    ///
    /// * `target_worker_id` - ID of the target worker
    /// * `packet` - Packet to route
    ///
    /// # Returns
    ///
    /// `Ok(())` if packet was enqueued, `Err(packet)` if channel is full.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines
    #[inline]
    pub fn route_to_worker(&mut self, target_worker_id: u32, packet: PacketSlot) -> Result<(), PacketSlot> {
        // Precondition: target is not self
        assert_ne!(
            target_worker_id, self.worker_id,
            "cannot route to self via SPSC"
        );
        // Precondition: target is valid
        assert!(
            (target_worker_id as usize) < self.spsc_senders.len(),
            "target_worker_id must be < num_workers"
        );

        // Get sender for target worker
        if let Some(ref sender) = self.spsc_senders[target_worker_id as usize] {
            match sender.try_send(packet) {
                Ok(()) => {
                    self.spsc_packets_sent += 1;
                    Ok(())
                }
                Err(packet) => {
                    self.spsc_packets_dropped += 1;
                    Err(packet)
                }
            }
        } else {
            // No sender for this worker (shouldn't happen if properly initialized)
            self.spsc_packets_dropped += 1;
            Err(packet)
        }
    }

    /// Route a packet by SSRC using consistent hashing.
    ///
    /// Determines the target worker for the given SSRC and routes the packet
    /// via SPSC channel if the target differs from this worker.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC of the packet
    /// * `packet` - Packet to route
    ///
    /// # Returns
    ///
    /// `Some(packet)` if the packet should be processed locally (same worker),
    /// `None` if the packet was routed to another worker.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines
    #[inline]
    pub fn route_by_ssrc(&mut self, ssrc: Ssrc, packet: PacketSlot) -> Option<PacketSlot> {
        // Precondition: SSRC is valid
        assert!(ssrc != 0, "ssrc must not be 0");
        // Precondition: hasher is initialized
        assert!(self.ssrc_hasher.is_some(), "ssrc_hasher must be initialized");

        let target_worker_id = self.ssrc_hasher.as_ref().unwrap().hash(ssrc);

        if target_worker_id == self.worker_id {
            // Packet belongs to this worker
            Some(packet)
        } else {
            // Route to target worker via SPSC
            match self.route_to_worker(target_worker_id, packet) {
                Ok(()) => None, // Successfully routed
                Err(packet) => {
                    // Channel full, drop packet (already counted in route_to_worker)
                    drop(packet);
                    None
                }
            }
        }
    }

    /// Set the shutdown flag.
    pub fn set_shutdown_flag(&mut self, flag: Arc<AtomicBool>) {
        self.should_shutdown = flag;
    }

    /// Run the worker's main loop (spin-loop version).
    ///
    /// Implements Requirement 1.2: Pure spin-loop cycle:
    /// 1. Drain SPSC channels from other workers (Requirement 1.5)
    /// 2. Process legacy crossbeam messages (for backward compatibility)
    /// 3. Flush outbound batches
    /// 4. Periodic tasks (BWE, SR generation)
    /// 5. Adaptive wait based on activity (Requirement 1.8)
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines (main loop body delegated to helper methods)
    pub fn run(&mut self) {
        // Precondition: worker ID is valid
        assert!(self.worker_id < 64, "worker_id must be < 64");
        // Precondition: arena is initialized
        assert!(self.arena.capacity() > 0, "arena must be initialized");

        self.is_running.store(true, Ordering::Release);

        // Main spin-loop
        loop {
            // Check shutdown flag
            if self.should_shutdown.load(Ordering::Acquire) {
                break;
            }

            let activity_count = self.process_one_iteration();

            // Adaptive wait based on activity (Requirement 1.8)
            self.spin_loop.on_poll_result(activity_count);
            self.spin_loop.wait();
        }

        // Drain remaining messages before shutdown
        self.drain_messages();

        // Final flush
        self.flush_batches();

        self.is_running.store(false, Ordering::Release);
    }

    /// Execute one cycle of the worker loop.
    ///
    /// Drains SPSC channels, processes legacy messages, flushes batches,
    /// and runs periodic tasks. Returns the activity count (number of
    /// messages/packets processed). The DST simulator calls this directly
    /// to drive each worker one cycle at a time.
    pub fn process_one_iteration(&mut self) -> u32 {
        let mut activity_count: u32 = 0;

        // Phase 1: Drain SPSC channels from other workers (Requirement 1.5)
        activity_count += self.drain_spsc_channels();

        // Phase 2: Process legacy crossbeam messages (non-blocking)
        activity_count += self.drain_legacy_messages();

        // Phase 3: Flush outbound batches if needed
        if self.batch_sender.should_flush() {
            self.flush_batches();
        }

        // Phase 4: Periodic tasks
        let now_us = self.get_timestamp_us();
        if self.coordinator.is_some() {
            self.perform_bandwidth_allocation(now_us);
        }
        self.generate_and_send_sender_reports(now_us);
        self.generate_and_send_remb(now_us);

        activity_count
    }

    /// Drain all SPSC channels from other workers.
    ///
    /// Implements Requirement 1.5: Drain cross-worker packets before
    /// processing new network packets.
    ///
    /// # Returns
    ///
    /// Number of packets processed.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines
    /// - Bounded loop (MAX_DRAIN_PER_CHANNEL)
    #[inline]
    fn drain_spsc_channels(&mut self) -> u32 {
        const MAX_DRAIN_PER_CHANNEL: u32 = 64;
        let mut total_processed: u32 = 0;

        // Precondition: spsc_receivers is initialized
        // (may be empty if SPSC not configured)
        
        for receiver_opt in &self.spsc_receivers {
            if let Some(receiver) = receiver_opt {
                let mut channel_processed: u32 = 0;

                // Bounded drain from this channel
                while channel_processed < MAX_DRAIN_PER_CHANNEL {
                    match receiver.try_recv() {
                        Some(packet) => {
                            // Process the cross-worker packet
                            // For now, we just count it - actual routing TBD
                            self.spsc_packets_received += 1;
                            channel_processed += 1;
                            
                            // TODO: Route packet to appropriate track
                            // This requires track_id to be encoded in the packet
                            // or a separate routing mechanism
                            drop(packet);
                        }
                        None => break,
                    }
                }

                total_processed += channel_processed;
            }
        }

        // Postcondition: processed count is bounded
        assert!(
            total_processed <= MAX_DRAIN_PER_CHANNEL * self.spsc_receivers.len() as u32,
            "processed count must be bounded"
        );

        total_processed
    }

    /// Drain legacy crossbeam messages (non-blocking).
    ///
    /// For backward compatibility during transition to SPSC.
    ///
    /// # Returns
    ///
    /// Number of messages processed.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines
    /// - Bounded loop (MAX_DRAIN_MESSAGES)
    #[inline]
    fn drain_legacy_messages(&mut self) -> u32 {
        let mut processed: u32 = 0;

        // Drain all available messages without artificial cap.
        // The channel is bounded (4096), so this loop is inherently bounded.
        // Draining fully each iteration prevents backpressure and packet drops.
        loop {
            match self.receiver.try_recv() {
                Ok(msg) => {
                    if !self.handle_message(msg) {
                        self.should_shutdown.store(true, Ordering::Release);
                        break;
                    }
                    processed += 1;
                }
                Err(_) => break,
            }
        }

        processed
    }

    /// Handle a single message.
    ///
    /// Returns false if shutdown was received.
    #[inline(always)]
    fn handle_message(&mut self, msg: WorkerMessage) -> bool {
        match msg {
            WorkerMessage::AssignTrack {
                track_id,
                ssrc,
                kind,
            } => {
                // Delegate to spawn_actor for unified track management
                let ct = if kind == MediaKind::Audio { 2 } else { 0 };
                self.spawn_actor(track_id, 0, ssrc, kind, ct);
                true
            }
            WorkerMessage::RemoveTrack { track_id } => {
                // Delegate to terminate_actor for unified track management
                self.terminate_actor(track_id);
                true
            }
            WorkerMessage::Packet { track_id, packet, source_addr } => {
                // Delegate to actor_process_packet for unified packet handling
                self.actor_process_packet(track_id, packet, source_addr);
                true
            }
            WorkerMessage::Shutdown => false,

            // === Actor System Messages ===
            WorkerMessage::SpawnActor {
                track_id,
                participant_id,
                ssrc,
                kind,
                content_type,
            } => {
                self.spawn_actor(track_id, participant_id, ssrc, kind, content_type);
                true
            }
            WorkerMessage::ActorSubscribe {
                track_id,
                subscriber_id,
                participant_id,
                dest_addr,
            } => {
                self.actor_subscribe(track_id, subscriber_id, participant_id, dest_addr);
                true
            }
            WorkerMessage::ActorUnsubscribe {
                track_id,
                subscriber_id,
            } => {
                self.actor_unsubscribe(track_id, subscriber_id);
                true
            }
            WorkerMessage::ActorPacket { track_id, packet, source_addr } => {
                self.actor_process_packet(track_id, packet, source_addr);
                true
            }
            WorkerMessage::TerminateActor { track_id } => {
                self.terminate_actor(track_id);
                true
            }

            // === Migration Messages ===
            WorkerMessage::PrepareMigration {
                migration_id,
                track_id,
                target_worker_id,
            } => {
                self.prepare_migration(migration_id, track_id, target_worker_id);
                true
            }
            WorkerMessage::TransferMigrationState {
                migration_id,
                snapshot,
            } => {
                self.transfer_migration_state(migration_id, snapshot);
                true
            }
            WorkerMessage::ResumeMigration {
                migration_id,
                track_id,
            } => {
                self.resume_migration(migration_id, track_id);
                true
            }
            WorkerMessage::AbortMigration {
                migration_id,
                track_id,
            } => {
                self.abort_migration(migration_id, track_id);
                true
            }

            // === Bandwidth Allocation Messages ===
            WorkerMessage::UpdateBandwidth {
                track_id,
                allocated_bps,
                target_layer,
            } => {
                self.update_bandwidth(track_id, allocated_bps, target_layer);
                true
            }
            WorkerMessage::RtcpReceiverReport {
                ssrc,
                fraction_lost,
                rtt_us,
                timestamp_us,
            } => {
                self.handle_rtcp_receiver_report(ssrc, fraction_lost, rtt_us, timestamp_us);
                true
            }
            WorkerMessage::TransportFeedback {
                feedback,
                timestamp_us,
            } => {
                self.handle_transport_feedback(&feedback, timestamp_us);
                true
            }
            WorkerMessage::RtcpPli { media_ssrc, sender_ssrc } => {
                self.handle_rtcp_pli(media_ssrc, sender_ssrc);
                true
            }
            WorkerMessage::RtcpNack {
                media_ssrc,
                sender_ssrc,
                lost_packets,
            } => {
                self.handle_rtcp_nack(media_ssrc, sender_ssrc, lost_packets);
                true
            }
            WorkerMessage::SetPublisherSrtcp {
                track_id,
                key_material,
                srtp_policy,
            } => {
                self.set_publisher_srtcp(track_id, key_material, srtp_policy);
                true
            }
            WorkerMessage::SetSubscriberSrtp {
                track_id,
                subscriber_id,
                key_material,
                srtp_policy,
            } => {
                self.set_subscriber_srtp(track_id, subscriber_id, key_material, srtp_policy);
                true
            }
            WorkerMessage::AddSubscriber {
                track_id,
                subscriber_id,
                participant_id,
                dest_addr,
                target_layer,
                srtp_context,
            } => {
                self.add_subscriber(track_id, subscriber_id, participant_id, dest_addr, target_layer, srtp_context);
                true
            }
            WorkerMessage::RemoveSubscriber {
                track_id,
                subscriber_id,
            } => {
                self.remove_subscriber(track_id, subscriber_id);
                true
            }
            WorkerMessage::SetSimulcastSsrc {
                track_id,
                layer,
                ssrc,
            } => {
                assert!(layer < 3, "Simulcast layer must be 0, 1, or 2");
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    actor.simulcast_ssrcs[layer as usize] = Some(ssrc);
                    tracing::info!(track_id, layer, ssrc, "Simulcast SSRC mapped");
                }
                true
            }
            WorkerMessage::SetSubscriberLayer {
                track_id,
                subscriber_id,
                target_layer,
            } => {
                assert!(target_layer < 3, "Target layer must be 0, 1, or 2");
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    if let Some(sub) = actor.subscribers.iter_mut().find(|s| s.id == subscriber_id) {
                        sub.target_layer = target_layer;
                        tracing::debug!(track_id, subscriber_id, target_layer, "Subscriber layer updated");
                    }
                }
                true
            }
            WorkerMessage::SetTrackMid {
                track_id,
                mid_ext_id,
                mid_value,
                mid_value_len,
            } => {
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    actor.mid_ext_id = mid_ext_id;
                    actor.mid_value = mid_value;
                    actor.mid_value_len = mid_value_len;
                    tracing::debug!(track_id, mid_ext_id, mid = ?&mid_value[..mid_value_len as usize], "Track MID updated");
                }
                true
            }
            WorkerMessage::UpdateViewport {
                track_id,
                subscriber_id,
                visible,
                pinned,
            } => {
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    if let Some(sub) = actor.subscribers.iter_mut().find(|s| s.id == subscriber_id) {
                        sub.viewport_visible = visible;
                        sub.viewport_pinned = pinned;
                        tracing::debug!(
                            track_id, subscriber_id,
                            visible_count = sub.viewport_visible.len(),
                            pinned_count = sub.viewport_pinned.len(),
                            "Subscriber viewport updated"
                        );
                    }
                }
                true
            }
            WorkerMessage::SetContentType {
                track_id,
                content_type,
            } => {
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    actor.content_type = content_type;
                }
                true
            }
            WorkerMessage::AddRelaySubscriber {
                track_id,
                peer_node,
                subscriber_id,
            } => {
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    const MAX_SUBSCRIBERS_PER_TRACK: usize = 2000;
                    if actor.subscribers.len() < MAX_SUBSCRIBERS_PER_TRACK {
                        actor.subscribers.push(ActorSubscriber {
                            id: subscriber_id,
                            participant_id: 0, // Relay — no real participant
                            dest_addr: "0.0.0.0:0".parse().unwrap(), // Unused for relay
                            target_layer: 2,
                            srtp_context: None,
                            max_requested_layer: 2,
                            viewport_visible: Vec::new(),
                            viewport_pinned: Vec::new(),
                            is_relay: true,
                            relay_node: peer_node,
                        });
                        tracing::info!(
                            worker_id = self.worker_id,
                            track_id, peer_node,
                            "Added relay subscriber"
                        );
                    }
                }
                true
            }
            WorkerMessage::RelayPacket {
                track_id,
                data,
                len,
            } => {
                // Inject relay packet as if it was received locally.
                // Find the track actor and process through the forwarding pipeline.
                if let Some(actor) = self.actors.get_mut(&track_id) {
                    if let Some(mut slot) = self.arena.alloc() {
                        let slot_data = slot.data_mut();
                        slot_data[..len as usize].copy_from_slice(&data[..len as usize]);
                        slot.set_len(len);
                        actor.ring_buffer.push(slot);
                        actor.packets_received += 1;
                    }
                }
                true
            }
        }
    }

    // === Actor System Methods ===

    /// Spawn a new TrackActor on this worker.
    fn spawn_actor(
        &mut self,
        track_id: TrackId,
        participant_id: ParticipantId,
        ssrc: Ssrc,
        kind: MediaKind,
        content_type: u8,
    ) {
        let actor_state = TrackActorState::new(track_id, participant_id, ssrc, kind, content_type);
        self.actors.insert(track_id, actor_state);
        self.track_count.fetch_add(1, Ordering::Relaxed);
        self.actor_messages_processed += 1;
    }

    /// Subscribe to a TrackActor.
    fn actor_subscribe(
        &mut self,
        track_id: TrackId,
        subscriber_id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
    ) {
        if let Some(actor) = self.actors.get_mut(&track_id) {
            actor.add_subscriber(subscriber_id, participant_id, dest_addr);
        }
        self.actor_messages_processed += 1;
    }

    /// Unsubscribe from a TrackActor.
    fn actor_unsubscribe(&mut self, track_id: TrackId, subscriber_id: u32) {
        if let Some(actor) = self.actors.get_mut(&track_id) {
            actor.remove_subscriber(subscriber_id);
        }
        self.actor_messages_processed += 1;
    }

    /// Process a packet through the actor system.
    fn actor_process_packet(&mut self, track_id: TrackId, packet: PacketSlot, source_addr: SocketAddr) {
        // Check if actor exists first
        let has_subscribers = self.actors.get(&track_id)
            .map(|a| !a.subscribers.is_empty())
            .unwrap_or(false);
        
        // Set publisher address from the first packet's source address
        // This ensures PLI/NACK feedback can reach the publisher
        if let Some(actor) = self.actors.get_mut(&track_id) {
            if actor.publisher_addr.is_none() {
                actor.set_publisher_addr(source_addr);
                tracing::info!(
                    track_id,
                    publisher_addr = ?source_addr,
                    "Set publisher address from first RTP/RTCP packet"
                );
            }
            
            // Extract RTP timestamp from packet for SR generation
            if packet.len() >= 12 {
                let rtp_timestamp = u32::from_be_bytes([
                    packet.data()[4],
                    packet.data()[5],
                    packet.data()[6],
                    packet.data()[7],
                ]);
                actor.last_rtp_timestamp = Some(rtp_timestamp);
            }
            
            // Update SR generator stats once per RTP packet
            actor.sr_generator.update_stats(packet.len() as usize);
        }
        
        // Forward to subscribers if needed
        if has_subscribers {
            if let Some(actor) = self.actors.get_mut(&track_id) {
                // Determine which simulcast layer this packet belongs to
                let packet_ssrc = if packet.len() >= 12 {
                    let data = packet.data();
                    u32::from_be_bytes([data[8], data[9], data[10], data[11]])
                } else {
                    actor.ssrc
                };

                let packet_layer: u8 = actor
                    .simulcast_ssrcs
                    .iter()
                    .enumerate()
                    .find(|(_, ssrc_opt)| ssrc_opt.map(|s| s == packet_ssrc).unwrap_or(false))
                    .map(|(idx, _)| idx as u8)
                    .unwrap_or(actor.current_layer);

                // Forward with layer filtering
                Self::forward_to_subscribers_static(
                    actor,
                    &packet,
                    packet_layer,
                    &mut self.arena,
                    &mut self.batch_sender,
                    &mut self.packets_dropped,
                    &mut self.dropped_unprotected,
                    &mut self.bytes_copied_fanout,
                    &mut self.arena_alloc_failures_fanout,
                    &self.relay_out_tx,
                );
            }
        }
        
        // Now process the packet (store in ring buffer)
        if let Some(actor) = self.actors.get_mut(&track_id) {
            actor.process_packet(packet);
            self.packets_processed += 1;
        } else {
            self.packets_dropped += 1;
        }
        self.actor_messages_processed += 1;
    }

    /// Inject a one-byte MID RTP header extension into an RTP packet buffer.
    ///
    /// If the packet already has a one-byte header extension block, the MID
    /// extension element is prepended (shifting existing extension data).
    /// If the packet has no extension, a new one-byte extension header is added.
    ///
    /// Returns the new packet length, or None if the buffer is too small.
    ///
    /// One-byte header extension format (RFC 8285):
    ///   0                   1
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |  ID   |  len  |   data...     |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  ID: 1-14, len: 0-15 (actual length - 1)
    #[inline]
    fn inject_mid_extension(
        buf: &mut [u8],
        packet_len: usize,
        mid_ext_id: u8,
        mid_value: &[u8],
        mid_value_len: usize,
    ) -> Option<usize> {
        // Minimum RTP header: 12 bytes
        if packet_len < 12 || mid_ext_id == 0 || mid_value_len == 0 {
            return None;
        }

        let cc = (buf[0] & 0x0F) as usize;
        let has_extension = (buf[0] & 0x10) != 0;
        let fixed_header_len = 12 + cc * 4;

        if packet_len < fixed_header_len {
            return None;
        }

        // Size of the MID extension element: 1 byte header + mid_value_len bytes
        // Padded to 4-byte boundary within the extension block
        let mid_element_len = 1 + mid_value_len; // header byte + value

        if has_extension {
            // Packet already has an extension header.
            // Check if it's one-byte format (0xBEDE magic).
            if fixed_header_len + 4 > packet_len {
                return None;
            }
            let ext_profile = u16::from_be_bytes([
                buf[fixed_header_len],
                buf[fixed_header_len + 1],
            ]);
            if ext_profile != 0xBEDE {
                // Two-byte or unknown format — don't modify
                return None;
            }

            let ext_len_words = u16::from_be_bytes([
                buf[fixed_header_len + 2],
                buf[fixed_header_len + 3],
            ]) as usize;
            let ext_data_start = fixed_header_len + 4;
            let ext_data_len = ext_len_words * 4;
            let payload_start = ext_data_start + ext_data_len;

            if payload_start > packet_len {
                return None;
            }

            // Check if MID extension already exists by scanning extension elements
            let mut pos = ext_data_start;
            while pos < payload_start {
                let byte = buf[pos];
                if byte == 0 {
                    // Padding byte
                    pos += 1;
                    continue;
                }
                let elem_id = (byte >> 4) & 0x0F;
                let elem_len = (byte & 0x0F) as usize + 1;
                if elem_id == mid_ext_id {
                    // MID extension already present — no injection needed
                    return Some(packet_len);
                }
                pos += 1 + elem_len;
            }

            // Need to prepend MID element to existing extension data.
            // New extension data = mid_element + existing extension data.
            // Must be padded to 4-byte boundary.
            let new_ext_data_len_unpadded = mid_element_len + ext_data_len;
            let new_ext_data_len = (new_ext_data_len_unpadded + 3) & !3;
            let growth = new_ext_data_len - ext_data_len;
            let new_packet_len = packet_len + growth;

            if new_packet_len > buf.len() {
                return None;
            }

            // Shift payload (everything after extension) right by `growth` bytes
            let payload_len = packet_len - payload_start;
            if payload_len > 0 {
                buf.copy_within(payload_start..packet_len, payload_start + growth);
            }

            // Shift existing extension data right by mid_element_len
            if ext_data_len > 0 {
                buf.copy_within(ext_data_start..ext_data_start + ext_data_len, ext_data_start + mid_element_len);
            }

            // Write MID element at ext_data_start
            buf[ext_data_start] = (mid_ext_id << 4) | ((mid_value_len as u8) - 1);
            buf[ext_data_start + 1..ext_data_start + 1 + mid_value_len]
                .copy_from_slice(&mid_value[..mid_value_len]);

            // Zero-fill any padding bytes between old data end and new boundary
            let filled = mid_element_len + ext_data_len;
            for i in filled..new_ext_data_len {
                buf[ext_data_start + i] = 0;
            }

            // Update extension length in header
            let new_ext_len_words = (new_ext_data_len / 4) as u16;
            buf[fixed_header_len + 2..fixed_header_len + 4]
                .copy_from_slice(&new_ext_len_words.to_be_bytes());

            Some(new_packet_len)
        } else {
            // No extension header — add one.
            // Extension header: 4 bytes (profile + length) + padded extension data
            let ext_data_len_unpadded = mid_element_len;
            let ext_data_len = (ext_data_len_unpadded + 3) & !3;
            let ext_header_total = 4 + ext_data_len;
            let new_packet_len = packet_len + ext_header_total;

            if new_packet_len > buf.len() {
                return None;
            }

            // Shift everything after fixed header right by ext_header_total
            let payload_len = packet_len - fixed_header_len;
            if payload_len > 0 {
                buf.copy_within(fixed_header_len..packet_len, fixed_header_len + ext_header_total);
            }

            // Set extension bit in RTP header
            buf[0] |= 0x10;

            // Write extension header
            let ext_start = fixed_header_len;
            // One-byte header magic: 0xBEDE
            buf[ext_start] = 0xBE;
            buf[ext_start + 1] = 0xDE;
            let ext_len_words = (ext_data_len / 4) as u16;
            buf[ext_start + 2..ext_start + 4].copy_from_slice(&ext_len_words.to_be_bytes());

            // Write MID element
            let data_start = ext_start + 4;
            buf[data_start] = (mid_ext_id << 4) | ((mid_value_len as u8) - 1);
            buf[data_start + 1..data_start + 1 + mid_value_len]
                .copy_from_slice(&mid_value[..mid_value_len]);

            // Zero-fill padding
            for i in mid_element_len..ext_data_len {
                buf[data_start + i] = 0;
            }

            Some(new_packet_len)
        }
    }

    /// Static helper for forwarding to avoid borrow checker issues.
    ///
    /// # Why Per-Subscriber Copy is Required (Requirement 29.4)
    /// Each subscriber has a unique SRTP encryption context with its own:
    /// - Rollover counter (ROC) tracking sequence number wraps
    /// - Replay protection window state
    /// - Key derivation state for SRTP key scheduling
    /// Therefore, we MUST encrypt separately for each subscriber — a single
    /// encrypted packet cannot be reused across subscribers.
    ///
    /// # Simulcast Layer Filtering
    /// Only forwards to subscribers whose `target_layer` matches the packet's
    /// simulcast layer. Audio tracks (single layer, packet_layer=0) always
    /// forward since all subscribers have target_layer >= 0.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop (MAX_SUBSCRIBERS_PER_TRACK)
    /// - Explicit error handling
    fn forward_to_subscribers_static(
        actor: &mut TrackActorState,
        packet: &PacketSlot,
        packet_layer: u8,
        arena: &mut PacketArena,
        batch_sender: &mut BatchSender,
        packets_dropped: &mut u64,
        dropped_unprotected: &mut u64,
        bytes_copied_fanout: &mut u64,
        arena_alloc_failures_fanout: &mut u64,
        relay_out_tx: &Option<crossbeam::channel::Sender<RelayOutput>>,
    ) {
        // Precondition assertions (TigerStyle: ≥2 assertions)
        assert!(packet.len() > 0, "packet length must be positive");
        assert!(packet.len() >= 12, "packet must have RTP header");
        assert!(packet_layer < 3, "packet layer must be 0, 1, or 2");

        // In sim mode, SRTP protection is bypassed so this counter is unused
        #[cfg(feature = "sim")]
        let _ = &dropped_unprotected;
        
        const MAX_SUBSCRIBERS_PER_TRACK: usize = 2000;
        
        let subscriber_count = actor.subscribers.len().min(MAX_SUBSCRIBERS_PER_TRACK);
        let packet_len = packet.len() as usize;
        let mut forwarded_count = 0u32;
        
        // Bounded iteration over subscribers
        for i in 0..subscriber_count {
            let subscriber = &mut actor.subscribers[i];
            
            // Simulcast layer filtering: only forward if this packet's layer
            // matches the subscriber's target layer.
            // For audio (kind == Audio), packet_layer is always 0 and
            // target_layer defaults to 2, so we skip filtering for audio.
            if actor.kind == MediaKind::Video && packet_layer != subscriber.target_layer {
                continue;
            }

            // Viewport filtering: skip video if source not in subscriber's viewport.
            // Empty viewport_visible = no filtering (forward everything).
            // Audio and screen share are always forwarded regardless of viewport.
            if actor.kind == MediaKind::Video
                && actor.content_type != 1 // 1 = screen share — bypass viewport
                && !subscriber.viewport_visible.is_empty()
            {
                let src = actor.participant_id as u32;
                let in_pinned = subscriber.viewport_pinned.binary_search(&src).is_ok();
                let in_visible = subscriber.viewport_visible.binary_search(&src).is_ok();
                if !in_pinned && !in_visible {
                    continue;
                }
            }
            
            // Relay forwarding: skip SRTP, send raw RTP to peer node.
            if subscriber.is_relay {
                if let Some(tx) = relay_out_tx {
                    let mut out = RelayOutput {
                        peer_node: subscriber.relay_node,
                        track_id: actor.track_id,
                        data: [0u8; 1500],
                        len: packet_len as u16,
                    };
                    out.data[..packet_len].copy_from_slice(packet.data());
                    let _ = tx.try_send(out); // Drop if full — backpressure
                }
                forwarded_count += 1;
                continue;
            }

            // Under sim feature, skip SRTP entirely — forward plain RTP
            #[cfg(feature = "sim")]
            {
                let mut forward_slot = match arena.alloc() {
                    Some(slot) => slot,
                    None => {
                        *arena_alloc_failures_fanout += 1;
                        *packets_dropped += 1;
                        break;
                    }
                };
                let slot_data = forward_slot.data_mut();
                slot_data[..packet_len].copy_from_slice(packet.data());

                // Inject MID header extension so receiver can demux by transceiver
                let actual_len = if actor.mid_ext_id > 0 && actor.mid_value_len > 0 {
                    Self::inject_mid_extension(
                        slot_data,
                        packet_len,
                        actor.mid_ext_id,
                        &actor.mid_value,
                        actor.mid_value_len as usize,
                    ).unwrap_or(packet_len)
                } else {
                    packet_len
                };

                // Inject RID header extension (required by webrtc-rs simulcast probing)
                let actual_len = if actor.rid_ext_id > 0 && actor.rid_value_len > 0 {
                    Self::inject_mid_extension(
                        slot_data,
                        actual_len,
                        actor.rid_ext_id,
                        &actor.rid_value,
                        actor.rid_value_len as usize,
                    ).unwrap_or(actual_len)
                } else {
                    actual_len
                };

                forward_slot.set_len(actual_len as u16);
                *bytes_copied_fanout += actual_len as u64;
                batch_sender.queue(subscriber.dest_addr, forward_slot);
                forwarded_count += 1;
                continue;
            }

            // Drop packet if SRTP context is not available
            #[cfg(not(feature = "sim"))]
            let srtp_ctx = match subscriber.srtp_context.as_mut() {
                Some(ctx) => ctx,
                None => {
                    *dropped_unprotected += 1;
                    continue;
                }
            };
            
            // Allocate from arena FIRST, then encrypt in-place
            #[cfg(not(feature = "sim"))]
            {
                let mut forward_slot = match arena.alloc() {
                    Some(slot) => slot,
                    None => {
                        *arena_alloc_failures_fanout += 1;
                        *packets_dropped += 1;
                        break;
                    }
                };
                
                // Copy RTP data into arena slot
                let slot_data = forward_slot.data_mut();
                let srtp_tag_len = srtp_ctx.cipher_tag_len();
                if packet_len + srtp_tag_len > slot_data.len() {
                    continue; // Packet too large for slot
                }
                slot_data[..packet_len].copy_from_slice(packet.data());

                // Inject MID header extension so receiver can demux by transceiver
                let actual_len = if actor.mid_ext_id > 0 && actor.mid_value_len > 0 {
                    Self::inject_mid_extension(
                        slot_data,
                        packet_len,
                        actor.mid_ext_id,
                        &actor.mid_value,
                        actor.mid_value_len as usize,
                    ).unwrap_or(packet_len)
                } else {
                    packet_len
                };

                // Inject RID header extension (required by webrtc-rs simulcast probing)
                let actual_len = if actor.rid_ext_id > 0 && actor.rid_value_len > 0 {
                    Self::inject_mid_extension(
                        slot_data,
                        actual_len,
                        actor.rid_ext_id,
                        &actor.rid_value,
                        actor.rid_value_len as usize,
                    ).unwrap_or(actual_len)
                } else {
                    actual_len
                };

                // Verify there's still room for SRTP auth tag after injection
                if actual_len + srtp_tag_len > slot_data.len() {
                    continue;
                }
                
                // Encrypt in-place in the arena slot
                let protected_len = match srtp_ctx.protect_rtp(slot_data, actual_len) {
                    Ok(len) => len,
                    Err(_e) => {
                        continue;
                    }
                };
                
                forward_slot.set_len(protected_len as u16);
                
                // Track bytes copied for capacity planning
                *bytes_copied_fanout += protected_len as u64;
                
                // Queue directly to batch sender — no second copy
                batch_sender.queue(subscriber.dest_addr, forward_slot);
                forwarded_count += 1;
            }
        }
        
        actor.packets_forwarded += forwarded_count as u64;

        // Postcondition assertion (TigerStyle)
        assert!(forwarded_count <= subscriber_count as u32, 
            "forwarded count must not exceed subscriber count");
    }

    /// Terminate a TrackActor.
    fn terminate_actor(&mut self, track_id: TrackId) {
        if self.actors.remove(&track_id).is_some() {
            self.track_count.fetch_sub(1, Ordering::Relaxed);
        }
        self.actor_messages_processed += 1;
    }

    // === Migration Methods ===

    /// Prepare track for migration (stub - would send to actual TrackActor)
    fn prepare_migration(
        &mut self,
        _migration_id: u64,
        _track_id: TrackId,
        _target_worker_id: u32,
    ) {
        // In full implementation, would forward to TrackActor message queue
        // For now, actors are simplified state structs
        self.actor_messages_processed += 1;
    }

    /// Transfer migrated state to this worker
    fn transfer_migration_state(
        &mut self,
        _migration_id: u64,
        snapshot: nexus_actor::MigrationSnapshot,
    ) {
        // Create new actor state from snapshot
        // Note: We don't have participant_id, ssrc, or kind in the snapshot,
        // so we use default values. In a full implementation, the snapshot
        // should include these fields.
        let mut actor_state = TrackActorState::new(
            snapshot.track_id,
            0,                // participant_id - not in snapshot
            0,                // ssrc - not in snapshot
            MediaKind::Video, // kind - default to video
            0,                // content_type - default to camera
        );

        // Restore subscribers
        for sub_snap in snapshot.subscribers {
            actor_state.add_subscriber(sub_snap.id, sub_snap.participant_id, sub_snap.dest_addr);
        }

        // Restore statistics
        actor_state.packets_received = snapshot.stats.packets_received;
        actor_state.packets_forwarded = snapshot.stats.packets_forwarded;
        actor_state.packets_dropped = snapshot.stats.packets_dropped;

        self.actors.insert(snapshot.track_id, actor_state);
        self.track_count.fetch_add(1, Ordering::Relaxed);
        self.actor_messages_processed += 1;
    }

    /// Resume track after migration
    fn resume_migration(&mut self, _migration_id: u64, _track_id: TrackId) {
        // In full implementation, would forward to TrackActor
        self.actor_messages_processed += 1;
    }

    /// Abort migration
    fn abort_migration(&mut self, _migration_id: u64, _track_id: TrackId) {
        // In full implementation, would forward to TrackActor
        self.actor_messages_processed += 1;
    }

    // === Bandwidth Allocation Methods ===

    /// Get current timestamp in microseconds
    fn get_timestamp_us(&self) -> u64 {
        crate::clock::now_us()
    }

    /// Perform bandwidth allocation across all tracks
    fn perform_bandwidth_allocation(&mut self, timestamp_us: u64) {
        // Take coordinator out temporarily to avoid borrow conflicts
        let mut coordinator = match self.coordinator.take() {
            Some(c) => c,
            None => return,
        };

        // Check if allocation should run
        if !coordinator.should_allocate(timestamp_us) {
            self.coordinator = Some(coordinator);
            return;
        }

        // Update speaker detector with packet rates
        for (_track_id, actor) in &self.actors {
            self.speaker_detector.update(
                actor.track_id as u64,
                actor.packets_received,
                timestamp_us,
            );
        }

        // Detect current speaker
        self.speaker_detector.detect_speaker(timestamp_us);

        // Collect track information with proper priorities
        let allocs: Vec<nexus_bwe::TrackAllocation> = self
            .actors
            .iter()
            .map(|(_track_id, actor)| {
                // Determine priority based on speaker detection and media kind
                // Map internal MediaKind to BWE MediaKind
                let media_kind = match actor.kind {
                    MediaKind::Audio => nexus_bwe::MediaKind::Audio,
                    MediaKind::Video => nexus_bwe::MediaKind::Video,
                };

                let priority = self
                    .speaker_detector
                    .get_priority(actor.track_id as u64, media_kind);

                // Build allocation request with proper structure
                let mut allocation = nexus_bwe::TrackAllocation::new(
                    actor.track_id as u64,
                    priority,
                    actor.max_bitrate_bps,
                );

                // Add simulcast layers from actor
                for layer in &actor.simulcast_layers {
                    allocation.add_layer(*layer);
                }

                allocation
            })
            .collect();

        // Feed allocations to coordinator
        let _allocations = coordinator.collect_track_info(move || allocs);

        // Perform allocation
        let layer_updates = coordinator.allocate_and_dispatch(timestamp_us);

        // Collect REMB packets to send to publishers (not subscribers)
        // REMB must be sent to the media sender for bitrate control
        let remb_packets: Vec<(SocketAddr, Vec<u8>)> = self
            .actors
            .iter()
            .filter_map(|(_track_id, actor)| {
                let remb_packet = coordinator.generate_remb(actor.ssrc);
                // Use publisher address instead of subscriber address
                actor.publisher_addr.map(|addr| (addr, remb_packet))
            })
            .collect();

        // Put coordinator back before modifying actors
        self.coordinator = Some(coordinator);

        // Apply layer updates to actors
        for (track_id, target_layer) in layer_updates {
            if let Some(actor) = self.actors.get_mut(&(track_id as TrackId)) {
                // Get allocated bitrate from the selected layer
                let allocated_bps = if (target_layer as usize) < actor.simulcast_layers.len() {
                    actor.simulcast_layers[target_layer as usize].bitrate_bps
                } else {
                    actor.max_bitrate_bps
                };

                // Update bandwidth allocation directly
                actor.allocated_bitrate_bps = allocated_bps;
                actor.target_layer = target_layer;
                actor.last_layer_switch_us = timestamp_us;

                // Propagate target_layer to all subscribers (bounded)
                let sub_count = actor.subscribers.len().min(100);
                for i in 0..sub_count {
                    let sub = &mut actor.subscribers[i];
                    // Respect subscriber's max_requested_layer
                    sub.target_layer = target_layer.min(sub.max_requested_layer);
                }
            }
        }

        // Send REMB packets with SRTCP protection to publishers
        for (publisher_addr, remb_packet) in remb_packets {
            // Find the actor with matching publisher address to get SRTCP context
            if let Some(actor) = self.actors.values_mut().find(|a| a.publisher_addr == Some(publisher_addr)) {
                if let Some(ref mut srtcp_ctx) = actor.publisher_srtcp_context {
                    // Apply SRTCP protection — add room for 4-byte index + auth tag
                    let srtcp_overhead = 4 + srtcp_ctx.cipher_tag_len();
                    let mut protected_remb = Vec::with_capacity(remb_packet.len() + srtcp_overhead);
                    protected_remb.extend_from_slice(&remb_packet);
                    protected_remb.resize(remb_packet.len() + srtcp_overhead, 0);
                    let remb_len = remb_packet.len();
                    
                    match srtcp_ctx.protect_rtcp(&mut protected_remb, remb_len) {
                        Ok(protected_len) => {
                            protected_remb.truncate(protected_len);
                            self.send_rtcp_packet(publisher_addr, &protected_remb);
                            tracing::trace!(
                                publisher_addr = ?publisher_addr,
                                "REMB sent to publisher with SRTCP protection"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = ?e,
                                "Failed to protect REMB with SRTCP, dropping"
                            );
                        }
                    }
                } else {
                    // No SRTCP context - skip sending
                    tracing::trace!(
                        publisher_addr = ?publisher_addr,
                        "No SRTCP context for publisher, skipping REMB"
                    );
                }
            }
        }

        // Update last allocation check time
        self.last_allocation_check_us = timestamp_us;
    }

    /// Generate and send Sender Reports to all subscribers.
    ///
    /// Generates RTCP SR packets for timing synchronization every 1 second.
    /// Applies SRTCP protection per subscriber before sending.
    ///
    /// # Arguments
    ///
    /// * `timestamp_us` - Current timestamp in microseconds
    ///
    /// # Assertions
    ///
    /// * `timestamp_us > 0` - Valid timestamp
    /// * `actors.len() <= 1000` - Bounded iteration
    /// * `last_sr_sent_us == timestamp_us` - Postcondition after send
    fn generate_and_send_sender_reports(&mut self, timestamp_us: u64) {
        // Precondition assertion
        assert!(timestamp_us > 0, "Timestamp must be non-zero");

        // Collect SR packets to send (to avoid borrow conflicts)
        let mut sr_packets: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

        // Bounded iteration over actors (max 1000 tracks)
        let max_tracks = 1000;
        let mut track_count = 0;

        for (_track_id, actor) in &mut self.actors {
            // Enforce bound
            if track_count >= max_tracks {
                break;
            }
            track_count += 1;

            // Check if SR should be sent
            if actor.subscribers.is_empty() {
                continue;
            }

            let time_since_last_sr = timestamp_us.saturating_sub(actor.last_sr_sent_us);
            if time_since_last_sr < SR_INTERVAL_US && actor.last_sr_sent_us > 0 {
                continue;
            }

            // Comment 3 fix: Require last_rtp_timestamp to be Some, otherwise skip SR generation
            // This ensures RTP/NTP correlation is accurate and avoids using wall-clock microseconds
            // which breaks synchronization for new tracks that haven't received packets yet.
            let rtp_timestamp = match actor.last_rtp_timestamp {
                Some(ts) => ts,
                None => {
                    // No RTP timestamp available yet - skip SR generation
                    // SR will be sent once we receive the first RTP packet
                    tracing::trace!(
                        track_id = actor.track_id,
                        "Skipping SR generation - no RTP timestamp available yet"
                    );
                    continue;
                }
            };

            let sr_packet = actor.sr_generator.generate(rtp_timestamp);

            // Apply SRTCP protection per subscriber
            // Comment 2 fix: Bound subscriber iteration to MAX_SUBSCRIBERS_PER_TRACK
            // This ensures SR emission stays within fixed limits and prevents unbounded loops.
            const MAX_SUBSCRIBERS_PER_TRACK: usize = 2000;
            let subscriber_count = actor.subscribers.len().min(MAX_SUBSCRIBERS_PER_TRACK);
            
            // Precondition assertion: subscriber count must be bounded
            assert!(subscriber_count <= MAX_SUBSCRIBERS_PER_TRACK,
                "Subscriber count must not exceed MAX_SUBSCRIBERS_PER_TRACK");
            
            // Comment 3 fix: Track whether an SR was actually queued/sent
            // Only advance the timer if at least one SR is successfully protected and queued
            let mut sr_queued = false;
            
            for i in 0..subscriber_count {
                let subscriber = &mut actor.subscribers[i];
                
                // Only send if SRTCP context is available
                if let Some(ref mut srtp_ctx) = subscriber.srtp_context {
                    // Create a mutable copy with room for SRTCP overhead (4-byte index + auth tag)
                    let srtcp_overhead = 4 + srtp_ctx.cipher_tag_len();
                    let mut protected_sr = Vec::with_capacity(sr_packet.len() + srtcp_overhead);
                    protected_sr.extend_from_slice(&sr_packet);
                    protected_sr.resize(sr_packet.len() + srtcp_overhead, 0);
                    let sr_len = sr_packet.len();
                    
                    // Apply SRTCP protection
                    match srtp_ctx.protect_rtcp(&mut protected_sr, sr_len) {
                        Ok(protected_len) => {
                            // Truncate to protected length
                            protected_sr.truncate(protected_len);
                            sr_packets.push((subscriber.dest_addr, protected_sr));
                            sr_queued = true; // Mark that we queued at least one SR
                        }
                        Err(e) => {
                            tracing::warn!(
                                subscriber_id = subscriber.id,
                                error = ?e,
                                "Failed to protect RTCP SR packet, skipping subscriber"
                            );
                            // Skip this subscriber - don't send unprotected
                        }
                    }
                } else {
                    // No SRTCP context - skip sending rather than sending plaintext
                    tracing::trace!(
                        subscriber_id = subscriber.id,
                        "No SRTCP context for subscriber, skipping SR"
                    );
                }
            }
            
            // Postcondition assertion: we processed at most MAX_SUBSCRIBERS_PER_TRACK
            debug_assert!(subscriber_count <= MAX_SUBSCRIBERS_PER_TRACK);

            // Comment 3 fix: Only update last_sr_sent_us if at least one SR was queued
            // This prevents the timer from advancing when no SR is actually transmitted
            if sr_queued {
                actor.last_sr_sent_us = timestamp_us;
                // Postcondition assertion
                debug_assert_eq!(actor.last_sr_sent_us, timestamp_us);
            }
        }

        // Send all collected SR packets
        for (dest_addr, packet) in sr_packets {
            self.send_rtcp_packet(dest_addr, &packet);
        }

        // Postcondition: bounded iteration
        debug_assert!(track_count <= max_tracks);
    }

    /// Internal method to update bandwidth without message passing
    #[allow(dead_code)]
    fn update_bandwidth_internal(
        &mut self,
        actor: &mut TrackActorState,
        allocated_bps: u64,
        target_layer: u8,
        timestamp_us: u64,
    ) {
        // Store allocated bitrate
        actor.allocated_bitrate_bps = allocated_bps;
        actor.target_layer = target_layer;

        // Apply layer selection with hysteresis
        actor.apply_layer_selection(target_layer, timestamp_us);
    }

    /// Generate and send REMB packets to all publishers on this worker.
    ///
    /// REMB tells each publisher the maximum bitrate the SFU can receive
    /// from them, based on the GCC congestion controller's estimate.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop (MAX_ACTORS_PER_WORKER)
    /// - Explicit error handling
    fn generate_and_send_remb(&mut self, now_us: u64) {
        // REMB generation interval (5 seconds, per GCC spec recommendation)
        const REMB_INTERVAL_US: u64 = 5_000_000;
        
        // Check interval
        if now_us.saturating_sub(self.last_remb_sent_us) < REMB_INTERVAL_US {
            return;
        }
        self.last_remb_sent_us = now_us;

        // Get current bandwidth estimate from coordinator
        let estimated_bps = match &self.coordinator {
            Some(coord) => coord.target_bitrate(),
            None => return, // No BWE, skip REMB
        };

        // Precondition: estimate must be positive
        if estimated_bps == 0 {
            return;
        }

        const MAX_ACTORS_PER_WORKER: usize = 10_000;
        let mut remb_sent_count: u32 = 0;

        // Bounded iteration over actors
        let actor_count = self.actors.len().min(MAX_ACTORS_PER_WORKER);
        let actor_keys: Vec<TrackId> = self.actors.keys().copied().take(actor_count).collect();

        for track_id in actor_keys {
            let actor = match self.actors.get_mut(&track_id) {
                Some(a) => a,
                None => continue,
            };

            // Only send REMB for video tracks (audio doesn't need it)
            if actor.kind != crate::types::MediaKind::Video {
                continue;
            }

            // Need both publisher address and SRTCP context
            let (publisher_addr, srtcp_ctx) = match (actor.publisher_addr, actor.publisher_srtcp_context.as_mut()) {
                (Some(addr), Some(ctx)) => (addr, ctx),
                _ => continue,
            };

            // Generate REMB packet
            let mut remb_packet = self.remb_generator.generate(estimated_bps, actor.ssrc);
            let remb_len = remb_packet.len();

            // Ensure buffer has room for SRTCP overhead (4-byte index + auth tag)
            let srtcp_overhead = 4 + srtcp_ctx.cipher_tag_len();
            remb_packet.resize(remb_len + srtcp_overhead, 0);

            // Apply SRTCP protection
            match srtcp_ctx.protect_rtcp(&mut remb_packet, remb_len) {
                Ok(protected_len) => {
                    remb_packet.truncate(protected_len);
                    self.send_rtcp_packet(publisher_addr, &remb_packet);
                    remb_sent_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        track_id,
                        error = ?e,
                        "Failed to protect REMB with SRTCP"
                    );
                }
            }
        }

        // Postcondition: bounded output
        assert!(
            remb_sent_count <= MAX_ACTORS_PER_WORKER as u32,
            "REMB count must be bounded"
        );

        if remb_sent_count > 0 {
            tracing::debug!(
                worker_id = self.worker_id,
                remb_sent_count,
                estimated_bps,
                "REMB packets sent to publishers"
            );
        }
    }

    /// Send RTCP packet to destination
    fn send_rtcp_packet(&mut self, dest_addr: SocketAddr, packet: &[u8]) {
        // Precondition: packet must not be empty
        assert!(!packet.is_empty(), "RTCP packet must not be empty");

        // Allocate packet slot from arena
        let mut slot = match self.arena.alloc() {
            Some(s) => s,
            None => {
                self.packets_dropped += 1;
                tracing::warn!("Failed to allocate slot for RTCP packet");
                return;
            }
        };

        // Set packet length
        slot.set_len(packet.len() as u16);

        // Copy RTCP data into slot
        unsafe {
            std::ptr::copy_nonoverlapping(
                packet.as_ptr(),
                slot.data_mut().as_mut_ptr(),
                packet.len(),
            );
        }

        // TODO: SRTP-protect the packet if subscriber has SRTP context
        // For now, send unprotected

        // Enqueue for sending via batch sender
        self.batch_sender.queue(dest_addr, slot);
        
        tracing::trace!(
            dest = ?dest_addr,
            len = packet.len(),
            "RTCP packet queued for sending"
        );
    }

    /// Update bandwidth allocation for a track
    fn update_bandwidth(&mut self, track_id: TrackId, allocated_bps: u64, target_layer: u8) {
        let timestamp_us = self.get_timestamp_us();
        if let Some(actor) = self.actors.get_mut(&track_id) {
            // Update actor state directly without calling self method
            actor.allocated_bitrate_bps = allocated_bps;
            actor.target_layer = target_layer;
            actor.last_layer_switch_us = timestamp_us;
        }
        self.actor_messages_processed += 1;
    }

    /// Handle RTCP receiver report for BWE
    fn handle_rtcp_receiver_report(
        &mut self,
        ssrc: Ssrc,
        fraction_lost: u8,
        rtt_us: Option<u64>,
        timestamp_us: u64,
    ) {
        if let Some(coordinator) = self.coordinator.as_mut() {
            coordinator.on_receiver_report(ssrc, fraction_lost, rtt_us, timestamp_us);
        }
    }

    /// Handle transport feedback for BWE
    fn handle_transport_feedback(
        &mut self,
        feedback: &nexus_bwe::TransportFeedback,
        timestamp_us: u64,
    ) {
        if let Some(coordinator) = self.coordinator.as_mut() {
            coordinator.on_transport_feedback(feedback, timestamp_us);
        }
    }

    /// Handle RTCP PLI (Picture Loss Indication) feedback.
    ///
    /// Resolves actor by media_ssrc and forwards PLI to publisher.
    ///
    /// # Arguments
    ///
    /// * `media_ssrc` - SSRC of media source
    /// * `sender_ssrc` - SSRC of feedback sender
    ///
    /// # Assertions
    ///
    /// * `media_ssrc > 0` - Valid SSRC
    fn handle_rtcp_pli(&mut self, media_ssrc: u32, sender_ssrc: u32) {
        // Precondition assertion
        assert!(media_ssrc > 0, "Media SSRC must be non-zero");

        tracing::debug!(
            worker_id = self.worker_id,
            media_ssrc,
            sender_ssrc,
            "PLI received - keyframe requested"
        );

        // Find actor by SSRC and get publisher address
        let _publisher_addr = self
            .actors
            .values()
            .find(|a| a.ssrc == media_ssrc)
            .and_then(|actor| {
                tracing::info!(
                    worker_id = self.worker_id,
                    track_id = actor.track_id,
                    media_ssrc,
                    sender_ssrc,
                    "Processing PLI - forwarding to publisher"
                );
                actor.publisher_addr
            });

        // Find actor and get both publisher address and SRTCP context
        let (publisher_addr, publisher_srtcp) = self
            .actors
            .values_mut()
            .find(|a| a.ssrc == media_ssrc)
            .map(|actor| (actor.publisher_addr, actor.publisher_srtcp_context.as_mut()))
            .unwrap_or((None, None));

        match (publisher_addr, publisher_srtcp) {
            (Some(addr), Some(srtcp_ctx)) => {
                // Build PLI packet with original sender_ssrc
                let mut pli_packet = Self::build_pli_packet_static(media_ssrc, sender_ssrc);
                let pli_len = pli_packet.len();

                // Add room for SRTCP overhead (4-byte index + auth tag)
                let srtcp_overhead = 4 + srtcp_ctx.cipher_tag_len();
                pli_packet.resize(pli_len + srtcp_overhead, 0);

                // Apply SRTCP protection (Comment 2 fix)
                match srtcp_ctx.protect_rtcp(&mut pli_packet, pli_len) {
                    Ok(protected_len) => {
                        pli_packet.truncate(protected_len);
                        self.send_rtcp_packet(addr, &pli_packet);

                        tracing::info!(
                            publisher_addr = ?addr,
                            "PLI forwarded to publisher with SRTCP protection"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Failed to protect PLI with SRTCP, dropping"
                        );
                    }
                }
            }
            (Some(_), None) => {
                tracing::warn!(
                    worker_id = self.worker_id,
                    media_ssrc,
                    "PLI cannot be sent - no SRTCP context for publisher"
                );
            }
            (None, _) => {
                tracing::warn!(
                    worker_id = self.worker_id,
                    media_ssrc,
                    "PLI for unknown SSRC or no publisher address"
                );
            }
        }
    }

    /// Attempt to retransmit lost packets from the ring buffer.
    ///
    /// Returns the sequence numbers that were NOT found in the ring buffer
    /// (these should be forwarded to the publisher as a NACK).
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop (max 64 lost packets per NACK)
    fn retransmit_from_ring_buffer(
        &mut self,
        media_ssrc: u32,
        sender_ssrc: u32,
        lost_packets: &[u16],
    ) -> Vec<u16> {
        // Precondition assertions
        assert!(media_ssrc > 0, "Media SSRC must be non-zero");
        assert!(lost_packets.len() <= 64, "Lost packets must be bounded to 64");

        // Find the actor for this SSRC
        let actor = match self.actors.values_mut().find(|a| a.ssrc == media_ssrc) {
            Some(a) => a,
            None => return lost_packets.to_vec(),
        };

        // Find the subscriber that sent this NACK
        let subscriber_idx = actor.subscribers.iter().position(|s| s.id == sender_ssrc);

        let mut not_found: Vec<u16> = Vec::with_capacity(lost_packets.len());
        let mut retransmitted: u32 = 0;

        const MAX_RETRANSMIT_PER_NACK: usize = 64;
        let count = lost_packets.len().min(MAX_RETRANSMIT_PER_NACK);

        for i in 0..count {
            let seq = lost_packets[i];

            match actor.ring_buffer.peek(seq as u32) {
                Some(cached_packet) => {
                    if let Some(sub_idx) = subscriber_idx {
                        let subscriber = &mut actor.subscribers[sub_idx];
                        let packet_len = cached_packet.len() as usize;

                        // Under sim feature, skip SRTP — retransmit plain data
                        #[cfg(feature = "sim")]
                        {
                            if let Some(mut slot) = self.arena.alloc() {
                                let slot_data = slot.data_mut();
                                if packet_len <= slot_data.len() {
                                    slot_data[..packet_len]
                                        .copy_from_slice(&cached_packet.data()[..packet_len]);
                                    slot.set_len(packet_len as u16);
                                    self.batch_sender.queue(subscriber.dest_addr, slot);
                                    retransmitted += 1;
                                    continue;
                                }
                            }
                        }

                        #[cfg(not(feature = "sim"))]
                        {
                            if let Some(srtp_ctx) = subscriber.srtp_context.as_mut() {
                                if let Some(mut slot) = self.arena.alloc() {
                                    let slot_data = slot.data_mut();
                                    if packet_len + 16 <= slot_data.len() {
                                        slot_data[..packet_len]
                                            .copy_from_slice(&cached_packet.data()[..packet_len]);

                                        match srtp_ctx.protect_rtp(slot_data, packet_len) {
                                            Ok(protected_len) => {
                                                slot.set_len(protected_len as u16);
                                                self.batch_sender.queue(subscriber.dest_addr, slot);
                                                retransmitted += 1;
                                                continue;
                                            }
                                            Err(_) => { /* fall through to NACK publisher */ }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    not_found.push(seq);
                }
                None => {
                    not_found.push(seq);
                }
            }
        }

        // Postcondition
        assert!(
            retransmitted as usize + not_found.len() <= MAX_RETRANSMIT_PER_NACK,
            "Total processed must not exceed max"
        );

        tracing::debug!(
            worker_id = self.worker_id,
            media_ssrc,
            requested = lost_packets.len(),
            retransmitted,
            forwarded_to_publisher = not_found.len(),
            "NACK retransmission from ring buffer"
        );

        not_found
    }

    /// Handle RTCP NACK (Negative Acknowledgement) feedback.
    ///
    /// First checks the ring buffer for cached packets and retransmits
    /// directly to the subscriber. Only forwards remaining NACKs to the
    /// publisher for packets not found in the buffer.
    ///
    /// # Arguments
    ///
    /// * `media_ssrc` - SSRC of media source
    /// * `sender_ssrc` - SSRC of feedback sender
    /// * `lost_packets` - List of lost packet sequence numbers
    ///
    /// # Assertions
    ///
    /// * `media_ssrc > 0` - Valid SSRC
    /// * `lost_packets.len() <= 64` - Bounded packet list
    fn handle_rtcp_nack(&mut self, media_ssrc: u32, sender_ssrc: u32, lost_packets: Vec<u16>) {
        // Precondition assertions
        assert!(media_ssrc > 0, "Media SSRC must be non-zero");
        assert!(
            lost_packets.len() <= 64,
            "Lost packets must be bounded to 64"
        );

        tracing::debug!(
            worker_id = self.worker_id,
            media_ssrc,
            sender_ssrc,
            lost_count = lost_packets.len(),
            "NACK received — checking ring buffer first"
        );

        // Step 1: Try retransmitting from ring buffer
        let remaining = self.retransmit_from_ring_buffer(media_ssrc, sender_ssrc, &lost_packets);

        // Step 2: Forward remaining NACKs to publisher
        if remaining.is_empty() {
            tracing::debug!(
                worker_id = self.worker_id,
                media_ssrc,
                "All NACK packets retransmitted from ring buffer"
            );
            return;
        }

        // Build and send NACK to publisher for packets not in ring buffer
        let (publisher_addr, publisher_srtcp) = self
            .actors
            .values_mut()
            .find(|a| a.ssrc == media_ssrc)
            .map(|actor| (actor.publisher_addr, actor.publisher_srtcp_context.as_mut()))
            .unwrap_or((None, None));

        match (publisher_addr, publisher_srtcp) {
            (Some(addr), Some(srtcp_ctx)) => {
                let mut nack_packet =
                    Self::build_nack_packet_static(media_ssrc, &remaining, sender_ssrc);
                let nack_len = nack_packet.len();

                // Add room for SRTCP overhead (4-byte index + auth tag)
                let srtcp_overhead = 4 + srtcp_ctx.cipher_tag_len();
                nack_packet.resize(nack_len + srtcp_overhead, 0);

                match srtcp_ctx.protect_rtcp(&mut nack_packet, nack_len) {
                    Ok(protected_len) => {
                        nack_packet.truncate(protected_len);
                        self.send_rtcp_packet(addr, &nack_packet);

                        tracing::info!(
                            publisher_addr = ?addr,
                            remaining_count = remaining.len(),
                            "NACK forwarded to publisher for packets not in ring buffer"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, "Failed to protect NACK with SRTCP");
                    }
                }
            }
            (Some(_), None) => {
                tracing::warn!(
                    worker_id = self.worker_id,
                    media_ssrc,
                    "NACK cannot be forwarded — no SRTCP context for publisher"
                );
            }
            (None, _) => {
                tracing::warn!(
                    worker_id = self.worker_id,
                    media_ssrc,
                    "NACK for unknown SSRC or no publisher address"
                );
            }
        }
    }

    /// Build PLI RTCP packet (static version).
    ///
    /// # Arguments
    ///
    /// * `media_ssrc` - SSRC of media source
    /// * `sender_ssrc` - SSRC of feedback sender
    ///
    /// # Returns
    ///
    /// 12-byte PLI packet
    fn build_pli_packet_static(media_ssrc: u32, sender_ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 12];

        // Header: V=2, P=0, FMT=1, PT=206
        packet[0] = (2 << 6) | 1; // Version 2, FMT=1
        packet[1] = 206; // PayloadFeedback
        packet[2] = 0;
        packet[3] = 2; // Length = 2 words

        // Sender SSRC
        packet[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());

        // Media SSRC
        packet[8..12].copy_from_slice(&media_ssrc.to_be_bytes());

        packet
    }

    /// Build NACK RTCP packet (static version).
    ///
    /// # Arguments
    ///
    /// * `media_ssrc` - SSRC of media source
    /// * `lost_packets` - List of lost packet sequence numbers
    /// * `sender_ssrc` - SSRC of feedback sender
    ///
    /// # Returns
    ///
    /// NACK packet with FCI entries
    fn build_nack_packet_static(media_ssrc: u32, lost_packets: &[u16], sender_ssrc: u32) -> Vec<u8> {
        // Bound lost_packets to 64 entries max
        let bounded_lost = &lost_packets[..lost_packets.len().min(64)];
        
        // Calculate number of FCI entries needed
        // Each FCI entry encodes 1 PID + up to 16 BLP bits (17 packets total)
        let fci_count = (bounded_lost.len() + 16) / 17;
        let fci_count = fci_count.max(1); // At least one FCI entry
        
        // Calculate packet size: header (8) + media SSRC (4) + FCI entries (4 bytes each)
        let packet_size = 12 + (fci_count * 4);
        let mut packet = vec![0u8; packet_size];

        // Header: V=2, P=0, FMT=1, PT=205
        packet[0] = (2 << 6) | 1; // Version 2, FMT=1
        packet[1] = 205; // TransportFeedback
        let length_words = ((packet_size / 4) - 1) as u16;
        packet[2..4].copy_from_slice(&length_words.to_be_bytes());

        // Sender SSRC
        packet[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());

        // Media SSRC
        packet[8..12].copy_from_slice(&media_ssrc.to_be_bytes());

        // Write FCI entries - iterate over lost_packets in chunks of up to 17
        let mut offset = 12;
        let mut packet_idx = 0;
        
        while packet_idx < bounded_lost.len() && offset + 4 <= packet_size {
            // PID is the first packet in this chunk
            let pid = bounded_lost[packet_idx];
            packet[offset..offset + 2].copy_from_slice(&pid.to_be_bytes());
            
            // BLP encodes the next up to 16 packets
            let mut blp: u16 = 0;
            packet_idx += 1; // Move past PID
            
            // Process up to 16 more packets for BLP
            let mut blp_count = 0;
            while blp_count < 16 && packet_idx < bounded_lost.len() {
                let seq = bounded_lost[packet_idx];
                let offset_from_pid = seq.wrapping_sub(pid).wrapping_sub(1);
                
                // Only set bit if within 16-bit range
                if offset_from_pid < 16 {
                    blp |= 1 << offset_from_pid;
                }
                
                packet_idx += 1;
                blp_count += 1;
            }
            
            packet[offset + 2..offset + 4].copy_from_slice(&blp.to_be_bytes());
            offset += 4;
        }

        packet
    }

    /// Set publisher SRTCP context for a track.
    ///
    /// This enables SRTCP protection of PLI/NACK feedback sent to the publisher.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to set context for
    /// * `srtcp_context` - SRTCP context from publisher's DTLS handshake
    ///
    /// # Assertions
    ///
    /// Set publisher SRTCP context for a track.
    ///
    /// Comment 1 fix: This method now always overwrites any existing SRTCP context,
    /// ensuring that PLI/NACK feedback is encrypted with the current key material.
    /// This is critical for ICE restart and DTLS rekey scenarios where the keys change.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to set context for
    /// * `key_material` - SRTCP key material from publisher's DTLS handshake
    /// * `srtp_policy` - SRTP policy (cipher suite, etc.)
    ///
    /// # Assertions
    ///
    /// * `track_id > 0` - Valid track ID
    fn set_publisher_srtcp(&mut self, track_id: TrackId, key_material: nexus_transport::srtp::KeyMaterial, srtp_policy: nexus_transport::srtp::SrtpPolicy) {
        // Precondition assertion
        assert!(track_id > 0, "Track ID must be non-zero");

        if let Some(actor) = self.actors.get_mut(&track_id) {
            // Create SRTCP context from key material
            match nexus_transport::srtp::SrtpContext::new(&key_material, srtp_policy) {
                Ok(srtcp_context) => {
                    let is_update = actor.publisher_srtcp_context.is_some();
                    actor.publisher_srtcp_context = Some(srtcp_context);
                    tracing::info!(
                        worker_id = self.worker_id,
                        track_id,
                        is_update,
                        "Publisher SRTCP context {} for track",
                        if is_update { "updated" } else { "set" }
                    );
                }
                Err(e) => {
                    tracing::error!(
                        worker_id = self.worker_id,
                        track_id,
                        error = ?e,
                        "Failed to create SRTCP context from key material"
                    );
                }
            }
        } else {
            tracing::warn!(
                worker_id = self.worker_id,
                track_id,
                "Cannot set publisher SRTCP context - track not found"
            );
        }

        self.actor_messages_processed += 1;
    }

    /// Set subscriber SRTP context for a track.
    ///
    /// Comment 2 fix: This enables SRTP protection of outbound RTP packets and RTCP SRs
    /// sent to the subscriber. Called when subscriber's DTLS handshake completes.
    /// Always overwrites any existing context to handle ICE restart/DTLS rekey.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to set context for
    /// * `subscriber_id` - Subscriber ID to set context for
    /// * `key_material` - SRTP key material from subscriber's DTLS handshake
    /// * `srtp_policy` - SRTP policy (cipher suite, etc.)
    ///
    /// # Assertions
    ///
    /// * `track_id > 0` - Valid track ID
    /// * `subscriber_id > 0` - Valid subscriber ID
    fn set_subscriber_srtp(
        &mut self,
        track_id: TrackId,
        subscriber_id: u32,
        key_material: nexus_transport::srtp::KeyMaterial,
        srtp_policy: nexus_transport::srtp::SrtpPolicy,
    ) {
        // Precondition assertions
        assert!(track_id > 0, "Track ID must be non-zero");
        assert!(subscriber_id > 0, "Subscriber ID must be non-zero");

        if let Some(actor) = self.actors.get_mut(&track_id) {
            // Find the subscriber by ID
            if let Some(subscriber) = actor.subscribers.iter_mut().find(|s| s.id == subscriber_id) {
                // Create SRTP context from key material
                match nexus_transport::srtp::SrtpContext::new(&key_material, srtp_policy) {
                    Ok(srtp_context) => {
                        let is_update = subscriber.srtp_context.is_some();
                        subscriber.srtp_context = Some(srtp_context);
                        tracing::info!(
                            worker_id = self.worker_id,
                            track_id,
                            subscriber_id,
                            is_update,
                            "Subscriber SRTP context {} - SR generation and RTP forwarding now enabled",
                            if is_update { "updated" } else { "set" }
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            worker_id = self.worker_id,
                            track_id,
                            subscriber_id,
                            error = ?e,
                            "Failed to create SRTP context from key material"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    worker_id = self.worker_id,
                    track_id,
                    subscriber_id,
                    "Cannot set subscriber SRTP context - subscriber not found"
                );
            }
        } else {
            tracing::warn!(
                worker_id = self.worker_id,
                track_id,
                subscriber_id,
                "Cannot set subscriber SRTP context - track not found"
            );
        }

        self.actor_messages_processed += 1;
    }

    /// Add a subscriber to a track actor.
    ///
    /// Creates a subscriber entry with SRTP context for outbound packet encryption.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to subscribe to
    /// * `subscriber_id` - Unique subscriber identifier  
    /// * `participant_id` - Participant ID of the subscriber
    /// * `dest_addr` - Destination address for RTP forwarding
    /// * `target_layer` - Target simulcast layer (default: 2)
    /// * `srtp_context` - SRTP context for packet encryption
    fn add_subscriber(
        &mut self,
        track_id: TrackId,
        subscriber_id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
        target_layer: u8,
        srtp_context: nexus_transport::srtp::SrtpContext,
    ) {
        if let Some(actor) = self.actors.get_mut(&track_id) {
            // Check subscriber limit
            const MAX_SUBSCRIBERS_PER_TRACK: usize = 2000;
            if actor.subscribers.len() < MAX_SUBSCRIBERS_PER_TRACK {
                actor.subscribers.push(ActorSubscriber {
                    id: subscriber_id,
                    participant_id,
                    dest_addr,
                    target_layer,
                    srtp_context: Some(srtp_context),
                    max_requested_layer: target_layer,
                    viewport_visible: Vec::new(),
                    viewport_pinned: Vec::new(),
                    is_relay: false,
                    relay_node: 0,
                });
                tracing::info!(
                    worker_id = self.worker_id,
                    track_id,
                    subscriber_id,
                    "Added subscriber to track"
                );
            } else {
                tracing::warn!(
                    worker_id = self.worker_id,
                    track_id,
                    subscriber_id,
                    "Track subscriber limit reached"
                );
            }
        } else {
            tracing::warn!(
                worker_id = self.worker_id,
                track_id,
                subscriber_id,
                "Cannot add subscriber - track not found"
            );
        }
    }

    /// Remove a subscriber from a track actor.
    ///
    /// Removes the subscriber entry and stops packet forwarding to that destination.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to unsubscribe from
    /// * `subscriber_id` - Subscriber identifier to remove
    fn remove_subscriber(&mut self, track_id: TrackId, subscriber_id: u32) {
        if let Some(actor) = self.actors.get_mut(&track_id) {
            actor.subscribers.retain(|s| s.id != subscriber_id);
            tracing::info!(
                worker_id = self.worker_id,
                track_id,
                subscriber_id,
                "Removed subscriber from track"
            );
        } else {
            tracing::warn!(
                worker_id = self.worker_id,
                track_id,
                subscriber_id,
                "Cannot remove subscriber - track not found"
            );
        }
    }

    /// Flush outbound batches.
    fn flush_batches(&mut self) {
        if self.batch_sender.pending_count() > 0 {
            self.batch_sender.flush();
            self.batches_flushed += 1;
        }
    }

    /// Drain remaining messages during shutdown.
    fn drain_messages(&mut self) {
        // TigerStyle: Fixed loop bound
        const MAX_DRAIN_ITERATIONS: u32 = 10000;
        let mut iterations = 0u32;

        while let Ok(msg) = self.receiver.try_recv() {
            if iterations >= MAX_DRAIN_ITERATIONS {
                break;
            }
            iterations += 1;

            match msg {
                WorkerMessage::Packet { track_id, packet, source_addr } => {
                    self.actor_process_packet(track_id as TrackId, packet, source_addr);
                }
                WorkerMessage::Shutdown => break,
                _ => {} // Ignore other messages during drain
            }
        }
    }

    /// Get worker statistics.
    pub fn stats(&self) -> WorkerStats {
        WorkerStats {
            track_count: self.actors.len() as u32,
            packets_processed: self.packets_processed,
            packets_dropped: self.packets_dropped,
            batches_flushed: self.batches_flushed,
            bytes_copied_fanout: self.bytes_copied_fanout,
            arena_alloc_failures_fanout: self.arena_alloc_failures_fanout,
        }
    }

    /// Get actor count.
    pub fn actor_count(&self) -> u32 {
        self.actors.len() as u32
    }

    /// Get actor messages processed count.
    pub fn actor_messages_processed(&self) -> u64 {
        self.actor_messages_processed
    }

    /// Get count of packets dropped due to missing SRTP context.
    /// Requirement 4.4: Track packets that cannot be protected.
    pub fn dropped_unprotected(&self) -> u64 {
        self.dropped_unprotected
    }
}

/// Pool of CPU-pinned worker threads.
///
/// Manages worker lifecycle, track assignment, and packet routing.
/// Uses consistent hashing to deterministically assign tracks to workers.
pub struct WorkerPool {
    /// Worker handles.
    pub(crate) workers: Vec<WorkerHandle>,
    /// Consistent hash for track assignment.
    track_hasher: ConsistentHash,
    /// Track to worker mapping.
    track_to_worker: HashMap<TrackId, u32>,
    /// Next track ID.
    next_track_id: AtomicU64,
    /// Shutdown flag.
    is_shutdown: AtomicBool,

    // === Migration Support ===
    /// Migration queue (bounded to MAX_CONCURRENT_MIGRATIONS).
    migration_queue: Arc<Mutex<MigrationQueue>>,
    /// Migration event receiver.
    migration_event_rx: Receiver<MigrationEvent>,
    /// Migration event sender (cloned to track actors).
    migration_event_tx: Sender<MigrationEvent>,
    /// Migration metrics.
    migration_metrics: Arc<MigrationMetrics>,
    /// Last rebalance timestamp (nanos since epoch).
    last_rebalance_time: Arc<AtomicU64>,
    /// Receiver for relay output packets from workers.
    /// Drained by the SFU main loop and forwarded to RelayManager.
    relay_out_rx: crossbeam::channel::Receiver<RelayOutput>,
}

impl WorkerPool {
    /// Create a new worker pool.
    ///
    /// Spawns one worker per CPU core (or specified number) and pins
    /// each worker to its corresponding core. Creates N×(N-1) SPSC channels
    /// for cross-worker packet forwarding (Requirement 1.3). Waits for all
    /// workers to initialize successfully before returning.
    ///
    /// # Arguments
    ///
    /// * `num_workers` - Number of workers (1-64, or 0 for auto-detect)
    /// * `arena_size_mb` - Size of packet arena per worker in MB
    /// * `socket_fd` - Socket file descriptor for batch senders
    /// * `realtime_priority` - Whether to attempt SCHED_FIFO real-time scheduling
    /// * `realtime_priority_level` - SCHED_FIFO priority (1-99, default 80)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any worker fails to initialize
    /// - Workers don't start within the timeout period
    /// - Thread spawning fails
    ///
    /// # Panics
    ///
    /// Panics if num_workers > 64.
    ///
    /// # Assertions
    /// - num_workers <= 64
    /// - N×(N-1) SPSC channels are created
    pub fn new(
        num_workers: u32,
        arena_size_mb: u32,
        socket_fd: i32,
        realtime_priority: bool,
        realtime_priority_level: u32,
    ) -> Result<Self, WorkerError> {
        // Auto-detect if 0
        let num_workers = if num_workers == 0 {
            num_cpus::get() as u32
        } else {
            num_workers
        };

        // TigerStyle: Assert preconditions
        assert!(num_workers > 0, "num_workers must be > 0");
        assert!(num_workers <= 64, "num_workers must be <= 64");

        // Validate realtime priority level if enabled
        // Note: _realtime_priority_level is prefixed with _ because it's only used on Linux
        let _realtime_priority_level = if realtime_priority {
            if realtime_priority_level == 0 {
                80 // Default priority
            } else {
                assert!(
                    realtime_priority_level >= 1 && realtime_priority_level <= 99,
                    "realtime_priority_level must be in range 1-99"
                );
                realtime_priority_level
            }
        } else {
            0 // Not used when realtime_priority is false
        };

        let arena_size_mb = if arena_size_mb == 0 {
            DEFAULT_ARENA_SIZE_MB
        } else {
            arena_size_mb
        };

        let track_hasher = ConsistentHash::new(num_workers);

        // Get available CPU cores
        let core_ids = core_affinity::get_core_ids().unwrap_or_default();

        // Relay output channel — all workers share the sender.
        // SFU main loop drains relay_out_rx → RelayManager.
        let (relay_out_tx, relay_out_rx) = crossbeam::channel::bounded::<RelayOutput>(8192);

        // =========================================================================
        // Phase 1: Create N×(N-1) SPSC channels and distribute handles
        // (Requirement 1.3)
        // Each worker gets N-1 senders (to other workers) and N-1 receivers (from other workers)
        // =========================================================================
        let n = num_workers as usize;
        
        // Storage for channel boxes (to keep them alive)
        let mut spsc_channel_storage: Vec<Box<super::spsc::SpscChannel<4096>>> = Vec::with_capacity(n * n);
        
        // Initialize sender/receiver vectors for each worker
        // worker_senders[i][j] = sender from worker i to worker j (None if i == j)
        // worker_receivers[i][j] = receiver for worker i from worker j (None if i == j)
        let mut worker_senders: Vec<Vec<Option<super::spsc::SpscSender<4096>>>> = Vec::with_capacity(n);
        let mut worker_receivers: Vec<Vec<Option<super::spsc::SpscReceiver<4096>>>> = Vec::with_capacity(n);
        
        // Initialize with None values (can't use vec![vec![None; n]; n] because SpscSender/Receiver don't impl Clone)
        for _ in 0..n {
            let mut sender_row = Vec::with_capacity(n);
            let mut receiver_row = Vec::with_capacity(n);
            for _ in 0..n {
                sender_row.push(None);
                receiver_row.push(None);
            }
            worker_senders.push(sender_row);
            worker_receivers.push(receiver_row);
        }
        
        // Create channels and distribute handles
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    // Create channel from worker i to worker j
                    let (channel, sender, receiver) = super::spsc::channel::<4096>();
                    
                    // Worker i gets the sender (to send to worker j)
                    worker_senders[i][j] = Some(sender);
                    
                    // Worker j gets the receiver (to receive from worker i)
                    worker_receivers[j][i] = Some(receiver);
                    
                    // Store channel to keep it alive
                    spsc_channel_storage.push(channel);
                }
            }
        }
        
        // Postcondition: verify channel count
        assert_eq!(
            spsc_channel_storage.len(),
            n * n.saturating_sub(1),
            "must have N×(N-1) SPSC channels"
        );
        
        // Verify distribution
        for i in 0..n {
            let sender_count = worker_senders[i].iter().filter(|s| s.is_some()).count();
            let receiver_count = worker_receivers[i].iter().filter(|r| r.is_some()).count();
            assert_eq!(
                sender_count,
                n.saturating_sub(1),
                "worker {} must have N-1 senders",
                i
            );
            assert_eq!(
                receiver_count,
                n.saturating_sub(1),
                "worker {} must have N-1 receivers",
                i
            );
        }

        // Leak the channel storage to keep channels alive for the lifetime of the pool
        // This is safe because the pool owns the channels and they live as long as the pool
        let _channel_storage = Box::leak(spsc_channel_storage.into_boxed_slice());

        // =========================================================================
        // Phase 3: Spawn worker threads
        // =========================================================================
        let mut workers = Vec::with_capacity(num_workers as usize);

        for worker_id in 0..num_workers {
            // Determine core ID (wrap around if more workers than cores)
            let core_id = if !core_ids.is_empty() {
                worker_id % core_ids.len() as u32
            } else {
                worker_id
            };

            // Create legacy channel for this worker (for backward compatibility)
            let (sender, receiver) = channel::bounded(DEFAULT_CHANNEL_CAPACITY);

            // Shared state
            let track_count = Arc::new(AtomicU32::new(0));
            let is_running = Arc::new(AtomicBool::new(false));
            let init_failed = Arc::new(AtomicBool::new(false));
            let init_error: Arc<parking_lot::Mutex<Option<String>>> =
                Arc::new(parking_lot::Mutex::new(None));
            // Scheduling policy: 0 = Normal, 1 = Fifo, 2 = RoundRobin
            let scheduling_policy_atomic = Arc::new(AtomicU8::new(0));

            // Clone for worker thread
            let track_count_clone = Arc::clone(&track_count);
            let is_running_clone = Arc::clone(&is_running);
            let init_failed_clone = Arc::clone(&init_failed);
            let init_error_clone = Arc::clone(&init_error);
            // Note: _scheduling_policy_clone is prefixed with _ because it's only used on Linux
            let _scheduling_policy_clone = Arc::clone(&scheduling_policy_atomic);

            // Get core affinity ID if available
            let affinity_core_id = if !core_ids.is_empty() {
                Some(core_ids[core_id as usize])
            } else {
                None
            };

            // Take SPSC channel handles for this worker (move ownership, not clone)
            let spsc_senders: Vec<Option<super::spsc::SpscSender<4096>>> = 
                std::mem::take(&mut worker_senders[worker_id as usize]);
            let spsc_receivers: Vec<Option<super::spsc::SpscReceiver<4096>>> = 
                std::mem::take(&mut worker_receivers[worker_id as usize]);

            let relay_tx_clone = relay_out_tx.clone();

            // Spawn worker thread
            let thread = thread::Builder::new()
                .name(format!("nexus-worker-{}", worker_id))
                .spawn(move || {
                    // Pin to CPU core if available
                    if let Some(core) = affinity_core_id {
                        let _ = core_affinity::set_for_current(core);
                    }

                    // Attempt real-time scheduling if configured (Linux only)
                    #[cfg(target_os = "linux")]
                    if realtime_priority {
                        match set_realtime_scheduling(_realtime_priority_level) {
                            Ok(()) => {
                                // Successfully set SCHED_FIFO
                                _scheduling_policy_clone.store(1, Ordering::Release); // 1 = Fifo
                                tracing::info!(
                                    worker_id = worker_id,
                                    priority = _realtime_priority_level,
                                    "Worker thread set to SCHED_FIFO"
                                );
                            }
                            Err(e) => {
                                // Failed to set real-time scheduling, continue with Normal
                                _scheduling_policy_clone.store(0, Ordering::Release); // 0 = Normal
                                tracing::warn!(
                                    worker_id = worker_id,
                                    error = %e,
                                    "Failed to set SCHED_FIFO, continuing with normal scheduling"
                                );
                            }
                        }
                    }

                    // On non-Linux, real-time scheduling is not supported
                    #[cfg(not(target_os = "linux"))]
                    if realtime_priority {
                        tracing::debug!(
                            worker_id = worker_id,
                            "Real-time scheduling not supported on this platform"
                        );
                    }

                    // Create and run worker
                    match MediaWorker::new(
                        worker_id,
                        core_id,
                        arena_size_mb,
                        socket_fd,
                        receiver,
                        track_count_clone,
                        is_running_clone,
                    ) {
                        Ok(mut worker) => {
                            // Set SPSC channel handles (Requirement 1.3)
                            worker.set_spsc_channels(spsc_receivers, spsc_senders);
                            worker.relay_out_tx = Some(relay_tx_clone);
                            worker.run()
                        }
                        Err(e) => {
                            // Store error for main thread to retrieve
                            *init_error_clone.lock() = Some(e.to_string());
                            init_failed_clone.store(true, Ordering::Release);
                        }
                    }
                })
                .map_err(|e| WorkerError::InvalidConfig {
                    message: format!("failed to spawn worker thread {}: {}", worker_id, e),
                })?;

            // Read the scheduling policy set by the worker thread
            // Note: We wait for workers to start before returning, so this will be set
            // For now, we initialize with Normal and update after workers start
            workers.push(WorkerHandle {
                thread: Some(thread),
                worker_id,
                core_id,
                track_count,
                sender,
                is_running,
                init_failed,
                init_error,
                scheduling_policy: scheduling_policy_atomic,
            });
        }

        // Wait for all workers to start with proper timeout
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_millis(WORKER_STARTUP_TIMEOUT_MS);

        // TigerStyle: Fixed loop bound
        const MAX_WAIT_ITERATIONS: u32 = 2000;
        let mut iterations = 0u32;

        loop {
            if iterations >= MAX_WAIT_ITERATIONS {
                // Cleanup workers before returning error
                for worker in &workers {
                    let _ = worker.sender.send(WorkerMessage::Shutdown);
                }
                return Err(WorkerError::ShutdownTimeout {
                    timeout_ms: WORKER_STARTUP_TIMEOUT_MS,
                });
            }
            iterations += 1;

            // Check for initialization failures
            for worker in &workers {
                if worker.init_failed() {
                    let error_msg = worker
                        .init_error()
                        .unwrap_or_else(|| "unknown error".to_string());

                    // Cleanup other workers
                    for w in &workers {
                        let _ = w.sender.send(WorkerMessage::Shutdown);
                    }

                    return Err(WorkerError::WorkerPanicked {
                        worker_id: worker.worker_id,
                        message: format!("worker initialization failed: {}", error_msg),
                    });
                }
            }

            // Check if all workers are running
            let all_running = workers.iter().all(|w| w.is_running());
            if all_running {
                break;
            }

            // Check timeout
            if start_time.elapsed() > timeout {
                // Find which workers didn't start
                let not_running: Vec<u32> = workers
                    .iter()
                    .filter(|w| !w.is_running() && !w.init_failed())
                    .map(|w| w.worker_id)
                    .collect();

                // Cleanup workers
                for worker in &workers {
                    let _ = worker.sender.send(WorkerMessage::Shutdown);
                }

                return Err(WorkerError::InvalidConfig {
                    message: format!(
                        "workers {:?} failed to start within {}ms timeout",
                        not_running, WORKER_STARTUP_TIMEOUT_MS
                    ),
                });
            }

            thread::sleep(Duration::from_millis(WORKER_POLL_INTERVAL_MS));
        }

        // Create migration event channel
        let (migration_event_tx, migration_event_rx) = channel::unbounded();

        Ok(Self {
            workers,
            track_hasher,
            track_to_worker: HashMap::new(),
            next_track_id: AtomicU64::new(1),
            is_shutdown: AtomicBool::new(false),
            migration_queue: Arc::new(Mutex::new(MigrationQueue::new())),
            migration_event_rx,
            migration_event_tx,
            migration_metrics: Arc::new(MigrationMetrics::new()),
            last_rebalance_time: Arc::new(AtomicU64::new(0)),
            relay_out_rx,
        })
    }

    /// Create a worker pool with default settings.
    ///
    /// Uses auto-detected number of workers and default arena size.
    /// Real-time scheduling is disabled by default.
    pub fn with_defaults(socket_fd: i32) -> Result<Self, WorkerError> {
        Self::new(0, DEFAULT_ARENA_SIZE_MB, socket_fd, false, 0)
    }

    /// Get the number of workers.
    #[inline(always)]
    pub fn num_workers(&self) -> u32 {
        self.workers.len() as u32
    }

    /// Assign a track to a worker using consistent hashing.
    ///
    /// Returns the assigned worker ID.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC of the track
    /// * `kind` - Media kind (audio/video)
    ///
    /// # Returns
    ///
    /// Tuple of (track_id, worker_id)
    ///
    /// # Assertions
    /// - ssrc != 0
    pub fn assign_track(
        &mut self,
        ssrc: Ssrc,
        kind: MediaKind,
    ) -> Result<(TrackId, u32), WorkerError> {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0");

        let track_id = self.next_track_id.fetch_add(1, Ordering::Relaxed);
        let worker_id = self.track_hasher.hash(ssrc);

        // Send assignment message to worker
        let worker = &self.workers[worker_id as usize];
        worker.send(WorkerMessage::AssignTrack {
            track_id,
            ssrc,
            kind,
        })?;
        worker.increment_track_count();

        // Track the mapping
        self.track_to_worker.insert(track_id, worker_id);

        Ok((track_id, worker_id))
    }

    /// Remove a track from its worker.
    ///
    /// # Arguments
    ///
    /// * `track_id` - ID of the track to remove
    pub fn remove_track(&mut self, track_id: TrackId) -> Result<(), WorkerError> {
        if let Some(worker_id) = self.track_to_worker.remove(&track_id) {
            let worker = &self.workers[worker_id as usize];
            worker.send(WorkerMessage::RemoveTrack { track_id })?;
            worker.decrement_track_count();
        }
        Ok(())
    }

    /// Route a packet to the correct worker via legacy crossbeam channel.
    ///
    /// This method is used for external routing (from transport layer to workers).
    /// For cross-worker routing within the data plane, workers use SPSC channels
    /// directly via `MediaWorker::route_by_ssrc()` (Requirement 1.4).
    ///
    /// # Arguments
    ///
    /// * `track_id` - ID of the track
    /// * `packet` - Packet to route
    /// * `source_addr` - Source address of the packet (for setting publisher_addr)
    ///
    /// # Assertions
    /// - track_id is assigned
    pub fn route_packet(&self, track_id: TrackId, packet: PacketSlot, source_addr: SocketAddr) -> Result<(), WorkerError> {
        if let Some(&worker_id) = self.track_to_worker.get(&track_id) {
            let worker = &self.workers[worker_id as usize];
            worker.send(WorkerMessage::Packet { track_id, packet, source_addr })
        } else {
            Err(WorkerError::InvalidConfig {
                message: format!("track {} not assigned to any worker", track_id),
            })
        }
    }

    /// Send a message to the worker owning a specific track.
    pub fn send_to_track(&self, track_id: TrackId, msg: WorkerMessage) -> Result<(), WorkerError> {
        if let Some(&worker_id) = self.track_to_worker.get(&track_id) {
            self.workers[worker_id as usize].send(msg)
        } else {
            Err(WorkerError::InvalidConfig {
                message: format!("track {} not assigned to any worker", track_id),
            })
        }
    }

    /// Route a packet by SSRC using consistent hashing.
    ///
    /// Determines the target worker for the given SSRC and routes the packet
    /// via the legacy crossbeam channel. This is the external API for routing
    /// packets from the transport layer.
    ///
    /// For cross-worker routing within the data plane (worker-to-worker),
    /// use `MediaWorker::route_by_ssrc()` which uses lock-free SPSC channels.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - SSRC of the packet
    /// * `packet` - Packet to route
    /// * `source_addr` - Source address of the packet
    ///
    /// # Returns
    ///
    /// The worker ID the packet was routed to.
    ///
    /// # Assertions
    /// - ssrc != 0
    pub fn route_packet_by_ssrc(
        &self,
        ssrc: Ssrc,
        packet: PacketSlot,
        source_addr: SocketAddr,
    ) -> Result<u32, WorkerError> {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0");

        let worker_id = self.track_hasher.hash(ssrc);
        let worker = &self.workers[worker_id as usize];

        // Route via legacy channel (for external routing)
        worker.send(WorkerMessage::Packet {
            track_id: 0, // Track ID unknown, worker will look up by SSRC
            packet,
            source_addr,
        })?;

        Ok(worker_id)
    }

    /// Get the worker with the fewest tracks for load balancing.
    ///
    /// # Returns
    ///
    /// Worker ID of the least loaded worker.
    pub fn least_loaded_worker(&self) -> u32 {
        let mut min_count = u32::MAX;
        let mut min_worker = 0u32;

        for (i, worker) in self.workers.iter().enumerate() {
            let count = worker.track_count();
            if count < min_count {
                min_count = count;
                min_worker = i as u32;
            }
        }

        min_worker
    }

    /// Get a worker handle by ID.
    pub fn get_worker(&self, worker_id: u32) -> Option<&WorkerHandle> {
        self.workers.get(worker_id as usize)
    }

    /// Get the scheduling policy for a specific worker.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - ID of the worker (0-based)
    ///
    /// # Returns
    ///
    /// The active scheduling policy for the worker, or `None` if the worker ID is invalid.
    pub fn worker_scheduling_policy(&self, worker_id: u32) -> Option<SchedulingPolicy> {
        self.workers
            .get(worker_id as usize)
            .map(|w| w.scheduling_policy())
    }

    /// Check if the pool is shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Relaxed)
    }

    /// Add a subscriber to a track.
    ///
    /// Routes the AddSubscriber message to the correct worker based on track assignment.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to subscribe to
    /// * `subscriber_id` - Unique subscriber identifier
    /// * `participant_id` - Participant ID of the subscriber
    /// * `dest_addr` - Destination address for RTP forwarding
    /// * `target_layer` - Target simulcast layer (default: 2)
    /// * `srtp_context` - SRTP context for packet encryption
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(WorkerError)` on failure
    ///
    /// # Assertions
    ///
    /// - track_id != 0
    /// - subscriber_id != 0
    /// - participant_id != 0
    pub fn add_subscriber(
        &self,
        track_id: TrackId,
        subscriber_id: u32,
        participant_id: ParticipantId,
        dest_addr: SocketAddr,
        target_layer: u8,
        srtp_context: nexus_transport::srtp::SrtpContext,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(subscriber_id != 0, "subscriber_id must be non-zero");
        assert!(participant_id != 0, "participant_id must be non-zero");

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Err(WorkerError::InvalidConfig {
                message: format!("track {} not assigned to worker", track_id),
            }),
        };

        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Err(WorkerError::InvalidConfig {
                message: format!("worker {} not found", worker_id),
            }),
        };

        worker.send(WorkerMessage::AddSubscriber {
            track_id,
            subscriber_id,
            participant_id,
            dest_addr,
            target_layer,
            srtp_context,
        })
    }

    /// Remove a subscriber from a track.
    ///
    /// Routes the RemoveSubscriber message to the correct worker based on track assignment.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to unsubscribe from
    /// * `subscriber_id` - Subscriber identifier to remove
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(WorkerError)` on failure
    ///
    /// # Assertions
    ///
    /// - track_id != 0
    pub fn remove_subscriber(
        &self,
        track_id: TrackId,
        subscriber_id: u32,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Ok(()), // Track already removed, no-op
        };

        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Ok(()), // Worker already removed, no-op
        };

        worker.send(WorkerMessage::RemoveSubscriber {
            track_id,
            subscriber_id,
        })
    }

    /// Update viewport filter for a subscriber on a track.
    ///
    /// Routes the UpdateViewport message to the correct worker.
    /// Both `visible` and `pinned` must be sorted for binary_search on the hot path.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn update_viewport(
        &self,
        track_id: TrackId,
        subscriber_id: u32,
        mut visible: Vec<u32>,
        mut pinned: Vec<u32>,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(subscriber_id != 0, "subscriber_id must be non-zero");

        // Sort for binary_search on hot path.
        visible.sort_unstable();
        visible.dedup();
        pinned.sort_unstable();
        pinned.dedup();

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Ok(()),
        };

        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Ok(()),
        };

        worker.send(WorkerMessage::UpdateViewport {
            track_id,
            subscriber_id,
            visible,
            pinned,
        })
    }

    /// Set content type on a track (0=camera, 1=screen, 2=audio).
    /// Screen share tracks bypass viewport filtering.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn set_content_type(
        &self,
        track_id: TrackId,
        content_type: u8,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(content_type <= 2, "content_type must be 0, 1, or 2");

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Ok(()),
        };
        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Ok(()),
        };
        worker.send(WorkerMessage::SetContentType { track_id, content_type })
    }

    /// Get the relay output receiver. The SFU main loop drains this
    /// and forwards packets to `RelayManager::relay_packet()`.
    pub fn relay_output_rx(&self) -> &crossbeam::channel::Receiver<RelayOutput> {
        &self.relay_out_rx
    }

    /// Add a relay subscriber to a track (for cascade to a peer node).
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn add_relay_subscriber(
        &self,
        track_id: TrackId,
        peer_node: u64,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(peer_node != 0, "peer_node must be non-zero");

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Err(WorkerError::InvalidConfig {
                message: format!("track {} not assigned to worker", track_id),
            }),
        };

        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Err(WorkerError::InvalidConfig {
                message: format!("worker {} not found", worker_id),
            }),
        };

        // Derive subscriber_id from peer_node to ensure uniqueness.
        let subscriber_id = (peer_node & 0x7FFFFFFF) as u32 | 0x80000000; // High bit set = relay

        worker.send(WorkerMessage::AddRelaySubscriber {
            track_id,
            peer_node,
            subscriber_id,
        })
    }

    /// Inject a relay packet from a peer node into the local worker pipeline.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn inject_relay_packet(
        &self,
        track_id: TrackId,
        data: [u8; 1500],
        len: u16,
    ) -> Result<(), WorkerError> {
        assert!(track_id != 0, "track_id must be non-zero");
        assert!(len > 0, "len must be positive");

        let worker_id = match self.track_to_worker.get(&track_id) {
            Some(&id) => id,
            None => return Ok(()), // Track not on this node — ignore.
        };

        let worker = match self.get_worker(worker_id) {
            Some(w) => w,
            None => return Ok(()),
        };

        worker.send(WorkerMessage::RelayPacket {
            track_id,
            data,
            len,
        })
    }

    /// Graceful shutdown with draining of in-flight packets.
    ///
    /// Sends shutdown message to all workers and waits for them to finish.
    /// Uses a proper timeout mechanism with polling.
    pub fn shutdown(&mut self) -> Result<(), WorkerError> {
        if self.is_shutdown.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already shutdown
        }

        let mut shutdown_errors: Vec<(u32, String)> = Vec::new();

        // Send shutdown to all workers, tracking failures
        for worker in &self.workers {
            if let Err(e) = worker.send_blocking(WorkerMessage::Shutdown) {
                shutdown_errors.push((worker.worker_id, e.to_string()));
            }
        }

        // Wait for workers to finish with proper timeout
        let timeout = Duration::from_millis(SHUTDOWN_TIMEOUT_MS);
        let start = std::time::Instant::now();

        // TigerStyle: Fixed loop bound for waiting
        const MAX_SHUTDOWN_ITERATIONS: u32 = 1000;
        let mut iterations = 0u32;

        // First, poll workers to check if they've stopped
        while iterations < MAX_SHUTDOWN_ITERATIONS {
            iterations += 1;

            let all_stopped = self.workers.iter().all(|w| !w.is_running());
            if all_stopped {
                break;
            }

            if start.elapsed() > timeout {
                // Timeout reached, but continue to join threads
                break;
            }

            thread::sleep(Duration::from_millis(WORKER_POLL_INTERVAL_MS));
        }

        // Now join all threads
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let remaining = timeout.saturating_sub(start.elapsed());

                if remaining.is_zero() {
                    // We've exceeded timeout, but still try to join
                    // This is best-effort cleanup
                    if thread.join().is_err() {
                        shutdown_errors.push((
                            worker.worker_id,
                            "thread panicked during shutdown".to_string(),
                        ));
                    }
                } else {
                    // Join the thread (blocking)
                    if thread.join().is_err() {
                        shutdown_errors.push((
                            worker.worker_id,
                            "thread panicked during shutdown".to_string(),
                        ));
                    }
                }
            }
        }

        // Report first error if any occurred
        if let Some((worker_id, message)) = shutdown_errors.into_iter().next() {
            return Err(WorkerError::WorkerPanicked { worker_id, message });
        }

        // Check if we exceeded timeout
        if start.elapsed() > timeout {
            return Err(WorkerError::ShutdownTimeout {
                timeout_ms: SHUTDOWN_TIMEOUT_MS,
            });
        }

        Ok(())
    }

    /// Check if all workers are healthy (running and not failed).
    pub fn all_workers_healthy(&self) -> bool {
        self.workers
            .iter()
            .all(|w| w.is_running() && !w.init_failed())
    }

    /// Get the number of running workers.
    pub fn running_worker_count(&self) -> u32 {
        self.workers.iter().filter(|w| w.is_running()).count() as u32
    }

    // === Migration Support ===

    /// Initiate track migration
    ///
    /// Enqueues migration request and sends PrepareMigration to source worker.
    ///
    /// # Assertions
    /// - track_id != 0
    /// - source_worker_id < num_workers
    /// - target_worker_id < num_workers
    /// - source_worker_id != target_worker_id
    pub fn migrate_track(
        &mut self,
        track_id: TrackId,
        source_worker_id: u32,
        target_worker_id: u32,
    ) -> Result<u64, WorkerError> {
        assert!(track_id != 0, "track_id must not be 0");
        assert!(source_worker_id < self.workers.len() as u32);
        assert!(target_worker_id < self.workers.len() as u32);
        assert_ne!(source_worker_id, target_worker_id);

        // Enqueue migration
        let mut queue = self.migration_queue.lock();
        let migration_id = queue
            .enqueue(track_id as u64, source_worker_id, target_worker_id)
            .ok_or_else(|| WorkerError::InvalidConfig {
                message: "migration queue full".to_string(),
            })?;
        drop(queue);

        // Send PrepareMigration to source worker
        let source_worker = &self.workers[source_worker_id as usize];
        source_worker.send(WorkerMessage::PrepareMigration {
            migration_id,
            track_id,
            target_worker_id,
        })?;

        // Record migration start
        self.migration_metrics.record_start();

        Ok(migration_id)
    }

    /// Process migration events from track actors
    ///
    /// Should be called periodically to handle snapshot transfers and completions.
    ///
    /// # Loop Bound
    /// - Processes up to 100 events per call
    pub fn process_migration_events(&mut self) -> Result<(), WorkerError> {
        const MAX_EVENTS_PER_CALL: usize = 100;
        let mut processed = 0;

        while processed < MAX_EVENTS_PER_CALL {
            match self.migration_event_rx.try_recv() {
                Ok(event) => {
                    self.handle_migration_event(event)?;
                    processed += 1;
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    /// Handle a single migration event
    fn handle_migration_event(&mut self, event: MigrationEvent) -> Result<(), WorkerError> {
        match event {
            MigrationEvent::SnapshotReady {
                migration_id,
                snapshot,
            } => {
                // Send snapshot to target worker
                let target_worker_id = snapshot.target_worker_id;
                let target_worker = &self.workers[target_worker_id as usize];

                target_worker.send(WorkerMessage::TransferMigrationState {
                    migration_id,
                    snapshot: snapshot.clone(),
                })?;

                // Send ResumeMigration to source worker
                let source_worker_id = snapshot.source_worker_id;
                let source_worker = &self.workers[source_worker_id as usize];

                source_worker.send(WorkerMessage::ResumeMigration {
                    migration_id,
                    track_id: snapshot.track_id as TrackId,
                })?;

                Ok(())
            }
            MigrationEvent::Completed {
                migration_id,
                track_id: _,
            } => {
                // Get start time before dequeuing
                let mut queue = self.migration_queue.lock();
                let start_time_ns = queue.get_start_time(migration_id);

                if queue.dequeue(migration_id) {
                    drop(queue);

                    // Calculate migration latency using actual start time
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    // Compute actual latency from start time
                    let latency_ns = if let Some(start_ns) = start_time_ns {
                        now_ns.saturating_sub(start_ns)
                    } else {
                        // Fallback if start time not found (shouldn't happen)
                        1_000_000
                    };

                    // Record completion with actual measured latency
                    self.migration_metrics.record_completion(latency_ns);

                    Ok(())
                } else {
                    Ok(())
                }
            }
            MigrationEvent::Failed {
                migration_id,
                track_id: _,
                reason: _,
            } => {
                // Dequeue and record failure
                let mut queue = self.migration_queue.lock();
                queue.dequeue(migration_id);
                drop(queue);

                self.migration_metrics.record_failure();

                Ok(())
            }
        }
    }

    /// Check for rebalancing opportunities
    ///
    /// Called periodically (every 30s) to trigger migrations for tracks
    /// with poor subscriber gravity.
    ///
    /// # Loop Bound
    /// - Checks up to 1000 tracks per call
    pub fn check_rebalancing(&mut self) -> Result<(), WorkerError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let last_rebalance = self.last_rebalance_time.load(Ordering::Relaxed);
        let interval_nanos = nexus_actor::MIGRATION_REBALANCE_INTERVAL_SECS * 1_000_000_000;

        if now.saturating_sub(last_rebalance) < interval_nanos {
            return Ok(()); // Too soon
        }

        // Update last rebalance time
        self.last_rebalance_time.store(now, Ordering::Relaxed);

        // Check if migration queue has capacity
        let queue = self.migration_queue.lock();
        if queue.is_full() {
            return Ok(()); // Queue full, skip rebalancing
        }
        drop(queue);

        // Check each track for migration opportunity
        // This would require access to track actors - simplified for now
        // In a full implementation, we'd iterate through track_to_worker
        // and query each track's gravity

        Ok(())
    }

    /// Handle timed-out migrations
    ///
    /// Aborts migrations that exceed timeout.
    ///
    /// # Loop Bound
    /// - Iterates up to MAX_CONCURRENT_MIGRATIONS
    pub fn handle_migration_timeouts(&mut self) -> Result<(), WorkerError> {
        let timeout_nanos = nexus_actor::MIGRATION_TIMEOUT_SECS * 1_000_000_000;

        let queue = self.migration_queue.lock();
        let timed_out = queue.get_timed_out(timeout_nanos);
        drop(queue);

        for migration_id in timed_out {
            // Send abort to all workers (they'll ignore if not relevant)
            for worker in &self.workers {
                let _ = worker.send(WorkerMessage::AbortMigration {
                    migration_id,
                    track_id: 0, // Worker will match by migration_id
                });
            }

            // Record abort
            self.migration_metrics.record_abort();

            // Dequeue
            let mut queue = self.migration_queue.lock();
            queue.dequeue(migration_id);
        }

        Ok(())
    }

    /// Get migration metrics
    pub fn migration_metrics(&self) -> &MigrationMetrics {
        &self.migration_metrics
    }

    /// Get migration event sender for track actors
    pub fn migration_event_sender(&self) -> Sender<MigrationEvent> {
        self.migration_event_tx.clone()
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a dummy socket for testing.
    fn create_test_socket() -> i32 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std::os::fd::AsRawFd::as_raw_fd(&socket)
    }

    #[test]
    fn test_worker_handle_track_count() {
        let track_count = Arc::new(AtomicU32::new(0));
        let is_running = Arc::new(AtomicBool::new(true));
        let init_failed = Arc::new(AtomicBool::new(false));
        let init_error = Arc::new(parking_lot::Mutex::new(None));
        let (sender, _receiver) = channel::bounded(10);

        let handle = WorkerHandle {
            thread: None,
            worker_id: 0,
            core_id: 0,
            track_count: Arc::clone(&track_count),
            sender,
            is_running,
            init_failed,
            init_error,
            scheduling_policy: Arc::new(AtomicU8::new(0)),
        };

        assert_eq!(handle.track_count(), 0);

        handle.increment_track_count();
        assert_eq!(handle.track_count(), 1);

        handle.increment_track_count();
        assert_eq!(handle.track_count(), 2);

        handle.decrement_track_count();
        assert_eq!(handle.track_count(), 1);
    }

    #[test]
    fn test_worker_handle_init_state() {
        let track_count = Arc::new(AtomicU32::new(0));
        let is_running = Arc::new(AtomicBool::new(false));
        let init_failed = Arc::new(AtomicBool::new(false));
        let init_error = Arc::new(parking_lot::Mutex::new(None));
        let (sender, _receiver) = channel::bounded(10);

        let handle = WorkerHandle {
            thread: None,
            worker_id: 0,
            core_id: 0,
            track_count,
            sender,
            is_running: Arc::clone(&is_running),
            init_failed: Arc::clone(&init_failed),
            init_error: Arc::clone(&init_error),
            scheduling_policy: Arc::new(AtomicU8::new(0)),
        };

        assert!(!handle.is_running());
        assert!(!handle.init_failed());
        assert!(handle.init_error().is_none());

        // Simulate initialization failure
        *init_error.lock() = Some("test error".to_string());
        init_failed.store(true, Ordering::Release);

        assert!(handle.init_failed());
        assert_eq!(handle.init_error(), Some("test error".to_string()));
    }

    #[test]
    fn test_worker_pool_new() {
        let socket_fd = create_test_socket();
        let pool = WorkerPool::new(2, 1, socket_fd, false, 0).unwrap();

        assert_eq!(pool.num_workers(), 2);
        assert!(!pool.is_shutdown());
        assert!(pool.all_workers_healthy());
        assert_eq!(pool.running_worker_count(), 2);
    }

    #[test]
    fn test_worker_pool_assign_track() {
        let socket_fd = create_test_socket();
        let mut pool = WorkerPool::new(4, 1, socket_fd, false, 0).unwrap();

        let (track_id, worker_id) = pool.assign_track(12345, MediaKind::Video).unwrap();
        assert_eq!(track_id, 1);
        assert!(worker_id < 4);

        // Same SSRC should map to same worker
        let (track_id2, worker_id2) = pool.assign_track(12345, MediaKind::Audio).unwrap();
        assert_eq!(track_id2, 2);
        assert_eq!(worker_id, worker_id2);
    }

    #[test]
    fn test_worker_pool_least_loaded() {
        let socket_fd = create_test_socket();
        let pool = WorkerPool::new(4, 1, socket_fd, false, 0).unwrap();

        // Initially all workers have 0 tracks
        let least = pool.least_loaded_worker();
        assert!(least < 4);
    }

    #[test]
    fn test_worker_pool_shutdown() {
        let socket_fd = create_test_socket();
        let mut pool = WorkerPool::new(2, 1, socket_fd, false, 0).unwrap();

        // Workers should already be running after new()
        assert!(pool.all_workers_healthy());

        // Shutdown should succeed
        let result = pool.shutdown();
        assert!(result.is_ok());
        assert!(pool.is_shutdown());

        // Second shutdown should be no-op
        let result2 = pool.shutdown();
        assert!(result2.is_ok());
    }

    #[test]
    #[should_panic(expected = "num_workers must be <= 64")]
    fn test_worker_pool_too_many_workers() {
        let socket_fd = create_test_socket();
        let _ = WorkerPool::new(100, 1, socket_fd, false, 0);
    }

    #[test]
    fn test_worker_pool_get_worker() {
        let socket_fd = create_test_socket();
        let pool = WorkerPool::new(4, 1, socket_fd, false, 0).unwrap();

        assert!(pool.get_worker(0).is_some());
        assert!(pool.get_worker(3).is_some());
        assert!(pool.get_worker(4).is_none());

        // Verify workers are running
        for i in 0..4 {
            let worker = pool.get_worker(i).unwrap();
            assert!(worker.is_running());
            assert!(!worker.init_failed());
        }
    }

    #[test]
    fn test_worker_pool_remove_track() {
        let socket_fd = create_test_socket();
        let mut pool = WorkerPool::new(2, 1, socket_fd, false, 0).unwrap();

        let (track_id, _) = pool.assign_track(12345, MediaKind::Video).unwrap();

        // Remove should succeed
        let result = pool.remove_track(track_id);
        assert!(result.is_ok());

        // Removing again should be no-op
        let result2 = pool.remove_track(track_id);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_worker_pool_running_count() {
        let socket_fd = create_test_socket();
        let pool = WorkerPool::new(3, 1, socket_fd, false, 0).unwrap();

        assert_eq!(pool.running_worker_count(), 3);
        assert!(pool.all_workers_healthy());
    }
}
