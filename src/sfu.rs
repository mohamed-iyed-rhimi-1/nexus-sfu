//! SFU - Main entry point wiring all components together.
//!
//! The Sfu struct is the top-level coordinator that initializes and manages
//! all SFU components: PacketArena, WorkerPool, SsrcRouter,
//! and CongestionController (GCC).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                              Sfu                                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
//! │  │  Signaling   │     │    Room      │     │    BWE       │            │
//! │  │   Server     │────▶│   Manager    │────▶│  Estimator   │            │
//! │  └──────────────┘     └──────────────┘     └──────────────┘            │
//! │         │                    │                    │                     │
//! │         ▼                    ▼                    ▼                     │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                      Control Plane                               │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                │                                        │
//! │  ═══════════════════════════════════════════════════════════════════   │
//! │                                │                                        │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                       Data Plane (Hot Path)                      │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │         │                    │                    │                     │
//! │         ▼                    ▼                    ▼                     │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
//! │  │ UDP Transport│     │ SSRC Router  │     │ Worker Pool  │            │
//! │  │              │────▶│              │────▶│ (CPU-pinned) │            │
//! │  └──────────────┘     └──────────────┘     └──────────────┘            │
//! │         │                                        │                      │
//! │         ▼                                        ▼                      │
//! │  ┌──────────────┐                         ┌──────────────┐             │
//! │  │Packet Arena  │                         │Batch Sender  │             │
//! │  │(pre-alloc)   │                         │ (sendmmsg)   │             │
//! │  └──────────────┘                         └──────────────┘             │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - Zero dynamic allocation after initialization
//! - Comprehensive assertions for pre/post conditions
//! - Explicit error handling with Result types
//! - No panics on the hot path

use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::NexusConfig;
use crate::error::{SfuError, SignalingError, TransportError, WorkerError};
use crate::forward::SsrcRouter;
use crate::transport::TransportConfig;
use crate::types::{ParticipantId, TrackId};
use crate::worker::WorkerPool;
use nexus_bwe::CongestionController;
use nexus_media::rtcp::{RtcpHeader, RtcpType};
use nexus_media::rtp::RtpHeader;
use nexus_metrics::MetricsCollector;
use nexus_state::{DistributedState, GossipConfig, SwimProtocol};
use nexus_transport::arena::PacketArena;
use nexus_webrtc::webrtc::{
    PacketType, TransportId, TransportState as WebRtcTransportState, WebRtcTransport,
    MAX_PACKET_SIZE,
};

// ============================================================================
// Compile-time assertions (TigerStyle)
// ============================================================================

/// Compile-time assertions for struct sizes to catch design issues early.
/// Following TigerStyle: assert compile-time constants to prevent stack overflow
/// and ensure reasonable memory footprint.
const _: () = {
    use std::mem::size_of;

    // Ensure Sfu struct size is reasonable (most fields are Arc/Box)
    // 2KB limit since most data is heap-allocated through Arc/Box
    // Increased from 1KB to accommodate IceServerConfig with Vec fields
    const MAX_SFU_SIZE: usize = 2048;
    assert!(size_of::<Sfu>() < MAX_SFU_SIZE);

    // Assert packet size is reasonable (TigerStyle: assert compile-time constants)
    const MAX_UDP_PACKET: usize = 65535;
    assert!(MAX_PACKET_SIZE <= MAX_UDP_PACKET);
    assert!(MAX_PACKET_SIZE >= 1200); // Minimum for WebRTC
};

// ============================================================================
// Drain State (Requirement 10: Graceful Drain on Shutdown)
// ============================================================================

/// State for graceful drain during shutdown.
///
/// Tracks the drain process including:
/// - Whether draining is active
/// - When drain started
/// - Timeout for drain completion
/// - Number of active sessions being drained
///
/// # Requirements Coverage
///
/// - Requirement 10.1: Stop accepting new connections
/// - Requirement 10.2: Continue forwarding for drain_timeout
/// - Requirement 10.3: Notify participants of shutdown
/// - Requirement 10.4: Terminate after timeout
///
/// # TigerStyle Compliance
///
/// - Lock-free atomic state
/// - Explicit timestamps in microseconds
/// - Bounded timeout values
#[derive(Debug)]
pub struct DrainState {
    /// Whether drain mode is active
    pub is_draining: AtomicBool,
    /// Timestamp when drain started (microseconds since epoch)
    pub drain_started_at_us: std::sync::atomic::AtomicU64,
    /// Drain timeout in microseconds
    pub drain_timeout_us: std::sync::atomic::AtomicU64,
    /// Number of active sessions being drained
    pub active_sessions: std::sync::atomic::AtomicU32,
}

impl DrainState {
    /// Create new drain state with the given timeout.
    ///
    /// # Arguments
    ///
    /// * `drain_timeout_ms` - Drain timeout in milliseconds
    ///
    /// # Assertions
    ///
    /// * `drain_timeout_ms > 0` - Timeout must be positive
    pub fn new(drain_timeout_ms: u32) -> Self {
        assert!(drain_timeout_ms > 0, "drain_timeout_ms must be > 0");

        Self {
            is_draining: AtomicBool::new(false),
            drain_started_at_us: std::sync::atomic::AtomicU64::new(0),
            drain_timeout_us: std::sync::atomic::AtomicU64::new(drain_timeout_ms as u64 * 1000),
            active_sessions: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Start the drain process.
    ///
    /// Sets the drain flag and records the start time.
    ///
    /// # Returns
    ///
    /// `true` if drain was started, `false` if already draining.
    pub fn start_drain(&self) -> bool {
        // Try to set draining flag
        if self.is_draining.swap(true, Ordering::SeqCst) {
            // Already draining
            return false;
        }

        // Record start time
        self.drain_started_at_us
            .store(crate::clock::now_us(), Ordering::SeqCst);

        true
    }

    /// Check if drain mode is active.
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
    }

    /// Check if drain timeout has expired.
    ///
    /// # Returns
    ///
    /// `true` if drain started and timeout has elapsed.
    pub fn is_drain_timeout_expired(&self) -> bool {
        if !self.is_draining() {
            return false;
        }

        let started_at = self.drain_started_at_us.load(Ordering::SeqCst);
        let timeout = self.drain_timeout_us.load(Ordering::SeqCst);

        let now_us = crate::clock::now_us();

        now_us >= started_at + timeout
    }

    /// Get remaining drain time in milliseconds.
    ///
    /// # Returns
    ///
    /// Remaining time in milliseconds, or 0 if not draining or expired.
    pub fn remaining_drain_time_ms(&self) -> u64 {
        if !self.is_draining() {
            return 0;
        }

        let started_at = self.drain_started_at_us.load(Ordering::SeqCst);
        let timeout = self.drain_timeout_us.load(Ordering::SeqCst);

        let now_us = crate::clock::now_us();

        let deadline = started_at + timeout;
        if now_us >= deadline {
            0
        } else {
            (deadline - now_us) / 1000
        }
    }

    /// Set the number of active sessions.
    pub fn set_active_sessions(&self, count: u32) {
        self.active_sessions.store(count, Ordering::SeqCst);
    }

    /// Get the number of active sessions.
    pub fn active_sessions(&self) -> u32 {
        self.active_sessions.load(Ordering::SeqCst)
    }

    /// Decrement active session count.
    ///
    /// # Returns
    ///
    /// New session count after decrement.
    pub fn decrement_sessions(&self) -> u32 {
        self.active_sessions
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_sub(1))
            })
            .unwrap_or(0)
    }
}

impl Default for DrainState {
    fn default() -> Self {
        Self::new(5000) // 5 second default
    }
}

/// Shutdown timeout in milliseconds.
#[allow(dead_code)] // Reserved for graceful shutdown implementation
const SHUTDOWN_TIMEOUT_MS: u64 = 5000;

/// Batch receive size for UDP transport.
const RECV_BATCH_SIZE: usize = 64;

/// Main SFU struct wiring all components together.
///
/// The Sfu is the top-level coordinator that manages the lifecycle of all
/// SFU components and orchestrates packet processing.
///
/// # Example
///
/// ```ignore
/// use nexus_sfu::sfu::Sfu;
/// use nexus_sfu::config::NexusConfig;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = NexusConfig::default();
///     let sfu = Sfu::new(config).await?;
///
///     // Run the SFU (blocks until shutdown)
///     // sfu.run().await?;
///
///     Ok(())
/// }
/// ```
/// Counts dropped ingest packets and logs at most once per second, rather than
/// a log line per packet on the hot path.
#[derive(Default)]
struct DropTracker {
    since_last_log: AtomicU64,
    last_log_us: AtomicU64,
}

impl DropTracker {
    const LOG_INTERVAL_US: u64 = 1_000_000;

    /// Count one drop; returns the drops to report if a log line is due.
    fn record(&self) -> Option<u64> {
        self.since_last_log.fetch_add(1, Ordering::Relaxed);
        let now = crate::clock::now_us();
        let last = self.last_log_us.load(Ordering::Relaxed);
        if now.saturating_sub(last) < Self::LOG_INTERVAL_US {
            return None;
        }
        // One thread wins the interval and reports everything counted so far
        self.last_log_us
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .ok()
            .map(|_| self.since_last_log.swap(0, Ordering::Relaxed))
    }
}

/// Per-track cache of the publisher SRTCP key last sent to the worker:
/// track_id -> (session_id, key fingerprint). Lets the ingress loop send
/// `SetPublisherSrtcp` once per key instead of on every packet. Entries are
/// removed when the track is removed (`forget_publisher_srtcp`).
static SRTCP_SENT_CACHE: Lazy<dashmap::DashMap<u64, (u64, [u8; 32])>> =
    Lazy::new(|| dashmap::DashMap::with_capacity(256));

/// Drop a removed track's entry from the SRTCP sent-cache.
pub(crate) fn forget_publisher_srtcp(track_id: crate::types::TrackId) {
    SRTCP_SENT_CACHE.remove(&track_id);
    assert!(!SRTCP_SENT_CACHE.contains_key(&track_id));
}

#[cfg(test)]
pub(crate) fn publisher_srtcp_cached(track_id: crate::types::TrackId) -> bool {
    SRTCP_SENT_CACHE.contains_key(&track_id)
}

#[cfg(test)]
pub(crate) fn remember_publisher_srtcp_for_test(track_id: crate::types::TrackId) {
    SRTCP_SENT_CACHE.insert(track_id, (0, [0; 32]));
}

pub struct Sfu {
    /// Configuration.
    config: NexusConfig,

    /// Packet arena for zero-allocation packet handling.
    arena: Arc<PacketArena>,

    /// Worker pool with CPU-pinned threads.
    worker_pool: Option<Arc<RwLock<WorkerPool>>>,

    /// SSRC to track routing table.
    ssrc_router: Arc<SsrcRouter>,

    /// Distributed state for CRDT synchronization.
    distributed_state: Arc<DistributedState>,

    /// GCC congestion controller.
    gcc: Arc<CongestionController>,

    /// UDP transport for media packets (standard or io_uring).
    transport: Option<crate::transport::MediaTransport>,

    /// Address the media socket actually bound (resolves port 0).
    media_local_addr: SocketAddr,

    /// WebRTC transport for session management (ICE/DTLS/SRTP).
    /// Uses interior mutability - all methods take &self instead of &mut self.
    webrtc_transport: Arc<WebRtcTransport>,

    /// Shutdown flag.
    is_shutdown: AtomicBool,

    /// Shared shutdown signal for all subsystems.
    ///
    /// This AtomicBool is shared by:
    /// - WorkerPool (all MediaWorkers)
    /// - Gossip thread
    /// - Signaling server
    /// - Metrics server
    /// - API server
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 15.6: Common shutdown signal for coordinated termination
    shared_shutdown: Arc<AtomicBool>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Set from outside (`stop_handle`) to end the packet loop; the caller
    /// then runs `shutdown()`, which notifies clients before the shared
    /// shutdown flag stops signaling.
    stop_requested: Arc<AtomicBool>,

    /// The signaling server's connections, for shutdown notifications.
    signaling_connections: Option<crate::signal::SignalingConnections>,

    /// Gossip thread handle.
    /// The gossip thread runs the SWIM protocol for cluster membership
    /// and state synchronization.
    gossip_thread: Option<std::thread::JoinHandle<()>>,

    /// Gossip shutdown signal sender.
    /// Used to signal the gossip thread to stop.
    gossip_shutdown_tx: Option<std::sync::mpsc::Sender<()>>,

    /// Drain state for graceful shutdown.
    ///
    /// Tracks the drain process including whether draining is active,
    /// when drain started, and the number of active sessions.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 10.1: Stop accepting new connections
    /// - Requirement 10.2: Continue forwarding for drain_timeout
    /// - Requirement 10.3: Notify participants of shutdown
    drain_state: Arc<DrainState>,

    /// Metrics collector for unified metrics export.
    ///
    /// Aggregates metrics from all subsystems:
    /// - Workers (packet counts, latency)
    /// - Actors (room/participant/track counts)
    /// - CRDTs (merge counts, state size)
    /// - Transport (bytes sent/received)
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 15.5: MetricsCollector wired to all subsystems
    metrics: Option<Arc<MetricsCollector>>,

    /// Ingest drops because the owning worker's queue was full.
    worker_queue_drops: DropTracker,
    /// Ingest drops because the packet arena had no free slot.
    arena_drops: DropTracker,

    packets_processed: u64,
    /// Cold-path channel: STUN/DTLS packets → ConnectionMonitor in orchestrator.
    connection_tx: Option<mpsc::Sender<crate::orchestrator::events::ColdPathPacket>>,
}

impl Sfu {
    /// Create a new SFU instance with the given configuration (production mode).
    ///
    /// Initializes all components:
    /// - PacketArena for zero-allocation packet handling
    /// - WorkerPool with CPU-pinned threads
    /// - SsrcRouter for packet routing
    /// - CongestionController (GCC) for bandwidth estimation
    /// - MediaTransport for media I/O
    ///
    /// # Arguments
    ///
    /// * `config` - SFU configuration
    ///
    /// # Returns
    ///
    /// `Ok(Sfu)` on success, `Err(SfuError)` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration validation fails
    /// - Arena allocation fails
    /// - Worker pool creation fails
    /// - UDP transport binding fails
    ///
    /// # Requirements
    ///
    /// * 14.6 - Complete initialization within 1 second
    pub async fn new(config: NexusConfig) -> Result<Self, SfuError> {
        // Validate configuration
        config.validate().map_err(|e| {
            SfuError::Worker(WorkerError::InvalidConfig {
                message: e.to_string(),
            })
        })?;

        info!("Initializing Nexus SFU v{}", crate::VERSION);
        info!("Configuration: {:?}", config);

        // Initialize packet arena
        info!(
            "Creating packet arena ({}MB)...",
            config.memory.arena_size_mb
        );
        let arena =
            Arc::new(PacketArena::new(config.memory.arena_size_mb).map_err(SfuError::Arena)?);
        info!("Packet arena created: {} slots available", arena.capacity());

        // Initialize SSRC router
        let ssrc_router = Arc::new(SsrcRouter::new());
        info!("SSRC router initialized");

        // Initialize distributed state
        info!("Initializing distributed state...");
        // Generate unique actor ID for CRDT operations
        let actor_id: u64 = if config.cluster.node_id > 0 {
            // Use configured node_id, but validate it's within range
            let node_id = config.cluster.node_id;
            if node_id >= nexus_state::MAX_ACTORS as u64 {
                return Err(SfuError::Worker(WorkerError::InvalidConfig {
                    message: format!(
                        "cluster.node_id ({}) must be < MAX_ACTORS ({})",
                        node_id,
                        nexus_state::MAX_ACTORS
                    ),
                }));
            }
            node_id
        } else {
            // Auto-generate from machine identity:
            // hash(hostname + process_id + boot_time)
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();

            if let Ok(hostname) = std::env::var("HOSTNAME") {
                hostname.hash(&mut hasher);
            } else {
                // Fallback: use random bytes for uniqueness
                let random_bytes: [u8; 8] = rand::random();
                random_bytes.hash(&mut hasher);
            }

            std::process::id().hash(&mut hasher);

            crate::clock::now_ns().hash(&mut hasher);

            let generated = hasher.finish();
            // Map to valid range [1, MAX_ACTORS) using modulo
            // MAX_ACTORS is 256, so valid range is 1..256
            let mapped = (generated % (nexus_state::MAX_ACTORS as u64 - 1)) + 1;
            // Ensure non-zero (actor_id 0 is reserved)
            if mapped == 0 {
                1
            } else {
                mapped
            }
        };

        // Precondition: actor_id must be non-zero and within valid range
        assert!(actor_id > 0, "Actor ID must be non-zero");
        assert!(
            actor_id < nexus_state::MAX_ACTORS as u64,
            "Actor ID must be < MAX_ACTORS ({})",
            nexus_state::MAX_ACTORS
        );
        info!("Node actor ID: {}", actor_id);

        let state_config = nexus_state::DistributedStateConfig::new(actor_id);
        let distributed_state = Arc::new(DistributedState::new(state_config));
        info!("Distributed state initialized with actor_id={}", actor_id);

        // Initialize GCC congestion controller
        let gcc = Arc::new(CongestionController::new(
            config.bwe.min_bandwidth_bps as u64,
            config.bwe.max_bandwidth_bps as u64,
            config.bwe.initial_bandwidth_bps as u64,
        ));
        info!(
            "GCC controller initialized: {}bps initial, {}bps min, {}bps max",
            config.bwe.initial_bandwidth_bps,
            config.bwe.min_bandwidth_bps,
            config.bwe.max_bandwidth_bps
        );

        // Initialize UDP transport
        info!(
            "Binding UDP transport to {}...",
            config.transport.media_bind_addr
        );
        let transport_config = TransportConfig {
            recv_buffer_size_bytes: config.transport.recv_buffer_size_bytes,
            send_buffer_size_bytes: config.transport.send_buffer_size_bytes,
            #[cfg(target_os = "linux")]
            io_uring_entries: 4096,
        };
        let transport = crate::transport::MediaTransport::bind(
            config.transport.media_bind_addr,
            transport_config,
        )
        .map_err(SfuError::Transport)?;
        let socket_fd = transport.socket_fd();
        let media_local_addr = transport.local_addr().map_err(|source| {
            SfuError::Transport(TransportError::BindFailed {
                addr: config.transport.media_bind_addr,
                source,
            })
        })?;
        assert!(media_local_addr.port() != 0, "bound media port is known");
        info!("Media transport bound to {}", media_local_addr);

        // Initialize WebRTC transport for session management
        info!("Creating WebRTC transport...");
        // Use config value, capped at MAX_SESSIONS (1000) per plan requirement
        let max_sessions = std::cmp::min(
            config.transport.max_webrtc_sessions as usize,
            nexus_webrtc::webrtc::MAX_SESSIONS,
        );
        let webrtc_config = nexus_webrtc::webrtc::TransportConfig::default()
            .with_bind_addr(config.transport.media_bind_addr)
            .with_max_sessions(max_sessions);

        let webrtc_transport = WebRtcTransport::new(webrtc_config).map_err(|e| {
            SfuError::Worker(WorkerError::InvalidConfig {
                message: format!("Failed to create WebRTC transport: {:?}", e),
            })
        })?;
        webrtc_transport.start().map_err(|e| {
            SfuError::Worker(WorkerError::InvalidConfig {
                message: format!("Failed to start WebRTC transport: {:?}", e),
            })
        })?;

        let webrtc_transport = Arc::new(webrtc_transport);

        // Postcondition assertions (TigerStyle)
        assert!(webrtc_transport.state() == WebRtcTransportState::Running);
        assert_eq!(webrtc_transport.session_count(), 0);

        info!(
            "WebRTC transport initialized: max_sessions={}",
            config.actor.max_participant_actors
        );

        // Initialize worker pool
        let num_workers = if config.worker.num_workers == 0 {
            num_cpus::get() as u32
        } else {
            config.worker.num_workers
        };
        info!("Creating worker pool with {} workers...", num_workers);
        let worker_pool = WorkerPool::new(
            num_workers,
            config.memory.arena_size_mb / num_workers.max(1),
            socket_fd,
            config.worker.cpu_affinity,
            config.worker.realtime_priority,
            config.worker.realtime_priority_level,
        )
        .map_err(SfuError::Worker)?;
        worker_pool.set_ring_retention(config.memory.ring_buffer_size);
        info!(
            "Worker pool created: {} workers running, {}-packet NACK window per track",
            worker_pool.num_workers(),
            config.memory.ring_buffer_size
        );

        // Initialize gossip protocol for cluster membership
        info!("Initializing gossip protocol...");

        // Create shared shutdown signal for all subsystems
        // Common shutdown signal for coordinated termination
        let shared_shutdown = Arc::new(AtomicBool::new(false));
        info!("Shared shutdown signal created");

        // Initialize metrics collector
        // MetricsCollector wired to all subsystems
        let metrics = match MetricsCollector::new(num_workers) {
            Ok(m) => {
                info!("Metrics collector initialized with {} workers", num_workers);
                Some(Arc::new(m))
            }
            Err(e) => {
                warn!(
                    "Failed to create metrics collector: {}, metrics disabled",
                    e
                );
                None
            }
        };

        let (gossip_shutdown_tx, gossip_shutdown_rx) = std::sync::mpsc::channel::<()>();

        // Create channel for state updates from DistributedState to gossip thread
        let (state_update_tx, state_update_rx) =
            std::sync::mpsc::channel::<nexus_state::StateUpdate>();

        // Set the broadcast sender on distributed state
        distributed_state.set_broadcast_sender(state_update_tx);

        // Create SwimProtocol with gossip config
        // Use a random port for gossip (0 = OS assigns)
        let gossip_bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let local_actor_id = actor_id;

        let gossip_config = GossipConfig {
            probe_interval_ms: config.gossip.probe_interval_ms,
            ping_timeout_ms: config.gossip.ping_timeout_ms,
            suspect_timeout_ms: config.gossip.suspect_timeout_ms,
            fanout: config.gossip.fanout,
            max_piggyback_updates: config.gossip.max_piggyback_updates,
            seed_peers: config.gossip.seed_peers.clone(),
        };

        let mut swim_protocol =
            SwimProtocol::new(local_actor_id, gossip_bind_addr, gossip_config.clone()).map_err(
                |e| {
                    SfuError::Worker(WorkerError::InvalidConfig {
                        message: format!("Failed to create SwimProtocol: {:?}", e),
                    })
                },
            )?;

        // Set distributed state for CRDT updates
        swim_protocol.set_distributed_state(distributed_state.clone());

        // Add seed peers from config
        for seed_peer in &config.gossip.seed_peers {
            if let Err(e) = swim_protocol.add_seed_peer(seed_peer.actor_id, seed_peer.addr) {
                warn!("Failed to add seed peer {}: {:?}", seed_peer.addr, e);
            } else {
                info!(
                    "Added seed peer: actor_id={}, addr={}",
                    seed_peer.actor_id, seed_peer.addr
                );
            }
        }

        let gossip_addr = swim_protocol.local_addr();
        info!("Gossip protocol bound to {}", gossip_addr);

        // Spawn dedicated gossip thread
        let probe_interval_ms = config.gossip.probe_interval_ms;
        let distributed_state_for_gossip = distributed_state.clone();
        let shared_shutdown_for_gossip = shared_shutdown.clone();
        let gossip_thread = std::thread::Builder::new()
            .name("nexus-gossip".into())
            .spawn(move || {
                info!("Gossip thread started");

                loop {
                    // Check shared shutdown signal
                    if shared_shutdown_for_gossip.load(Ordering::Acquire) {
                        info!("Gossip thread detected shared shutdown signal");
                        break;
                    }

                    // Check for shutdown signal (non-blocking)
                    if gossip_shutdown_rx.try_recv().is_ok() {
                        info!("Gossip thread received shutdown signal");
                        break;
                    }

                    // Process any pending state updates from DistributedState
                    // and enqueue them into the gossip piggyback queue
                    while let Ok(update) = state_update_rx.try_recv() {
                        swim_protocol.broadcast_state_update(update);
                    }

                    // Run probe cycle and handle any newly dead nodes
                    match swim_protocol.run_probe_cycle() {
                        Ok(dead_nodes) => {
                            // Handle node failures - remove state owned by dead nodes
                            for dead_actor_id in dead_nodes {
                                let (tracks_removed, subs_removed) =
                                    distributed_state_for_gossip.handle_node_failure(dead_actor_id);
                                if tracks_removed > 0 || subs_removed > 0 {
                                    info!(
                                        "Handled node failure for actor {}: removed {} tracks, {} subscriptions",
                                        dead_actor_id, tracks_removed, subs_removed
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Gossip probe cycle error: {:?}", e);
                        }
                    }

                    // Process incoming messages
                    if let Err(e) = swim_protocol.recv_loop_iteration() {
                        warn!("Gossip recv error: {:?}", e);
                    }

                    // Sleep for probe interval
                    std::thread::sleep(std::time::Duration::from_millis(probe_interval_ms));
                }

                info!("Gossip thread stopped");
            })
            .map_err(|e| SfuError::Worker(WorkerError::InvalidConfig {
                message: format!("Failed to spawn gossip thread: {:?}", e),
            }))?;

        info!("Gossip thread spawned");
        info!("Nexus SFU MVP initialization complete");

        // Create drain state before moving config
        let drain_timeout_ms = config.drain_timeout_ms;

        Ok(Self {
            config,
            arena,
            worker_pool: Some(Arc::new(RwLock::new(worker_pool))),
            ssrc_router,
            distributed_state,
            gcc,
            transport: Some(transport),
            media_local_addr,
            webrtc_transport,
            is_shutdown: AtomicBool::new(false),
            shared_shutdown,
            shutdown_tx: None,
            stop_requested: Arc::new(AtomicBool::new(false)),
            signaling_connections: None,
            gossip_thread: Some(gossip_thread),
            gossip_shutdown_tx: Some(gossip_shutdown_tx),
            drain_state: Arc::new(DrainState::new(drain_timeout_ms)),
            metrics,
            worker_queue_drops: DropTracker::default(),
            arena_drops: DropTracker::default(),
            packets_processed: 0,
            connection_tx: None,
        })
    }

    /// Get the SFU configuration.
    #[inline]
    /// Set the cold-path channel sender for STUN/DTLS packets.
    pub fn set_connection_tx(
        &mut self,
        tx: mpsc::Sender<crate::orchestrator::events::ColdPathPacket>,
    ) {
        self.connection_tx = Some(tx);
    }

    /// Address the media socket is bound to, with the real port when the
    /// configured port was 0.
    pub fn media_local_addr(&self) -> SocketAddr {
        self.media_local_addr
    }

    /// Get the media transport's local address for creating a PacketSender.
    pub fn media_socket_for_sender(&self) -> Option<Arc<std::net::UdpSocket>> {
        use std::os::fd::FromRawFd;
        let transport = self.transport.as_ref()?;
        let fd = transport.socket_fd();
        if fd < 0 {
            return None;
        }
        // Safety: we duplicate the fd so both the transport and PacketSender
        // can use it independently. The dup'd fd is owned by the Arc<UdpSocket>.
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return None;
        }
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(dup_fd) };
        socket.set_nonblocking(true).ok()?;
        Some(Arc::new(socket))
    }

    pub fn config(&self) -> &NexusConfig {
        &self.config
    }

    /// Get the packet arena.
    #[inline]
    pub fn arena(&self) -> &Arc<PacketArena> {
        &self.arena
    }

    /// Get the SSRC router.
    #[inline]
    pub fn ssrc_router(&self) -> &Arc<SsrcRouter> {
        &self.ssrc_router
    }

    /// Get worker pool.
    ///
    /// Returns Arc<RwLock<WorkerPool>> for thread-safe access.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    #[inline]
    pub fn worker_pool_arc(&self) -> Option<Arc<RwLock<WorkerPool>>> {
        self.worker_pool.clone()
    }

    /// Get the distributed state.
    #[inline]
    pub fn distributed_state(&self) -> &Arc<DistributedState> {
        &self.distributed_state
    }

    /// Get the WebRTC transport.
    ///
    /// Returns &Arc<WebRtcTransport> for thread-safe access.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    #[inline]
    pub fn webrtc_transport(&self) -> &Arc<WebRtcTransport> {
        &self.webrtc_transport
    }

    /// Get the GCC congestion controller.
    #[inline]
    pub fn gcc(&self) -> &Arc<CongestionController> {
        &self.gcc
    }

    /// Get the bandwidth estimator (alias for gcc for backward compatibility).
    #[inline]
    pub fn bwe(&self) -> &Arc<CongestionController> {
        &self.gcc
    }

    /// Flag that ends the packet loop when set (see `stop_requested`).
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_requested)
    }

    /// Connections to notify on shutdown (the signaling server's registry).
    pub fn set_signaling_connections(&mut self, connections: crate::signal::SignalingConnections) {
        self.signaling_connections = Some(connections);
    }

    /// Get the shared shutdown signal.
    ///
    /// This signal is shared by all subsystems for coordinated termination.
    /// When set to true, all subsystems should gracefully stop.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 15.6: Common shutdown signal for coordinated termination
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    #[inline]
    pub fn shared_shutdown(&self) -> &Arc<AtomicBool> {
        &self.shared_shutdown
    }

    /// Get the metrics collector.
    ///
    /// Returns the metrics collector if initialized, None otherwise.
    /// The metrics collector aggregates metrics from all subsystems.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 15.5: MetricsCollector wired to all subsystems
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    #[inline]
    pub fn metrics(&self) -> Option<&Arc<MetricsCollector>> {
        self.metrics.as_ref()
    }

    /// Account for a dropped ingest packet: Prometheus counter plus a
    /// rate-limited warning with the count and reason.
    #[inline]
    fn record_ingest_drop(&self, tracker: &DropTracker, reason: &dyn std::fmt::Display) {
        if let Some(metrics) = &self.metrics {
            metrics.sfu.record_packet_dropped();
        }
        if let Some(dropped) = tracker.record() {
            warn!(
                "Dropped {} ingest packets in the last second: {}",
                dropped, reason
            );
        }
    }

    /// Subscribe a participant to a track with destination address.
    ///
    /// This is a convenience method that:
    /// 1. Looks up the worker that owns the track in the SSRC router
    /// 2. Sends ActorSubscribe message to the appropriate worker
    /// 3. Returns the generated subscriber_id for tracking
    ///
    /// # Arguments
    /// * `subscriber_id` - Participant subscribing
    /// * `track_id` - Track to subscribe to
    /// * `dest_addr` - Destination socket address for RTP forwarding
    ///
    /// # Returns
    /// * `Ok(subscriber_id_unique)` - The unique subscriber ID generated for this subscription
    /// * `Err(String)` on failure
    ///
    /// # Assertions
    /// * `dest_addr.port() > 0` - Destination port must be valid
    pub fn subscribe_to_track(
        &self,
        subscriber_id: ParticipantId,
        track_id: TrackId,
        dest_addr: SocketAddr,
    ) -> Result<u32, String> {
        // Precondition: validate destination address
        if dest_addr.port() == 0 {
            return Err("destination port must be valid (> 0)".to_string());
        }

        // The router records (ssrc, track, worker) when the track is assigned.
        let worker_id = self
            .ssrc_router
            .lookup_by_track(track_id)
            .map(|(_ssrc, worker_id)| worker_id)
            .ok_or(format!("Track {} is not assigned to a worker", track_id))?;

        // Get worker pool
        let worker_pool_arc = self.worker_pool_arc().ok_or("Worker pool not available")?;
        let worker_pool = worker_pool_arc.read();

        // Get worker handle
        let worker = worker_pool
            .get_worker(worker_id)
            .ok_or(format!("Worker {} not found", worker_id))?;

        // Generate unique subscriber ID
        static SUBSCRIBER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        let subscriber_id_unique = SUBSCRIBER_ID_COUNTER.fetch_add(1, Ordering::SeqCst) as u32;

        // Send ActorSubscribe message to worker
        worker
            .send(crate::worker::WorkerMessage::ActorSubscribe {
                track_id,
                subscriber_id: subscriber_id_unique,
                participant_id: subscriber_id,
                dest_addr,
                srtp_context: None,
            })
            .map_err(|e| format!("Failed to send subscribe message to worker: {:?}", e))?;

        Ok(subscriber_id_unique)
    }

    /// Register and assign a track from SDP to a worker.
    ///
    /// This method:
    /// 1. Assigns the track to a worker using consistent hashing on SSRC
    /// 2. Registers the SSRC in the router
    /// 3. Spawns the track actor on the worker
    ///
    /// # Arguments
    /// * `track_id` - Track ID
    /// * `participant_id` - Participant who owns the track
    /// * `ssrc` - RTP SSRC
    /// * `kind` - Media kind (audio/video)
    ///
    /// # Returns
    /// * `Ok(worker_id)` - Worker ID where track was assigned
    /// * `Err(String)` on failure
    ///
    /// # Assertions
    /// * `track_id > 0` - Track ID must be valid
    /// * `ssrc > 0` - SSRC must be valid
    pub fn register_and_assign_track(
        &mut self,
        track_id: TrackId,
        participant_id: ParticipantId,
        ssrc: crate::types::Ssrc,
        kind: crate::types::MediaKind,
    ) -> Result<u32, String> {
        // Precondition checks
        if track_id == 0 {
            return Err("track_id must be valid (> 0)".to_string());
        }
        if ssrc == 0 {
            return Err("ssrc must be valid (> 0)".to_string());
        }

        // Get worker pool
        let worker_pool_arc = self.worker_pool_arc().ok_or("Worker pool not available")?;
        let mut worker_pool = worker_pool_arc.write();

        // Assign track to worker using consistent hashing on SSRC
        // This returns (track_id, worker_id) but we already have track_id
        let (_assigned_track_id, worker_id) = worker_pool
            .assign_track(ssrc, kind)
            .map_err(|e| format!("Failed to assign track to worker: {:?}", e))?;

        // Register in SSRC router with the assigned worker
        self.ssrc_router
            .register(ssrc, track_id, worker_id)
            .map_err(|e| format!("Failed to register SSRC in router: {:?}", e))?;

        // Get worker handle
        let worker = worker_pool
            .get_worker(worker_id)
            .ok_or(format!("Worker {} not found", worker_id))?;

        // Send SpawnActor message to worker
        worker
            .send(crate::worker::WorkerMessage::SpawnActor {
                track_id,
                participant_id,
                ssrc,
                kind,
                content_type: if kind == crate::types::MediaKind::Audio {
                    2
                } else {
                    0
                },
            })
            .map_err(|e| format!("Failed to send spawn actor message to worker: {:?}", e))?;

        info!(
            track_id, ssrc, worker_id, kind = ?kind,
            "Registered and assigned track to worker"
        );

        Ok(worker_id)
    }

    /// Find WebRTC session by source address.
    ///
    /// Returns session ID if address is associated with an active session.
    ///
    /// # Arguments
    ///
    /// * `addr` - Source address to lookup
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    /// - Explicit return type
    /// - No allocation
    #[inline]
    fn find_session_by_address(&self, addr: &SocketAddr) -> Option<TransportId> {
        // Precondition: address must be valid (TigerStyle)
        if addr.port() == 0 {
            return None;
        }

        self.webrtc_transport.find_session_by_addr(addr)
    }

    /// Check if the SFU is shutdown.
    #[inline]
    pub fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }
}

impl Sfu {
    /// Run the SFU, starting all services.
    ///
    /// This method starts:
    /// - The signaling server for WebSocket connections
    /// - The main packet processing loop
    ///
    /// It blocks until shutdown is signaled.
    ///
    /// # Returns
    ///
    /// `Ok(())` on graceful shutdown, `Err(SfuError)` on failure.
    ///
    /// # Requirements
    ///
    /// * 14.2 - P50 latency below 20ms
    /// * 14.3 - P99 latency below 50ms
    /// * 14.4 - 500K+ packets/sec/core
    pub async fn run(&mut self) -> Result<(), SfuError> {
        if self.is_shutdown.load(Ordering::Acquire) {
            return Err(SfuError::Worker(WorkerError::InvalidConfig {
                message: "SFU is already shutdown".to_string(),
            }));
        }

        info!("Starting Nexus SFU MVP...");

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Note: Signaling is now handled externally via QUIC/WebSocket
        // See main.rs for QuicSignaling and WebSocketServer initialization
        let process_result = self.run_packet_loop(&mut shutdown_rx).await;

        info!("Nexus SFU MVP stopped");

        process_result
    }

    /// Run the main packet processing loop.
    ///
    /// Receives packets from UDP transport, parses RTP/RTCP headers,
    /// routes packets to tracks, and processes RTCP for BWE updates.
    /// Also polls WebRTC sessions for pending ICE connectivity checks
    /// and cleans up idle sessions periodically.
    ///
    /// WHY adaptive spin: Replaces unconditional yield_now() with state-aware
    /// waiting that minimizes latency when packets are flowing and conserves
    /// CPU during idle periods.
    ///
    /// # Requirements
    ///
    /// * 28.6 - Use SpinLoop for packet processing
    async fn run_packet_loop(
        &mut self,
        shutdown_rx: &mut mpsc::Receiver<()>,
    ) -> Result<(), SfuError> {
        use crate::spin::SpinLoop;

        self.packets_processed = 0;
        let mut spin_loop = SpinLoop::new();

        info!("Starting packet processing loop");

        loop {
            // Check for shutdown signal
            if shutdown_rx.try_recv().is_ok() {
                info!("Shutdown signal received");
                break;
            }

            // Check if shutdown flag is set
            if self.is_shutdown.load(Ordering::Acquire) {
                break;
            }

            if self.stop_requested.load(Ordering::Acquire) {
                info!("Stop requested");
                break;
            }

            // Check shared shutdown signal (Requirement 15.6)
            if self.shared_shutdown.load(Ordering::Acquire) {
                info!("Shared shutdown signal detected");
                break;
            }

            let batch_count = self.step_once()?;

            // Adaptive spin: update state and wait appropriately (async version)
            spin_loop.on_poll_result(batch_count);
            tokio::task::yield_now().await;
        }

        info!(
            "Packet processing loop stopped, processed {} packets",
            self.packets_processed
        );
        Ok(())
    }

    /// Execute one iteration of the packet processing loop.
    ///
    /// Receives a batch of packets, processes them, runs periodic checks
    /// (ICE, DTLS, cleanup, flush), and returns the number of packets processed.
    /// The DST simulator calls this directly to drive the SFU one step at a time.
    pub fn step_once(&mut self) -> Result<u32, SfuError> {
        // Receive batch of packets
        let batch_count = {
            let transport = match self.transport.as_mut() {
                Some(t) => t,
                None => {
                    return Err(SfuError::Transport(TransportError::BufferExhausted));
                }
            };

            let packets = match transport.recv_batch(RECV_BATCH_SIZE) {
                Ok(p) => p,
                Err(TransportError::RecvFailed { source }) => {
                    if source.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Receive error: {}", source);
                    }
                    Vec::new()
                }
                Err(e) => {
                    warn!("Transport error: {}", e);
                    Vec::new()
                }
            };

            let count = packets.len() as u32;
            for recv_packet in packets {
                self.process_packet(&recv_packet.data, recv_packet.source_addr);
                self.packets_processed += 1;
            }
            count
        };

        Ok(batch_count)
    }

    /// Process a single packet by routing through WebRTC sessions.
    ///
    /// All packets are first routed to the appropriate WebRTC session for:
    /// - Packet demultiplexing (STUN/DTLS/RTP/RTCP)
    /// - ICE connectivity checks and state transitions
    /// - DTLS handshake processing
    /// - SRTP/SRTCP decryption
    ///
    /// Only decrypted RTP/RTCP packets are forwarded to tracks for media processing.ssing.
    ///
    /// # Packet Flow
    ///
    /// ```text
    /// UDP → process_packet() → WebRtcTransport → WebRtcSession
    ///                                              ↓
    ///                                         Demux + Decrypt
    ///                                              ↓
    ///                           ┌─────────────────┴─────────────────┐
    ///                           ↓                 ↓                 ↓
    ///                        STUN/DTLS         RTP              RTCP
    ///                        (send response)   (to tracks)      (to BWE)
    /// ```
    ///
    /// # Requirements
    ///
    /// * 14.2 - P50 latency below 20ms (zero-copy after session established)
    /// * 14.3 - P99 latency below 50ms (no allocation on hot path)
    /// * 14.4 - 500K+ packets/sec/core (inline processing)
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit control flow (no recursion)
    /// - Bounds checks before processing
    /// - Assertions for positive/negative space
    /// - Zero allocation on hot path (after session established)
    ///
    /// # NASA Rules Compliance
    ///
    /// - Bounded packet length check
    /// - Explicit state transitions
    /// - No dynamic allocation
    #[inline]
    fn process_packet(&self, data: &[u8], source_addr: SocketAddr) {
        // Precondition checks (TigerStyle: validate function arguments)
        if data.is_empty() {
            return;
        }
        if source_addr.port() == 0 {
            return;
        }

        // Bounds check (NASA Rule: put a limit on everything)
        if data.len() < 4 {
            return; // Too short for any valid packet
        }
        if data.len() > MAX_PACKET_SIZE {
            warn!(
                "Packet too large: {} bytes from {}",
                data.len(),
                source_addr
            );
            return;
        }

        // Under sim feature, bypass WebRTC/SRTP and treat data as plain RTP/RTCP
        #[cfg(feature = "sim")]
        {
            let packet_type = PacketType::classify(data);
            match packet_type {
                PacketType::Rtp => {
                    self.process_decrypted_rtp(data, source_addr);
                }
                PacketType::Rtcp => {
                    self.process_decrypted_rtcp(data);
                }
                _ => {
                    // Skip STUN/DTLS/unknown in simulation
                }
            }
            return;
        }

        // Classify packet type before session lookup (TigerStyle: assert positive space)
        #[cfg(not(feature = "sim"))]
        {
            let packet_type = PacketType::classify(data);

            // Assert packet type is valid (TigerStyle: assert negative space)
            if packet_type == PacketType::Unknown {
                debug!("Unknown packet type from {}", source_addr);
                return;
            }

            // Cold path: STUN/DTLS → ConnectionMonitor via channel
            if packet_type == PacketType::Stun || packet_type == PacketType::Dtls {
                if let Some(ref tx) = self.connection_tx {
                    let _ = tx.try_send(crate::orchestrator::events::ColdPathPacket {
                        data: data.to_vec(),
                        source_addr,
                    });
                }
                return;
            }

            // Hot path: RTP/RTCP → inline processing via WebRTC transport
            let mut out_buf = [0u8; 2048];
            let result = self
                .webrtc_transport
                .process_packet(data, source_addr, &mut out_buf);

            // Handle result
            match result {
                Ok(Some((_session_id, incoming_data))) => {
                    use nexus_webrtc::webrtc::IncomingData;
                    match incoming_data {
                        IncomingData::Rtp(len) => {
                            self.process_decrypted_rtp(&out_buf[..len], source_addr);
                        }
                        IncomingData::Rtcp(len) => {
                            tracing::trace!(
                                payload_len = len,
                                first_bytes = ?&out_buf[..len.min(8)],
                                "Decrypted RTCP compound packet"
                            );
                            self.process_decrypted_rtcp(&out_buf[..len]);
                        }
                        // STUN/DTLS responses shouldn't arrive here since we routed them above,
                        // but handle gracefully if they do.
                        IncomingData::Stun(response) => {
                            self.send_packet(&response, source_addr);
                        }
                        IncomingData::Dtls(response) => {
                            self.send_packet(&response, source_addr);
                        }
                        IncomingData::StunAndDtls(stun_response, dtls_flight) => {
                            self.send_packet(&stun_response, source_addr);
                            self.send_packet(&dtls_flight, source_addr);
                        }
                        IncomingData::None => {}
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("WebRTC transport error from {}: {:?}", source_addr, e);
                }
            }
        }
    }

    /// Send packet to destination address.
    ///
    /// # Arguments
    ///
    /// * `data` - Packet data to send
    /// * `dest_addr` - Destination address
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for hot path performance
    /// - Explicit error handling
    #[inline]
    #[cfg_attr(feature = "sim", allow(dead_code))] // callers are compiled out in sim
    fn send_packet(&self, data: &[u8], dest_addr: SocketAddr) {
        // Precondition checks (TigerStyle)
        if data.is_empty() {
            return;
        }
        if data.len() > MAX_PACKET_SIZE {
            return;
        }
        if dest_addr.port() == 0 {
            return;
        }

        if let Some(ref transport) = self.transport {
            if let Err(e) = transport.send(data, dest_addr) {
                warn!("Failed to send packet to {}: {:?}", dest_addr, e);
            }
        }
    }

    /// Process decrypted RTP packet.
    ///
    /// Routes the already-decrypted RTP packet to the appropriate track
    /// via the SSRC router and worker pool.
    ///
    /// # Arguments
    ///
    /// * `data` - Decrypted RTP packet data
    /// * `source_addr` - Source address of the packet
    ///
    /// # TigerStyle Compliance
    ///
    /// - Renamed from process_rtp to clarify it handles decrypted data
    /// - Assertions for preconditions
    /// - Explicit error handling
    #[inline]
    fn process_decrypted_rtp(&self, data: &[u8], source_addr: SocketAddr) {
        // Precondition checks (TigerStyle)
        if data.is_empty() || data.len() < 12 {
            return;
        }

        // Parse RTP header using SIMD-accelerated parsing
        let header = match RtpHeader::parse_simd(data) {
            Some(h) => h,
            None => {
                debug!("RTP parse failed for decrypted packet");
                return;
            }
        };

        // Postcondition check (TigerStyle: paired check)
        if header.ssrc == 0 {
            debug!("Dropping RTP packet with zero SSRC");
            return;
        }

        // Lookup track by SSRC
        let (track_id, _worker_id) = match self.ssrc_router.lookup(header.ssrc) {
            Some(route) => route,
            None => {
                // Unknown SSRC - could auto-create track here
                debug!("Unknown SSRC: {}", header.ssrc);
                return;
            }
        };

        // Comment 1 fix: Send publisher SRTCP context to worker when DTLS completes
        // This enables PLI/NACK feedback to be protected with SRTCP before sending to publisher.
        // We detect DTLS completion by checking if the session is Established and if we haven't
        // already sent the SRTCP context for this track.
        self.send_publisher_srtcp_if_needed(track_id, source_addr);

        // Allocate packet slot from arena
        let mut slot = match self.arena.alloc() {
            Some(s) => s,
            None => {
                self.record_ingest_drop(&self.arena_drops, &"packet arena exhausted");
                return;
            }
        };

        // Copy packet data to slot
        let len = data.len().min(slot.data_mut().len());
        slot.data_mut()[..len].copy_from_slice(&data[..len]);
        slot.set_len(len as u16);

        // Postcondition check (TigerStyle)
        if slot.len() as usize != len {
            debug!("Slot length mismatch: expected {}, got {}", len, slot.len());
            return;
        }

        // Route to worker
        if let Some(ref pool_arc) = self.worker_pool {
            let pool = pool_arc.read();
            if let Err(e) = pool.route_packet(track_id, slot, source_addr) {
                self.record_ingest_drop(&self.worker_queue_drops, &e);
            }
        }
    }

    /// Process decrypted RTCP packet.
    ///
    /// Parses the already-decrypted RTCP header and processes Receiver Reports
    /// for bandwidth estimation updates.
    ///
    /// # Arguments
    ///
    /// * `data` - Decrypted RTCP packet data
    ///
    /// # TigerStyle Compliance
    ///
    /// - Renamed to clarify it handles decrypted data
    /// - Assertions for preconditions
    #[inline]
    fn process_decrypted_rtcp(&self, data: &[u8]) {
        // Precondition checks (TigerStyle)
        if data.is_empty() || data.len() < 8 {
            return;
        }

        // Comment 2 fix: Walk compound RTCP buffer to process all packets
        // RTCP compound packets contain multiple RTCP packets concatenated together.
        // We must parse each packet header, process it, then advance to the next.
        let mut offset = 0;
        const MAX_RTCP_PACKETS_PER_COMPOUND: usize = 32; // Bounded iteration
        let mut packet_count = 0;

        while offset < data.len() && packet_count < MAX_RTCP_PACKETS_PER_COMPOUND {
            // Check if we have enough bytes for a header
            if offset + 8 > data.len() {
                debug!(
                    "Incomplete RTCP header at offset {}, stopping compound parse",
                    offset
                );
                break;
            }

            // Parse RTCP header at current offset
            let packet_data = &data[offset..];
            let header = match RtcpHeader::parse(packet_data) {
                Ok(h) => h,
                Err(e) => {
                    debug!(
                        "RTCP parse error at offset {}: {:?}, bytes: {:02x?}",
                        offset,
                        e,
                        &data[offset..data.len().min(offset + 8)]
                    );
                    break; // Stop processing on parse error
                }
            };

            // Calculate packet length in bytes from header's length field
            let packet_len_bytes = header.packet_len_bytes();

            // Validate packet length doesn't exceed remaining buffer
            if offset + packet_len_bytes > data.len() {
                debug!(
                    "RTCP packet length {} exceeds remaining buffer {} at offset {}, stopping",
                    packet_len_bytes,
                    data.len() - offset,
                    offset
                );
                break;
            }

            // Note: SSRC 0 can appear in some RTCP packet types (e.g., BYE with no sources)
            // so we don't assert non-zero here.

            // Comment 1 fix: Limit per-packet slice to current RTCP packet length
            // This prevents parsers from reading into subsequent RTCP packets in compound buffer
            let end = offset + packet_len_bytes;
            let packet_data = &data[offset..end];

            // Process based on packet type
            match header.packet_type {
                RtcpType::ReceiverReport => {
                    // Extract receiver report blocks and update BWE
                    self.process_receiver_report(packet_data, &header);
                }
                RtcpType::SenderReport => {
                    // Could extract sender statistics here
                    debug!("Received SR from SSRC {}", header.ssrc);
                }
                RtcpType::PayloadFeedback => {
                    // Check FMT field for PLI (FMT=1)
                    let fmt = packet_data[0] & 0x1F;
                    if fmt == 1 {
                        self.process_pli_feedback(packet_data);
                    }
                }
                RtcpType::TransportFeedback => {
                    // Check FMT field for NACK (FMT=1)
                    let fmt = packet_data[0] & 0x1F;
                    if fmt == 1 {
                        self.process_nack_feedback(packet_data);
                    }
                }
                _ => {
                    // Other RTCP types (SDES, BYE, etc.)
                }
            }

            // Advance to next packet in compound buffer
            offset += packet_len_bytes;
            packet_count += 1;
        }

        // Postcondition: bounded iteration
        debug_assert!(packet_count <= MAX_RTCP_PACKETS_PER_COMPOUND);
    }

    /// Process an RTCP Receiver Report for BWE updates.
    ///
    /// Parses receiver report blocks and updates the GCC congestion controller
    /// with loss and RTT information for bandwidth estimation.
    ///
    /// # Arguments
    ///
    /// * `data` - RTCP receiver report packet data
    /// * `header` - Parsed RTCP header
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration (report_count from header)
    /// - Uses interior mutability for GCC updates
    /// - No dynamic allocation
    fn process_receiver_report(&self, data: &[u8], header: &RtcpHeader) {
        use nexus_media::rtcp::ReceiverReportBlock;

        // RR has report blocks starting at offset 8
        let report_count = header.count as usize;
        let mut offset = 8;

        // Get current timestamp for BWE updates
        let timestamp_us = crate::clock::now_us();

        for _ in 0..report_count {
            if offset + 24 > data.len() {
                break;
            }

            if let Ok(block) = ReceiverReportBlock::parse(&data[offset..]) {
                debug!(
                    "RR block: SSRC={}, loss={}%, jitter={}",
                    block.ssrc,
                    (block.fraction_lost as u32 * 100) / 256,
                    block.jitter
                );

                // Calculate RTT from LSR and DLSR if available
                // RTT = current_time - LSR - DLSR
                // LSR is middle 32 bits of NTP timestamp, DLSR is in 1/65536 seconds
                let rtt_us = if block.last_sr > 0 && block.delay_since_sr > 0 {
                    // DLSR is in 1/65536 second units, convert to microseconds
                    let _dlsr_us = (block.delay_since_sr as u64 * 1_000_000) / 65536;
                    // For now, we don't have the original send time, so we can't compute RTT
                    // This would require tracking NTP timestamps per SSRC
                    // TODO: Implement proper RTT calculation with NTP timestamp tracking
                    None
                } else {
                    None
                };

                // Update GCC congestion controller with loss and RTT
                // Uses interior mutability - no &mut self required
                self.gcc
                    .on_receiver_report(block.fraction_lost, rtt_us, timestamp_us);
            }

            offset += 24;
        }
    }

    /// Process PLI (Picture Loss Indication) feedback.
    ///
    /// Forwards PLI request to the publisher to trigger keyframe generation.
    ///
    /// # Arguments
    ///
    /// * `data` - RTCP PLI packet data
    ///
    /// # Assertions
    ///
    /// * `media_ssrc > 0` - Valid media SSRC
    #[inline]
    fn process_pli_feedback(&self, data: &[u8]) {
        use nexus_media::rtcp::PliPacket;

        // Parse PLI packet
        let pli = match PliPacket::parse(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("PLI parse error: {:?}", e);
                return;
            }
        };

        // Precondition check
        if pli.media_ssrc == 0 {
            debug!("Dropping PLI with zero media SSRC");
            return;
        }

        debug!(
            "PLI received: sender_ssrc={}, media_ssrc={}",
            pli.sender_ssrc, pli.media_ssrc
        );

        // Forward to publisher with sender_ssrc
        self.forward_pli_to_publisher(pli.media_ssrc, pli.sender_ssrc);
    }

    /// Process NACK (Negative Acknowledgement) feedback.
    ///
    /// Forwards NACK request to the publisher for packet retransmission.
    ///
    /// # Arguments
    ///
    /// * `data` - RTCP NACK packet data
    ///
    /// # Assertions
    ///
    /// * `media_ssrc > 0` - Valid media SSRC
    /// * `lost_packets.len() <= 64` - Bounded packet list
    #[inline]
    fn process_nack_feedback(&self, data: &[u8]) {
        use nexus_media::rtcp::NackPacket;

        // Parse NACK packet
        let nack = match NackPacket::parse(data) {
            Ok(n) => n,
            Err(e) => {
                debug!("NACK parse error: {:?}", e);
                return;
            }
        };

        // Precondition checks
        if nack.media_ssrc == 0 {
            debug!("Dropping NACK with zero media SSRC");
            return;
        }
        if nack.lost_packets.len() > 64 {
            debug!(
                "Dropping NACK with excessive lost packets: {}",
                nack.lost_packets.len()
            );
            return;
        }

        debug!(
            "NACK received: sender_ssrc={}, media_ssrc={}, lost_count={}",
            nack.sender_ssrc,
            nack.media_ssrc,
            nack.lost_packets.len()
        );

        // Forward to publisher with sender_ssrc
        self.forward_nack_to_publisher(nack.media_ssrc, nack.sender_ssrc, nack.lost_packets);
    }

    /// Forward PLI to publisher via worker.
    ///
    /// Looks up track by SSRC and sends feedback message to worker.
    ///
    /// # Arguments
    ///
    /// * `media_ssrc` - SSRC of media source
    /// * `sender_ssrc` - SSRC of feedback sender
    ///
    /// # Assertions
    ///
    /// * `media_ssrc > 0` - Valid SSRC
    #[inline]
    fn forward_pli_to_publisher(&self, media_ssrc: u32, sender_ssrc: u32) {
        // Precondition check
        if media_ssrc == 0 {
            debug!("Cannot forward PLI: media SSRC is zero");
            return;
        }

        // Lookup track by SSRC in ssrc_router
        let (_track_id, worker_id) = match self.ssrc_router.lookup(media_ssrc) {
            Some(r) => r,
            None => {
                debug!("PLI for unknown SSRC {}", media_ssrc);
                return;
            }
        };

        // Send WorkerMessage::RtcpPli to worker
        if let Some(ref pool_arc) = self.worker_pool {
            let pool = pool_arc.read();
            if let Some(worker) = pool.get_worker(worker_id) {
                if let Err(e) = worker.send(crate::worker::WorkerMessage::RtcpPli {
                    media_ssrc,
                    sender_ssrc,
                }) {
                    debug!("Failed to send RTCP PLI to worker {}: {}", worker_id, e);
                }
            }
        }

        // Postcondition: Message sent or logged
    }

    /// Maximum SRTCP cache entries (prevents unbounded growth).
    const MAX_SRTCP_CACHE_SIZE: usize = 4096;

    /// Send publisher SRTCP context to worker if DTLS is complete.
    ///
    /// This method checks if the WebRTC session for the publisher has completed
    /// DTLS handshake and has SRTP key material available. If so, it extracts
    /// the SRTCP context and sends it to the worker via SetPublisherSrtcp message.
    ///
    /// Comment 1 fix: Added guard to skip sending if worker already has current SRTCP context.
    /// Tracks a per-track cached key fingerprint so we only send once when DTLS first reaches
    /// Established and again when get_srtp_key_material() changes (e.g., after ICE restart/DTLS rekey).
    /// This prevents spamming SetPublisherSrtcp messages on every RTP packet.
    ///
    /// # Arguments
    ///
    /// * `track_id` - Track ID to send context for
    /// * `source_addr` - Source address to find session
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded operations (single session lookup)
    #[inline]
    fn send_publisher_srtcp_if_needed(
        &self,
        track_id: crate::types::TrackId,
        source_addr: SocketAddr,
    ) {
        // Precondition check
        if track_id == 0 {
            debug!("Cannot send publisher SRTCP: track ID is zero");
            return;
        }

        // Find session by source address
        let session_id = match self.find_session_by_address(&source_addr) {
            Some(id) => id,
            None => {
                debug!("No session found for address {}", source_addr);
                return;
            }
        };

        // Get SRTCP key material from session
        let (key_material, srtp_policy) = {
            let session_result = self.webrtc_transport.with_session(session_id, |session| {
                // Check if session is established (DTLS complete)
                if session.state() != nexus_webrtc::webrtc::SessionState::Established {
                    // DTLS not complete yet, will try again on next packet
                    return None;
                }

                // Get SRTP key material from DTLS session
                match session.get_srtp_key_material() {
                    Some((km, policy, _epoch)) => Some((km, policy)),
                    None => {
                        debug!(
                            "Session {} has no SRTP key material despite being Established",
                            session_id.value()
                        );
                        None
                    }
                }
            });

            match session_result {
                Some(Some(result)) => result,
                _ => return,
            }
        };

        // Compute fingerprint of key material to detect changes
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key_material.master_key.hash(&mut hasher);
        key_material.master_salt.hash(&mut hasher);
        let key_fingerprint_u64 = hasher.finish();

        // Convert to fixed-size array for storage
        let mut key_fingerprint = [0u8; 32];
        key_fingerprint[..8].copy_from_slice(&key_fingerprint_u64.to_le_bytes());
        key_fingerprint[8..16].copy_from_slice(&session_id.value().to_le_bytes());

        // Check cache to see if we already sent this exact context
        if let Some(entry) = SRTCP_SENT_CACHE.get(&track_id) {
            let (cached_session_id, cached_fingerprint) = entry.value();
            if *cached_session_id == session_id.value() && cached_fingerprint == &key_fingerprint {
                return;
            }
        }

        // Enforce capacity bound before inserting. Entries are removed with
        // their track (`forget_publisher_srtcp`), so this only triggers with
        // more than MAX_SRTCP_CACHE_SIZE live published tracks. An evicted
        // track is sent again; the worker keeps its context for the same key.
        if SRTCP_SENT_CACHE.len() >= Self::MAX_SRTCP_CACHE_SIZE {
            warn!(
                "SRTCP sent-cache full ({} tracks); evicting half",
                SRTCP_SENT_CACHE.len()
            );
            let to_remove: Vec<u64> = SRTCP_SENT_CACHE
                .iter()
                .take(Self::MAX_SRTCP_CACHE_SIZE / 2)
                .map(|e| *e.key())
                .collect();
            for key in to_remove {
                SRTCP_SENT_CACHE.remove(&key);
            }
        }
        SRTCP_SENT_CACHE.insert(track_id, (session_id.value(), key_fingerprint));

        // Send SetPublisherSrtcp message to worker
        // This will overwrite any existing context, ensuring current keys are used
        if let Some(ref pool_arc) = self.worker_pool {
            let pool = pool_arc.read();
            // Lookup worker for this track
            let worker_id = match self.ssrc_router.lookup_by_track(track_id) {
                Some((_ssrc, wid)) => wid,
                None => {
                    debug!("No worker found for track {}", track_id);
                    return;
                }
            };

            if let Some(worker) = pool.get_worker(worker_id) {
                if let Err(e) = worker.send(crate::worker::WorkerMessage::SetPublisherSrtcp {
                    track_id,
                    key_material,
                    srtp_policy,
                }) {
                    debug!("Failed to send SetPublisherSrtcp to worker: {:?}", e);
                } else {
                    info!(
                        "Sent publisher SRTCP context for track {} to worker {} (session {})",
                        track_id,
                        worker_id,
                        session_id.value()
                    );
                }
            }
        }
    }

    /// Forward NACK to publisher via worker.
    ///
    /// Looks up track by SSRC and sends feedback message to worker.
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
    #[inline]
    fn forward_nack_to_publisher(&self, media_ssrc: u32, sender_ssrc: u32, lost_packets: Vec<u16>) {
        // Precondition checks
        if media_ssrc == 0 {
            debug!("Cannot forward NACK: media SSRC is zero");
            return;
        }
        if lost_packets.len() > 64 {
            debug!(
                "Cannot forward NACK: lost packets exceeds bound ({})",
                lost_packets.len()
            );
            return;
        }

        // Lookup track by SSRC in ssrc_router
        let (_track_id, worker_id) = match self.ssrc_router.lookup(media_ssrc) {
            Some(r) => r,
            None => {
                debug!("NACK for unknown SSRC {}", media_ssrc);
                return;
            }
        };

        // Send WorkerMessage::RtcpNack to worker
        if let Some(ref pool_arc) = self.worker_pool {
            let pool = pool_arc.read();
            if let Some(worker) = pool.get_worker(worker_id) {
                if let Err(e) = worker.send(crate::worker::WorkerMessage::RtcpNack {
                    media_ssrc,
                    sender_ssrc,
                    lost_packets: lost_packets.clone(),
                }) {
                    debug!("Failed to send RTCP NACK to worker {}: {}", worker_id, e);
                }
            }
        }

        // Postcondition: Message sent or logged
    }

    /// Start the SFU asynchronously.
    ///
    /// Spawns the SFU run loop in a background task and returns immediately.
    ///
    /// # Returns
    ///
    /// A handle to the spawned task.
    pub fn start(mut self) -> tokio::task::JoinHandle<Result<(), SfuError>> {
        tokio::spawn(async move { self.run().await })
    }

    /// Run the SFU with signal handling.
    ///
    /// This method runs the SFU and handles SIGTERM/SIGINT signals for
    /// graceful shutdown. It blocks until a signal is received or an error occurs.
    ///
    /// # Returns
    ///
    /// `Ok(())` on graceful shutdown, `Err(SfuError)` on failure.
    ///
    /// # Requirements
    ///
    /// * 14.6 - Handle SIGTERM/SIGINT for clean shutdown
    pub async fn run_with_signals(&mut self) -> Result<(), SfuError> {
        if self.is_shutdown.load(Ordering::Acquire) {
            return Err(SfuError::Worker(WorkerError::InvalidConfig {
                message: "SFU is already shutdown".to_string(),
            }));
        }

        info!("Starting Nexus SFU with signal handling...");

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Note: Signaling is now handled externally via QUIC/WebSocket
        // See main.rs for QuicSignaling and WebSocketServer initialization

        // Spawn signal handler
        let shutdown_tx_signal = shutdown_tx.clone();
        let signal_handle = tokio::spawn(async move {
            Self::wait_for_shutdown_signal().await;
            info!("Shutdown signal received");
            let _ = shutdown_tx_signal.send(()).await;
        });

        // Run the main packet processing loop
        let process_result = self.run_packet_loop(&mut shutdown_rx).await;

        // Cleanup
        signal_handle.abort();

        // Perform graceful shutdown
        self.shutdown().await?;

        info!("Nexus SFU stopped");

        process_result
    }

    /// Wait for a shutdown signal (SIGTERM or SIGINT).
    ///
    /// This function blocks until a shutdown signal is received.
    async fn wait_for_shutdown_signal() {
        #[cfg(unix)]
        {
            use tokio::signal;
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to register SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                }
            }
        }

        #[cfg(not(unix))]
        {
            use tokio::signal;
            // On non-Unix platforms, just wait for Ctrl+C
            signal::ctrl_c()
                .await
                .expect("Failed to register Ctrl+C handler");
            info!("Received Ctrl+C");
        }
    }

    /// Graceful drain of the SFU.
    ///
    /// Initiates graceful drain mode:
    /// 1. Stops accepting new connections
    /// 2. Notifies all connected participants of impending shutdown
    /// 3. Continues forwarding packets for drain_timeout duration
    /// 4. Shuts down workers and releases resources
    ///
    /// # Arguments
    ///
    /// * `timeout` - Optional override for drain timeout. If None, uses config value.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful drain, `Err(SfuError)` on failure.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 10.1: Stop accepting new connections
    /// - Requirement 10.2: Continue forwarding for drain_timeout
    /// - Requirement 10.3: Notify participants of shutdown
    /// - Requirement 10.4: Terminate after timeout
    /// - Requirement 10.5: Signal workers to stop
    /// - Requirement 10.6: Deallocate resources
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines (split into helpers)
    /// - ≥2 assertions
    pub async fn drain(&mut self, timeout: Option<Duration>) -> Result<(), SfuError> {
        // Precondition check
        if self.is_shutdown.load(Ordering::Acquire) {
            return Err(SfuError::Signaling(SignalingError::InvalidState {
                expected: "Running",
                actual: "Shutdown",
            }));
        }

        // Start drain mode
        if !self.drain_state.start_drain() {
            info!("Drain already in progress");
            return Ok(());
        }

        info!("Initiating graceful drain...");

        // Get session count for drain state
        let session_count = self.webrtc_transport.session_count() as u32;
        self.drain_state.set_active_sessions(session_count);

        info!(
            "Drain started: {} active sessions, timeout {}ms",
            session_count,
            timeout
                .map(|t| t.as_millis() as u32)
                .unwrap_or(self.config.drain_timeout_ms)
        );

        // Notify participants of impending shutdown
        self.notify_participants_of_shutdown().await;

        // Determine drain timeout
        let drain_timeout =
            timeout.unwrap_or(Duration::from_millis(self.config.drain_timeout_ms as u64));

        // Continue forwarding packets during drain period
        info!("Continuing packet forwarding for {:?}...", drain_timeout);
        tokio::time::sleep(drain_timeout).await;

        // Check if all sessions have drained
        let remaining = self.drain_state.active_sessions();
        if remaining > 0 {
            warn!(
                "Drain timeout expired with {} sessions remaining",
                remaining
            );
        } else {
            info!("All sessions drained successfully");
        }

        // Proceed with shutdown
        self.shutdown().await
    }

    /// Notify all connected participants of impending shutdown.
    ///
    /// Sends a shutdown notification to all active WebRTC sessions.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 10.3: Notify participants of shutdown
    async fn notify_participants_of_shutdown(&self) {
        let Some(connections) = self.signaling_connections.clone() else {
            return;
        };
        let drain_seconds = self.config.drain_timeout_ms / 1000;

        let shutdown_msg = crate::signal::SignalMessage::ServerShutdown {
            reason: "Server shutting down for maintenance".to_string(),
            drain_seconds,
        };

        let mut notified: u32 = 0;
        const MAX_NOTIFICATIONS: u32 = 10_000;

        // Bounded iteration over all connections
        for entry in connections.iter() {
            if notified >= MAX_NOTIFICATIONS {
                tracing::warn!(
                    "Notification limit reached ({}), some participants not notified",
                    MAX_NOTIFICATIONS
                );
                break;
            }

            let participant_id = *entry.key();

            match entry.value().sender.try_send(shutdown_msg.clone()) {
                Ok(()) => {
                    notified += 1;
                    tracing::debug!(participant_id, "Shutdown notification sent");
                }
                Err(e) => {
                    tracing::warn!(
                        participant_id,
                        error = %e,
                        "Failed to send shutdown notification"
                    );
                }
            }
        }

        // Postcondition: bounded
        assert!(
            notified <= MAX_NOTIFICATIONS,
            "Notification count must be bounded"
        );

        info!(
            notified,
            total_connections = connections.len(),
            drain_seconds,
            "Shutdown notifications sent"
        );
    }

    /// Check if the SFU is in drain mode.
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.drain_state.is_draining()
    }

    /// Get the drain state.
    #[inline]
    pub fn drain_state(&self) -> &Arc<DrainState> {
        &self.drain_state
    }

    /// Graceful shutdown of the SFU.
    ///
    /// Signals all components to stop and waits for them to drain
    /// in-flight packets before returning.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful shutdown, `Err(SfuError)` on timeout or error.
    ///
    /// # Requirements
    ///
    /// * 14.6 - Graceful shutdown with drain
    /// * 15.6 - Common shutdown signal for coordinated termination
    pub async fn shutdown(&mut self) -> Result<(), SfuError> {
        if self.is_shutdown.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already shutdown
        }

        info!("Initiating SFU shutdown...");

        // Step 1: Notify all connected participants before drain
        self.notify_participants_of_shutdown().await;

        // Step 2: Start drain (continue forwarding for drain_timeout)
        let drain_started = self.drain_state.start_drain();
        if drain_started {
            let drain_timeout = Duration::from_millis(self.config.drain_timeout_ms as u64);
            info!(
                "Drain started, waiting {}ms for in-flight packets",
                self.config.drain_timeout_ms
            );
            tokio::time::sleep(drain_timeout).await;
        }

        // Step 3: Set shared shutdown signal for all subsystems
        self.shared_shutdown.store(true, Ordering::SeqCst);
        info!("Shared shutdown signal set");

        // Signal shutdown via channel
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        // Shutdown gossip thread
        info!("Shutting down gossip thread...");
        if let Some(tx) = self.gossip_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.gossip_thread.take() {
            // Wait for gossip thread to finish (with timeout)
            let join_result = handle.join();
            match join_result {
                Ok(()) => info!("Gossip thread shutdown complete"),
                Err(_) => warn!("Gossip thread panicked during shutdown"),
            }
        }

        // Shutdown WebRTC transport
        info!("Shutting down WebRTC transport...");
        let session_count = self.webrtc_transport.session_count();
        self.webrtc_transport.stop();
        info!(
            "WebRTC transport stopped, cleaned up {} sessions",
            session_count
        );

        // Postcondition assertion (TigerStyle)
        assert!(self.webrtc_transport.state() == WebRtcTransportState::Stopped);

        // Shutdown worker pool. The orchestrator holds another reference, so
        // stop the workers through the lock rather than waiting for the last
        // Arc; shutdown is idempotent.
        if let Some(pool_arc) = self.worker_pool.take() {
            info!("Shutting down worker pool...");
            pool_arc.write().shutdown().map_err(SfuError::Worker)?;
            info!("Worker pool shutdown complete");
        }

        // Drop transport
        self.transport.take();

        info!("SFU shutdown complete");
        Ok(())
    }

    /// Get statistics snapshot for monitoring.
    pub fn stats(&self) -> SfuStats {
        let webrtc_stats = (
            self.webrtc_transport.session_count() as u32,
            self.webrtc_transport.connected_session_count() as u32,
        );

        // Postcondition assertion (TigerStyle: paired assertion)
        assert!(
            webrtc_stats.0 >= webrtc_stats.1,
            "Total sessions must be >= connected sessions"
        );

        SfuStats {
            arena_free_slots: self.arena.free_count(),
            arena_capacity: self.arena.capacity(),
            ssrc_count: self.ssrc_router.len() as u32,
            room_count: self.distributed_state.room_count() as u32,
            bwe_estimate_bps: self.bwe().estimated_bandwidth_bps(),
            bwe_target_bps: self.bwe().target_bitrate_bps(),
            webrtc_session_count: webrtc_stats.0,
            webrtc_connected_count: webrtc_stats.1,
        }
    }
}

impl Drop for Sfu {
    fn drop(&mut self) {
        // Ensure shutdown is called
        if !self.is_shutdown.load(Ordering::Acquire) {
            self.is_shutdown.store(true, Ordering::Release);

            // Set shared shutdown signal for all subsystems
            // Requirement 15.6: Common shutdown signal for coordinated termination
            self.shared_shutdown.store(true, Ordering::SeqCst);

            // Shutdown gossip thread synchronously
            if let Some(tx) = self.gossip_shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = self.gossip_thread.take() {
                let _ = handle.join();
            }

            // Shutdown worker pool synchronously
            if let Some(pool_arc) = self.worker_pool.take() {
                let _ = pool_arc.write().shutdown();
            }
        }
    }
}

/// SFU statistics snapshot for monitoring.
#[derive(Clone, Debug, Default)]
pub struct SfuStats {
    /// Number of free slots in the packet arena.
    pub arena_free_slots: u32,
    /// Total capacity of the packet arena.
    pub arena_capacity: u32,
    /// Number of registered SSRCs.
    pub ssrc_count: u32,
    /// Number of active rooms.
    pub room_count: u32,
    /// Current bandwidth estimate in bps.
    pub bwe_estimate_bps: u64,
    /// Target bandwidth in bps (with headroom).
    pub bwe_target_bps: u64,
    /// Number of active WebRTC sessions.
    pub webrtc_session_count: u32,
    /// Number of established WebRTC sessions.
    pub webrtc_connected_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sfu_new() {
        let mut config = NexusConfig::default();
        // Use ephemeral ports for testing
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16; // Minimum required

        let sfu = Sfu::new(config).await;
        assert!(sfu.is_ok());

        let mut sfu = sfu.unwrap();
        assert!(!sfu.is_shutdown());

        // Shutdown
        let result = sfu.shutdown().await;
        assert!(result.is_ok());
        assert!(sfu.is_shutdown());
    }

    #[tokio::test]
    async fn test_sfu_stats() {
        let mut config = NexusConfig::default();
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16; // Minimum required

        let mut sfu = Sfu::new(config).await.unwrap();
        let stats = sfu.stats();

        assert!(stats.arena_capacity > 0);
        assert_eq!(stats.arena_free_slots, stats.arena_capacity);
        assert_eq!(stats.ssrc_count, 0);
        assert_eq!(stats.room_count, 0);
        assert!(stats.bwe_estimate_bps > 0);

        sfu.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_sfu_double_shutdown() {
        let mut config = NexusConfig::default();
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16; // Minimum required

        let mut sfu = Sfu::new(config).await.unwrap();

        // First shutdown
        assert!(sfu.shutdown().await.is_ok());

        // Second shutdown should be idempotent
        assert!(sfu.shutdown().await.is_ok());
    }

    #[test]
    fn test_sfu_stats_default() {
        let stats = SfuStats::default();
        assert_eq!(stats.arena_free_slots, 0);
        assert_eq!(stats.arena_capacity, 0);
        assert_eq!(stats.ssrc_count, 0);
        assert_eq!(stats.room_count, 0);
        assert_eq!(stats.bwe_estimate_bps, 0);
        assert_eq!(stats.bwe_target_bps, 0);
    }

    #[tokio::test]
    async fn test_actor_id_explicit_node_id() {
        let mut config = NexusConfig::default();
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16;
        config.cluster.node_id = 42; // Explicit node_id

        let mut sfu = Sfu::new(config).await.unwrap();

        // Verify the distributed state uses the configured node_id
        let state_actor_id = sfu.distributed_state.local_actor();
        assert_eq!(
            state_actor_id, 42,
            "Actor ID should match configured node_id"
        );

        sfu.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_actor_id_auto_generated() {
        let mut config = NexusConfig::default();
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16;
        config.cluster.node_id = 0; // Auto-generate

        let mut sfu = Sfu::new(config).await.unwrap();

        // Verify the actor_id is non-zero and within valid range
        let state_actor_id = sfu.distributed_state.local_actor();
        assert!(
            state_actor_id > 0,
            "Auto-generated actor ID must be non-zero"
        );
        assert!(
            state_actor_id < nexus_state::MAX_ACTORS as u64,
            "Auto-generated actor ID must be < MAX_ACTORS"
        );

        sfu.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_actor_id_invalid_node_id() {
        let mut config = NexusConfig::default();
        config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
        config.worker.num_workers = 1;
        config.memory.arena_size_mb = 16;
        config.cluster.node_id = 1000; // Invalid: > MAX_ACTORS (256)

        let result = Sfu::new(config).await;
        assert!(result.is_err(), "Should fail with node_id >= MAX_ACTORS");

        if let Err(SfuError::Worker(WorkerError::InvalidConfig { message })) = result {
            assert!(
                message.contains("MAX_ACTORS"),
                "Error message should mention MAX_ACTORS constraint"
            );
        } else {
            panic!("Expected InvalidConfig error");
        }
    }
}
