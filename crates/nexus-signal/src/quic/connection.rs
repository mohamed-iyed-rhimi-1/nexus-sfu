use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

/// QUIC connection state.
///
/// # TigerStyle Compliance
/// - Explicitly-sized types
/// - Bounded stream counts
/// - State machine with assertions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Handshake in progress.
    Handshaking,
    /// 0-RTT data accepted (early data).
    ZeroRtt,
    /// Fully established (1-RTT).
    Established,
    /// Connection migrating to new path.
    Migrating,
    /// Connection closing.
    Closing,
    /// Connection closed.
    Closed,
}

/// Per-connection state tracking.
pub struct QuicConnection {
    /// Unique connection ID.
    pub connection_id: u64,
    /// Quinn connection handle.
    pub connection: quinn::Connection,
    /// Current state.
    pub state: ConnectionState,
    /// Associated participant ID (after join).
    pub participant_id: Option<u32>,
    /// Associated room ID (after join).
    pub room_id: Option<u32>,
    /// Connection established timestamp.
    pub established_at: Instant,
    /// Last activity timestamp (nanoseconds).
    pub last_activity_ns: AtomicU64,
    /// Number of bidirectional streams opened.
    pub bi_stream_count: AtomicU32,
    /// Number of unidirectional streams opened.
    pub uni_stream_count: AtomicU32,
    /// Whether 0-RTT was used.
    pub used_0rtt: bool,
    /// Migration count.
    pub migration_count: AtomicU32,
}

impl QuicConnection {
    /// Create new connection state.
    pub fn new(connection_id: u64, connection: quinn::Connection, used_0rtt: bool) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            connection_id,
            connection,
            state: if used_0rtt {
                ConnectionState::ZeroRtt
            } else {
                ConnectionState::Handshaking
            },
            participant_id: None,
            room_id: None,
            established_at: Instant::now(),
            last_activity_ns: AtomicU64::new(now_ns),
            bi_stream_count: AtomicU32::new(0),
            uni_stream_count: AtomicU32::new(0),
            used_0rtt,
            migration_count: AtomicU32::new(0),
        }
    }

    /// Transition to established state.
    pub fn mark_established(&mut self) {
        assert!(
            self.state == ConnectionState::Handshaking || self.state == ConnectionState::ZeroRtt
        );
        self.state = ConnectionState::Established;
    }

    /// Record stream creation.
    pub fn record_bi_stream(&self) {
        let count = self.bi_stream_count.fetch_add(1, Ordering::Relaxed);
        // Invariant: stream count should not overflow
        assert!(count < u32::MAX, "Bidirectional stream count overflow");
        self.touch_activity();
    }

    pub fn record_uni_stream(&self) {
        let count = self.uni_stream_count.fetch_add(1, Ordering::Relaxed);
        // Invariant: stream count should not overflow
        assert!(count < u32::MAX, "Unidirectional stream count overflow");
        self.touch_activity();
    }

    /// Record connection migration.
    pub fn record_migration(&self) {
        let count = self.migration_count.fetch_add(1, Ordering::Relaxed);
        // Invariant: migration count should be bounded
        assert!(count < 10, "Migration count exceeds maximum");
        self.touch_activity();
    }

    /// Update last activity timestamp.
    pub fn touch_activity(&self) {
        let now_ns = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.last_activity_ns.store(now_ns, Ordering::Relaxed);
    }

    /// Check if connection is idle.
    pub fn is_idle(&self, timeout_ms: u64) -> bool {
        let last_activity = self.last_activity_ns.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let elapsed_ms = (now.saturating_sub(last_activity)) / 1_000_000;
        elapsed_ms > timeout_ms
    }

    /// Get connection duration in milliseconds.
    pub fn connection_duration_ms(&self) -> u64 {
        self.established_at.elapsed().as_millis() as u64
    }
}
