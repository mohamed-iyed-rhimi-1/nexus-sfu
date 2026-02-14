//! Configuration primitives and validation traits for Nexus SFU.
//!
//! Base config structs live here so all crates share a single
//! source of truth for configuration shape and defaults.
//! The full `NexusConfig` aggregator remains in the root crate
//! because it depends on crate-specific configs (e.g. GossipConfig).
//!
//! # Validation
//!
//! Every config struct implements the `Validate` trait, which
//! returns a list of all validation errors rather than failing
//! on the first one. This lets operators fix all issues at once.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;

// -----------------------------------------------------------------------
// Validation trait
// -----------------------------------------------------------------------

/// Trait for validating configuration structs.
///
/// Returns `Ok(())` when valid, or `Err(Vec<String>)` with all
/// validation errors collected. Collecting all errors (instead
/// of failing on the first) lets operators fix everything in
/// one pass.
pub trait Validate {
    /// Validate this configuration.
    ///
    /// # Returns
    /// - `Ok(())` if all fields are valid
    /// - `Err(Vec<String>)` with one message per invalid field
    fn validate(&self) -> Result<(), Vec<String>>;
}

// -----------------------------------------------------------------------
// ConfigError — shared config error type
// -----------------------------------------------------------------------

/// Configuration validation error.
///
/// Carries the field name and a human-readable message
/// describing what is wrong. Used by all config modules.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub field: String,
    pub message: String,
}

impl ConfigError {
    /// Create an error for an invalid field value.
    ///
    /// # Arguments
    /// * `field` — dotted path to the field (e.g. "transport.batch_size")
    /// * `message` — what is wrong (e.g. "must be > 0")
    pub fn invalid(field: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    /// Create an error for a config loading failure.
    pub fn load_error(message: &str) -> Self {
        Self {
            field: "config".to_string(),
            message: message.to_string(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Configuration error in '{}': {}",
            self.field, self.message
        )
    }
}

impl std::error::Error for ConfigError {}

// -----------------------------------------------------------------------
// TransportConfig
// -----------------------------------------------------------------------

/// Transport configuration for network I/O and packet processing.
///
/// Controls UDP socket buffer sizes, batch sending parameters,
/// and bind addresses for media and signaling traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Address for media (RTP/RTCP) UDP traffic
    pub media_bind_addr: SocketAddr,
    /// Address for WebSocket signaling traffic
    pub signaling_bind_addr: SocketAddr,
    /// UDP receive buffer size in bytes (kernel SO_RCVBUF)
    pub recv_buffer_size_bytes: u32,
    /// UDP send buffer size in bytes (kernel SO_SNDBUF)
    pub send_buffer_size_bytes: u32,
    /// Max packets per sendmmsg batch (must be power of 2)
    pub batch_size: u32,
    /// Flush interval for batch sender in microseconds
    pub batch_flush_interval_us: u32,
    /// Maximum concurrent WebRTC sessions
    pub max_webrtc_sessions: u32,
    /// TLS certificate path for WSS (PEM format). Empty = plain WS.
    #[serde(default)]
    pub tls_cert_path: String,
    /// TLS private key path for WSS (PEM format). Empty = plain WS.
    #[serde(default)]
    pub tls_key_path: String,
    /// STUN server addresses for server-reflexive candidate gathering.
    #[serde(default)]
    pub stun_servers: Vec<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            media_bind_addr: "127.0.0.1:10000"
                .parse()
                .expect("default media addr is valid"),
            signaling_bind_addr: "127.0.0.1:8080"
                .parse()
                .expect("default signaling addr is valid"),
            recv_buffer_size_bytes: 8_388_608, // 8 MB
            send_buffer_size_bytes: 8_388_608, // 8 MB
            batch_size: 32,
            batch_flush_interval_us: 1000, // 1 ms
            max_webrtc_sessions: 10_000,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            stun_servers: Vec::new(),
        }
    }
}

impl Validate for TransportConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Positive-space assertions
        if self.recv_buffer_size_bytes == 0 {
            errors.push(
                "transport.recv_buffer_size_bytes must be > 0"
                    .to_string(),
            );
        }
        if self.send_buffer_size_bytes == 0 {
            errors.push(
                "transport.send_buffer_size_bytes must be > 0"
                    .to_string(),
            );
        }
        if self.batch_size == 0 {
            errors.push(
                "transport.batch_size must be > 0".to_string(),
            );
        }
        if self.batch_flush_interval_us == 0 {
            errors.push(
                "transport.batch_flush_interval_us must be > 0"
                    .to_string(),
            );
        }

        // Negative-space assertions (upper bounds)
        const MAX_BUFFER_BYTES: u32 = 1_073_741_824; // 1 GB
        if self.recv_buffer_size_bytes > MAX_BUFFER_BYTES {
            errors.push(
                "transport.recv_buffer_size_bytes must be <= 1 GB"
                    .to_string(),
            );
        }
        if self.send_buffer_size_bytes > MAX_BUFFER_BYTES {
            errors.push(
                "transport.send_buffer_size_bytes must be <= 1 GB"
                    .to_string(),
            );
        }

        // Batch size must be power of 2 for efficient modulo
        if self.batch_size > 0
            && !self.batch_size.is_power_of_two()
        {
            errors.push(
                "transport.batch_size must be power of 2"
                    .to_string(),
            );
        }
        if self.batch_size > 64 {
            errors.push(
                "transport.batch_size must be <= 64".to_string(),
            );
        }

        // WebRTC session bounds
        if self.max_webrtc_sessions == 0 {
            errors.push(
                "transport.max_webrtc_sessions must be > 0"
                    .to_string(),
            );
        }
        if self.max_webrtc_sessions > 100_000 {
            errors.push(
                "transport.max_webrtc_sessions must be <= 100000"
                    .to_string(),
            );
        }

        // TLS paths: both or neither must be set
        let has_cert = !self.tls_cert_path.is_empty();
        let has_key = !self.tls_key_path.is_empty();
        if has_cert != has_key {
            errors.push(
                "transport.tls_cert_path and tls_key_path \
                 must both be set or both be empty"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl TransportConfig {
    /// Set the media bind address.
    pub fn with_media_addr(mut self, addr: SocketAddr) -> Self {
        self.media_bind_addr = addr;
        self
    }

    /// Set the signaling bind address.
    pub fn with_signaling_addr(
        mut self,
        addr: SocketAddr,
    ) -> Self {
        self.signaling_bind_addr = addr;
        self
    }

    /// Set both send and receive buffer sizes.
    pub fn with_buffer_sizes(mut self, size_bytes: u32) -> Self {
        self.recv_buffer_size_bytes = size_bytes;
        self.send_buffer_size_bytes = size_bytes;
        self
    }
}

// -----------------------------------------------------------------------
// MemoryConfig
// -----------------------------------------------------------------------

/// Memory configuration for pre-allocated pools.
///
/// Controls the packet arena size and per-track ring buffer
/// capacity. Both are allocated at startup and never grow.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Packet arena size in megabytes (pre-allocated at startup)
    pub arena_size_mb: u32,
    /// Ring buffer capacity per track (must be power of 2)
    pub ring_buffer_size: u32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            arena_size_mb: 64,
            ring_buffer_size: 1024,
        }
    }
}

impl Validate for MemoryConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.arena_size_mb == 0 {
            errors.push(
                "memory.arena_size_mb must be > 0".to_string(),
            );
        }
        if self.arena_size_mb > 4096 {
            errors.push(
                "memory.arena_size_mb must be <= 4096 (4 GB)"
                    .to_string(),
            );
        }
        if self.ring_buffer_size == 0 {
            errors.push(
                "memory.ring_buffer_size must be > 0".to_string(),
            );
        }
        if self.ring_buffer_size > 0
            && !self.ring_buffer_size.is_power_of_two()
        {
            errors.push(
                "memory.ring_buffer_size must be power of 2"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl MemoryConfig {
    /// Set the arena size in megabytes.
    pub fn with_arena_size_mb(mut self, size_mb: u32) -> Self {
        self.arena_size_mb = size_mb;
        self
    }

    /// Set the ring buffer size per track.
    pub fn with_ring_buffer_size(mut self, size: u32) -> Self {
        self.ring_buffer_size = size;
        self
    }
}

// -----------------------------------------------------------------------
// WorkerConfig
// -----------------------------------------------------------------------

/// Default SCHED_FIFO priority level (1-99, higher = more priority).
fn default_realtime_priority_level() -> u32 {
    80
}

/// Worker configuration for CPU-pinned threads.
///
/// Controls the number of media worker threads, CPU affinity,
/// and real-time scheduling priority. `num_workers == 0` means
/// auto-detect from available CPU cores.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Number of worker threads (0 = auto-detect from CPU count)
    pub num_workers: u32,
    /// Pin each worker to a dedicated CPU core
    pub cpu_affinity: bool,
    /// Request real-time scheduling priority (requires CAP_SYS_NICE)
    pub realtime_priority: bool,
    /// SCHED_FIFO priority level (1-99, default 80).
    /// Only used when realtime_priority is true.
    #[serde(default = "default_realtime_priority_level")]
    pub realtime_priority_level: u32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            num_workers: 0,
            cpu_affinity: false,
            realtime_priority: false,
            realtime_priority_level: default_realtime_priority_level(),
        }
    }
}

impl Validate for WorkerConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // num_workers == 0 means auto-detect, which is valid.
        // Upper bound is checked in cross-module validation
        // because it depends on the CPU count at runtime.

        // Validate realtime_priority_level when realtime_priority is enabled
        if self.realtime_priority
            && !(1..=99).contains(&self.realtime_priority_level)
        {
            errors.push(
                "worker.realtime_priority_level must be in \
                 range 1..=99 when realtime_priority is true"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// RoomConfig
// -----------------------------------------------------------------------

/// Room configuration for limits and timeouts.
///
/// Controls maximum participants per room, total room count,
/// and how long an empty room persists before cleanup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RoomConfig {
    /// Maximum participants allowed in a single room
    pub max_participants_per_room: u32,
    /// Maximum number of rooms the SFU can host
    pub max_rooms: u32,
    /// Timeout in milliseconds before an empty room is cleaned up
    pub empty_room_timeout_ms: u32,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            max_participants_per_room: 100,
            max_rooms: 100,
            empty_room_timeout_ms: 30_000, // 30 seconds
        }
    }
}

impl Validate for RoomConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.max_participants_per_room == 0 {
            errors.push(
                "room.max_participants_per_room must be > 0"
                    .to_string(),
            );
        }
        if self.max_participants_per_room > 10_000 {
            errors.push(
                "room.max_participants_per_room must be <= 10000"
                    .to_string(),
            );
        }
        if self.max_rooms == 0 {
            errors.push(
                "room.max_rooms must be > 0".to_string(),
            );
        }
        if self.max_rooms > 100_000 {
            errors.push(
                "room.max_rooms must be <= 100000".to_string(),
            );
        }
        if self.empty_room_timeout_ms == 0 {
            errors.push(
                "room.empty_room_timeout_ms must be > 0"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// BweConfig
// -----------------------------------------------------------------------

/// Bandwidth estimation configuration (AIMD algorithm).
///
/// Controls the loss-based bandwidth estimator's initial value,
/// bounds, and AIMD (Additive Increase Multiplicative Decrease)
/// parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BweConfig {
    /// Starting bandwidth estimate in bits per second
    pub initial_bandwidth_bps: u32,
    /// Floor for bandwidth estimate in bits per second
    pub min_bandwidth_bps: u32,
    /// Ceiling for bandwidth estimate in bits per second
    pub max_bandwidth_bps: u32,
    /// Loss percentage threshold that triggers decrease (0–100)
    pub loss_threshold_percent: u32,
    /// Multiplicative decrease factor (0.0 < f < 1.0)
    pub decrease_factor: f64,
    /// Additive increase step in bits per second
    pub increase_bps: u32,
}

impl Default for BweConfig {
    fn default() -> Self {
        Self {
            initial_bandwidth_bps: 1_000_000, // 1 Mbps
            min_bandwidth_bps: 100_000,       // 100 Kbps
            max_bandwidth_bps: 10_000_000,    // 10 Mbps
            loss_threshold_percent: 5,
            decrease_factor: 0.85,
            increase_bps: 100_000, // 100 Kbps
        }
    }
}

impl Validate for BweConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Positive-space assertions
        if self.initial_bandwidth_bps == 0 {
            errors.push(
                "bwe.initial_bandwidth_bps must be > 0"
                    .to_string(),
            );
        }
        if self.min_bandwidth_bps == 0 {
            errors.push(
                "bwe.min_bandwidth_bps must be > 0".to_string(),
            );
        }
        if self.max_bandwidth_bps == 0 {
            errors.push(
                "bwe.max_bandwidth_bps must be > 0".to_string(),
            );
        }
        if self.increase_bps == 0 {
            errors.push(
                "bwe.increase_bps must be > 0".to_string(),
            );
        }

        // Ordering: min <= initial <= max
        if self.min_bandwidth_bps > self.initial_bandwidth_bps {
            errors.push(
                "bwe.min_bandwidth_bps must be <= \
                 initial_bandwidth_bps"
                    .to_string(),
            );
        }
        if self.initial_bandwidth_bps > self.max_bandwidth_bps {
            errors.push(
                "bwe.initial_bandwidth_bps must be <= \
                 max_bandwidth_bps"
                    .to_string(),
            );
        }

        // Loss threshold is a percentage
        if self.loss_threshold_percent > 100 {
            errors.push(
                "bwe.loss_threshold_percent must be <= 100"
                    .to_string(),
            );
        }

        // Decrease factor must be in open interval (0, 1)
        if self.decrease_factor <= 0.0
            || self.decrease_factor >= 1.0
        {
            errors.push(
                "bwe.decrease_factor must be in (0.0, 1.0)"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// LoggingConfig
// -----------------------------------------------------------------------

/// Logging configuration.
///
/// Controls log verbosity, format, and metadata inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Minimum log level to emit
    pub level: LogLevel,
    /// Use structured (JSON) log output
    pub structured: bool,
    /// Include timestamps in log lines
    pub include_timestamps: bool,
    /// Include thread IDs in log lines
    pub include_thread_ids: bool,
    /// Optional file path for log output.
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Log verbosity level.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq,
    Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Debug,
            structured: true,
            include_timestamps: true,
            include_thread_ids: true,
            file_path: None,
        }
    }
}

impl Validate for LoggingConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        // All enum variants are valid; nothing to reject.
        Ok(())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            other => Err(format!(
                "invalid log level: '{}' \
                 (expected trace|debug|info|warn|error)",
                other
            )),
        }
    }
}

// -----------------------------------------------------------------------
// SecurityConfig
// -----------------------------------------------------------------------

/// Security configuration for JWT authentication.
///
/// The JWT secret should be set via the `NEXUS_JWT_SECRET`
/// environment variable in production. The default value is
/// only suitable for local development.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// HMAC secret for JWT token signing and verification
    pub jwt_secret: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret:
                "dev-secret-change-in-production".to_string(),
        }
    }
}

impl Validate for SecurityConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.jwt_secret.is_empty() {
            errors.push(
                "security.jwt_secret must not be empty \
                 (set NEXUS_JWT_SECRET env var)"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// ActorConfig
// -----------------------------------------------------------------------

/// Actor system configuration.
///
/// Controls the maximum number of each actor type and their
/// message queue sizes. All limits are fixed at startup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ActorConfig {
    /// Maximum track actors in the system
    pub max_track_actors: u32,
    /// Maximum participant actors in the system
    pub max_participant_actors: u32,
    /// Maximum room actors in the system
    pub max_room_actors: u32,
    /// Per-actor message queue capacity (must be power of 2)
    pub message_queue_size: u32,
    /// Queue size for actor migration messages
    pub migration_queue_size: u32,
    /// Max restarts before an actor is permanently stopped
    pub supervision_restart_limit: u32,
}

impl Default for ActorConfig {
    fn default() -> Self {
        Self {
            max_track_actors: 10_000,
            max_participant_actors: 1_000,
            max_room_actors: 100,
            message_queue_size: 1024,
            migration_queue_size: 10,
            supervision_restart_limit: 3,
        }
    }
}

impl Validate for ActorConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.max_track_actors == 0 {
            errors.push(
                "actor.max_track_actors must be > 0".to_string(),
            );
        }
        if self.max_track_actors > 1_000_000 {
            errors.push(
                "actor.max_track_actors must be <= 1000000"
                    .to_string(),
            );
        }
        if self.message_queue_size == 0 {
            errors.push(
                "actor.message_queue_size must be > 0"
                    .to_string(),
            );
        }
        if self.message_queue_size > 0
            && !self.message_queue_size.is_power_of_two()
        {
            errors.push(
                "actor.message_queue_size must be power of 2"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// MetricsConfig
// -----------------------------------------------------------------------

/// Metrics collection configuration.
///
/// Controls the Prometheus metrics endpoint and collection
/// interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Bind address for the metrics HTTP endpoint
    pub bind_addr: String,
    /// How often to collect metrics, in milliseconds
    pub collection_interval_ms: u32,
    /// Enable Prometheus text format export
    pub enable_prometheus: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9090".to_string(),
            collection_interval_ms: 1000,
            enable_prometheus: true,
        }
    }
}

impl Validate for MetricsConfig {
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.bind_addr.parse::<SocketAddr>().is_err() {
            errors.push(
                "metrics.bind_addr must be a valid socket address"
                    .to_string(),
            );
        }
        if self.collection_interval_ms == 0 {
            errors.push(
                "metrics.collection_interval_ms must be > 0"
                    .to_string(),
            );
        }
        if self.collection_interval_ms > 60_000 {
            errors.push(
                "metrics.collection_interval_ms must be <= 60000 \
                 (1 minute)"
                    .to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------
// Compile-time assertions for defaults
// -----------------------------------------------------------------------

const _: () = {
    // Verify ActorConfig defaults are sane at compile time.
    const DEFAULT_ACTOR: ActorConfig = ActorConfig {
        max_track_actors: 10_000,
        max_participant_actors: 1_000,
        max_room_actors: 100,
        message_queue_size: 1024,
        migration_queue_size: 10,
        supervision_restart_limit: 3,
    };
    assert!(DEFAULT_ACTOR.max_track_actors > 0);
    assert!(DEFAULT_ACTOR.max_track_actors <= 1_000_000);
    assert!(DEFAULT_ACTOR.message_queue_size.is_power_of_two());
};

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Validate trait --

    #[test]
    fn test_valid_transport_config() {
        let cfg = TransportConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_transport_zero_buffer() {
        let cfg = TransportConfig {
            recv_buffer_size_bytes: 0,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("recv_buffer")));
    }

    #[test]
    fn test_invalid_transport_batch_not_power_of_two() {
        let cfg = TransportConfig {
            batch_size: 3,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("power of 2")));
    }

    #[test]
    fn test_valid_memory_config() {
        let cfg = MemoryConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_memory_zero_arena() {
        let cfg = MemoryConfig {
            arena_size_mb: 0,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("arena_size_mb")));
    }

    #[test]
    fn test_invalid_memory_ring_not_power_of_two() {
        let cfg = MemoryConfig {
            ring_buffer_size: 1000,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("power of 2"))
        );
    }

    #[test]
    fn test_valid_worker_config() {
        let cfg = WorkerConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_valid_room_config() {
        let cfg = RoomConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_room_zero_participants() {
        let cfg = RoomConfig {
            max_participants_per_room: 0,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("max_participants"))
        );
    }

    #[test]
    fn test_valid_bwe_config() {
        let cfg = BweConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_bwe_ordering() {
        let cfg = BweConfig {
            min_bandwidth_bps: 2_000_000,
            initial_bandwidth_bps: 1_000_000,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("min_bandwidth_bps"))
        );
    }

    #[test]
    fn test_invalid_bwe_decrease_factor() {
        let cfg = BweConfig {
            decrease_factor: 1.5,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("decrease_factor"))
        );
    }

    #[test]
    fn test_valid_logging_config() {
        let cfg = LoggingConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(
            "debug".parse::<LogLevel>().unwrap(),
            LogLevel::Debug
        );
        assert_eq!(
            "INFO".parse::<LogLevel>().unwrap(),
            LogLevel::Info
        );
        assert!("invalid".parse::<LogLevel>().is_err());
    }

    #[test]
    fn test_valid_security_config() {
        let cfg = SecurityConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_security_empty_secret() {
        let cfg = SecurityConfig {
            jwt_secret: String::new(),
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("jwt_secret")));
    }

    #[test]
    fn test_valid_actor_config() {
        let cfg = ActorConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_actor_queue_not_power_of_two() {
        let cfg = ActorConfig {
            message_queue_size: 100,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("power of 2")));
    }

    #[test]
    fn test_valid_metrics_config() {
        let cfg = MetricsConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_metrics_bad_addr() {
        let cfg = MetricsConfig {
            bind_addr: "not-an-address".to_string(),
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("bind_addr")));
    }

    #[test]
    fn test_invalid_metrics_zero_interval() {
        let cfg = MetricsConfig {
            collection_interval_ms: 0,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("collection_interval_ms"))
        );
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::invalid(
            "transport.batch_size",
            "must be > 0",
        );
        let msg = err.to_string();
        assert!(msg.contains("transport.batch_size"));
        assert!(msg.contains("must be > 0"));
    }

    #[test]
    fn test_config_error_load() {
        let err = ConfigError::load_error("file not found");
        assert!(err.to_string().contains("file not found"));
    }

    // -- Serde round-trip --

    #[test]
    fn test_transport_config_serde_roundtrip() {
        let cfg = TransportConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: TransportConfig =
            serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.batch_size, decoded.batch_size);
        assert_eq!(
            cfg.recv_buffer_size_bytes,
            decoded.recv_buffer_size_bytes
        );
        assert_eq!(cfg.tls_cert_path, decoded.tls_cert_path);
        assert_eq!(cfg.tls_key_path, decoded.tls_key_path);
        assert_eq!(cfg.stun_servers, decoded.stun_servers);
    }

    #[test]
    fn test_bwe_config_serde_roundtrip() {
        let cfg = BweConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: BweConfig =
            serde_json::from_str(&json).unwrap();
        assert_eq!(
            cfg.initial_bandwidth_bps,
            decoded.initial_bandwidth_bps
        );
        assert_eq!(
            cfg.decrease_factor, decoded.decrease_factor
        );
    }

    #[test]
    fn test_multiple_validation_errors_collected() {
        // A config with multiple problems should report all of
        // them, not just the first.
        let cfg = TransportConfig {
            recv_buffer_size_bytes: 0,
            send_buffer_size_bytes: 0,
            batch_size: 3,
            batch_flush_interval_us: 0,
            max_webrtc_sessions: 0,
            ..Default::default()
        };
        let errs = cfg.validate().unwrap_err();
        // At least 5 distinct errors expected
        assert!(
            errs.len() >= 5,
            "expected >= 5 errors, got {}: {:?}",
            errs.len(),
            errs
        );
    }
}
