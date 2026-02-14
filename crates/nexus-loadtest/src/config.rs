//! Configuration types for load testing
//!
//! Defines configuration structures for clients, test scenarios,
//! and performance targets.

use std::time::Duration;

pub use crate::cli::OutputFormat;

/// Client role determines publishing/subscribing behavior
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRole {
    /// Only receives media (webinar viewers)
    Viewer,
    /// Only publishes media (webinar broadcaster)
    Broadcaster,
    /// Both publishes and receives (conference participants)
    Participant,
}

impl ClientRole {
    /// Returns true if this role can publish media
    pub fn can_publish(&self) -> bool {
        matches!(self, ClientRole::Broadcaster | ClientRole::Participant)
    }

    /// Returns true if this role can subscribe to media
    pub fn can_subscribe(&self) -> bool {
        matches!(self, ClientRole::Viewer | ClientRole::Participant)
    }
}

/// Configuration for a headless client
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// SFU WebSocket/QUIC URL
    pub sfu_url: String,
    /// Room name or ID
    pub room: String,
    /// Client role (Viewer, Broadcaster, or Participant)
    pub role: ClientRole,
    /// Connection timeout duration
    pub connection_timeout: Duration,
    /// ICE server URLs (STUN/TURN). Defaults to Google public STUN servers when empty.
    pub ice_servers: Vec<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            sfu_url: String::new(),
            room: String::new(),
            role: ClientRole::Viewer,
            connection_timeout: Duration::from_secs(60),
            ice_servers: Vec::new(),
        }
    }
}

/// Base test configuration shared across all scenarios
#[derive(Clone, Debug)]
pub struct TestConfig {
    /// SFU WebSocket/QUIC URL
    pub sfu_url: String,
    /// Test duration
    pub duration: Duration,
    /// Output format for reports
    pub output_format: OutputFormat,
    /// Optional file path for report output
    pub report_file: Option<String>,
    /// Connection timeout for each client
    pub connection_timeout: Duration,
    /// Enable verbose logging
    pub verbose: bool,
    /// Port for Prometheus metrics HTTP endpoint (only used with prometheus output)
    pub prometheus_port: u16,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            sfu_url: String::new(),
            duration: Duration::from_secs(60),
            output_format: OutputFormat::Console,
            report_file: None,
            connection_timeout: Duration::from_secs(30),
            verbose: false,
            prometheus_port: 9090,
        }
    }
}

/// Webinar-specific configuration
#[derive(Clone, Debug)]
pub struct WebinarConfig {
    /// Base test configuration
    pub base: TestConfig,
    /// Room name or ID
    pub room: String,
    /// Number of viewers
    pub viewer_count: u32,
}

/// Conference-specific configuration
#[derive(Clone, Debug)]
pub struct ConferenceConfig {
    /// Base test configuration
    pub base: TestConfig,
    /// Room name or ID
    pub room: String,
    /// Number of participants
    pub participant_count: u32,
}

/// Stress test configuration
#[derive(Clone, Debug)]
pub struct StressConfig {
    /// Base test configuration
    pub base: TestConfig,
    /// Number of rooms to create
    pub room_count: u32,
    /// Number of participants per room
    pub participants_per_room: u32,
}

/// Architecture performance targets for validation
#[derive(Clone, Debug)]
pub struct PerformanceTargets {
    /// Target P50 latency in milliseconds (default: 5ms)
    pub latency_p50_ms: u64,
    /// Target P99 latency in milliseconds (default: 15ms)
    pub latency_p99_ms: u64,
    /// Minimum participant count target (default: 1000)
    pub min_participants: u32,
    /// Target throughput in packets per second per core (default: 500K)
    pub throughput_pps: u64,
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            latency_p50_ms: 5,
            latency_p99_ms: 15,
            min_participants: 1000,
            throughput_pps: 500_000,
        }
    }
}
