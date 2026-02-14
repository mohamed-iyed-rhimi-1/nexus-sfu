//! nexus-loadtest: CLI-based WebRTC load testing tool for Nexus SFU
//!
//! This crate provides a load testing tool that spawns lightweight headless
//! WebRTC clients using webrtc-rs to simulate real-world load scenarios:
//!
//! - **Webinar**: 1 broadcaster + N viewers (fan-out testing)
//! - **Conference**: N participants all publishing/subscribing (mesh testing)
//! - **Stress**: Multiple rooms with configurable participants (scalability testing)
//!
//! Unlike browser-based load testing, each headless client uses ~2-5MB RAM,
//! enabling 1000+ concurrent clients on a single machine.
//!
//! # Example
//!
//! ```bash
//! # Run a webinar test with 100 viewers
//! nexus-loadtest webinar --sfu-url wss://localhost:8443 --room test --viewers 100
//!
//! # Run a conference test with 10 participants
//! nexus-loadtest conference --sfu-url wss://localhost:8443 --room test --participants 10
//!
//! # Run a stress test across 5 rooms
//! nexus-loadtest stress --sfu-url wss://localhost:8443 --rooms 5 --participants-per-room 20
//! ```

#![deny(warnings)]

pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod media;
pub mod metrics;
pub mod progress;
pub mod prometheus;
pub mod report;
pub mod runner;
pub mod signaling;

// Re-export commonly used types at crate root
pub use cli::{Cli, Command};
pub use config::{
    ClientConfig, ClientRole, ConferenceConfig, OutputFormat, PerformanceTargets, StressConfig,
    TestConfig, WebinarConfig,
};
pub use error::{ClientError, LoadTestError, SignalingError};
pub use metrics::{AggregatedMetrics, ClientMetrics, MetricsCollector};
pub use progress::ProgressDisplay;
pub use prometheus::{PrometheusServer, PrometheusState};
pub use report::{ReportGenerator, TargetValidation, TestReport};
pub use runner::TestRunner;
