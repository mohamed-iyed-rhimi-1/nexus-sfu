//! CLI parsing module using clap
//!
//! Provides command-line argument parsing for the nexus-loadtest tool.
//! Supports three test scenarios: webinar, conference, and stress.

use clap::{Parser, Subcommand, ValueEnum};

/// WebRTC load testing tool for Nexus SFU
#[derive(Parser, Debug)]
#[command(name = "nexus-loadtest", about = "WebRTC load testing for Nexus SFU")]
#[command(version, author)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Verbose output for debugging
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// Available test scenarios
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Webinar scenario: 1 broadcaster + N viewers
    Webinar {
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8443)
        #[arg(long, required = true)]
        sfu_url: String,

        /// Room name or ID
        #[arg(long, required = true)]
        room: String,

        /// Number of viewers
        #[arg(long, required = true)]
        viewers: u32,

        /// Test duration in seconds
        #[arg(long, default_value = "60")]
        duration: u64,

        /// Output format: console, json, prometheus
        #[arg(long, default_value = "console")]
        output: OutputFormat,

        /// Write report to file
        #[arg(long)]
        report_file: Option<String>,

        /// Port for Prometheus metrics HTTP endpoint (only used with --output prometheus)
        #[arg(long, default_value = "9090")]
        prometheus_port: u16,
    },

    /// Conference scenario: N participants all publishing/subscribing
    Conference {
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8443)
        #[arg(long, required = true)]
        sfu_url: String,

        /// Room name or ID
        #[arg(long, required = true)]
        room: String,

        /// Number of participants
        #[arg(long, required = true)]
        participants: u32,

        /// Test duration in seconds
        #[arg(long, default_value = "60")]
        duration: u64,

        /// Output format: console, json, prometheus
        #[arg(long, default_value = "console")]
        output: OutputFormat,

        /// Write report to file
        #[arg(long)]
        report_file: Option<String>,

        /// Port for Prometheus metrics HTTP endpoint (only used with --output prometheus)
        #[arg(long, default_value = "9090")]
        prometheus_port: u16,
    },

    /// Stress scenario: multiple rooms with configurable participants
    Stress {
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8443)
        #[arg(long, required = true)]
        sfu_url: String,

        /// Number of rooms to create
        #[arg(long, required = true)]
        rooms: u32,

        /// Number of participants per room
        #[arg(long, required = true)]
        participants_per_room: u32,

        /// Test duration in seconds
        #[arg(long, default_value = "60")]
        duration: u64,

        /// Output format: console, json, prometheus
        #[arg(long, default_value = "console")]
        output: OutputFormat,

        /// Write report to file
        #[arg(long)]
        report_file: Option<String>,

        /// Port for Prometheus metrics HTTP endpoint (only used with --output prometheus)
        #[arg(long, default_value = "9090")]
        prometheus_port: u16,
    },
}

/// Output format for test reports
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable console output with progress bar
    Console,
    /// Structured JSON for CI/CD integration
    Json,
    /// Prometheus metrics format via HTTP endpoint
    Prometheus,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Console
    }
}
