//! CLI parsing module using clap
//!
//! Provides command-line argument parsing for the nexus-loadtest tool.
//! Supports three test scenarios (webinar, conference, stress) and `token`, which
//! prints a dev JWT.

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

    /// Pre-issued JWT sent in the signaling auth handshake (overrides --jwt-secret)
    #[arg(long, global = true)]
    pub token: Option<String>,

    /// HS256 secret used to mint a JWT per client (the SFU's `jwt_secret`)
    #[arg(long, global = true)]
    pub jwt_secret: Option<String>,

    /// Skip TLS certificate verification for wss:// (self-signed dev certs only)
    #[arg(long, global = true)]
    pub insecure: bool,
}

impl Cli {
    /// Signaling auth/TLS options shared by every client in the run
    pub fn connection_options(&self) -> crate::config::ConnectionOptions {
        crate::config::ConnectionOptions {
            auth_token: self.token.clone(),
            jwt_secret: self.jwt_secret.clone(),
            insecure_tls: self.insecure,
        }
    }
}

/// Available test scenarios
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Webinar scenario: 1 broadcaster + N viewers
    Webinar {
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8080)
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
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8080)
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
        /// SFU WebSocket/QUIC URL (e.g., wss://localhost:8080)
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

    /// Print a dev JWT for a browser or SDK client, signed with --jwt-secret or
    /// NEXUS_JWT_SECRET (the SFU's `security.jwt_secret`)
    Token {
        /// Subject claim (`sub`); any non-empty name
        #[arg(long, required = true)]
        sub: String,

        /// Lifetime in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,
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
