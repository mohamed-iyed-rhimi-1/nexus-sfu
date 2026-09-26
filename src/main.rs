//! Nexus SFU MVP - Main Entry Point
//!
//! High-performance WebRTC Selective Forwarding Unit.
//!
//! # Startup Sequence
//!
//! The SFU follows a specific initialization order per the architecture document:
//! 1. Configuration loading and validation
//! 2. Tracing/logging initialization
//! 3. `nexus_sfu::server::start`: SFU (distributed state, gossip, worker
//!    pool, media socket), signaling, orchestrator, API, packet loop
//! 4. Wait for SIGTERM / SIGINT, then graceful shutdown
//!
//! # Usage
//!
//! ```bash
//! # Run with default configuration
//! nexus-sfu
//!
//! # Run with custom configuration file
//! nexus-sfu --config /path/to/config.toml
//!
//! # Run with specific bind addresses
//! nexus-sfu --media-addr 0.0.0.0:10000 --signal-addr 0.0.0.0:8080
//! ```

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tracing::{error, info, warn};

use nexus_sfu::config::{ConfigLoader, ConfigWatcher, NexusConfig};
use nexus_sfu::tracing::{init_tracing, ExtendedLoggingConfig};
use nexus_sfu::VERSION;

// ============================================================================
// Command-line argument parsing
// ============================================================================

/// Command-line arguments for the SFU.
struct Args {
    /// Path to configuration file (TOML format).
    config_path: Option<String>,
    /// Media (RTP/RTCP) bind address override.
    media_addr: Option<SocketAddr>,
    /// Signaling (WebSocket) bind address override.
    signal_addr: Option<SocketAddr>,
    /// Number of worker threads override.
    num_workers: Option<u32>,
    /// Log level override.
    log_level: Option<String>,
    /// Log file path override.
    log_file: Option<String>,
    /// Show help message.
    help: bool,
    /// Show version.
    version: bool,
}

impl Args {
    /// Parse command-line arguments.
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut result = Args {
            config_path: None,
            media_addr: None,
            signal_addr: None,
            num_workers: None,
            log_level: None,
            log_file: None,
            help: false,
            version: false,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    result.help = true;
                }
                "-v" | "--version" => {
                    result.version = true;
                }
                "-c" | "--config" => {
                    i += 1;
                    if i < args.len() {
                        result.config_path = Some(args[i].clone());
                    }
                }
                "--media-addr" => {
                    i += 1;
                    if i < args.len() {
                        result.media_addr = args[i].parse().ok();
                    }
                }
                "--signal-addr" => {
                    i += 1;
                    if i < args.len() {
                        result.signal_addr = args[i].parse().ok();
                    }
                }
                "--workers" => {
                    i += 1;
                    if i < args.len() {
                        result.num_workers = args[i].parse().ok();
                    }
                }
                "--log-level" => {
                    i += 1;
                    if i < args.len() {
                        result.log_level = Some(args[i].clone());
                    }
                }
                "--log-file" => {
                    i += 1;
                    if i < args.len() {
                        result.log_file = Some(args[i].clone());
                    }
                }
                _ => {
                    // Unknown argument - ignore
                }
            }
            i += 1;
        }

        result
    }
}

// ============================================================================
// Help and version output
// ============================================================================

/// Print help message.
fn print_help() {
    println!(
        r#"Nexus SFU MVP v{version}
High-performance WebRTC Selective Forwarding Unit

USAGE:
    nexus-sfu [OPTIONS]

OPTIONS:
    -h, --help              Print this help message
    -v, --version           Print version information
    -c, --config <PATH>     Path to TOML configuration file
    --media-addr <ADDR>     Media (RTP/RTCP) bind address [default: 0.0.0.0:10000]
    --signal-addr <ADDR>    Signaling (WebSocket) bind address [default: 0.0.0.0:8080]
    --workers <NUM>         Number of worker threads [default: auto-detect]
    --log-level <LEVEL>     Log level: trace, debug, info, warn, error [default: info]
    --log-file <PATH>       Optional log file path for file output

EXAMPLES:
    # Run with default configuration
    nexus-sfu

    # Run with custom configuration file
    nexus-sfu --config /etc/nexus-sfu/config.toml

    # Run with specific bind addresses
    nexus-sfu --media-addr 0.0.0.0:10000 --signal-addr 0.0.0.0:8080

    # Run with 4 worker threads and debug logging
    nexus-sfu --workers 4 --log-level debug

    # Run with file logging
    nexus-sfu --log-file /var/log/nexus-sfu.log

STARTUP SEQUENCE:
    1. Configuration loading and validation
    2. Tracing/logging initialization
    3. Distributed state initialization
    4. Gossip protocol initialization
    5. Worker pool initialization
    6. Signaling server initialization
    7. Metrics server initialization
    8. API server initialization
    9. Shutdown signal handler registration
"#,
        version = VERSION
    );
}

/// Print version information.
fn print_version() {
    println!("Nexus SFU MVP v{}", VERSION);
    println!("High-performance WebRTC Selective Forwarding Unit");
}

// ============================================================================
// Configuration loading
// ============================================================================

/// Load configuration from file and apply command-line overrides.
///
/// Follows precedence: CLI > env > file > defaults
///
/// # Requirements Coverage
///
fn load_config(args: &Args) -> Result<NexusConfig, String> {
    // Step 1: Start with defaults, then load from file if specified
    // Precedence so far: file > defaults
    let mut config = if let Some(ref path) = args.config_path {
        // CLI-specified config file takes precedence over NEXUS_CONFIG_PATH env var
        NexusConfig::from_file(path).map_err(|e| format!("Failed to load config: {}", e))?
    } else if let Ok(env_path) = std::env::var("NEXUS_CONFIG_PATH") {
        // Fall back to NEXUS_CONFIG_PATH env var
        NexusConfig::from_file(&env_path).map_err(|e| format!("Failed to load config: {}", e))?
    } else {
        // No file specified, use defaults
        NexusConfig::default()
    };

    // Step 2: Apply environment variable overrides
    // Precedence so far: env > file > defaults
    config = ConfigLoader::merge_from_env(config)
        .map_err(|e| format!("Failed to merge env overrides: {}", e))?;

    // Step 3: Apply command-line overrides (highest precedence)
    // Final precedence: CLI > env > file > defaults
    if let Some(addr) = args.media_addr {
        config.transport.media_bind_addr = addr;
    }
    if let Some(addr) = args.signal_addr {
        config.transport.signaling_bind_addr = addr;
    }
    if let Some(workers) = args.num_workers {
        config.worker.num_workers = workers;
    }
    if let Some(ref level) = args.log_level {
        config.logging.level = level.parse().map_err(|e: String| e)?;
    }
    if let Some(ref file_path) = args.log_file {
        config.logging.file_path = Some(file_path.clone());
    }

    // Step 4: Validate configuration
    config
        .validate()
        .map_err(|e| format!("Invalid config: {}", e))?;

    Ok(config)
}

// ============================================================================
// Main entry point
// ============================================================================

#[tokio::main]
async fn main() -> ExitCode {
    // ========================================================================
    // Phase 1: Parse command-line arguments
    // ========================================================================
    let args = Args::parse();

    // Handle help and version (no logging needed)
    if args.help {
        print_help();
        return ExitCode::SUCCESS;
    }
    if args.version {
        print_version();
        return ExitCode::SUCCESS;
    }

    // ========================================================================
    // Phase 2: Load and validate configuration
    // ========================================================================
    let config = match load_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // ========================================================================
    // Phase 3: Initialize tracing/logging
    // ========================================================================
    let _extended_logging = ExtendedLoggingConfig {
        base: config.logging.clone(),
        file_path: config.logging.file_path.clone(),
    };

    if let Err(e) = init_tracing(&config.logging) {
        eprintln!("Failed to initialize tracing: {}", e);
        return ExitCode::FAILURE;
    }

    info!("Starting Nexus SFU v{}", VERSION);
    info!("Startup sequence: config → tracing → distributed state → gossip → worker pool → signaling → metrics → API");

    // Log configuration summary
    info!("Configuration loaded:");
    info!("  Media address: {}", config.transport.media_bind_addr);
    info!(
        "  Signaling address: {}",
        config.transport.signaling_bind_addr
    );
    info!("  Workers: {} (0 = auto)", config.worker.num_workers);
    info!("  Arena size: {}MB", config.memory.arena_size_mb);
    info!("  Drain timeout: {}ms", config.drain_timeout_ms);

    // ========================================================================
    // Phase 4: Start config watcher for hot-reload (optional)
    // ========================================================================
    let config_path_for_watcher = args
        .config_path
        .clone()
        .or_else(|| env::var("NEXUS_CONFIG_PATH").ok());

    let config_watcher = if let Some(path) = config_path_for_watcher {
        match ConfigWatcher::new(PathBuf::from(&path), config.clone()) {
            Ok(w) => {
                info!("Config hot-reload enabled for: {}", path);
                Some(w)
            }
            Err(e) => {
                warn!("Failed to start config watcher: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Runtime config access (for hot-reload)
    let _runtime_config = config_watcher
        .as_ref()
        .map(|w| w.config())
        .unwrap_or_else(|| Arc::new(tokio::sync::RwLock::new(config.clone())));

    // ========================================================================
    // Phase 5: Start the server (SFU, signaling, orchestrator, API) and run
    // until SIGTERM / SIGINT
    // ========================================================================
    let server = match nexus_sfu::server::start(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Startup failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    info!(
        media = %server.media_addr(),
        signaling = %server.signaling_addr(),
        candidates = ?server.candidate_addrs(),
        "Nexus SFU running"
    );

    wait_for_shutdown_signal(&server).await;
    match server.shutdown().await {
        Ok(()) => {
            info!("Nexus SFU shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("SFU error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Wait for SIGTERM or SIGINT, or for the packet loop to stop on its own.
async fn wait_for_shutdown_signal(server: &nexus_sfu::server::ServerHandle) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("register SIGINT handler");
    let mut check = tokio::time::interval(std::time::Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = sigterm.recv() => { info!("Received SIGTERM"); return; }
            _ = sigint.recv() => { info!("Received SIGINT"); return; }
            _ = check.tick() => {
                if server.is_finished() {
                    warn!("Packet loop stopped; shutting down");
                    return;
                }
            }
        }
    }
}
