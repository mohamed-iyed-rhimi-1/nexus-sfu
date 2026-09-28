//! nexus-loadtest CLI entry point
//!
//! This binary provides the command-line interface for running WebRTC load tests
//! against a Nexus SFU server.
//!
//! **Validates: Requirements 7.1, 7.2, 7.3, 8.5**

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use nexus_loadtest::cli::{Cli, Command};
use nexus_loadtest::config::{ConferenceConfig, StressConfig, TestConfig, WebinarConfig};
use nexus_loadtest::runner::TestRunner;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() -> ExitCode {
    // Parse CLI arguments
    let cli = Cli::parse();
    // Before logging starts: stdout carries only the token.
    if let Command::Token { sub, ttl } = &cli.command {
        return print_token(cli.jwt_secret.clone(), sub, *ttl);
    }

    // Initialize logging based on verbose flag
    let log_level = if cli.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
        )
        .init();

    tracing::info!("nexus-loadtest v{}", env!("CARGO_PKG_VERSION"));

    let connection = cli.connection_options();
    if connection.auth_token.is_none() && connection.jwt_secret.is_none() {
        tracing::warn!(
            "No --token or --jwt-secret given; the SFU will reject unauthenticated clients"
        );
    }

    // Options shared by every scenario
    let verbose = cli.verbose;
    let base_config = |sfu_url, duration, output_format, report_file, prometheus_port| TestConfig {
        sfu_url,
        duration: Duration::from_secs(duration),
        output_format,
        report_file,
        connection_timeout: Duration::from_secs(30),
        verbose,
        prometheus_port,
        connection: connection.clone(),
    };

    // Dispatch to appropriate test scenario based on command
    let result = match cli.command {
        Command::Webinar {
            sfu_url,
            room,
            viewers,
            duration,
            output,
            report_file,
            prometheus_port,
        } => {
            let base = base_config(sfu_url, duration, output, report_file, prometheus_port);
            run_webinar(base, room, viewers).await
        }
        Command::Conference {
            sfu_url,
            room,
            participants,
            duration,
            output,
            report_file,
            prometheus_port,
        } => {
            let base = base_config(sfu_url, duration, output, report_file, prometheus_port);
            run_conference(base, room, participants).await
        }
        Command::Token { .. } => unreachable!("handled before logging starts"),
        Command::Stress {
            sfu_url,
            rooms,
            participants_per_room,
            duration,
            output,
            report_file,
            prometheus_port,
        } => {
            let base = base_config(sfu_url, duration, output, report_file, prometheus_port);
            run_stress(base, rooms, participants_per_room).await
        }
    };

    // Set exit code based on target validation (Requirement 8.5)
    match result {
        Ok(passed) => {
            if passed {
                tracing::info!("Load test completed successfully - all targets met");
                ExitCode::SUCCESS
            } else {
                tracing::warn!("Load test completed - some targets not met");
                ExitCode::from(1)
            }
        }
        Err(e) => {
            tracing::error!("Load test failed: {}", e);
            ExitCode::from(2)
        }
    }
}

/// `token`: print a JWT minted with `--jwt-secret`, else `NEXUS_JWT_SECRET`.
fn print_token(secret: Option<String>, sub: &str, ttl: u64) -> ExitCode {
    let Some(secret) = secret.or_else(|| std::env::var("NEXUS_JWT_SECRET").ok()) else {
        eprintln!("error: no --jwt-secret given and NEXUS_JWT_SECRET is not set");
        return ExitCode::from(2);
    };
    match nexus_loadtest::signaling::mint_token(&secret, sub, ttl) {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Run webinar scenario: 1 broadcaster + N viewers
///
/// **Validates: Requirements 3.1, 3.2, 7.1, 7.2, 7.3**
async fn run_webinar(
    base: TestConfig,
    room: String,
    viewers: u32,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting webinar scenario: 1 broadcaster + {} viewers in room '{}'",
        viewers,
        room
    );

    let config = WebinarConfig {
        base,
        room,
        viewer_count: viewers,
    };

    let report = TestRunner::run_webinar(config).await?;
    Ok(report.passed)
}

/// Run conference scenario: N participants all publishing/subscribing
///
/// **Validates: Requirements 4.1, 4.2, 4.3, 7.1, 7.2, 7.3**
async fn run_conference(
    base: TestConfig,
    room: String,
    participants: u32,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting conference scenario: {} participants in room '{}'",
        participants,
        room
    );

    let config = ConferenceConfig {
        base,
        room,
        participant_count: participants,
    };

    let report = TestRunner::run_conference(config).await?;
    Ok(report.passed)
}

/// Run stress scenario: multiple rooms with configurable participants
///
/// **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 7.1, 7.2, 7.3**
async fn run_stress(
    base: TestConfig,
    rooms: u32,
    participants_per_room: u32,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting stress scenario: {} rooms with {} participants each (total: {})",
        rooms,
        participants_per_room,
        rooms * participants_per_room
    );

    let config = StressConfig {
        base,
        room_count: rooms,
        participants_per_room,
    };

    let report = TestRunner::run_stress(config).await?;
    Ok(report.passed)
}
