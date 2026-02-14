//! nexus-loadtest CLI entry point
//!
//! This binary provides the command-line interface for running WebRTC load tests
//! against a Nexus SFU server.
//!
//! **Validates: Requirements 7.1, 7.2, 7.3, 8.5**

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use nexus_loadtest::cli::{Cli, Command, OutputFormat};
use nexus_loadtest::config::{ConferenceConfig, StressConfig, TestConfig, WebinarConfig};
use nexus_loadtest::runner::TestRunner;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() -> ExitCode {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging based on verbose flag
    let log_level = if cli.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(log_level.into()),
        )
        .init();

    tracing::info!("nexus-loadtest v{}", env!("CARGO_PKG_VERSION"));

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
            run_webinar(sfu_url, room, viewers, duration, output, report_file, prometheus_port, cli.verbose).await
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
            run_conference(sfu_url, room, participants, duration, output, report_file, prometheus_port, cli.verbose)
                .await
        }
        Command::Stress {
            sfu_url,
            rooms,
            participants_per_room,
            duration,
            output,
            report_file,
            prometheus_port,
        } => {
            run_stress(
                sfu_url,
                rooms,
                participants_per_room,
                duration,
                output,
                report_file,
                prometheus_port,
                cli.verbose,
            )
            .await
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

/// Run webinar scenario: 1 broadcaster + N viewers
///
/// **Validates: Requirements 3.1, 3.2, 7.1, 7.2, 7.3**
async fn run_webinar(
    sfu_url: String,
    room: String,
    viewers: u32,
    duration: u64,
    output: OutputFormat,
    report_file: Option<String>,
    prometheus_port: u16,
    verbose: bool,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting webinar scenario: 1 broadcaster + {} viewers in room '{}'",
        viewers,
        room
    );

    let config = WebinarConfig {
        base: TestConfig {
            sfu_url,
            duration: Duration::from_secs(duration),
            output_format: output,
            report_file,
            connection_timeout: Duration::from_secs(30),
            verbose,
            prometheus_port,
        },
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
    sfu_url: String,
    room: String,
    participants: u32,
    duration: u64,
    output: OutputFormat,
    report_file: Option<String>,
    prometheus_port: u16,
    verbose: bool,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting conference scenario: {} participants in room '{}'",
        participants,
        room
    );

    let config = ConferenceConfig {
        base: TestConfig {
            sfu_url,
            duration: Duration::from_secs(duration),
            output_format: output,
            report_file,
            connection_timeout: Duration::from_secs(30),
            verbose,
            prometheus_port,
        },
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
    sfu_url: String,
    rooms: u32,
    participants_per_room: u32,
    duration: u64,
    output: OutputFormat,
    report_file: Option<String>,
    prometheus_port: u16,
    verbose: bool,
) -> Result<bool, nexus_loadtest::error::LoadTestError> {
    tracing::info!(
        "Starting stress scenario: {} rooms with {} participants each (total: {})",
        rooms,
        participants_per_room,
        rooms * participants_per_room
    );

    let config = StressConfig {
        base: TestConfig {
            sfu_url,
            duration: Duration::from_secs(duration),
            output_format: output,
            report_file,
            connection_timeout: Duration::from_secs(30),
            verbose,
            prometheus_port,
        },
        room_count: rooms,
        participants_per_room,
    };

    let report = TestRunner::run_stress(config).await?;
    Ok(report.passed)
}
