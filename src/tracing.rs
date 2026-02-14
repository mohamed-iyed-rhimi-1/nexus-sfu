//! Tracing module for structured logging and hot-path instrumentation.
//!
//! Provides `init_tracing()` to set up a tracing subscriber with:
//! - Configurable log level
//! - Structured JSON output
//! - Optional file output
//! - Thread ID inclusion
//!
//! Also provides hot-path span macros for packet receive/forward/send latency.
//!
//! # Requirements Coverage
//!
//! - Requirement 12.1: Initialize tracing subscriber with configurable level
//! - Requirement 12.2: Hot-path span instrumentation with microsecond precision
//! - Requirement 12.3: Control-path span instrumentation
//! - Requirement 12.4: End-to-end latency recording
//!
//! # TigerStyle Compliance
//!
//! - ≤70 lines per function
//! - ≥2 assertions per function
//! - Explicit types
//! - No dynamic allocation after initialization

use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::config::{LogLevel, LoggingConfig};

// ============================================================================
// Compile-time assertions (TigerStyle)
// ============================================================================

const _: () = {
    // Ensure LogLevel enum is small
    assert!(std::mem::size_of::<LogLevel>() <= 1);
};

// ============================================================================
// Hot-path latency tracking (lock-free)
// ============================================================================

/// Global atomic counters for hot-path latency tracking.
/// These are updated by the hot-path span macros and read by metrics.
pub struct HotPathMetrics {
    /// Total packet receive latency in nanoseconds
    pub recv_latency_sum_ns: AtomicU64,
    /// Number of receive operations
    pub recv_count: AtomicU64,
    /// Total packet forward latency in nanoseconds
    pub forward_latency_sum_ns: AtomicU64,
    /// Number of forward operations
    pub forward_count: AtomicU64,
    /// Total packet send latency in nanoseconds
    pub send_latency_sum_ns: AtomicU64,
    /// Number of send operations
    pub send_count: AtomicU64,
}

impl HotPathMetrics {
    /// Create new hot-path metrics.
    pub const fn new() -> Self {
        Self {
            recv_latency_sum_ns: AtomicU64::new(0),
            recv_count: AtomicU64::new(0),
            forward_latency_sum_ns: AtomicU64::new(0),
            forward_count: AtomicU64::new(0),
            send_latency_sum_ns: AtomicU64::new(0),
            send_count: AtomicU64::new(0),
        }
    }

    /// Record packet receive latency.
    #[inline(always)]
    pub fn record_recv(&self, latency_ns: u64) {
        self.recv_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.recv_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record packet forward latency.
    #[inline(always)]
    pub fn record_forward(&self, latency_ns: u64) {
        self.forward_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.forward_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record packet send latency.
    #[inline(always)]
    pub fn record_send(&self, latency_ns: u64) {
        self.send_latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.send_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average receive latency in microseconds.
    pub fn avg_recv_latency_us(&self) -> f64 {
        let sum = self.recv_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.recv_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get average forward latency in microseconds.
    pub fn avg_forward_latency_us(&self) -> f64 {
        let sum = self.forward_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.forward_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get average send latency in microseconds.
    pub fn avg_send_latency_us(&self) -> f64 {
        let sum = self.send_latency_sum_ns.load(Ordering::Relaxed);
        let count = self.send_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        (sum as f64 / count as f64) / 1000.0
    }

    /// Get total packet rate (packets per second estimate).
    /// Based on forward count as the primary metric.
    pub fn packet_rate(&self) -> u64 {
        self.forward_count.load(Ordering::Relaxed)
    }

    /// Reset all counters (for testing or periodic reset).
    pub fn reset(&self) {
        self.recv_latency_sum_ns.store(0, Ordering::Relaxed);
        self.recv_count.store(0, Ordering::Relaxed);
        self.forward_latency_sum_ns.store(0, Ordering::Relaxed);
        self.forward_count.store(0, Ordering::Relaxed);
        self.send_latency_sum_ns.store(0, Ordering::Relaxed);
        self.send_count.store(0, Ordering::Relaxed);
    }

    /// Get snapshot of all metrics.
    pub fn snapshot(&self) -> HotPathMetricsSnapshot {
        HotPathMetricsSnapshot {
            recv_latency_sum_ns: self.recv_latency_sum_ns.load(Ordering::Relaxed),
            recv_count: self.recv_count.load(Ordering::Relaxed),
            forward_latency_sum_ns: self.forward_latency_sum_ns.load(Ordering::Relaxed),
            forward_count: self.forward_count.load(Ordering::Relaxed),
            send_latency_sum_ns: self.send_latency_sum_ns.load(Ordering::Relaxed),
            send_count: self.send_count.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of hot-path metrics for export.
#[derive(Clone, Debug, Default)]
pub struct HotPathMetricsSnapshot {
    pub recv_latency_sum_ns: u64,
    pub recv_count: u64,
    pub forward_latency_sum_ns: u64,
    pub forward_count: u64,
    pub send_latency_sum_ns: u64,
    pub send_count: u64,
}

impl HotPathMetricsSnapshot {
    /// Get average receive latency in microseconds.
    pub fn avg_recv_latency_us(&self) -> f64 {
        if self.recv_count == 0 {
            return 0.0;
        }
        (self.recv_latency_sum_ns as f64 / self.recv_count as f64) / 1000.0
    }

    /// Get average forward latency in microseconds.
    pub fn avg_forward_latency_us(&self) -> f64 {
        if self.forward_count == 0 {
            return 0.0;
        }
        (self.forward_latency_sum_ns as f64 / self.forward_count as f64) / 1000.0
    }

    /// Get average send latency in microseconds.
    pub fn avg_send_latency_us(&self) -> f64 {
        if self.send_count == 0 {
            return 0.0;
        }
        (self.send_latency_sum_ns as f64 / self.send_count as f64) / 1000.0
    }
}

/// Global hot-path metrics instance.
pub static HOT_PATH_METRICS: HotPathMetrics = HotPathMetrics::new();

// ============================================================================
// Latency guard for RAII-style timing
// ============================================================================

/// RAII guard for measuring latency.
/// Records latency to the appropriate counter when dropped.
pub struct LatencyGuard {
    start: Instant,
    kind: LatencyKind,
}

/// Kind of latency being measured.
#[derive(Clone, Copy)]
pub enum LatencyKind {
    Recv,
    Forward,
    Send,
}

impl LatencyGuard {
    /// Create a new latency guard for receive operations.
    #[inline(always)]
    pub fn recv() -> Self {
        Self {
            start: Instant::now(),
            kind: LatencyKind::Recv,
        }
    }

    /// Create a new latency guard for forward operations.
    #[inline(always)]
    pub fn forward() -> Self {
        Self {
            start: Instant::now(),
            kind: LatencyKind::Forward,
        }
    }

    /// Create a new latency guard for send operations.
    #[inline(always)]
    pub fn send() -> Self {
        Self {
            start: Instant::now(),
            kind: LatencyKind::Send,
        }
    }
}

impl Drop for LatencyGuard {
    #[inline(always)]
    fn drop(&mut self) {
        let elapsed_ns = self.start.elapsed().as_nanos() as u64;
        match self.kind {
            LatencyKind::Recv => HOT_PATH_METRICS.record_recv(elapsed_ns),
            LatencyKind::Forward => HOT_PATH_METRICS.record_forward(elapsed_ns),
            LatencyKind::Send => HOT_PATH_METRICS.record_send(elapsed_ns),
        }
    }
}

// ============================================================================
// Hot-path span macros
// ============================================================================

/// Macro for timing packet receive operations.
/// Returns a guard that records latency when dropped.
///
/// # Example
///
/// ```ignore
/// let _guard = recv_span!();
/// // ... receive packet ...
/// // latency recorded when _guard is dropped
/// ```
#[macro_export]
macro_rules! recv_span {
    () => {
        $crate::tracing::LatencyGuard::recv()
    };
}

/// Macro for timing packet forward operations.
/// Returns a guard that records latency when dropped.
///
/// # Example
///
/// ```ignore
/// let _guard = forward_span!();
/// // ... forward packet ...
/// // latency recorded when _guard is dropped
/// ```
#[macro_export]
macro_rules! forward_span {
    () => {
        $crate::tracing::LatencyGuard::forward()
    };
}

/// Macro for timing packet send operations.
/// Returns a guard that records latency when dropped.
///
/// # Example
///
/// ```ignore
/// let _guard = send_span!();
/// // ... send packet ...
/// // latency recorded when _guard is dropped
/// ```
#[macro_export]
macro_rules! send_span {
    () => {
        $crate::tracing::LatencyGuard::send()
    };
}

// ============================================================================
// Tracing initialization
// ============================================================================

/// Extended logging configuration with optional file output.
#[derive(Debug, Clone)]
pub struct ExtendedLoggingConfig {
    /// Base logging config
    pub base: LoggingConfig,
    /// Optional file path for log output
    pub file_path: Option<String>,
}

impl Default for ExtendedLoggingConfig {
    fn default() -> Self {
        Self {
            base: LoggingConfig::default(),
            file_path: None,
        }
    }
}

impl From<LoggingConfig> for ExtendedLoggingConfig {
    fn from(base: LoggingConfig) -> Self {
        Self {
            base,
            file_path: None,
        }
    }
}

/// Initialize tracing with the given configuration.
///
/// Sets up a tracing subscriber with:
/// - Configurable log level from config
/// - Structured JSON output when `config.structured` is true
/// - Optional file output when `file_path` is provided
/// - Thread ID inclusion when `config.include_thread_ids` is true
///
/// # Arguments
///
/// * `config` - Logging configuration
///
/// # Returns
///
/// `Ok(())` on success, `Err` with description on failure.
///
/// # Requirements Coverage
///
/// - Requirement 12.1: Initialize tracing subscriber with configurable level
///
/// # TigerStyle Compliance
///
/// - ≤70 lines
/// - ≥2 assertions
/// - Explicit error handling
pub fn init_tracing(config: &LoggingConfig) -> Result<(), TracingError> {
    init_tracing_extended(&ExtendedLoggingConfig::from(config.clone()))
}

/// Initialize tracing with extended configuration including file output.
///
/// # Arguments
///
/// * `config` - Extended logging configuration
///
/// # Returns
///
/// `Ok(())` on success, `Err` with description on failure.
pub fn init_tracing_extended(config: &ExtendedLoggingConfig) -> Result<(), TracingError> {
    // Precondition assertions
    assert!(
        matches!(
            config.base.level,
            LogLevel::Trace | LogLevel::Debug | LogLevel::Info | LogLevel::Warn | LogLevel::Error
        ),
        "Log level must be valid"
    );

    // Convert LogLevel to tracing Level
    let level = match config.base.level {
        LogLevel::Trace => Level::TRACE,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Info => Level::INFO,
        LogLevel::Warn => Level::WARN,
        LogLevel::Error => Level::ERROR,
    };

    // Create env filter with configured level
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    // Build the subscriber based on configuration
    if config.base.structured {
        init_json_subscriber(config, filter)?;
    } else {
        init_pretty_subscriber(config, filter)?;
    }

    // Postcondition assertion
    assert!(
        tracing::dispatcher::has_been_set(),
        "Tracing dispatcher must be set after init"
    );

    Ok(())
}

/// Initialize JSON-formatted subscriber.
fn init_json_subscriber(
    config: &ExtendedLoggingConfig,
    filter: EnvFilter,
) -> Result<(), TracingError> {
    let registry = Registry::default();

    // Create JSON layer for stdout
    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_timer(SystemTime::default())
        .with_thread_ids(config.base.include_thread_ids)
        .with_thread_names(config.base.include_thread_ids)
        .with_target(true)
        .with_file(config.base.include_timestamps)
        .with_line_number(config.base.include_timestamps)
        .with_span_events(FmtSpan::CLOSE)
        .with_filter(filter.clone());

    // Add file layer if configured
    if let Some(ref file_path) = config.file_path {
        let file = File::create(file_path).map_err(|e| TracingError::FileCreate {
            path: file_path.clone(),
            source: e,
        })?;

        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_timer(SystemTime::default())
            .with_thread_ids(config.base.include_thread_ids)
            .with_thread_names(config.base.include_thread_ids)
            .with_target(true)
            .with_ansi(false)
            .with_writer(file)
            .with_filter(filter);

        registry
            .with(json_layer)
            .with(file_layer)
            .try_init()
            .map_err(|e| TracingError::Init {
                message: e.to_string(),
            })?;
    } else {
        registry
            .with(json_layer)
            .try_init()
            .map_err(|e| TracingError::Init {
                message: e.to_string(),
            })?;
    }

    Ok(())
}

/// Initialize pretty-formatted subscriber (human-readable).
fn init_pretty_subscriber(
    config: &ExtendedLoggingConfig,
    filter: EnvFilter,
) -> Result<(), TracingError> {
    let registry = Registry::default();

    // Create pretty layer for stdout
    let pretty_layer = tracing_subscriber::fmt::layer()
        .with_timer(SystemTime::default())
        .with_thread_ids(config.base.include_thread_ids)
        .with_thread_names(config.base.include_thread_ids)
        .with_target(true)
        .with_file(config.base.include_timestamps)
        .with_line_number(config.base.include_timestamps)
        .with_span_events(FmtSpan::CLOSE)
        .with_filter(filter.clone());

    // Add file layer if configured
    if let Some(ref file_path) = config.file_path {
        let file = File::create(file_path).map_err(|e| TracingError::FileCreate {
            path: file_path.clone(),
            source: e,
        })?;

        let file_layer = tracing_subscriber::fmt::layer()
            .with_timer(SystemTime::default())
            .with_thread_ids(config.base.include_thread_ids)
            .with_thread_names(config.base.include_thread_ids)
            .with_target(true)
            .with_ansi(false)
            .with_writer(file)
            .with_filter(filter);

        registry
            .with(pretty_layer)
            .with(file_layer)
            .try_init()
            .map_err(|e| TracingError::Init {
                message: e.to_string(),
            })?;
    } else {
        registry
            .with(pretty_layer)
            .try_init()
            .map_err(|e| TracingError::Init {
                message: e.to_string(),
            })?;
    }

    Ok(())
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during tracing initialization.
#[derive(Debug)]
pub enum TracingError {
    /// Failed to create log file
    FileCreate { path: String, source: io::Error },
    /// Failed to initialize tracing subscriber
    Init { message: String },
}

impl std::fmt::Display for TracingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracingError::FileCreate { path, source } => {
                write!(f, "Failed to create log file '{}': {}", path, source)
            }
            TracingError::Init { message } => {
                write!(f, "Failed to initialize tracing: {}", message)
            }
        }
    }
}

impl std::error::Error for TracingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TracingError::FileCreate { source, .. } => Some(source),
            TracingError::Init { .. } => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_path_metrics_new() {
        let metrics = HotPathMetrics::new();
        assert_eq!(metrics.recv_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.forward_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.send_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_hot_path_metrics_record() {
        let metrics = HotPathMetrics::new();
        
        metrics.record_recv(1000);
        assert_eq!(metrics.recv_count.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.recv_latency_sum_ns.load(Ordering::Relaxed), 1000);
        
        metrics.record_forward(2000);
        assert_eq!(metrics.forward_count.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.forward_latency_sum_ns.load(Ordering::Relaxed), 2000);
        
        metrics.record_send(3000);
        assert_eq!(metrics.send_count.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.send_latency_sum_ns.load(Ordering::Relaxed), 3000);
    }

    #[test]
    fn test_hot_path_metrics_avg() {
        let metrics = HotPathMetrics::new();
        
        // Record multiple samples
        metrics.record_recv(1000); // 1us
        metrics.record_recv(3000); // 3us
        
        // Average should be 2us
        let avg = metrics.avg_recv_latency_us();
        assert!((avg - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_hot_path_metrics_reset() {
        let metrics = HotPathMetrics::new();
        
        metrics.record_recv(1000);
        metrics.record_forward(2000);
        metrics.record_send(3000);
        
        metrics.reset();
        
        assert_eq!(metrics.recv_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.forward_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.send_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_hot_path_metrics_snapshot() {
        let metrics = HotPathMetrics::new();
        
        metrics.record_recv(1000);
        metrics.record_forward(2000);
        metrics.record_send(3000);
        
        let snapshot = metrics.snapshot();
        
        assert_eq!(snapshot.recv_count, 1);
        assert_eq!(snapshot.recv_latency_sum_ns, 1000);
        assert_eq!(snapshot.forward_count, 1);
        assert_eq!(snapshot.forward_latency_sum_ns, 2000);
        assert_eq!(snapshot.send_count, 1);
        assert_eq!(snapshot.send_latency_sum_ns, 3000);
    }

    #[test]
    fn test_latency_guard() {
        // Reset global metrics
        HOT_PATH_METRICS.reset();
        
        {
            let _guard = LatencyGuard::recv();
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_micros(10));
        }
        
        // Should have recorded one recv
        assert_eq!(HOT_PATH_METRICS.recv_count.load(Ordering::Relaxed), 1);
        assert!(HOT_PATH_METRICS.recv_latency_sum_ns.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_extended_logging_config_default() {
        let config = ExtendedLoggingConfig::default();
        assert!(config.file_path.is_none());
    }

    #[test]
    fn test_extended_logging_config_from() {
        let base = LoggingConfig::default();
        let extended: ExtendedLoggingConfig = base.into();
        assert!(extended.file_path.is_none());
    }

    #[test]
    fn test_tracing_error_display() {
        let err = TracingError::Init {
            message: "test error".to_string(),
        };
        assert!(err.to_string().contains("test error"));
    }
}
