//! Test runner and orchestration
//!
//! Orchestrates test scenarios and manages client lifecycle.
//! Supports spawning at least 1000 concurrent HeadlessClients on a single machine with 16GB RAM.
//!
//! **Validates: Requirements 2.3**

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::client::HeadlessClient;
use crate::config::{ClientConfig, ClientRole, ConferenceConfig, OutputFormat, StressConfig, TestConfig, WebinarConfig};
use crate::error::LoadTestError;
use crate::metrics::{AggregatedMetrics, MetricsCollector};
use crate::progress::ProgressDisplay;
use crate::prometheus::{PrometheusServer, PrometheusState};
use crate::report::TestReport;

/// Result of spawning a client
struct SpawnResult {
    /// Client ID (index in the pool)
    client_id: usize,
    /// The spawned client (if successful)
    client: Option<HeadlessClient>,
    /// Error message (if failed)
    error: Option<String>,
}

/// Test runner that orchestrates load tests
///
/// Manages a pool of HeadlessClients and coordinates their lifecycle
/// for various test scenarios (webinar, conference, stress).
pub struct TestRunner {
    /// Pool of headless clients
    clients: Vec<Arc<Mutex<HeadlessClient>>>,
    /// Metrics collector for aggregating performance data
    metrics_collector: MetricsCollector,
    /// Test configuration
    #[allow(dead_code)]
    config: TestConfig,
    /// Number of failed client connections
    failed_count: u32,
    /// Number of successful client connections
    success_count: u32,
}

impl TestRunner {
    /// Create a new test runner with the given configuration
    pub fn new(config: TestConfig) -> Self {
        Self {
            clients: Vec::new(),
            metrics_collector: MetricsCollector::new(Duration::from_secs(1)),
            config,
            failed_count: 0,
            success_count: 0,
        }
    }

    /// Create a new test runner with default configuration
    pub fn with_defaults() -> Self {
        Self::new(TestConfig::default())
    }

    /// Get the number of clients in the pool
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Get the number of successfully connected clients
    pub fn success_count(&self) -> u32 {
        self.success_count
    }

    /// Get the number of failed client connections
    pub fn failed_count(&self) -> u32 {
        self.failed_count
    }

    /// Get the metrics collector
    pub fn metrics_collector(&self) -> &MetricsCollector {
        &self.metrics_collector
    }

    /// Get mutable access to the metrics collector
    pub fn metrics_collector_mut(&mut self) -> &mut MetricsCollector {
        &mut self.metrics_collector
    }

    /// Spawn a single client and connect it to the SFU
    ///
    /// Returns the client wrapped in Arc<Mutex<>> for concurrent access.
    async fn spawn_client(
        client_id: usize,
        client_config: ClientConfig,
    ) -> SpawnResult {
        debug!("Spawning client {} with role {:?}", client_id, client_config.role);

        // Create the client
        let client = match HeadlessClient::new(client_config).await {
            Ok(c) => c,
            Err(e) => {
                return SpawnResult {
                    client_id,
                    client: None,
                    error: Some(format!("Failed to create client: {}", e)),
                };
            }
        };

        SpawnResult {
            client_id,
            client: Some(client),
            error: None,
        }
    }

    /// Spawn multiple clients concurrently
    ///
    /// Uses tokio tasks to spawn clients in parallel, respecting the
    /// concurrency limit to avoid overwhelming the system.
    ///
    /// **Validates: Requirements 2.3** - Support spawning at least 1000 concurrent clients
    pub async fn spawn_clients(
        &mut self,
        configs: Vec<ClientConfig>,
    ) -> Result<(), LoadTestError> {
        let total_clients = configs.len();
        info!("Spawning {} clients concurrently", total_clients);

        // Spawn all clients concurrently using tokio tasks
        let mut handles: Vec<JoinHandle<SpawnResult>> = Vec::with_capacity(total_clients);

        for (client_id, config) in configs.into_iter().enumerate() {
            // Register client in metrics collector
            self.metrics_collector.register_client(client_id);

            // Spawn task for this client
            let handle = tokio::spawn(async move {
                Self::spawn_client(client_id, config).await
            });
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(result) => {
                    if let Some(client) = result.client {
                        self.clients.push(Arc::new(Mutex::new(client)));
                        self.success_count += 1;
                        self.metrics_collector.mark_connected(result.client_id);
                    } else if let Some(error) = result.error {
                        warn!("Client {} failed to spawn: {}", result.client_id, error);
                        self.failed_count += 1;
                        self.metrics_collector.mark_failed(result.client_id);
                    }
                }
                Err(e) => {
                    error!("Task join error: {}", e);
                    self.failed_count += 1;
                }
            }
        }

        info!(
            "Spawned {} clients: {} successful, {} failed",
            total_clients, self.success_count, self.failed_count
        );

        Ok(())
    }

    /// Connect all clients in the pool to the SFU
    ///
    /// Connects clients concurrently and tracks connection success/failure.
    pub async fn connect_all(&mut self) -> Result<(), LoadTestError> {
        let client_count = self.clients.len();
        info!("Connecting {} clients to SFU", client_count);

        let mut handles: Vec<JoinHandle<(usize, Result<(), String>)>> = Vec::with_capacity(client_count);

        for (client_id, client) in self.clients.iter().enumerate() {
            let client = Arc::clone(client);
            let handle = tokio::spawn(async move {
                let mut client = client.lock().await;
                let result = client.connect().await.map_err(|e| e.to_string());
                (client_id, result)
            });
            handles.push(handle);
        }

        // Reset counters for connection phase
        self.success_count = 0;
        self.failed_count = 0;

        // Collect results
        for handle in handles {
            match handle.await {
                Ok((client_id, result)) => {
                    match result {
                        Ok(()) => {
                            self.success_count += 1;
                            self.metrics_collector.mark_connected(client_id);
                            debug!("Client {} connected successfully", client_id);
                        }
                        Err(e) => {
                            self.failed_count += 1;
                            self.metrics_collector.mark_failed(client_id);
                            warn!("Client {} failed to connect: {}", client_id, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Task join error during connect: {}", e);
                    self.failed_count += 1;
                }
            }
        }

        info!(
            "Connection complete: {} successful, {} failed",
            self.success_count, self.failed_count
        );

        Ok(())
    }

    /// Start publishing for all clients that have the Broadcaster or Participant role
    pub async fn start_publishing_all(&mut self) -> Result<(), LoadTestError> {
        let mut handles: Vec<JoinHandle<(usize, Result<(), String>)>> = Vec::new();

        for (client_id, client) in self.clients.iter().enumerate() {
            let client = Arc::clone(client);
            let handle = tokio::spawn(async move {
                let mut client = client.lock().await;
                if client.role().can_publish() {
                    let result = client.start_publishing().await.map_err(|e| e.to_string());
                    (client_id, result)
                } else {
                    (client_id, Ok(()))
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok((client_id, result)) => {
                    if let Err(e) = result {
                        warn!("Client {} failed to start publishing: {}", client_id, e);
                    }
                }
                Err(e) => {
                    error!("Task join error during publishing: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Collect metrics from all clients
    ///
    /// Aggregates metrics from all clients in the pool into the metrics collector.
    pub fn collect_metrics(&mut self) {
        for (client_id, client) in self.clients.iter().enumerate() {
            // Try to lock without blocking - skip if locked
            if let Ok(mut client) = client.try_lock() {
                // Sync atomic counters into the client's metrics struct
                client.sync_metrics();
                let metrics = client.metrics();

                // Record latency samples
                for &latency in &metrics.latency_samples {
                    self.metrics_collector.record_latency(client_id, latency);
                }

                // Record jitter samples
                for &jitter in &metrics.jitter_samples {
                    self.metrics_collector.record_jitter(client_id, jitter);
                }

                // Record packet statistics
                self.metrics_collector.record_packets(
                    client_id,
                    metrics.packets_received,
                    metrics.packets_lost,
                );

                // Record bytes
                self.metrics_collector.record_bytes(client_id, metrics.bytes_received);

                // Record time to first frame
                if let Some(ttff) = metrics.time_to_first_frame {
                    self.metrics_collector.record_first_frame(client_id, ttff);
                }

                // Record connection time
                if let Some(conn_time) = metrics.connection_time {
                    self.metrics_collector.record_connection_time(client_id, conn_time);
                }
            }
        }
    }

    /// Aggregate metrics from all clients
    ///
    /// Returns aggregated metrics including percentiles, rates, and throughput.
    pub fn aggregate_metrics(&self) -> AggregatedMetrics {
        self.metrics_collector.aggregate()
    }

    /// Disconnect all clients and cleanup resources
    pub async fn disconnect_all(&mut self) -> Result<(), LoadTestError> {
        info!("Disconnecting {} clients", self.clients.len());

        let mut handles: Vec<JoinHandle<Result<(), String>>> = Vec::new();

        for client in self.clients.iter() {
            let client = Arc::clone(client);
            let handle = tokio::spawn(async move {
                let mut client = client.lock().await;
                client.disconnect().await.map_err(|e| e.to_string())
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                error!("Task join error during disconnect: {}", e);
            }
        }

        // Clear the client pool
        self.clients.clear();

        info!("All clients disconnected");
        Ok(())
    }

    /// Run a webinar scenario
    ///
    /// Creates 1 broadcaster and N viewers, runs for the configured duration,
    /// and returns a test report.
    ///
    /// **Validates: Requirements 3.1, 3.2, 3.4, 3.5**
    pub async fn run_webinar(config: WebinarConfig) -> Result<TestReport, LoadTestError> {
        use crate::report::ReportGenerator;

        info!(
            "Starting webinar scenario: 1 broadcaster + {} viewers in room '{}'",
            config.viewer_count, config.room
        );

        // Initialize progress display (only shows for Console output format)
        let progress = ProgressDisplay::new(config.base.output_format, config.base.duration);

        // Start Prometheus server if prometheus output is selected (Requirement 7.3)
        let prometheus_state = Arc::new(PrometheusState::new());
        let mut prometheus_server = if config.base.output_format == OutputFormat::Prometheus {
            let mut server = PrometheusServer::new(Arc::clone(&prometheus_state));
            server.start(config.base.prometheus_port).await?;
            Some(server)
        } else {
            None
        };

        let mut runner = TestRunner::new(config.base.clone());

        // Step 1: Create client configurations
        // Requirement 3.1: Create exactly one Broadcaster
        let mut client_configs = Vec::with_capacity(1 + config.viewer_count as usize);

        let broadcaster_config = ClientConfig {
            sfu_url: config.base.sfu_url.clone(),
            room: config.room.clone(),
            role: ClientRole::Broadcaster,
            connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
        };
        client_configs.push(broadcaster_config);

        // Requirement 3.2: Create the specified number of Viewers
        for _ in 0..config.viewer_count {
            let viewer_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Viewer,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(viewer_config);
        }

        // Step 2: Spawn all clients
        progress.set_connecting(1 + config.viewer_count);
        runner.spawn_clients(client_configs).await?;

        // Step 3: Connect all clients to the SFU
        runner.connect_all().await?;
        progress.set_connected(runner.success_count(), runner.failed_count());

        // Requirement 3.4: Begin collecting metrics when all Viewers have connected
        info!(
            "All clients connected: {} successful, {} failed. Starting metrics collection.",
            runner.success_count(),
            runner.failed_count()
        );

        // Step 4: Start publishing on the broadcaster (first client)
        progress.set_publishing();
        runner.start_publishing_all().await?;

        // Give the SFU time to process the published tracks and send notifications
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 4b: Have all viewers discover and subscribe to the broadcaster's tracks concurrently
        let mut subscribe_handles: Vec<JoinHandle<(usize, Result<Vec<u64>, String>)>> = Vec::new();
        for (idx, client) in runner.clients.iter().enumerate() {
            let client = Arc::clone(client);
            let handle = tokio::spawn(async move {
                let mut c = client.lock().await;
                if c.role().can_subscribe() {
                    let result = c.discover_and_subscribe(Duration::from_secs(5)).await
                        .map_err(|e| e.to_string());
                    (idx, result)
                } else {
                    (idx, Ok(Vec::new()))
                }
            });
            subscribe_handles.push(handle);
        }
        for handle in subscribe_handles {
            match handle.await {
                Ok((idx, Err(e))) => warn!("Viewer {} failed to discover/subscribe: {}", idx, e),
                Err(e) => warn!("Subscribe task join error: {}", e),
                _ => {}
            }
        }

        // Create report generator for Prometheus updates
        let report_generator = ReportGenerator::new(
            config.base.output_format,
            crate::config::PerformanceTargets::default(),
        );

        // Step 5: Run for the configured duration, collecting metrics periodically
        let test_start = std::time::Instant::now();
        let sample_interval = Duration::from_secs(1);

        while test_start.elapsed() < config.base.duration {
            // Collect metrics from all clients
            runner.collect_metrics();

            // Update progress display with current metrics
            let metrics = runner.aggregate_metrics();
            progress.update(&metrics);

            // Update Prometheus metrics if server is running
            if let Some(ref server) = prometheus_server {
                let report = report_generator.generate("webinar", &config.base, metrics.clone());
                server.update(report).await;
            }

            // Sleep until next sample interval
            tokio::time::sleep(sample_interval).await;

            if config.base.verbose {
                debug!(
                    "Metrics snapshot: {} clients, {:.2} pps throughput, {:.2}ms P50 latency",
                    metrics.total_clients,
                    metrics.throughput_pps,
                    metrics.latency_p50.as_secs_f64() * 1000.0
                );
            }
        }

        // Step 6: Final metrics collection
        runner.collect_metrics();
        let aggregated_metrics = runner.aggregate_metrics();

        // Finish progress display
        progress.finish(&aggregated_metrics);

        // Requirement 3.5: Report time taken for all Viewers to receive their first frame
        // This is captured in avg_time_to_first_frame in the aggregated metrics
        info!(
            "Test complete. Avg time to first frame: {:.2}ms",
            aggregated_metrics.avg_time_to_first_frame.as_secs_f64() * 1000.0
        );

        if aggregated_metrics.throughput_pps == 0.0 && aggregated_metrics.successful_clients > 1 {
            warn!(
                "Zero throughput detected with {} successful clients — media may not be flowing. \
                 Check SFU logs for subscription/renegotiation errors.",
                aggregated_metrics.successful_clients
            );
        }

        // Step 7: Disconnect all clients
        runner.disconnect_all().await?;

        // Step 8: Generate final report
        let report = report_generator.generate("webinar", &config.base, aggregated_metrics);

        // Update Prometheus with final metrics
        if let Some(ref server) = prometheus_server {
            server.update(report.clone()).await;
        }

        // Output report if requested (for non-Prometheus formats)
        if config.base.output_format != OutputFormat::Prometheus {
            report_generator.output(&report, config.base.report_file.as_deref())?;
        } else {
            // For Prometheus, keep the server running briefly to allow scraping
            info!("Prometheus metrics available at http://0.0.0.0:{}/metrics", config.base.prometheus_port);
            info!("Press Ctrl+C to stop the metrics server, or wait 5 seconds for auto-shutdown");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Stop Prometheus server if running
        if let Some(ref mut server) = prometheus_server {
            server.stop().await;
        }

        Ok(report)
    }

    /// Run a conference scenario
    ///
    /// Creates N participants that all publish and subscribe to each other.
    ///
    /// **Validates: Requirements 4.1, 4.3, 4.4**
    pub async fn run_conference(config: ConferenceConfig) -> Result<TestReport, LoadTestError> {
        use crate::report::ReportGenerator;

        info!(
            "Starting conference scenario: {} participants in room '{}'",
            config.participant_count, config.room
        );

        // Initialize progress display (only shows for Console output format)
        let progress = ProgressDisplay::new(config.base.output_format, config.base.duration);

        // Start Prometheus server if prometheus output is selected (Requirement 7.3)
        let prometheus_state = Arc::new(PrometheusState::new());
        let mut prometheus_server = if config.base.output_format == OutputFormat::Prometheus {
            let mut server = PrometheusServer::new(Arc::clone(&prometheus_state));
            server.start(config.base.prometheus_port).await?;
            Some(server)
        } else {
            None
        };

        let mut runner = TestRunner::new(config.base.clone());

        // Step 1: Create client configurations
        // Requirement 4.1: Create the specified number of Participants
        let mut client_configs = Vec::with_capacity(config.participant_count as usize);

        for _ in 0..config.participant_count {
            let participant_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Participant,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(participant_config);
        }

        // Step 2: Spawn all clients
        progress.set_connecting(config.participant_count);
        runner.spawn_clients(client_configs).await?;

        // Step 3: Connect all clients to the SFU
        runner.connect_all().await?;
        progress.set_connected(runner.success_count(), runner.failed_count());

        info!(
            "All clients connected: {} successful, {} failed. Starting publishing.",
            runner.success_count(),
            runner.failed_count()
        );

        // Step 4: Start publishing on all participants
        // Requirement 4.2: Each Participant publishes audio and video test patterns
        progress.set_publishing();
        runner.start_publishing_all().await?;

        // Give some time for tracks to be published and propagated
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 5: Each participant discovers and subscribes to other participants' tracks concurrently
        // Requirement 4.3: Each Participant subscribes to all other Participants' tracks
        // Requirement 4.4: Track subscription success rate
        let mut subscribe_handles: Vec<JoinHandle<(usize, Result<Vec<u64>, String>)>> = Vec::new();
        for (idx, client) in runner.clients.iter().enumerate() {
            let client = Arc::clone(client);
            let handle = tokio::spawn(async move {
                let mut c = client.lock().await;
                if c.role().can_subscribe() {
                    let result = c.discover_and_subscribe(Duration::from_secs(5)).await
                        .map_err(|e| e.to_string());
                    (idx, result)
                } else {
                    (idx, Ok(Vec::new()))
                }
            });
            subscribe_handles.push(handle);
        }

        let mut total_subscriptions = 0u32;
        let mut successful_subscriptions = 0u32;
        for handle in subscribe_handles {
            match handle.await {
                Ok((idx, Ok(tracks))) => {
                    let count = tracks.len() as u32;
                    total_subscriptions += count;
                    successful_subscriptions += count;
                    debug!("Client {} subscribed to {} tracks", idx, count);
                }
                Ok((idx, Err(e))) => {
                    total_subscriptions += 1;
                    warn!("Client {} failed to discover/subscribe: {}", idx, e);
                }
                Err(e) => {
                    total_subscriptions += 1;
                    error!("Subscribe task join error: {}", e);
                }
            }
        }

        // Calculate subscription success rate for Requirement 4.4
        let subscription_success_rate = if total_subscriptions > 0 {
            (successful_subscriptions as f64 / total_subscriptions as f64) * 100.0
        } else {
            100.0
        };

        info!(
            "Subscription complete: {}/{} successful ({:.1}%)",
            successful_subscriptions, total_subscriptions, subscription_success_rate
        );

        // Create report generator for Prometheus updates
        let report_generator = ReportGenerator::new(
            config.base.output_format,
            crate::config::PerformanceTargets::default(),
        );

        // Step 6: Run for the configured duration, collecting metrics periodically
        let test_start = std::time::Instant::now();
        let sample_interval = Duration::from_secs(1);

        while test_start.elapsed() < config.base.duration {
            // Collect metrics from all clients
            runner.collect_metrics();

            // Update progress display with current metrics
            let metrics = runner.aggregate_metrics();
            progress.update(&metrics);

            // Update Prometheus metrics if server is running
            if let Some(ref server) = prometheus_server {
                let report = report_generator.generate("conference", &config.base, metrics.clone());
                server.update(report).await;
            }

            // Sleep until next sample interval
            tokio::time::sleep(sample_interval).await;

            if config.base.verbose {
                debug!(
                    "Metrics snapshot: {} clients, {:.2} pps throughput, {:.2}ms P50 latency",
                    metrics.total_clients,
                    metrics.throughput_pps,
                    metrics.latency_p50.as_secs_f64() * 1000.0
                );
            }
        }

        // Step 7: Final metrics collection
        runner.collect_metrics();
        let aggregated_metrics = runner.aggregate_metrics();

        // Finish progress display
        progress.finish(&aggregated_metrics);

        info!(
            "Test complete. Subscription success rate: {:.1}%, Avg latency P50: {:.2}ms",
            subscription_success_rate,
            aggregated_metrics.latency_p50.as_secs_f64() * 1000.0
        );

        if aggregated_metrics.throughput_pps == 0.0 && aggregated_metrics.successful_clients > 1 {
            warn!(
                "Zero throughput detected with {} successful clients — media may not be flowing. \
                 Check SFU logs for subscription/renegotiation errors.",
                aggregated_metrics.successful_clients
            );
        }

        // Step 8: Disconnect all clients
        runner.disconnect_all().await?;

        // Step 9: Generate final report
        let report = report_generator.generate("conference", &config.base, aggregated_metrics);

        // Update Prometheus with final metrics
        if let Some(ref server) = prometheus_server {
            server.update(report.clone()).await;
        }

        // Output report if requested (for non-Prometheus formats)
        if config.base.output_format != OutputFormat::Prometheus {
            report_generator.output(&report, config.base.report_file.as_deref())?;
        } else {
            // For Prometheus, keep the server running briefly to allow scraping
            info!("Prometheus metrics available at http://0.0.0.0:{}/metrics", config.base.prometheus_port);
            info!("Press Ctrl+C to stop the metrics server, or wait 5 seconds for auto-shutdown");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Stop Prometheus server if running
        if let Some(ref mut server) = prometheus_server {
            server.stop().await;
        }

        Ok(report)
    }

    /// Run a stress test scenario
    ///
    /// Creates R rooms with P participants each, tracks per-room metrics,
    /// and aggregates results.
    ///
    /// **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5**
    pub async fn run_stress(config: StressConfig) -> Result<TestReport, LoadTestError> {
        use crate::report::ReportGenerator;

        info!(
            "Starting stress scenario: {} rooms with {} participants each (total: {} participants)",
            config.room_count,
            config.participants_per_room,
            config.room_count * config.participants_per_room
        );

        // Initialize progress display (only shows for Console output format)
        let progress = ProgressDisplay::new(config.base.output_format, config.base.duration);

        // Start Prometheus server if prometheus output is selected (Requirement 7.3)
        let prometheus_state = Arc::new(PrometheusState::new());
        let mut prometheus_server = if config.base.output_format == OutputFormat::Prometheus {
            let mut server = PrometheusServer::new(Arc::clone(&prometheus_state));
            server.start(config.base.prometheus_port).await?;
            Some(server)
        } else {
            None
        };

        // Create report generator for Prometheus updates
        let report_generator = ReportGenerator::new(
            config.base.output_format,
            crate::config::PerformanceTargets::default(),
        );

        // Track per-room metrics independently (Requirement 5.3)
        let mut room_runners: Vec<(String, TestRunner)> = Vec::with_capacity(config.room_count as usize);
        let mut room_init_failures: Vec<(String, String)> = Vec::new();

        // Step 1: Create R rooms with P participants each (Requirements 5.1, 5.2)
        progress.set_connecting(config.room_count * config.participants_per_room);

        for room_idx in 0..config.room_count {
            let room_name = format!("stress-room-{}", room_idx);
            info!("Initializing room '{}' with {} participants", room_name, config.participants_per_room);

            let mut runner = TestRunner::new(config.base.clone());

            // Create participant configurations for this room
            let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);
            for _ in 0..config.participants_per_room {
                let participant_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: room_name.clone(),
                    role: ClientRole::Participant,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(participant_config);
            }

            // Spawn clients for this room
            // Requirement 5.5: Handle room initialization failures gracefully
            match runner.spawn_clients(client_configs).await {
                Ok(()) => {
                    // Connect all clients in this room
                    match runner.connect_all().await {
                        Ok(()) => {
                            info!(
                                "Room '{}' initialized: {} successful, {} failed connections",
                                room_name,
                                runner.success_count(),
                                runner.failed_count()
                            );
                            room_runners.push((room_name, runner));
                        }
                        Err(e) => {
                            // Requirement 5.5: Log the failure and continue with remaining rooms
                            warn!("Room '{}' connection failed: {}. Continuing with remaining rooms.", room_name, e);
                            room_init_failures.push((room_name, e.to_string()));
                        }
                    }
                }
                Err(e) => {
                    // Requirement 5.5: Log the failure and continue with remaining rooms
                    warn!("Room '{}' spawn failed: {}. Continuing with remaining rooms.", room_name, e);
                    room_init_failures.push((room_name, e.to_string()));
                }
            }
        }

        // Log summary of room initialization
        let total_successful: u32 = room_runners.iter().map(|(_, r)| r.success_count()).sum();
        let total_failed: u32 = room_runners.iter().map(|(_, r)| r.failed_count()).sum();
        progress.set_connected(total_successful, total_failed + room_init_failures.len() as u32);

        info!(
            "Room initialization complete: {} rooms active, {} rooms failed",
            room_runners.len(),
            room_init_failures.len()
        );

        if room_runners.is_empty() {
            warn!("All rooms failed to initialize. Generating failure report.");
            progress.finish_with_error("All rooms failed to initialize");
            // Generate a report with zero metrics
            let empty_metrics = AggregatedMetrics::default();
            let report = report_generator.generate("stress", &config.base, empty_metrics);
            report_generator.output(&report, config.base.report_file.as_deref())?;
            
            // Stop Prometheus server if running
            if let Some(ref mut server) = prometheus_server {
                server.stop().await;
            }
            
            return Ok(report);
        }

        // Step 2: Start publishing on all participants in all rooms
        progress.set_publishing();
        for (room_name, runner) in room_runners.iter_mut() {
            if let Err(e) = runner.start_publishing_all().await {
                warn!("Room '{}' failed to start publishing: {}", room_name, e);
            }
        }

        // Give some time for tracks to be published and propagated
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 3: Run for the configured duration, collecting metrics periodically
        // Requirement 5.3: Track per-room metrics independently
        let test_start = std::time::Instant::now();
        let sample_interval = Duration::from_secs(1);

        while test_start.elapsed() < config.base.duration {
            // Collect metrics from all rooms independently
            for (_room_name, runner) in room_runners.iter_mut() {
                runner.collect_metrics();
            }

            // Update progress display with aggregated metrics
            let aggregated = Self::aggregate_room_metrics(&room_runners, room_init_failures.len() as u32);
            progress.update_stress(&aggregated, room_runners.len(), room_init_failures.len());

            // Update Prometheus metrics if server is running
            if let Some(ref server) = prometheus_server {
                let report = report_generator.generate("stress", &config.base, aggregated.clone());
                server.update(report).await;
            }

            // Sleep until next sample interval
            tokio::time::sleep(sample_interval).await;

            if config.base.verbose {
                // Log per-room metrics snapshot
                for (room_name, runner) in room_runners.iter() {
                    let metrics = runner.aggregate_metrics();
                    debug!(
                        "Room '{}' metrics: {} clients, {:.2} pps throughput, {:.2}ms P50 latency",
                        room_name,
                        metrics.total_clients,
                        metrics.throughput_pps,
                        metrics.latency_p50.as_secs_f64() * 1000.0
                    );
                }
            }
        }

        // Step 4: Final metrics collection from all rooms
        for (_room_name, runner) in room_runners.iter_mut() {
            runner.collect_metrics();
        }

        // Step 5: Aggregate metrics across all rooms (Requirement 5.4)
        let aggregated_metrics = Self::aggregate_room_metrics(&room_runners, room_init_failures.len() as u32);

        // Finish progress display
        progress.finish(&aggregated_metrics);

        info!(
            "Stress test complete. Total clients: {}, Successful: {}, Failed: {}",
            aggregated_metrics.total_clients,
            aggregated_metrics.successful_clients,
            aggregated_metrics.failed_clients
        );

        // Step 6: Disconnect all clients in all rooms
        for (room_name, runner) in room_runners.iter_mut() {
            if let Err(e) = runner.disconnect_all().await {
                warn!("Room '{}' disconnect error: {}", room_name, e);
            }
        }

        // Step 7: Generate final report
        let report = report_generator.generate("stress", &config.base, aggregated_metrics);

        // Update Prometheus with final metrics
        if let Some(ref server) = prometheus_server {
            server.update(report.clone()).await;
        }

        // Output report if requested (for non-Prometheus formats)
        if config.base.output_format != OutputFormat::Prometheus {
            report_generator.output(&report, config.base.report_file.as_deref())?;
        } else {
            // For Prometheus, keep the server running briefly to allow scraping
            info!("Prometheus metrics available at http://0.0.0.0:{}/metrics", config.base.prometheus_port);
            info!("Press Ctrl+C to stop the metrics server, or wait 5 seconds for auto-shutdown");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Stop Prometheus server if running
        if let Some(ref mut server) = prometheus_server {
            server.stop().await;
        }

        Ok(report)
    }

    /// Aggregate metrics from multiple room runners
    ///
    /// Combines per-room metrics into a single aggregated result.
    /// This implements Requirement 5.4: Aggregate metrics across all rooms.
    pub fn aggregate_room_metrics(room_runners: &[(String, TestRunner)], failed_rooms: u32) -> AggregatedMetrics {
        use crate::metrics::{
            calculate_connection_success_rate, calculate_packet_loss_rate,
            calculate_percentile, calculate_throughput_bps, calculate_throughput_pps,
        };

        if room_runners.is_empty() {
            return AggregatedMetrics {
                failed_clients: failed_rooms,
                ..Default::default()
            };
        }

        // Collect all latency samples from all rooms
        let mut all_latencies: Vec<Duration> = Vec::new();
        let mut all_jitter: Vec<Duration> = Vec::new();
        let mut all_ttff: Vec<Duration> = Vec::new();

        let mut total_packets_received: u64 = 0;
        let mut total_packets_lost: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_clients: u32 = 0;
        let mut successful_clients: u32 = 0;
        let mut failed_clients: u32 = 0;

        // Aggregate from each room's metrics collector
        for (_room_name, runner) in room_runners {
            let room_metrics = runner.metrics_collector().client_metrics();

            for client_metrics in room_metrics {
                total_clients += 1;

                if client_metrics.connection_successful {
                    successful_clients += 1;
                } else {
                    failed_clients += 1;
                }

                // Collect latency samples
                all_latencies.extend(client_metrics.latency_samples.iter().copied());

                // Collect jitter samples
                all_jitter.extend(client_metrics.jitter_samples.iter().copied());

                // Collect time to first frame
                if let Some(ttff) = client_metrics.time_to_first_frame {
                    all_ttff.push(ttff);
                }

                // Sum packet statistics
                total_packets_received += client_metrics.packets_received;
                total_packets_lost += client_metrics.packets_lost;
                total_bytes += client_metrics.bytes_received;
            }
        }

        // Add failed rooms to failed client count
        // Each failed room represents participants_per_room failed clients
        // But we don't know the exact count, so we just track room failures
        failed_clients += failed_rooms;

        // Sort latencies for percentile calculation
        all_latencies.sort();

        // Calculate percentiles
        let latency_p50 = calculate_percentile(&all_latencies, 50.0);
        let latency_p95 = calculate_percentile(&all_latencies, 95.0);
        let latency_p99 = calculate_percentile(&all_latencies, 99.0);

        // Calculate packet loss rate
        let packet_loss_rate = calculate_packet_loss_rate(total_packets_received, total_packets_lost);

        // Calculate average jitter
        let jitter_avg = if all_jitter.is_empty() {
            Duration::ZERO
        } else {
            let total_nanos: u128 = all_jitter.iter().map(|d| d.as_nanos()).sum();
            Duration::from_nanos((total_nanos / all_jitter.len() as u128) as u64)
        };

        // Calculate throughput (use first room's elapsed time as reference)
        let duration = room_runners
            .first()
            .map(|(_, r)| r.metrics_collector().elapsed())
            .unwrap_or(Duration::from_secs(1));

        let total_packets = total_packets_received + total_packets_lost;
        let throughput_pps = calculate_throughput_pps(total_packets, duration);
        let throughput_bps = calculate_throughput_bps(total_bytes, duration);

        // Calculate connection success rate
        let connection_success_rate = calculate_connection_success_rate(successful_clients, failed_clients);

        // Calculate average time to first frame
        let avg_time_to_first_frame = if all_ttff.is_empty() {
            Duration::ZERO
        } else {
            let total_nanos: u128 = all_ttff.iter().map(|d| d.as_nanos()).sum();
            Duration::from_nanos((total_nanos / all_ttff.len() as u128) as u64)
        };

        AggregatedMetrics {
            latency_p50,
            latency_p95,
            latency_p99,
            packet_loss_rate,
            jitter_avg,
            throughput_pps,
            throughput_bps,
            connection_success_rate,
            avg_time_to_first_frame,
            total_clients,
            successful_clients,
            failed_clients,
        }
    }
}

impl Default for TestRunner {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_creation() {
        let runner = TestRunner::with_defaults();
        assert_eq!(runner.client_count(), 0);
        assert_eq!(runner.success_count(), 0);
        assert_eq!(runner.failed_count(), 0);
    }

    #[test]
    fn test_runner_with_config() {
        let config = TestConfig {
            sfu_url: "wss://localhost:8443".to_string(),
            duration: Duration::from_secs(120),
            verbose: true,
            ..Default::default()
        };
        let runner = TestRunner::new(config);
        assert_eq!(runner.client_count(), 0);
    }

    #[tokio::test]
    async fn test_spawn_clients_empty() {
        let mut runner = TestRunner::with_defaults();
        let result = runner.spawn_clients(vec![]).await;
        assert!(result.is_ok());
        assert_eq!(runner.client_count(), 0);
    }

    #[tokio::test]
    async fn test_aggregate_metrics_empty() {
        let runner = TestRunner::with_defaults();
        let metrics = runner.aggregate_metrics();
        assert_eq!(metrics.total_clients, 0);
        assert_eq!(metrics.successful_clients, 0);
        assert_eq!(metrics.failed_clients, 0);
    }

    /// Test that webinar config creates correct client configurations
    /// Validates: Requirements 3.1 (exactly 1 Broadcaster), 3.2 (N Viewers)
    #[test]
    fn test_webinar_client_config_creation() {
        // Test helper to create client configs as run_webinar does
        fn create_webinar_client_configs(config: &WebinarConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(1 + config.viewer_count as usize);

            // Requirement 3.1: Create exactly one Broadcaster
            let broadcaster_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Broadcaster,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(broadcaster_config);

            // Requirement 3.2: Create the specified number of Viewers
            for _ in 0..config.viewer_count {
                let viewer_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Viewer,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(viewer_config);
            }

            client_configs
        }

        // Test with 10 viewers
        let config = WebinarConfig {
            base: TestConfig {
                sfu_url: "wss://test.example.com".to_string(),
                duration: Duration::from_secs(60),
                ..Default::default()
            },
            room: "test-room".to_string(),
            viewer_count: 10,
        };

        let configs = create_webinar_client_configs(&config);

        // Verify total count: 1 broadcaster + 10 viewers = 11
        assert_eq!(configs.len(), 11);

        // Verify exactly 1 broadcaster (Requirement 3.1)
        let broadcaster_count = configs.iter()
            .filter(|c| c.role == ClientRole::Broadcaster)
            .count();
        assert_eq!(broadcaster_count, 1, "Should have exactly 1 broadcaster");

        // Verify exactly N viewers (Requirement 3.2)
        let viewer_count = configs.iter()
            .filter(|c| c.role == ClientRole::Viewer)
            .count();
        assert_eq!(viewer_count, 10, "Should have exactly 10 viewers");

        // Verify first client is the broadcaster
        assert_eq!(configs[0].role, ClientRole::Broadcaster);

        // Verify all clients have correct room and URL
        for config_item in &configs {
            assert_eq!(config_item.sfu_url, "wss://test.example.com");
            assert_eq!(config_item.room, "test-room");
        }
    }

    /// Test webinar config with zero viewers
    #[test]
    fn test_webinar_client_config_zero_viewers() {
        fn create_webinar_client_configs(config: &WebinarConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(1 + config.viewer_count as usize);

            let broadcaster_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Broadcaster,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(broadcaster_config);

            for _ in 0..config.viewer_count {
                let viewer_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Viewer,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(viewer_config);
            }

            client_configs
        }

        let config = WebinarConfig {
            base: TestConfig::default(),
            room: "empty-room".to_string(),
            viewer_count: 0,
        };

        let configs = create_webinar_client_configs(&config);

        // Should still have exactly 1 broadcaster
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].role, ClientRole::Broadcaster);
    }

    /// Test webinar config with large viewer count
    #[test]
    fn test_webinar_client_config_large_viewer_count() {
        fn create_webinar_client_configs(config: &WebinarConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(1 + config.viewer_count as usize);

            let broadcaster_config = ClientConfig {
                sfu_url: config.base.sfu_url.clone(),
                room: config.room.clone(),
                role: ClientRole::Broadcaster,
                connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
            };
            client_configs.push(broadcaster_config);

            for _ in 0..config.viewer_count {
                let viewer_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Viewer,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(viewer_config);
            }

            client_configs
        }

        let config = WebinarConfig {
            base: TestConfig::default(),
            room: "large-room".to_string(),
            viewer_count: 1000,
        };

        let configs = create_webinar_client_configs(&config);

        // Verify 1 broadcaster + 1000 viewers = 1001 total
        assert_eq!(configs.len(), 1001);

        let broadcaster_count = configs.iter()
            .filter(|c| c.role == ClientRole::Broadcaster)
            .count();
        assert_eq!(broadcaster_count, 1);

        let viewer_count = configs.iter()
            .filter(|c| c.role == ClientRole::Viewer)
            .count();
        assert_eq!(viewer_count, 1000);
    }

    /// Test that conference config creates correct client configurations
    /// Validates: Requirements 4.1 (N Participants)
    #[test]
    fn test_conference_client_config_creation() {
        // Test helper to create client configs as run_conference does
        fn create_conference_client_configs(config: &ConferenceConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(config.participant_count as usize);

            // Requirement 4.1: Create the specified number of Participants
            for _ in 0..config.participant_count {
                let participant_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Participant,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(participant_config);
            }

            client_configs
        }

        // Test with 5 participants
        let config = ConferenceConfig {
            base: TestConfig {
                sfu_url: "wss://test.example.com".to_string(),
                duration: Duration::from_secs(60),
                ..Default::default()
            },
            room: "conference-room".to_string(),
            participant_count: 5,
        };

        let configs = create_conference_client_configs(&config);

        // Verify total count: exactly N participants (Requirement 4.1)
        assert_eq!(configs.len(), 5);

        // Verify all are Participants
        let participant_count = configs.iter()
            .filter(|c| c.role == ClientRole::Participant)
            .count();
        assert_eq!(participant_count, 5, "Should have exactly 5 participants");

        // Verify no Broadcasters or Viewers
        let broadcaster_count = configs.iter()
            .filter(|c| c.role == ClientRole::Broadcaster)
            .count();
        assert_eq!(broadcaster_count, 0, "Should have no broadcasters");

        let viewer_count = configs.iter()
            .filter(|c| c.role == ClientRole::Viewer)
            .count();
        assert_eq!(viewer_count, 0, "Should have no viewers");

        // Verify all clients have correct room and URL
        for config_item in &configs {
            assert_eq!(config_item.sfu_url, "wss://test.example.com");
            assert_eq!(config_item.room, "conference-room");
        }
    }

    /// Test conference config with zero participants
    #[test]
    fn test_conference_client_config_zero_participants() {
        fn create_conference_client_configs(config: &ConferenceConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(config.participant_count as usize);

            for _ in 0..config.participant_count {
                let participant_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Participant,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(participant_config);
            }

            client_configs
        }

        let config = ConferenceConfig {
            base: TestConfig::default(),
            room: "empty-conference".to_string(),
            participant_count: 0,
        };

        let configs = create_conference_client_configs(&config);

        // Should have no clients
        assert_eq!(configs.len(), 0);
    }

    /// Test conference config with large participant count
    #[test]
    fn test_conference_client_config_large_participant_count() {
        fn create_conference_client_configs(config: &ConferenceConfig) -> Vec<ClientConfig> {
            let mut client_configs = Vec::with_capacity(config.participant_count as usize);

            for _ in 0..config.participant_count {
                let participant_config = ClientConfig {
                    sfu_url: config.base.sfu_url.clone(),
                    room: config.room.clone(),
                    role: ClientRole::Participant,
                    connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                };
                client_configs.push(participant_config);
            }

            client_configs
        }

        let config = ConferenceConfig {
            base: TestConfig::default(),
            room: "large-conference".to_string(),
            participant_count: 100,
        };

        let configs = create_conference_client_configs(&config);

        // Verify exactly 100 participants
        assert_eq!(configs.len(), 100);

        let participant_count = configs.iter()
            .filter(|c| c.role == ClientRole::Participant)
            .count();
        assert_eq!(participant_count, 100);
    }

    /// Test that conference subscription count is correct
    /// Validates: Requirement 4.3 (each participant subscribes to N-1 others)
    #[test]
    fn test_conference_subscription_count() {
        // For N participants, each subscribes to (N-1) other participants
        // Each participant has 2 tracks (audio + video)
        // So total subscriptions = N * (N-1) * 2

        fn calculate_expected_subscriptions(participant_count: u32) -> u32 {
            if participant_count <= 1 {
                return 0;
            }
            // Each of N participants subscribes to (N-1) others' tracks
            // Each participant has 2 tracks (audio + video)
            participant_count * (participant_count - 1) * 2
        }

        // Test with 2 participants
        assert_eq!(calculate_expected_subscriptions(2), 4);
        // 2 participants, each subscribes to 1 other's 2 tracks = 2 * 1 * 2 = 4

        // Test with 3 participants
        assert_eq!(calculate_expected_subscriptions(3), 12);
        // 3 participants, each subscribes to 2 others' 2 tracks = 3 * 2 * 2 = 12

        // Test with 5 participants
        assert_eq!(calculate_expected_subscriptions(5), 40);
        // 5 participants, each subscribes to 4 others' 2 tracks = 5 * 4 * 2 = 40

        // Test with 10 participants
        assert_eq!(calculate_expected_subscriptions(10), 180);
        // 10 participants, each subscribes to 9 others' 2 tracks = 10 * 9 * 2 = 180

        // Edge cases
        assert_eq!(calculate_expected_subscriptions(0), 0);
        assert_eq!(calculate_expected_subscriptions(1), 0);
    }

    /// Test that stress config creates correct client configurations
    /// Validates: Requirements 5.1 (R rooms), 5.2 (P participants per room)
    #[test]
    fn test_stress_client_config_creation() {
        // Test helper to create client configs as run_stress does
        fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
            let mut room_configs = Vec::with_capacity(config.room_count as usize);

            // Requirement 5.1: Create the specified number of rooms
            for room_idx in 0..config.room_count {
                let room_name = format!("stress-room-{}", room_idx);
                let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

                // Requirement 5.2: Create P participants per room
                for _ in 0..config.participants_per_room {
                    let participant_config = ClientConfig {
                        sfu_url: config.base.sfu_url.clone(),
                        room: room_name.clone(),
                        role: ClientRole::Participant,
                        connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                    };
                    client_configs.push(participant_config);
                }

                room_configs.push((room_name, client_configs));
            }

            room_configs
        }

        // Test with 3 rooms and 5 participants per room
        let config = StressConfig {
            base: TestConfig {
                sfu_url: "wss://test.example.com".to_string(),
                duration: Duration::from_secs(60),
                ..Default::default()
            },
            room_count: 3,
            participants_per_room: 5,
        };

        let room_configs = create_stress_client_configs(&config);

        // Verify exactly R rooms (Requirement 5.1)
        assert_eq!(room_configs.len(), 3, "Should have exactly 3 rooms");

        // Verify each room has exactly P participants (Requirement 5.2)
        for (room_name, configs) in &room_configs {
            assert_eq!(
                configs.len(),
                5,
                "Room '{}' should have exactly 5 participants",
                room_name
            );

            // Verify all are Participants
            for config_item in configs {
                assert_eq!(config_item.role, ClientRole::Participant);
                assert_eq!(config_item.room, *room_name);
                assert_eq!(config_item.sfu_url, "wss://test.example.com");
            }
        }

        // Verify total participant count = R * P
        let total_participants: usize = room_configs.iter().map(|(_, c)| c.len()).sum();
        assert_eq!(total_participants, 15, "Total should be 3 * 5 = 15 participants");
    }

    /// Test stress config with zero rooms
    #[test]
    fn test_stress_client_config_zero_rooms() {
        fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
            let mut room_configs = Vec::with_capacity(config.room_count as usize);

            for room_idx in 0..config.room_count {
                let room_name = format!("stress-room-{}", room_idx);
                let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

                for _ in 0..config.participants_per_room {
                    let participant_config = ClientConfig {
                        sfu_url: config.base.sfu_url.clone(),
                        room: room_name.clone(),
                        role: ClientRole::Participant,
                        connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                    };
                    client_configs.push(participant_config);
                }

                room_configs.push((room_name, client_configs));
            }

            room_configs
        }

        let config = StressConfig {
            base: TestConfig::default(),
            room_count: 0,
            participants_per_room: 10,
        };

        let room_configs = create_stress_client_configs(&config);

        // Should have no rooms
        assert_eq!(room_configs.len(), 0);
    }

    /// Test stress config with zero participants per room
    #[test]
    fn test_stress_client_config_zero_participants() {
        fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
            let mut room_configs = Vec::with_capacity(config.room_count as usize);

            for room_idx in 0..config.room_count {
                let room_name = format!("stress-room-{}", room_idx);
                let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

                for _ in 0..config.participants_per_room {
                    let participant_config = ClientConfig {
                        sfu_url: config.base.sfu_url.clone(),
                        room: room_name.clone(),
                        role: ClientRole::Participant,
                        connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                    };
                    client_configs.push(participant_config);
                }

                room_configs.push((room_name, client_configs));
            }

            room_configs
        }

        let config = StressConfig {
            base: TestConfig::default(),
            room_count: 5,
            participants_per_room: 0,
        };

        let room_configs = create_stress_client_configs(&config);

        // Should have 5 rooms, each with 0 participants
        assert_eq!(room_configs.len(), 5);
        for (_, configs) in &room_configs {
            assert_eq!(configs.len(), 0);
        }
    }

    /// Test stress config with large room and participant counts
    #[test]
    fn test_stress_client_config_large_counts() {
        fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
            let mut room_configs = Vec::with_capacity(config.room_count as usize);

            for room_idx in 0..config.room_count {
                let room_name = format!("stress-room-{}", room_idx);
                let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

                for _ in 0..config.participants_per_room {
                    let participant_config = ClientConfig {
                        sfu_url: config.base.sfu_url.clone(),
                        room: room_name.clone(),
                        role: ClientRole::Participant,
                        connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                    };
                    client_configs.push(participant_config);
                }

                room_configs.push((room_name, client_configs));
            }

            room_configs
        }

        let config = StressConfig {
            base: TestConfig::default(),
            room_count: 10,
            participants_per_room: 100,
        };

        let room_configs = create_stress_client_configs(&config);

        // Verify 10 rooms with 100 participants each = 1000 total
        assert_eq!(room_configs.len(), 10);

        let total_participants: usize = room_configs.iter().map(|(_, c)| c.len()).sum();
        assert_eq!(total_participants, 1000);
    }

    /// Test that room names are unique
    #[test]
    fn test_stress_room_names_unique() {
        fn create_stress_client_configs(config: &StressConfig) -> Vec<(String, Vec<ClientConfig>)> {
            let mut room_configs = Vec::with_capacity(config.room_count as usize);

            for room_idx in 0..config.room_count {
                let room_name = format!("stress-room-{}", room_idx);
                let mut client_configs = Vec::with_capacity(config.participants_per_room as usize);

                for _ in 0..config.participants_per_room {
                    let participant_config = ClientConfig {
                        sfu_url: config.base.sfu_url.clone(),
                        room: room_name.clone(),
                        role: ClientRole::Participant,
                        connection_timeout: config.base.connection_timeout,
            ice_servers: Vec::new(),
                    };
                    client_configs.push(participant_config);
                }

                room_configs.push((room_name, client_configs));
            }

            room_configs
        }

        let config = StressConfig {
            base: TestConfig::default(),
            room_count: 5,
            participants_per_room: 2,
        };

        let room_configs = create_stress_client_configs(&config);

        // Collect all room names
        let room_names: Vec<&str> = room_configs.iter().map(|(name, _)| name.as_str()).collect();

        // Verify all room names are unique
        let mut unique_names = room_names.clone();
        unique_names.sort();
        unique_names.dedup();
        assert_eq!(
            room_names.len(),
            unique_names.len(),
            "All room names should be unique"
        );

        // Verify expected naming pattern
        assert!(room_names.contains(&"stress-room-0"));
        assert!(room_names.contains(&"stress-room-1"));
        assert!(room_names.contains(&"stress-room-2"));
        assert!(room_names.contains(&"stress-room-3"));
        assert!(room_names.contains(&"stress-room-4"));
    }

    /// Test aggregate_room_metrics with empty input
    #[test]
    fn test_aggregate_room_metrics_empty() {
        let room_runners: Vec<(String, TestRunner)> = vec![];
        let metrics = TestRunner::aggregate_room_metrics(&room_runners, 0);

        assert_eq!(metrics.total_clients, 0);
        assert_eq!(metrics.successful_clients, 0);
        assert_eq!(metrics.failed_clients, 0);
    }

    /// Test aggregate_room_metrics with failed rooms
    #[test]
    fn test_aggregate_room_metrics_with_failed_rooms() {
        let room_runners: Vec<(String, TestRunner)> = vec![];
        let metrics = TestRunner::aggregate_room_metrics(&room_runners, 3);

        // Failed rooms should be counted in failed_clients
        assert_eq!(metrics.failed_clients, 3);
    }

    /// Test aggregate_room_metrics combines metrics from multiple rooms
    #[test]
    fn test_aggregate_room_metrics_multiple_rooms() {
        // Create two test runners with some metrics
        let mut runner1 = TestRunner::with_defaults();
        runner1.metrics_collector_mut().register_client(0);
        runner1.metrics_collector_mut().mark_connected(0);
        runner1.metrics_collector_mut().record_latency(0, Duration::from_millis(10));
        runner1.metrics_collector_mut().record_packets(0, 100, 5);

        let mut runner2 = TestRunner::with_defaults();
        runner2.metrics_collector_mut().register_client(0);
        runner2.metrics_collector_mut().mark_connected(0);
        runner2.metrics_collector_mut().record_latency(0, Duration::from_millis(20));
        runner2.metrics_collector_mut().record_packets(0, 200, 10);

        let room_runners = vec![
            ("room-1".to_string(), runner1),
            ("room-2".to_string(), runner2),
        ];

        let metrics = TestRunner::aggregate_room_metrics(&room_runners, 0);

        // Should have 2 total clients (1 from each room)
        assert_eq!(metrics.total_clients, 2);
        assert_eq!(metrics.successful_clients, 2);
        assert_eq!(metrics.failed_clients, 0);

        // Latency should be aggregated (P50 of [10ms, 20ms])
        assert!(metrics.latency_p50 > Duration::ZERO);
    }
}
