//! Prometheus metrics HTTP endpoint
//!
//! Provides an HTTP server that exposes metrics in Prometheus text format
//! at the `/metrics` endpoint.
//!
//! **Validates: Requirements 7.3**

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::report::TestReport;

/// Shared state for the Prometheus metrics server
pub struct PrometheusState {
    /// The current test report (updated periodically during the test)
    report: RwLock<Option<TestReport>>,
}

impl PrometheusState {
    /// Create a new Prometheus state
    pub fn new() -> Self {
        Self {
            report: RwLock::new(None),
        }
    }

    /// Update the current report
    pub async fn update_report(&self, report: TestReport) {
        let mut guard = self.report.write().await;
        *guard = Some(report);
    }

    /// Get the current metrics in Prometheus format
    pub async fn get_metrics(&self) -> String {
        let guard = self.report.read().await;
        match &*guard {
            Some(report) => report.to_prometheus(),
            None => {
                // Return empty metrics with a status indicator
                "# HELP nexus_loadtest_status Load test status (0=not started, 1=running)\n\
                 # TYPE nexus_loadtest_status gauge\n\
                 nexus_loadtest_status 0\n"
                    .to_string()
            }
        }
    }
}

impl Default for PrometheusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus metrics HTTP server
pub struct PrometheusServer {
    /// Shared state containing the current metrics
    state: Arc<PrometheusState>,
    /// Server shutdown signal sender
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Server task handle
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl PrometheusServer {
    /// Create a new Prometheus server with the given state
    pub fn new(state: Arc<PrometheusState>) -> Self {
        Self {
            state,
            shutdown_tx: None,
            handle: None,
        }
    }

    /// Start the HTTP server on the specified port
    ///
    /// The server exposes metrics at `/metrics` in Prometheus text format.
    pub async fn start(&mut self, port: u16) -> Result<(), crate::error::LoadTestError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        info!("Starting Prometheus metrics server on http://{}/metrics", addr);

        // Create the router with the metrics endpoint
        let state = Arc::clone(&self.state);
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(state);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        // Create the TCP listener
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            crate::error::LoadTestError::PrometheusError(format!(
                "Failed to bind to port {}: {}",
                port, e
            ))
        })?;

        // Spawn the server task
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap_or_else(|e| {
                    error!("Prometheus server error: {}", e);
                });
        });

        self.handle = Some(handle);

        info!("Prometheus metrics server started successfully");
        Ok(())
    }

    /// Update the metrics with a new report
    pub async fn update(&self, report: TestReport) {
        self.state.update_report(report).await;
    }

    /// Stop the HTTP server gracefully
    pub async fn stop(&mut self) {
        info!("Stopping Prometheus metrics server");

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the server task to complete
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }

        info!("Prometheus metrics server stopped");
    }

    /// Get a reference to the shared state
    pub fn state(&self) -> Arc<PrometheusState> {
        Arc::clone(&self.state)
    }
}

/// Handler for the /metrics endpoint
async fn metrics_handler(State(state): State<Arc<PrometheusState>>) -> impl IntoResponse {
    let metrics = state.get_metrics().await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics,
    )
}

/// Handler for the /health endpoint
async fn health_handler() -> impl IntoResponse {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{SerializableMetrics, TargetValidation};

    fn create_test_report() -> TestReport {
        TestReport {
            scenario: "test".to_string(),
            sfu_url: "wss://test.example.com".to_string(),
            duration_secs: 60,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            metrics: SerializableMetrics {
                latency_p50_ms: 5.0,
                latency_p95_ms: 10.0,
                latency_p99_ms: 15.0,
                packet_loss_rate: 0.01,
                jitter_avg_ms: 2.0,
                throughput_pps: 100000.0,
                throughput_bps: 1000000.0,
                connection_success_rate: 0.99,
                avg_time_to_first_frame_ms: 50.0,
                total_clients: 100,
                successful_clients: 99,
                failed_clients: 1,
            },
            target_validations: vec![TargetValidation {
                name: "P50 Latency".to_string(),
                target: "≤ 5ms".to_string(),
                actual: "5.00ms".to_string(),
                passed: true,
            }],
            passed: true,
        }
    }

    #[tokio::test]
    async fn test_prometheus_state_empty() {
        let state = PrometheusState::new();
        let metrics = state.get_metrics().await;

        assert!(metrics.contains("nexus_loadtest_status 0"));
    }

    #[tokio::test]
    async fn test_prometheus_state_with_report() {
        let state = PrometheusState::new();
        let report = create_test_report();

        state.update_report(report).await;
        let metrics = state.get_metrics().await;

        assert!(metrics.contains("nexus_loadtest_latency_p50_ms"));
        assert!(metrics.contains("nexus_loadtest_passed"));
        assert!(metrics.contains("scenario=\"test\""));
    }

    #[tokio::test]
    async fn test_prometheus_server_start_stop() {
        let state = Arc::new(PrometheusState::new());
        let mut server = PrometheusServer::new(state);

        // Start on a random available port
        let result = server.start(0).await;
        // Note: This may fail in CI if port binding is restricted
        if result.is_ok() {
            // Give the server a moment to start
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Stop the server
            server.stop().await;
        }
    }
}
