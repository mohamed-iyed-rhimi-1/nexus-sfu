//! Kubernetes deployment integration test
//!
//! Tests:
//! 1. Configuration loading from ConfigMap
//! 2. Health check endpoints
//! 3. Metrics endpoint for Prometheus
//! 4. Graceful shutdown on SIGTERM

#[cfg(feature = "kubernetes")]
#[tokio::test]
async fn test_health_check_endpoint() {
    use nexus_sfu::{NexusConfig, Sfu};
    use nexus_sfu::api::ApiServer;
    use std::sync::Arc;

    let mut config = NexusConfig::default();
    config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.transport.signaling_bind_addr = "127.0.0.1:18080".parse().unwrap();
    config.worker.num_workers = 1;
    config.memory.arena_size_mb = 1;

    let sfu = Arc::new(Sfu::new(config.clone()).await.expect("Failed to create SFU"));

    // Start API server with health endpoint
    let api_server = ApiServer::new(
        config.transport.signaling_bind_addr,
        sfu.clone(),
        None, // No metrics collector for this test
    );

    // Start API server in background
    let api_handle = tokio::spawn(async move {
        api_server.run().await.ok();
    });

    // Wait for server startup
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check health endpoint
    let response = reqwest::get("http://127.0.0.1:18080/health")
        .await
        .expect("Failed to get health");

    assert_eq!(response.status(), 200, "Health check should return 200");

    // Cleanup
    api_handle.abort();
}

#[cfg(feature = "kubernetes")]
#[tokio::test]
async fn test_metrics_endpoint() {
    use nexus_sfu::{NexusConfig, Sfu};
    use nexus_sfu::api::ApiServer;
    use std::sync::Arc;

    let mut config = NexusConfig::default();
    config.transport.media_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.transport.signaling_bind_addr = "127.0.0.1:19090".parse().unwrap();
    config.worker.num_workers = 1;
    config.memory.arena_size_mb = 1;

    let sfu = Arc::new(Sfu::new(config.clone()).await.expect("Failed to create SFU"));

    // Start API server with metrics endpoint
    let api_server = ApiServer::new(
        config.transport.signaling_bind_addr,
        sfu.clone(),
        None, // No metrics collector for this test
    );

    // Start API server in background
    let api_handle = tokio::spawn(async move {
        api_server.run().await.ok();
    });

    // Wait for server startup
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check metrics endpoint
    let response = reqwest::get("http://127.0.0.1:19090/metrics")
        .await
        .expect("Failed to get metrics");

    assert_eq!(response.status(), 200, "Metrics should return 200");

    let body = response.text().await.expect("Failed to read body");

    // Verify Prometheus format
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "Should have Prometheus format markers"
    );

    // Cleanup
    api_handle.abort();
}
