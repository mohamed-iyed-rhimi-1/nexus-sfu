use nexus_signal::WebSocketServer;
use nexus_signal::websocket::OrchestratorEvent;
use nexus_api::JwtValidator;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create WebSocket server
    let bind_addr = "127.0.0.1:8080".parse()?;
    let jwt_secret = "this-is-a-test-secret-with-32-chars!";
    let jwt_validator = Arc::new(JwtValidator::new(jwt_secret));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (orchestrator_tx, mut _orchestrator_rx) = tokio::sync::mpsc::channel::<OrchestratorEvent>(4096);

    let server = WebSocketServer::new(
        bind_addr,
        jwt_validator,
        shutdown,
        orchestrator_tx,
        "",
        "",
    );

    println!("WebSocket server listening on {}", bind_addr);
    println!("Press Ctrl+C to stop");

    // Run server
    server.run().await?;

    Ok(())
}
