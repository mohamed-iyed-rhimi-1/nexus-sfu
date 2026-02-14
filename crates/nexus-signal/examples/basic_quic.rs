use nexus_signal::{QuicConfig, QuicSignaling};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create QUIC configuration
    let config = QuicConfig {
        bind_addr: "127.0.0.1:5000".to_string(),
        max_connections: 1_000,
        max_session_tickets: 1_000,
        session_ticket_ttl_secs: 3600, // 1 hour
        max_bi_streams: 50,
        max_uni_streams: 50,
        stream_recv_window_bytes: 512 * 1024, // 512KB
        connection_recv_window_bytes: 4 * 1024 * 1024, // 4MB
        keep_alive_interval_ms: 15_000, // 15 seconds
        idle_timeout_ms: 30_000, // 30 seconds
        enable_0rtt: true,
        cert_path: "/tmp/cert.pem".to_string(),
        key_path: "/tmp/key.pem".to_string(),
    };

    // Create QUIC signaling server
    let bind_addr = "127.0.0.1:5000".parse()?;
    let server = Arc::new(QuicSignaling::new(bind_addr, config).await?);

    println!("QUIC signaling server listening on {}", bind_addr);
    println!("Press Ctrl+C to stop");

    // Run server
    server.run().await?;

    Ok(())
}
