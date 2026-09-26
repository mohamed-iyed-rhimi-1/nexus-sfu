//! Signaling server: WebSocket (WSS when TLS is configured).
//!
//! WebSocket + JSON is the only signaling transport the SDK and loadtest
//! use. The QUIC module in `nexus-signal` is not started: it only echoes
//! offers and is not connected to the orchestrator
//! (`docs/dataplane-design.md` §3.10). `[quic]` config is kept but unused.
//!
//! # TigerStyle Compliance
//!
//! - Explicit error handling: TLS or bind failure stops startup
//! - Bounded connection pools

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::info;

use crate::nexus_api::JwtValidator;
use nexus_signal::websocket::server::{OrchestratorEvent, WebSocketServer};
use nexus_signal::SignalingConnections;

/// Signaling server configuration.
#[derive(Debug, Clone)]
pub struct SignalingConfig {
    /// WebSocket bind address (port 0 picks a free port).
    pub ws_addr: SocketAddr,
    /// TLS certificate path for WSS (PEM). Empty = plain WS.
    pub tls_cert_path: String,
    /// TLS key path for WSS (PEM). Empty = plain WS.
    pub tls_key_path: String,
    /// JWT secret for authentication.
    pub jwt_secret: String,
    /// Maximum connections.
    pub max_connections: u32,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            ws_addr: "0.0.0.0:8080".parse().unwrap(),
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            jwt_secret: String::new(),
            max_connections: 10_000,
        }
    }
}

/// Signaling server.
pub struct SignalingServer {
    /// WebSocket server, built (and bound) up front so a TLS or bind
    /// failure stops startup.
    ws_server: WebSocketServer,
}

impl SignalingServer {
    /// Create the signaling server and bind its listener.
    ///
    /// # Errors
    ///
    /// Fails if TLS paths are configured but the certificate or key cannot
    /// be loaded, if only one of the two paths is set, or if the address
    /// cannot be bound.
    pub fn new(
        config: SignalingConfig,
        shutdown: Arc<AtomicBool>,
        orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    ) -> Result<Self, String> {
        assert!(
            !config.jwt_secret.is_empty(),
            "JWT secret must not be empty"
        );

        let ws_server = WebSocketServer::new(
            config.ws_addr,
            Arc::new(JwtValidator::new(&config.jwt_secret)),
            shutdown,
            orchestrator_tx,
            &config.tls_cert_path,
            &config.tls_key_path,
        )?;
        assert!(ws_server.local_addr().port() != 0);

        Ok(Self { ws_server })
    }

    /// Address the WebSocket listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.ws_server.local_addr()
    }

    /// Live connections, for shutdown notifications.
    pub fn connections(&self) -> SignalingConnections {
        self.ws_server.connections()
    }

    /// Run until the shared shutdown flag is set.
    pub async fn run(self) -> Result<(), String> {
        info!(addr = %self.local_addr(), "Starting WebSocket signaling");
        self.ws_server
            .run()
            .await
            .map_err(|e| format!("WebSocket server error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SignalingConfig::default();
        assert_eq!(config.ws_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.max_connections, 10_000);
    }
}
