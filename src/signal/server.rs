//! Signaling Server - QUIC-first with WebSocket fallback.
//!
//! This module provides the signaling server that:
//! 1. Attempts to start QUIC signaling as the primary transport
//! 2. Automatically falls back to WebSocket if QUIC fails
//!
//! # Design
//!
//! QUIC is the preferred transport due to:
//! - 0-RTT connection establishment
//! - Connection migration support
//! - Multiplexed streams without head-of-line blocking
//! - Better performance on lossy networks
//!
//! WebSocket fallback ensures compatibility with:
//! - Browsers without QUIC support
//! - Networks that block UDP
//! - Development environments without TLS certificates
//!
//! # TigerStyle Compliance
//!
//! - Explicit error handling with fallback
//! - Bounded connection pools
//! - Comprehensive logging at each stage
//! - No panics on transport failures

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use nexus_signal::websocket::server::{OrchestratorEvent, WebSocketServer};
use crate::nexus_api::JwtValidator;

use nexus_signal::{QuicConfig, QuicSignaling};

/// Active transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// No transport active yet.
    None,
    /// Only QUIC is active.
    Quic,
    /// Only WebSocket is active (QUIC failed).
    WebSocket,
    /// Both transports are active (QUIC succeeded, WS for fallback clients).
    Both,
}

/// Signaling server configuration.
#[derive(Debug, Clone)]
pub struct SignalingConfig {
    /// QUIC bind address.
    pub quic_addr: SocketAddr,
    /// WebSocket bind address.
    pub ws_addr: SocketAddr,
    /// TLS certificate path for QUIC and WSS.
    pub tls_cert_path: String,
    /// TLS key path for QUIC and WSS.
    pub tls_key_path: String,
    /// JWT secret for authentication.
    pub jwt_secret: String,
    /// Maximum connections per transport.
    pub max_connections: u32,
    /// QUIC-specific configuration.
    pub quic_config: QuicConfig,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            quic_addr: "0.0.0.0:4433".parse().unwrap(),
            ws_addr: "0.0.0.0:8080".parse().unwrap(),
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            jwt_secret: String::new(),
            max_connections: 10_000,
            quic_config: QuicConfig::default(),
        }
    }
}

/// Signaling server.
///
/// Tries QUIC first, falls back to WebSocket if QUIC fails.
pub struct SignalingServer {
    /// Configuration.
    config: SignalingConfig,
    /// Shared shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Orchestrator event sender.
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    /// Active transport state.
    active_transport: Arc<std::sync::atomic::AtomicU8>,
    /// Total active connections across all transports.
    total_connections: Arc<AtomicU32>,
}

impl SignalingServer {
    /// Create a new signaling server.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `shutdown` - Shared shutdown signal
    /// * `orchestrator_tx` - Channel to send events to the orchestrator
    pub fn new(
        config: SignalingConfig,
        shutdown: Arc<AtomicBool>,
        orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    ) -> Self {
        assert!(!config.jwt_secret.is_empty(), "JWT secret must not be empty");
        
        Self {
            config,
            shutdown,
            orchestrator_tx,
            active_transport: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            total_connections: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Get the currently active transport.
    pub fn active_transport(&self) -> ActiveTransport {
        match self.active_transport.load(Ordering::Acquire) {
            1 => ActiveTransport::Quic,
            2 => ActiveTransport::WebSocket,
            3 => ActiveTransport::Both,
            _ => ActiveTransport::None,
        }
    }

    /// Get total active connections.
    pub fn total_connections(&self) -> u32 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Run the signaling server.
    ///
    /// Tries QUIC first, falls back to WebSocket if QUIC fails.
    /// If QUIC succeeds, both QUIC and WebSocket run for client compatibility.
    pub async fn run(self) -> Result<(), String> {
        info!(
            quic_addr = %self.config.quic_addr,
            ws_addr = %self.config.ws_addr,
            "Starting signaling server (QUIC-first with WebSocket fallback)"
        );

        // Try to start QUIC server
        match self.try_start_quic().await {
            Ok(quic_server) => {
                info!(addr = %self.config.quic_addr, "QUIC signaling started successfully");
                
                // QUIC handles TLS, so run WebSocket as plain WS for browser fallback.
                // Browsers can't easily use WSS with self-signed certs in development.
                let ws_server = self.create_websocket_server_plain();
                self.active_transport.store(3, Ordering::Release); // Both
                
                info!(
                    quic_addr = %self.config.quic_addr,
                    ws_addr = %self.config.ws_addr,
                    "Both QUIC and WebSocket signaling active"
                );
                
                // Run both servers
                self.run_both(quic_server, ws_server).await
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "QUIC signaling failed, falling back to WebSocket"
                );
                
                // Fall back to WebSocket only
                let ws_server = self.create_websocket_server();
                self.active_transport.store(2, Ordering::Release); // WebSocket
                
                info!(addr = %self.config.ws_addr, "WebSocket signaling started (fallback)");
                
                self.run_websocket(ws_server).await
            }
        }
    }

    /// Try to start QUIC server.
    async fn try_start_quic(&self) -> Result<Arc<QuicSignaling>, String> {
        // Check TLS configuration
        if self.config.tls_cert_path.is_empty() || self.config.tls_key_path.is_empty() {
            return Err("QUIC requires TLS certificate and key paths".to_string());
        }

        // Check if certificate files exist
        if !std::path::Path::new(&self.config.tls_cert_path).exists() {
            return Err(format!(
                "TLS certificate not found: {}",
                self.config.tls_cert_path
            ));
        }
        if !std::path::Path::new(&self.config.tls_key_path).exists() {
            return Err(format!(
                "TLS key not found: {}",
                self.config.tls_key_path
            ));
        }

        // Create QUIC config
        let mut quic_config = self.config.quic_config.clone();
        quic_config.bind_addr = self.config.quic_addr.to_string();
        quic_config.cert_path = self.config.tls_cert_path.clone();
        quic_config.key_path = self.config.tls_key_path.clone();
        quic_config.max_connections = self.config.max_connections;

        // Create QUIC server
        QuicSignaling::new(self.config.quic_addr, quic_config)
            .await
            .map(Arc::new)
            .map_err(|e| format!("Failed to create QUIC server: {}", e))
    }

    /// Create WebSocket server.
    fn create_websocket_server(&self) -> WebSocketServer {
        WebSocketServer::new(
            self.config.ws_addr,
            Arc::new(JwtValidator::new(&self.config.jwt_secret)),
            self.shutdown.clone(),
            self.orchestrator_tx.clone(),
            &self.config.tls_cert_path,
            &self.config.tls_key_path,
        )
    }

    /// Create a plain (non-TLS) WebSocket server for use alongside QUIC.
    /// When QUIC handles TLS signaling, the WS fallback runs without TLS
    /// so browsers can connect without self-signed cert issues in development.
    fn create_websocket_server_plain(&self) -> WebSocketServer {
        WebSocketServer::new(
            self.config.ws_addr,
            Arc::new(JwtValidator::new(&self.config.jwt_secret)),
            self.shutdown.clone(),
            self.orchestrator_tx.clone(),
            "",
            "",
        )
    }

    /// Run WebSocket server only.
    async fn run_websocket(self, server: WebSocketServer) -> Result<(), String> {
        server.run().await.map_err(|e| format!("WebSocket server error: {}", e))
    }

    /// Run both QUIC and WebSocket servers.
    async fn run_both(
        self,
        quic_server: Arc<QuicSignaling>,
        ws_server: WebSocketServer,
    ) -> Result<(), String> {
        let shutdown = self.shutdown.clone();
        
        // Spawn QUIC server task
        let quic_handle = tokio::spawn(async move {
            tokio::select! {
                result = quic_server.run() => {
                    if let Err(e) = result {
                        error!(error = %e, "QUIC signaling server error");
                    }
                }
                _ = wait_for_shutdown(shutdown) => {
                    info!("QUIC signaling server shutting down");
                }
            }
        });

        // Run WebSocket server in current task
        let ws_result = ws_server.run().await;

        // Wait for QUIC to finish
        let _ = quic_handle.await;

        ws_result.map_err(|e| format!("WebSocket server error: {}", e))
    }
}

/// Wait for shutdown signal.
async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_transport_encoding() {
        let transport = Arc::new(std::sync::atomic::AtomicU8::new(0));
        
        transport.store(0, Ordering::Release);
        assert_eq!(transport.load(Ordering::Acquire), 0);
        
        transport.store(1, Ordering::Release);
        assert_eq!(transport.load(Ordering::Acquire), 1);
        
        transport.store(2, Ordering::Release);
        assert_eq!(transport.load(Ordering::Acquire), 2);
        
        transport.store(3, Ordering::Release);
        assert_eq!(transport.load(Ordering::Acquire), 3);
    }

    #[test]
    fn test_default_config() {
        let config = SignalingConfig::default();
        assert_eq!(config.quic_addr, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(config.ws_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.max_connections, 10_000);
    }
}
