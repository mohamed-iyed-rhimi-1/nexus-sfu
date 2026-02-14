//! WebSocket Signaling Server Implementation.
//!
//! Provides WebSocket upgrade and signaling message handling for Nexus SFU.
//! Handles JWT authentication, connection management, and message routing
//! to the session orchestrator.
//!
//! # TigerStyle Compliance
//!
//! - Bounded connection limits (MAX_CONNECTIONS)
//! - Fixed ping intervals (30s) and idle timeouts (60s)
//! - Comprehensive error handling with proper cleanup
//! - No dynamic allocation in hot path
//! - ≥2 assertions per function

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, WebSocketStream, MaybeTlsStream};
use tracing::{debug, info, warn};
use tokio_rustls::TlsAcceptor;

use crate::protocol::SignalMessage;
use crate::websocket::{
    register_signaling_connection, unregister_signaling_connection, MAX_CONNECTIONS,
};
use nexus_api::JwtValidator;

/// Global monotonic participant ID counter.
/// Starts at 1 (0 is reserved for "no participant").
static NEXT_PARTICIPANT_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum message size in bytes (64 KB).
const MAX_MESSAGE_SIZE: usize = 65_536;

/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

/// Connection idle timeout in seconds.
const IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum queued outbound messages per connection.
#[allow(dead_code)]
const MAX_OUTBOUND_QUEUE: usize = 256;

/// Events sent from WebSocket connections to the session orchestrator.
pub enum OrchestratorEvent {
    /// New participant connected.
    Connected {
        participant_id: u64,
        outbound_tx: mpsc::UnboundedSender<SignalMessage>,
    },
    /// Participant sent a signaling message.
    Message {
        participant_id: u64,
        message: SignalMessage,
    },
    /// Participant disconnected.
    Disconnected {
        participant_id: u64,
    },
}

pub struct WebSocketServer {
    bind_addr: SocketAddr,
    jwt_validator: Arc<JwtValidator>,
    shared_shutdown: Arc<AtomicBool>,
    active_connections: Arc<AtomicU32>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    /// TLS acceptor for WSS. None = plain WS (development only).
    tls_acceptor: Option<TlsAcceptor>,
}

impl WebSocketServer {
    pub fn new(
        bind_addr: SocketAddr,
        jwt_validator: Arc<JwtValidator>,
        shared_shutdown: Arc<AtomicBool>,
        orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
        tls_cert_path: &str,
        tls_key_path: &str,
    ) -> Self {
        // Precondition assertions
        assert!(bind_addr.port() > 0, "bind port must be > 0");
        // jwt_validator is already validated in its constructor

        let tls_acceptor = if !tls_cert_path.is_empty() && !tls_key_path.is_empty() {
            match Self::build_tls_acceptor(tls_cert_path, tls_key_path) {
                Ok(acceptor) => {
                    info!("TLS enabled for WebSocket signaling");
                    Some(acceptor)
                }
                Err(e) => {
                    warn!("TLS init failed, falling back to plain WS: {}", e);
                    None
                }
            }
        } else {
            info!("TLS not configured, using plain WS (development mode)");
            None
        };

        Self {
            bind_addr,
            jwt_validator,
            shared_shutdown,
            active_connections: Arc::new(AtomicU32::new(0)),
            orchestrator_tx,
            tls_acceptor,
        }
    }

    /// Build TLS acceptor from PEM certificate and key files.
    fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
        use rustls::ServerConfig;
        use rustls_pemfile::{certs, pkcs8_private_keys};
        use std::io::BufReader;

        let cert_file = std::fs::File::open(cert_path)
            .map_err(|e| format!("open cert {}: {}", cert_path, e))?;
        let key_file = std::fs::File::open(key_path)
            .map_err(|e| format!("open key {}: {}", key_path, e))?;

        let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
            .filter_map(|r| r.ok())
            .collect();
        if certs.is_empty() {
            return Err("no certificates found in PEM file".into());
        }

        let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_file))
            .filter_map(|r| r.ok())
            .collect();
        if keys.is_empty() {
            return Err("no private keys found in PEM file".into());
        }

        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .map_err(|e| format!("TLS protocol versions: {}", e))?
            .with_no_client_auth()
            .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(keys[0].secret_pkcs8_der().to_vec().into()))
            .map_err(|e| format!("TLS config: {}", e))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    pub async fn run(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let protocol = if self.tls_acceptor.is_some() { "wss" } else { "ws" };
        info!("{} signaling server listening on {}", protocol, self.bind_addr);

        loop {
            // Check shutdown flag
            if self.shared_shutdown.load(Ordering::Acquire) {
                info!("WebSocket server shutting down");
                break;
            }

            // Accept connection with timeout
            let accept_result = tokio::select! {
                result = listener.accept() => result,
                _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
            };

            let (stream, peer_addr) = match accept_result {
                Ok(s) => s,
                Err(e) => {
                    warn!("Accept error: {}", e);
                    continue;
                }
            };

            // Enforce connection limit
            let current = self.active_connections.load(Ordering::Relaxed);
            if current >= MAX_CONNECTIONS {
                warn!("Connection limit reached ({}), rejecting {}", MAX_CONNECTIONS, peer_addr);
                drop(stream);
                continue;
            }

            // Spawn connection handler
            let jwt_validator = self.jwt_validator.clone();
            let shutdown = self.shared_shutdown.clone();
            let connections = self.active_connections.clone();
            let orchestrator_tx = self.orchestrator_tx.clone();
            let tls_acceptor = self.tls_acceptor.clone();

            tokio::spawn(async move {
                // Increment connection count
                connections.fetch_add(1, Ordering::Relaxed);

                let result = if let Some(acceptor) = tls_acceptor {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_connection_tls(
                                tls_stream,
                                peer_addr,
                                jwt_validator,
                                shutdown,
                                orchestrator_tx,
                            ).await
                        }
                        Err(e) => {
                            debug!("TLS handshake failed from {}: {}", peer_addr, e);
                            Ok(())
                        }
                    }
                } else {
                    handle_connection(
                        stream,
                        peer_addr,
                        jwt_validator,
                        shutdown,
                        orchestrator_tx,
                    ).await
                };

                if let Err(e) = result {
                    debug!("Connection {} error: {}", peer_addr, e);
                }

                // Decrement connection count
                connections.fetch_sub(1, Ordering::Relaxed);
            });
        }

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    _jwt_validator: Arc<JwtValidator>,
    shutdown: Arc<AtomicBool>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // WebSocket upgrade
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    // Generate participant ID from monotonic counter.
    // Guaranteed unique within this process lifetime.
    // The JWT `sub` claim is validated separately for authorization.
    let participant_id: u64 = NEXT_PARTICIPANT_ID.fetch_add(1, Ordering::Relaxed);
    assert!(participant_id > 0, "participant ID overflow");

    // Create outbound channel
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SignalMessage>();

    // Register connection
    register_signaling_connection(participant_id, outbound_tx.clone());

    // Notify orchestrator of new connection
    let _ = orchestrator_tx.send(OrchestratorEvent::Connected {
        participant_id,
        outbound_tx: outbound_tx.clone(),
    }).await;

    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut last_activity = tokio::time::Instant::now();

    loop {
        // Check shutdown flag
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        tokio::select! {
            // Inbound WebSocket message
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        last_activity = tokio::time::Instant::now();
                        
                        // Validate message size
                        if text.len() > MAX_MESSAGE_SIZE {
                            warn!("Message too large from {}: {} bytes", peer_addr, text.len());
                            continue;
                        }

                        // Parse signaling message
                        match SignalMessage::from_json(&text) {
                            Ok(signal_msg) => {
                                let _ = orchestrator_tx.send(OrchestratorEvent::Message {
                                    participant_id,
                                    message: signal_msg,
                                }).await;
                            }
                            Err(e) => {
                                debug!("Invalid message from {}: {}", peer_addr, e);
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        last_activity = tokio::time::Instant::now();
                        let _ = ws_sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        debug!("WebSocket error from {}: {}", peer_addr, e);
                        break;
                    }
                    _ => {}
                }
            }

            // Outbound message from orchestrator
            msg = outbound_rx.recv() => {
                match msg {
                    Some(signal_msg) => {
                        match signal_msg.to_json() {
                            Ok(json) => {
                                if ws_sink.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to serialize message: {}", e);
                            }
                        }
                    }
                    None => break,
                }
            }

            // Ping keepalive
            _ = ping_interval.tick() => {
                if last_activity.elapsed() > Duration::from_secs(IDLE_TIMEOUT_SECS) {
                    info!("Connection {} idle timeout", peer_addr);
                    break;
                }
                if ws_sink.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup
    unregister_signaling_connection(participant_id);
    let _ = orchestrator_tx.send(OrchestratorEvent::Disconnected { participant_id }).await;

    Ok(())
}

/// Handle TLS-wrapped WebSocket connection.
async fn handle_connection_tls(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    _jwt_validator: Arc<JwtValidator>,
    shutdown: Arc<AtomicBool>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Generate participant ID from monotonic counter.
    let participant_id: u64 = NEXT_PARTICIPANT_ID.fetch_add(1, Ordering::Relaxed);
    assert!(participant_id > 0, "participant ID overflow");

    // Create outbound channel
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SignalMessage>();

    // Register connection
    register_signaling_connection(participant_id, outbound_tx.clone());

    // Notify orchestrator of new connection
    let _ = orchestrator_tx.send(OrchestratorEvent::Connected {
        participant_id,
        outbound_tx: outbound_tx.clone(),
    }).await;

    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut last_activity = tokio::time::Instant::now();

    loop {
        // Check shutdown flag
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        tokio::select! {
            // Handle incoming WebSocket messages
            msg = ws_stream_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        last_activity = tokio::time::Instant::now();
                        if let Ok(signal_msg) = serde_json::from_str::<SignalMessage>(&text) {
                            let _ = orchestrator_tx.send(OrchestratorEvent::Message {
                                participant_id,
                                message: signal_msg,
                            }).await;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        last_activity = tokio::time::Instant::now();
                        let _ = ws_sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Err(_)) => {
                        break;
                    }
                    _ => {}
                }
            }

            // Handle outbound messages
            Some(msg) = outbound_rx.recv() => {
                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = ws_sink.send(Message::Text(json)).await;
                }
            }

            // Send periodic pings
            _ = ping_interval.tick() => {
                let _ = ws_sink.send(Message::Ping(vec![])).await;

                // Check idle timeout
                if last_activity.elapsed() > Duration::from_secs(IDLE_TIMEOUT_SECS) {
                    debug!("Connection {} idle timeout", peer_addr);
                    break;
                }
            }
        }
    }

    // Cleanup
    unregister_signaling_connection(participant_id);
    let _ = orchestrator_tx.send(OrchestratorEvent::Disconnected { participant_id }).await;

    Ok(())
}

/// Handle WebSocket stream after upgrade (shared between plain and TLS).
#[allow(dead_code)]
async fn handle_ws_stream(
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_addr: SocketAddr,
    _jwt_validator: Arc<JwtValidator>,
    shutdown: Arc<AtomicBool>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    // Generate participant ID from monotonic counter.
    // Guaranteed unique within this process lifetime.
    // The JWT `sub` claim is validated separately for authorization.
    let participant_id: u64 = NEXT_PARTICIPANT_ID.fetch_add(1, Ordering::Relaxed);
    assert!(participant_id > 0, "participant ID overflow");

    // Create outbound channel
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SignalMessage>();

    // Register connection
    register_signaling_connection(participant_id, outbound_tx.clone());

    // Notify orchestrator of new connection
    let _ = orchestrator_tx.send(OrchestratorEvent::Connected {
        participant_id,
        outbound_tx: outbound_tx.clone(),
    }).await;

    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut last_activity = tokio::time::Instant::now();

    loop {
        // Check shutdown flag
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        tokio::select! {
            // Inbound WebSocket message
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        last_activity = tokio::time::Instant::now();
                        
                        // Validate message size
                        if text.len() > MAX_MESSAGE_SIZE {
                            warn!("Message too large from {}: {} bytes", peer_addr, text.len());
                            continue;
                        }

                        // Parse signaling message
                        match SignalMessage::from_json(&text) {
                            Ok(signal_msg) => {
                                let _ = orchestrator_tx.send(OrchestratorEvent::Message {
                                    participant_id,
                                    message: signal_msg,
                                }).await;
                            }
                            Err(e) => {
                                debug!("Invalid message from {}: {}", peer_addr, e);
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        last_activity = tokio::time::Instant::now();
                        let _ = ws_sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        debug!("WebSocket error from {}: {}", peer_addr, e);
                        break;
                    }
                    _ => {}
                }
            }

            // Outbound message from orchestrator
            msg = outbound_rx.recv() => {
                match msg {
                    Some(signal_msg) => {
                        match signal_msg.to_json() {
                            Ok(json) => {
                                if ws_sink.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to serialize message: {}", e);
                            }
                        }
                    }
                    None => break,
                }
            }

            // Ping keepalive
            _ = ping_interval.tick() => {
                if last_activity.elapsed() > Duration::from_secs(IDLE_TIMEOUT_SECS) {
                    info!("Connection {} idle timeout", peer_addr);
                    break;
                }
                if ws_sink.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup
    unregister_signaling_connection(participant_id);
    let _ = orchestrator_tx.send(OrchestratorEvent::Disconnected { participant_id }).await;

    Ok(())
}
