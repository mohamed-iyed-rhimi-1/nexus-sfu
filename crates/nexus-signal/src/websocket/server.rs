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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async_with_config, WebSocketStream};
use tracing::{debug, info, warn};

use crate::protocol::SignalMessage;
use crate::websocket::{
    new_signaling_connections, register_signaling_connection, unregister_signaling_connection,
    SignalingConnections, MAX_CONNECTIONS,
};
use nexus_api::JwtValidator;

/// Global monotonic participant ID counter.
/// Starts at 1 (0 is reserved for "no participant").
static NEXT_PARTICIPANT_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum signaling message size in bytes (256 KB). An offer or answer with 32
/// m-lines (the SDP limit, `MAX_SDP_SIZE` = 128 KB) plus its JSON envelope fits.
/// A larger text message is dropped and answered with `Error { MESSAGE_TOO_LARGE }`.
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// Largest message or frame the WebSocket layer buffers (1 MB). Without it tungstenite
/// buffers up to 64 MB before `MAX_MESSAGE_SIZE` is checked; above it the connection is
/// closed with a protocol error.
const MAX_WS_BUFFERED_MESSAGE: usize = 1024 * 1024;

const _: () = assert!(MAX_MESSAGE_SIZE < MAX_WS_BUFFERED_MESSAGE);

/// WebSocket settings for every accepted connection.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_WS_BUFFERED_MESSAGE),
        max_frame_size: Some(MAX_WS_BUFFERED_MESSAGE),
        ..WebSocketConfig::default()
    }
}

/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

/// Connection idle timeout in seconds.
const IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum queued outbound messages per connection.
const MAX_OUTBOUND_QUEUE: usize = 256;

/// Timeout for the first authentication message.
const AUTH_TIMEOUT_SECS: u64 = 10;

/// Events sent from WebSocket connections to the session orchestrator.
pub enum OrchestratorEvent {
    /// New participant connected.
    Connected {
        participant_id: u64,
        outbound_tx: mpsc::Sender<SignalMessage>,
        /// JWT claims from the authenticated participant; their `rooms` claim
        /// bounds the rooms it may create or join.
        claims: nexus_api::auth::Claims,
    },
    /// Participant sent a signaling message.
    Message {
        participant_id: u64,
        message: SignalMessage,
    },
    /// Participant disconnected.
    Disconnected { participant_id: u64 },
}

pub struct WebSocketServer {
    /// Listener bound in `new`, so the address (and a port-0 port) is known
    /// before `run` and a bind failure stops startup.
    listener: std::net::TcpListener,
    local_addr: SocketAddr,
    connections: SignalingConnections,
    jwt_validator: Arc<JwtValidator>,
    shared_shutdown: Arc<AtomicBool>,
    active_connections: Arc<AtomicU32>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    /// TLS acceptor for WSS. None = plain WS (development only).
    tls_acceptor: Option<TlsAcceptor>,
}

impl WebSocketServer {
    /// Create the server.
    ///
    /// TLS is all or nothing: with both paths empty the server speaks plain
    /// WS (development only); with both set, a certificate that fails to
    /// load is an error, never a silent downgrade to plain WS.
    pub fn new(
        bind_addr: SocketAddr,
        jwt_validator: Arc<JwtValidator>,
        shared_shutdown: Arc<AtomicBool>,
        orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
        tls_cert_path: &str,
        tls_key_path: &str,
    ) -> Result<Self, String> {
        let tls_acceptor = match (tls_cert_path.is_empty(), tls_key_path.is_empty()) {
            (true, true) => {
                warn!("TLS not configured: WebSocket signaling is UNENCRYPTED (development only)");
                None
            }
            (false, false) => {
                let acceptor = Self::build_tls_acceptor(tls_cert_path, tls_key_path)
                    .map_err(|e| format!("WebSocket TLS init failed: {}", e))?;
                info!("TLS enabled for WebSocket signaling");
                Some(acceptor)
            }
            _ => {
                return Err(
                    "tls_cert_path and tls_key_path must both be set or both be empty".to_string(),
                )
            }
        };

        let listener = std::net::TcpListener::bind(bind_addr)
            .map_err(|e| format!("WebSocket bind {}: {}", bind_addr, e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("WebSocket listener nonblocking: {}", e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| format!("WebSocket local address: {}", e))?;
        assert!(local_addr.port() != 0, "bound port is known");

        Ok(Self {
            listener,
            local_addr,
            connections: new_signaling_connections(),
            jwt_validator,
            shared_shutdown,
            active_connections: Arc::new(AtomicU32::new(0)),
            orchestrator_tx,
            tls_acceptor,
        })
    }

    /// Address the listener is bound to (the real port when 0 was requested).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// This server's live connections (for shutdown notifications).
    pub fn connections(&self) -> SignalingConnections {
        Arc::clone(&self.connections)
    }

    /// Build TLS acceptor from PEM certificate and key files.
    fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
        use rustls::ServerConfig;
        use rustls_pemfile::{certs, pkcs8_private_keys};
        use std::io::BufReader;

        let cert_file = std::fs::File::open(cert_path)
            .map_err(|e| format!("open cert {}: {}", cert_path, e))?;
        let key_file =
            std::fs::File::open(key_path).map_err(|e| format!("open key {}: {}", key_path, e))?;

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

        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::ALL_VERSIONS)
                .map_err(|e| format!("TLS protocol versions: {}", e))?
                .with_no_client_auth()
                .with_single_cert(
                    certs,
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        keys[0].secret_pkcs8_der().to_vec().into(),
                    ),
                )
                .map_err(|e| format!("TLS config: {}", e))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    pub async fn run(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::from_std(self.listener.try_clone()?)?;
        let protocol = if self.tls_acceptor.is_some() {
            "wss"
        } else {
            "ws"
        };
        info!(
            "{} signaling server listening on {}",
            protocol, self.local_addr
        );

        let shutdown = self.shared_shutdown.clone();
        let shutdown_notify = async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
            }
        };
        tokio::pin!(shutdown_notify);

        loop {
            // Accept connection or shutdown
            let accept_result = tokio::select! {
                result = listener.accept() => result,
                _ = &mut shutdown_notify => {
                    info!("WebSocket server shutting down");
                    return Ok(());
                },
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
                warn!(
                    "Connection limit reached ({}), rejecting {}",
                    MAX_CONNECTIONS, peer_addr
                );
                drop(stream);
                continue;
            }

            // Spawn connection handler
            let jwt_validator = self.jwt_validator.clone();
            let shutdown = self.shared_shutdown.clone();
            let connections = self.active_connections.clone();
            let orchestrator_tx = self.orchestrator_tx.clone();
            let tls_acceptor = self.tls_acceptor.clone();
            let registry = self.connections();

            tokio::spawn(async move {
                connections.fetch_add(1, Ordering::Relaxed);

                let result = match upgrade_and_handle(
                    stream,
                    peer_addr,
                    tls_acceptor,
                    jwt_validator,
                    shutdown,
                    orchestrator_tx,
                    registry,
                )
                .await
                {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        debug!("Connection {} error: {}", peer_addr, e);
                        Err(e)
                    }
                };

                connections.fetch_sub(1, Ordering::Relaxed);
                result
            });
        }
    }
}

/// Perform TLS accept (if needed), WebSocket upgrade, then hand off to the unified handler.
async fn upgrade_and_handle(
    stream: TcpStream,
    peer_addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    jwt_validator: Arc<JwtValidator>,
    shutdown: Arc<AtomicBool>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    connections: SignalingConnections,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("TLS handshake failed from {}: {}", peer_addr, e).into()
            },
        )?;
        let ws_stream = accept_async_with_config(tls_stream, Some(ws_config())).await?;
        handle_connection(
            ws_stream,
            peer_addr,
            jwt_validator,
            shutdown,
            orchestrator_tx,
            connections,
        )
        .await
    } else {
        let ws_stream = accept_async_with_config(stream, Some(ws_config())).await?;
        handle_connection(
            ws_stream,
            peer_addr,
            jwt_validator,
            shutdown,
            orchestrator_tx,
            connections,
        )
        .await
    }
}

/// Unified WebSocket connection handler with JWT authentication.
///
/// Expects the first message to be `{"type": "auth", "token": "..."}`.
/// On successful JWT validation, begins normal signaling message processing.
async fn handle_connection<S>(
    ws_stream: WebSocketStream<S>,
    peer_addr: SocketAddr,
    jwt_validator: Arc<JwtValidator>,
    shutdown: Arc<AtomicBool>,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
    connections: SignalingConnections,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // ── Phase 1: JWT Authentication ──────────────────────────────
    // Auth handshake uses raw JSON deliberately (not SignalMessage).
    // This is a separate protocol layer: the client sends {"type":"auth","token":"..."}
    // and receives {"type":"auth_ok","participant_id":...} or {"type":"error",...}.
    // Post-auth signaling uses the SignalMessage codec.
    // Wait for first text message (auth) with a timeout.
    let auth_result = tokio::time::timeout(
        Duration::from_secs(AUTH_TIMEOUT_SECS),
        wait_for_auth(&mut ws_stream_rx),
    )
    .await;

    let participant_claims = match auth_result {
        Ok(Ok(token)) => match jwt_validator.validate(&token) {
            Ok(claims) => claims,
            Err(e) => {
                let err_msg = serde_json::json!({
                    "type": "error",
                    "code": "AUTH_FAILED",
                    "message": format!("JWT validation failed: {}", e)
                });
                let _ = ws_sink.send(Message::Text(err_msg.to_string())).await;
                let _ = ws_sink.send(Message::Close(None)).await;
                return Ok(());
            }
        },
        Ok(Err(e)) => {
            debug!("Auth failed from {}: {}", peer_addr, e);
            let err_msg = serde_json::json!({
                "type": "error",
                "code": "AUTH_FAILED",
                "message": format!("{}", e)
            });
            let _ = ws_sink.send(Message::Text(err_msg.to_string())).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return Ok(());
        }
        Err(_) => {
            // Timeout
            let err_msg = serde_json::json!({
                "type": "error",
                "code": "AUTH_TIMEOUT",
                "message": "Authentication timeout"
            });
            let _ = ws_sink.send(Message::Text(err_msg.to_string())).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return Ok(());
        }
    };

    // Generate participant ID from monotonic counter.
    let participant_id: u64 = NEXT_PARTICIPANT_ID.fetch_add(1, Ordering::Relaxed);
    if participant_id == 0 {
        // Overflow after u64::MAX connections — practically impossible but handle gracefully.
        return Ok(());
    }

    // Bounded outbound channel.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<SignalMessage>(MAX_OUTBOUND_QUEUE);

    // Register connection.
    register_signaling_connection(&connections, participant_id, outbound_tx.clone());

    // Drop guard: ensure cleanup runs even on early returns / panics.
    let _cleanup = ConnectionCleanup {
        connections,
        participant_id,
        orchestrator_tx: orchestrator_tx.clone(),
    };

    // Send auth success
    let auth_ok = serde_json::json!({
        "type": "auth_ok",
        "participant_id": participant_id
    });
    if ws_sink
        .send(Message::Text(auth_ok.to_string()))
        .await
        .is_err()
    {
        return Ok(());
    }

    // Notify orchestrator of new connection
    if orchestrator_tx
        .send(OrchestratorEvent::Connected {
            participant_id,
            outbound_tx: outbound_tx.clone(),
            claims: participant_claims,
        })
        .await
        .is_err()
    {
        warn!("Orchestrator channel closed, disconnecting {}", peer_addr);
        return Ok(());
    }

    // ── Phase 2: Signaling Message Loop ──────────────────────────
    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut last_activity = tokio::time::Instant::now();

    // Simple token-bucket rate limiter: MESSAGE_RATE_LIMIT messages per second
    const MESSAGE_RATE_LIMIT: u32 = 100;
    let mut message_budget: u32 = MESSAGE_RATE_LIMIT;
    let mut last_budget_refill = tokio::time::Instant::now();

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        tokio::select! {
            // Inbound WebSocket message
            msg = ws_stream_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        last_activity = tokio::time::Instant::now();

                        // Refill rate limit budget every second
                        if last_budget_refill.elapsed() >= Duration::from_secs(1) {
                            message_budget = MESSAGE_RATE_LIMIT;
                            last_budget_refill = tokio::time::Instant::now();
                        }

                        // Rate limit check
                        if message_budget == 0 {
                            warn!("Rate limit exceeded from {}, dropping message", peer_addr);
                            continue;
                        }
                        message_budget -= 1;

                        // Validate message size
                        if text.len() > MAX_MESSAGE_SIZE {
                            warn!("Message too large from {}: {} bytes", peer_addr, text.len());
                            // Tell the client: otherwise it waits for a reply forever.
                            let _ = outbound_tx.try_send(SignalMessage::Error {
                                code: "MESSAGE_TOO_LARGE".to_string(),
                                message: format!(
                                    "message of {} bytes exceeds the {} byte limit",
                                    text.len(),
                                    MAX_MESSAGE_SIZE
                                ),
                            });
                            continue;
                        }

                        // Parse signaling message
                        match SignalMessage::from_json(&text) {
                            Ok(signal_msg) => {
                                if orchestrator_tx.send(OrchestratorEvent::Message {
                                    participant_id,
                                    message: signal_msg,
                                }).await.is_err() {
                                    warn!("Orchestrator channel closed, disconnecting {}", peer_addr);
                                    break;
                                }
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
                                // Server-sent messages count as activity for idle timeout
                                last_activity = tokio::time::Instant::now();
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

    // _cleanup Drop will call unregister + disconnect
    Ok(())
}

/// Wait for the first auth message from the WebSocket stream.
async fn wait_for_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
) -> Result<String, String> {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // Parse auth message
                let parsed: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {}", e))?;

                let msg_type = parsed
                    .get("type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing 'type' field".to_string())?;

                if msg_type != "auth" {
                    return Err(format!("expected auth message, got '{}'", msg_type));
                }

                let token = parsed
                    .get("token")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing 'token' field in auth message".to_string())?;

                return Ok(token.to_string());
            }
            Ok(Message::Close(_)) | Err(_) => {
                return Err("connection closed before auth".to_string());
            }
            _ => continue, // Ignore ping/pong during auth
        }
    }

    Err("stream ended before auth message".to_string())
}

/// Drop guard that ensures signaling connection cleanup on all exit paths.
struct ConnectionCleanup {
    connections: SignalingConnections,
    participant_id: u64,
    orchestrator_tx: mpsc::Sender<OrchestratorEvent>,
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        unregister_signaling_connection(&self.connections, self.participant_id);
        // Fire-and-forget disconnect notification.
        let _ = self
            .orchestrator_tx
            .try_send(OrchestratorEvent::Disconnected {
                participant_id: self.participant_id,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(cert: &str, key: &str) -> Result<WebSocketServer, String> {
        let (tx, _rx) = mpsc::channel(1);
        WebSocketServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(JwtValidator::new("test-secret-at-least-32-characters-long")),
            Arc::new(AtomicBool::new(false)),
            tx,
            cert,
            key,
        )
    }

    #[test]
    fn test_no_tls_paths_gives_plain_ws() {
        let server = build("", "").expect("plain WS is allowed without TLS paths");
        assert!(server.tls_acceptor.is_none());
    }

    #[test]
    fn test_missing_cert_files_fail_instead_of_downgrading() {
        let err = build("/nonexistent/cert.pem", "/nonexistent/key.pem")
            .err()
            .expect("a configured but missing certificate must be an error");
        assert!(err.contains("TLS init failed"), "unexpected error: {}", err);
    }

    #[test]
    fn test_port_zero_binds_a_real_port() {
        let a = build("", "").unwrap();
        let b = build("", "").unwrap();
        assert_ne!(a.local_addr().port(), 0);
        assert_ne!(a.local_addr(), b.local_addr());
        // Each server has its own connection registry.
        assert!(!Arc::ptr_eq(&a.connections(), &b.connections()));
    }

    /// A JWT the test server accepts.
    fn test_token(secret: &str) -> String {
        let claims = nexus_api::auth::Claims {
            sub: "size-test".to_string(),
            exp: u64::MAX / 2,
            iat: 0,
            rooms: vec!["*".to_string()],
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    /// The next text frame from the server, within 5 s.
    async fn next_text<S>(ws: &mut S) -> String
    where
        S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
    {
        let deadline = Duration::from_secs(5);
        loop {
            match tokio::time::timeout(deadline, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => return text,
                Ok(Some(Ok(_))) => continue,
                other => panic!("expected a text message, got {:?}", other),
            }
        }
    }

    /// The next orchestrator message event, within 5 s.
    async fn next_message(rx: &mut mpsc::Receiver<OrchestratorEvent>) -> SignalMessage {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("orchestrator event in time")
                .expect("orchestrator channel open");
            if let OrchestratorEvent::Message { message, .. } = event {
                return message;
            }
        }
    }

    /// An answer whose JSON is `len` bytes long, give or take the envelope.
    fn answer_of(len: usize) -> String {
        SignalMessage::Answer {
            sdp: "x".repeat(len),
        }
        .to_json()
        .unwrap()
    }

    #[tokio::test]
    async fn test_message_size_limits() {
        let secret = "test-secret-at-least-32-characters-long";
        let (tx, mut rx) = mpsc::channel(16);
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = Arc::new(
            WebSocketServer::new(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(JwtValidator::new(secret)),
                shutdown.clone(),
                tx,
                "",
                "",
            )
            .unwrap(),
        );
        let addr = server.local_addr();
        let srv = server.clone();
        let task = tokio::spawn(async move { srv.run().await });

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let auth = serde_json::json!({"type": "auth", "token": test_token(secret)});
        ws.send(Message::Text(auth.to_string())).await.unwrap();
        assert!(next_text(&mut ws).await.contains("auth_ok"));

        // A 32-m-line offer or answer (≤ 128 KB of SDP) fits with room to spare.
        let big = answer_of(200 * 1024);
        assert!(big.len() <= MAX_MESSAGE_SIZE);
        ws.send(Message::Text(big)).await.unwrap();
        match next_message(&mut rx).await {
            SignalMessage::Answer { sdp } => assert_eq!(sdp.len(), 200 * 1024),
            other => panic!("expected the answer, got {:?}", other),
        }

        // Over the limit: dropped, answered with an error, connection kept.
        let too_big = answer_of(300 * 1024);
        assert!(too_big.len() > MAX_MESSAGE_SIZE && too_big.len() < MAX_WS_BUFFERED_MESSAGE);
        ws.send(Message::Text(too_big)).await.unwrap();
        match SignalMessage::from_json(&next_text(&mut ws).await).unwrap() {
            SignalMessage::Error { code, .. } => assert_eq!(code, "MESSAGE_TOO_LARGE"),
            other => panic!("expected MESSAGE_TOO_LARGE, got {:?}", other),
        }
        ws.send(Message::Text(answer_of(10))).await.unwrap();
        assert!(matches!(
            next_message(&mut rx).await,
            SignalMessage::Answer { .. }
        ));

        shutdown.store(true, Ordering::Release);
        let _ = ws.close(None).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[test]
    fn test_only_one_tls_path_is_rejected() {
        assert!(build("/etc/cert.pem", "").is_err());
        assert!(build("", "/etc/key.pem").is_err());
    }
}
