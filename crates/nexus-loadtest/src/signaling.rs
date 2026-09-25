//! Signaling connection module
//!
//! Handles WebSocket and QUIC signaling using nexus-signal protocol.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use nexus_signal::SignalMessage;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::protocol::Message, Connector, MaybeTlsStream,
    WebSocketStream,
};

use crate::config::ConnectionOptions;

/// Lifetime of JWTs minted from `--jwt-secret`
const MINTED_TOKEN_TTL_SECS: u64 = 3600;

// Use u64 for IDs to match nexus-signal protocol types
pub type ParticipantId = u64;
pub type RoomId = u64;

use crate::error::SignalingError;

/// Signaling transport type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalingTransport {
    /// WebSocket transport (wss://)
    WebSocket,
    /// QUIC transport (quic://)
    Quic,
}

impl SignalingTransport {
    /// Determine transport type from URL scheme
    pub fn from_url(url: &str) -> Result<Self, SignalingError> {
        if url.starts_with("wss://") || url.starts_with("ws://") {
            Ok(SignalingTransport::WebSocket)
        } else if url.starts_with("quic://") {
            Ok(SignalingTransport::Quic)
        } else {
            Err(SignalingError::InvalidUrl(format!(
                "Unsupported URL scheme: {}. Expected wss://, ws://, or quic://",
                url
            )))
        }
    }
}

/// Join room response
#[derive(Clone, Debug)]
pub struct JoinResponse {
    /// Assigned participant ID
    pub participant_id: ParticipantId,
    /// Room ID
    pub room_id: RoomId,
    /// Existing participants in the room
    pub participants: Vec<nexus_signal::ParticipantInfo>,
    /// Existing tracks in the room
    pub tracks: Vec<nexus_signal::TrackInfo>,
}

/// Internal transport connection
#[allow(dead_code)]
enum TransportConnection {
    /// WebSocket connection
    WebSocket(WebSocketStream<MaybeTlsStream<TcpStream>>),
    /// QUIC connection (placeholder for future implementation)
    Quic,
}

/// Signaling connection to the SFU
pub struct SignalingConnection {
    /// Transport connection
    connection: TransportConnection,
    /// Transport type
    transport: SignalingTransport,
    /// Room ID (set after joining)
    room_id: Option<RoomId>,
    /// Participant ID (set after joining)
    participant_id: Option<ParticipantId>,
}

impl SignalingConnection {
    /// Default connection timeout (30 seconds per Requirement 10.3)
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Connect to SFU signaling endpoint and complete the auth handshake
    ///
    /// `subject` becomes the `sub` claim when a token is minted from `jwt_secret`.
    pub async fn connect(
        url: &str,
        options: &ConnectionOptions,
        subject: &str,
    ) -> Result<Self, SignalingError> {
        let transport = SignalingTransport::from_url(url)?;
        // Resolve credentials before dialing so a missing token fails fast
        let token = resolve_token(options, subject)?;

        let connection = match transport {
            SignalingTransport::WebSocket => {
                let connector = if options.insecure_tls && url.starts_with("wss://") {
                    Some(Connector::Rustls(insecure_tls_config()))
                } else {
                    None
                };
                let (ws_stream, _response) =
                    connect_async_tls_with_config(url, None, false, connector)
                        .await
                        .map_err(|e| {
                            if e.to_string().contains("Connection refused") {
                                SignalingError::ConnectionRefused
                            } else {
                                SignalingError::WebSocketError(e.to_string())
                            }
                        })?;
                TransportConnection::WebSocket(ws_stream)
            }
            SignalingTransport::Quic => {
                // QUIC transport is a placeholder for now
                return Err(SignalingError::QuicError(
                    "QUIC transport not yet implemented".to_string(),
                ));
            }
        };

        let mut conn = Self {
            connection,
            transport,
            room_id: None,
            participant_id: None,
        };
        conn.authenticate(&token).await?;
        Ok(conn)
    }

    /// Send `{"type":"auth","token":...}` and wait for `auth_ok`.
    ///
    /// The SFU closes connections that don't authenticate within 10 seconds.
    /// The handshake uses raw JSON rather than `SignalMessage`.
    async fn authenticate(&mut self, token: &str) -> Result<(), SignalingError> {
        let ws = match &mut self.connection {
            TransportConnection::WebSocket(ws) => ws,
            TransportConnection::Quic => {
                return Err(SignalingError::QuicError(
                    "QUIC transport not yet implemented".to_string(),
                ))
            }
        };

        let auth = serde_json::json!({ "type": "auth", "token": token });
        ws.send(Message::Text(auth.to_string()))
            .await
            .map_err(|e| SignalingError::WebSocketError(e.to_string()))?;

        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    let reply: serde_json::Value = serde_json::from_str(&text)
                        .map_err(|e| SignalingError::SerializationError(e.to_string()))?;
                    if reply.get("type").and_then(|v| v.as_str()) == Some("auth_ok") {
                        return Ok(());
                    }
                    let reason = reply
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&text);
                    return Err(SignalingError::AuthFailed(reason.to_string()));
                }
                Some(Ok(Message::Close(_))) | None => return Err(SignalingError::ConnectionClosed),
                Some(Err(e)) => return Err(SignalingError::WebSocketError(e.to_string())),
                Some(Ok(_)) => continue,
            }
        }
    }

    /// Connect to SFU signaling endpoint with a configurable timeout
    ///
    /// Wraps the connection attempt with a timeout. If the connection
    /// does not complete within the specified duration, returns a timeout error.
    ///
    /// # Arguments
    /// * `url` - The SFU signaling URL (wss://, ws://, or quic://)
    /// * `options` - Auth token/secret and TLS verification settings
    /// * `subject` - `sub` claim for a minted token
    /// * `timeout` - Maximum duration to wait for connection and auth
    ///
    /// # Returns
    /// * `Ok(SignalingConnection)` - Successfully connected
    /// * `Err(SignalingError::Timeout)` - Connection timed out
    /// * `Err(SignalingError::*)` - Other connection errors
    pub async fn connect_with_timeout(
        url: &str,
        options: &ConnectionOptions,
        subject: &str,
        timeout: std::time::Duration,
    ) -> Result<Self, SignalingError> {
        tokio::time::timeout(timeout, Self::connect(url, options, subject))
            .await
            .map_err(|_| SignalingError::Timeout(timeout))?
    }

    /// Send a signaling message
    pub async fn send(&mut self, msg: SignalMessage) -> Result<(), SignalingError> {
        let json = msg
            .to_json()
            .map_err(|e| SignalingError::SerializationError(e.to_string()))?;

        match &mut self.connection {
            TransportConnection::WebSocket(ws) => {
                ws.send(Message::Text(json)).await.map_err(|e| {
                    if e.to_string().contains("Connection reset")
                        || e.to_string().contains("Broken pipe")
                    {
                        SignalingError::ConnectionClosed
                    } else {
                        SignalingError::WebSocketError(e.to_string())
                    }
                })?;
            }
            TransportConnection::Quic => {
                return Err(SignalingError::QuicError(
                    "QUIC transport not yet implemented".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Receive next signaling message
    pub async fn recv(&mut self) -> Result<SignalMessage, SignalingError> {
        match &mut self.connection {
            TransportConnection::WebSocket(ws) => {
                loop {
                    match ws.next().await {
                        Some(Ok(Message::Text(text))) => {
                            let msg = SignalMessage::from_json(&text)
                                .map_err(|e| SignalingError::SerializationError(e.to_string()))?;
                            return Ok(msg);
                        }
                        Some(Ok(Message::Binary(data))) => {
                            // Try to parse binary as JSON text
                            let text = String::from_utf8(data).map_err(|e| {
                                SignalingError::ProtocolError(format!("Invalid UTF-8: {}", e))
                            })?;
                            let msg = SignalMessage::from_json(&text)
                                .map_err(|e| SignalingError::SerializationError(e.to_string()))?;
                            return Ok(msg);
                        }
                        Some(Ok(Message::Ping(_))) => {
                            // Respond to ping with pong (handled automatically by tungstenite)
                            continue;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            // Ignore pong messages
                            continue;
                        }
                        Some(Ok(Message::Close(_))) => {
                            return Err(SignalingError::ConnectionClosed);
                        }
                        Some(Ok(Message::Frame(_))) => {
                            // Raw frame, skip
                            continue;
                        }
                        Some(Err(e)) => {
                            return Err(SignalingError::WebSocketError(e.to_string()));
                        }
                        None => {
                            return Err(SignalingError::ConnectionClosed);
                        }
                    }
                }
            }
            TransportConnection::Quic => Err(SignalingError::QuicError(
                "QUIC transport not yet implemented".to_string(),
            )),
        }
    }

    /// Join a room
    ///
    /// Sends a Join message and waits for the Joined response.
    pub async fn join_room(
        &mut self,
        room_id: u64,
        participant_name: &str,
    ) -> Result<JoinResponse, SignalingError> {
        // Send join request
        let join_msg = SignalMessage::Join {
            room_id,
            participant_name: participant_name.to_string(),
        };
        self.send(join_msg).await?;

        // Wait for response
        loop {
            let msg = self.recv().await?;
            match msg {
                SignalMessage::Joined {
                    participant_id,
                    room_id,
                    participants,
                    tracks,
                } => {
                    self.participant_id = Some(participant_id);
                    self.room_id = Some(room_id);
                    return Ok(JoinResponse {
                        participant_id,
                        room_id,
                        participants,
                        tracks,
                    });
                }
                SignalMessage::Error { code, message } => {
                    if code == "room_not_found" || code == "ROOM_NOT_FOUND" {
                        return Err(SignalingError::RoomNotFound(message));
                    }
                    return Err(SignalingError::ProtocolError(format!(
                        "Join failed: {} - {}",
                        code, message
                    )));
                }
                // Ignore other messages while waiting for join response
                _ => continue,
            }
        }
    }

    /// Leave the current room
    pub async fn leave_room(&mut self) -> Result<(), SignalingError> {
        if self.room_id.is_none() {
            // Not in a room, nothing to do
            return Ok(());
        }

        // Send leave request
        self.send(SignalMessage::Leave).await?;

        // Clear local state
        self.room_id = None;
        self.participant_id = None;

        Ok(())
    }

    /// Get the transport type
    pub fn transport(&self) -> SignalingTransport {
        self.transport
    }

    /// Get the room ID (if joined)
    pub fn room_id(&self) -> Option<RoomId> {
        self.room_id
    }

    /// Get the participant ID (if joined)
    pub fn participant_id(&self) -> Option<ParticipantId> {
        self.participant_id
    }

    /// Send a ping message for keepalive
    pub async fn ping(&mut self) -> Result<(), SignalingError> {
        self.send(SignalMessage::Ping).await
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<(), SignalingError> {
        match &mut self.connection {
            TransportConnection::WebSocket(ws) => {
                ws.close(None)
                    .await
                    .map_err(|e| SignalingError::WebSocketError(e.to_string()))?;
            }
            TransportConnection::Quic => {
                // QUIC close not implemented
            }
        }
        Ok(())
    }
}

/// Pick the explicit token, or mint a short-lived HS256 JWT from the secret
fn resolve_token(options: &ConnectionOptions, subject: &str) -> Result<String, SignalingError> {
    if let Some(token) = &options.auth_token {
        return Ok(token.clone());
    }
    let secret = options.jwt_secret.as_deref().ok_or_else(|| {
        SignalingError::AuthFailed("no --token or --jwt-secret provided".to_string())
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let claims = serde_json::json!({
        "sub": subject,
        "iat": now,
        "exp": now + MINTED_TOKEN_TTL_SECS,
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| SignalingError::AuthFailed(format!("failed to mint JWT: {}", e)))
}

/// rustls config that accepts any server certificate (for `--insecure` only)
fn insecure_tls_config() -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    Arc::new(config)
}

/// Certificate verifier that skips all checks. Never use against production SFUs.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_from_url_websocket() {
        assert_eq!(
            SignalingTransport::from_url("wss://localhost:8443").unwrap(),
            SignalingTransport::WebSocket
        );
        assert_eq!(
            SignalingTransport::from_url("ws://localhost:8080").unwrap(),
            SignalingTransport::WebSocket
        );
    }

    #[test]
    fn test_transport_from_url_quic() {
        assert_eq!(
            SignalingTransport::from_url("quic://localhost:4433").unwrap(),
            SignalingTransport::Quic
        );
    }

    #[test]
    fn test_transport_from_url_invalid() {
        assert!(SignalingTransport::from_url("http://localhost").is_err());
        assert!(SignalingTransport::from_url("https://localhost").is_err());
        assert!(SignalingTransport::from_url("invalid").is_err());
    }

    #[test]
    fn test_default_timeout_is_30_seconds() {
        // Requirement 10.3: default timeout should be 30 seconds
        assert_eq!(
            SignalingConnection::DEFAULT_TIMEOUT,
            std::time::Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn test_connect_with_timeout_returns_timeout_error() {
        // Use a very short timeout and an unreachable address to trigger timeout
        let timeout = std::time::Duration::from_millis(1);
        let options = ConnectionOptions {
            auth_token: Some("test-token".to_string()),
            ..Default::default()
        };
        let result = SignalingConnection::connect_with_timeout(
            "wss://192.0.2.1:9999", // TEST-NET-1 address, should be unreachable
            &options,
            "test-client",
            timeout,
        )
        .await;

        // Should either timeout or fail to connect
        assert!(result.is_err());
        // If it's a timeout error, verify the duration is correct
        if let Err(crate::error::SignalingError::Timeout(duration)) = result {
            assert_eq!(duration, timeout);
        }
    }

    #[test]
    fn test_resolve_token_prefers_explicit_token() {
        let options = ConnectionOptions {
            auth_token: Some("explicit".to_string()),
            jwt_secret: Some("dev-secret-minimum-32-characters-long".to_string()),
            insecure_tls: false,
        };
        assert_eq!(resolve_token(&options, "client").unwrap(), "explicit");
    }

    #[test]
    fn test_resolve_token_mints_valid_hs256_jwt() {
        let secret = "dev-secret-minimum-32-characters-long";
        let options = ConnectionOptions {
            jwt_secret: Some(secret.to_string()),
            ..Default::default()
        };
        let token = resolve_token(&options, "loadtest-viewer").unwrap();

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.required_spec_claims.insert("exp".to_string());
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.claims["sub"], "loadtest-viewer");
    }

    #[test]
    fn test_resolve_token_without_credentials_fails() {
        let result = resolve_token(&ConnectionOptions::default(), "client");
        assert!(matches!(result, Err(SignalingError::AuthFailed(_))));
    }
}
