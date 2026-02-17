//! Signaling connection module
//!
//! Handles WebSocket and QUIC signaling using nexus-signal protocol.

use futures_util::{SinkExt, StreamExt};
use nexus_signal::SignalMessage;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

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

    /// Connect to SFU signaling endpoint
    pub async fn connect(url: &str) -> Result<Self, SignalingError> {
        let transport = SignalingTransport::from_url(url)?;

        let connection = match transport {
            SignalingTransport::WebSocket => {
                let (ws_stream, _response) = connect_async(url).await.map_err(|e| {
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

        Ok(Self {
            connection,
            transport,
            room_id: None,
            participant_id: None,
        })
    }

    /// Connect to SFU signaling endpoint with a configurable timeout
    ///
    /// Wraps the connection attempt with a timeout. If the connection
    /// does not complete within the specified duration, returns a timeout error.
    ///
    /// # Arguments
    /// * `url` - The SFU signaling URL (wss://, ws://, or quic://)
    /// * `timeout` - Maximum duration to wait for connection
    ///
    /// # Returns
    /// * `Ok(SignalingConnection)` - Successfully connected
    /// * `Err(SignalingError::Timeout)` - Connection timed out
    /// * `Err(SignalingError::*)` - Other connection errors
    pub async fn connect_with_timeout(
        url: &str,
        timeout: std::time::Duration,
    ) -> Result<Self, SignalingError> {
        tokio::time::timeout(timeout, Self::connect(url))
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
        let result = SignalingConnection::connect_with_timeout(
            "wss://192.0.2.1:9999", // TEST-NET-1 address, should be unreachable
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
}
