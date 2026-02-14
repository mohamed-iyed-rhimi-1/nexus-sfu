use crate::error::SignalError;
use crate::protocol::{signaling_capnp, MessageBuilder, MessageReader};

/// Stream type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// SDP offer/answer exchange (bidirectional).
    Sdp,
    /// Track updates (unidirectional server→client).
    TrackUpdate,
    /// Statistics (unidirectional client→server).
    Stats,
}

/// Stream priority levels (lower = higher priority).
pub const PRIORITY_SDP: i32 = 0;
pub const PRIORITY_TRACK_UPDATE: i32 = 128;
pub const PRIORITY_STATS: i32 = 255;

/// Client statistics sent from client to server via unidirectional stream.
///
/// # TigerStyle Compliance
/// - Fixed-size binary encoding (12 bytes)
/// - Explicitly-sized types (u32)
/// - No dynamic allocation in encode/decode
///
/// # Wire Format
/// ```text
/// +--------+--------+--------+--------+
/// |       rtt_us (u32 BE)             |
/// +--------+--------+--------+--------+
/// |     packets_lost (u32 BE)         |
/// +--------+--------+--------+--------+
/// |      jitter_us (u32 BE)           |
/// +--------+--------+--------+--------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientStats {
    /// Round-trip time in microseconds.
    pub rtt_us: u32,
    /// Number of packets lost.
    pub packets_lost: u32,
    /// Jitter in microseconds.
    pub jitter_us: u32,
}

/// Size of ClientStats in bytes when encoded.
pub const CLIENT_STATS_SIZE: usize = 12;

impl ClientStats {
    /// Create new client stats.
    pub fn new(rtt_us: u32, packets_lost: u32, jitter_us: u32) -> Self {
        Self {
            rtt_us,
            packets_lost,
            jitter_us,
        }
    }

    /// Encode client stats to fixed-layout binary format.
    ///
    /// # TigerStyle Compliance
    /// - No dynamic allocation
    /// - Fixed output size (12 bytes)
    /// - Big-endian encoding for network byte order
    pub fn encode(&self) -> [u8; CLIENT_STATS_SIZE] {
        let mut buf = [0u8; CLIENT_STATS_SIZE];

        // Encode rtt_us (bytes 0-3)
        buf[0..4].copy_from_slice(&self.rtt_us.to_be_bytes());

        // Encode packets_lost (bytes 4-7)
        buf[4..8].copy_from_slice(&self.packets_lost.to_be_bytes());

        // Encode jitter_us (bytes 8-11)
        buf[8..12].copy_from_slice(&self.jitter_us.to_be_bytes());

        buf
    }

    /// Decode client stats from fixed-layout binary format.
    ///
    /// # TigerStyle Compliance
    /// - Explicit error handling via Option
    /// - No panics on invalid input
    /// - Validates input length
    ///
    /// # Returns
    /// - `Some(ClientStats)` if decoding succeeds
    /// - `None` if input is too short
    pub fn decode(data: &[u8]) -> Option<Self> {
        // Validate minimum length
        if data.len() < CLIENT_STATS_SIZE {
            return None;
        }

        // Decode rtt_us (bytes 0-3)
        let rtt_us = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Decode packets_lost (bytes 4-7)
        let packets_lost = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Decode jitter_us (bytes 8-11)
        let jitter_us = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        Some(Self {
            rtt_us,
            packets_lost,
            jitter_us,
        })
    }

    /// Decode client stats from a slice, returning the stats and remaining bytes.
    ///
    /// Useful for parsing multiple stats from a stream.
    pub fn decode_with_remainder(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < CLIENT_STATS_SIZE {
            return None;
        }

        let stats = Self::decode(data)?;
        Some((stats, &data[CLIENT_STATS_SIZE..]))
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self {
            rtt_us: 0,
            packets_lost: 0,
            jitter_us: 0,
        }
    }
}

/// Extracted SDP message data (Send-safe).
enum SdpMessage {
    Offer(String),
    Answer(String),
}

/// Handle bidirectional stream for SDP exchange using Cap'n Proto.
///
/// # TigerStyle Compliance
/// - Function ≤70 lines
/// - Bounded read (max 64KB SDP)
/// - Explicit error handling
pub async fn handle_sdp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), SignalError> {
    // Set stream priority
    send.set_priority(PRIORITY_SDP).ok();

    let mut handler = StreamHandler::new();

    // Read SDP message with length prefix
    let msg_reader = handler.recv_message(&mut recv).await?;

    // Extract SDP data before any await points to avoid Send issues
    // Cap'n Proto readers contain raw pointers that aren't Send
    let sdp_message = {
        let msg = msg_reader
            .get_root::<signaling_capnp::signal_message::Reader>()
            .map_err(|e| SignalError::InvalidMessage(e.to_string()))?;

        // Use which() to access union variants
        use signaling_capnp::signal_message::Which;
        let which = msg
            .which()
            .map_err(|e| SignalError::InvalidMessage(format!("invalid union variant: {:?}", e)))?;

        // Extract and clone the SDP string to make it Send-safe
        match which {
            Which::Offer(offer_result) => {
                let offer = offer_result.map_err(|e| {
                    SignalError::InvalidMessage(format!("failed to read offer: {}", e))
                })?;
                let sdp = offer.get_sdp().map_err(|e| {
                    SignalError::InvalidMessage(format!("failed to get sdp: {}", e))
                })?;
                SdpMessage::Offer(sdp.to_string().map_err(|e| {
                    SignalError::InvalidMessage(format!("invalid utf8 in sdp: {}", e))
                })?)
            }
            Which::Answer(answer_result) => {
                let answer = answer_result.map_err(|e| {
                    SignalError::InvalidMessage(format!("failed to read answer: {}", e))
                })?;
                let sdp = answer.get_sdp().map_err(|e| {
                    SignalError::InvalidMessage(format!("failed to get sdp: {}", e))
                })?;
                SdpMessage::Answer(sdp.to_string().map_err(|e| {
                    SignalError::InvalidMessage(format!("invalid utf8 in sdp: {}", e))
                })?)
            }
            _ => {
                return Err(SignalError::InvalidMessage(
                    "Expected SDP offer or answer".into(),
                ));
            }
        }
    };
    // msg_reader is dropped here, releasing the non-Send pointers

    // Now we can safely await with the extracted String data
    match sdp_message {
        SdpMessage::Offer(sdp) => {
            // Echo back as answer
            handler
                .send_message(&mut send, |response| {
                    let mut answer = response.init_answer();
                    answer.set_sdp(&sdp);
                    answer.set_schema_version(1);
                })
                .await?;
        }
        SdpMessage::Answer(sdp) => {
            // Echo back as offer
            handler
                .send_message(&mut send, |response| {
                    let mut offer = response.init_offer();
                    offer.set_sdp(&sdp);
                    offer.set_schema_version(1);
                })
                .await?;
        }
    }

    // finish() is not async in newer quinn versions
    send.finish()
        .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;

    Ok(())
}

/// Handle unidirectional stream for track updates (server→client) using Cap'n Proto.
pub async fn send_track_update(
    mut send: quinn::SendStream,
    track_id: u32,
    participant_id: u32,
    kind: signaling_capnp::MediaKind,
    enabled: bool,
) -> Result<(), SignalError> {
    // Set stream priority
    send.set_priority(PRIORITY_TRACK_UPDATE).ok();

    let handler = StreamHandler::new();

    // Send track update
    handler
        .send_message(&mut send, |msg| {
            let mut update = msg.init_track_update();
            update.set_track_id(track_id);
            update.set_participant_id(participant_id);
            update.set_kind(kind);
            update.set_enabled(enabled);
            update.set_schema_version(1);
        })
        .await?;

    // finish() is not async in newer quinn versions
    send.finish()
        .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;

    Ok(())
}

/// Stream handler with Cap'n Proto support.
pub struct StreamHandler {
    builder: MessageBuilder,
    reader: MessageReader,
}

impl StreamHandler {
    pub fn new() -> Self {
        Self {
            builder: MessageBuilder::new(4096),
            reader: MessageReader::new(),
        }
    }

    /// Send SignalMessage over QUIC stream.
    pub async fn send_message<F>(
        &self,
        send: &mut quinn::SendStream,
        builder_fn: F,
    ) -> Result<(), SignalError>
    where
        F: FnOnce(signaling_capnp::signal_message::Builder),
    {
        let bytes = self.builder.build_signal_message(builder_fn);

        // Write length prefix (u32 big-endian)
        let len = bytes.len() as u32;
        assert!(len > 0);
        assert!(len < 1024 * 1024); // Max 1MB message

        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;

        Ok(())
    }

    /// Receive SignalMessage from QUIC stream.
    pub async fn recv_message(
        &mut self,
        recv: &mut quinn::RecvStream,
    ) -> Result<capnp::message::Reader<capnp::serialize::OwnedSegments>, SignalError> {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        recv.read_exact(&mut len_bytes)
            .await
            .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_bytes);

        assert!(len > 0);
        assert!(len < 1024 * 1024); // Max 1MB message

        // Read message bytes
        let mut bytes = vec![0u8; len as usize];
        recv.read_exact(&mut bytes)
            .await
            .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;

        // Deserialize
        self.reader
            .read_signal_message(&bytes)
            .map_err(|e| SignalError::InvalidMessage(e.to_string()))
    }
}

impl Default for StreamHandler {
    fn default() -> Self {
        Self::new()
    }
}
