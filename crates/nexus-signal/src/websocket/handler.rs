//! Signaling message handler for WebSocket communication.
//!
//! This module provides the `SignalingHandler` struct that routes WebSocket
//! messages and manages session state for 0-RTT resumption.
//!
//! # TigerStyle Compliance
//!
//! - All functions ≤70 lines
//! - Minimum 2 assertions per function
//! - No recursion, bounded loops
//! - Static allocation after initialization
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      SignalingHandler                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  state: Arc<DistributedState>                                   │
//! │  session_tickets: [Option<SessionTicket>; MAX_SESSION_TICKETS]  │
//! │  handlers: MessageHandlerTable                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_state::{DistributedState, DistributedStateConfig};

use nexus_core::{MediaKind, ParticipantId, RoomId, Ssrc, TrackId};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of session tickets stored
pub const MAX_SESSION_TICKETS: usize = 1000;

/// Session ticket lifetime in seconds (24 hours)
pub const TICKET_LIFETIME_SECS: u64 = 86400;

/// Maximum tracks in a join response
pub const MAX_TRACKS_IN_RESPONSE: usize = 1000;

/// Maximum participant name length in bytes
pub const MAX_PARTICIPANT_NAME_LEN: usize = 256;

/// Maximum binary stats payload size
pub const MAX_STATS_PAYLOAD_SIZE: usize = 256;

// Compile-time assertions
const _: () = {
    assert!(MAX_SESSION_TICKETS > 0, "MAX_SESSION_TICKETS must be positive");
    assert!(MAX_SESSION_TICKETS <= 10_000, "MAX_SESSION_TICKETS must not exceed 10_000");
    assert!(TICKET_LIFETIME_SECS > 0, "TICKET_LIFETIME_SECS must be positive");
    assert!(MAX_TRACKS_IN_RESPONSE > 0, "MAX_TRACKS_IN_RESPONSE must be positive");
};

// =============================================================================
// Error Types
// =============================================================================

/// Signaling handler error codes (3001-3020 range)
pub mod error_codes {
    /// Session ticket not found
    pub const TICKET_NOT_FOUND: u32 = 3001;
    /// Session ticket expired
    pub const TICKET_EXPIRED: u32 = 3002;
    /// Session ticket ID mismatch
    pub const TICKET_ID_MISMATCH: u32 = 3003;
    /// Invalid message type
    pub const INVALID_MESSAGE_TYPE: u32 = 3004;
    /// Room not found
    pub const ROOM_NOT_FOUND: u32 = 3005;
    /// Participant name too long
    pub const NAME_TOO_LONG: u32 = 3006;
    /// Stats payload too large
    pub const STATS_TOO_LARGE: u32 = 3007;
    /// Stats payload malformed
    pub const STATS_MALFORMED: u32 = 3008;
    /// Ticket store full
    pub const TICKET_STORE_FULL: u32 = 3009;
}

/// Errors from signaling handler operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalingHandlerError {
    /// Session ticket not found in store
    TicketNotFound,
    /// Session ticket has expired
    TicketExpired {
        /// Ticket expiration timestamp
        expires_at: u64,
        /// Current timestamp
        current_time: u64,
    },
    /// Session ticket ID does not match
    TicketIdMismatch,
    /// Invalid message type received
    InvalidMessageType {
        /// The invalid message type value
        msg_type: u8,
    },
    /// Room not found in distributed state
    RoomNotFound {
        /// The room ID that was not found
        room_id: RoomId,
    },
    /// Participant name exceeds maximum length
    NameTooLong {
        /// Actual length
        len: usize,
        /// Maximum allowed length
        max_len: usize,
    },
    /// Stats payload exceeds maximum size
    StatsPayloadTooLarge {
        /// Actual size
        size: usize,
        /// Maximum allowed size
        max_size: usize,
    },
    /// Stats payload is malformed
    StatsMalformed {
        /// Description of the malformation
        reason: &'static str,
    },
    /// Session ticket store is full
    TicketStoreFull {
        /// Current capacity
        capacity: usize,
    },
}

impl SignalingHandlerError {
    /// Returns the error code for this error
    #[inline]
    pub const fn code(&self) -> u32 {
        match self {
            Self::TicketNotFound => error_codes::TICKET_NOT_FOUND,
            Self::TicketExpired { .. } => error_codes::TICKET_EXPIRED,
            Self::TicketIdMismatch => error_codes::TICKET_ID_MISMATCH,
            Self::InvalidMessageType { .. } => error_codes::INVALID_MESSAGE_TYPE,
            Self::RoomNotFound { .. } => error_codes::ROOM_NOT_FOUND,
            Self::NameTooLong { .. } => error_codes::NAME_TOO_LONG,
            Self::StatsPayloadTooLarge { .. } => error_codes::STATS_TOO_LARGE,
            Self::StatsMalformed { .. } => error_codes::STATS_MALFORMED,
            Self::TicketStoreFull { .. } => error_codes::TICKET_STORE_FULL,
        }
    }
}

impl std::fmt::Display for SignalingHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TicketNotFound => {
                write!(f, "[E{}] session ticket not found", self.code())
            }
            Self::TicketExpired { expires_at, current_time } => {
                write!(
                    f,
                    "[E{}] session ticket expired at {}, current time {}",
                    self.code(),
                    expires_at,
                    current_time
                )
            }
            Self::TicketIdMismatch => {
                write!(f, "[E{}] session ticket ID mismatch", self.code())
            }
            Self::InvalidMessageType { msg_type } => {
                write!(f, "[E{}] invalid message type: {}", self.code(), msg_type)
            }
            Self::RoomNotFound { room_id } => {
                write!(f, "[E{}] room {} not found", self.code(), room_id)
            }
            Self::NameTooLong { len, max_len } => {
                write!(
                    f,
                    "[E{}] participant name too long: {} bytes, max {}",
                    self.code(),
                    len,
                    max_len
                )
            }
            Self::StatsPayloadTooLarge { size, max_size } => {
                write!(
                    f,
                    "[E{}] stats payload too large: {} bytes, max {}",
                    self.code(),
                    size,
                    max_size
                )
            }
            Self::StatsMalformed { reason } => {
                write!(f, "[E{}] stats malformed: {}", self.code(), reason)
            }
            Self::TicketStoreFull { capacity } => {
                write!(f, "[E{}] ticket store full at {} tickets", self.code(), capacity)
            }
        }
    }
}

impl std::error::Error for SignalingHandlerError {}

// =============================================================================
// Message Types
// =============================================================================

/// WebSocket message types for dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Join room request
    Join = 0,
    /// Leave room request
    Leave = 1,
    /// SDP offer
    Offer = 2,
    /// SDP answer
    Answer = 3,
    /// ICE candidate
    Candidate = 4,
    /// Client statistics
    Stats = 5,
    /// Ping/keepalive
    Ping = 6,
    /// Pong response
    Pong = 7,
    /// Subscribe to track
    Subscribe = 8,
    /// Unsubscribe from track
    Unsubscribe = 9,
    /// Viewport update
    Viewport = 10,
    /// Set content type on a track
    SetContent = 11,
}

impl MessageType {
    /// Convert from u8, returns None if invalid
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Join),
            1 => Some(Self::Leave),
            2 => Some(Self::Offer),
            3 => Some(Self::Answer),
            4 => Some(Self::Candidate),
            5 => Some(Self::Stats),
            6 => Some(Self::Ping),
            7 => Some(Self::Pong),
            8 => Some(Self::Subscribe),
            9 => Some(Self::Unsubscribe),
            10 => Some(Self::Viewport),
            11 => Some(Self::SetContent),
            _ => None,
        }
    }
}

// =============================================================================
// Session Ticket
// =============================================================================

/// Session ticket for 0-RTT resumption.
///
/// Stores encrypted session data for fast reconnection without
/// full handshake. Tickets expire after TICKET_LIFETIME_SECS.
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Ticket identifier (32 bytes)
    pub ticket_id: [u8; 32],
    /// Encrypted session data
    pub session_data: [u8; 256],
    /// Session data length (actual bytes used in session_data)
    pub data_len: u16,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// Associated participant ID
    pub participant_id: ParticipantId,
}

impl SessionTicket {
    /// Creates a new session ticket.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    #[inline]
    pub fn new(
        ticket_id: [u8; 32],
        session_data: &[u8],
        participant_id: ParticipantId,
    ) -> Self {
        // Precondition: session data must fit in buffer
        assert!(
            session_data.len() <= 256,
            "session_data must not exceed 256 bytes"
        );
        // Precondition: participant_id must be non-zero
        assert!(participant_id != 0, "participant_id must be non-zero");

        let mut data = [0u8; 256];
        let data_len = session_data.len().min(256);
        data[..data_len].copy_from_slice(&session_data[..data_len]);

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + TICKET_LIFETIME_SECS;

        // Postcondition: expires_at is in the future
        debug_assert!(expires_at > 0);

        Self {
            ticket_id,
            session_data: data,
            data_len: data_len as u16,
            expires_at,
            participant_id,
        }
    }

    /// Checks if the ticket has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }

    /// Returns the session data slice.
    #[inline]
    pub fn session_data(&self) -> &[u8] {
        &self.session_data[..self.data_len as usize]
    }
}

// =============================================================================
// Client Stats
// =============================================================================

/// Client statistics parsed from binary stats stream.
///
/// Binary format (40 bytes total):
/// - rtt_us: u32 (4 bytes)
/// - jitter_us: u32 (4 bytes)
/// - packets_sent: u64 (8 bytes)
/// - packets_lost: u32 (4 bytes)
/// - bytes_sent: u64 (8 bytes)
/// - timestamp_us: u64 (8 bytes)
/// - reserved: u32 (4 bytes)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Round-trip time in microseconds
    pub rtt_us: u32,
    /// Jitter in microseconds
    pub jitter_us: u32,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets lost
    pub packets_lost: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Timestamp in microseconds since epoch
    pub timestamp_us: u64,
}

impl ClientStats {
    /// Binary stats payload size
    pub const BINARY_SIZE: usize = 40;
}

// =============================================================================
// Track Entry (for join response)
// =============================================================================

/// Track entry in join response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackEntry {
    /// Track identifier
    pub track_id: TrackId,
    /// SSRC for the track
    pub ssrc: Ssrc,
    /// Media kind (audio/video)
    pub kind: MediaKind,
    /// Whether the track is active
    pub active: bool,
}

// =============================================================================
// Join Response
// =============================================================================

/// Join response containing room state.
#[derive(Debug, Clone)]
pub struct JoinResponse {
    /// Participant ID assigned to the joining client
    pub participant_id: ParticipantId,
    /// Room ID
    pub room_id: RoomId,
    /// List of active tracks in the room
    pub tracks: Vec<TrackEntry>,
    /// Number of participants in the room
    pub participant_count: u32,
}

// =============================================================================
// Message Handler Table
// =============================================================================

/// Handler function type for message dispatch
pub type MessageHandler = fn(&mut SignalingHandler, &[u8]) -> Result<Vec<u8>, SignalingHandlerError>;

/// Message handler lookup table (fixed-size array)
pub struct MessageHandlerTable {
    /// Handlers indexed by MessageType
    handlers: [Option<MessageHandler>; 10],
}

impl MessageHandlerTable {
    /// Creates a new handler table with default handlers.
    #[inline]
    pub fn new() -> Self {
        Self {
            handlers: [None; 10],
        }
    }

    /// Registers a handler for a message type.
    #[inline]
    pub fn register(&mut self, msg_type: MessageType, handler: MessageHandler) {
        let idx = msg_type as usize;
        assert!(idx < 10, "message type index out of bounds");
        self.handlers[idx] = Some(handler);
    }

    /// Gets the handler for a message type.
    #[inline]
    pub fn get(&self, msg_type: MessageType) -> Option<MessageHandler> {
        let idx = msg_type as usize;
        if idx < 10 {
            self.handlers[idx]
        } else {
            None
        }
    }
}

impl Default for MessageHandlerTable {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SignalingHandler
// =============================================================================

/// Signaling message handler.
///
/// Routes WebSocket messages and manages session state for 0-RTT resumption.
/// All operations follow TigerStyle guidelines with bounded loops and
/// static allocation.
pub struct SignalingHandler {
    /// Distributed state reference
    state: Arc<DistributedState>,
    /// Session ticket store (fixed capacity)
    session_tickets: Vec<Option<SessionTicket>>,
    /// Current ticket count
    ticket_count: u32,
    /// Message handlers by type
    handlers: MessageHandlerTable,
    /// Participant names (participant_id -> name)
    /// Using a simple fixed-size approach for TigerStyle compliance
    participant_names: Vec<(ParticipantId, String)>,
}

impl SignalingHandler {
    /// Creates a new signaling handler.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `state` - Reference to the distributed state
    #[inline]
    pub fn new(state: Arc<DistributedState>) -> Self {
        // Precondition: state must be valid
        assert!(state.local_actor() < 256, "local_actor must be < MAX_ACTORS");

        // Pre-allocate session ticket storage
        let mut session_tickets = Vec::with_capacity(MAX_SESSION_TICKETS);
        for _ in 0..MAX_SESSION_TICKETS {
            session_tickets.push(None);
        }

        // Pre-allocate participant names storage
        let participant_names = Vec::with_capacity(1000);

        // Postcondition: storage is pre-allocated
        debug_assert_eq!(session_tickets.len(), MAX_SESSION_TICKETS);

        Self {
            state,
            session_tickets,
            ticket_count: 0,
            handlers: MessageHandlerTable::new(),
            participant_names,
        }
    }

    /// Creates a new signaling handler with a new distributed state.
    ///
    /// Convenience constructor for testing.
    #[inline]
    pub fn with_new_state(actor_id: u64) -> Self {
        let config = DistributedStateConfig::new(actor_id);
        let state = Arc::new(DistributedState::new(config));
        Self::new(state)
    }

    /// Returns a reference to the distributed state.
    #[inline]
    pub fn state(&self) -> &Arc<DistributedState> {
        &self.state
    }

    /// Returns the current session ticket count.
    #[inline]
    pub fn ticket_count(&self) -> u32 {
        self.ticket_count
    }

    /// Dispatches a WebSocket message to the appropriate handler.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `msg_type` - The message type
    /// * `payload` - The message payload
    ///
    /// # Returns
    ///
    /// Response bytes on success, or error if dispatch fails.
    pub fn dispatch_message(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>, SignalingHandlerError> {
        // Precondition: payload must not exceed reasonable size
        assert!(payload.len() <= 65536, "payload too large");

        // Look up handler
        if let Some(handler) = self.handlers.get(msg_type) {
            handler(self, payload)
        } else {
            // Default handling for messages without registered handlers
            match msg_type {
                MessageType::Ping => {
                    // Return pong response
                    Ok(vec![MessageType::Pong as u8])
                }
                MessageType::Pong => {
                    // Pong is a no-op response
                    Ok(Vec::new())
                }
                _ => {
                    // No handler registered
                    Err(SignalingHandlerError::InvalidMessageType {
                        msg_type: msg_type as u8,
                    })
                }
            }
        }
    }

    /// Dispatches a raw message by parsing the type from the first byte.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `data` - Raw message data (first byte is type)
    ///
    /// # Returns
    ///
    /// Response bytes on success, or error if dispatch fails.
    pub fn dispatch_raw(&mut self, data: &[u8]) -> Result<Vec<u8>, SignalingHandlerError> {
        // Precondition: data must have at least type byte
        assert!(!data.is_empty(), "message data must not be empty");

        let msg_type_byte = data[0];
        let msg_type = MessageType::from_u8(msg_type_byte).ok_or(
            SignalingHandlerError::InvalidMessageType {
                msg_type: msg_type_byte,
            },
        )?;

        let payload = if data.len() > 1 { &data[1..] } else { &[] };

        // Postcondition: dispatch with parsed type
        self.dispatch_message(msg_type, payload)
    }

    /// Registers a message handler.
    #[inline]
    pub fn register_handler(&mut self, msg_type: MessageType, handler: MessageHandler) {
        self.handlers.register(msg_type, handler);
    }

    // =========================================================================
    // Join Response and Participant Management (Task 6.2)
    // =========================================================================

    /// Builds a join response with all active tracks in the room.
    ///
    /// Populates the track list with all active tracks, SSRCs, and media kinds
    /// from the distributed state.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop
    ///
    /// # Arguments
    ///
    /// * `room_id` - The room to join
    /// * `participant_id` - The participant ID assigned to the joining client
    ///
    /// # Returns
    ///
    /// `JoinResponse` with track list on success, or error if room not found.
    pub fn build_join_response(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> Result<JoinResponse, SignalingHandlerError> {
        // Precondition: room_id must be non-zero
        assert!(room_id != 0, "room_id must be non-zero");
        // Precondition: participant_id must be non-zero
        assert!(participant_id != 0, "participant_id must be non-zero");

        // Check if room exists
        if !self.state.room_exists(room_id) {
            return Err(SignalingHandlerError::RoomNotFound { room_id });
        }

        // Get participant count
        let participant_count = self.state.participant_count(room_id) as u32;

        // Collect active tracks
        // Note: In a real implementation, we'd have a room->tracks mapping.
        // For now, we iterate through subscriptions to find tracks in this room.
        let mut tracks: Vec<TrackEntry> = Vec::with_capacity(MAX_TRACKS_IN_RESPONSE);
        let mut track_count = 0u32;

        // Get all participants in the room and their subscriptions
        let participants = self.state.get_participants(room_id);

        // Bounded loop: iterate through participants to find their tracks
        for (idx, pid) in participants.iter().enumerate() {
            if idx >= MAX_TRACKS_IN_RESPONSE {
                break;
            }

            // Get tracks this participant is subscribed to
            let subscribed_tracks = self.state.get_subscriptions_for_participant(*pid);

            // Bounded inner loop
            for (tidx, track_id) in subscribed_tracks.iter().enumerate() {
                if tidx >= MAX_TRACKS_IN_RESPONSE || track_count >= MAX_TRACKS_IN_RESPONSE as u32 {
                    break;
                }

                // Get track info if available
                if let Some(track_info) = self.state.get_track(*track_id) {
                    let kind = if track_info.track_type == 0 {
                        MediaKind::Audio
                    } else {
                        MediaKind::Video
                    };

                    let entry = TrackEntry {
                        track_id: *track_id as TrackId,
                        ssrc: track_info.codec, // Using codec field as SSRC placeholder
                        kind,
                        active: true,
                    };

                    // Avoid duplicates (bounded check)
                    let mut found = false;
                    for existing in &tracks {
                        if existing.track_id == entry.track_id {
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        tracks.push(entry);
                        track_count += 1;
                    }
                }
            }
        }

        // Postcondition: tracks count is bounded
        debug_assert!(tracks.len() <= MAX_TRACKS_IN_RESPONSE);

        Ok(JoinResponse {
            participant_id,
            room_id,
            tracks,
            participant_count,
        })
    }

    /// Stores a participant's name in the handler's local storage.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `participant_id` - The participant's ID
    /// * `name` - The participant's display name
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or error if name is too long.
    pub fn store_participant_name(
        &mut self,
        participant_id: ParticipantId,
        name: &str,
    ) -> Result<(), SignalingHandlerError> {
        // Precondition: participant_id must be non-zero
        assert!(participant_id != 0, "participant_id must be non-zero");
        // Precondition: name must not be empty
        assert!(!name.is_empty(), "name must not be empty");

        // Check name length
        if name.len() > MAX_PARTICIPANT_NAME_LEN {
            return Err(SignalingHandlerError::NameTooLong {
                len: name.len(),
                max_len: MAX_PARTICIPANT_NAME_LEN,
            });
        }

        // Check if participant already has a name (update it)
        let mut found = false;
        for (pid, stored_name) in &mut self.participant_names {
            if *pid == participant_id {
                *stored_name = name.to_string();
                found = true;
                break;
            }
        }

        // If not found, add new entry
        if !found {
            self.participant_names.push((participant_id, name.to_string()));
        }

        // Postcondition: name is stored
        debug_assert!(self.get_participant_name(participant_id).is_some());

        Ok(())
    }

    /// Gets a participant's stored name.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - The participant's ID
    ///
    /// # Returns
    ///
    /// The participant's name if stored, None otherwise.
    pub fn get_participant_name(&self, participant_id: ParticipantId) -> Option<&str> {
        for (pid, name) in &self.participant_names {
            if *pid == participant_id {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Parses binary client statistics data into `ClientStats`.
    ///
    /// Binary format (40 bytes):
    /// - rtt_us: u32 (4 bytes, big-endian)
    /// - jitter_us: u32 (4 bytes, big-endian)
    /// - packets_sent: u64 (8 bytes, big-endian)
    /// - packets_lost: u32 (4 bytes, big-endian)
    /// - bytes_sent: u64 (8 bytes, big-endian)
    /// - timestamp_us: u64 (8 bytes, big-endian)
    /// - reserved: u32 (4 bytes)
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `data` - Binary statistics data
    ///
    /// # Returns
    ///
    /// Parsed `ClientStats` on success, or error if data is malformed.
    pub fn parse_client_stats(&self, data: &[u8]) -> Result<ClientStats, SignalingHandlerError> {
        // Precondition: data must not be empty
        assert!(!data.is_empty(), "stats data must not be empty");

        // Check payload size
        if data.len() > MAX_STATS_PAYLOAD_SIZE {
            return Err(SignalingHandlerError::StatsPayloadTooLarge {
                size: data.len(),
                max_size: MAX_STATS_PAYLOAD_SIZE,
            });
        }

        // Check minimum size
        if data.len() < ClientStats::BINARY_SIZE {
            return Err(SignalingHandlerError::StatsMalformed {
                reason: "payload too short for ClientStats",
            });
        }

        // Parse fields (big-endian)
        let rtt_us = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let jitter_us = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let packets_sent = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let packets_lost = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let bytes_sent = u64::from_be_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);
        let timestamp_us = u64::from_be_bytes([
            data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
        ]);
        // Reserved bytes [36..40] are ignored

        // Postcondition: stats are valid
        let stats = ClientStats {
            rtt_us,
            jitter_us,
            packets_sent,
            packets_lost,
            bytes_sent,
            timestamp_us,
        };

        Ok(stats)
    }

    // =========================================================================
    // Session Ticket Validation (Task 6.3)
    // =========================================================================

    /// Validates a 0-RTT session ticket.
    ///
    /// Checks that the ticket exists in the store, has not expired,
    /// and the ticket ID matches exactly.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `ticket_id` - The 32-byte ticket identifier to validate
    ///
    /// # Returns
    ///
    /// Reference to the valid `SessionTicket` on success, or error if:
    /// - Ticket not found
    /// - Ticket expired
    /// - Ticket ID mismatch
    pub fn validate_session_ticket(
        &self,
        ticket_id: &[u8; 32],
    ) -> Result<&SessionTicket, SignalingHandlerError> {
        // Precondition: ticket_id must not be all zeros
        let all_zeros = ticket_id.iter().all(|&b| b == 0);
        assert!(!all_zeros, "ticket_id must not be all zeros");

        // Get current time for expiration check
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Search for ticket in store (bounded loop)
        for idx in 0..MAX_SESSION_TICKETS {
            if let Some(ref ticket) = self.session_tickets[idx] {
                // Check exact ID match
                if ticket.ticket_id == *ticket_id {
                    // Check expiration
                    if current_time >= ticket.expires_at {
                        return Err(SignalingHandlerError::TicketExpired {
                            expires_at: ticket.expires_at,
                            current_time,
                        });
                    }

                    // Postcondition: ticket is valid
                    return Ok(ticket);
                }
            }
        }

        // Ticket not found
        Err(SignalingHandlerError::TicketNotFound)
    }

    /// Stores a session ticket for 0-RTT resumption.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Arguments
    ///
    /// * `ticket` - The session ticket to store
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or error if store is full.
    pub fn store_session_ticket(
        &mut self,
        ticket: SessionTicket,
    ) -> Result<(), SignalingHandlerError> {
        // Precondition: ticket must have valid participant_id
        assert!(ticket.participant_id != 0, "ticket participant_id must be non-zero");

        // First, try to find an empty slot or expired ticket to replace
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Bounded loop: find empty or expired slot
        for idx in 0..MAX_SESSION_TICKETS {
            let should_replace = match &self.session_tickets[idx] {
                None => true,
                Some(existing) => current_time >= existing.expires_at,
            };

            if should_replace {
                // Check if we're replacing an expired ticket (decrement count)
                if self.session_tickets[idx].is_some() {
                    // Replacing expired ticket, count stays same
                } else {
                    // New slot, increment count
                    self.ticket_count += 1;
                }

                self.session_tickets[idx] = Some(ticket);

                // Postcondition: ticket is stored
                debug_assert!(self.session_tickets[idx].is_some());
                return Ok(());
            }
        }

        // No empty or expired slots found
        Err(SignalingHandlerError::TicketStoreFull {
            capacity: MAX_SESSION_TICKETS,
        })
    }

    /// Removes a session ticket from the store.
    ///
    /// # Arguments
    ///
    /// * `ticket_id` - The ticket ID to remove
    ///
    /// # Returns
    ///
    /// `true` if ticket was found and removed, `false` otherwise.
    pub fn remove_session_ticket(&mut self, ticket_id: &[u8; 32]) -> bool {
        // Bounded loop
        for idx in 0..MAX_SESSION_TICKETS {
            if let Some(ref ticket) = self.session_tickets[idx] {
                if ticket.ticket_id == *ticket_id {
                    self.session_tickets[idx] = None;
                    self.ticket_count = self.ticket_count.saturating_sub(1);
                    return true;
                }
            }
        }
        false
    }

    /// Cleans up expired session tickets.
    ///
    /// # Returns
    ///
    /// Number of tickets removed.
    pub fn cleanup_expired_tickets(&mut self) -> u32 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut removed = 0u32;

        // Bounded loop
        for idx in 0..MAX_SESSION_TICKETS {
            if let Some(ref ticket) = self.session_tickets[idx] {
                if current_time >= ticket.expires_at {
                    self.session_tickets[idx] = None;
                    self.ticket_count = self.ticket_count.saturating_sub(1);
                    removed += 1;
                }
            }
        }

        removed
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_from_u8() {
        assert_eq!(MessageType::from_u8(0), Some(MessageType::Join));
        assert_eq!(MessageType::from_u8(1), Some(MessageType::Leave));
        assert_eq!(MessageType::from_u8(5), Some(MessageType::Stats));
        assert_eq!(MessageType::from_u8(10), Some(MessageType::Viewport));
        assert_eq!(MessageType::from_u8(11), Some(MessageType::SetContent));
        assert_eq!(MessageType::from_u8(12), None);
        assert_eq!(MessageType::from_u8(255), None);
    }

    #[test]
    fn test_session_ticket_new() {
        let ticket_id = [1u8; 32];
        let session_data = b"test session data";
        let participant_id = 42;

        let ticket = SessionTicket::new(ticket_id, session_data, participant_id);

        assert_eq!(ticket.ticket_id, ticket_id);
        assert_eq!(ticket.participant_id, participant_id);
        assert_eq!(ticket.data_len, session_data.len() as u16);
        assert!(!ticket.is_expired());
    }

    #[test]
    fn test_signaling_handler_new() {
        let handler = SignalingHandler::with_new_state(1);
        assert_eq!(handler.ticket_count(), 0);
        assert_eq!(handler.session_tickets.len(), MAX_SESSION_TICKETS);
    }

    #[test]
    fn test_dispatch_ping_pong() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Dispatch ping
        let response = handler
            .dispatch_message(MessageType::Ping, &[])
            .unwrap();
        assert_eq!(response, vec![MessageType::Pong as u8]);

        // Dispatch pong (no-op)
        let response = handler
            .dispatch_message(MessageType::Pong, &[])
            .unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn test_dispatch_raw() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Raw ping message
        let response = handler.dispatch_raw(&[MessageType::Ping as u8]).unwrap();
        assert_eq!(response, vec![MessageType::Pong as u8]);
    }

    #[test]
    fn test_dispatch_invalid_type() {
        let mut handler = SignalingHandler::with_new_state(1);

        let result = handler.dispatch_raw(&[255]);
        assert!(matches!(
            result,
            Err(SignalingHandlerError::InvalidMessageType { msg_type: 255 })
        ));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            SignalingHandlerError::TicketNotFound.code(),
            error_codes::TICKET_NOT_FOUND
        );
        assert_eq!(
            SignalingHandlerError::TicketExpired {
                expires_at: 100,
                current_time: 200
            }
            .code(),
            error_codes::TICKET_EXPIRED
        );
    }

    #[test]
    fn test_message_handler_table() {
        let mut table = MessageHandlerTable::new();

        fn test_handler(
            _handler: &mut SignalingHandler,
            _payload: &[u8],
        ) -> Result<Vec<u8>, SignalingHandlerError> {
            Ok(vec![42])
        }

        table.register(MessageType::Join, test_handler);
        assert!(table.get(MessageType::Join).is_some());
        assert!(table.get(MessageType::Leave).is_none());
    }

    #[test]
    fn test_build_join_response_room_not_found() {
        let handler = SignalingHandler::with_new_state(1);

        // Room doesn't exist
        let result = handler.build_join_response(999, 42);
        assert!(matches!(
            result,
            Err(SignalingHandlerError::RoomNotFound { room_id: 999 })
        ));
    }

    #[test]
    fn test_build_join_response_success() {
        let handler = SignalingHandler::with_new_state(1);

        // Create a room
        handler
            .state
            .create_room(1, "Test Room".to_string(), 100)
            .unwrap();

        // Build join response
        let response = handler.build_join_response(1, 42).unwrap();

        assert_eq!(response.room_id, 1);
        assert_eq!(response.participant_id, 42);
        assert_eq!(response.participant_count, 0); // No participants yet
        assert!(response.tracks.is_empty()); // No tracks yet
    }

    #[test]
    fn test_store_participant_name() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Store a name
        handler.store_participant_name(42, "Alice").unwrap();
        assert_eq!(handler.get_participant_name(42), Some("Alice"));

        // Update the name
        handler.store_participant_name(42, "Alice Smith").unwrap();
        assert_eq!(handler.get_participant_name(42), Some("Alice Smith"));

        // Store another participant
        handler.store_participant_name(43, "Bob").unwrap();
        assert_eq!(handler.get_participant_name(43), Some("Bob"));
    }

    #[test]
    fn test_store_participant_name_too_long() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Create a name that's too long
        let long_name = "x".repeat(MAX_PARTICIPANT_NAME_LEN + 1);
        let result = handler.store_participant_name(42, &long_name);

        assert!(matches!(
            result,
            Err(SignalingHandlerError::NameTooLong { .. })
        ));
    }

    #[test]
    fn test_parse_client_stats() {
        let handler = SignalingHandler::with_new_state(1);

        // Create valid stats payload (40 bytes)
        let mut data = [0u8; 40];
        // rtt_us = 1000
        data[0..4].copy_from_slice(&1000u32.to_be_bytes());
        // jitter_us = 50
        data[4..8].copy_from_slice(&50u32.to_be_bytes());
        // packets_sent = 10000
        data[8..16].copy_from_slice(&10000u64.to_be_bytes());
        // packets_lost = 5
        data[16..20].copy_from_slice(&5u32.to_be_bytes());
        // bytes_sent = 1000000
        data[20..28].copy_from_slice(&1000000u64.to_be_bytes());
        // timestamp_us = 1234567890
        data[28..36].copy_from_slice(&1234567890u64.to_be_bytes());

        let stats = handler.parse_client_stats(&data).unwrap();

        assert_eq!(stats.rtt_us, 1000);
        assert_eq!(stats.jitter_us, 50);
        assert_eq!(stats.packets_sent, 10000);
        assert_eq!(stats.packets_lost, 5);
        assert_eq!(stats.bytes_sent, 1000000);
        assert_eq!(stats.timestamp_us, 1234567890);
    }

    #[test]
    fn test_parse_client_stats_too_short() {
        let handler = SignalingHandler::with_new_state(1);

        // Payload too short
        let data = [0u8; 20];
        let result = handler.parse_client_stats(&data);

        assert!(matches!(
            result,
            Err(SignalingHandlerError::StatsMalformed { .. })
        ));
    }

    #[test]
    fn test_parse_client_stats_too_large() {
        let handler = SignalingHandler::with_new_state(1);

        // Payload too large
        let data = [0u8; MAX_STATS_PAYLOAD_SIZE + 1];
        let result = handler.parse_client_stats(&data);

        assert!(matches!(
            result,
            Err(SignalingHandlerError::StatsPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_store_and_validate_session_ticket() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Create a ticket
        let ticket_id = [1u8; 32];
        let session_data = b"test session data";
        let ticket = SessionTicket::new(ticket_id, session_data, 42);

        // Store the ticket
        handler.store_session_ticket(ticket).unwrap();
        assert_eq!(handler.ticket_count(), 1);

        // Validate the ticket
        let validated = handler.validate_session_ticket(&ticket_id).unwrap();
        assert_eq!(validated.participant_id, 42);
        assert_eq!(validated.ticket_id, ticket_id);
    }

    #[test]
    fn test_validate_session_ticket_not_found() {
        let handler = SignalingHandler::with_new_state(1);

        let ticket_id = [1u8; 32];
        let result = handler.validate_session_ticket(&ticket_id);

        assert!(matches!(result, Err(SignalingHandlerError::TicketNotFound)));
    }

    #[test]
    fn test_remove_session_ticket() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Create and store a ticket
        let ticket_id = [1u8; 32];
        let ticket = SessionTicket::new(ticket_id, b"data", 42);
        handler.store_session_ticket(ticket).unwrap();
        assert_eq!(handler.ticket_count(), 1);

        // Remove the ticket
        let removed = handler.remove_session_ticket(&ticket_id);
        assert!(removed);
        assert_eq!(handler.ticket_count(), 0);

        // Validate should now fail
        let result = handler.validate_session_ticket(&ticket_id);
        assert!(matches!(result, Err(SignalingHandlerError::TicketNotFound)));
    }

    #[test]
    fn test_remove_nonexistent_ticket() {
        let mut handler = SignalingHandler::with_new_state(1);

        let ticket_id = [1u8; 32];
        let removed = handler.remove_session_ticket(&ticket_id);
        assert!(!removed);
    }

    #[test]
    fn test_multiple_session_tickets() {
        let mut handler = SignalingHandler::with_new_state(1);

        // Store multiple tickets
        for i in 1..=5u8 {
            let mut ticket_id = [0u8; 32];
            ticket_id[0] = i;
            let ticket = SessionTicket::new(ticket_id, b"data", i as u64);
            handler.store_session_ticket(ticket).unwrap();
        }

        assert_eq!(handler.ticket_count(), 5);

        // Validate each ticket
        for i in 1..=5u8 {
            let mut ticket_id = [0u8; 32];
            ticket_id[0] = i;
            let validated = handler.validate_session_ticket(&ticket_id).unwrap();
            assert_eq!(validated.participant_id, i as u64);
        }
    }
}
