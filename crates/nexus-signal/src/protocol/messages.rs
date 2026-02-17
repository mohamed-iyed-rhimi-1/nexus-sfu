use serde::{Deserialize, Serialize};

/// Signal message types for WebRTC signaling.
///
/// The SFU is the sole offerer — clients only send Answer.
/// This eliminates glare (JSEP §5.4) and ensures media only
/// flows after the client accepts the offer (RFC 3264 §8).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalMessage {
    // ── Room management ──

    /// Create a new room.
    Create {
        room_name: Option<String>,
    },
    /// Room created response.
    Created {
        room_id: u64,
        room_name: Option<String>,
    },
    /// Join an existing room by ID.
    Join {
        room_id: u64,
        participant_name: String,
    },
    /// Join room response.
    Joined {
        participant_id: u64,
        room_id: u64,
        participants: Vec<ParticipantInfo>,
        tracks: Vec<TrackInfo>,
    },
    /// Leave room request.
    Leave,
    /// Participant joined notification.
    ParticipantJoined {
        participant_id: u64,
        name: String,
    },
    /// Participant left notification.
    ParticipantLeft {
        participant_id: u64,
    },

    // ── SDP negotiation (SFU-driven) ──

    /// Client declares intent to publish media tracks.
    /// SFU responds with an Offer containing recvonly m-lines.
    Publish {
        kinds: Vec<String>,
        contents: Vec<String>,
    },
    /// Client stops publishing tracks.
    Unpublish {
        track_ids: Vec<u64>,
    },
    /// SDP offer from SFU to client (SFU is sole offerer).
    Offer {
        sdp: String,
    },
    /// SDP answer from client to SFU.
    /// Client's SDP contains SSRCs and codec parameters.
    Answer {
        sdp: String,
    },

    // ── ICE ──

    /// ICE candidate exchange (bidirectional).
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u32>,
    },
    /// End of ICE candidates signal (Trickle ICE, RFC 8838).
    EndOfCandidates,

    // ── Track subscription ──

    /// Subscribe to one or more tracks.
    /// SFU responds with Subscribed + Offer.
    Subscribe {
        track_ids: Vec<u64>,
    },
    /// Subscription confirmed (no media yet — wait for Offer/Answer).
    Subscribed {
        track_ids: Vec<u64>,
    },
    /// Unsubscribe from one or more tracks.
    Unsubscribe {
        track_ids: Vec<u64>,
    },
    /// Unsubscription confirmed.
    Unsubscribed {
        track_ids: Vec<u64>,
    },
    /// Track published notification (new track available in room).
    TrackPublished {
        publisher_id: u64,
        track_id: u64,
        kind: String,
        /// Content type: "camera", "screen", or "audio".
        content: String,
    },
    /// Track unpublished notification.
    TrackUnpublished {
        track_id: u64,
    },

    // ── Viewport optimization ──

    /// Update viewport (visible/pinned participants).
    Viewport {
        visible: Vec<u64>,
        pinned: Vec<u64>,
    },
    /// Viewport update acknowledged.
    ViewportUpdated {
        visible_count: u32,
        pinned_count: u32,
    },
    /// Declare content type for a published track.
    SetContent {
        track_id: u64,
        /// "camera", "screen", or "audio".
        content: String,
    },
    /// Content type set acknowledged.
    ContentSet {
        track_id: u64,
        content: String,
    },

    // ── Connection health ──

    /// Ping (keepalive).
    Ping,
    /// Pong (keepalive response).
    Pong,
    /// Client stats report.
    Stats {
        tracks_count: u32,
        packets_sent: u64,
        packets_received: u64,
        bytes_sent: u64,
        bytes_received: u64,
    },

    // ── Errors & shutdown ──

    /// Error response.
    Error {
        code: String,
        message: String,
    },
    /// Server shutdown notification.
    ServerShutdown {
        reason: String,
        drain_seconds: u32,
    },
}

impl SignalMessage {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Participant info for signaling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub id: u64,
    pub name: String,
}

/// Track info returned in Joined and TrackPublished.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackInfo {
    pub track_id: u64,
    pub publisher_id: u64,
    /// "audio" or "video".
    pub kind: String,
    /// "camera", "screen", or "audio".
    pub content: String,
}

/// Track kind (audio or video).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrackKind {
    Audio,
    Video,
}
