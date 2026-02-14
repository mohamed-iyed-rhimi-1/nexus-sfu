use serde::{Deserialize, Serialize};

/// Signal message types for WebRTC signaling.
///
/// These messages are exchanged between clients and the SFU for:
/// - Room management (join/leave)
/// - SDP negotiation (offer/answer)
/// - ICE candidate exchange
/// - Track subscription management
/// - Connection health (ping/pong)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalMessage {
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
        tracks: Vec<u64>,
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
    /// SDP offer.
    Offer {
        target_participant_id: Option<u64>,
        sdp: String,
    },
    /// SDP offer received from another participant.
    OfferReceived {
        from_participant_id: u64,
        sdp: String,
    },
    /// SDP answer.
    Answer {
        target_participant_id: u64,
        sdp: String,
    },
    /// SDP answer received from another participant.
    AnswerReceived {
        from_participant_id: u64,
        sdp: String,
    },
    /// ICE candidate.
    IceCandidate {
        target_participant_id: u64,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u32>,
    },
    /// End of ICE candidates signal (Trickle ICE, RFC 8838).
    EndOfCandidates,
    /// Client stats report.
    Stats {
        tracks_count: u32,
        packets_sent: u64,
        packets_received: u64,
        bytes_sent: u64,
        bytes_received: u64,
    },
    /// Error response.
    Error {
        code: String,
        message: String,
    },
    /// Ping (keepalive).
    Ping,
    /// Pong (keepalive response).
    Pong,
    /// Subscribe to a track.
    Subscribe {
        track_id: u64,
    },
    /// Subscription confirmed.
    Subscribed {
        track_id: u64,
        subscriber_id: u32,
    },
    /// Unsubscribe from a track.
    Unsubscribe {
        track_id: u64,
    },
    /// Unsubscription confirmed.
    Unsubscribed {
        track_id: u64,
    },
    /// Track published notification.
    TrackPublished {
        publisher_id: u64,
        track_id: u64,
        kind: String,
    },
    /// Track unpublished notification.
    TrackUnpublished {
        track_id: u64,
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

/// Track update message (server→client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackUpdateMessage {
    pub track_id: String,
    pub participant_id: String,
    pub kind: TrackKind,
    pub enabled: bool,
}

/// Track kind (audio or video).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrackKind {
    Audio,
    Video,
}
