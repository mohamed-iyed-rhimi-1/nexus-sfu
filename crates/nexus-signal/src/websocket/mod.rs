pub mod server;
pub mod handler;

pub use server::{WebSocketServer, OrchestratorEvent};
pub use handler::{
    SignalingHandler, SignalingHandlerError, SessionTicket,
    ClientStats, JoinResponse, MessageType, TrackEntry,
    MessageHandler, MessageHandlerTable,
    MAX_SESSION_TICKETS, TICKET_LIFETIME_SECS,
    MAX_PARTICIPANT_NAME_LEN, MAX_STATS_PAYLOAD_SIZE, MAX_TRACKS_IN_RESPONSE,
    error_codes as handler_error_codes,
};

// ============================================================================
// Shared Signaling Connections Registry
// ============================================================================

use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::protocol::SignalMessage;

/// Maximum concurrent signaling connections.
pub const MAX_CONNECTIONS: u32 = 10_000;

/// Sender handle for a signaling connection.
pub struct SignalingConnectionHandle {
    /// Channel sender for outbound messages to this participant.
    pub sender: mpsc::UnboundedSender<SignalMessage>,
}

/// Get the global signaling connections registry.
pub fn signaling_connections() -> &'static Arc<DashMap<u64, SignalingConnectionHandle>> {
    use std::sync::OnceLock;
    static CONNECTIONS: OnceLock<Arc<DashMap<u64, SignalingConnectionHandle>>> = OnceLock::new();
    CONNECTIONS.get_or_init(|| Arc::new(DashMap::new()))
}

/// Register a signaling connection for a participant.
pub fn register_signaling_connection(participant_id: u64, sender: mpsc::UnboundedSender<SignalMessage>) {
    signaling_connections().insert(participant_id, SignalingConnectionHandle { sender });
}

/// Unregister a signaling connection for a participant.
pub fn unregister_signaling_connection(participant_id: u64) {
    signaling_connections().remove(&participant_id);
}
