pub mod server;

pub use server::{OrchestratorEvent, WebSocketServer};

// ============================================================================
// Shared Signaling Connections Registry
// ============================================================================

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::protocol::SignalMessage;

/// Maximum concurrent signaling connections.
pub const MAX_CONNECTIONS: u32 = 10_000;

/// Sender handle for a signaling connection.
pub struct SignalingConnectionHandle {
    /// Channel sender for outbound messages to this participant.
    pub sender: mpsc::Sender<SignalMessage>,
}

/// One signaling server's live connections, by participant ID. Owned by the
/// server (not process-global), so two servers in one process, as in the
/// end-to-end tests, never reach each other's clients.
pub type SignalingConnections = Arc<DashMap<u64, SignalingConnectionHandle>>;

/// Create an empty connections registry.
pub fn new_signaling_connections() -> SignalingConnections {
    Arc::new(DashMap::new())
}

/// Register a signaling connection for a participant.
pub fn register_signaling_connection(
    connections: &SignalingConnections,
    participant_id: u64,
    sender: mpsc::Sender<SignalMessage>,
) {
    assert!(participant_id != 0, "participant 0 is reserved");
    connections.insert(participant_id, SignalingConnectionHandle { sender });
}

/// Unregister a signaling connection for a participant.
pub fn unregister_signaling_connection(connections: &SignalingConnections, participant_id: u64) {
    connections.remove(&participant_id);
}
