//! Session lifecycle events emitted by ConnectionMonitor.
//!
//! These events bridge the connection layer (ICE/DTLS state machine)
//! with the orchestrator (subscription activation, room cleanup).

use std::net::SocketAddr;

/// Session lifecycle event detected by ConnectionMonitor.
///
/// Emitted when a WebRTC session transitions to a terminal-ish state
/// that requires orchestrator action.
#[derive(Debug)]
pub enum SessionEvent {
    /// DTLS handshake complete, SRTP keys derived — media can flow.
    /// Triggers deferred subscriber activation in SubscriptionManager.
    Established { session_id: u64 },
    /// Session is dead. Triggers participant cleanup in RoomManager.
    Disconnected {
        session_id: u64,
        reason: DisconnectReason,
    },
}

/// Why a session was disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// RFC 7675: peer stopped responding to consent checks.
    ConsentExpired,
    /// ICE connectivity checks failed (no valid pair found).
    IceFailed,
    /// No activity for SESSION_IDLE_TIMEOUT_SECS.
    IdleTimeout,
}

/// Raw cold-path packet forwarded from the packet loop to ConnectionMonitor.
#[derive(Debug)]
pub struct ColdPathPacket {
    pub data: Vec<u8>,
    pub source_addr: SocketAddr,
}
