#![allow(clippy::len_zero)]
#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::let_and_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::eq_op)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::get_first)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::derivable_impls)]
#![deny(warnings)]

pub mod config;
pub mod error;
pub mod metrics;
pub mod protocol;
pub mod quic;
pub mod websocket;

pub use config::QuicConfig;
pub use error::SignalError;
pub use metrics::SignalMetrics;
pub use protocol::{OfferTrack, ParticipantInfo, SignalMessage, TrackInfo, TrackKind};
pub use quic::{QuicConnection, QuicSignaling, SessionStore, SessionTicket};

// WebSocket server types (moved from src/signal/)
pub use websocket::{
    handler_error_codes,
    register_signaling_connection,
    signaling_connections,
    unregister_signaling_connection,
    ClientStats,
    JoinResponse,
    MessageType,
    OrchestratorEvent,
    // Connection registry
    SignalingConnectionHandle,
    SignalingHandler,
    SignalingHandlerError,
    TrackEntry,
    WebSocketServer,
    MAX_CONNECTIONS,
    MAX_PARTICIPANT_NAME_LEN,
    MAX_SESSION_TICKETS,
    MAX_STATS_PAYLOAD_SIZE,
    MAX_TRACKS_IN_RESPONSE,
    TICKET_LIFETIME_SECS,
};
