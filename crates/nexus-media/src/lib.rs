//! nexus-media: RTP/RTCP parsing, codec-specific handlers,
//! and simulcast logic for the Nexus SFU crate ecosystem.
//!
//! This crate contains all media processing functionality:
//! - RTP header parsing with SIMD acceleration (SSE4.1, NEON)
//! - RTCP header and packet type parsing (SR, RR, SDES, BYE,
//!   feedback)
//! - Codec-specific payload parsing (VP8, VP9, H264, AV1, Opus)
//! - Simulcast layer selection logic
//!
//! Depends only on nexus-core for shared types and error primitives.

#![deny(warnings)]

pub mod rtp;
pub mod rtcp;
pub mod codec;
pub mod simulcast;

// Re-export primary types at crate root for convenience.
// Re-export primary types at crate root for convenience.
pub use rtp::RtpHeader;
pub use rtcp::{
    RtcpHeader, RtcpType,
    SenderReport, ReceiverReportBlock,
    PliPacket, NackPacket, RembPacket, TransportCcFeedback,
    SenderReportGenerator,
    REMB_PACKET_LENGTH, MAX_NACK_PACKETS,
};
pub use simulcast::{
    SimulcastLayer, SimulcastLayerConfig,
    LayerSelector, select_layer, standard_layers,
    MAX_LAYERS,
};
