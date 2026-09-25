//! nexus-media: RTP/RTCP parsing, codec-specific handlers,
//! and simulcast logic for the Nexus SFU crate ecosystem.
//!
//! This crate contains all media processing functionality:
//! - RTP header parsing with SIMD acceleration (SSE4.1, NEON)
//! - RTCP header and packet type parsing (SR, RR, SDES, BYE,
//!   feedback)
//! - Compound RTCP demuxing
//! - Codec-specific payload parsing (VP8, VP9, H264, AV1, Opus)
//! - Simulcast layer selection logic
//!
//! Depends only on nexus-core for shared types and error primitives.

#![deny(warnings)]

pub mod codec;
pub mod rtcp;
pub mod rtp;
pub mod simulcast;

pub use codec::{is_keyframe, MediaCodec};
pub use rtcp::{
    demux_compound, CompoundEntry, CompoundPacket, FirEntry, FirPacket, FirSeqTracker, NackPacket,
    PliPacket, ReceiverReport, ReceiverReportBlock, RembPacket, RtcpHeader, RtcpType, SenderReport,
    SenderReportGenerator, TransportCcFeedback, TwccFeedbackBuilder, MAX_NACK_PACKETS,
    MAX_REPORT_BLOCKS, REMB_PACKET_LENGTH,
};
pub use rtp::RtpHeader;
pub use simulcast::{
    select_layer, standard_layers, LayerSelector, SimulcastLayer, SimulcastLayerConfig, MAX_LAYERS,
};
