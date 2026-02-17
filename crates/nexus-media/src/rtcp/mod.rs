//! RTCP (RTP Control Protocol) packet parsing.
//!
//! Implements parsing of RTCP packets according to RFC 3550.
//! Supports Sender Reports (SR), Receiver Reports (RR),
//! Source Description (SDES), Goodbye (BYE), and transport/payload
//! feedback packet types (PLI, NACK, FIR, REMB, Transport-CC).
//!
//! Compound RTCP packets (multiple RTCP packets in one UDP datagram)
//! are handled by the `compound` module.

pub mod header;
pub mod packet;
pub mod compound;

pub use header::{
    RtcpHeader, RtcpType,
    RTCP_HEADER_MIN_SIZE_BYTES, RTCP_VERSION,
};
pub use packet::{
    SenderReport, ReceiverReportBlock, ReceiverReport,
    PliPacket, NackPacket, RembPacket, TransportCcFeedback,
    FirPacket, FirEntry,
    SenderReportGenerator,
    SENDER_REPORT_MIN_SIZE_BYTES,
    RECEIVER_REPORT_MIN_SIZE_BYTES,
    RECEIVER_REPORT_BLOCK_SIZE_BYTES,
    SENDER_REPORT_SIZE_BYTES,
    MAX_NACK_PACKETS,
    MAX_REPORT_BLOCKS,
    REMB_PACKET_LENGTH,
    TwccFeedbackBuilder,
};
pub use compound::{demux_compound, CompoundPacket, CompoundEntry};
