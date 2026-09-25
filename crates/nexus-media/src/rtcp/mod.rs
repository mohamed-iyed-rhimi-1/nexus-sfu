//! RTCP (RTP Control Protocol) packet parsing.
//!
//! Implements parsing of RTCP packets according to RFC 3550.
//! Supports Sender Reports (SR), Receiver Reports (RR),
//! Source Description (SDES), Goodbye (BYE), and transport/payload
//! feedback packet types (PLI, NACK, FIR, REMB, Transport-CC).
//!
//! Compound RTCP packets (multiple RTCP packets in one UDP datagram)
//! are handled by the `compound` module.

pub mod compound;
pub mod header;
pub mod packet;
pub mod scheduler;

pub use compound::{demux_compound, CompoundEntry, CompoundPacket};
pub use header::{RtcpHeader, RtcpType, RTCP_HEADER_MIN_SIZE_BYTES, RTCP_VERSION};
pub use packet::{
    FirEntry, FirPacket, FirSeqTracker, NackPacket, PliPacket, ReceiverReport, ReceiverReportBlock,
    RembPacket, SenderReport, SenderReportGenerator, TransportCcFeedback, TwccFeedbackBuilder,
    MAX_NACK_PACKETS, MAX_REPORT_BLOCKS, RECEIVER_REPORT_BLOCK_SIZE_BYTES,
    RECEIVER_REPORT_MIN_SIZE_BYTES, REMB_PACKET_LENGTH, SENDER_REPORT_MIN_SIZE_BYTES,
    SENDER_REPORT_SIZE_BYTES,
};
pub use scheduler::RtcpScheduler;
