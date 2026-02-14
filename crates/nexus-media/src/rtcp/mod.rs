//! RTCP (RTP Control Protocol) packet parsing.
//!
//! Implements parsing of RTCP packets according to RFC 3550.
//! Supports Sender Reports (SR), Receiver Reports (RR),
//! Source Description (SDES), Goodbye (BYE), and transport/payload
//! feedback packet types (PLI, NACK).
//!
//! # RTCP Packet Format (RFC 3550)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|    RC   |   PT=SR=200   |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         SSRC of sender                        |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! ```

pub mod header;
pub mod packet;

pub use header::{
    RtcpHeader, RtcpType,
    RTCP_HEADER_MIN_SIZE_BYTES, RTCP_VERSION,
};
pub use packet::{
    SenderReport, ReceiverReportBlock, PliPacket, NackPacket,
    SenderReportGenerator, RembPacket, TransportCcFeedback,
    SENDER_REPORT_MIN_SIZE_BYTES,
    RECEIVER_REPORT_BLOCK_SIZE_BYTES,
    SENDER_REPORT_SIZE_BYTES,
    MAX_NACK_PACKETS,
    REMB_PACKET_LENGTH,
};
