//! RTCP Transport-Wide Congestion Control (TWCC) feedback parsing.
//!
//! Implements RFC 8888 for extracting packet arrival times.

use thiserror::Error;

/// Maximum packets in single feedback message.
pub const MAX_FEEDBACK_PACKETS: usize = 256;

/// Transport feedback error types.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FeedbackError {
    #[error("Packet too short: {actual_bytes} bytes, need {min_bytes}")]
    TooShort { actual_bytes: usize, min_bytes: usize },

    #[error("Invalid packet count: {count}")]
    InvalidPacketCount { count: usize },
}

/// Packet arrival information from TWCC feedback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketArrivalInfo {
    /// Sequence number (transport-wide).
    pub sequence: u16,

    /// Send time in microseconds.
    pub send_time_us: u64,

    /// Receive time in microseconds.
    pub recv_time_us: u64,

    /// Packet size in bytes.
    pub size_bytes: u16,
}

/// Transport-wide congestion control feedback.
///
/// Contains packet arrival times for delay-based BWE.
#[derive(Clone, Debug)]
pub struct TransportFeedback {
    /// SSRC of media source.
    pub ssrc: u32,

    /// Base sequence number.
    pub base_sequence: u16,

    /// Packet arrival information (pre-allocated, fixed size).
    packets: [Option<PacketArrivalInfo>; MAX_FEEDBACK_PACKETS],

    /// Number of valid packets.
    packet_count: usize,
}

impl TransportFeedback {
    /// Create new transport feedback.
    ///
    /// # Assertions
    /// - ssrc > 0
    pub fn new(ssrc: u32, base_sequence: u16) -> Self {
        assert!(ssrc > 0, "ssrc must be > 0");

        Self {
            ssrc,
            base_sequence,
            packets: [None; MAX_FEEDBACK_PACKETS],
            packet_count: 0,
        }
    }

    /// Add packet arrival info.
    ///
    /// # Arguments
    /// - `info`: Packet arrival information
    ///
    /// # Returns
    /// - `Ok(())` if added successfully
    /// - `Err` if feedback is full
    ///
    /// # Assertions
    /// - recv_time_us >= send_time_us (causality)
    /// - size_bytes > 0
    pub fn add_packet(&mut self, info: PacketArrivalInfo) -> Result<(), FeedbackError> {
        assert!(
            info.recv_time_us >= info.send_time_us,
            "recv_time must be >= send_time (causality)"
        );
        assert!(info.size_bytes > 0, "size_bytes must be > 0");

        if self.packet_count >= MAX_FEEDBACK_PACKETS {
            return Err(FeedbackError::InvalidPacketCount {
                count: self.packet_count,
            });
        }

        self.packets[self.packet_count] = Some(info);
        self.packet_count += 1;
        Ok(())
    }

    /// Get packet count.
    #[inline]
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    /// Iterate over packets.
    pub fn packets(&self) -> impl Iterator<Item = &PacketArrivalInfo> {
        self.packets[..self.packet_count]
            .iter()
            .filter_map(|p| p.as_ref())
    }
}
