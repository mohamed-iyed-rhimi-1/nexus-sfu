//! RTCP header parsing and packet type identification.

use nexus_core::RtcpError;

/// Minimum RTCP header size in bytes.
pub const RTCP_HEADER_MIN_SIZE_BYTES: usize = 8;

/// RTCP version (always 2).
pub const RTCP_VERSION: u8 = 2;

/// RTCP packet types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpType {
    /// Sender Report (PT=200)
    SenderReport,
    /// Receiver Report (PT=201)
    ReceiverReport,
    /// Source Description (PT=202)
    SourceDescription,
    /// Goodbye (PT=203)
    Goodbye,
    /// Application-Defined (PT=204)
    ApplicationDefined,
    /// Transport Layer Feedback (PT=205)
    TransportFeedback,
    /// Payload-Specific Feedback (PT=206)
    PayloadFeedback,
    /// Extended Reports (PT=207)
    ExtendedReports,
    /// Unknown packet type
    Unknown(u8),
}

impl RtcpType {
    /// Convert packet type byte to enum variant.
    #[inline]
    pub fn from_byte(pt: u8) -> Self {
        match pt {
            200 => RtcpType::SenderReport,
            201 => RtcpType::ReceiverReport,
            202 => RtcpType::SourceDescription,
            203 => RtcpType::Goodbye,
            204 => RtcpType::ApplicationDefined,
            205 => RtcpType::TransportFeedback,
            206 => RtcpType::PayloadFeedback,
            207 => RtcpType::ExtendedReports,
            _ => RtcpType::Unknown(pt),
        }
    }

    /// Convert enum variant to packet type byte.
    #[inline]
    pub fn to_byte(self) -> u8 {
        match self {
            RtcpType::SenderReport => 200,
            RtcpType::ReceiverReport => 201,
            RtcpType::SourceDescription => 202,
            RtcpType::Goodbye => 203,
            RtcpType::ApplicationDefined => 204,
            RtcpType::TransportFeedback => 205,
            RtcpType::PayloadFeedback => 206,
            RtcpType::ExtendedReports => 207,
            RtcpType::Unknown(pt) => pt,
        }
    }
}

/// Parsed RTCP packet header.
///
/// Common header for all RTCP packet types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtcpHeader {
    /// RTCP version (2 bits, must be 2)
    pub version: u8,
    /// Padding flag (1 bit)
    pub padding: bool,
    /// Reception report count or subtype (5 bits)
    pub count: u8,
    /// Packet type
    pub packet_type: RtcpType,
    /// Length in 32-bit words minus one
    pub length_words: u16,
    /// SSRC of packet sender
    pub ssrc: u32,
}

impl RtcpHeader {
    /// Parse RTCP header from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 8 bytes)
    ///
    /// # Requirements
    ///
    /// * 3.2 - Identify packet type (SR, RR, SDES, BYE, APP,
    ///         or feedback)
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Check minimum length
        if data.len() < RTCP_HEADER_MIN_SIZE_BYTES {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: RTCP_HEADER_MIN_SIZE_BYTES,
            });
        }

        // Parse first byte: V(2) P(1) RC(5)
        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let count = first_byte & 0x1F;

        // Validate version
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        // Parse packet type (byte 1)
        let pt_byte = data[1];
        let packet_type = RtcpType::from_byte(pt_byte);

        // Parse length in 32-bit words minus one (bytes 2-3)
        let length_words =
            u16::from_be_bytes([data[2], data[3]]);

        // Parse SSRC (bytes 4-7)
        let ssrc = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        Ok(RtcpHeader {
            version,
            padding,
            count,
            packet_type,
            length_words,
            ssrc,
        })
    }

    /// Get total packet length in bytes.
    #[inline]
    pub fn packet_len_bytes(&self) -> usize {
        ((self.length_words as usize) + 1) * 4
    }
}
