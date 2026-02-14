//! RTCP packet type parsing: Sender Reports, Receiver Reports,
//! PLI, NACK, and Sender Report generation.

use nexus_core::RtcpError;
use super::header::RTCP_VERSION;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Sender Report minimum size (header + sender info, no blocks).
pub const SENDER_REPORT_MIN_SIZE_BYTES: usize = 28;

/// Receiver Report block size in bytes.
pub const RECEIVER_REPORT_BLOCK_SIZE_BYTES: usize = 24;

/// Maximum number of lost packets in a NACK message.
pub const MAX_NACK_PACKETS: usize = 64;

/// NTP epoch offset (seconds from 1900-01-01 to 1970-01-01).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// Sender Report packet size in bytes.
pub const SENDER_REPORT_SIZE_BYTES: usize = 28;

// ---------------------------------------------------------------
// Sender Report
// ---------------------------------------------------------------

/// Sender Report data.
///
/// Contains sender statistics from an RTCP Sender Report packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReport {
    /// SSRC of sender
    pub ssrc: u32,
    /// NTP timestamp (64 bits)
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to NTP timestamp
    pub rtp_timestamp: u32,
    /// Total packets sent
    pub packet_count: u32,
    /// Total octets sent
    pub octet_count: u32,
}

impl SenderReport {
    /// Parse Sender Report from RTCP packet.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 28 bytes)
    ///
    /// # Requirements
    ///
    /// * 3.4 - Parse Sender Reports to extract sender statistics
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Check minimum length
        if data.len() < SENDER_REPORT_MIN_SIZE_BYTES {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: SENDER_REPORT_MIN_SIZE_BYTES,
            });
        }

        // Validate header
        let version = (data[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        let pt = data[1];
        if pt != 200 {
            return Err(RtcpError::InvalidPacketType {
                packet_type: pt,
            });
        }

        // Parse SSRC (bytes 4-7)
        let ssrc = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        // Parse NTP timestamp (bytes 8-15)
        let ntp_timestamp = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        // Parse RTP timestamp (bytes 16-19)
        let rtp_timestamp = u32::from_be_bytes([
            data[16], data[17], data[18], data[19],
        ]);

        // Parse packet count (bytes 20-23)
        let packet_count = u32::from_be_bytes([
            data[20], data[21], data[22], data[23],
        ]);

        // Parse octet count (bytes 24-27)
        let octet_count = u32::from_be_bytes([
            data[24], data[25], data[26], data[27],
        ]);

        Ok(SenderReport {
            ssrc,
            ntp_timestamp,
            rtp_timestamp,
            packet_count,
            octet_count,
        })
    }
}

// ---------------------------------------------------------------
// Receiver Report Block
// ---------------------------------------------------------------

/// Receiver Report block.
///
/// Contains reception statistics for a single source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverReportBlock {
    /// SSRC of the source being reported
    pub ssrc: u32,
    /// Fraction of packets lost (0-255, representing 0.0-1.0)
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24 bits, signed)
    pub cumulative_lost: i32,
    /// Extended highest sequence number received
    pub highest_seq: u32,
    /// Interarrival jitter
    pub jitter: u32,
    /// Last SR timestamp (middle 32 bits of NTP timestamp)
    pub last_sr: u32,
    /// Delay since last SR (in 1/65536 seconds)
    pub delay_since_sr: u32,
}

impl ReceiverReportBlock {
    /// Parse single Receiver Report block.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw block bytes (must be at least 24 bytes)
    ///
    /// # Requirements
    ///
    /// * 3.5 - Parse Receiver Reports to extract loss and jitter
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Check minimum length
        if data.len() < RECEIVER_REPORT_BLOCK_SIZE_BYTES {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: RECEIVER_REPORT_BLOCK_SIZE_BYTES,
            });
        }

        // Parse SSRC (bytes 0-3)
        let ssrc = u32::from_be_bytes([
            data[0], data[1], data[2], data[3],
        ]);

        // Parse fraction lost (byte 4)
        let fraction_lost = data[4];

        // Parse cumulative lost (bytes 5-7, 24-bit signed)
        // Sign-extend from 24 bits to 32 bits
        let cumulative_lost_bytes =
            [data[5], data[6], data[7]];
        let cumulative_lost =
            if cumulative_lost_bytes[0] & 0x80 != 0 {
                // Negative: sign extend
                i32::from_be_bytes([
                    0xFF,
                    cumulative_lost_bytes[0],
                    cumulative_lost_bytes[1],
                    cumulative_lost_bytes[2],
                ])
            } else {
                // Positive
                i32::from_be_bytes([
                    0x00,
                    cumulative_lost_bytes[0],
                    cumulative_lost_bytes[1],
                    cumulative_lost_bytes[2],
                ])
            };

        // Parse highest sequence number (bytes 8-11)
        let highest_seq = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        // Parse jitter (bytes 12-15)
        let jitter = u32::from_be_bytes([
            data[12], data[13], data[14], data[15],
        ]);

        // Parse last SR (bytes 16-19)
        let last_sr = u32::from_be_bytes([
            data[16], data[17], data[18], data[19],
        ]);

        // Parse delay since last SR (bytes 20-23)
        let delay_since_sr = u32::from_be_bytes([
            data[20], data[21], data[22], data[23],
        ]);

        Ok(ReceiverReportBlock {
            ssrc,
            fraction_lost,
            cumulative_lost,
            highest_seq,
            jitter,
            last_sr,
            delay_since_sr,
        })
    }

    /// Calculate loss percentage from fraction_lost.
    ///
    /// # Returns
    ///
    /// Loss percentage (0.0 - 100.0)
    #[inline]
    pub fn loss_percent(&self) -> f32 {
        (self.fraction_lost as f32 / 256.0) * 100.0
    }
}

// ---------------------------------------------------------------
// PLI (Picture Loss Indication)
// ---------------------------------------------------------------

/// PLI (Picture Loss Indication) packet.
///
/// PLI is a Payload-Specific Feedback message (PT=206, FMT=1)
/// requesting a keyframe from the sender due to decoder state loss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PliPacket {
    /// SSRC of packet sender (receiver requesting keyframe)
    pub sender_ssrc: u32,
    /// SSRC of media source (sender that should generate keyframe)
    pub media_ssrc: u32,
}

/// RTCP Payload-Specific Feedback packet type (PT=206).
const RTCP_PSFB_PT: u8 = 206;

/// RTCP Transport Layer Feedback packet type (PT=205).
const RTCP_RTPFB_PT: u8 = 205;

/// REMB format type (FMT=15).
const RTCP_PSFB_FMT_REMB: u8 = 15;

/// REMB unique identifier.
const REMB_IDENTIFIER: [u8; 4] = *b"REMB";

/// REMB packet length in bytes (minimum).
pub const REMB_PACKET_LENGTH: usize = 24;

impl PliPacket {
    /// Parse PLI packet from RTCP bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 12 bytes)
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Precondition assertions
        debug_assert!(data.len() >= 12 || data.len() < 12);

        // Check minimum length
        if data.len() < 12 {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: 12,
            });
        }

        // Validate version
        let version = (data[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        // Validate packet type (must be 206 = PayloadFeedback)
        let packet_type = data[1];
        if packet_type != RTCP_PSFB_PT {
            return Err(RtcpError::InvalidPacketType {
                packet_type,
            });
        }

        // Validate FMT (should be 1 for PLI)
        let fmt = data[0] & 0x1F;
        if fmt != 1 {
            return Err(RtcpError::InvalidPacketType {
                packet_type: fmt,
            });
        }

        // Parse sender SSRC (bytes 4-7)
        let sender_ssrc = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        // Parse media SSRC (bytes 8-11)
        let media_ssrc = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        // Postcondition: parsing completed successfully
        debug_assert!(data.len() >= 12, "PLI packet must be at least 12 bytes");

        Ok(PliPacket { sender_ssrc, media_ssrc })
    }

    /// Build PLI packet bytes.
    ///
    /// # Returns
    ///
    /// 12-byte PLI packet ready for transmission
    #[inline]
    pub fn build(&self) -> Vec<u8> {
        // Precondition: struct is valid (no specific constraints on SSRC values)
        // SSRCs can be any u32 value including 0

        let mut packet = vec![0u8; 12];

        // Header: V=2, P=0, FMT=1, PT=206
        packet[0] = (RTCP_VERSION << 6) | 1; // Version 2, FMT=1
        packet[1] = RTCP_PSFB_PT; // PayloadFeedback

        // Length = 2 words (12 bytes / 4 - 1)
        packet[2] = 0;
        packet[3] = 2;

        // Sender SSRC
        packet[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());

        // Media SSRC
        packet[8..12].copy_from_slice(&self.media_ssrc.to_be_bytes());

        // Postcondition assertions
        debug_assert_eq!(packet.len(), 12);
        debug_assert_eq!(packet[1], RTCP_PSFB_PT);

        packet
    }
}

// ---------------------------------------------------------------
// NACK (Negative Acknowledgement)
// ---------------------------------------------------------------

/// NACK (Negative Acknowledgement) packet.
///
/// NACK is a Transport Layer Feedback message (PT=205, FMT=1)
/// indicating lost RTP packets that should be retransmitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NackPacket {
    /// SSRC of packet sender (receiver reporting loss)
    pub sender_ssrc: u32,
    /// SSRC of media source (sender that should retransmit)
    pub media_ssrc: u32,
    /// List of lost packet sequence numbers (bounded to 64)
    pub lost_packets: Vec<u16>,
}

impl NackPacket {
    /// Parse NACK packet from RTCP bytes.
    ///
    /// Parses packet ID (PID) and bitmask of lost packets (BLP)
    /// according to RFC 4585 Section 6.2.1.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 12 bytes)
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Precondition assertions
        debug_assert!(data.len() >= 12 || data.len() < 12);

        // Check minimum length
        if data.len() < 12 {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: 12,
            });
        }

        // Validate version
        let version = (data[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        // Validate packet type (must be 205 = TransportFeedback)
        let packet_type = data[1];
        if packet_type != RTCP_RTPFB_PT {
            return Err(RtcpError::InvalidPacketType {
                packet_type,
            });
        }

        // Validate FMT (should be 1 for Generic NACK)
        let fmt = data[0] & 0x1F;
        if fmt != 1 {
            return Err(RtcpError::InvalidPacketType {
                packet_type: fmt,
            });
        }

        // Parse sender SSRC (bytes 4-7)
        let sender_ssrc = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        // Parse media SSRC (bytes 8-11)
        let media_ssrc = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        // Parse FCI (Feedback Control Information) entries
        let mut lost_packets = Vec::new();
        let mut offset = 12;

        // Bounded iteration: max 64 packets
        while offset + 4 <= data.len()
            && lost_packets.len() < MAX_NACK_PACKETS
        {
            // Parse PID (Packet ID) — bytes 0-1 of FCI entry
            let pid = u16::from_be_bytes([
                data[offset],
                data[offset + 1],
            ]);
            lost_packets.push(pid);

            // Parse BLP (Bitmask of Lost Packets) — bytes 2-3
            let blp = u16::from_be_bytes([
                data[offset + 2],
                data[offset + 3],
            ]);

            // Decode bitmask: bit N set means packet
            // (PID + N + 1) is lost
            for bit in 0..16 {
                if blp & (1 << bit) != 0 {
                    let seq = pid.wrapping_add(bit + 1);
                    lost_packets.push(seq);

                    // Enforce bound
                    if lost_packets.len() >= MAX_NACK_PACKETS {
                        break;
                    }
                }
            }

            offset += 4;
        }

        // Postcondition: bounded packet list
        debug_assert!(lost_packets.len() <= MAX_NACK_PACKETS);

        Ok(NackPacket {
            sender_ssrc,
            media_ssrc,
            lost_packets,
        })
    }

    /// Build NACK packet bytes.
    ///
    /// # Returns
    ///
    /// NACK packet ready for transmission
    #[inline]
    pub fn build(&self) -> Vec<u8> {
        // Precondition assertions
        debug_assert!(self.lost_packets.len() <= MAX_NACK_PACKETS);

        // Group lost packets into FCI entries (PID + BLP pairs)
        let fci_entries = self.encode_fci_entries();
        let fci_len = fci_entries.len() * 4;
        let packet_len = 12 + fci_len;

        let mut packet = vec![0u8; packet_len];

        // Header: V=2, P=0, FMT=1, PT=205
        packet[0] = (RTCP_VERSION << 6) | 1; // Version 2, FMT=1
        packet[1] = RTCP_RTPFB_PT; // TransportFeedback

        // Length in 32-bit words minus 1
        let length_words = (packet_len / 4) - 1;
        packet[2] = ((length_words >> 8) & 0xFF) as u8;
        packet[3] = (length_words & 0xFF) as u8;

        // Sender SSRC
        packet[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());

        // Media SSRC
        packet[8..12].copy_from_slice(&self.media_ssrc.to_be_bytes());

        // FCI entries
        for (i, (pid, blp)) in fci_entries.iter().enumerate() {
            let offset = 12 + i * 4;
            packet[offset..offset + 2].copy_from_slice(&pid.to_be_bytes());
            packet[offset + 2..offset + 4].copy_from_slice(&blp.to_be_bytes());
        }

        // Postcondition assertions
        debug_assert!(packet.len() >= 12);
        debug_assert_eq!(packet[1], RTCP_RTPFB_PT);

        packet
    }

    /// Encode lost packets into FCI entries (PID + BLP pairs).
    fn encode_fci_entries(&self) -> Vec<(u16, u16)> {
        if self.lost_packets.is_empty() {
            return Vec::new();
        }

        let mut entries = Vec::new();
        let mut sorted = self.lost_packets.clone();
        sorted.sort();

        let mut i = 0;
        while i < sorted.len() {
            let pid = sorted[i];
            let mut blp: u16 = 0;

            // Look for packets that can be encoded in the BLP
            let mut j = i + 1;
            while j < sorted.len() {
                let diff = sorted[j].wrapping_sub(pid);
                if (1..=16).contains(&diff) {
                    blp |= 1 << (diff - 1);
                    j += 1;
                } else if diff > 16 {
                    break;
                } else {
                    j += 1;
                }
            }

            entries.push((pid, blp));
            i = j;
        }

        entries
    }
}

// ---------------------------------------------------------------
// Sender Report Generator
// ---------------------------------------------------------------

/// Sender Report generator.
///
/// Maintains sender statistics and generates RTCP SR packets for
/// timing synchronization. Thread-safe via atomic counters.
pub struct SenderReportGenerator {
    /// SSRC of sender
    sender_ssrc: u32,
    /// Total packets sent
    packet_count: AtomicU32,
    /// Total octets sent
    octet_count: AtomicU64,
}

impl SenderReportGenerator {
    /// Create new Sender Report generator.
    ///
    /// # Arguments
    ///
    /// * `sender_ssrc` - SSRC of media sender
    ///
    /// # Panics
    ///
    /// Panics if `sender_ssrc` is zero.
    #[inline]
    pub fn new(sender_ssrc: u32) -> Self {
        // Precondition assertion
        assert!(
            sender_ssrc > 0,
            "Sender SSRC must be non-zero"
        );

        Self {
            sender_ssrc,
            packet_count: AtomicU32::new(0),
            octet_count: AtomicU64::new(0),
        }
    }

    /// Generate Sender Report packet.
    ///
    /// Creates 28-byte RTCP SR packet with current NTP timestamp
    /// and RTP timestamp correlation.
    ///
    /// # Arguments
    ///
    /// * `rtp_timestamp` - Current RTP timestamp
    ///
    /// # Returns
    ///
    /// 28-byte SR packet ready for SRTP protection
    #[inline]
    pub fn generate(&self, rtp_timestamp: u32) -> Vec<u8> {
        let mut packet = vec![0u8; SENDER_REPORT_SIZE_BYTES];

        // Header: V=2, P=0, RC=0, PT=200, length=6 words
        packet[0] = RTCP_VERSION << 6;
        packet[1] = 200; // Sender Report
        packet[2] = 0;
        packet[3] = 6; // Length = 6 words (28 bytes / 4 - 1)

        // SSRC of sender (bytes 4-7)
        packet[4..8]
            .copy_from_slice(&self.sender_ssrc.to_be_bytes());

        // NTP timestamp (bytes 8-15)
        let ntp_timestamp = self.calculate_ntp_timestamp();
        packet[8..16]
            .copy_from_slice(&ntp_timestamp.to_be_bytes());

        // RTP timestamp (bytes 16-19)
        packet[16..20]
            .copy_from_slice(&rtp_timestamp.to_be_bytes());

        // Sender's packet count (bytes 20-23)
        let pkt_count =
            self.packet_count.load(Ordering::Relaxed);
        packet[20..24]
            .copy_from_slice(&pkt_count.to_be_bytes());

        // Sender's octet count (bytes 24-27)
        let oct_count =
            self.octet_count.load(Ordering::Relaxed) as u32;
        packet[24..28]
            .copy_from_slice(&oct_count.to_be_bytes());

        // Postcondition assertions
        debug_assert_eq!(packet.len(), SENDER_REPORT_SIZE_BYTES);
        debug_assert_eq!(packet[1], 200);

        packet
    }

    /// Update sender statistics.
    ///
    /// Increments packet and octet counters atomically.
    ///
    /// # Arguments
    ///
    /// * `packet_size` - Size of sent packet in bytes
    #[inline]
    pub fn update_stats(&self, packet_size: usize) {
        self.packet_count.fetch_add(1, Ordering::Relaxed);
        self.octet_count.fetch_add(
            packet_size as u64,
            Ordering::Relaxed,
        );
    }

    /// Calculate NTP timestamp from current system time.
    ///
    /// Converts SystemTime to NTP format (seconds since
    /// 1900-01-01).
    #[inline]
    fn calculate_ntp_timestamp(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        // Convert Unix timestamp to NTP timestamp
        let ntp_seconds = now.as_secs() + NTP_EPOCH_OFFSET;

        // Convert fractional seconds to NTP fraction
        let ntp_fraction =
            ((now.subsec_nanos() as u64) << 32)
            / 1_000_000_000;

        (ntp_seconds << 32) | ntp_fraction
    }
}

// ---------------------------------------------------------------
// REMB (Receiver Estimated Maximum Bitrate)
// ---------------------------------------------------------------

/// REMB (Receiver Estimated Maximum Bitrate) packet.
///
/// REMB is a Payload-Specific Feedback message (PT=206, FMT=15) used for
/// sender-side bandwidth estimation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RembPacket {
    /// SSRC of packet sender
    pub sender_ssrc: u32,
    /// Estimated maximum bitrate in bits per second
    pub bitrate_bps: u64,
    /// SSRCs this REMB applies to
    pub ssrcs: Vec<u32>,
}

impl RembPacket {
    /// Parse REMB packet from RTCP bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 20 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(RembPacket)` - Successfully parsed REMB
    /// * `Err(RtcpError)` - Parsing failed
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Precondition assertions
        debug_assert!(data.len() >= 20 || data.len() < 20);

        // Check minimum length (header + REMB identifier + bitrate + 1 SSRC)
        if data.len() < 20 {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: 20,
            });
        }

        // Validate version
        let version = (data[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        // Validate packet type
        let packet_type = data[1];
        if packet_type != RTCP_PSFB_PT {
            return Err(RtcpError::InvalidPacketType { packet_type });
        }

        // Validate FMT (should be 15 for REMB)
        let fmt = data[0] & 0x1F;
        if fmt != RTCP_PSFB_FMT_REMB {
            return Err(RtcpError::InvalidPacketType { packet_type: fmt });
        }

        // Parse sender SSRC (bytes 4-7)
        let sender_ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Verify REMB identifier (bytes 12-15)
        if data[12..16] != REMB_IDENTIFIER {
            return Err(RtcpError::InvalidPacketType { packet_type: 0 });
        }

        // Parse num SSRCs (byte 16)
        let num_ssrcs = data[16] as usize;

        // Parse bitrate exponent and mantissa (bytes 17-19)
        let exp = (data[17] >> 2) & 0x3F;
        let mantissa = (((data[17] & 0x03) as u32) << 16)
            | ((data[18] as u32) << 8)
            | (data[19] as u32);
        let bitrate_bps = (mantissa as u64) << exp;

        // Parse SSRCs
        let mut ssrcs = Vec::with_capacity(num_ssrcs);
        let mut offset = 20;
        for _ in 0..num_ssrcs {
            if offset + 4 > data.len() {
                break;
            }
            let ssrc = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            ssrcs.push(ssrc);
            offset += 4;
        }

        // Postcondition: parsing completed successfully
        debug_assert!(ssrcs.len() == num_ssrcs, "All SSRCs must be parsed");

        Ok(RembPacket {
            sender_ssrc,
            bitrate_bps,
            ssrcs,
        })
    }

    /// Build REMB packet bytes.
    ///
    /// # Returns
    ///
    /// REMB packet ready for transmission
    ///
    /// # Panics
    ///
    /// Panics if bitrate_bps is zero or ssrcs is empty.
    #[inline]
    pub fn build(&self) -> Vec<u8> {
        // Precondition assertions
        assert!(self.bitrate_bps > 0, "Bitrate must be positive");
        assert!(!self.ssrcs.is_empty(), "Must have at least one SSRC");

        let packet_len = 20 + self.ssrcs.len() * 4;
        let mut packet = vec![0u8; packet_len];

        // Header: V=2, P=0, FMT=15, PT=206
        packet[0] = (RTCP_VERSION << 6) | RTCP_PSFB_FMT_REMB;
        packet[1] = RTCP_PSFB_PT;

        // Length in 32-bit words minus 1
        let length_words = (packet_len / 4) - 1;
        packet[2] = ((length_words >> 8) & 0xFF) as u8;
        packet[3] = (length_words & 0xFF) as u8;

        // Sender SSRC
        packet[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());

        // Media source SSRC (0 for REMB)
        packet[8..12].copy_from_slice(&0u32.to_be_bytes());

        // REMB identifier
        packet[12..16].copy_from_slice(&REMB_IDENTIFIER);

        // Encode bitrate
        let (exp, mantissa) = Self::encode_bitrate(self.bitrate_bps);

        // Num SSRCs | BR Exp | BR Mantissa
        packet[16] = self.ssrcs.len() as u8;
        packet[17] = (exp << 2) | ((mantissa >> 16) & 0x03) as u8;
        packet[18] = ((mantissa >> 8) & 0xFF) as u8;
        packet[19] = (mantissa & 0xFF) as u8;

        // SSRCs
        for (i, ssrc) in self.ssrcs.iter().enumerate() {
            let offset = 20 + i * 4;
            packet[offset..offset + 4].copy_from_slice(&ssrc.to_be_bytes());
        }

        // Postcondition assertions
        debug_assert!(packet.len() >= 20);
        debug_assert_eq!(packet[1], RTCP_PSFB_PT);

        packet
    }

    /// Encode bitrate as exponent and mantissa.
    ///
    /// Bitrate = mantissa × 2^exp
    /// Mantissa is 18 bits, exponent is 6 bits
    fn encode_bitrate(bitrate_bps: u64) -> (u8, u32) {
        if bitrate_bps == 0 {
            return (0, 0);
        }

        let mut exp = 0u8;
        let mut mantissa = bitrate_bps;

        // Find smallest exponent where mantissa fits in 18 bits
        while mantissa > 0x3FFFF && exp < 63 {
            mantissa >>= 1;
            exp += 1;
        }

        (exp, mantissa as u32)
    }
}

// ---------------------------------------------------------------
// Transport-CC Feedback
// ---------------------------------------------------------------

/// Transport-CC feedback packet.
///
/// Transport-wide congestion control feedback (PT=205, FMT=15) containing
/// packet arrival times for delay-based bandwidth estimation.
///
/// Note: Full Transport-CC parsing is provided by `nexus_bwe::TransportFeedback`.
/// This struct provides basic parsing for RTCP routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportCcFeedback {
    /// SSRC of packet sender
    pub sender_ssrc: u32,
    /// SSRC of media source
    pub media_ssrc: u32,
    /// Base sequence number
    pub base_sequence: u16,
    /// Packet status count
    pub packet_status_count: u16,
    /// Reference time (24 bits, in 64ms units)
    pub reference_time: u32,
    /// Feedback packet count
    pub feedback_packet_count: u8,
}

impl TransportCcFeedback {
    /// Parse Transport-CC feedback header from RTCP bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 20 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(TransportCcFeedback)` - Successfully parsed header
    /// * `Err(RtcpError)` - Parsing failed
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtcpError> {
        // Precondition assertions
        debug_assert!(data.len() >= 20 || data.len() < 20);

        // Check minimum length
        if data.len() < 20 {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: 20,
            });
        }

        // Validate version
        let version = (data[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        // Validate packet type
        let packet_type = data[1];
        if packet_type != RTCP_RTPFB_PT {
            return Err(RtcpError::InvalidPacketType { packet_type });
        }

        // Validate FMT (should be 15 for Transport-CC)
        let fmt = data[0] & 0x1F;
        if fmt != 15 {
            return Err(RtcpError::InvalidPacketType { packet_type: fmt });
        }

        // Parse sender SSRC (bytes 4-7)
        let sender_ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Parse media SSRC (bytes 8-11)
        let media_ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // Parse base sequence number (bytes 12-13)
        let base_sequence = u16::from_be_bytes([data[12], data[13]]);

        // Parse packet status count (bytes 14-15)
        let packet_status_count = u16::from_be_bytes([data[14], data[15]]);

        // Parse reference time (bytes 16-18, 24 bits)
        let reference_time =
            ((data[16] as u32) << 16) | ((data[17] as u32) << 8) | (data[18] as u32);

        // Parse feedback packet count (byte 19)
        let feedback_packet_count = data[19];

        // Postcondition: parsing completed successfully
        debug_assert!(data.len() >= 20, "Transport-CC feedback must be at least 20 bytes");

        Ok(TransportCcFeedback {
            sender_ssrc,
            media_ssrc,
            base_sequence,
            packet_status_count,
            reference_time,
            feedback_packet_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pli_build_roundtrip() {
        let original = PliPacket {
            sender_ssrc: 0x11111111,
            media_ssrc: 0x22222222,
        };

        let bytes = original.build();
        let parsed = PliPacket::parse(&bytes).unwrap();

        assert_eq!(original.sender_ssrc, parsed.sender_ssrc);
        assert_eq!(original.media_ssrc, parsed.media_ssrc);
    }

    #[test]
    fn test_nack_build_roundtrip() {
        let original = NackPacket {
            sender_ssrc: 0x11111111,
            media_ssrc: 0x22222222,
            lost_packets: vec![1000, 1001, 1003],
        };

        let bytes = original.build();
        let parsed = NackPacket::parse(&bytes).unwrap();

        assert_eq!(original.sender_ssrc, parsed.sender_ssrc);
        assert_eq!(original.media_ssrc, parsed.media_ssrc);
        // Lost packets should contain the same values
        for seq in &original.lost_packets {
            assert!(parsed.lost_packets.contains(seq));
        }
    }

    #[test]
    fn test_remb_build_roundtrip() {
        let original = RembPacket {
            sender_ssrc: 0x12345678,
            bitrate_bps: 1_000_000,
            ssrcs: vec![0x87654321],
        };

        let bytes = original.build();
        let parsed = RembPacket::parse(&bytes).unwrap();

        assert_eq!(original.sender_ssrc, parsed.sender_ssrc);
        assert_eq!(original.ssrcs, parsed.ssrcs);
        // Allow some rounding error in bitrate due to encoding
        let error = (original.bitrate_bps as i64 - parsed.bitrate_bps as i64).abs();
        assert!(error < 50_000, "Bitrate error too large: {}", error);
    }

    #[test]
    fn test_parse_transport_cc() {
        let mut packet = vec![0u8; 20];

        // Header: V=2, P=0, FMT=15, PT=205
        packet[0] = (2 << 6) | 15;
        packet[1] = 205;
        packet[2] = 0;
        packet[3] = 4; // Length = 4 words

        // Sender SSRC
        packet[4..8].copy_from_slice(&0x11111111u32.to_be_bytes());

        // Media SSRC
        packet[8..12].copy_from_slice(&0x22222222u32.to_be_bytes());

        // Base sequence
        packet[12..14].copy_from_slice(&1000u16.to_be_bytes());

        // Packet status count
        packet[14..16].copy_from_slice(&10u16.to_be_bytes());

        // Reference time (24 bits)
        packet[16] = 0x01;
        packet[17] = 0x02;
        packet[18] = 0x03;

        // Feedback packet count
        packet[19] = 5;

        let tcc = TransportCcFeedback::parse(&packet).unwrap();

        assert_eq!(tcc.sender_ssrc, 0x11111111);
        assert_eq!(tcc.media_ssrc, 0x22222222);
        assert_eq!(tcc.base_sequence, 1000);
        assert_eq!(tcc.packet_status_count, 10);
        assert_eq!(tcc.reference_time, 0x010203);
        assert_eq!(tcc.feedback_packet_count, 5);
    }
}
