//! Compound RTCP packet demuxer (RFC 3550 §6.1).
//!
//! RTCP packets are sent as compound packets: a single UDP
//! datagram containing multiple RTCP packets concatenated.
//! This module provides an iterator that yields individual
//! RTCP packets from a compound datagram.

use nexus_core::RtcpError;
use super::header::{RtcpHeader, RTCP_HEADER_MIN_SIZE_BYTES, RTCP_VERSION};

/// Maximum number of RTCP packets in a compound packet.
/// RFC 3550 doesn't specify a limit, but 16 is generous
/// for real-world traffic (typically SR + SDES + feedback).
const MAX_COMPOUND_PACKETS: usize = 16;

/// Parsed sub-packet from a compound RTCP datagram.
#[derive(Clone, Debug)]
pub struct CompoundEntry<'a> {
    /// Parsed RTCP header
    pub header: RtcpHeader,
    /// Raw bytes of this individual RTCP packet (including header)
    pub data: &'a [u8],
}

/// Iterate over individual RTCP packets in a compound datagram.
///
/// Returns up to `MAX_COMPOUND_PACKETS` entries. Stops on the
/// first malformed sub-packet or when the buffer is exhausted.
///
/// # Arguments
///
/// * `data` - Raw UDP datagram containing compound RTCP
pub fn demux_compound(data: &[u8]) -> Result<CompoundPacket<'_>, RtcpError> {
    let mut entries = CompoundPacket {
        entries: [const { None }; MAX_COMPOUND_PACKETS],
        count: 0,
    };

    let mut offset: usize = 0;

    while offset + RTCP_HEADER_MIN_SIZE_BYTES <= data.len()
        && entries.count < MAX_COMPOUND_PACKETS
    {
        // Validate version before full parse
        let version = (data[offset] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion { version });
        }

        let header = RtcpHeader::parse(&data[offset..])?;
        let packet_len = header.packet_len_bytes();

        if packet_len < 4 || offset + packet_len > data.len() {
            return Err(RtcpError::TooShort {
                actual_bytes: data.len() - offset,
                min_bytes: packet_len,
            });
        }

        let packet_data = &data[offset..offset + packet_len];
        entries.entries[entries.count] = Some(CompoundEntry {
            header,
            data: packet_data,
        });
        entries.count += 1;
        offset += packet_len;
    }

    Ok(entries)
}

/// Collection of RTCP sub-packets from a compound datagram.
///
/// Fixed-size array to avoid allocation. Access via `iter()`.
pub struct CompoundPacket<'a> {
    entries: [Option<CompoundEntry<'a>>; MAX_COMPOUND_PACKETS],
    count: usize,
}

impl<'a> CompoundPacket<'a> {
    /// Number of RTCP packets in this compound.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no packets were parsed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over parsed sub-packets.
    pub fn iter(&self) -> impl Iterator<Item = &CompoundEntry<'a>> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
    }
}
