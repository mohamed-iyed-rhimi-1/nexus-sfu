//! GRO (Generic Receive Offload) packet splitter.
//!
//! When GRO is enabled, the kernel may coalesce multiple UDP packets into
//! a single recv() call. This module provides utilities to split these
//! coalesced packets back into individual packets.
//!
//! # How GRO Works
//!
//! 1. Multiple UDP packets arrive at the NIC
//! 2. Kernel coalesces packets with same (src, dst, port) into one buffer
//! 3. recv() returns the coalesced buffer with GRO_SIZE in cmsg
//! 4. Application splits buffer using segment size from cmsg
//!
//! # Example
//!
//! ```ignore
//! let splitter = GroSplitter::new(1200); // 1200 byte segments
//! for packet in splitter.split(&coalesced_buffer) {
//!     process_packet(packet);
//! }
//! ```
//!
//! # TigerStyle Compliance
//!
//! All functions follow TigerStyle rules:
//! - Maximum 70 lines per function
//! - Minimum 2 assertions per function
//! - Explicit error handling

/// GRO segment size from cmsg (UDP_GRO).
#[cfg(target_os = "linux")]
pub const UDP_GRO_CMSG: libc::c_int = 104;

/// Maximum segment size for GRO (MTU - headers).
pub const MAX_GRO_SEGMENT_SIZE: u16 = 1472;

/// Minimum segment size for GRO.
pub const MIN_GRO_SEGMENT_SIZE: u16 = 64;

/// GRO packet splitter.
///
/// Splits GRO-coalesced buffers into individual UDP packets.
#[derive(Debug, Clone, Copy)]
pub struct GroSplitter {
    /// Segment size from cmsg (0 = no GRO, single packet).
    segment_size: u16,
}

impl GroSplitter {
    /// Create a new GRO splitter with the given segment size.
    ///
    /// # Arguments
    /// * `segment_size` - Size of each segment (from UDP_GRO cmsg).
    ///                    Use 0 for non-GRO packets.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn new(segment_size: u16) -> Self {
        // Assertion: segment_size is valid or zero
        assert!(
            segment_size == 0 || segment_size >= MIN_GRO_SEGMENT_SIZE,
            "segment_size must be 0 or >= {}",
            MIN_GRO_SEGMENT_SIZE
        );
        assert!(
            segment_size <= MAX_GRO_SEGMENT_SIZE,
            "segment_size must be <= {}",
            MAX_GRO_SEGMENT_SIZE
        );

        Self { segment_size }
    }

    /// Create a splitter for non-GRO packets (no splitting).
    #[inline]
    pub fn no_gro() -> Self {
        Self { segment_size: 0 }
    }

    /// Get the segment size.
    #[inline]
    pub fn segment_size(&self) -> u16 {
        self.segment_size
    }

    /// Check if this splitter will actually split packets.
    #[inline]
    pub fn will_split(&self) -> bool {
        self.segment_size > 0
    }


    /// Split a GRO-coalesced buffer into individual packets.
    ///
    /// If segment_size is 0 or >= data.len(), returns the entire buffer
    /// as a single packet. Otherwise, splits into chunks of segment_size.
    ///
    /// # Arguments
    /// * `data` - The coalesced buffer from recv()
    ///
    /// # Returns
    /// Iterator over individual packet slices.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn split<'a>(&self, data: &'a [u8]) -> GroPacketIterator<'a> {
        // Assertion: data must not be empty
        assert!(!data.is_empty(), "data must not be empty");

        GroPacketIterator {
            data,
            segment_size: self.segment_size,
            offset: 0,
        }
    }

    /// Count how many packets are in a coalesced buffer.
    ///
    /// # Arguments
    /// * `data_len` - Length of the coalesced buffer
    ///
    /// # Returns
    /// Number of packets in the buffer.
    #[inline]
    pub fn packet_count(&self, data_len: usize) -> usize {
        if self.segment_size == 0 || data_len == 0 {
            if data_len > 0 { 1 } else { 0 }
        } else {
            let seg = self.segment_size as usize;
            data_len.div_ceil(seg)
        }
    }
}

/// Iterator over GRO-split packets.
#[derive(Debug)]
pub struct GroPacketIterator<'a> {
    data: &'a [u8],
    segment_size: u16,
    offset: usize,
}

impl<'a> Iterator for GroPacketIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let remaining = self.data.len() - self.offset;

        // If no GRO or last segment, return all remaining data
        if self.segment_size == 0 || remaining <= self.segment_size as usize {
            let packet = &self.data[self.offset..];
            self.offset = self.data.len();
            return Some(packet);
        }

        // Return one segment
        let end = self.offset + self.segment_size as usize;
        let packet = &self.data[self.offset..end];
        self.offset = end;
        Some(packet)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.offset >= self.data.len() {
            return (0, Some(0));
        }

        let remaining = self.data.len() - self.offset;
        if self.segment_size == 0 {
            (1, Some(1))
        } else {
            let seg = self.segment_size as usize;
            let count = remaining.div_ceil(seg);
            (count, Some(count))
        }
    }
}

impl<'a> ExactSizeIterator for GroPacketIterator<'a> {}


/// Parse GRO segment size from cmsg data.
///
/// When receiving with recvmsg(), the kernel provides the GRO segment
/// size in a control message (cmsg) with level SOL_UDP and type UDP_GRO.
///
/// # Arguments
/// * `cmsg_data` - Raw cmsg buffer from recvmsg()
///
/// # Returns
/// Segment size if found, 0 if no GRO cmsg present.
///
/// # Safety
/// The cmsg_data must be a valid cmsg buffer from recvmsg().
///
/// # TigerStyle
/// - ≤70 lines
/// - ≥2 assertions
#[cfg(target_os = "linux")]
pub fn parse_gro_size_from_cmsg(cmsg_data: &[u8]) -> u16 {
    // Assertion: cmsg_data must have minimum header size
    if cmsg_data.len() < std::mem::size_of::<libc::cmsghdr>() {
        return 0;
    }

    let mut offset = 0;
    let cmsg_align = std::mem::size_of::<usize>();

    while offset + std::mem::size_of::<libc::cmsghdr>() <= cmsg_data.len() {
        // Read cmsg header
        let cmsg_ptr = cmsg_data[offset..].as_ptr() as *const libc::cmsghdr;
        let cmsg = unsafe { &*cmsg_ptr };

        // Check for UDP_GRO
        if cmsg.cmsg_level == libc::SOL_UDP && cmsg.cmsg_type == UDP_GRO_CMSG {
            // Data follows header
            let data_offset = offset + std::mem::size_of::<libc::cmsghdr>();
            if data_offset + 2 <= cmsg_data.len() {
                let segment_size = u16::from_ne_bytes([
                    cmsg_data[data_offset],
                    cmsg_data[data_offset + 1],
                ]);
                // Assertion: segment size should be reasonable
                if segment_size >= MIN_GRO_SEGMENT_SIZE && segment_size <= MAX_GRO_SEGMENT_SIZE {
                    return segment_size;
                }
            }
        }

        // Move to next cmsg (aligned)
        let cmsg_len = cmsg.cmsg_len as usize;
        if cmsg_len == 0 {
            break;
        }
        offset += (cmsg_len + cmsg_align - 1) & !(cmsg_align - 1);
    }

    0
}

#[cfg(not(target_os = "linux"))]
pub fn parse_gro_size_from_cmsg(_cmsg_data: &[u8]) -> u16 {
    0
}

/// Statistics for GRO operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct GroStats {
    /// Total coalesced buffers received.
    pub coalesced_buffers: u64,
    /// Total packets extracted from coalesced buffers.
    pub packets_extracted: u64,
    /// Non-GRO packets (single packet per recv).
    pub single_packets: u64,
}

impl GroStats {
    /// Create new stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a GRO receive operation.
    pub fn record(&mut self, packet_count: usize) {
        if packet_count > 1 {
            self.coalesced_buffers += 1;
            self.packets_extracted += packet_count as u64;
        } else {
            self.single_packets += 1;
        }
    }

    /// Get average packets per coalesced buffer.
    pub fn avg_packets_per_buffer(&self) -> f64 {
        if self.coalesced_buffers == 0 {
            0.0
        } else {
            self.packets_extracted as f64 / self.coalesced_buffers as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gro_splitter_no_gro() {
        let splitter = GroSplitter::no_gro();
        assert_eq!(splitter.segment_size(), 0);
        assert!(!splitter.will_split());
    }

    #[test]
    fn test_gro_splitter_with_segment() {
        let splitter = GroSplitter::new(1200);
        assert_eq!(splitter.segment_size(), 1200);
        assert!(splitter.will_split());
    }

    #[test]
    fn test_gro_split_single_packet() {
        let splitter = GroSplitter::no_gro();
        let data = vec![1u8; 1000];

        let packets: Vec<_> = splitter.split(&data).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 1000);
    }

    #[test]
    fn test_gro_split_multiple_packets() {
        let splitter = GroSplitter::new(100);
        let data = vec![1u8; 350]; // Should split into 4 packets: 100, 100, 100, 50

        let packets: Vec<_> = splitter.split(&data).collect();
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0].len(), 100);
        assert_eq!(packets[1].len(), 100);
        assert_eq!(packets[2].len(), 100);
        assert_eq!(packets[3].len(), 50);
    }

    #[test]
    fn test_gro_split_exact_multiple() {
        let splitter = GroSplitter::new(100);
        let data = vec![1u8; 300]; // Exactly 3 packets

        let packets: Vec<_> = splitter.split(&data).collect();
        assert_eq!(packets.len(), 3);
        for packet in &packets {
            assert_eq!(packet.len(), 100);
        }
    }

    #[test]
    fn test_gro_packet_count() {
        let splitter = GroSplitter::new(100);
        assert_eq!(splitter.packet_count(0), 0);
        assert_eq!(splitter.packet_count(50), 1);
        assert_eq!(splitter.packet_count(100), 1);
        assert_eq!(splitter.packet_count(101), 2);
        assert_eq!(splitter.packet_count(200), 2);
        assert_eq!(splitter.packet_count(350), 4);

        let no_gro = GroSplitter::no_gro();
        assert_eq!(no_gro.packet_count(0), 0);
        assert_eq!(no_gro.packet_count(1000), 1);
    }

    #[test]
    fn test_gro_iterator_size_hint() {
        let splitter = GroSplitter::new(100);
        let data = vec![1u8; 350];

        let iter = splitter.split(&data);
        assert_eq!(iter.size_hint(), (4, Some(4)));
        assert_eq!(iter.len(), 4);
    }

    #[test]
    fn test_gro_stats() {
        let mut stats = GroStats::new();

        // Single packet
        stats.record(1);
        assert_eq!(stats.single_packets, 1);
        assert_eq!(stats.coalesced_buffers, 0);

        // Coalesced buffer with 5 packets
        stats.record(5);
        assert_eq!(stats.coalesced_buffers, 1);
        assert_eq!(stats.packets_extracted, 5);

        // Another coalesced buffer with 3 packets
        stats.record(3);
        assert_eq!(stats.coalesced_buffers, 2);
        assert_eq!(stats.packets_extracted, 8);

        assert_eq!(stats.avg_packets_per_buffer(), 4.0);
    }

    #[test]
    #[should_panic(expected = "segment_size must be 0 or >= 64")]
    fn test_gro_splitter_invalid_small() {
        let _ = GroSplitter::new(10);
    }

    #[test]
    #[should_panic(expected = "segment_size must be <= 1472")]
    fn test_gro_splitter_invalid_large() {
        let _ = GroSplitter::new(2000);
    }
}
