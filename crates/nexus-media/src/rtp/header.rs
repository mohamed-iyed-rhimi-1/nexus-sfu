//! RTP header parsing, validation, and serialization.
//!
//! Contains the core `RtpHeader` struct with scalar and SIMD
//! parsing implementations. All methods are `#[inline]` for
//! hot-path performance.

use nexus_core::RtpError;

// SIMD intrinsics for accelerated parsing
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

/// Minimum RTP header size in bytes (without CSRC or extensions).
pub const RTP_HEADER_MIN_SIZE_BYTES: usize = 12;

/// Maximum CSRC count (4 bits = 0-15).
pub const RTP_MAX_CSRC_COUNT: u8 = 15;

/// Size of each CSRC entry in bytes.
pub const RTP_CSRC_SIZE_BYTES: usize = 4;

/// RTP version (always 2).
pub const RTP_VERSION: u8 = 2;

/// Parsed RTP header fields.
///
/// Contains all fields from the RTP fixed header plus computed
/// values like total header length. CSRC list is not stored but
/// can be accessed via the original packet data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpHeader {
    /// RTP version (2 bits, must be 2)
    pub version: u8,
    /// Padding flag (1 bit)
    pub padding: bool,
    /// Extension flag (1 bit)
    pub extension: bool,
    /// CSRC count (4 bits, 0-15)
    pub csrc_count: u8,
    /// Marker bit (1 bit)
    pub marker: bool,
    /// Payload type (7 bits, 0-127)
    pub payload_type: u8,
    /// Sequence number (16 bits)
    pub sequence_number: u16,
    /// Timestamp (32 bits)
    pub timestamp: u32,
    /// Synchronization source identifier (32 bits)
    pub ssrc: u32,
    /// Total header length in bytes (including CSRC and extension)
    pub header_len_bytes: u8,
}

impl RtpHeader {
    /// Parse RTP header from bytes.
    ///
    /// Extracts all header fields and validates the packet structure.
    /// Returns an error for malformed packets.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 12 bytes)
    ///
    /// # Requirements
    ///
    /// * 3.1 - Extract version, padding, extension, CSRC count,
    ///         marker, payload type, sequence number, timestamp,
    ///         and SSRC fields
    /// * 3.6 - Parse header extensions when present
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtpError> {
        // Check minimum length
        if data.len() < RTP_HEADER_MIN_SIZE_BYTES {
            return Err(RtpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: RTP_HEADER_MIN_SIZE_BYTES,
            });
        }

        // Parse first byte: V(2) P(1) X(1) CC(4)
        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        // Validate version (must be 2)
        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion { version });
        }

        // Parse second byte: M(1) PT(7)
        let second_byte = data[1];
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

        // Parse sequence number (bytes 2-3, big-endian)
        let sequence_number =
            u16::from_be_bytes([data[2], data[3]]);

        // Parse timestamp (bytes 4-7, big-endian)
        let timestamp = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        // Parse SSRC (bytes 8-11, big-endian)
        let ssrc = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        // Calculate header length with CSRC
        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        // Validate CSRC count against available bytes
        if data.len() < header_after_csrc {
            return Err(RtpError::InvalidCsrcCount {
                count: csrc_count,
                available_bytes: data.len()
                    - RTP_HEADER_MIN_SIZE_BYTES,
            });
        }

        // Calculate total header length including extension
        let mut header_len_bytes = header_after_csrc;

        if extension {
            // Extension header format:
            // 2 bytes: defined by profile
            // 2 bytes: length in 32-bit words (excl. 4-byte hdr)
            let ext_header_start = header_after_csrc;

            // Need at least 4 bytes for extension header
            if data.len() < ext_header_start + 4 {
                return Err(RtpError::InvalidExtension);
            }

            // Parse extension length (in 32-bit words)
            let ext_len_words = u16::from_be_bytes([
                data[ext_header_start + 2],
                data[ext_header_start + 3],
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;

            // Total extension size = 4 byte header + ext data
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            // Validate extension fits in packet
            if data.len() < header_len_bytes {
                return Err(RtpError::InvalidExtension);
            }
        }

        // Assertion: header length is reasonable
        debug_assert!(
            header_len_bytes <= 255,
            "RTP header length {} exceeds u8 max",
            header_len_bytes
        );

        Ok(RtpHeader {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            header_len_bytes: header_len_bytes as u8,
        })
    }

    /// Parse RTP header with SIMD acceleration.
    ///
    /// Auto-selects the fastest available implementation:
    /// - **x86_64 with SSE4.1**: 128-bit SIMD loads
    /// - **aarch64**: NEON intrinsics
    /// - **Fallback**: Standard byte-by-byte parsing
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes (must be at least 12 bytes)
    ///
    /// # Returns
    ///
    /// * `Some(RtpHeader)` - Successfully parsed header
    /// * `None` - Parsing failed
    #[inline(always)]
    pub fn parse_simd(data: &[u8]) -> Option<Self> {
        // Quick length check before any SIMD operations
        if data.len() < RTP_HEADER_MIN_SIZE_BYTES {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("sse4.1") {
                // SAFETY: length >= 12 verified, SSE4.1 available
                return unsafe { Self::parse_simd_x86(data) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // NEON is always available on aarch64
            // SAFETY: length >= 12 verified
            return unsafe { Self::parse_simd_neon(data) };
        }

        // Fallback to standard parsing
        #[allow(unreachable_code)]
        Self::parse(data).ok()
    }

    /// SIMD-accelerated RTP parsing using x86_64 SSE4.1.
    ///
    /// Loads the first 16 bytes in a single SIMD instruction and
    /// extracts header fields using SSE4.1 extract operations.
    ///
    /// # Safety
    ///
    /// - Caller must ensure `data.len() >= 12`
    /// - Caller must ensure SSE4.1 is available
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.1")]
    #[inline(always)]
    unsafe fn parse_simd_x86(data: &[u8]) -> Option<Self> {
        // Load 16 bytes — use unaligned load since RTP packets
        // may not be aligned
        let header_bytes = if data.len() >= 16 {
            _mm_loadu_si128(data.as_ptr() as *const __m128i)
        } else {
            // For packets between 12-15 bytes, safe loading
            let mut buf = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf.as_mut_ptr(),
                data.len(),
            );
            _mm_loadu_si128(buf.as_ptr() as *const __m128i)
        };

        // Extract byte 0: V(2) P(1) X(1) CC(4)
        let first_byte =
            _mm_extract_epi8(header_bytes, 0) as u8;
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        // Validate version (must be 2)
        if version != RTP_VERSION {
            return None;
        }

        // Extract byte 1: M(1) PT(7)
        let second_byte =
            _mm_extract_epi8(header_bytes, 1) as u8;
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

        // Extract sequence number (bytes 2-3, big-endian)
        let seq_le =
            _mm_extract_epi16(header_bytes, 1) as u16;
        let sequence_number = seq_le.swap_bytes();

        // Extract timestamp (bytes 4-7, big-endian)
        let ts_le =
            _mm_extract_epi32(header_bytes, 1) as u32;
        let timestamp = ts_le.swap_bytes();

        // Extract SSRC (bytes 8-11, big-endian)
        let ssrc_le =
            _mm_extract_epi32(header_bytes, 2) as u32;
        let ssrc = ssrc_le.swap_bytes();

        // Calculate header length with CSRC
        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        // Validate CSRC count against available bytes
        if data.len() < header_after_csrc {
            return None;
        }

        // Calculate total header length including extension
        let mut header_len_bytes = header_after_csrc;

        if extension {
            let ext_header_start = header_after_csrc;

            // Need at least 4 bytes for extension header
            if data.len() < ext_header_start + 4 {
                return None;
            }

            // Parse extension length (in 32-bit words)
            let ext_len_words = u16::from_be_bytes([
                *data.get_unchecked(ext_header_start + 2),
                *data.get_unchecked(ext_header_start + 3),
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;

            // Total extension size = 4 byte header + ext data
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            // Validate extension fits in packet
            if data.len() < header_len_bytes {
                return None;
            }
        }

        Some(RtpHeader {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            header_len_bytes: header_len_bytes as u8,
        })
    }

    /// SIMD-accelerated RTP parsing using aarch64 NEON.
    ///
    /// Loads the first 16 bytes using NEON and extracts header
    /// fields using lane extraction operations.
    ///
    /// # Safety
    ///
    /// - Caller must ensure `data.len() >= 12`
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn parse_simd_neon(data: &[u8]) -> Option<Self> {
        // Load 16 bytes using NEON
        let header_bytes = if data.len() >= 16 {
            vld1q_u8(data.as_ptr())
        } else {
            let mut buf = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf.as_mut_ptr(),
                data.len(),
            );
            vld1q_u8(buf.as_ptr())
        };

        // Extract byte 0: V(2) P(1) X(1) CC(4)
        let first_byte = vgetq_lane_u8(header_bytes, 0);
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        // Validate version (must be 2)
        if version != RTP_VERSION {
            return None;
        }

        // Extract byte 1: M(1) PT(7)
        let second_byte = vgetq_lane_u8(header_bytes, 1);
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

        // Extract multi-byte fields using from_be_bytes
        let sequence_number = u16::from_be_bytes([
            vgetq_lane_u8(header_bytes, 2),
            vgetq_lane_u8(header_bytes, 3),
        ]);

        let timestamp = u32::from_be_bytes([
            vgetq_lane_u8(header_bytes, 4),
            vgetq_lane_u8(header_bytes, 5),
            vgetq_lane_u8(header_bytes, 6),
            vgetq_lane_u8(header_bytes, 7),
        ]);

        let ssrc = u32::from_be_bytes([
            vgetq_lane_u8(header_bytes, 8),
            vgetq_lane_u8(header_bytes, 9),
            vgetq_lane_u8(header_bytes, 10),
            vgetq_lane_u8(header_bytes, 11),
        ]);

        // Calculate header length with CSRC
        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        // Validate CSRC count against available bytes
        if data.len() < header_after_csrc {
            return None;
        }

        // Calculate total header length including extension
        let mut header_len_bytes = header_after_csrc;

        if extension {
            let ext_header_start = header_after_csrc;

            // Need at least 4 bytes for extension header
            if data.len() < ext_header_start + 4 {
                return None;
            }

            // Parse extension length (in 32-bit words)
            let ext_len_words = u16::from_be_bytes([
                *data.get_unchecked(ext_header_start + 2),
                *data.get_unchecked(ext_header_start + 3),
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;

            // Total extension size = 4 byte header + ext data
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            // Validate extension fits in packet
            if data.len() < header_len_bytes {
                return None;
            }
        }

        Some(RtpHeader {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            header_len_bytes: header_len_bytes as u8,
        })
    }

    /// Serialize RTP header to bytes.
    ///
    /// Writes the fixed 12-byte header to the buffer. Does not write
    /// CSRC or extension data (caller must handle those separately).
    ///
    /// # Arguments
    ///
    /// * `buffer` - Output buffer (must be at least 12 bytes)
    ///
    /// # Returns
    ///
    /// Number of bytes written (always 12 for fixed header)
    ///
    /// # Requirements
    ///
    /// * 3.8 - Serialize RTP headers back to bytes for forwarding
    #[inline]
    pub fn serialize(&self, buffer: &mut [u8]) -> usize {
        // Assertion: buffer is large enough
        debug_assert!(
            buffer.len() >= RTP_HEADER_MIN_SIZE_BYTES,
            "RTP serialize buffer {} bytes, need at least {}",
            buffer.len(),
            RTP_HEADER_MIN_SIZE_BYTES
        );

        assert!(
            buffer.len() >= RTP_HEADER_MIN_SIZE_BYTES,
            "buffer too small for RTP header"
        );

        // First byte: V(2) P(1) X(1) CC(4)
        buffer[0] = (self.version << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | (self.csrc_count & 0x0F);

        // Second byte: M(1) PT(7)
        buffer[1] =
            ((self.marker as u8) << 7)
            | (self.payload_type & 0x7F);

        // Sequence number (bytes 2-3, big-endian)
        let seq_bytes = self.sequence_number.to_be_bytes();
        buffer[2] = seq_bytes[0];
        buffer[3] = seq_bytes[1];

        // Timestamp (bytes 4-7, big-endian)
        let ts_bytes = self.timestamp.to_be_bytes();
        buffer[4] = ts_bytes[0];
        buffer[5] = ts_bytes[1];
        buffer[6] = ts_bytes[2];
        buffer[7] = ts_bytes[3];

        // SSRC (bytes 8-11, big-endian)
        let ssrc_bytes = self.ssrc.to_be_bytes();
        buffer[8] = ssrc_bytes[0];
        buffer[9] = ssrc_bytes[1];
        buffer[10] = ssrc_bytes[2];
        buffer[11] = ssrc_bytes[3];

        RTP_HEADER_MIN_SIZE_BYTES
    }

    /// Get the offset to the payload data.
    ///
    /// Returns the total header length including CSRC and extension.
    #[inline(always)]
    pub fn payload_offset(&self) -> usize {
        self.header_len_bytes as usize
    }

    /// Get CSRC list from packet data.
    ///
    /// Returns an iterator over CSRC values. The packet data must
    /// be the same data that was used to parse this header.
    ///
    /// # Arguments
    ///
    /// * `data` - Original packet data
    #[inline]
    pub fn csrc_list<'a>(
        &self,
        data: &'a [u8],
    ) -> impl Iterator<Item = u32> + 'a {
        let csrc_count = self.csrc_count as usize;
        (0..csrc_count).map(move |i| {
            let offset =
                RTP_HEADER_MIN_SIZE_BYTES
                + (i * RTP_CSRC_SIZE_BYTES);
            u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        })
    }
}
