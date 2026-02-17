//! RTP header parsing, validation, and serialization.
//!
//! Contains the core `RtpHeader` struct with scalar and SIMD
//! parsing implementations. All methods are `#[inline]` for
//! hot-path performance.

use nexus_core::RtpError;

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

/// Maximum RTP header length in bytes.
///
/// 12 (fixed) + 15*4 (CSRC) + 4 (ext hdr) + 65535*4 (ext data) = 262216.
/// u16 max is 65535, which covers all realistic packets. The theoretical
/// max of 262216 exceeds u16 but requires a 256KB+ extension which no
/// browser or endpoint sends. We cap at u16::MAX and return InvalidExtension
/// for anything larger.
const MAX_HEADER_LEN_BYTES: usize = u16::MAX as usize;

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
    /// Total header length in bytes (including CSRC and extension).
    /// u16 supports headers up to 65535 bytes — sufficient for all
    /// real-world RTP packets.
    pub header_len_bytes: u16,
    /// Number of padding bytes (0 if padding flag is false).
    /// Read from the last byte of the packet per RFC 3550 §5.1.
    pub padding_len: u8,
}

impl RtpHeader {
    /// Parse RTP header from bytes.
    ///
    /// Extracts all header fields and validates the packet structure
    /// including padding. Returns an error for malformed packets.
    #[inline]
    pub fn parse(data: &[u8]) -> Result<Self, RtpError> {
        if data.len() < RTP_HEADER_MIN_SIZE_BYTES {
            return Err(RtpError::TooShort {
                actual_bytes: data.len(),
                min_bytes: RTP_HEADER_MIN_SIZE_BYTES,
            });
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion { version });
        }

        let second_byte = data[1];
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

        let sequence_number =
            u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);
        let ssrc = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        if data.len() < header_after_csrc {
            return Err(RtpError::InvalidCsrcCount {
                count: csrc_count,
                available_bytes: data.len()
                    - RTP_HEADER_MIN_SIZE_BYTES,
            });
        }

        let mut header_len_bytes = header_after_csrc;

        if extension {
            let ext_header_start = header_after_csrc;

            if data.len() < ext_header_start + 4 {
                return Err(RtpError::InvalidExtension);
            }

            let ext_len_words = u16::from_be_bytes([
                data[ext_header_start + 2],
                data[ext_header_start + 3],
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            if header_len_bytes > MAX_HEADER_LEN_BYTES {
                return Err(RtpError::InvalidExtension);
            }

            if data.len() < header_len_bytes {
                return Err(RtpError::InvalidExtension);
            }
        }

        // Validate padding per RFC 3550 §5.1
        let padding_len = if padding {
            if data.len() <= header_len_bytes {
                return Err(RtpError::InvalidPadding {
                    padding_len: 0,
                    available_bytes: data.len().saturating_sub(header_len_bytes),
                });
            }
            let pad = data[data.len() - 1];
            let payload_plus_padding = data.len() - header_len_bytes;
            if pad == 0 || (pad as usize) > payload_plus_padding {
                return Err(RtpError::InvalidPadding {
                    padding_len: pad,
                    available_bytes: payload_plus_padding,
                });
            }
            pad
        } else {
            0
        };

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
            header_len_bytes: header_len_bytes as u16,
            padding_len,
        })
    }

    /// Parse RTP header with SIMD acceleration.
    ///
    /// Auto-selects the fastest available implementation:
    /// - **x86_64 with SSE4.1**: 128-bit SIMD loads
    /// - **aarch64**: NEON intrinsics
    /// - **Fallback**: Standard byte-by-byte parsing
    #[inline(always)]
    pub fn parse_simd(data: &[u8]) -> Option<Self> {
        if data.len() < RTP_HEADER_MIN_SIZE_BYTES {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("sse4.1") {
                return unsafe { Self::parse_simd_x86(data) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            return unsafe { Self::parse_simd_neon(data) };
        }

        #[allow(unreachable_code)]
        Self::parse(data).ok()
    }

    /// SIMD-accelerated RTP parsing using x86_64 SSE4.1.
    ///
    /// # Safety
    ///
    /// - Caller must ensure `data.len() >= 12`
    /// - Caller must ensure SSE4.1 is available
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.1")]
    #[inline(always)]
    unsafe fn parse_simd_x86(data: &[u8]) -> Option<Self> {
        let header_bytes = if data.len() >= 16 {
            _mm_loadu_si128(data.as_ptr() as *const __m128i)
        } else {
            let mut buf = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf.as_mut_ptr(),
                data.len(),
            );
            _mm_loadu_si128(buf.as_ptr() as *const __m128i)
        };

        let first_byte =
            _mm_extract_epi8(header_bytes, 0) as u8;
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        if version != RTP_VERSION {
            return None;
        }

        let second_byte =
            _mm_extract_epi8(header_bytes, 1) as u8;
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

        let seq_le =
            _mm_extract_epi16(header_bytes, 1) as u16;
        let sequence_number = seq_le.swap_bytes();

        let ts_le =
            _mm_extract_epi32(header_bytes, 1) as u32;
        let timestamp = ts_le.swap_bytes();

        let ssrc_le =
            _mm_extract_epi32(header_bytes, 2) as u32;
        let ssrc = ssrc_le.swap_bytes();

        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        if data.len() < header_after_csrc {
            return None;
        }

        let mut header_len_bytes = header_after_csrc;

        if extension {
            let ext_header_start = header_after_csrc;

            if data.len() < ext_header_start + 4 {
                return None;
            }

            let ext_len_words = u16::from_be_bytes([
                *data.get_unchecked(ext_header_start + 2),
                *data.get_unchecked(ext_header_start + 3),
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            if header_len_bytes > MAX_HEADER_LEN_BYTES {
                return None;
            }

            if data.len() < header_len_bytes {
                return None;
            }
        }

        // Validate padding
        let padding_len = if padding {
            if data.len() <= header_len_bytes {
                return None;
            }
            let pad = *data.get_unchecked(data.len() - 1);
            let payload_plus_padding = data.len() - header_len_bytes;
            if pad == 0 || (pad as usize) > payload_plus_padding {
                return None;
            }
            pad
        } else {
            0
        };

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
            header_len_bytes: header_len_bytes as u16,
            padding_len,
        })
    }

    /// SIMD-accelerated RTP parsing using aarch64 NEON.
    ///
    /// # Safety
    ///
    /// - Caller must ensure `data.len() >= 12`
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn parse_simd_neon(data: &[u8]) -> Option<Self> {
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

        let first_byte = vgetq_lane_u8(header_bytes, 0);
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        if version != RTP_VERSION {
            return None;
        }

        let second_byte = vgetq_lane_u8(header_bytes, 1);
        let marker = (second_byte >> 7) & 0x01 != 0;
        let payload_type = second_byte & 0x7F;

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

        let csrc_size_bytes =
            (csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        let header_after_csrc =
            RTP_HEADER_MIN_SIZE_BYTES + csrc_size_bytes;

        if data.len() < header_after_csrc {
            return None;
        }

        let mut header_len_bytes = header_after_csrc;

        if extension {
            let ext_header_start = header_after_csrc;

            if data.len() < ext_header_start + 4 {
                return None;
            }

            let ext_len_words = u16::from_be_bytes([
                *data.get_unchecked(ext_header_start + 2),
                *data.get_unchecked(ext_header_start + 3),
            ]);
            let ext_len_bytes = (ext_len_words as usize) * 4;
            let total_ext_size = 4 + ext_len_bytes;
            header_len_bytes += total_ext_size;

            if header_len_bytes > MAX_HEADER_LEN_BYTES {
                return None;
            }

            if data.len() < header_len_bytes {
                return None;
            }
        }

        // Validate padding
        let padding_len = if padding {
            if data.len() <= header_len_bytes {
                return None;
            }
            let pad = *data.get_unchecked(data.len() - 1);
            let payload_plus_padding = data.len() - header_len_bytes;
            if pad == 0 || (pad as usize) > payload_plus_padding {
                return None;
            }
            pad
        } else {
            0
        };

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
            header_len_bytes: header_len_bytes as u16,
            padding_len,
        })
    }

    /// Serialize RTP header to bytes.
    ///
    /// Writes the fixed 12-byte header to the buffer. Does not write
    /// CSRC or extension data (caller must handle those separately).
    #[inline]
    pub fn serialize(&self, buffer: &mut [u8]) -> usize {
        assert!(
            buffer.len() >= RTP_HEADER_MIN_SIZE_BYTES,
            "buffer too small for RTP header"
        );

        buffer[0] = (self.version << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | (self.csrc_count & 0x0F);

        buffer[1] =
            ((self.marker as u8) << 7)
            | (self.payload_type & 0x7F);

        let seq_bytes = self.sequence_number.to_be_bytes();
        buffer[2] = seq_bytes[0];
        buffer[3] = seq_bytes[1];

        let ts_bytes = self.timestamp.to_be_bytes();
        buffer[4] = ts_bytes[0];
        buffer[5] = ts_bytes[1];
        buffer[6] = ts_bytes[2];
        buffer[7] = ts_bytes[3];

        let ssrc_bytes = self.ssrc.to_be_bytes();
        buffer[8] = ssrc_bytes[0];
        buffer[9] = ssrc_bytes[1];
        buffer[10] = ssrc_bytes[2];
        buffer[11] = ssrc_bytes[3];

        RTP_HEADER_MIN_SIZE_BYTES
    }

    /// Get the offset to the payload data.
    #[inline(always)]
    pub fn payload_offset(&self) -> usize {
        self.header_len_bytes as usize
    }

    /// Get the payload length excluding padding.
    ///
    /// Returns the number of actual payload bytes in the packet,
    /// accounting for both header and padding.
    #[inline(always)]
    pub fn payload_len(&self, packet_len: usize) -> usize {
        let offset = self.header_len_bytes as usize;
        let pad = self.padding_len as usize;
        packet_len.saturating_sub(offset).saturating_sub(pad)
    }

    /// Get CSRC list from packet data.
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

    /// Extract a one-byte header extension value by extension ID.
    ///
    /// Walks the RFC 5285 one-byte header extension block and returns
    /// the payload bytes for the given `ext_id`, or `None` if not found.
    #[inline]
    pub fn get_extension_value<'a>(&self, data: &'a [u8], ext_id: u8) -> Option<&'a [u8]> {
        if !self.extension { return None; }

        let ext_start = RTP_HEADER_MIN_SIZE_BYTES + (self.csrc_count as usize) * RTP_CSRC_SIZE_BYTES;
        if data.len() < ext_start + 4 { return None; }

        let profile = u16::from_be_bytes([data[ext_start], data[ext_start + 1]]);
        let ext_len_words = u16::from_be_bytes([data[ext_start + 2], data[ext_start + 3]]) as usize;
        let ext_data_start = ext_start + 4;
        let ext_data_end = ext_data_start + ext_len_words * 4;
        if ext_data_end > data.len() { return None; }

        // RFC 5285 one-byte header: profile 0xBEDE
        if profile == 0xBEDE {
            let mut pos = ext_data_start;
            while pos < ext_data_end {
                let byte = data[pos];
                if byte == 0 { pos += 1; continue; } // padding
                let id = (byte >> 4) & 0x0F;
                let len = (byte & 0x0F) as usize + 1;
                pos += 1;
                if id == 0x0F { break; } // terminator
                if pos + len > ext_data_end { break; }
                if id == ext_id {
                    return Some(&data[pos..pos + len]);
                }
                pos += len;
            }
        }
        None
    }
}
