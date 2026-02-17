//! VP8 RTP payload descriptor parsing (RFC 7741).
//!
//! Parses the VP8 payload descriptor that precedes the VP8
//! bitstream in each RTP packet. The descriptor carries
//! partition info, keyframe flag, picture ID, and temporal
//! layer information needed for SVC and simulcast.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc7741

use super::{CodecError, LayerInfo};

/// VP8 RTP payload header (RFC 7741).
///
/// Fixed size: 1–6 bytes depending on extensions.
/// The first byte is always present; optional extensions
/// are signaled by the X, I, L, T, and K bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vp8PayloadHeader {
    /// X bit — extended control bits present
    pub extended_bit: bool,
    /// S bit — start of a VP8 partition
    pub start_of_partition: bool,
    /// Partition index (3 bits, 0–7)
    pub partition_index: u8,
    /// True if this packet carries a VP8 keyframe
    pub is_keyframe: bool,
    /// PictureID (7 or 15 bits, if I bit set)
    pub picture_id: Option<u16>,
    /// TL0PICIDX (8 bits, if L bit set)
    pub tl0_pic_idx: Option<u8>,
    /// Temporal layer index (if T bit set)
    pub temporal_layer: Option<u8>,
    /// Total descriptor length in bytes
    pub header_len_bytes: u8,
}

impl Vp8PayloadHeader {
    /// Parse VP8 payload descriptor from RTP payload.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP payload bytes (after RTP header)
    ///
    /// # TigerStyle
    ///
    /// Asserts: data.len() >= 1
    /// Asserts: result.partition_index <= 8
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        // Precondition: need at least 1 byte
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        let mut offset: usize = 0;

        // --- First byte (required) ---
        // |X|R|N|S|R| PID |
        let first = data[0];
        let extended_bit = (first & 0x80) != 0;
        let start_of_partition = (first & 0x10) != 0;
        let partition_index = first & 0x0F;
        offset += 1;

        // Parse extension byte if X bit is set
        let mut i_bit = false;
        let mut l_bit = false;
        let mut t_bit = false;

        if extended_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            // |I|L|T|K| RSV |
            let ext = data[offset];
            i_bit = (ext & 0x80) != 0;
            l_bit = (ext & 0x40) != 0;
            t_bit = (ext & 0x20) != 0;
            offset += 1;
        }

        // Parse PictureID if I bit is set
        let mut picture_id: Option<u16> = None;
        if i_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            let pid_byte = data[offset];
            if (pid_byte & 0x80) != 0 {
                // 15-bit PictureID (M bit set)
                if offset + 1 >= data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + 2,
                    });
                }
                let hi = ((pid_byte & 0x7F) as u16) << 8;
                let lo = data[offset + 1] as u16;
                picture_id = Some(hi | lo);
                offset += 2;
            } else {
                // 7-bit PictureID
                picture_id = Some(pid_byte as u16 & 0x7F);
                offset += 1;
            }
        }

        // Parse TL0PICIDX if L bit is set
        let mut tl0_pic_idx: Option<u8> = None;
        if l_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            tl0_pic_idx = Some(data[offset]);
            offset += 1;
        }

        // Parse temporal layer if T bit is set
        let mut temporal_layer: Option<u8> = None;
        if t_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            // |TID|Y| RSV |
            temporal_layer = Some((data[offset] >> 6) & 0x03);
            offset += 1;
        }

        // Detect keyframe from VP8 bitstream header.
        // The first byte of the VP8 payload (after descriptor)
        // has bit 0 = 0 for keyframes, 1 for interframes.
        // Only valid when start_of_partition is true.
        let is_keyframe = if start_of_partition
            && offset < data.len()
        {
            (data[offset] & 0x01) == 0
        } else {
            false
        };

        // Postcondition: partition_index is bounded (4-bit field, 0-15)
        debug_assert!(
            partition_index <= 15,
            "VP8 partition_index {} exceeds max 15",
            partition_index
        );

        Ok(Vp8PayloadHeader {
            extended_bit,
            start_of_partition,
            partition_index,
            is_keyframe,
            picture_id,
            tl0_pic_idx,
            temporal_layer,
            header_len_bytes: offset as u8,
        })
    }

    /// Return layer information for simulcast/SVC decisions.
    pub fn layer_info(&self) -> LayerInfo {
        LayerInfo {
            temporal_layer: self.temporal_layer,
            spatial_layer: None, // VP8 has no spatial layers
        }
    }
}

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_keyframe() {
        // Minimal VP8 payload: S=1, no extensions,
        // followed by keyframe indicator byte (bit0 = 0).
        let data: &[u8] = &[0x10, 0x00];
        let hdr = Vp8PayloadHeader::parse(data).unwrap();
        assert!(hdr.start_of_partition);
        assert!(hdr.is_keyframe);
        assert!(!hdr.extended_bit);
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_minimal_interframe() {
        // S=1, interframe (bit0 = 1 in VP8 payload byte)
        let data: &[u8] = &[0x10, 0x01];
        let hdr = Vp8PayloadHeader::parse(data).unwrap();
        assert!(hdr.start_of_partition);
        assert!(!hdr.is_keyframe);
    }

    #[test]
    fn test_extended_with_picture_id_7bit() {
        // X=1, S=1 | I=1 | PictureID=42 | keyframe byte
        let data: &[u8] = &[0x90, 0x80, 42, 0x00];
        let hdr = Vp8PayloadHeader::parse(data).unwrap();
        assert!(hdr.extended_bit);
        assert!(hdr.start_of_partition);
        assert_eq!(hdr.picture_id, Some(42));
        assert!(hdr.is_keyframe);
        assert_eq!(hdr.header_len_bytes, 3);
    }

    #[test]
    fn test_extended_with_picture_id_15bit() {
        // X=1, S=1 | I=1 | PictureID M=1, 0x1234 | kf byte
        let data: &[u8] =
            &[0x90, 0x80, 0x92, 0x34, 0x00];
        let hdr = Vp8PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.picture_id, Some(0x1234));
        assert_eq!(hdr.header_len_bytes, 4);
    }

    #[test]
    fn test_temporal_layer() {
        // X=1, S=1 | I=0,L=0,T=1 | TID=2 | kf byte
        let data: &[u8] = &[0x90, 0x20, 0x80, 0x00];
        let hdr = Vp8PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.temporal_layer, Some(2));
    }

    #[test]
    fn test_too_short() {
        let result = Vp8PayloadHeader::parse(&[]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            }
        );
    }

    #[test]
    fn test_layer_info() {
        let hdr = Vp8PayloadHeader {
            extended_bit: false,
            start_of_partition: true,
            partition_index: 0,
            is_keyframe: true,
            picture_id: None,
            tl0_pic_idx: None,
            temporal_layer: Some(1),
            header_len_bytes: 1,
        };
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, Some(1));
        assert_eq!(info.spatial_layer, None);
    }
}
