//! AV1 OBU (Open Bitstream Unit) parsing for RTP.
//!
//! Parses the AV1 RTP payload format as defined in the AV1
//! RTP specification. The aggregation header precedes one or
//! more OBUs. Keyframe detection inspects the OBU type and
//! the frame header's frame_type field.
//!
//! Reference: AV1 RTP payload format
//!   (https://aomediacodec.github.io/av1-rtp-spec/)

use super::{CodecError, LayerInfo};

/// AV1 OBU types relevant for SFU forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObuType {
    /// Sequence header OBU (type 1)
    SequenceHeader,
    /// Temporal delimiter OBU (type 2)
    TemporalDelimiter,
    /// Frame header OBU (type 3)
    FrameHeader,
    /// Tile group OBU (type 4)
    TileGroup,
    /// Frame OBU (type 6) — combined header + tile group
    Frame,
    /// Any other OBU type
    Other(u8),
}

impl ObuType {
    /// Convert raw 4-bit OBU type to enum.
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => ObuType::SequenceHeader,
            2 => ObuType::TemporalDelimiter,
            3 => ObuType::FrameHeader,
            4 => ObuType::TileGroup,
            6 => ObuType::Frame,
            other => ObuType::Other(other),
        }
    }
}

/// AV1 RTP payload header.
///
/// The first byte is the AV1 aggregation header, followed by
/// one or more OBUs. We parse the aggregation header and the
/// first OBU header for keyframe detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Av1PayloadHeader {
    /// Z bit — continuation of previous OBU fragment
    pub continuation: bool,
    /// Y bit — last OBU element will continue in next packet
    pub will_continue: bool,
    /// W field — number of OBU elements (0 = variable)
    pub obu_count: u8,
    /// N bit — new coded video sequence starts here
    pub new_sequence: bool,
    /// Type of the first OBU in the payload
    pub first_obu_type: ObuType,
    /// True if the first OBU indicates a keyframe
    pub is_key_obu: bool,
    /// Temporal ID from the first OBU extension header
    pub temporal_id: Option<u8>,
    /// Spatial ID from the first OBU extension header
    pub spatial_id: Option<u8>,
    /// Total parsed header length in bytes
    pub header_len_bytes: u8,
}

impl Av1PayloadHeader {
    /// Parse AV1 RTP payload from aggregation header + OBUs.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP payload bytes (after RTP header)
    ///
    /// # TigerStyle
    ///
    /// Asserts: data.len() >= 1
    /// Asserts: obu_count <= 3
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        let mut offset: usize = 0;

        // --- Aggregation header (1 byte) ---
        // |Z|Y|W W|N|0 0 0|
        let agg = data[0];
        let z_bit = (agg & 0x80) != 0;
        let y_bit = (agg & 0x40) != 0;
        let w_field = (agg >> 4) & 0x03;
        let n_bit = (agg & 0x08) != 0;
        offset += 1;

        // If this is a continuation fragment (Z=1) and not
        // the start, we cannot determine keyframe status.
        if z_bit {
            return Ok(Av1PayloadHeader {
                continuation: true,
                will_continue: y_bit,
                obu_count: w_field,
                new_sequence: n_bit,
                first_obu_type: ObuType::Other(0),
                is_key_obu: false,
                temporal_id: None,
                spatial_id: None,
                header_len_bytes: offset as u8,
            });
        }

        // Skip OBU element size (leb128) if W > 0 and
        // this is not the last element.
        // For W=1, there is exactly one OBU and no size
        // prefix. For W>1, each OBU except the last has
        // a leb128 size prefix.
        if w_field > 1 {
            // Skip leb128 size of first OBU element
            let max_leb_bytes: usize = 4;
            for _ in 0..max_leb_bytes {
                if offset >= data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + 1,
                    });
                }
                let byte = data[offset];
                offset += 1;
                // leb128: high bit = 0 means last byte
                if (byte & 0x80) == 0 {
                    break;
                }
            }
        }

        // Parse first OBU header
        if offset >= data.len() {
            return Err(CodecError::TooShort {
                actual_bytes: data.len(),
                min_bytes: offset + 1,
            });
        }

        // OBU header: |F|Type(4)|X|H|0|
        let obu_hdr = data[offset];
        let obu_type_raw = (obu_hdr >> 3) & 0x0F;
        let obu_type = ObuType::from_raw(obu_type_raw);
        let has_extension = (obu_hdr & 0x04) != 0;
        let has_size = (obu_hdr & 0x02) != 0;
        offset += 1;

        // Parse OBU extension header if present
        let mut temporal_id: Option<u8> = None;
        let mut spatial_id: Option<u8> = None;
        if has_extension {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            let ext = data[offset];
            temporal_id = Some((ext >> 5) & 0x07);
            spatial_id = Some((ext >> 3) & 0x03);
            offset += 1;
        }

        // Skip OBU size field (leb128) if present
        if has_size {
            let max_leb_bytes: usize = 4;
            for _ in 0..max_leb_bytes {
                if offset >= data.len() {
                    break;
                }
                let byte = data[offset];
                offset += 1;
                if (byte & 0x80) == 0 {
                    break;
                }
            }
        }

        // Determine keyframe status.
        // A sequence header or N=1 strongly indicates a
        // keyframe. For Frame/FrameHeader OBUs, we check
        // the frame_type field (first 2 bits of payload):
        //   0 = KEY_FRAME, others = non-key.
        let is_key_obu = match obu_type {
            ObuType::SequenceHeader => true,
            ObuType::Frame | ObuType::FrameHeader => {
                if offset < data.len() {
                    // frame_type is in bits 1-0 of the
                    // show_existing_frame byte. If
                    // show_existing_frame=0, frame_type
                    // is in bits 6-5 of the next bits.
                    // Simplified: check if N bit is set
                    // or first payload bits indicate key.
                    n_bit
                        || (data[offset] & 0x80) == 0
                            && (data[offset] & 0x60) == 0
                } else {
                    n_bit
                }
            }
            _ => n_bit,
        };

        Ok(Av1PayloadHeader {
            continuation: z_bit,
            will_continue: y_bit,
            obu_count: w_field,
            new_sequence: n_bit,
            first_obu_type: obu_type,
            is_key_obu,
            temporal_id,
            spatial_id,
            header_len_bytes: offset as u8,
        })
    }

    /// Returns true if this packet contains a keyframe.
    pub fn is_keyframe(&self) -> bool {
        self.is_key_obu
    }

    /// Return layer information for SVC forwarding decisions.
    pub fn layer_info(&self) -> LayerInfo {
        LayerInfo {
            temporal_layer: self.temporal_id,
            spatial_layer: self.spatial_id,
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
    fn test_sequence_header_keyframe() {
        // Aggregation: Z=0, Y=0, W=1, N=1 → 0x18
        // OBU header: type=1 (SeqHdr), no ext, no size
        //   → 0b0_0001_0_0_0 = 0x08
        let data: &[u8] = &[0x18, 0x08];
        let hdr = Av1PayloadHeader::parse(data).unwrap();
        assert!(!hdr.continuation);
        assert!(hdr.new_sequence);
        assert_eq!(
            hdr.first_obu_type,
            ObuType::SequenceHeader
        );
        assert!(hdr.is_keyframe());
    }

    #[test]
    fn test_continuation_fragment() {
        // Z=1 → continuation, cannot determine keyframe
        let data: &[u8] = &[0x80, 0x30];
        let hdr = Av1PayloadHeader::parse(data).unwrap();
        assert!(hdr.continuation);
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_frame_obu_with_extension() {
        // Aggregation: Z=0, Y=0, W=1, N=0 → 0x10
        // OBU header: type=6 (Frame), ext=1, no size
        //   → 0b0_0110_1_0_0 = 0x34
        // Extension: TID=1, SID=0 → 0b001_00_000 = 0x20
        let data: &[u8] = &[0x10, 0x34, 0x20, 0x00];
        let hdr = Av1PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.first_obu_type, ObuType::Frame);
        assert_eq!(hdr.temporal_id, Some(1));
        assert_eq!(hdr.spatial_id, Some(0));
    }

    #[test]
    fn test_too_short() {
        let result = Av1PayloadHeader::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_layer_info() {
        let hdr = Av1PayloadHeader {
            continuation: false,
            will_continue: false,
            obu_count: 1,
            new_sequence: false,
            first_obu_type: ObuType::Frame,
            is_key_obu: false,
            temporal_id: Some(2),
            spatial_id: Some(1),
            header_len_bytes: 3,
        };
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, Some(2));
        assert_eq!(info.spatial_layer, Some(1));
    }
}
