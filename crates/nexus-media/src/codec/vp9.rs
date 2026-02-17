//! VP9 RTP payload descriptor parsing.
//!
//! Parses the VP9 payload descriptor defined in
//! draft-ietf-payload-vp9. The descriptor carries picture ID,
//! layer indices, keyframe flag, and scalability structure
//! information needed for SVC forwarding decisions.
//!
//! Reference: draft-ietf-payload-vp9

use super::{CodecError, LayerInfo};

/// VP9 RTP payload header.
///
/// The first byte is always present. Optional fields are
/// signaled by the I, P, L, F, and V bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vp9PayloadHeader {
    /// I bit — PictureID present
    pub picture_id_present: bool,
    /// P bit — inter-picture predicted layer frame
    pub inter_picture_predicted: bool,
    /// L bit — layer indices present
    pub layer_indices_present: bool,
    /// F bit — flexible mode
    pub flexible_mode: bool,
    /// B bit — start of a VP9 frame
    pub start_of_frame: bool,
    /// E bit — end of a VP9 frame
    pub end_of_frame: bool,
    /// V bit — scalability structure present
    pub scalability_structure: bool,
    /// True if this is a keyframe (P=0 and B=1)
    pub is_keyframe: bool,
    /// PictureID (7 or 15 bits, if I bit set)
    pub picture_id: Option<u16>,
    /// Temporal layer index (if L bit set)
    pub temporal_layer: Option<u8>,
    /// Spatial layer index (if L bit set)
    pub spatial_layer: Option<u8>,
    /// Total descriptor length in bytes
    pub header_len_bytes: u8,
}

impl Vp9PayloadHeader {
    /// Parse VP9 payload descriptor from RTP payload.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP payload bytes (after RTP header)
    ///
    /// # TigerStyle
    ///
    /// Asserts: data.len() >= 1
    /// Asserts: temporal_layer <= 7 when present
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        let mut offset: usize = 0;

        // --- First byte (required) ---
        // |I|P|L|F|B|E|V|Z|
        let first = data[0];
        let i_bit = (first & 0x80) != 0;
        let p_bit = (first & 0x40) != 0;
        let l_bit = (first & 0x20) != 0;
        let f_bit = (first & 0x10) != 0;
        let b_bit = (first & 0x08) != 0;
        let e_bit = (first & 0x04) != 0;
        let v_bit = (first & 0x02) != 0;
        offset += 1;

        // Keyframe: not inter-predicted and start of frame
        let is_keyframe = !p_bit && b_bit;

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
                picture_id = Some(pid_byte as u16 & 0x7F);
                offset += 1;
            }
        }

        // Parse layer indices if L bit is set
        let mut temporal_layer: Option<u8> = None;
        let mut spatial_layer: Option<u8> = None;
        if l_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            // |TID|U|SID|D|
            let layer_byte = data[offset];
            temporal_layer =
                Some((layer_byte >> 5) & 0x07);
            spatial_layer =
                Some((layer_byte >> 1) & 0x07);
            offset += 1;

            // In non-flexible mode, skip TL0PICIDX byte
            if !f_bit {
                if offset >= data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + 1,
                    });
                }
                offset += 1; // TL0PICIDX
            }
        }

        // Skip reference indices in flexible mode
        if f_bit && p_bit {
            // Up to 3 reference indices, each 1 byte.
            // Each byte has an R bit (bit 0) indicating
            // whether another reference follows.
            let max_refs: usize = 3;
            for _ in 0..max_refs {
                if offset >= data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + 1,
                    });
                }
                let ref_byte = data[offset];
                offset += 1;
                // R bit = 0 means last reference
                if (ref_byte & 0x01) == 0 {
                    break;
                }
            }
        }

        // Skip scalability structure if V bit is set.
        // We parse just enough to skip past it.
        if v_bit {
            if offset >= data.len() {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: offset + 1,
                });
            }
            let ss_byte = data[offset];
            let n_s = ((ss_byte >> 5) & 0x07) + 1;
            let y_bit = (ss_byte & 0x10) != 0;
            let g_bit = (ss_byte & 0x08) != 0;
            offset += 1;

            // Skip resolution for each spatial layer
            if y_bit {
                let res_bytes = (n_s as usize) * 4;
                if offset + res_bytes > data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + res_bytes,
                    });
                }
                offset += res_bytes;
            }

            // Skip PG (picture group) description
            if g_bit {
                if offset >= data.len() {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: offset + 1,
                    });
                }
                let n_g = data[offset] as usize;
                offset += 1;

                // Bound PG iteration to prevent DoS from
                // malformed packets. VP9 spec allows up to 255
                // but real streams use < 16.
                if n_g > 64 {
                    return Err(CodecError::Unsupported {
                        feature: "VP9 n_g > 64",
                    });
                }

                // Each PG entry: 1 byte + variable refs
                for _ in 0..n_g {
                    if offset >= data.len() {
                        return Err(CodecError::TooShort {
                            actual_bytes: data.len(),
                            min_bytes: offset + 1,
                        });
                    }
                    let pg = data[offset];
                    let r_count =
                        ((pg >> 2) & 0x03) as usize;
                    offset += 1 + r_count;
                }
            }
        }

        // Postcondition: temporal_layer bounded
        debug_assert!(
            temporal_layer.map_or(true, |t| t <= 7),
            "VP9 temporal_layer {} exceeds max 7",
            temporal_layer.unwrap_or(0)
        );

        Ok(Vp9PayloadHeader {
            picture_id_present: i_bit,
            inter_picture_predicted: p_bit,
            layer_indices_present: l_bit,
            flexible_mode: f_bit,
            start_of_frame: b_bit,
            end_of_frame: e_bit,
            scalability_structure: v_bit,
            is_keyframe,
            picture_id,
            temporal_layer,
            spatial_layer,
            header_len_bytes: offset as u8,
        })
    }

    /// Return layer information for SVC forwarding decisions.
    pub fn layer_info(&self) -> LayerInfo {
        LayerInfo {
            temporal_layer: self.temporal_layer,
            spatial_layer: self.spatial_layer,
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
    fn test_keyframe_start_of_frame() {
        // I=0, P=0, L=0, F=0, B=1, E=1, V=0, Z=0
        // P=0 + B=1 → keyframe
        let data: &[u8] = &[0x0C];
        let hdr = Vp9PayloadHeader::parse(data).unwrap();
        assert!(hdr.is_keyframe);
        assert!(hdr.start_of_frame);
        assert!(hdr.end_of_frame);
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_interframe() {
        // I=0, P=1, L=0, F=0, B=1, E=1, V=0, Z=0
        let data: &[u8] = &[0x4C];
        let hdr = Vp9PayloadHeader::parse(data).unwrap();
        assert!(!hdr.is_keyframe);
        assert!(hdr.inter_picture_predicted);
    }

    #[test]
    fn test_picture_id_7bit() {
        // I=1, P=0, B=1, E=1 | PictureID=42
        let data: &[u8] = &[0x8C, 42];
        let hdr = Vp9PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.picture_id, Some(42));
        assert!(hdr.is_keyframe);
        assert_eq!(hdr.header_len_bytes, 2);
    }

    #[test]
    fn test_picture_id_15bit() {
        // I=1, P=0, B=1, E=1 | PictureID M=1, 0x1234
        let data: &[u8] = &[0x8C, 0x92, 0x34];
        let hdr = Vp9PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.picture_id, Some(0x1234));
        assert_eq!(hdr.header_len_bytes, 3);
    }

    #[test]
    fn test_layer_indices() {
        // I=0, P=0, L=1, F=0, B=1, E=1 | TID=1,SID=2 | TL0
        // layer byte: TID=1 (001), U=0, SID=2 (010), D=0
        // = 0b001_0_010_0 = 0x24
        let data: &[u8] = &[0x2C, 0x24, 0x00];
        let hdr = Vp9PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.temporal_layer, Some(1));
        assert_eq!(hdr.spatial_layer, Some(2));
        assert_eq!(hdr.header_len_bytes, 3);
    }

    #[test]
    fn test_too_short() {
        let result = Vp9PayloadHeader::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_layer_info() {
        let hdr = Vp9PayloadHeader {
            picture_id_present: false,
            inter_picture_predicted: false,
            layer_indices_present: true,
            flexible_mode: false,
            start_of_frame: true,
            end_of_frame: true,
            scalability_structure: false,
            is_keyframe: true,
            picture_id: None,
            temporal_layer: Some(2),
            spatial_layer: Some(1),
            header_len_bytes: 3,
        };
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, Some(2));
        assert_eq!(info.spatial_layer, Some(1));
    }
}
