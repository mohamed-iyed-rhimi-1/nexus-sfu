//! H.264 NAL unit parsing for RTP (RFC 6184).
//!
//! Parses the H.264 RTP payload to extract NAL unit type,
//! keyframe (IDR) detection, and NRI (importance) level.
//! Supports single NAL unit, STAP-A, FU-A, and FU-B
//! packetization modes commonly used in WebRTC.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc6184

use super::{CodecError, LayerInfo};

/// Maximum number of NAL units inside a STAP-A packet to inspect.
/// Browsers typically aggregate 2-4 NALUs (SPS + PPS + IDR).
const MAX_STAP_A_NALUS: usize = 32;

/// NAL unit types relevant for SFU forwarding decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NalUnitType {
    /// Coded slice of a non-IDR picture (1)
    SliceNonIdr,
    /// Coded slice data partition A (2)
    SlicePartA,
    /// Coded slice of an IDR picture (5) — keyframe
    SliceIdr,
    /// Supplemental enhancement information (6)
    Sei,
    /// Sequence parameter set (7)
    Sps,
    /// Picture parameter set (8)
    Pps,
    /// STAP-A: Single-time aggregation packet (24)
    StapA,
    /// FU-A: Fragmentation unit (28)
    FuA,
    /// FU-B: Fragmentation unit (29)
    FuB,
    /// Any other NAL unit type
    Other(u8),
}

impl NalUnitType {
    /// Convert raw 5-bit NAL unit type to enum.
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => NalUnitType::SliceNonIdr,
            2 => NalUnitType::SlicePartA,
            5 => NalUnitType::SliceIdr,
            6 => NalUnitType::Sei,
            7 => NalUnitType::Sps,
            8 => NalUnitType::Pps,
            24 => NalUnitType::StapA,
            28 => NalUnitType::FuA,
            29 => NalUnitType::FuB,
            other => NalUnitType::Other(other),
        }
    }

    /// Returns true if this NAL type is an IDR or parameter set
    /// that signals a keyframe boundary.
    #[inline]
    fn is_idr_or_param_set(self) -> bool {
        matches!(
            self,
            NalUnitType::SliceIdr
                | NalUnitType::Sps
                | NalUnitType::Pps
        )
    }
}

/// H.264 RTP payload header.
///
/// Represents the parsed NAL unit header from the RTP payload.
/// For FU-A/FU-B packets, the actual NAL type is extracted from
/// the FU header. For STAP-A, aggregated NALUs are inspected
/// for keyframe detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H264PayloadHeader {
    /// Forbidden zero bit (must be 0 in valid streams)
    pub forbidden_zero: bool,
    /// NAL reference indicator (2 bits, 0–3)
    pub nri: u8,
    /// NAL unit type from the indicator byte
    pub nal_unit_type: NalUnitType,
    /// For FU-A/FU-B: the actual NAL type from the FU header
    pub fu_nal_type: Option<NalUnitType>,
    /// For FU-A/FU-B: start bit (first fragment)
    pub fu_start: bool,
    /// For FU-A/FU-B: end bit (last fragment)
    pub fu_end: bool,
    /// For STAP-A: true if any aggregated NAL is IDR/SPS/PPS
    pub stap_a_has_idr: bool,
    /// Total parsed header length in bytes
    pub header_len_bytes: u8,
}

impl H264PayloadHeader {
    /// Parse H.264 NAL unit header from RTP payload.
    ///
    /// For STAP-A packets, walks the aggregated NAL units to
    /// detect keyframes (IDR/SPS/PPS). This is critical because
    /// Chrome, Firefox, and Safari all send H.264 keyframes as
    /// STAP-A packets containing SPS + PPS + IDR.
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        let nal_byte = data[0];
        let forbidden_zero = (nal_byte & 0x80) != 0;
        let nri = (nal_byte >> 5) & 0x03;
        let raw_type = nal_byte & 0x1F;
        let nal_unit_type = NalUnitType::from_raw(raw_type);

        let mut fu_nal_type: Option<NalUnitType> = None;
        let mut fu_start = false;
        let mut fu_end = false;
        let mut stap_a_has_idr = false;
        let mut header_len_bytes: u8 = 1;

        match nal_unit_type {
            NalUnitType::FuA => {
                if data.len() < 2 {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: 2,
                    });
                }
                let fu_header = data[1];
                fu_start = (fu_header & 0x80) != 0;
                fu_end = (fu_header & 0x40) != 0;
                let fu_type = fu_header & 0x1F;
                fu_nal_type =
                    Some(NalUnitType::from_raw(fu_type));
                header_len_bytes = 2;
            }
            NalUnitType::FuB => {
                // FU-B = FU-A + 2-byte DON (RFC 6184 §5.8)
                if data.len() < 4 {
                    return Err(CodecError::TooShort {
                        actual_bytes: data.len(),
                        min_bytes: 4,
                    });
                }
                let fu_header = data[1];
                fu_start = (fu_header & 0x80) != 0;
                fu_end = (fu_header & 0x40) != 0;
                let fu_type = fu_header & 0x1F;
                fu_nal_type =
                    Some(NalUnitType::from_raw(fu_type));
                // 1 (indicator) + 1 (FU header) + 2 (DON)
                header_len_bytes = 4;
            }
            NalUnitType::StapA => {
                // Walk aggregated NALUs: [2-byte size][NAL unit]...
                // Check each NAL type for IDR/SPS/PPS.
                let mut offset: usize = 1;
                let mut nalu_count: usize = 0;
                while offset + 2 <= data.len()
                    && nalu_count < MAX_STAP_A_NALUS
                {
                    let nalu_size = u16::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                    ]) as usize;
                    offset += 2;

                    if nalu_size == 0 || offset + nalu_size > data.len() {
                        break;
                    }

                    let nalu_type =
                        NalUnitType::from_raw(data[offset] & 0x1F);
                    if nalu_type.is_idr_or_param_set() {
                        stap_a_has_idr = true;
                    }

                    offset += nalu_size;
                    nalu_count += 1;
                }
                header_len_bytes = 1;
            }
            _ => {}
        }

        debug_assert!(nri <= 3);

        Ok(H264PayloadHeader {
            forbidden_zero,
            nri,
            nal_unit_type,
            fu_nal_type,
            fu_start,
            fu_end,
            stap_a_has_idr,
            header_len_bytes,
        })
    }

    /// Returns true if this packet contains a keyframe (IDR).
    ///
    /// Detects keyframes in all packetization modes:
    /// - Single NAL IDR (type 5)
    /// - FU-A/FU-B start fragment of IDR
    /// - STAP-A containing IDR/SPS/PPS (Chrome/Firefox/Safari)
    /// - Standalone SPS/PPS (parameter sets preceding keyframe)
    pub fn is_keyframe(&self) -> bool {
        match self.nal_unit_type {
            NalUnitType::SliceIdr => true,
            NalUnitType::Sps | NalUnitType::Pps => true,
            NalUnitType::StapA => self.stap_a_has_idr,
            NalUnitType::FuA | NalUnitType::FuB => {
                self.fu_start
                    && self.fu_nal_type
                        == Some(NalUnitType::SliceIdr)
            }
            _ => false,
        }
    }

    /// Return layer information.
    ///
    /// H.264 base profile does not carry temporal/spatial
    /// layer info in the NAL header.
    pub fn layer_info(&self) -> LayerInfo {
        LayerInfo {
            temporal_layer: None,
            spatial_layer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idr_slice() {
        // F=0, NRI=3, Type=5 (IDR) → 0x65
        let data: &[u8] = &[0x65, 0x88, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.forbidden_zero);
        assert_eq!(hdr.nri, 3);
        assert_eq!(hdr.nal_unit_type, NalUnitType::SliceIdr);
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_non_idr_slice() {
        // F=0, NRI=2, Type=1 → 0x41
        let data: &[u8] = &[0x41, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::SliceNonIdr);
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_fu_a_idr_start() {
        // Indicator: F=0, NRI=3, Type=28 (FU-A) → 0x7C
        // FU header: S=1, E=0, Type=5 (IDR) → 0x85
        let data: &[u8] = &[0x7C, 0x85, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::FuA);
        assert!(hdr.fu_start);
        assert!(!hdr.fu_end);
        assert_eq!(hdr.fu_nal_type, Some(NalUnitType::SliceIdr));
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 2);
    }

    #[test]
    fn test_fu_a_non_idr() {
        let data: &[u8] = &[0x7C, 0x81, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_fu_a_middle_fragment() {
        let data: &[u8] = &[0x7C, 0x05, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.fu_start);
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_fu_b_idr_start() {
        // FU-B indicator: F=0, NRI=3, Type=29 → 0x7D
        // FU header: S=1, E=0, Type=5 (IDR) → 0x85
        // DON: 2 bytes
        let data: &[u8] = &[0x7D, 0x85, 0x00, 0x01, 0xAA];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::FuB);
        assert!(hdr.fu_start);
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 4);
    }

    #[test]
    fn test_fu_b_too_short() {
        // FU-B needs 4 bytes minimum (indicator + FU hdr + 2 DON)
        let result = H264PayloadHeader::parse(&[0x7D, 0x85, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sps() {
        // F=0, NRI=3, Type=7 (SPS) → 0x67
        let data: &[u8] = &[0x67, 0x42, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::Sps);
        assert!(hdr.is_keyframe());
    }

    #[test]
    fn test_stap_a_with_idr() {
        // STAP-A indicator: F=0, NRI=3, Type=24 → 0x78
        // NAL 1: SPS (type 7), 3 bytes
        // NAL 2: PPS (type 8), 2 bytes
        // NAL 3: IDR (type 5), 4 bytes
        let data: &[u8] = &[
            0x78, // STAP-A indicator
            0x00, 0x03, 0x67, 0x42, 0x00, // SPS: size=3, [0x67, 0x42, 0x00]
            0x00, 0x02, 0x68, 0xCE,       // PPS: size=2, [0x68, 0xCE]
            0x00, 0x04, 0x65, 0x88, 0x00, 0x01, // IDR: size=4
        ];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::StapA);
        assert!(hdr.stap_a_has_idr);
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_stap_a_without_idr() {
        // STAP-A with only non-IDR slices
        let data: &[u8] = &[
            0x78, // STAP-A indicator
            0x00, 0x02, 0x41, 0x00, // non-IDR: size=2, type=1
            0x00, 0x02, 0x41, 0x01, // non-IDR: size=2, type=1
        ];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.nal_unit_type, NalUnitType::StapA);
        assert!(!hdr.stap_a_has_idr);
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_stap_a_truncated() {
        // STAP-A with size field pointing past end of data
        let data: &[u8] = &[
            0x78, // STAP-A indicator
            0x00, 0xFF, // size=255 but only 1 byte follows
            0x67,
        ];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        // Should not crash, just stop walking
        assert_eq!(hdr.nal_unit_type, NalUnitType::StapA);
        assert!(!hdr.stap_a_has_idr);
    }

    #[test]
    fn test_too_short() {
        let result = H264PayloadHeader::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fu_a_too_short() {
        let result = H264PayloadHeader::parse(&[0x7C]);
        assert!(result.is_err());
    }

    #[test]
    fn test_layer_info() {
        let hdr = H264PayloadHeader {
            forbidden_zero: false,
            nri: 3,
            nal_unit_type: NalUnitType::SliceIdr,
            fu_nal_type: None,
            fu_start: false,
            fu_end: false,
            stap_a_has_idr: false,
            header_len_bytes: 1,
        };
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, None);
        assert_eq!(info.spatial_layer, None);
    }
}
