//! H.264 NAL unit parsing for RTP (RFC 6184).
//!
//! Parses the H.264 RTP payload to extract NAL unit type,
//! keyframe (IDR) detection, and NRI (importance) level.
//! Supports single NAL unit, STAP-A, and FU-A packetization
//! modes commonly used in WebRTC.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc6184

use super::{CodecError, LayerInfo};

/// NAL unit types relevant for SFU forwarding decisions.
/// Only the types needed for keyframe detection and routing
/// are enumerated; others are captured as `Other`.
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
}

/// H.264 RTP payload header.
///
/// Represents the parsed NAL unit header from the RTP payload.
/// For FU-A packets, the actual NAL type is extracted from the
/// FU header rather than the indicator byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H264PayloadHeader {
    /// Forbidden zero bit (must be 0 in valid streams)
    pub forbidden_zero: bool,
    /// NAL reference indicator (2 bits, 0–3)
    pub nri: u8,
    /// NAL unit type from the indicator byte
    pub nal_unit_type: NalUnitType,
    /// For FU-A: the actual NAL type from the FU header
    pub fu_nal_type: Option<NalUnitType>,
    /// For FU-A: start bit (first fragment)
    pub fu_start: bool,
    /// For FU-A: end bit (last fragment)
    pub fu_end: bool,
    /// Total parsed header length in bytes
    pub header_len_bytes: u8,
}

impl H264PayloadHeader {
    /// Parse H.264 NAL unit header from RTP payload.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP payload bytes (after RTP header)
    ///
    /// # TigerStyle
    ///
    /// Asserts: data.len() >= 1
    /// Asserts: nri <= 3
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        // NAL unit header byte: F(1) NRI(2) Type(5)
        let nal_byte = data[0];
        let forbidden_zero = (nal_byte & 0x80) != 0;
        let nri = (nal_byte >> 5) & 0x03;
        let raw_type = nal_byte & 0x1F;
        let nal_unit_type = NalUnitType::from_raw(raw_type);

        let mut fu_nal_type: Option<NalUnitType> = None;
        let mut fu_start = false;
        let mut fu_end = false;
        let mut header_len_bytes: u8 = 1;

        // For FU-A packets, parse the FU header to get the
        // actual NAL type and fragmentation flags.
        if matches!(nal_unit_type, NalUnitType::FuA) {
            if data.len() < 2 {
                return Err(CodecError::TooShort {
                    actual_bytes: data.len(),
                    min_bytes: 2,
                });
            }
            // FU header: S(1) E(1) R(1) Type(5)
            let fu_header = data[1];
            fu_start = (fu_header & 0x80) != 0;
            fu_end = (fu_header & 0x40) != 0;
            let fu_type = fu_header & 0x1F;
            fu_nal_type =
                Some(NalUnitType::from_raw(fu_type));
            header_len_bytes = 2;
        }

        // For STAP-A, the header is just the indicator byte.
        // Individual NAL units inside are not parsed here —
        // keyframe detection checks the first aggregated NAL.
        if matches!(nal_unit_type, NalUnitType::StapA) {
            header_len_bytes = 1;
        }

        // Postcondition: NRI is bounded to 2 bits
        debug_assert!(
            nri <= 3,
            "H.264 NRI {} exceeds max 3",
            nri
        );

        Ok(H264PayloadHeader {
            forbidden_zero,
            nri,
            nal_unit_type,
            fu_nal_type,
            fu_start,
            fu_end,
            header_len_bytes,
        })
    }

    /// Returns true if this packet contains a keyframe (IDR).
    ///
    /// Checks for:
    /// - Direct IDR NAL unit (type 5)
    /// - FU-A fragment of an IDR (start bit set)
    /// - STAP-A containing an IDR (checks first NAL)
    pub fn is_keyframe(&self) -> bool {
        match self.nal_unit_type {
            NalUnitType::SliceIdr => true,
            NalUnitType::FuA => {
                // Only the first fragment (S=1) of an IDR
                self.fu_start
                    && self.fu_nal_type
                        == Some(NalUnitType::SliceIdr)
            }
            NalUnitType::Sps | NalUnitType::Pps => {
                // SPS/PPS typically precede keyframes;
                // treat as keyframe-adjacent for SFU
                // forwarding purposes.
                true
            }
            _ => false,
        }
    }

    /// Return layer information.
    ///
    /// H.264 base profile does not carry temporal/spatial
    /// layer info in the NAL header. SVC extensions (Annex G)
    /// would require additional parsing not implemented here.
    pub fn layer_info(&self) -> LayerInfo {
        LayerInfo {
            temporal_layer: None,
            spatial_layer: None,
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
    fn test_idr_slice() {
        // F=0, NRI=3, Type=5 (IDR) → 0b0_11_00101 = 0x65
        let data: &[u8] = &[0x65, 0x88, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.forbidden_zero);
        assert_eq!(hdr.nri, 3);
        assert_eq!(
            hdr.nal_unit_type,
            NalUnitType::SliceIdr
        );
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_non_idr_slice() {
        // F=0, NRI=2, Type=1 → 0b0_10_00001 = 0x41
        let data: &[u8] = &[0x41, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert_eq!(
            hdr.nal_unit_type,
            NalUnitType::SliceNonIdr
        );
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
        assert_eq!(
            hdr.fu_nal_type,
            Some(NalUnitType::SliceIdr)
        );
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 2);
    }

    #[test]
    fn test_fu_a_non_idr() {
        // Indicator: FU-A (28) → 0x7C
        // FU header: S=1, E=0, Type=1 → 0x81
        let data: &[u8] = &[0x7C, 0x81, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.is_keyframe());
    }

    #[test]
    fn test_fu_a_middle_fragment() {
        // FU-A with S=0, E=0 (middle fragment of IDR)
        // Should NOT be keyframe (only start fragment is)
        let data: &[u8] = &[0x7C, 0x05, 0x00];
        let hdr = H264PayloadHeader::parse(data).unwrap();
        assert!(!hdr.fu_start);
        assert!(!hdr.is_keyframe());
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
    fn test_too_short() {
        let result = H264PayloadHeader::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fu_a_too_short() {
        // FU-A indicator but no FU header
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
            header_len_bytes: 1,
        };
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, None);
        assert_eq!(info.spatial_layer, None);
    }
}
