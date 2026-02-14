//! Opus packet parsing for RTP (RFC 7587).
//!
//! Parses the Opus RTP payload to extract configuration,
//! channel count, and frame information. Opus is an audio
//! codec — every packet is independently decodable, so all
//! packets are effectively "keyframes" for SFU purposes.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc7587

use super::{CodecError, LayerInfo};

/// Opus bandwidth modes encoded in the TOC byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpusBandwidth {
    /// Narrowband (4 kHz)
    Narrowband,
    /// Medium-band (6 kHz)
    Mediumband,
    /// Wideband (8 kHz)
    Wideband,
    /// Super-wideband (12 kHz)
    SuperWideband,
    /// Fullband (20 kHz)
    Fullband,
}

/// Opus coding mode from the TOC byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpusMode {
    /// SILK-only mode (low bitrate, speech)
    Silk,
    /// Hybrid mode (SILK + CELT)
    Hybrid,
    /// CELT-only mode (high bitrate, music)
    Celt,
}

/// Opus RTP payload header.
///
/// The first byte of an Opus RTP payload is the TOC (Table of
/// Contents) byte, which encodes the configuration, stereo
/// flag, and frame count code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpusPayloadHeader {
    /// Configuration number (0–31)
    pub config: u8,
    /// True if stereo (2 channels), false if mono
    pub stereo: bool,
    /// Frame count code (0–3)
    ///   0 = 1 frame
    ///   1 = 2 frames, equal size
    ///   2 = 2 frames, different size
    ///   3 = arbitrary number of frames
    pub frame_count_code: u8,
    /// Coding mode derived from config
    pub mode: OpusMode,
    /// Bandwidth derived from config
    pub bandwidth: OpusBandwidth,
    /// Total parsed header length in bytes
    pub header_len_bytes: u8,
}

impl OpusPayloadHeader {
    /// Parse Opus TOC byte from RTP payload.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP payload bytes (after RTP header)
    ///
    /// # TigerStyle
    ///
    /// Asserts: data.len() >= 1
    /// Asserts: config <= 31
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::TooShort {
                actual_bytes: 0,
                min_bytes: 1,
            });
        }

        // TOC byte: config(5) s(1) c(2)
        let toc = data[0];
        let config = (toc >> 3) & 0x1F;
        let stereo = (toc & 0x04) != 0;
        let frame_count_code = toc & 0x03;

        // Derive mode and bandwidth from config number.
        // Config 0–3: SILK NB, Config 4–7: SILK MB,
        // Config 8–11: SILK WB, Config 12–13: Hybrid SWB,
        // Config 14–15: Hybrid FB, Config 16–19: CELT NB,
        // Config 20–23: CELT WB, Config 24–27: CELT SWB,
        // Config 28–31: CELT FB
        let (mode, bandwidth) = Self::decode_config(config);

        // Postcondition: config is bounded to 5 bits
        debug_assert!(
            config <= 31,
            "Opus config {} exceeds max 31",
            config
        );

        Ok(OpusPayloadHeader {
            config,
            stereo,
            frame_count_code,
            mode,
            bandwidth,
            header_len_bytes: 1,
        })
    }

    /// Decode mode and bandwidth from config number.
    ///
    /// The config number (0–31) encodes both the coding mode
    /// and the audio bandwidth per RFC 6716 Section 3.1.
    fn decode_config(config: u8) -> (OpusMode, OpusBandwidth) {
        match config {
            0..=3 => {
                (OpusMode::Silk, OpusBandwidth::Narrowband)
            }
            4..=7 => {
                (OpusMode::Silk, OpusBandwidth::Mediumband)
            }
            8..=11 => {
                (OpusMode::Silk, OpusBandwidth::Wideband)
            }
            12..=13 => {
                (OpusMode::Hybrid, OpusBandwidth::SuperWideband)
            }
            14..=15 => {
                (OpusMode::Hybrid, OpusBandwidth::Fullband)
            }
            16..=19 => {
                (OpusMode::Celt, OpusBandwidth::Narrowband)
            }
            20..=23 => {
                (OpusMode::Celt, OpusBandwidth::Wideband)
            }
            24..=27 => {
                (OpusMode::Celt, OpusBandwidth::SuperWideband)
            }
            28..=31 => {
                (OpusMode::Celt, OpusBandwidth::Fullband)
            }
            // Config is 5 bits, so 0–31 is exhaustive.
            // This branch is unreachable but required by
            // the compiler.
            _ => {
                (OpusMode::Celt, OpusBandwidth::Fullband)
            }
        }
    }

    /// Opus packets are always independently decodable.
    ///
    /// Every Opus packet can be decoded without reference to
    /// previous packets, making every packet a "keyframe"
    /// for SFU forwarding purposes.
    pub fn is_keyframe(&self) -> bool {
        true
    }

    /// Return layer information.
    ///
    /// Opus does not have temporal or spatial layers in the
    /// traditional video codec sense.
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
    fn test_silk_narrowband_mono() {
        // Config=0, stereo=0, code=0 → TOC = 0b00000_0_00 = 0x00
        let data: &[u8] = &[0x00, 0xFF];
        let hdr = OpusPayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.config, 0);
        assert!(!hdr.stereo);
        assert_eq!(hdr.frame_count_code, 0);
        assert_eq!(hdr.mode, OpusMode::Silk);
        assert_eq!(
            hdr.bandwidth,
            OpusBandwidth::Narrowband
        );
        assert!(hdr.is_keyframe());
        assert_eq!(hdr.header_len_bytes, 1);
    }

    #[test]
    fn test_celt_fullband_stereo() {
        // Config=31, stereo=1, code=1
        // TOC = 0b11111_1_01 = 0xFD
        let data: &[u8] = &[0xFD];
        let hdr = OpusPayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.config, 31);
        assert!(hdr.stereo);
        assert_eq!(hdr.frame_count_code, 1);
        assert_eq!(hdr.mode, OpusMode::Celt);
        assert_eq!(hdr.bandwidth, OpusBandwidth::Fullband);
    }

    #[test]
    fn test_hybrid_super_wideband() {
        // Config=12, stereo=0, code=0
        // TOC = 0b01100_0_00 = 0x60
        let data: &[u8] = &[0x60];
        let hdr = OpusPayloadHeader::parse(data).unwrap();
        assert_eq!(hdr.config, 12);
        assert_eq!(hdr.mode, OpusMode::Hybrid);
        assert_eq!(
            hdr.bandwidth,
            OpusBandwidth::SuperWideband
        );
    }

    #[test]
    fn test_too_short() {
        let result = OpusPayloadHeader::parse(&[]);
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
    fn test_always_keyframe() {
        // Every Opus packet is independently decodable
        for toc in 0..=255u8 {
            let data = [toc];
            let hdr =
                OpusPayloadHeader::parse(&data).unwrap();
            assert!(hdr.is_keyframe());
        }
    }

    #[test]
    fn test_layer_info_empty() {
        let data: &[u8] = &[0x00];
        let hdr = OpusPayloadHeader::parse(data).unwrap();
        let info = hdr.layer_info();
        assert_eq!(info.temporal_layer, None);
        assert_eq!(info.spatial_layer, None);
    }
}
