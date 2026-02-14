//! REMB (Receiver Estimated Maximum Bitrate) Generation
//!
//! Creates RTCP PSFB packets with REMB payload according to draft-alvestrand-rmcat-remb.

pub type Ssrc = u32;

const RTCP_VERSION: u8 = 2;
const RTCP_PSFB_PT: u8 = 206;
const RTCP_PSFB_FMT_REMB: u8 = 15;
const REMB_IDENTIFIER: [u8; 4] = *b"REMB";
const REMB_PACKET_LENGTH: usize = 24;

/// REMB packet generator
pub struct RembGenerator {
    sender_ssrc: Ssrc,
}

impl RembGenerator {
    /// Create new REMB generator
    pub fn new(sender_ssrc: Ssrc) -> Self {
        Self { sender_ssrc }
    }

    /// Generate REMB packet for target bitrate
    ///
    /// Packet format (RFC 5104 + draft-alvestrand-rmcat-remb):
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |V=2|P| FMT=15  |   PT=206      |             length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  SSRC of packet sender                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  SSRC of media source                         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Unique identifier 'R' 'E' 'M' 'B'                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Num SSRC     | BR Exp    |  BR Mantissa                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   SSRC feedback                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn generate(&self, target_bitrate_bps: u64, media_ssrc: Ssrc) -> Vec<u8> {
        assert!(target_bitrate_bps > 0, "Bitrate must be positive");

        let mut packet = vec![0u8; REMB_PACKET_LENGTH];

        // Byte 0: V=2, P=0, FMT=15
        packet[0] = (RTCP_VERSION << 6) | RTCP_PSFB_FMT_REMB;

        // Byte 1: PT=206 (PSFB)
        packet[1] = RTCP_PSFB_PT;

        // Bytes 2-3: Length in 32-bit words minus 1
        // Total length is 24 bytes = 6 words, so length field = 5
        let length_words = (REMB_PACKET_LENGTH / 4) - 1;
        packet[2] = ((length_words >> 8) & 0xFF) as u8;
        packet[3] = (length_words & 0xFF) as u8;

        // Bytes 4-7: SSRC of packet sender
        packet[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());

        // Bytes 8-11: SSRC of media source (0 for REMB)
        packet[8..12].copy_from_slice(&0u32.to_be_bytes());

        // Bytes 12-15: Unique identifier "REMB"
        packet[12..16].copy_from_slice(&REMB_IDENTIFIER);

        // Bytes 16-19: Num SSRC (1) | BR Exp | BR Mantissa
        let (exp, mantissa) = Self::encode_bitrate(target_bitrate_bps);
        packet[16] = 1; // Num SSRC
        packet[17] = (exp << 2) | ((mantissa >> 16) & 0x03) as u8;
        packet[18] = ((mantissa >> 8) & 0xFF) as u8;
        packet[19] = (mantissa & 0xFF) as u8;

        // Bytes 20-23: SSRC feedback
        packet[20..24].copy_from_slice(&media_ssrc.to_be_bytes());

        assert_eq!(packet.len(), REMB_PACKET_LENGTH, "Packet length mismatch");

        packet
    }

    /// Encode bitrate as exponent and mantissa
    ///
    /// Bitrate = mantissa × 2^exp
    /// Mantissa is 18 bits, exponent is 6 bits
    fn encode_bitrate(bitrate_bps: u64) -> (u8, u32) {
        if bitrate_bps == 0 {
            return (0, 0);
        }

        // Find smallest exponent where mantissa fits in 18 bits
        let mut exp = 0u8;
        let mut mantissa = bitrate_bps;

        while mantissa > 0x3FFFF && exp < 63 {
            // 0x3FFFF = 2^18 - 1
            mantissa >>= 1;
            exp += 1;
        }

        assert!(mantissa < (1 << 18), "Mantissa exceeds 18-bit limit");
        assert!(exp <= 63, "Exponent exceeds 6-bit limit");

        (exp, mantissa as u32)
    }

    /// Decode bitrate from exponent and mantissa (for testing)
    #[cfg(test)]
    fn decode_bitrate(exp: u8, mantissa: u32) -> u64 {
        (mantissa as u64) << exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bitrate() {
        // Test exact powers of 2
        assert_eq!(RembGenerator::encode_bitrate(1024), (0, 1024));
        // 1 << 18 = 262144 exceeds 0x3FFFF (262143), so it gets shifted
        // 262144 >> 1 = 131072, exp = 1
        assert_eq!(RembGenerator::encode_bitrate(1 << 18), (1, 131072));

        // Test 1 Mbps
        let (exp, mantissa) = RembGenerator::encode_bitrate(1_000_000);
        let decoded = RembGenerator::decode_bitrate(exp, mantissa);
        // Allow some rounding error
        assert!((decoded as i64 - 1_000_000).abs() < 10_000);

        // Test 10 Mbps
        let (exp, mantissa) = RembGenerator::encode_bitrate(10_000_000);
        let decoded = RembGenerator::decode_bitrate(exp, mantissa);
        assert!((decoded as i64 - 10_000_000).abs() < 100_000);
    }

    #[test]
    fn test_generate_remb_packet() {
        let generator = RembGenerator::new(0x12345678);
        let packet = generator.generate(1_000_000, 0x87654321);

        assert_eq!(packet.len(), REMB_PACKET_LENGTH);

        // Check version and format
        assert_eq!(packet[0] >> 6, RTCP_VERSION);
        assert_eq!(packet[0] & 0x1F, RTCP_PSFB_FMT_REMB);

        // Check packet type
        assert_eq!(packet[1], RTCP_PSFB_PT);

        // Check sender SSRC
        let sender_ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        assert_eq!(sender_ssrc, 0x12345678);

        // Check REMB identifier
        assert_eq!(&packet[12..16], b"REMB");

        // Check num SSRC
        assert_eq!(packet[16], 1);

        // Check media SSRC
        let media_ssrc = u32::from_be_bytes([packet[20], packet[21], packet[22], packet[23]]);
        assert_eq!(media_ssrc, 0x87654321);
    }

    #[test]
    fn test_bitrate_encoding_roundtrip() {
        let test_bitrates = vec![
            100_000,   // 100 kbps
            500_000,   // 500 kbps
            1_000_000, // 1 Mbps
            5_000_000, // 5 Mbps
            10_000_000, // 10 Mbps
        ];

        for bitrate in test_bitrates {
            let (exp, mantissa) = RembGenerator::encode_bitrate(bitrate);
            let decoded = RembGenerator::decode_bitrate(exp, mantissa);

            // Allow 5% error due to quantization
            let error_percent = ((decoded as i64 - bitrate as i64).abs() * 100) / bitrate as i64;
            assert!(
                error_percent < 5,
                "Bitrate {} encoded/decoded with {}% error",
                bitrate,
                error_percent
            );
        }
    }

    #[test]
    #[should_panic(expected = "Bitrate must be positive")]
    fn test_zero_bitrate_panics() {
        let generator = RembGenerator::new(0);
        generator.generate(0, 0);
    }
}
