//! SRTP types and configuration.
//!
//! Core types for SRTP session configuration following RFC 3711 and RFC 7714.

use core::fmt;

// ============================================================================
// Type-Safe Wrappers (TigerStyle)
// ============================================================================

/// SSRC (Synchronization Source) identifier.
///
/// Type-safe wrapper for 32-bit SSRC values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Ssrc(pub u32);

impl Ssrc {
    /// Create from raw value.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    
    /// Get raw value.
    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl From<u32> for Ssrc {
    #[inline]
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl fmt::Display for Ssrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

/// RTP sequence number.
///
/// Type-safe wrapper for 16-bit sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct SeqNum(pub u16);

impl SeqNum {
    /// Create from raw value.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }
    
    /// Get raw value.
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
    
    /// Wrapping increment.
    #[inline]
    pub const fn wrapping_add(self, n: u16) -> Self {
        Self(self.0.wrapping_add(n))
    }
}

impl From<u16> for SeqNum {
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Rollover Counter (ROC).
///
/// Type-safe wrapper for 32-bit ROC values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Roc(pub u32);

impl Roc {
    /// Create from raw value.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    
    /// Get raw value.
    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }
    
    /// Saturating increment.
    #[inline]
    pub const fn saturating_add(self, n: u32) -> Self {
        Self(self.0.saturating_add(n))
    }
}

impl From<u32> for Roc {
    #[inline]
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl fmt::Display for Roc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SRTP protection profile (from DTLS-SRTP).
///
/// Defines the cipher suite and key lengths for SRTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtectionProfile {
    /// SRTP_AEAD_AES_128_GCM (RFC 7714)
    /// Key: 16 bytes, Salt: 12 bytes, Tag: 16 bytes
    AeadAes128Gcm = 0x0007,
    
    /// SRTP_AEAD_AES_256_GCM (RFC 7714)
    /// Key: 32 bytes, Salt: 12 bytes, Tag: 16 bytes
    AeadAes256Gcm = 0x0008,
    
    /// SRTP_AES128_CM_HMAC_SHA1_80 (RFC 5764)
    /// Key: 16 bytes, Salt: 14 bytes, Tag: 10 bytes
    Aes128CmHmacSha1_80 = 0x0001,
    
    /// SRTP_AES128_CM_HMAC_SHA1_32 (RFC 5764)
    /// Key: 16 bytes, Salt: 14 bytes, Tag: 4 bytes
    Aes128CmHmacSha1_32 = 0x0002,
}

impl ProtectionProfile {
    /// Get key length in bytes.
    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => 16,
            Self::AeadAes256Gcm => 32,
            Self::Aes128CmHmacSha1_80 => 16,
            Self::Aes128CmHmacSha1_32 => 16,
        }
    }
    
    /// Get salt length in bytes.
    #[inline]
    pub const fn salt_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => 12,
            Self::AeadAes256Gcm => 12,
            Self::Aes128CmHmacSha1_80 => 14,
            Self::Aes128CmHmacSha1_32 => 14,
        }
    }
    
    /// Get authentication tag length in bytes.
    #[inline]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => 16,
            Self::AeadAes256Gcm => 16,
            Self::Aes128CmHmacSha1_80 => 10,
            Self::Aes128CmHmacSha1_32 => 4,
        }
    }
    
    /// Get total key material length (key + salt for both RTP and RTCP).
    #[inline]
    pub const fn master_key_len(self) -> usize {
        self.key_len() + self.salt_len()
    }
    
    /// Check if this is an AEAD cipher suite.
    #[inline]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }
    
    /// Try to create from raw u16 value.
    #[inline]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0007 => Some(Self::AeadAes128Gcm),
            0x0008 => Some(Self::AeadAes256Gcm),
            0x0001 => Some(Self::Aes128CmHmacSha1_80),
            0x0002 => Some(Self::Aes128CmHmacSha1_32),
            _ => None,
        }
    }
}

impl Default for ProtectionProfile {
    fn default() -> Self {
        Self::AeadAes128Gcm
    }
}

/// SRTP policy configuration.
///
/// Configures SRTP session behavior.
#[derive(Debug, Clone, Copy)]
pub struct SrtpPolicy {
    /// Protection profile (cipher suite).
    pub profile: ProtectionProfile,
    
    /// Allow replay protection to be disabled (for testing only).
    pub allow_replay: bool,
    
    /// Window size for replay protection.
    pub window_size: u64,
    
    /// SSRC value (0 = any SSRC allowed).
    pub ssrc: u32,
}

impl Default for SrtpPolicy {
    fn default() -> Self {
        Self {
            profile: ProtectionProfile::default(),
            allow_replay: false,
            window_size: super::REPLAY_WINDOW_SIZE,
            ssrc: 0,
        }
    }
}

impl SrtpPolicy {
    /// Create policy for AES-128-GCM.
    #[inline]
    pub const fn aes_128_gcm() -> Self {
        Self {
            profile: ProtectionProfile::AeadAes128Gcm,
            allow_replay: false,
            window_size: super::REPLAY_WINDOW_SIZE,
            ssrc: 0,
        }
    }
    
    /// Create policy with specific SSRC.
    #[inline]
    pub const fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }
    
    /// Create policy with replay allowed (testing only).
    #[inline]
    pub const fn with_allow_replay(mut self) -> Self {
        self.allow_replay = true;
        self
    }
}

/// RTP header parsed from packet.
///
/// Zero-copy view into RTP header fields.
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    /// RTP version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Extension flag.
    pub extension: bool,
    /// CSRC count.
    pub csrc_count: u8,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// SSRC.
    pub ssrc: u32,
    /// Total header length (including CSRC and extensions).
    pub header_len: usize,
}

impl RtpHeader {
    /// Parse RTP header from bytes.
    ///
    /// Returns None if packet is too short or invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < super::RTP_HEADER_SIZE {
            return None;
        }
        
        let first = data[0];
        let version = (first >> 6) & 0x03;
        
        // Version must be 2
        if version != 2 {
            return None;
        }
        
        let padding = (first & 0x20) != 0;
        let extension = (first & 0x10) != 0;
        let csrc_count = first & 0x0F;
        
        let second = data[1];
        let marker = (second & 0x80) != 0;
        let payload_type = second & 0x7F;
        
        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        
        // Calculate header length
        let mut header_len = super::RTP_HEADER_SIZE + (csrc_count as usize * 4);
        
        // Check for header extension
        if extension {
            if data.len() < header_len + 4 {
                return None;
            }
            // Extension length is in 32-bit words
            let ext_len = u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]);
            header_len += 4 + (ext_len as usize * 4);
        }
        
        if data.len() < header_len {
            return None;
        }
        
        Some(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            header_len,
        })
    }
    
    /// Get payload offset.
    #[inline]
    pub const fn payload_offset(&self) -> usize {
        self.header_len
    }
}

/// RTCP header parsed from packet.
#[derive(Debug, Clone, Copy)]
pub struct RtcpHeader {
    /// RTCP version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Reception report count / format.
    pub count: u8,
    /// Packet type.
    pub packet_type: u8,
    /// Length in 32-bit words minus one.
    pub length: u16,
    /// SSRC of sender.
    pub ssrc: u32,
}

impl RtcpHeader {
    /// Parse RTCP header from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < super::RTCP_HEADER_SIZE {
            return None;
        }
        
        let first = data[0];
        let version = (first >> 6) & 0x03;
        
        if version != 2 {
            return None;
        }
        
        let padding = (first & 0x20) != 0;
        let count = first & 0x1F;
        let packet_type = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);
        let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        Some(Self {
            version,
            padding,
            count,
            packet_type,
            length,
            ssrc,
        })
    }
    
    /// Get packet length in bytes (including header).
    #[inline]
    pub const fn packet_len(&self) -> usize {
        (self.length as usize + 1) * 4
    }
}

/// SRTP packet index (48-bit).
///
/// Combines ROC (32-bit) and sequence number (16-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketIndex(pub u64);

impl PacketIndex {
    /// Create from ROC and sequence number.
    #[inline]
    pub const fn new(roc: u32, seq: u16) -> Self {
        Self(((roc as u64) << 16) | (seq as u64))
    }
    
    /// Get the ROC component.
    #[inline]
    pub const fn roc(self) -> u32 {
        (self.0 >> 16) as u32
    }
    
    /// Get the sequence number component.
    #[inline]
    pub const fn seq(self) -> u16 {
        self.0 as u16
    }
    
    /// Get raw 48-bit value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PacketIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.roc(), self.seq())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_profile_key_lengths() {
        let p = ProtectionProfile::AeadAes128Gcm;
        assert_eq!(p.key_len(), 16);
        assert_eq!(p.salt_len(), 12);
        assert_eq!(p.tag_len(), 16);
        assert!(p.is_aead());
        
        let p = ProtectionProfile::Aes128CmHmacSha1_80;
        assert_eq!(p.key_len(), 16);
        assert_eq!(p.salt_len(), 14);
        assert_eq!(p.tag_len(), 10);
        assert!(!p.is_aead());
    }

    #[test]
    fn test_protection_profile_from_u16() {
        assert_eq!(
            ProtectionProfile::from_u16(0x0007),
            Some(ProtectionProfile::AeadAes128Gcm)
        );
        assert_eq!(
            ProtectionProfile::from_u16(0x0001),
            Some(ProtectionProfile::Aes128CmHmacSha1_80)
        );
        assert_eq!(ProtectionProfile::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_rtp_header_parse() {
        // Valid RTP packet
        let rtp = [
            0x80, 0x60, // V=2, P=0, X=0, CC=0, M=0, PT=96
            0x00, 0x01, // Seq=1
            0x00, 0x00, 0x00, 0x64, // Timestamp=100
            0x12, 0x34, 0x56, 0x78, // SSRC=0x12345678
            0x00, 0x00, 0x00, 0x00, // Payload
        ];
        
        let hdr = RtpHeader::parse(&rtp).unwrap();
        assert_eq!(hdr.version, 2);
        assert!(!hdr.padding);
        assert!(!hdr.extension);
        assert_eq!(hdr.csrc_count, 0);
        assert!(!hdr.marker);
        assert_eq!(hdr.payload_type, 96);
        assert_eq!(hdr.sequence_number, 1);
        assert_eq!(hdr.timestamp, 100);
        assert_eq!(hdr.ssrc, 0x12345678);
        assert_eq!(hdr.header_len, 12);
    }

    #[test]
    fn test_rtp_header_with_csrc() {
        let rtp = vec![
            0x82, 0x60, // V=2, CC=2
            0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x64, // Timestamp
            0x12, 0x34, 0x56, 0x78, // SSRC
            0xAA, 0xBB, 0xCC, 0xDD, // CSRC 1
            0x11, 0x22, 0x33, 0x44, // CSRC 2
        ];
        
        let hdr = RtpHeader::parse(&rtp).unwrap();
        assert_eq!(hdr.csrc_count, 2);
        assert_eq!(hdr.header_len, 20); // 12 + 2*4
    }

    #[test]
    fn test_rtp_header_invalid_version() {
        let rtp = [0x00, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x12, 0x34, 0x56, 0x78];
        assert!(RtpHeader::parse(&rtp).is_none());
    }

    #[test]
    fn test_rtp_header_too_short() {
        let rtp = [0x80, 0x60, 0x00, 0x01];
        assert!(RtpHeader::parse(&rtp).is_none());
    }

    #[test]
    fn test_rtcp_header_parse() {
        let rtcp = [
            0x80, 0xC8, // V=2, PT=200 (SR)
            0x00, 0x06, // Length=6
            0x12, 0x34, 0x56, 0x78, // SSRC
        ];
        
        let hdr = RtcpHeader::parse(&rtcp).unwrap();
        assert_eq!(hdr.version, 2);
        assert!(!hdr.padding);
        assert_eq!(hdr.count, 0);
        assert_eq!(hdr.packet_type, 200);
        assert_eq!(hdr.length, 6);
        assert_eq!(hdr.ssrc, 0x12345678);
        assert_eq!(hdr.packet_len(), 28); // (6+1)*4
    }

    #[test]
    fn test_packet_index() {
        let idx = PacketIndex::new(5, 1000);
        assert_eq!(idx.roc(), 5);
        assert_eq!(idx.seq(), 1000);
        assert_eq!(idx.value(), (5u64 << 16) | 1000);
        
        let idx2 = PacketIndex::new(5, 1001);
        assert!(idx < idx2);
    }

    #[test]
    fn test_srtp_policy() {
        let policy = SrtpPolicy::aes_128_gcm()
            .with_ssrc(0x12345678);
        
        assert_eq!(policy.profile, ProtectionProfile::AeadAes128Gcm);
        assert_eq!(policy.ssrc, 0x12345678);
        assert!(!policy.allow_replay);
    }
}
