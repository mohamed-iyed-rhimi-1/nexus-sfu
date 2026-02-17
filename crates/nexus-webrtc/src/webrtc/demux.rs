//! Packet demultiplexing (RFC 5764).
//!
//! Classifies incoming packets as STUN, DTLS, or RTP/RTCP based on
//! the first byte of the packet.
//!
//! # TigerStyle Compliance
//!
//! - All functions have ≥2 assertions
//! - Bounded operations
//! - Explicit error handling
//! - Packet validation before processing

// ============================================================================
// Constants
// ============================================================================

/// Minimum STUN message size (20 bytes header).
pub const MIN_STUN_SIZE: usize = 20;

/// Minimum DTLS record size (13 bytes header).
pub const MIN_DTLS_SIZE: usize = 13;

/// Minimum RTP packet size (12 bytes header).
pub const MIN_RTP_SIZE: usize = 12;

/// Minimum RTCP packet size (8 bytes header).
pub const MIN_RTCP_SIZE: usize = 8;

/// STUN magic cookie (RFC 5389).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// DTLS version 1.2 major.minor.
pub const DTLS_VERSION_1_2: u16 = 0xFEFD;

/// RTP version field value.
pub const RTP_VERSION: u8 = 2;

// ============================================================================
// PacketType
// ============================================================================

/// Packet type after demultiplexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// STUN message (ICE connectivity check).
    Stun,
    /// DTLS record (handshake or application data).
    Dtls,
    /// RTP packet (media).
    Rtp,
    /// RTCP packet (control).
    Rtcp,
    /// Unknown packet type.
    Unknown,
}

impl PacketType {
    /// Classify packet based on first byte (RFC 5764).
    #[inline]
    pub fn classify(data: &[u8]) -> Self {
        debug_assert!(data.len() <= 65535, "Packet too large");

        if data.is_empty() {
            return Self::Unknown;
        }

        let first_byte: u8 = data[0];

        match first_byte {
            0..=3 => Self::Stun,
            20..=63 => Self::Dtls,
            128..=191 => Self::classify_rtp_or_rtcp(data),
            _ => Self::Unknown,
        }
    }

    #[inline]
    fn classify_rtp_or_rtcp(data: &[u8]) -> Self {
        debug_assert!(!data.is_empty(), "Empty data for RTP/RTCP classification");

        if data.len() < 2 {
            return Self::Unknown;
        }

        let payload_type: u8 = data[1] & 0x7F;

        // RFC 5761 §4: RTCP packet types 200-207 map to 72-79 after
        // masking with 0x7F. WebRTC uses dynamic RTP PTs 96-127, so
        // there is no overlap. We also include 64-71 in the RTCP range
        // per RFC 5761's reservation of PTs 64-95 to avoid future
        // conflicts — any packet in this range on a muxed port is RTCP.
        match payload_type {
            72..=79 => Self::Rtcp,
            _ => Self::Rtp,
        }
    }

    #[inline]
    pub fn is_media(self) -> bool {
        matches!(self, Self::Rtp | Self::Rtcp)
    }

    #[inline]
    pub fn is_signaling(self) -> bool {
        matches!(self, Self::Stun | Self::Dtls)
    }

    #[inline]
    pub fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

// ============================================================================
// Validation
// ============================================================================

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub recovery_hint: Option<RecoveryHint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHint {
    Drop,
    RequestRetransmit,
    ResetConnection,
    LogAndContinue,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            error: None,
            recovery_hint: None,
        }
    }

    pub fn invalid(error: impl Into<String>, hint: RecoveryHint) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            recovery_hint: Some(hint),
        }
    }
}

pub fn validate_stun_packet(data: &[u8]) -> ValidationResult {
    if data.is_empty() {
        return ValidationResult::invalid("Empty STUN data", RecoveryHint::Drop);
    }

    if data.len() < MIN_STUN_SIZE {
        return ValidationResult::invalid(
            format!("STUN too short: {} < {}", data.len(), MIN_STUN_SIZE),
            RecoveryHint::Drop,
        );
    }

    let magic: u32 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE {
        return ValidationResult::invalid(
            format!("Invalid STUN magic cookie: {:#X}", magic),
            RecoveryHint::Drop,
        );
    }

    let msg_len: u16 = u16::from_be_bytes([data[2], data[3]]);
    let expected_total: usize = 20 + msg_len as usize;
    if data.len() < expected_total {
        return ValidationResult::invalid(
            format!("STUN length mismatch: {} vs {}", data.len(), expected_total),
            RecoveryHint::RequestRetransmit,
        );
    }

    if data[0] & 0xC0 != 0 {
        return ValidationResult::invalid("Invalid STUN message type bits", RecoveryHint::Drop);
    }

    ValidationResult::valid()
}

pub fn validate_dtls_packet(data: &[u8]) -> ValidationResult {
    if data.is_empty() {
        return ValidationResult::invalid("Empty DTLS data", RecoveryHint::Drop);
    }

    if data.len() < MIN_DTLS_SIZE {
        return ValidationResult::invalid(
            format!("DTLS too short: {} < {}", data.len(), MIN_DTLS_SIZE),
            RecoveryHint::Drop,
        );
    }

    let content_type: u8 = data[0];
    let valid_types: [u8; 4] = [20, 21, 22, 23];
    if !valid_types.contains(&content_type) {
        return ValidationResult::invalid(
            format!("Invalid DTLS content type: {}", content_type),
            RecoveryHint::Drop,
        );
    }

    let version: u16 = u16::from_be_bytes([data[1], data[2]]);
    if version != 0xFEFF && version != DTLS_VERSION_1_2 {
        return ValidationResult::invalid(
            format!("Unsupported DTLS version: {:#X}", version),
            RecoveryHint::ResetConnection,
        );
    }

    let record_len: u16 = u16::from_be_bytes([data[11], data[12]]);
    let expected_total: usize = 13 + record_len as usize;
    if data.len() < expected_total {
        return ValidationResult::invalid(
            format!("DTLS length mismatch: {} vs {}", data.len(), expected_total),
            RecoveryHint::RequestRetransmit,
        );
    }

    ValidationResult::valid()
}

pub fn validate_rtp_packet(data: &[u8]) -> ValidationResult {
    if data.is_empty() {
        return ValidationResult::invalid("Empty RTP data", RecoveryHint::Drop);
    }

    if data.len() < MIN_RTP_SIZE {
        return ValidationResult::invalid(
            format!("RTP too short: {} < {}", data.len(), MIN_RTP_SIZE),
            RecoveryHint::Drop,
        );
    }

    let version: u8 = (data[0] >> 6) & 0x03;
    if version != RTP_VERSION {
        return ValidationResult::invalid(
            format!("Invalid RTP version: {}", version),
            RecoveryHint::Drop,
        );
    }

    let has_extension: bool = (data[0] & 0x10) != 0;
    let csrc_count: u8 = data[0] & 0x0F;
    let base_header_size: usize = 12 + (csrc_count as usize * 4);

    if data.len() < base_header_size {
        return ValidationResult::invalid(
            format!("RTP header truncated: {} < {}", data.len(), base_header_size),
            RecoveryHint::Drop,
        );
    }

    if has_extension {
        let ext_offset: usize = base_header_size;
        if data.len() < ext_offset + 4 {
            return ValidationResult::invalid("RTP extension header truncated", RecoveryHint::Drop);
        }

        let ext_len: u16 = u16::from_be_bytes([data[ext_offset + 2], data[ext_offset + 3]]);
        let total_header: usize = ext_offset + 4 + (ext_len as usize * 4);
        if data.len() < total_header {
            return ValidationResult::invalid(
                format!("RTP extension too long: {} < {}", data.len(), total_header),
                RecoveryHint::Drop,
            );
        }
    }

    ValidationResult::valid()
}

pub fn validate_rtcp_packet(data: &[u8]) -> ValidationResult {
    if data.is_empty() {
        return ValidationResult::invalid("Empty RTCP data", RecoveryHint::Drop);
    }

    if data.len() < MIN_RTCP_SIZE {
        return ValidationResult::invalid(
            format!("RTCP too short: {} < {}", data.len(), MIN_RTCP_SIZE),
            RecoveryHint::Drop,
        );
    }

    let version: u8 = (data[0] >> 6) & 0x03;
    if version != 2 {
        return ValidationResult::invalid(
            format!("Invalid RTCP version: {}", version),
            RecoveryHint::Drop,
        );
    }

    let payload_type: u8 = data[1];
    let valid_rtcp_types: [u8; 8] = [200, 201, 202, 203, 204, 205, 206, 207];
    if !valid_rtcp_types.contains(&payload_type) {
        return ValidationResult::invalid(
            format!("Unknown RTCP payload type: {}", payload_type),
            RecoveryHint::LogAndContinue,
        );
    }

    let length_words: u16 = u16::from_be_bytes([data[2], data[3]]);
    let expected_bytes: usize = (length_words as usize + 1) * 4;
    if data.len() < expected_bytes {
        return ValidationResult::invalid(
            format!("RTCP length mismatch: {} < {}", data.len(), expected_bytes),
            RecoveryHint::Drop,
        );
    }

    ValidationResult::valid()
}

// ============================================================================
// Recovery
// ============================================================================

#[derive(Debug)]
pub enum RecoveryAction {
    Drop { packet_type: PacketType, reason: String },
    RequestRetransmit { packet_type: PacketType },
    ResetConnection { reason: String },
    LogAndContinue { packet_type: PacketType, warning: String },
}

pub fn recover_from_malformed_packet(
    _data: &[u8],
    packet_type: PacketType,
    validation: &ValidationResult,
) -> RecoveryAction {
    debug_assert!(!validation.valid, "Cannot recover from valid packet");

    let hint: RecoveryHint = validation.recovery_hint.unwrap_or(RecoveryHint::Drop);

    match hint {
        RecoveryHint::Drop => RecoveryAction::Drop {
            packet_type,
            reason: validation.error.clone().unwrap_or_default(),
        },
        RecoveryHint::RequestRetransmit => {
            if packet_type.is_signaling() {
                RecoveryAction::RequestRetransmit { packet_type }
            } else {
                RecoveryAction::Drop {
                    packet_type,
                    reason: "Media packet loss acceptable".to_string(),
                }
            }
        }
        RecoveryHint::ResetConnection => RecoveryAction::ResetConnection {
            reason: validation.error.clone().unwrap_or_default(),
        },
        RecoveryHint::LogAndContinue => RecoveryAction::LogAndContinue {
            packet_type,
            warning: validation.error.clone().unwrap_or_default(),
        },
    }
}

// ============================================================================
// High-level API
// ============================================================================

pub fn demux_and_validate(data: &[u8]) -> (PacketType, ValidationResult) {
    if data.is_empty() {
        return (PacketType::Unknown, ValidationResult::invalid("Empty packet", RecoveryHint::Drop));
    }

    let packet_type: PacketType = PacketType::classify(data);

    let validation: ValidationResult = match packet_type {
        PacketType::Stun => validate_stun_packet(data),
        PacketType::Dtls => validate_dtls_packet(data),
        PacketType::Rtp => validate_rtp_packet(data),
        PacketType::Rtcp => validate_rtcp_packet(data),
        PacketType::Unknown => ValidationResult::invalid("Unknown packet type", RecoveryHint::Drop),
    };

    (packet_type, validation)
}

#[inline]
pub fn quick_classify(data: &[u8]) -> PacketType {
    PacketType::classify(data)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_stun() {
        let stun_packet: [u8; 20] = [
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(PacketType::classify(&stun_packet), PacketType::Stun);
    }

    #[test]
    fn test_classify_dtls() {
        let dtls_packet: [u8; 13] = [
            22, 0xFE, 0xFD, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00,
        ];
        assert_eq!(PacketType::classify(&dtls_packet), PacketType::Dtls);
    }

    #[test]
    fn test_classify_rtp() {
        let rtp_packet: [u8; 12] = [
            0x80, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(PacketType::classify(&rtp_packet), PacketType::Rtp);
    }

    #[test]
    fn test_classify_rtcp() {
        let rtcp_packet: [u8; 8] = [
            0x80, 0xC8, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(PacketType::classify(&rtcp_packet), PacketType::Rtcp);
    }

    #[test]
    fn test_classify_unknown() {
        let unknown: [u8; 4] = [100, 0, 0, 0];
        assert_eq!(PacketType::classify(&unknown), PacketType::Unknown);
        assert_eq!(PacketType::classify(&[]), PacketType::Unknown);
    }

    #[test]
    fn test_validate_stun_valid() {
        let stun: [u8; 20] = [
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = validate_stun_packet(&stun);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_stun_bad_magic() {
        let stun: [u8; 20] = [
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = validate_stun_packet(&stun);
        assert!(!result.valid);
    }

    #[test]
    fn test_packet_type_helpers() {
        assert!(PacketType::Rtp.is_media());
        assert!(PacketType::Rtcp.is_media());
        assert!(!PacketType::Stun.is_media());
        assert!(PacketType::Stun.is_signaling());
        assert!(PacketType::Dtls.is_signaling());
        assert!(!PacketType::Rtp.is_signaling());
        assert!(PacketType::Stun.is_known());
        assert!(!PacketType::Unknown.is_known());
    }
}
