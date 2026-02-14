//! STUN Attribute Parsing and Encoding.
//!
//! Zero-allocation attribute handling with fixed-size buffers.
//!
//! # Supported Attributes
//!
//! - MAPPED-ADDRESS (0x0001)
//! - USERNAME (0x0006)
//! - MESSAGE-INTEGRITY (0x0008)
//! - ERROR-CODE (0x0009)
//! - XOR-MAPPED-ADDRESS (0x0020)
//! - PRIORITY (0x0024)
//! - USE-CANDIDATE (0x0025)
//! - FINGERPRINT (0x8028)
//! - ICE-CONTROLLED (0x8029)
//! - ICE-CONTROLLING (0x802A)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::message::STUN_MAGIC_COOKIE;
use crate::ice::error::IceError;

// Attribute type constants
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_PRIORITY: u16 = 0x0024;
pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
pub const ATTR_FINGERPRINT: u16 = 0x8028;
pub const ATTR_ICE_CONTROLLED: u16 = 0x8029;
pub const ATTR_ICE_CONTROLLING: u16 = 0x802A;

// TURN-specific attributes
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// Maximum username length (bytes).
pub const MAX_USERNAME_LEN: usize = 128;

/// Maximum realm/nonce length (bytes).
pub const MAX_REALM_LEN: usize = 128;

/// Maximum error reason length (bytes).
pub const MAX_REASON_LEN: usize = 128;

/// Maximum data attribute length (bytes).
pub const MAX_DATA_LEN: usize = 1200;

/// STUN Attribute.
///
/// Fixed-size representation of STUN attributes.
/// No heap allocation - uses inline arrays.
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS (0x0001).
    MappedAddress(SocketAddr),
    
    /// USERNAME (0x0006).
    Username {
        value: [u8; MAX_USERNAME_LEN],
        len: u8,
    },
    
    /// MESSAGE-INTEGRITY (0x0008).
    MessageIntegrity([u8; 20]),
    
    /// ERROR-CODE (0x0009).
    ErrorCode {
        code: u16,
        reason: [u8; MAX_REASON_LEN],
        reason_len: u8,
    },
    
    /// REALM (0x0014).
    Realm {
        value: [u8; MAX_REALM_LEN],
        len: u8,
    },
    
    /// NONCE (0x0015).
    Nonce {
        value: [u8; MAX_REALM_LEN],
        len: u8,
    },
    
    /// XOR-MAPPED-ADDRESS (0x0020).
    XorMappedAddress(SocketAddr),
    
    /// PRIORITY (0x0024).
    Priority(u32),
    
    /// USE-CANDIDATE (0x0025).
    UseCandidate,
    
    /// FINGERPRINT (0x8028).
    Fingerprint(u32),
    
    /// ICE-CONTROLLED (0x8029).
    IceControlled(u64),
    
    /// ICE-CONTROLLING (0x802A).
    IceControlling(u64),
    
    // TURN attributes
    
    /// CHANNEL-NUMBER (0x000C).
    ChannelNumber(u16),
    
    /// LIFETIME (0x000D).
    Lifetime(u32),
    
    /// XOR-PEER-ADDRESS (0x0012).
    XorPeerAddress(SocketAddr),
    
    /// XOR-RELAYED-ADDRESS (0x0016).
    XorRelayedAddress(SocketAddr),
    
    /// DATA (0x0013).
    Data {
        value: [u8; MAX_DATA_LEN],
        len: u16,
    },
    
    /// REQUESTED-TRANSPORT (0x0019).
    RequestedTransport(u8),
}

impl StunAttribute {
    /// Parse attribute from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `attr_type` - Attribute type code.
    /// * `value` - Attribute value bytes.
    /// * `transaction_id` - Transaction ID for XOR operations.
    ///
    /// # Returns
    ///
    /// Some(attribute) if known, None if unknown (to be ignored).
    ///
    /// # TigerStyle Compliance (Phase 4.8)
    ///
    /// - Split into parse_address_attribute, parse_ice_attribute, parse_turn_attribute
    /// - Assertions for value length bounds
    /// - Bounded dispatch with explicit attribute type ranges
    pub fn parse(
        attr_type: u16,
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<Option<Self>, IceError> {
        // For external input, use debug_assert to catch programming errors
        // Individual attribute parsers will return errors for invalid data
        debug_assert!(value.len() <= MAX_DATA_LEN,
            "Attribute value length {} exceeds maximum {}",
            value.len(), MAX_DATA_LEN);
        
        // Dispatch to specialized parsers based on attribute type category
        let attr = match attr_type {
            // Address-related attributes
            ATTR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS => {
                Self::parse_address_attribute(attr_type, value, transaction_id)?
            }
            
            // Core STUN attributes
            ATTR_USERNAME | ATTR_MESSAGE_INTEGRITY | ATTR_ERROR_CODE |
            ATTR_REALM | ATTR_NONCE => {
                Self::parse_core_attribute(attr_type, value)?
            }
            
            // ICE-specific attributes
            ATTR_PRIORITY | ATTR_USE_CANDIDATE | ATTR_FINGERPRINT |
            ATTR_ICE_CONTROLLED | ATTR_ICE_CONTROLLING => {
                Self::parse_ice_attribute(attr_type, value)?
            }
            
            // TURN-specific attributes
            ATTR_LIFETIME | ATTR_CHANNEL_NUMBER | ATTR_XOR_PEER_ADDRESS |
            ATTR_XOR_RELAYED_ADDRESS | ATTR_REQUESTED_TRANSPORT | ATTR_DATA => {
                Self::parse_turn_attribute(attr_type, value, transaction_id)?
            }
            
            // Unknown attribute - ignore if comprehension-optional (0x8000+)
            _ => None,
        };
        
        Ok(attr)
    }
    
    /// Parse address-related attributes (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS).
    ///
    /// # TigerStyle Compliance (Phase 4.8)
    ///
    /// - Extracted helper for 70-line limit
    /// - Minimum address length check (underlying functions return errors)
    #[inline]
    fn parse_address_attribute(
        attr_type: u16,
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<Option<Self>, IceError> {
        // Underlying parse functions handle short data with proper errors
        // Use debug_assert to catch programming errors in development
        debug_assert!(value.len() >= 4 || attr_type != ATTR_MAPPED_ADDRESS,
            "Address attribute requires at least 4 bytes");
        
        match attr_type {
            ATTR_MAPPED_ADDRESS => {
                let addr = parse_mapped_address(value, attr_type)?;
                Ok(Some(Self::MappedAddress(addr)))
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                let addr = parse_xor_address(value, transaction_id, attr_type)?;
                Ok(Some(Self::XorMappedAddress(addr)))
            }
            _ => Ok(None),
        }
    }
    
    /// Parse core STUN attributes (USERNAME, MESSAGE-INTEGRITY, ERROR-CODE, etc).
    ///
    /// # TigerStyle Compliance (Phase 4.8)
    ///
    /// - Extracted helper for 70-line limit
    /// - Length validations for each attribute type
    #[inline]
    fn parse_core_attribute(
        attr_type: u16,
        value: &[u8],
    ) -> Result<Option<Self>, IceError> {
        match attr_type {
            ATTR_USERNAME => {
                if value.len() > MAX_USERNAME_LEN {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "username too long",
                    });
                }
                let mut buf = [0u8; MAX_USERNAME_LEN];
                buf[..value.len()].copy_from_slice(value);
                Ok(Some(Self::Username {
                    value: buf,
                    len: value.len() as u8,
                }))
            }
            
            ATTR_MESSAGE_INTEGRITY => {
                if value.len() != 20 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "MESSAGE-INTEGRITY must be 20 bytes",
                    });
                }
                let mut hmac = [0u8; 20];
                hmac.copy_from_slice(value);
                Ok(Some(Self::MessageIntegrity(hmac)))
            }
            
            ATTR_ERROR_CODE => {
                if value.len() < 4 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "ERROR-CODE too short",
                    });
                }
                let class = (value[2] & 0x07) as u16;
                let number = value[3] as u16;
                let code = class * 100 + number;
                
                let reason_bytes = &value[4..];
                let reason_len = reason_bytes.len().min(MAX_REASON_LEN);
                let mut reason = [0u8; MAX_REASON_LEN];
                reason[..reason_len].copy_from_slice(&reason_bytes[..reason_len]);
                
                Ok(Some(Self::ErrorCode {
                    code,
                    reason,
                    reason_len: reason_len as u8,
                }))
            }
            
            ATTR_REALM => {
                if value.len() > MAX_REALM_LEN {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "realm too long",
                    });
                }
                let mut buf = [0u8; MAX_REALM_LEN];
                buf[..value.len()].copy_from_slice(value);
                Ok(Some(Self::Realm {
                    value: buf,
                    len: value.len() as u8,
                }))
            }
            
            ATTR_NONCE => {
                if value.len() > MAX_REALM_LEN {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "nonce too long",
                    });
                }
                let mut buf = [0u8; MAX_REALM_LEN];
                buf[..value.len()].copy_from_slice(value);
                Ok(Some(Self::Nonce {
                    value: buf,
                    len: value.len() as u8,
                }))
            }
            
            _ => Ok(None),
        }
    }
    
    /// Parse ICE-specific attributes (PRIORITY, USE-CANDIDATE, FINGERPRINT, etc).
    ///
    /// # TigerStyle Compliance (Phase 4.8)
    ///
    /// - Extracted helper for 70-line limit
    /// - Strict length validations per RFC 5245
    #[inline]
    fn parse_ice_attribute(
        attr_type: u16,
        value: &[u8],
    ) -> Result<Option<Self>, IceError> {
        match attr_type {
            ATTR_PRIORITY => {
                if value.len() != 4 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "PRIORITY must be 4 bytes",
                    });
                }
                let priority = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Some(Self::Priority(priority)))
            }
            
            ATTR_USE_CANDIDATE => {
                Ok(Some(Self::UseCandidate))
            }
            
            ATTR_FINGERPRINT => {
                if value.len() != 4 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "FINGERPRINT must be 4 bytes",
                    });
                }
                let fp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Some(Self::Fingerprint(fp)))
            }
            
            ATTR_ICE_CONTROLLED => {
                if value.len() != 8 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "ICE-CONTROLLED must be 8 bytes",
                    });
                }
                let tb = u64::from_be_bytes(value.try_into().unwrap());
                Ok(Some(Self::IceControlled(tb)))
            }
            
            ATTR_ICE_CONTROLLING => {
                if value.len() != 8 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "ICE-CONTROLLING must be 8 bytes",
                    });
                }
                let tb = u64::from_be_bytes(value.try_into().unwrap());
                Ok(Some(Self::IceControlling(tb)))
            }
            
            _ => Ok(None),
        }
    }
    
    /// Parse TURN-specific attributes (LIFETIME, CHANNEL-NUMBER, XOR-*-ADDRESS, etc).
    ///
    /// # TigerStyle Compliance (Phase 4.8)
    ///
    /// - Extracted helper for 70-line limit
    /// - Strict length validations per RFC 5766
    #[inline]
    fn parse_turn_attribute(
        attr_type: u16,
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<Option<Self>, IceError> {
        match attr_type {
            ATTR_LIFETIME => {
                if value.len() != 4 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "LIFETIME must be 4 bytes",
                    });
                }
                let lifetime = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Some(Self::Lifetime(lifetime)))
            }
            
            ATTR_CHANNEL_NUMBER => {
                if value.len() < 2 {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "CHANNEL-NUMBER too short",
                    });
                }
                let channel = u16::from_be_bytes([value[0], value[1]]);
                Ok(Some(Self::ChannelNumber(channel)))
            }
            
            ATTR_XOR_PEER_ADDRESS => {
                let addr = parse_xor_address(value, transaction_id, attr_type)?;
                Ok(Some(Self::XorPeerAddress(addr)))
            }
            
            ATTR_XOR_RELAYED_ADDRESS => {
                let addr = parse_xor_address(value, transaction_id, attr_type)?;
                Ok(Some(Self::XorRelayedAddress(addr)))
            }
            
            ATTR_REQUESTED_TRANSPORT => {
                if value.is_empty() {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "REQUESTED-TRANSPORT empty",
                    });
                }
                Ok(Some(Self::RequestedTransport(value[0])))
            }
            
            ATTR_DATA => {
                if value.len() > MAX_DATA_LEN {
                    return Err(IceError::StunInvalidAttribute {
                        attr_type,
                        reason: "DATA too large",
                    });
                }
                let mut buf = [0u8; MAX_DATA_LEN];
                buf[..value.len()].copy_from_slice(value);
                Ok(Some(Self::Data {
                    value: buf,
                    len: value.len() as u16,
                }))
            }
            
            _ => Ok(None),
        }
    }

    /// Encode attribute to buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - Output buffer.
    /// * `transaction_id` - Transaction ID for XOR operations.
    ///
    /// # Returns
    ///
    /// Number of bytes written (including padding).
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    ///
    /// - Split into encode_address_attr, encode_core_attr, encode_ice_attr, encode_turn_attr
    /// - Buffer size assertions
    /// - Postcondition for padded output
    pub fn encode(&self, buf: &mut [u8], transaction_id: &[u8; 12]) -> usize {
        // Precondition: buffer large enough for any attribute (TigerStyle Phase 4.9)
        assert!(buf.len() >= 24, "Buffer too small for attribute encoding");
        
        let (attr_type, value_len) = match self {
            // Address attributes
            Self::MappedAddress(addr) => {
                self.encode_address_attr(buf, addr, None, ATTR_MAPPED_ADDRESS)
            }
            Self::XorMappedAddress(addr) => {
                self.encode_address_attr(buf, addr, Some(transaction_id), ATTR_XOR_MAPPED_ADDRESS)
            }
            
            // Core STUN attributes
            Self::Username { value: _, len: _ } |
            Self::Realm { value: _, len: _ } |
            Self::Nonce { value: _, len: _ } => {
                self.encode_string_attr(buf)
            }
            Self::MessageIntegrity(hmac) => {
                buf[4..24].copy_from_slice(hmac);
                (ATTR_MESSAGE_INTEGRITY, 20)
            }
            Self::ErrorCode { code, reason, reason_len } => {
                self.encode_error_code_attr(buf, *code, reason, *reason_len)
            }
            
            // ICE attributes
            Self::Priority(_) | Self::UseCandidate | Self::Fingerprint(_) |
            Self::IceControlled(_) | Self::IceControlling(_) => {
                self.encode_ice_attr(buf)
            }
            
            // TURN attributes
            Self::Lifetime(_) | Self::ChannelNumber(_) | Self::XorPeerAddress(_) |
            Self::XorRelayedAddress(_) | Self::Data { .. } | Self::RequestedTransport(_) => {
                self.encode_turn_attr(buf, transaction_id)
            }
        };
        
        // Write attribute header
        buf[0..2].copy_from_slice(&attr_type.to_be_bytes());
        buf[2..4].copy_from_slice(&(value_len as u16).to_be_bytes());
        
        // Calculate total with padding
        let total = 4 + value_len;
        let padded = (total + 3) & !3;
        
        // Zero padding bytes (bounded loop: max 3 iterations)
        for i in 0..3 {
            if total + i < padded {
                buf[total + i] = 0;
            }
        }
        
        // Postcondition: output is 4-byte aligned (TigerStyle Phase 4.9)
        assert!(padded % 4 == 0, "Encoded attribute must be 4-byte aligned");
        
        padded
    }
    
    /// Encode address attribute (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS).
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    #[inline]
    fn encode_address_attr(
        &self,
        buf: &mut [u8],
        addr: &std::net::SocketAddr,
        transaction_id: Option<&[u8; 12]>,
        attr_type: u16,
    ) -> (u16, usize) {
        let len = if let Some(tid) = transaction_id {
            encode_xor_address(&mut buf[4..], addr, tid)
        } else {
            encode_address(&mut buf[4..], addr)
        };
        (attr_type, len)
    }
    
    /// Encode string attribute (USERNAME, REALM, NONCE).
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    #[inline]
    fn encode_string_attr(&self, buf: &mut [u8]) -> (u16, usize) {
        match self {
            Self::Username { value, len } => {
                let l = *len as usize;
                buf[4..4 + l].copy_from_slice(&value[..l]);
                (ATTR_USERNAME, l)
            }
            Self::Realm { value, len } => {
                let l = *len as usize;
                buf[4..4 + l].copy_from_slice(&value[..l]);
                (ATTR_REALM, l)
            }
            Self::Nonce { value, len } => {
                let l = *len as usize;
                buf[4..4 + l].copy_from_slice(&value[..l]);
                (ATTR_NONCE, l)
            }
            _ => unreachable!(),
        }
    }
    
    /// Encode ERROR-CODE attribute.
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    #[inline]
    fn encode_error_code_attr(
        &self,
        buf: &mut [u8],
        code: u16,
        reason: &[u8; MAX_REASON_LEN],
        reason_len: u8,
    ) -> (u16, usize) {
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = (code / 100) as u8;
        buf[7] = (code % 100) as u8;
        let rl = reason_len as usize;
        buf[8..8 + rl].copy_from_slice(&reason[..rl]);
        (ATTR_ERROR_CODE, 4 + rl)
    }
    
    /// Encode ICE-specific attributes.
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    #[inline]
    fn encode_ice_attr(&self, buf: &mut [u8]) -> (u16, usize) {
        match self {
            Self::Priority(p) => {
                buf[4..8].copy_from_slice(&p.to_be_bytes());
                (ATTR_PRIORITY, 4)
            }
            Self::UseCandidate => {
                (ATTR_USE_CANDIDATE, 0)
            }
            Self::Fingerprint(fp) => {
                buf[4..8].copy_from_slice(&fp.to_be_bytes());
                (ATTR_FINGERPRINT, 4)
            }
            Self::IceControlled(tb) => {
                buf[4..12].copy_from_slice(&tb.to_be_bytes());
                (ATTR_ICE_CONTROLLED, 8)
            }
            Self::IceControlling(tb) => {
                buf[4..12].copy_from_slice(&tb.to_be_bytes());
                (ATTR_ICE_CONTROLLING, 8)
            }
            _ => unreachable!(),
        }
    }
    
    /// Encode TURN-specific attributes.
    ///
    /// # TigerStyle Compliance (Phase 4.9)
    #[inline]
    fn encode_turn_attr(&self, buf: &mut [u8], transaction_id: &[u8; 12]) -> (u16, usize) {
        match self {
            Self::Lifetime(secs) => {
                buf[4..8].copy_from_slice(&secs.to_be_bytes());
                (ATTR_LIFETIME, 4)
            }
            Self::ChannelNumber(ch) => {
                buf[4..6].copy_from_slice(&ch.to_be_bytes());
                buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // Reserved
                (ATTR_CHANNEL_NUMBER, 4)
            }
            Self::XorPeerAddress(addr) => {
                let len = encode_xor_address(&mut buf[4..], addr, transaction_id);
                (ATTR_XOR_PEER_ADDRESS, len)
            }
            Self::XorRelayedAddress(addr) => {
                let len = encode_xor_address(&mut buf[4..], addr, transaction_id);
                (ATTR_XOR_RELAYED_ADDRESS, len)
            }
            Self::Data { value, len } => {
                let l = *len as usize;
                buf[4..4 + l].copy_from_slice(&value[..l]);
                (ATTR_DATA, l)
            }
            Self::RequestedTransport(proto) => {
                buf[4] = *proto;
                buf[5] = 0;
                buf[6] = 0;
                buf[7] = 0;
                (ATTR_REQUESTED_TRANSPORT, 4)
            }
            _ => unreachable!(),
        }
    }

    /// Get attribute type code.
    pub const fn attr_type(&self) -> u16 {
        match self {
            Self::MappedAddress(_) => ATTR_MAPPED_ADDRESS,
            Self::Username { .. } => ATTR_USERNAME,
            Self::MessageIntegrity(_) => ATTR_MESSAGE_INTEGRITY,
            Self::ErrorCode { .. } => ATTR_ERROR_CODE,
            Self::Realm { .. } => ATTR_REALM,
            Self::Nonce { .. } => ATTR_NONCE,
            Self::XorMappedAddress(_) => ATTR_XOR_MAPPED_ADDRESS,
            Self::Priority(_) => ATTR_PRIORITY,
            Self::UseCandidate => ATTR_USE_CANDIDATE,
            Self::Fingerprint(_) => ATTR_FINGERPRINT,
            Self::IceControlled(_) => ATTR_ICE_CONTROLLED,
            Self::IceControlling(_) => ATTR_ICE_CONTROLLING,
            Self::Lifetime(_) => ATTR_LIFETIME,
            Self::ChannelNumber(_) => ATTR_CHANNEL_NUMBER,
            Self::XorPeerAddress(_) => ATTR_XOR_PEER_ADDRESS,
            Self::XorRelayedAddress(_) => ATTR_XOR_RELAYED_ADDRESS,
            Self::Data { .. } => ATTR_DATA,
            Self::RequestedTransport(_) => ATTR_REQUESTED_TRANSPORT,
        }
    }
}

/// Create USERNAME attribute from string.
impl StunAttribute {
    pub fn username(s: &str) -> Self {
        assert!(s.len() <= MAX_USERNAME_LEN, "username too long");
        let mut value = [0u8; MAX_USERNAME_LEN];
        value[..s.len()].copy_from_slice(s.as_bytes());
        Self::Username {
            value,
            len: s.len() as u8,
        }
    }
}

/// Parse MAPPED-ADDRESS value.
fn parse_mapped_address(data: &[u8], attr_type: u16) -> Result<SocketAddr, IceError> {
    if data.len() < 4 {
        return Err(IceError::StunInvalidAttribute {
            attr_type,
            reason: "address too short",
        });
    }
    
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);
    
    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(IceError::StunInvalidAttribute {
                    attr_type,
                    reason: "IPv4 address too short",
                });
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(IceError::StunInvalidAttribute {
                    attr_type,
                    reason: "IPv6 address too short",
                });
            }
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[4..20]).unwrap());
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(IceError::StunInvalidAttribute {
            attr_type,
            reason: "unknown address family",
        }),
    }
}

/// Parse XOR-MAPPED-ADDRESS value.
fn parse_xor_address(
    data: &[u8],
    transaction_id: &[u8; 12],
    attr_type: u16,
) -> Result<SocketAddr, IceError> {
    if data.len() < 4 {
        return Err(IceError::StunInvalidAttribute {
            attr_type,
            reason: "XOR address too short",
        });
    }
    
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    
    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(IceError::StunInvalidAttribute {
                    attr_type,
                    reason: "XOR IPv4 address too short",
                });
            }
            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                data[4] ^ magic_bytes[0],
                data[5] ^ magic_bytes[1],
                data[6] ^ magic_bytes[2],
                data[7] ^ magic_bytes[3],
            );
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(IceError::StunInvalidAttribute {
                    attr_type,
                    reason: "XOR IPv6 address too short",
                });
            }
            
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(transaction_id);
            
            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = data[4 + i] ^ xor_key[i];
            }
            
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(IceError::StunInvalidAttribute {
            attr_type,
            reason: "unknown address family",
        }),
    }
}

/// Encode address (MAPPED-ADDRESS format).
fn encode_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    buf[0] = 0; // Reserved
    
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf[1] = 0x01; // IPv4
            buf[2..4].copy_from_slice(&addr.port().to_be_bytes());
            buf[4..8].copy_from_slice(&ip.octets());
            8
        }
        IpAddr::V6(ip) => {
            buf[1] = 0x02; // IPv6
            buf[2..4].copy_from_slice(&addr.port().to_be_bytes());
            buf[4..20].copy_from_slice(&ip.octets());
            20
        }
    }
}

/// Encode XOR address.
fn encode_xor_address(
    buf: &mut [u8],
    addr: &SocketAddr,
    transaction_id: &[u8; 12],
) -> usize {
    let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    
    buf[0] = 0; // Reserved
    
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf[1] = 0x01; // IPv4
            buf[2..4].copy_from_slice(&xor_port.to_be_bytes());
            
            let ip_bytes = ip.octets();
            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            buf[4] = ip_bytes[0] ^ magic_bytes[0];
            buf[5] = ip_bytes[1] ^ magic_bytes[1];
            buf[6] = ip_bytes[2] ^ magic_bytes[2];
            buf[7] = ip_bytes[3] ^ magic_bytes[3];
            8
        }
        IpAddr::V6(ip) => {
            buf[1] = 0x02; // IPv6
            buf[2..4].copy_from_slice(&xor_port.to_be_bytes());
            
            let ip_bytes = ip.octets();
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(transaction_id);
            
            for i in 0..16 {
                buf[4 + i] = ip_bytes[i] ^ xor_key[i];
            }
            20
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_address_ipv4_roundtrip() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let tid = [0u8; 12];
        
        let mut buf = [0u8; 32];
        let len = encode_xor_address(&mut buf, &addr, &tid);
        assert_eq!(len, 8);
        
        let parsed = parse_xor_address(&buf[..len], &tid, ATTR_XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_xor_address_ipv6_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let tid = [1u8; 12];
        
        let mut buf = [0u8; 32];
        let len = encode_xor_address(&mut buf, &addr, &tid);
        assert_eq!(len, 20);
        
        let parsed = parse_xor_address(&buf[..len], &tid, ATTR_XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_username_attribute() {
        let username = StunAttribute::username("user:pass");
        
        if let StunAttribute::Username { value, len } = username {
            assert_eq!(len, 9);
            assert_eq!(&value[..9], b"user:pass");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_priority_roundtrip() {
        let priority = StunAttribute::Priority(0x6e0001ff);
        let tid = [0u8; 12];
        
        let mut buf = [0u8; 32];
        let len = priority.encode(&mut buf, &tid);
        assert_eq!(len, 8); // 4 header + 4 value
        
        let parsed = StunAttribute::parse(
            ATTR_PRIORITY,
            &buf[4..8],
            &tid,
        ).unwrap().unwrap();
        
        if let StunAttribute::Priority(p) = parsed {
            assert_eq!(p, 0x6e0001ff);
        } else {
            panic!("wrong variant");
        }
    }
}
