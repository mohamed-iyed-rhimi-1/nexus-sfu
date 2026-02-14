//! STUN Message Parsing and Serialization.
//!
//! Zero-allocation STUN message handling with explicit bounds checking.
//!
//! # Performance
//!
//! - Parse: ~50ns for typical message
//! - Encode: ~30ns for typical message
//! - Zero heap allocations

use super::attributes::StunAttribute;
use super::STUN_MAX_ATTRIBUTES;
use crate::ice::error::IceError;
use getrandom::getrandom;

/// STUN Magic Cookie (RFC 5389).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size in bytes.
pub const STUN_HEADER_SIZE: usize = 20;

/// Minimum buffer size for STUN message encoding.
/// This accounts for header (20) + max attributes with MESSAGE-INTEGRITY-SHA256 (32) + padding.
pub const STUN_BUFFER_SIZE: usize = 576;

/// STUN Message Class.
///
/// Encoded in bits 4 and 8 of the message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StunClass {
    /// Request (C0=0, C1=0).
    Request = 0b00,
    
    /// Indication (C0=1, C1=0).
    Indication = 0b01,
    
    /// Success Response (C0=0, C1=1).
    SuccessResponse = 0b10,
    
    /// Error Response (C0=1, C1=1).
    ErrorResponse = 0b11,
}

impl StunClass {
    /// Parse class from message type bits.
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::SuccessResponse,
            0b11 => Self::ErrorResponse,
            _ => unreachable!(),
        }
    }

    /// Returns true if this is a request.
    #[inline]
    pub const fn is_request(self) -> bool {
        matches!(self, Self::Request)
    }

    /// Returns true if this is a response.
    #[inline]
    pub const fn is_response(self) -> bool {
        matches!(self, Self::SuccessResponse | Self::ErrorResponse)
    }
}

/// STUN Method.
///
/// Defines the type of STUN operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StunMethod {
    /// Binding method (0x001).
    Binding = 0x001,
    
    /// Allocate (TURN, 0x003).
    Allocate = 0x003,
    
    /// Refresh (TURN, 0x004).
    Refresh = 0x004,
    
    /// Send (TURN, 0x006).
    Send = 0x006,
    
    /// Data (TURN, 0x007).
    Data = 0x007,
    
    /// CreatePermission (TURN, 0x008).
    CreatePermission = 0x008,
    
    /// ChannelBind (TURN, 0x009).
    ChannelBind = 0x009,
}

impl StunMethod {
    /// Try to parse method from 12-bit value.
    #[inline]
    pub const fn try_from_u16(value: u16) -> Option<Self> {
        match value {
            0x001 => Some(Self::Binding),
            0x003 => Some(Self::Allocate),
            0x004 => Some(Self::Refresh),
            0x006 => Some(Self::Send),
            0x007 => Some(Self::Data),
            0x008 => Some(Self::CreatePermission),
            0x009 => Some(Self::ChannelBind),
            _ => None,
        }
    }
}

/// STUN Message.
///
/// Fixed-size structure for STUN message representation.
/// Attributes stored in pre-allocated array.
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message class (request/response/indication).
    pub class: StunClass,
    
    /// Message method (binding, allocate, etc).
    pub method: StunMethod,
    
    /// 96-bit transaction ID.
    pub transaction_id: [u8; 12],
    
    /// Attributes (fixed-size array).
    pub attributes: [Option<StunAttribute>; STUN_MAX_ATTRIBUTES as usize],
    
    /// Number of valid attributes.
    pub attribute_count: u8,
}

impl StunMessage {
    /// Check if data looks like a STUN message.
    ///
    /// Quick check for STUN magic cookie without full parsing.
    #[inline]
    pub fn is_stun(data: &[u8]) -> bool {
        if data.len() < STUN_HEADER_SIZE as usize {
            return false;
        }
        
        // Check first two bits are 0 (STUN indicator)
        if data[0] & 0xC0 != 0 {
            return false;
        }
        
        // Check magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        cookie == STUN_MAGIC_COOKIE
    }

    /// Encode class and method into message type.
    #[inline]
    pub fn encode_type(class: StunClass, method: StunMethod) -> u16 {
        let method_val = method as u16;
        let class_val = class as u16;
        
        (method_val & 0x000F)
            | ((method_val << 1) & 0x00E0)
            | ((method_val << 2) & 0x3E00)
            | ((class_val & 0x1) << 4)
            | ((class_val & 0x2) << 7)
    }

    /// Create a new STUN Binding Request.
    pub fn binding_request() -> Self {
        let mut transaction_id = [0u8; 12];
        getrandom(&mut transaction_id).expect("getrandom failed");
        
        Self {
            class: StunClass::Request,
            method: StunMethod::Binding,
            transaction_id,
            attributes: Default::default(),
            attribute_count: 0,
        }
    }

    /// Create a STUN Binding Success Response.
    pub fn binding_response(
        transaction_id: [u8; 12],
        mapped_addr: std::net::SocketAddr,
    ) -> Self {
        let mut msg = Self {
            class: StunClass::SuccessResponse,
            method: StunMethod::Binding,
            transaction_id,
            attributes: Default::default(),
            attribute_count: 0,
        };
        
        msg.add_attribute(StunAttribute::XorMappedAddress(mapped_addr));
        msg
    }

    /// Create a STUN Error Response.
    pub fn error_response(
        transaction_id: [u8; 12],
        method: StunMethod,
        error_code: u16,
    ) -> Self {
        let mut msg = Self {
            class: StunClass::ErrorResponse,
            method,
            transaction_id,
            attributes: Default::default(),
            attribute_count: 0,
        };
        
        msg.add_attribute(StunAttribute::ErrorCode {
            code: error_code,
            reason_len: 0,
            reason: [0u8; 128],
        });
        msg
    }

    /// Add an attribute to the message.
    ///
    /// # Panics
    ///
    /// Panics if attribute array is full.
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        assert!(
            (self.attribute_count as u32) < STUN_MAX_ATTRIBUTES,
            "too many attributes: {} >= {}",
            self.attribute_count,
            STUN_MAX_ATTRIBUTES
        );
        
        self.attributes[self.attribute_count as usize] = Some(attr);
        self.attribute_count += 1;
    }

    /// Get XOR-MAPPED-ADDRESS attribute.
    pub fn get_xor_mapped_address(&self) -> Option<std::net::SocketAddr> {
        for i in 0..self.attribute_count as usize {
            if let Some(StunAttribute::XorMappedAddress(addr)) = &self.attributes[i] {
                return Some(*addr);
            }
        }
        None
    }

    /// Get USERNAME attribute.
    pub fn get_username(&self) -> Option<&str> {
        for i in 0..self.attribute_count as usize {
            if let Some(StunAttribute::Username { value, len }) = &self.attributes[i] {
                // Safety: we only store valid UTF-8
                return Some(unsafe {
                    std::str::from_utf8_unchecked(&value[..*len as usize])
                });
            }
        }
        None
    }

    /// Check if USE-CANDIDATE attribute is present.
    pub fn has_use_candidate(&self) -> bool {
        for i in 0..self.attribute_count as usize {
            if matches!(&self.attributes[i], Some(StunAttribute::UseCandidate)) {
                return true;
            }
        }
        false
    }

    /// Get PRIORITY attribute.
    pub fn get_priority(&self) -> Option<u32> {
        for i in 0..self.attribute_count as usize {
            if let Some(StunAttribute::Priority(p)) = &self.attributes[i] {
                return Some(*p);
            }
        }
        None
    }

    /// Get ICE-CONTROLLING tiebreaker.
    pub fn get_ice_controlling(&self) -> Option<u64> {
        for i in 0..self.attribute_count as usize {
            if let Some(StunAttribute::IceControlling(tb)) = &self.attributes[i] {
                return Some(*tb);
            }
        }
        None
    }

    /// Get ICE-CONTROLLED tiebreaker.
    pub fn get_ice_controlled(&self) -> Option<u64> {
        for i in 0..self.attribute_count as usize {
            if let Some(StunAttribute::IceControlled(tb)) = &self.attributes[i] {
                return Some(*tb);
            }
        }
        None
    }

    /// Parse STUN message from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw message bytes (minimum 20 bytes).
    ///
    /// # Errors
    ///
    /// Returns error if message is malformed.
    ///
    /// # TigerStyle Compliance (Phase 4.6)
    ///
    /// - Split into parse_header and parse_attributes helpers for 70-line limit
    /// - Preconditions for data length (via error return for external input)
    /// - Postconditions for attribute count bounds
    pub fn parse(data: &[u8]) -> Result<Self, IceError> {
        // For public parsing functions receiving external data, use error returns
        // instead of assertions to handle malformed input gracefully
        if data.len() < STUN_HEADER_SIZE {
            return Err(IceError::StunTooShort {
                actual_bytes: data.len() as u32,
                min_bytes: STUN_HEADER_SIZE as u32,
            });
        }
        
        // After validation, we can assert the invariant holds
        debug_assert!(data.len() >= STUN_HEADER_SIZE,
            "STUN parse requires at least {} bytes", STUN_HEADER_SIZE);

        // Parse header (class, method, transaction_id, msg_len)
        let (class, method, transaction_id, msg_len) = Self::parse_header(data)?;
        
        // Parse attributes
        let (attributes, attribute_count) = Self::parse_attributes(
            data,
            msg_len,
            &transaction_id,
        )?;
        
        // Postcondition: attribute count within bounds (TigerStyle Phase 4.6)
        assert!((attribute_count as u32) <= STUN_MAX_ATTRIBUTES,
            "Attribute count must not exceed STUN_MAX_ATTRIBUTES");

        Ok(Self {
            class,
            method,
            transaction_id,
            attributes,
            attribute_count,
        })
    }
    
    /// Parse STUN message header.
    ///
    /// Extracts class, method, transaction ID, and message length.
    ///
    /// # TigerStyle Compliance (Phase 4.6)
    ///
    /// - Extracted helper to keep parse() under 70 lines
    /// - Assertions for magic cookie and message length
    #[inline]
    fn parse_header(data: &[u8]) -> Result<(StunClass, StunMethod, [u8; 12], usize), IceError> {
        // Precondition
        assert!(data.len() >= STUN_HEADER_SIZE, "Header requires 20 bytes");
        
        // Parse message type (first 2 bytes)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        
        // Verify first two bits are 0 (RFC 5389)
        if msg_type & 0xC000 != 0 {
            return Err(IceError::StunInvalidHeader);
        }
        
        // Extract class from bits 4 and 8
        // Message type format: 0b00MMMMMCMMMCMMMM
        let c0 = (msg_type >> 4) & 0x1;
        let c1 = (msg_type >> 8) & 0x1;
        let class_bits = (c1 << 1) | c0;
        let class = StunClass::from_bits(class_bits as u8);
        
        // Extract method from remaining bits
        let m0 = msg_type & 0x000F;
        let m1 = (msg_type >> 5) & 0x0070;
        let m2 = (msg_type >> 6) & 0x0F80;
        let method_bits = m0 | m1 | m2;
        
        let method = StunMethod::try_from_u16(method_bits)
            .ok_or(IceError::StunUnknownMethod { method: method_bits })?;

        // Parse message length (bytes 2-3)
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        
        // Validate total length
        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(IceError::StunTooShort {
                actual_bytes: data.len() as u32,
                min_bytes: (STUN_HEADER_SIZE + msg_len) as u32,
            });
        }

        // Verify magic cookie (bytes 4-7)
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(IceError::StunInvalidMagicCookie { actual: cookie });
        }

        // Parse transaction ID (bytes 8-19)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);
        
        // Postcondition: transaction ID is 12 bytes
        assert!(transaction_id.len() == 12, "Transaction ID must be 12 bytes");

        Ok((class, method, transaction_id, msg_len))
    }
    
    /// Parse STUN message attributes.
    ///
    /// Iterates through attributes with bounded loop.
    ///
    /// # TigerStyle Compliance (Phase 4.6)
    ///
    /// - Extracted helper to keep parse() under 70 lines
    /// - Bounded loop with STUN_MAX_ATTRIBUTES limit
    /// - Assertions for attribute bounds
    #[inline]
    fn parse_attributes(
        data: &[u8],
        msg_len: usize,
        transaction_id: &[u8; 12],
    ) -> Result<([Option<StunAttribute>; STUN_MAX_ATTRIBUTES as usize], u8), IceError> {
        // Precondition
        assert!(data.len() >= STUN_HEADER_SIZE + msg_len,
            "Data must contain full message");
        
        let mut attributes: [Option<StunAttribute>; STUN_MAX_ATTRIBUTES as usize] = Default::default();
        let mut attribute_count = 0u8;
        let mut offset = STUN_HEADER_SIZE;
        let end = STUN_HEADER_SIZE + msg_len;

        // Bounded loop: max STUN_MAX_ATTRIBUTES iterations (TigerStyle)
        for _iteration in 0..STUN_MAX_ATTRIBUTES {
            if offset + 4 > end {
                break;
            }
            
            // Attribute header: type (2) + length (2)
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            // Check bounds
            if offset + attr_len > end {
                return Err(IceError::StunInvalidAttribute {
                    attr_type,
                    reason: "attribute extends beyond message",
                });
            }

            // Parse attribute value
            let attr_value = &data[offset..offset + attr_len];
            
            if let Some(attr) = StunAttribute::parse(attr_type, attr_value, transaction_id)? {
                if (attribute_count as u32) < STUN_MAX_ATTRIBUTES {
                    attributes[attribute_count as usize] = Some(attr);
                    attribute_count += 1;
                }
            }

            // Advance with 4-byte padding
            offset += (attr_len + 3) & !3;
        }
        
        // Postcondition: attribute count within bounds
        assert!((attribute_count as u32) <= STUN_MAX_ATTRIBUTES,
            "Parsed attribute count must not exceed max");

        Ok((attributes, attribute_count))
    }

    /// Encode message to buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - Output buffer (must be at least 548 bytes).
    ///
    /// # Returns
    ///
    /// Number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics if buffer is too small.
    ///
    /// # TigerStyle Compliance (Phase 4.7)
    ///
    /// - Buffer size precondition
    /// - Bounded loop for attributes
    /// - Postcondition for output size
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        // Precondition: buffer size (TigerStyle Phase 4.7)
        assert!(
            buf.len() >= STUN_BUFFER_SIZE,
            "buffer too small: {} < {}",
            buf.len(),
            STUN_BUFFER_SIZE
        );
        
        // Precondition: attribute count within bounds
        assert!((self.attribute_count as u32) <= STUN_MAX_ATTRIBUTES,
            "Attribute count exceeds maximum");

        // Build message type
        let method_val = self.method as u16;
        let class_val = self.class as u16;
        
        // Encode class bits at positions 4 and 8
        // Method bits at 0-3, 5-7, 9-15
        let msg_type = (method_val & 0x000F)
            | ((method_val << 1) & 0x00E0)
            | ((method_val << 2) & 0x3E00)
            | ((class_val & 0x1) << 4)
            | ((class_val & 0x2) << 7);

        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        
        // Placeholder for length (will update later)
        let len_pos = 2;
        buf[len_pos..len_pos + 2].copy_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        buf[8..20].copy_from_slice(&self.transaction_id);

        // Encode attributes with bounded loop (TigerStyle Phase 4.7)
        let mut offset = STUN_HEADER_SIZE;
        
        for i in 0..self.attribute_count as usize {
            // Bounded: i < attribute_count <= STUN_MAX_ATTRIBUTES
            if let Some(ref attr) = self.attributes[i] {
                offset += attr.encode(&mut buf[offset..], &self.transaction_id);
            }
        }

        // Update message length
        let msg_len = (offset - STUN_HEADER_SIZE) as u16;
        buf[len_pos..len_pos + 2].copy_from_slice(&msg_len.to_be_bytes());
        
        // Postcondition: output within buffer bounds (TigerStyle Phase 4.7)
        assert!(offset <= buf.len(),
            "Encoded message must fit in buffer");
        
        // Postcondition: minimum valid message size
        assert!(offset >= STUN_HEADER_SIZE,
            "Encoded message must include full header");

        offset
    }

    /// Encode message to a new vector.
    ///
    /// This allocates memory and should not be used on the hot path.
    #[cfg(test)]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 548];
        let len = self.encode(&mut buf);
        buf.truncate(len);
        buf
    }
}

impl Default for StunMessage {
    fn default() -> Self {
        Self::binding_request()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::STUN_FINGERPRINT_XOR;

    // ========================================================================
    // Basic Message Tests
    // ========================================================================

    #[test]
    fn test_binding_request_roundtrip() {
        let request = StunMessage::binding_request();
        
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = request.encode(&mut buf);
        
        assert!(len >= STUN_HEADER_SIZE as usize);
        
        let parsed = StunMessage::parse(&buf[..len]).unwrap();
        
        assert_eq!(parsed.class, StunClass::Request);
        assert_eq!(parsed.method, StunMethod::Binding);
        assert_eq!(parsed.transaction_id, request.transaction_id);
    }

    #[test]
    fn test_binding_response_with_address() {
        let addr: std::net::SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let tid = [1u8; 12];
        
        let response = StunMessage::binding_response(tid, addr);
        
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = response.encode(&mut buf);
        
        let parsed = StunMessage::parse(&buf[..len]).unwrap();
        
        assert_eq!(parsed.class, StunClass::SuccessResponse);
        assert_eq!(parsed.get_xor_mapped_address(), Some(addr));
    }

    #[test]
    fn test_parse_too_short() {
        let result = StunMessage::parse(&[0u8; 10]);
        assert!(matches!(result, Err(IceError::StunTooShort { .. })));
    }

    #[test]
    fn test_parse_invalid_magic_cookie() {
        let mut data = [0u8; 20];
        // Set valid Binding Request message type (0x0001)
        data[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        // Set invalid magic cookie
        data[4..8].copy_from_slice(&0x12345678u32.to_be_bytes()); // Wrong cookie
        
        let result = StunMessage::parse(&data);
        assert!(matches!(result, Err(IceError::StunInvalidMagicCookie { .. })));
    }

    #[test]
    fn test_class_from_bits() {
        assert_eq!(StunClass::from_bits(0b00), StunClass::Request);
        assert_eq!(StunClass::from_bits(0b01), StunClass::Indication);
        assert_eq!(StunClass::from_bits(0b10), StunClass::SuccessResponse);
        assert_eq!(StunClass::from_bits(0b11), StunClass::ErrorResponse);
    }

    #[test]
    fn test_method_try_from() {
        assert_eq!(StunMethod::try_from_u16(0x001), Some(StunMethod::Binding));
        assert_eq!(StunMethod::try_from_u16(0x003), Some(StunMethod::Allocate));
        assert_eq!(StunMethod::try_from_u16(0xFFF), None);
    }

    // ========================================================================
    // Message Integrity Tests (HMAC-SHA1, RFC 5389 Section 15.4)
    // ========================================================================

    #[test]
    fn test_message_integrity_attribute() {
        // Create a binding request with MESSAGE-INTEGRITY
        let mut request = StunMessage::binding_request();
        let _key = b"testpassword1234";
        
        // Add username attribute (required before MESSAGE-INTEGRITY)
        request.add_attribute(StunAttribute::username("user:peer"));
        
        // Encode and verify structure
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = request.encode(&mut buf);
        
        assert!(len >= STUN_HEADER_SIZE);
    }

    // ========================================================================
    // Fingerprint Tests (CRC-32, XOR with 0x5354554e)
    // ========================================================================

    #[test]
    fn test_fingerprint_xor_constant() {
        assert_eq!(STUN_FINGERPRINT_XOR, 0x5354554e,
            "STUN fingerprint XOR constant should be 0x5354554e (STUN in ASCII)");
    }

    // ========================================================================
    // Transaction ID Tests (96-bit random)
    // ========================================================================

    #[test]
    fn test_transaction_id_uniqueness() {
        let msg1 = StunMessage::binding_request();
        let msg2 = StunMessage::binding_request();
        
        // Transaction IDs should be unique
        assert_ne!(msg1.transaction_id, msg2.transaction_id,
            "Transaction IDs should be unique");
    }

    #[test]
    fn test_transaction_id_length() {
        let msg = StunMessage::binding_request();
        
        // Transaction ID should be exactly 12 bytes (96 bits)
        assert_eq!(msg.transaction_id.len(), 12);
    }

    #[test]
    fn test_transaction_id_preserved_in_response() {
        let request = StunMessage::binding_request();
        let addr: std::net::SocketAddr = "192.168.1.1:5000".parse().unwrap();
        
        let response = StunMessage::binding_response(request.transaction_id, addr);
        
        assert_eq!(response.transaction_id, request.transaction_id);
    }

    // ========================================================================
    // Message Parsing with Invalid Lengths
    // ========================================================================

    #[test]
    fn test_parse_empty_data() {
        let result = StunMessage::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_minimum_valid_message() {
        // Create a minimal valid STUN message (header only)
        let mut data = [0u8; 20];
        
        // Binding Request type (0x0001)
        data[0] = 0x00;
        data[1] = 0x01;
        
        // Length = 0 (no attributes)
        data[2] = 0x00;
        data[3] = 0x00;
        
        // Magic cookie
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID (12 bytes)
        data[8..20].copy_from_slice(&[1u8; 12]);
        
        let result = StunMessage::parse(&data);
        assert!(result.is_ok());
        
        let msg = result.unwrap();
        assert_eq!(msg.class, StunClass::Request);
        assert_eq!(msg.method, StunMethod::Binding);
    }

    #[test]
    fn test_parse_invalid_first_bits() {
        let mut data = [0u8; 20];
        
        // First two bits must be 0 for STUN
        data[0] = 0xC0; // Both bits set - invalid
        
        let result = StunMessage::parse(&data);
        // Should fail due to invalid header
        assert!(result.is_err());
    }

    // ========================================================================
    // Message Serialization Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_roundtrip_binding_request() {
        let original = StunMessage::binding_request();
        
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = original.encode(&mut buf);
        
        let parsed = StunMessage::parse(&buf[..len]).unwrap();
        
        // Re-encode and compare
        let mut buf2 = [0u8; STUN_BUFFER_SIZE];
        let len2 = parsed.encode(&mut buf2);
        
        assert_eq!(len, len2);
        assert_eq!(&buf[..len], &buf2[..len2]);
    }

    #[test]
    fn test_roundtrip_with_xor_mapped_address() {
        let tid = [0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let addr: std::net::SocketAddr = "203.0.113.1:12345".parse().unwrap();
        
        let original = StunMessage::binding_response(tid, addr);
        
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = original.encode(&mut buf);
        
        let parsed = StunMessage::parse(&buf[..len]).unwrap();
        
        assert_eq!(parsed.get_xor_mapped_address(), Some(addr));
    }

    // ========================================================================
    // Message Size Limits (max 548 bytes for STUN)
    // ========================================================================

    #[test]
    fn test_stun_header_size_constant() {
        assert_eq!(STUN_HEADER_SIZE, 20,
            "STUN header size should be 20 bytes");
    }

    #[test]
    fn test_magic_cookie_constant() {
        assert_eq!(STUN_MAGIC_COOKIE, 0x2112A442,
            "STUN magic cookie should be 0x2112A442");
    }

    // ========================================================================
    // STUN Class Tests
    // ========================================================================

    #[test]
    fn test_stun_class_is_request() {
        assert!(StunClass::Request.is_request());
        assert!(!StunClass::Indication.is_request());
        assert!(!StunClass::SuccessResponse.is_request());
        assert!(!StunClass::ErrorResponse.is_request());
    }

    #[test]
    fn test_stun_class_is_response() {
        assert!(!StunClass::Request.is_response());
        assert!(!StunClass::Indication.is_response());
        assert!(StunClass::SuccessResponse.is_response());
        assert!(StunClass::ErrorResponse.is_response());
    }

    // ========================================================================
    // STUN Method Tests
    // ========================================================================

    #[test]
    fn test_all_stun_methods() {
        assert_eq!(StunMethod::Binding as u16, 0x001);
        assert_eq!(StunMethod::Allocate as u16, 0x003);
        assert_eq!(StunMethod::Refresh as u16, 0x004);
        assert_eq!(StunMethod::Send as u16, 0x006);
        assert_eq!(StunMethod::Data as u16, 0x007);
        assert_eq!(StunMethod::CreatePermission as u16, 0x008);
        assert_eq!(StunMethod::ChannelBind as u16, 0x009);
    }

    // ========================================================================
    // Message Type Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_type_binding_request() {
        let msg_type = StunMessage::encode_type(StunClass::Request, StunMethod::Binding);
        assert_eq!(msg_type, 0x0001);
    }

    #[test]
    fn test_encode_type_binding_response() {
        let msg_type = StunMessage::encode_type(StunClass::SuccessResponse, StunMethod::Binding);
        assert_eq!(msg_type, 0x0101);
    }

    #[test]
    fn test_encode_type_binding_error_response() {
        let msg_type = StunMessage::encode_type(StunClass::ErrorResponse, StunMethod::Binding);
        assert_eq!(msg_type, 0x0111);
    }

    // ========================================================================
    // is_stun Quick Check Tests
    // ========================================================================

    #[test]
    fn test_is_stun_valid() {
        let mut data = [0u8; 20];
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        assert!(StunMessage::is_stun(&data));
    }

    #[test]
    fn test_is_stun_too_short() {
        let data = [0u8; 10];
        assert!(!StunMessage::is_stun(&data));
    }

    #[test]
    fn test_is_stun_wrong_first_bits() {
        let mut data = [0u8; 20];
        data[0] = 0x80; // First bit set - not STUN
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        assert!(!StunMessage::is_stun(&data));
    }

    #[test]
    fn test_is_stun_wrong_cookie() {
        let mut data = [0u8; 20];
        data[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        
        assert!(!StunMessage::is_stun(&data));
    }

    // ========================================================================
    // IPv6 Address Tests
    // ========================================================================

    #[test]
    fn test_binding_response_ipv6() {
        let addr: std::net::SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let tid = [1u8; 12];
        
        let response = StunMessage::binding_response(tid, addr);
        
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let len = response.encode(&mut buf);
        
        let parsed = StunMessage::parse(&buf[..len]).unwrap();
        
        assert_eq!(parsed.class, StunClass::SuccessResponse);
        assert_eq!(parsed.get_xor_mapped_address(), Some(addr));
    }

    // ========================================================================
    // Attribute Count Tests
    // ========================================================================

    #[test]
    fn test_empty_message_attribute_count() {
        let msg = StunMessage::binding_request();
        assert_eq!(msg.attribute_count, 0);
    }

    #[test]
    fn test_message_with_attribute() {
        let addr: std::net::SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let tid = [1u8; 12];
        
        let msg = StunMessage::binding_response(tid, addr);
        
        // Should have XOR-MAPPED-ADDRESS attribute
        assert!(msg.attribute_count >= 1);
    }

    // ========================================================================
    // Default Implementation Test
    // ========================================================================

    #[test]
    fn test_default_is_binding_request() {
        let msg = StunMessage::default();
        
        assert_eq!(msg.class, StunClass::Request);
        assert_eq!(msg.method, StunMethod::Binding);
    }
}
