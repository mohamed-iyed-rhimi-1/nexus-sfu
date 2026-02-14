//! STUN Server.
//!
//! Handles incoming STUN binding requests and generates responses.
//! Zero-allocation on hot path using pre-allocated buffers.

use std::net::SocketAddr;

use super::attributes::{StunAttribute, ATTR_MESSAGE_INTEGRITY, ATTR_FINGERPRINT};
use super::integrity::{sign_message, IntegrityContext};
use super::message::{StunMessage, StunClass, StunMethod, STUN_HEADER_SIZE, STUN_MAGIC_COOKIE, STUN_BUFFER_SIZE};
use crate::ice::error::IceError;
use crate::ice::types::IceCredentials;

/// Maximum response buffer size.
pub const MAX_STUN_RESPONSE_SIZE: usize = STUN_BUFFER_SIZE;

/// STUN server configuration.
#[derive(Debug, Clone)]
pub struct StunServerConfig {
    /// Require MESSAGE-INTEGRITY for binding requests.
    pub require_integrity: bool,
    
    /// Require FINGERPRINT for binding requests.
    pub require_fingerprint: bool,
    
    /// Software identifier to include in responses.
    pub software: Option<&'static str>,
}

impl Default for StunServerConfig {
    fn default() -> Self {
        Self {
            require_integrity: true,
            require_fingerprint: true,
            software: Some("nexus-sfu"),
        }
    }
}

/// STUN server state.
pub struct StunServer {
    config: StunServerConfig,
    
    /// Pre-allocated response buffer.
    response_buf: [u8; MAX_STUN_RESPONSE_SIZE],
}

impl StunServer {
    /// Create new STUN server.
    pub fn new(config: StunServerConfig) -> Self {
        Self {
            config,
            response_buf: [0u8; MAX_STUN_RESPONSE_SIZE],
        }
    }
    
    /// Create with default config.
    pub fn with_defaults() -> Self {
        Self::new(StunServerConfig::default())
    }
    
    /// Handle incoming STUN request.
    ///
    /// # Arguments
    ///
    /// * `data` - Incoming packet data.
    /// * `source` - Source address of the packet.
    /// * `credentials` - ICE credentials for integrity verification.
    ///
    /// # Returns
    ///
    /// Response bytes to send back, or None if not a valid STUN request.
    ///
    /// # TigerStyle Compliance (Phase 4.10)
    ///
    /// - Data length checks (graceful returns for external input)
    /// - Split validation logic into helper methods
    /// - Postcondition for response bounds
    pub fn handle_request(
        &mut self,
        data: &[u8],
        source: SocketAddr,
        credentials: &IceCredentials,
    ) -> Result<Option<&[u8]>, IceError> {
        // For external input, return None gracefully instead of panicking
        if data.is_empty() {
            return Ok(None);
        }
        
        // Check if this is a STUN message
        if !StunMessage::is_stun(data) {
            return Ok(None);
        }
        
        // is_stun already checks header size, so this should hold
        debug_assert!(data.len() >= STUN_HEADER_SIZE,
            "STUN message must be at least {} bytes", STUN_HEADER_SIZE);
        
        // Parse the message
        let (msg, integrity_ctx) = self.parse_with_integrity(data)?;
        
        // Only handle binding requests
        if msg.method != StunMethod::Binding || msg.class != StunClass::Request {
            return Ok(None);
        }
        
        // Validate request using helper method (now includes USERNAME validation)
        let validation_result = self.validate_request(data, &msg, credentials, &integrity_ctx);
        
        if let Err(error_response) = validation_result {
            if let Some((code, reason)) = error_response {
                let len = self.build_error_response(&msg, code, reason, credentials)?;
                // Postcondition: response within buffer (TigerStyle Phase 4.10)
                assert!(len <= MAX_STUN_RESPONSE_SIZE,
                    "Response size {} exceeds maximum {}", len, MAX_STUN_RESPONSE_SIZE);
                return Ok(Some(&self.response_buf[..len]));
            }
            return Ok(None);
        }
        
        // Build binding success response
        let len = self.build_binding_response(&msg, source, credentials)?;
        
        // Postcondition: response within buffer (TigerStyle Phase 4.10)
        assert!(len <= MAX_STUN_RESPONSE_SIZE,
            "Response size {} exceeds maximum {}", len, MAX_STUN_RESPONSE_SIZE);
        
        Ok(Some(&self.response_buf[..len]))
    }
    
    /// Validate STUN request: USERNAME, MESSAGE-INTEGRITY, FINGERPRINT.
    ///
    /// Returns Ok(username_str) on success, Err with optional error code on failure.
    ///
    /// # TigerStyle Compliance (Phase 4.10)
    ///
    /// - Extracted helper for 70-line limit
    /// - ≥2 assertions: precondition on data length, postcondition on username format
    /// - Bounded operations, explicit errors
    fn validate_request(
        &self,
        data: &[u8],
        msg: &StunMessage,
        credentials: &IceCredentials,
        integrity_ctx: &IntegrityContext,
    ) -> Result<String, Option<(u16, &'static str)>> {
        // Precondition: data must be at least a STUN header
        assert!(data.len() >= STUN_HEADER_SIZE,
            "validate_request requires at least {} bytes", STUN_HEADER_SIZE);

        // 1. Extract USERNAME attribute from parsed message
        let username = match msg.get_username() {
            Some(u) => u,
            None => return Err(Some((400, "Bad Request"))),
        };

        // 2. Parse USERNAME as "local_ufrag:remote_ufrag"
        let colon_pos = match username.find(':') {
            Some(pos) => pos,
            None => return Err(Some((400, "Bad Request"))),
        };
        let local_ufrag = &username[..colon_pos];

        // Postcondition: local_ufrag extracted from USERNAME must be non-empty
        assert!(!local_ufrag.is_empty(),
            "local_ufrag parsed from USERNAME must not be empty");

        // 3. Validate local_ufrag matches our credentials
        if local_ufrag != credentials.local_ufrag {
            return Err(Some((401, "Unauthorized")));
        }

        // 4. Validate MESSAGE-INTEGRITY if required
        if self.config.require_integrity {
            let key = credentials.local_pwd.as_bytes();

            if !integrity_ctx.verify_integrity(data, key) {
                return Err(Some((401, "Unauthorized")));
            }
        }

        // 5. Validate FINGERPRINT if required
        if self.config.require_fingerprint
            && (integrity_ctx.fingerprint_value.is_none()
                || !integrity_ctx.verify_fingerprint(data))
        {
            // Silently ignore malformed packets
            return Err(None);
        }

        Ok(username.to_string())
    }
    
    /// Parse STUN message with integrity context.
    fn parse_with_integrity(
        &self,
        data: &[u8],
    ) -> Result<(StunMessage, IntegrityContext), IceError> {
        let msg = StunMessage::parse(data)?;
        
        let mut ctx = IntegrityContext::empty();
        
        // Find MESSAGE-INTEGRITY and FINGERPRINT positions
        let mut offset = STUN_HEADER_SIZE;
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let end = STUN_HEADER_SIZE + msg_len;
        
        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            
            if offset + 4 + attr_len > data.len() {
                break;
            }
            
            match attr_type {
                ATTR_MESSAGE_INTEGRITY => {
                    if attr_len == 20 {
                        ctx.integrity_offset = offset;
                        let mut hmac = [0u8; 20];
                        hmac.copy_from_slice(&data[offset + 4..offset + 24]);
                        ctx.integrity_value = Some(hmac);
                    }
                }
                ATTR_FINGERPRINT => {
                    if attr_len == 4 {
                        ctx.fingerprint_offset = offset;
                        let fp = u32::from_be_bytes([
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7],
                        ]);
                        ctx.fingerprint_value = Some(fp);
                    }
                }
                _ => {}
            }
            
            // Move to next attribute (4-byte aligned)
            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }
        
        Ok((msg, ctx))
    }
    
    /// Build binding success response.
    fn build_binding_response(
        &mut self,
        request: &StunMessage,
        source: SocketAddr,
        credentials: &IceCredentials,
    ) -> Result<usize, IceError> {
        let buf = &mut self.response_buf;
        
        // Header
        let msg_type = StunMessage::encode_type(StunClass::SuccessResponse, StunMethod::Binding);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        // Length will be filled in later
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&request.transaction_id);
        
        let mut offset = STUN_HEADER_SIZE;
        
        // Add XOR-MAPPED-ADDRESS
        let xor_addr = StunAttribute::XorMappedAddress(source);
        let attr_len = xor_addr.encode(&mut buf[offset..], &request.transaction_id);
        offset += attr_len;
        
        // Update message length (before integrity)
        let attr_section_len = (offset - STUN_HEADER_SIZE) as u16;
        buf[2..4].copy_from_slice(&attr_section_len.to_be_bytes());
        
        // Sign with MESSAGE-INTEGRITY and FINGERPRINT
        let key = credentials.local_pwd.as_bytes();
        let final_len = sign_message(buf, offset, key);
        
        Ok(final_len)
    }
    
    /// Build error response.
    fn build_error_response(
        &mut self,
        request: &StunMessage,
        code: u16,
        reason: &str,
        credentials: &IceCredentials,
    ) -> Result<usize, IceError> {
        let buf = &mut self.response_buf;
        
        // Header
        let msg_type = StunMessage::encode_type(StunClass::ErrorResponse, StunMethod::Binding);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&request.transaction_id);
        
        let mut offset = STUN_HEADER_SIZE;
        
        // Add ERROR-CODE attribute
        let mut reason_buf = [0u8; 128];
        let reason_len = reason.len().min(128);
        reason_buf[..reason_len].copy_from_slice(&reason.as_bytes()[..reason_len]);
        
        let error = StunAttribute::ErrorCode {
            code,
            reason: reason_buf,
            reason_len: reason_len as u8,
        };
        let attr_len = error.encode(&mut buf[offset..], &request.transaction_id);
        offset += attr_len;
        
        // Update message length
        let attr_section_len = (offset - STUN_HEADER_SIZE) as u16;
        buf[2..4].copy_from_slice(&attr_section_len.to_be_bytes());
        
        // Sign response
        let key = credentials.local_pwd.as_bytes();
        let final_len = sign_message(buf, offset, key);
        
        Ok(final_len)
    }
}

/// Process a binding indication (ICE keepalive).
///
/// Binding indications don't require a response per RFC 5389.
/// They're used for ICE keepalives.
pub fn is_binding_indication(data: &[u8]) -> bool {
    if data.len() < STUN_HEADER_SIZE {
        return false;
    }
    
    if !StunMessage::is_stun(data) {
        return false;
    }
    
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let class = (msg_type >> 4) & 0x01 | (msg_type >> 7) & 0x02;
    let method = (msg_type & 0x000F) | ((msg_type >> 1) & 0x0070) | ((msg_type >> 2) & 0x0F80);
    
    class == 0x01 && method == 0x0001 // Indication + Binding
}

/// Create a binding request for ICE connectivity checks.
///
/// # Arguments
///
/// * `buf` - Output buffer.
/// * `transaction_id` - 12-byte transaction ID.
/// * `username` - ICE username (remote_ufrag:local_ufrag).
/// * `priority` - ICE priority.
/// * `ice_controlling` - Whether we're the controlling agent.
/// * `tie_breaker` - Tie-breaker value.
/// * `use_candidate` - Whether to include USE-CANDIDATE.
/// * `password` - Password for MESSAGE-INTEGRITY.
///
/// # Returns
///
/// Message length.
///
/// # TigerStyle Compliance (Phase 4.11)
///
/// - Buffer size precondition
/// - Username length assertion
/// - Postcondition for output bounds
pub fn create_binding_request(
    buf: &mut [u8],
    transaction_id: &[u8; 12],
    username: &str,
    priority: u32,
    ice_controlling: bool,
    tie_breaker: u64,
    use_candidate: bool,
    password: &str,
) -> usize {
    // Precondition: buffer size (TigerStyle Phase 4.11)
    assert!(buf.len() >= 128, "buffer too small: {} < 128", buf.len());
    
    // Precondition: username length bounded
    assert!(username.len() <= 128,
        "Username length {} exceeds maximum 128", username.len());
    
    // Precondition: password not empty
    assert!(!password.is_empty(), "Password cannot be empty");
    
    // Header
    let msg_type = StunMessage::encode_type(StunClass::Request, StunMethod::Binding);
    buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
    // Length filled in later
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(transaction_id);
    
    let mut offset = STUN_HEADER_SIZE;
    
    // USERNAME
    let username_attr = StunAttribute::username(username);
    offset += username_attr.encode(&mut buf[offset..], transaction_id);
    
    // PRIORITY
    let priority_attr = StunAttribute::Priority(priority);
    offset += priority_attr.encode(&mut buf[offset..], transaction_id);
    
    // ICE-CONTROLLING or ICE-CONTROLLED
    if ice_controlling {
        let ctrl = StunAttribute::IceControlling(tie_breaker);
        offset += ctrl.encode(&mut buf[offset..], transaction_id);
    } else {
        let ctrl = StunAttribute::IceControlled(tie_breaker);
        offset += ctrl.encode(&mut buf[offset..], transaction_id);
    }
    
    // USE-CANDIDATE (only for controlling agent)
    if use_candidate && ice_controlling {
        let uc = StunAttribute::UseCandidate;
        offset += uc.encode(&mut buf[offset..], transaction_id);
    }
    
    // Update length before signing
    let attr_len = (offset - STUN_HEADER_SIZE) as u16;
    buf[2..4].copy_from_slice(&attr_len.to_be_bytes());
    
    // Add MESSAGE-INTEGRITY and FINGERPRINT
    let final_len = sign_message(buf, offset, password.as_bytes());
    
    // Postcondition: output within buffer bounds (TigerStyle Phase 4.11)
    assert!(final_len <= buf.len(),
        "Final message length {} exceeds buffer size {}", final_len, buf.len());
    
    // Postcondition: minimum valid message size
    assert!(final_len >= STUN_HEADER_SIZE,
        "Final message must include full header");
    
    final_len
}

/// Generate a random transaction ID.
pub fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    
    // Use thread-local RNG for performance
    use std::cell::RefCell;
    thread_local! {
        static RNG: RefCell<u64> = RefCell::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        );
    }
    
    RNG.with(|rng| {
        let mut state = rng.borrow_mut();
        for chunk in id.chunks_exact_mut(8) {
            // Simple xorshift64
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            chunk.copy_from_slice(&state.to_ne_bytes());
        }
        // Fill remaining 4 bytes
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        id[8..12].copy_from_slice(&(*state as u32).to_ne_bytes());
    });
    
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_transaction_id() {
        let id1 = generate_transaction_id();
        let id2 = generate_transaction_id();
        
        // Should be different
        assert_ne!(id1, id2);
        
        // Should be 12 bytes
        assert_eq!(id1.len(), 12);
    }

    #[test]
    fn test_create_binding_request() {
        let mut buf = [0u8; STUN_BUFFER_SIZE];
        let tid = [1u8; 12];
        
        let len = create_binding_request(
            &mut buf,
            &tid,
            "remote:local",
            0x6e0001ff,
            true,
            0x123456789abcdef0,
            false,
            "password",
        );
        
        assert!(len > STUN_HEADER_SIZE);
        assert!(len < 128);
        
        // Verify it's a valid STUN message
        assert!(StunMessage::is_stun(&buf[..len]));
        
        // Parse it back
        let msg = StunMessage::parse(&buf[..len]).unwrap();
        assert_eq!(msg.class, StunClass::Request);
        assert_eq!(msg.method, StunMethod::Binding);
        assert_eq!(msg.transaction_id, tid);
    }

    #[test]
    fn test_binding_indication_detection() {
        // Create a binding indication (class 0x01, method 0x001)
        let mut data = [0u8; 20];
        
        // Message type for Binding Indication: 0x0011
        data[0..2].copy_from_slice(&0x0011u16.to_be_bytes());
        data[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length 0
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&[0u8; 12]); // Transaction ID
        
        assert!(is_binding_indication(&data));
        
        // Binding request should return false
        data[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(!is_binding_indication(&data));
    }

    #[test]
    fn test_stun_server_binding_response() {
        let mut server = StunServer::with_defaults();
        
        // Create a binding request
        let mut request = [0u8; 128];
        let tid = [5u8; 12];
        let credentials = IceCredentials::generate();
        
        let username = format!("{}:{}", credentials.local_ufrag, credentials.local_ufrag);
        let req_len = create_binding_request(
            &mut request,
            &tid,
            &username,
            0x6e0001ff,
            false,
            0x123456789abcdef0,
            false,
            &credentials.local_pwd,
        );
        
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        
        let result = server.handle_request(
            &request[..req_len],
            source,
            &credentials,
        );
        
        // Should get a response
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some());
        
        let response_data = response.unwrap();
        assert!(StunMessage::is_stun(response_data));
        
        let resp_msg = StunMessage::parse(response_data).unwrap();
        assert_eq!(resp_msg.class, StunClass::SuccessResponse);
        assert_eq!(resp_msg.method, StunMethod::Binding);
        assert_eq!(resp_msg.transaction_id, tid);
    }
}
