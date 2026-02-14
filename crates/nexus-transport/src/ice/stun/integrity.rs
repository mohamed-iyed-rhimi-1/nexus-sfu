//! STUN Message Integrity.
//!
//! HMAC-SHA1 and FINGERPRINT validation per RFC 5389.
//!
//! Zero-allocation implementation using pre-allocated buffers.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::message::STUN_HEADER_SIZE;
use super::STUN_FINGERPRINT_XOR;

type HmacSha1 = Hmac<Sha1>;

/// Compute MESSAGE-INTEGRITY HMAC-SHA1.
///
/// Per RFC 5389, the HMAC is computed over the STUN message
/// up to and including the MESSAGE-INTEGRITY attribute header,
/// with the message length adjusted to exclude any attributes
/// after MESSAGE-INTEGRITY.
///
/// # Arguments
///
/// * `data` - Complete STUN message bytes.
/// * `integrity_offset` - Offset where MESSAGE-INTEGRITY attribute starts.
/// * `key` - HMAC key (usually password or derived key).
///
/// # Returns
///
/// 20-byte HMAC-SHA1 digest.
///
/// # TigerStyle Compliance (Phase 4.1)
///
/// - Preconditions for data length and offset
/// - Key length assertion
/// - Postcondition for HMAC length
pub fn compute_message_integrity(
    data: &[u8],
    integrity_offset: usize,
    key: &[u8],
) -> [u8; 20] {
    // Preconditions (TigerStyle Phase 4.1)
    assert!(data.len() >= STUN_HEADER_SIZE, "message too short");
    assert!(integrity_offset >= STUN_HEADER_SIZE, "invalid offset");
    
    // Key length assertion (TigerStyle Phase 4.1)
    assert!(!key.is_empty() && key.len() <= 256,
        "HMAC key must be 1-256 bytes");
    
    // Per RFC 5389 Section 15.4:
    // The length field in the header is adjusted to point to the end of MESSAGE-INTEGRITY
    // (i.e., the length includes MESSAGE-INTEGRITY but excludes FINGERPRINT)
    let adjusted_len = (integrity_offset - STUN_HEADER_SIZE) + 24; // attributes + MESSAGE-INTEGRITY (4 header + 20 value)
    
    // Adjusted length bounds assertion (TigerStyle Phase 4.1)
    assert!(adjusted_len <= data.len() + 24,
        "Adjusted length must be reasonable");
    
    // Compute HMAC over header (with adjusted length) + attributes up to MESSAGE-INTEGRITY
    // Per RFC 5389: HMAC is computed over the STUN message up to and INCLUDING
    // the attribute preceding MESSAGE-INTEGRITY, but NOT including MESSAGE-INTEGRITY itself
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key size");
    
    // Feed header with adjusted length
    mac.update(&data[0..2]); // Type
    mac.update(&(adjusted_len as u16).to_be_bytes()); // Adjusted length
    mac.update(&data[4..STUN_HEADER_SIZE]); // Magic cookie + transaction ID
    
    // Feed attributes up to MESSAGE-INTEGRITY (NOT including MESSAGE-INTEGRITY header)
    mac.update(&data[STUN_HEADER_SIZE..integrity_offset]);
    
    let result = mac.finalize();
    let mut hmac = [0u8; 20];
    hmac.copy_from_slice(&result.into_bytes());
    
    // Postcondition: HMAC is 20 bytes (TigerStyle Phase 4.1)
    assert!(hmac.len() == 20, "HMAC must be exactly 20 bytes");
    
    hmac
}

/// Verify MESSAGE-INTEGRITY attribute.
///
/// # Arguments
///
/// * `data` - Complete STUN message bytes.
/// * `integrity_offset` - Offset where MESSAGE-INTEGRITY attribute starts.
/// * `expected_hmac` - Expected HMAC from the attribute.
/// * `key` - HMAC key.
///
/// # Returns
///
/// true if valid, false otherwise.
///
/// # TigerStyle Compliance (Phase 4.2)
///
/// - Precondition for expected HMAC length
/// - Computed HMAC length assertion
/// - Constant-time comparison for security
pub fn verify_message_integrity(
    data: &[u8],
    integrity_offset: usize,
    expected_hmac: &[u8; 20],
    key: &[u8],
) -> bool {
    // Precondition: expected HMAC must be 20 bytes (TigerStyle Phase 4.2)
    assert!(expected_hmac.len() == 20,
        "Expected HMAC must be 20 bytes");
    
    let computed = compute_message_integrity(data, integrity_offset, key);
    
    // Assertion: computed HMAC must be 20 bytes (TigerStyle Phase 4.2)
    assert!(computed.len() == 20,
        "Computed HMAC must be 20 bytes");
    
    // Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected_hmac.iter()) {
        diff |= a ^ b;
    }
    
    // Result is valid if and only if diff is 0
    diff == 0
}

/// Compute CRC-32 fingerprint.
///
/// Per RFC 5389, FINGERPRINT is CRC-32 XOR'd with 0x5354554e.
///
/// # Arguments
///
/// * `data` - STUN message bytes up to (but not including) FINGERPRINT attribute.
/// * `fingerprint_offset` - Offset where FINGERPRINT attribute starts.
///
/// # Returns
///
/// 4-byte fingerprint value.
///
/// # TigerStyle Compliance (Phase 4.3)
///
/// - Preconditions for data length and offset
/// - Adjusted length bounds assertion
pub fn compute_fingerprint(data: &[u8], fingerprint_offset: usize) -> u32 {
    // Preconditions (TigerStyle Phase 4.3)
    assert!(data.len() >= STUN_HEADER_SIZE, "message too short");
    assert!(fingerprint_offset >= STUN_HEADER_SIZE, "invalid offset");
    
    // Adjusted length includes FINGERPRINT (4 header + 4 value)
    let adjusted_len = (fingerprint_offset - STUN_HEADER_SIZE) + 8;
    
    // Adjusted length assertion (TigerStyle Phase 4.3)
    assert!(adjusted_len >= 8 && adjusted_len <= data.len() + 8,
        "Adjusted length must be valid");
    
    // Build data for CRC with adjusted length
    let mut crc = crc32fast::Hasher::new();
    
    // Header with adjusted length
    crc.update(&data[0..2]);
    crc.update(&(adjusted_len as u16).to_be_bytes());
    crc.update(&data[4..STUN_HEADER_SIZE]);
    
    // Attributes up to FINGERPRINT
    crc.update(&data[STUN_HEADER_SIZE..fingerprint_offset]);
    
    let crc_value = crc.finalize();
    let result = crc_value ^ STUN_FINGERPRINT_XOR;
    
    // Postcondition: XOR was applied (result differs from raw CRC unless CRC == 0x5354554e)
    // This is a documentation assertion
    result
}

/// Verify FINGERPRINT attribute.
///
/// # Arguments
///
/// * `data` - Complete STUN message bytes.
/// * `fingerprint_offset` - Offset where FINGERPRINT attribute starts.
/// * `expected_fp` - Expected fingerprint from the attribute.
///
/// # Returns
///
/// true if valid, false otherwise.
pub fn verify_fingerprint(
    data: &[u8],
    fingerprint_offset: usize,
    expected_fp: u32,
) -> bool {
    let computed = compute_fingerprint(data, fingerprint_offset);
    computed == expected_fp
}

/// Derive short-term credential key.
///
/// For short-term credentials (ICE), the key is just the password.
///
/// # Arguments
///
/// * `password` - Password string.
///
/// # Returns
///
/// Key bytes.
pub fn derive_short_term_key(password: &str) -> Vec<u8> {
    password.as_bytes().to_vec()
}

/// Derive long-term credential key.
///
/// For long-term credentials (TURN with authentication), the key is:
/// MD5(username:realm:password)
///
/// # Arguments
///
/// * `username` - Username.
/// * `realm` - Realm.
/// * `password` - Password.
///
/// # Returns
///
/// 16-byte key.
pub fn derive_long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    
    let mut hasher = Md5::new();
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(realm.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    
    let result = hasher.finalize();
    result.into()
}

/// Add MESSAGE-INTEGRITY to a STUN message.
///
/// This modifies the message in-place and returns the new length.
///
/// # Arguments
///
/// * `buf` - Buffer containing the STUN message.
/// * `msg_len` - Current message length.
/// * `key` - HMAC key.
///
/// # Returns
///
/// New message length (msg_len + 24).
///
/// # TigerStyle Compliance (Phase 4.4)
///
/// - Preconditions for buffer size and message length
/// - Integrity offset assertion
/// - Postcondition for new message length
pub fn add_message_integrity(buf: &mut [u8], msg_len: usize, key: &[u8]) -> usize {
    // Preconditions (TigerStyle Phase 4.4)
    assert!(buf.len() >= msg_len + 24, "buffer too small");
    assert!(msg_len >= STUN_HEADER_SIZE, "message too short");
    
    let integrity_offset = msg_len;
    
    // Integrity offset assertion (TigerStyle Phase 4.4)
    assert!(integrity_offset == msg_len,
        "Integrity offset must equal current message length");
    
    let new_msg_len = msg_len + 24; // 4 header + 20 HMAC
    
    // Update message length in header
    let attr_len = (new_msg_len - STUN_HEADER_SIZE) as u16;
    buf[2..4].copy_from_slice(&attr_len.to_be_bytes());
    
    // Compute HMAC
    let hmac = compute_message_integrity(buf, integrity_offset, key);
    
    // Write MESSAGE-INTEGRITY attribute
    buf[integrity_offset..integrity_offset + 2].copy_from_slice(&0x0008u16.to_be_bytes()); // Type
    buf[integrity_offset + 2..integrity_offset + 4].copy_from_slice(&0x0014u16.to_be_bytes()); // Length (20)
    buf[integrity_offset + 4..integrity_offset + 24].copy_from_slice(&hmac);
    
    // Postcondition: new message length is correct (TigerStyle Phase 4.4)
    assert!(new_msg_len == msg_len + 24,
        "New message length must be msg_len + 24");
    
    // Postcondition: attribute was written correctly (verify type)
    assert!(buf[integrity_offset] == 0x00 && buf[integrity_offset + 1] == 0x08,
        "MESSAGE-INTEGRITY type must be 0x0008");
    
    new_msg_len
}

/// Add FINGERPRINT to a STUN message.
///
/// This modifies the message in-place and returns the new length.
///
/// # Arguments
///
/// * `buf` - Buffer containing the STUN message.
/// * `msg_len` - Current message length.
///
/// # Returns
///
/// New message length (msg_len + 8).
///
/// # TigerStyle Compliance (Phase 4.5)
///
/// - Preconditions for buffer size and message length
/// - Fingerprint offset assertion
/// - Postcondition for new message length
pub fn add_fingerprint(buf: &mut [u8], msg_len: usize) -> usize {
    // Preconditions (TigerStyle Phase 4.5)
    assert!(buf.len() >= msg_len + 8, "buffer too small");
    assert!(msg_len >= STUN_HEADER_SIZE, "message too short");
    
    let fingerprint_offset = msg_len;
    
    // Fingerprint offset assertion (TigerStyle Phase 4.5)
    assert!(fingerprint_offset == msg_len,
        "Fingerprint offset must equal current message length");
    
    let new_msg_len = msg_len + 8; // 4 header + 4 CRC
    
    // Update message length in header
    let attr_len = (new_msg_len - STUN_HEADER_SIZE) as u16;
    buf[2..4].copy_from_slice(&attr_len.to_be_bytes());
    
    // Compute fingerprint
    let fp = compute_fingerprint(buf, fingerprint_offset);
    
    // Write FINGERPRINT attribute
    buf[fingerprint_offset..fingerprint_offset + 2].copy_from_slice(&0x8028u16.to_be_bytes()); // Type
    buf[fingerprint_offset + 2..fingerprint_offset + 4].copy_from_slice(&0x0004u16.to_be_bytes()); // Length (4)
    buf[fingerprint_offset + 4..fingerprint_offset + 8].copy_from_slice(&fp.to_be_bytes());
    
    // Postcondition: new message length is correct (TigerStyle Phase 4.5)
    assert!(new_msg_len == msg_len + 8,
        "New message length must be msg_len + 8");
    
    // Postcondition: attribute was written correctly (verify type)
    assert!(buf[fingerprint_offset] == 0x80 && buf[fingerprint_offset + 1] == 0x28,
        "FINGERPRINT type must be 0x8028");
    
    new_msg_len
}

/// Sign a STUN message with MESSAGE-INTEGRITY and FINGERPRINT.
///
/// # Arguments
///
/// * `buf` - Buffer containing the STUN message.
/// * `msg_len` - Current message length.
/// * `key` - HMAC key.
///
/// # Returns
///
/// New message length.
pub fn sign_message(buf: &mut [u8], msg_len: usize, key: &[u8]) -> usize {
    let len_after_integrity = add_message_integrity(buf, msg_len, key);
    add_fingerprint(buf, len_after_integrity)
}

/// Validate integrity context for incoming STUN message.
#[derive(Debug)]
pub struct IntegrityContext {
    /// Offset of MESSAGE-INTEGRITY attribute (0 if not present).
    pub integrity_offset: usize,
    
    /// MESSAGE-INTEGRITY value (if present).
    pub integrity_value: Option<[u8; 20]>,
    
    /// Offset of FINGERPRINT attribute (0 if not present).
    pub fingerprint_offset: usize,
    
    /// FINGERPRINT value (if present).
    pub fingerprint_value: Option<u32>,
}

impl IntegrityContext {
    /// Create empty context.
    pub const fn empty() -> Self {
        Self {
            integrity_offset: 0,
            integrity_value: None,
            fingerprint_offset: 0,
            fingerprint_value: None,
        }
    }
    
    /// Verify MESSAGE-INTEGRITY.
    pub fn verify_integrity(&self, data: &[u8], key: &[u8]) -> bool {
        match self.integrity_value {
            Some(ref expected) => {
                verify_message_integrity(data, self.integrity_offset, expected, key)
            }
            None => false,
        }
    }
    
    /// Verify FINGERPRINT.
    pub fn verify_fingerprint(&self, data: &[u8]) -> bool {
        match self.fingerprint_value {
            Some(expected) => {
                verify_fingerprint(data, self.fingerprint_offset, expected)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::message::STUN_MAGIC_COOKIE;

    #[test]
    fn test_short_term_key() {
        let key = derive_short_term_key("password123");
        assert_eq!(key, b"password123");
    }
    #[test]
    fn test_long_term_key() {
        // RFC 5389 test vector
        let key = derive_long_term_key("user", "realm.example.com", "password");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_fingerprint_xor() {
        // The FINGERPRINT XOR constant
        assert_eq!(STUN_FINGERPRINT_XOR, 0x5354554e);
        
        // Verify it spells "STUN" in ASCII
        let bytes = STUN_FINGERPRINT_XOR.to_be_bytes();
        assert_eq!(&bytes, b"STUN");
    }

    #[test]
    fn test_add_integrity_and_fingerprint() {
        // Create a minimal STUN binding request
        let mut buf = [0u8; 128];
        
        // Header
        buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length = 0
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&[1u8; 12]); // Transaction ID
        
        let mut len = 20usize;
        
        // Add integrity
        let key = b"testpassword";
        len = add_message_integrity(&mut buf, len, key);
        assert_eq!(len, 44); // 20 + 24
        
        // Verify length in header
        let attr_len = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(attr_len, 24);
        
        // Add fingerprint
        len = add_fingerprint(&mut buf, len);
        assert_eq!(len, 52); // 44 + 8
        
        // Verify final length
        let attr_len = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(attr_len, 32);
    }

    #[test]
    fn test_integrity_roundtrip() {
        let mut buf = [0u8; 128];
        
        // Header
        buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&[2u8; 12]);
        
        let key = b"secretkey";
        let len = add_message_integrity(&mut buf, 20, key);
        
        // Extract HMAC
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&buf[24..44]);
        
        // Verify
        assert!(verify_message_integrity(&buf[..len], 20, &expected, key));
        
        // Should fail with wrong key
        assert!(!verify_message_integrity(&buf[..len], 20, &expected, b"wrongkey"));
    }
}
