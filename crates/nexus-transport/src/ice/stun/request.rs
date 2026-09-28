//! STUN requests an ICE agent sends (used by the tests' peers and the loadtest):
//! binding requests and indications, and transaction ids. The SFU answers STUN in
//! the shard (`nexus-dataplane`'s slim scan); the old `StunServer` was removed in
//! Phase 1 (C5).

use super::attributes::StunAttribute;
use super::integrity::sign_message;
use super::message::{StunClass, StunMessage, StunMethod, STUN_HEADER_SIZE, STUN_MAGIC_COOKIE};

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

/// Create a STUN Binding Indication for ICE consent freshness (RFC 7675).
///
/// Binding Indications are fire-and-forget keepalives — no response expected.
/// Returns the message length (always 20 bytes = STUN header only).
pub fn create_binding_indication(buf: &mut [u8], transaction_id: &[u8; 12]) -> usize {
    assert!(buf.len() >= STUN_HEADER_SIZE);
    let msg_type = StunMessage::encode_type(StunClass::Indication, StunMethod::Binding);
    buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // length = 0
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(transaction_id);
    STUN_HEADER_SIZE
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
    assert!(
        username.len() <= 128,
        "Username length {} exceeds maximum 128",
        username.len()
    );

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
    assert!(
        final_len <= buf.len(),
        "Final message length {} exceeds buffer size {}",
        final_len,
        buf.len()
    );

    // Postcondition: minimum valid message size
    assert!(
        final_len >= STUN_HEADER_SIZE,
        "Final message must include full header"
    );

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
    use super::super::message::STUN_BUFFER_SIZE;
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
}
