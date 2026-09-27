//! STUN Protocol Implementation (RFC 5389).
//!
//! Zero-allocation STUN message parsing and serialization for ICE
//! connectivity checks and NAT traversal.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    STUN Message (20+ bytes)                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  0                   1                   2                   3  │
//! │  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1│
//! │ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+│
//! │ |0 0|     STUN Message Type     |         Message Length        │
//! │ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+│
//! │ |                         Magic Cookie                          │
//! │ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+│
//! │ |                                                               │
//! │ |                     Transaction ID (96 bits)                  │
//! │ |                                                               │
//! │ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+│
//! │ |                      Attributes (variable)                    │
//! │ └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - All parsing uses explicit bounds checking
//! - No dynamic allocation (fixed-size attribute arrays)
//! - Comprehensive assertions on all inputs
//! - SIMD-friendly data layout

pub mod attributes;
pub mod integrity;
pub mod message;
pub mod server;

pub use attributes::{
    StunAttribute,
    ATTR_CHANNEL_NUMBER,
    ATTR_DATA,
    ATTR_ERROR_CODE,
    ATTR_FINGERPRINT,
    ATTR_ICE_CONTROLLED,
    ATTR_ICE_CONTROLLING,
    // TURN-specific attribute constants needed by turn/client.rs
    ATTR_LIFETIME,
    // Core attribute constants
    ATTR_MAPPED_ADDRESS,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_PRIORITY,
    ATTR_REQUESTED_TRANSPORT,
    ATTR_USERNAME,
    ATTR_USE_CANDIDATE,
    ATTR_XOR_MAPPED_ADDRESS,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS,
};
pub use integrity::{
    compute_message_integrity, sign_message, verify_fingerprint, verify_message_integrity,
};
pub use message::{StunClass, StunMessage, StunMethod, STUN_HEADER_SIZE, STUN_MAGIC_COOKIE};
pub use server::{
    create_binding_indication, create_binding_request, generate_transaction_id, StunServer,
};

/// Maximum STUN message size (from RFC 5389).
pub const STUN_MAX_MESSAGE_SIZE: u32 = 548;

/// Maximum attributes per STUN message.
pub const STUN_MAX_ATTRIBUTES: u32 = 16;

/// STUN FINGERPRINT XOR value.
pub const STUN_FINGERPRINT_XOR: u32 = 0x5354554E;

// Compile-time assertions
const _: () = {
    assert!(STUN_MAX_MESSAGE_SIZE >= 548, "RFC minimum");
    assert!(STUN_MAX_ATTRIBUTES >= 8, "need room for ICE attributes");
};

/// Quick check if data looks like a STUN message.
///
/// This is used for demultiplexing STUN/DTLS/RTP on the same port.
///
/// # Arguments
///
/// * `data` - Raw packet data.
///
/// # Returns
///
/// `true` if data appears to be a STUN message.
#[inline]
pub fn is_stun(data: &[u8]) -> bool {
    // TigerStyle: Check bounds first
    if data.len() < STUN_HEADER_SIZE as usize {
        return false;
    }

    // First two bits must be 0
    if data[0] & 0xC0 != 0 {
        return false;
    }

    // Check magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    cookie == STUN_MAGIC_COOKIE
}

/// Quick check if data is DTLS (not STUN or RTP).
///
/// DTLS content types are 20-63.
#[inline]
pub fn is_dtls(data: &[u8]) -> bool {
    !data.is_empty() && matches!(data[0], 20..=63)
}

/// Quick check if data is RTP.
///
/// RTP version 2 has first two bits = 10.
#[inline]
pub fn is_rtp(data: &[u8]) -> bool {
    !data.is_empty() && (data[0] >> 6) == 2
}

/// Quick check if data is RTCP.
///
/// RTCP has payload types 200-210.
#[inline]
pub fn is_rtcp(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }

    // Check version (must be 2)
    if (data[0] >> 6) != 2 {
        return false;
    }

    // Check payload type
    let pt = data[1];
    matches!(pt, 200..=210)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stun() {
        // Valid STUN Binding Request
        let valid = [
            0x00, 0x01, 0x00, 0x00, // Type + Length
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            0x00, 0x00, 0x00, 0x00, // Transaction ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_stun(&valid));

        // Too short
        assert!(!is_stun(&[0x00, 0x01]));

        // Wrong magic cookie
        let wrong_cookie = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Wrong cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_stun(&wrong_cookie));

        // First two bits not 0 (looks like RTP)
        let rtp_like = [
            0x80, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_stun(&rtp_like));
    }

    #[test]
    fn test_is_dtls() {
        // DTLS ClientHello (content type 22)
        assert!(is_dtls(&[22, 0xFE, 0xFD]));

        // DTLS ChangeCipherSpec (content type 20)
        assert!(is_dtls(&[20, 0xFE, 0xFD]));

        // Not DTLS
        assert!(!is_dtls(&[0x80])); // RTP
        assert!(!is_dtls(&[0x00])); // STUN
        assert!(!is_dtls(&[])); // Empty
    }

    #[test]
    fn test_is_rtp() {
        // RTP v2 packet
        assert!(is_rtp(&[0x80, 0x60, 0x00, 0x01]));

        // Not RTP (STUN)
        assert!(!is_rtp(&[0x00, 0x01]));

        // Empty
        assert!(!is_rtp(&[]));
    }

    #[test]
    fn test_is_rtcp() {
        // RTCP Sender Report (PT=200)
        assert!(is_rtcp(&[0x80, 200]));

        // RTCP Receiver Report (PT=201)
        assert!(is_rtcp(&[0x80, 201]));

        // Not RTCP
        assert!(!is_rtcp(&[0x80, 96])); // RTP with dynamic PT
        assert!(!is_rtcp(&[]));
    }

    // ------------------------------------------------------------------
    // Network input never panics (Phase 1.2a)
    // ------------------------------------------------------------------

    /// A binding request whose only attribute is USERNAME with `username`.
    fn request_with_username(username: &[u8]) -> Vec<u8> {
        let padded = username.len().div_ceil(4) * 4;
        let mut msg = vec![0u8; STUN_HEADER_SIZE + 4 + padded];
        msg[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        msg[2..4].copy_from_slice(&((4 + padded) as u16).to_be_bytes());
        msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg[20..22].copy_from_slice(&ATTR_USERNAME.to_be_bytes());
        msg[22..24].copy_from_slice(&(username.len() as u16).to_be_bytes());
        msg[24..24 + username.len()].copy_from_slice(username);
        msg
    }

    #[test]
    fn username_that_is_not_utf8_is_rejected() {
        let msg = request_with_username(&[b'a', 0xFF, 0xFE, b':', b'b']);
        assert!(StunMessage::parse(&msg).is_err());

        let ok = request_with_username(b"abcd:efgh");
        let parsed = StunMessage::parse(&ok).expect("valid UTF-8 username parses");
        assert_eq!(parsed.get_username(), Some("abcd:efgh"));
    }

    #[test]
    fn oversized_attribute_value_is_an_error() {
        let value = [0u8; attributes::MAX_DATA_LEN + 1];
        assert!(StunAttribute::parse(ATTR_DATA, &value, &[0u8; 12]).is_err());
    }

    #[test]
    fn empty_local_ufrag_in_username_does_not_panic() {
        let creds = crate::ice::IceCredentials {
            local_ufrag: "local".into(),
            local_pwd: "password".into(),
        };
        let mut buf = [0u8; message::STUN_BUFFER_SIZE];
        let tid = generate_transaction_id();
        let len = create_binding_request(&mut buf, &tid, ":remote", 1, true, 7, false, "password");
        let mut server = StunServer::with_defaults();
        let src = "192.0.2.1:5000".parse().unwrap();
        let response = server.handle_request(&buf[..len], src, &creds);
        assert!(response.is_ok());
    }

    #[test]
    fn empty_local_password_does_not_panic() {
        let creds = crate::ice::IceCredentials {
            local_ufrag: "local".into(),
            local_pwd: String::new(),
        };
        let mut buf = [0u8; message::STUN_BUFFER_SIZE];
        let tid = generate_transaction_id();
        let len = create_binding_request(&mut buf, &tid, "local:r", 1, true, 7, false, "x");
        let mut server = StunServer::with_defaults();
        let src = "192.0.2.1:5000".parse().unwrap();
        assert!(matches!(
            server.handle_request(&buf[..len], src, &creds),
            Ok(None)
        ));
    }

    #[test]
    fn integrity_and_fingerprint_refuse_bad_offsets_and_keys() {
        let msg = request_with_username(b"abcd:efgh");
        let hmac = [0u8; 20];
        assert!(!verify_message_integrity(
            &msg,
            msg.len() + 1,
            &hmac,
            b"key"
        ));
        assert!(!verify_message_integrity(&msg, 4, &hmac, b"key"));
        assert!(!verify_message_integrity(&msg, 20, &hmac, b""));
        assert!(!verify_message_integrity(&msg, 20, &hmac, &[1u8; 257]));
        assert!(!verify_message_integrity(&msg[..10], 20, &hmac, b"key"));
        assert!(!verify_fingerprint(&msg, msg.len() + 1, 0));
        assert!(!verify_fingerprint(&msg, 0, 0));
        assert!(!verify_fingerprint(&msg[..10], 20, 0));
    }
}
