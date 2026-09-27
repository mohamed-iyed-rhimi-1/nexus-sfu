//! ICE-lite binding requests (note §8.2), without allocation.
//!
//! `StunMessage::parse` is not used: the message is ≈ 19 KB by value and does
//! not record the attribute offsets the integrity checks need. Instead one
//! bounded pass over the attributes records them, and the checks run on
//! slices of the datagram.

use std::net::SocketAddr;

use nexus_transport::ice::stun::attributes::{
    ATTR_FINGERPRINT, ATTR_MESSAGE_INTEGRITY, ATTR_USERNAME, ATTR_USE_CANDIDATE,
};
use nexus_transport::ice::stun::{
    sign_message, verify_fingerprint, verify_message_integrity, StunAttribute, STUN_HEADER_SIZE,
    STUN_MAGIC_COOKIE,
};

/// Length of the local ufrag the shard issues.
pub const UFRAG_LEN: usize = 16;

/// Most attributes scanned in one request.
pub const MAX_ATTRIBUTES: usize = 32;

/// Room a success response needs: header, IPv6 XOR-MAPPED-ADDRESS,
/// MESSAGE-INTEGRITY, FINGERPRINT.
pub const RESPONSE_MAX_LEN: usize = STUN_HEADER_SIZE + 24 + 24 + 8;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

/// What the scan found in a binding request.
#[derive(Clone, Copy, Debug)]
pub struct BindingRequest {
    /// Transaction id.
    pub transaction_id: [u8; 12],
    /// The local half of USERNAME (before `:`).
    pub local_ufrag: [u8; UFRAG_LEN],
    /// USE-CANDIDATE was present.
    pub use_candidate: bool,
    integrity_offset: usize,
    integrity: [u8; 20],
    fingerprint_offset: usize,
    fingerprint: u32,
}

#[derive(Default)]
struct Offsets {
    username: Option<(usize, usize)>,
    use_candidate: bool,
    integrity: Option<usize>,
    fingerprint: Option<usize>,
}

fn be16(data: &[u8], at: usize) -> usize {
    u16::from_be_bytes([data[at], data[at + 1]]) as usize
}

/// Scans a binding request. `None` for anything else, a malformed message,
/// or one without USERNAME, MESSAGE-INTEGRITY and FINGERPRINT.
pub fn scan(data: &[u8]) -> Option<BindingRequest> {
    if data.len() < STUN_HEADER_SIZE || be16(data, 0) != BINDING_REQUEST as usize {
        return None;
    }
    if data[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    let body = be16(data, 2);
    if body % 4 != 0 || STUN_HEADER_SIZE + body != data.len() {
        return None;
    }
    let found = scan_attributes(data)?;

    let (user_at, user_len) = found.username?;
    let username = &data[user_at..user_at + user_len];
    // USERNAME is UTF-8 (RFC 8489 §14.3); the remote half is otherwise opaque.
    if std::str::from_utf8(username).is_err() || username.get(UFRAG_LEN) != Some(&b':') {
        return None;
    }
    let mi_at = found.integrity?;
    let fp_at = found.fingerprint?;

    let mut request = BindingRequest {
        transaction_id: [0; 12],
        local_ufrag: [0; UFRAG_LEN],
        use_candidate: found.use_candidate,
        integrity_offset: mi_at,
        integrity: [0; 20],
        fingerprint_offset: fp_at,
        fingerprint: u32::from_be_bytes(data[fp_at + 4..fp_at + 8].try_into().ok()?),
    };
    request.transaction_id.copy_from_slice(&data[8..20]);
    request.local_ufrag.copy_from_slice(&username[..UFRAG_LEN]);
    request
        .integrity
        .copy_from_slice(&data[mi_at + 4..mi_at + 24]);
    Some(request)
}

/// One bounded pass over the attributes. Only FINGERPRINT may follow
/// MESSAGE-INTEGRITY, and nothing may follow FINGERPRINT.
fn scan_attributes(data: &[u8]) -> Option<Offsets> {
    let mut found = Offsets::default();
    let mut at = STUN_HEADER_SIZE;
    for _ in 0..MAX_ATTRIBUTES {
        if at == data.len() {
            return Some(found);
        }
        if at + 4 > data.len() || found.fingerprint.is_some() {
            return None;
        }
        let (kind, len) = (be16(data, at) as u16, be16(data, at + 2));
        let next = at + 4 + len.div_ceil(4) * 4;
        if next > data.len() {
            return None;
        }
        if found.integrity.is_some() && kind != ATTR_FINGERPRINT {
            return None;
        }
        match kind {
            ATTR_USERNAME if found.username.is_none() => found.username = Some((at + 4, len)),
            ATTR_USE_CANDIDATE => found.use_candidate = true,
            ATTR_MESSAGE_INTEGRITY if len == 20 => found.integrity = Some(at),
            ATTR_MESSAGE_INTEGRITY => return None,
            ATTR_FINGERPRINT if len == 4 => found.fingerprint = Some(at),
            ATTR_FINGERPRINT => return None,
            _ => {}
        }
        at = next;
    }
    (at == data.len()).then_some(found)
}

/// Checks FINGERPRINT, then MESSAGE-INTEGRITY with the session's password.
pub fn verify(data: &[u8], request: &BindingRequest, password: &[u8]) -> bool {
    debug_assert!(!password.is_empty());
    verify_fingerprint(data, request.fingerprint_offset, request.fingerprint)
        && verify_message_integrity(data, request.integrity_offset, &request.integrity, password)
}

/// Writes the success response to `request` from `source` into `dst`.
pub fn write_success(
    dst: &mut [u8],
    request: &BindingRequest,
    source: SocketAddr,
    password: &[u8],
) -> Option<usize> {
    if dst.len() < RESPONSE_MAX_LEN || password.is_empty() {
        return None;
    }
    dst[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
    dst[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    dst[8..20].copy_from_slice(&request.transaction_id);
    let attr = StunAttribute::XorMappedAddress(source)
        .encode(&mut dst[STUN_HEADER_SIZE..], &request.transaction_id);
    let body_len = STUN_HEADER_SIZE + attr;
    dst[2..4].copy_from_slice(&(attr as u16).to_be_bytes());
    let len = sign_message(dst, body_len, password);
    debug_assert!(len <= RESPONSE_MAX_LEN);
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_transport::ice::stun::{create_binding_request, StunMessage};

    const UFRAG: &[u8; 16] = b"sfuUfrag01234567";
    const PWD: &[u8; 32] = b"sfuPassword0123456789abcdefghijk";

    fn request(username: &str, password: &str, use_candidate: bool) -> Vec<u8> {
        let mut buf = [0u8; 576];
        let tid = [7u8; 12];
        let len = create_binding_request(
            &mut buf,
            &tid,
            username,
            9,
            true,
            1,
            use_candidate,
            password,
        );
        buf[..len].to_vec()
    }

    fn ok_request(use_candidate: bool) -> Vec<u8> {
        let user = format!("{}:peer", std::str::from_utf8(UFRAG).unwrap());
        request(&user, std::str::from_utf8(PWD).unwrap(), use_candidate)
    }

    #[test]
    fn valid_request_scans_and_verifies() {
        let data = ok_request(true);
        let req = scan(&data).expect("valid request");
        assert_eq!(&req.local_ufrag, UFRAG);
        assert!(req.use_candidate);
        assert!(verify(&data, &req, PWD));
        assert!(!verify(&data, &req, b"wrong password................ab"));
        assert!(!scan(&ok_request(false)).unwrap().use_candidate);
    }

    #[test]
    fn response_parses_with_mapped_address() {
        let data = ok_request(false);
        let req = scan(&data).unwrap();
        for source in ["192.0.2.7:5000", "[2001:db8::1]:6000"] {
            let source: SocketAddr = source.parse().unwrap();
            let mut dst = [0u8; 128];
            let n = write_success(&mut dst, &req, source, PWD).unwrap();
            let msg = StunMessage::parse(&dst[..n]).expect("response parses");
            assert_eq!(msg.transaction_id, [7u8; 12]);
            assert_eq!(msg.get_xor_mapped_address(), Some(source));
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        let good = ok_request(true);
        assert!(scan(&good[..good.len() - 4]).is_none(), "truncated");
        assert!(scan(&good[..19]).is_none());
        let mut bad_cookie = good.clone();
        bad_cookie[4] ^= 1;
        assert!(scan(&bad_cookie).is_none());
        let mut response = good.clone();
        response[1] = 0x01;
        response[0] = 0x01;
        assert!(scan(&response).is_none(), "not a request");
        assert!(
            scan(&request("short:peer", "pw", false)).is_none(),
            "ufrag not 16 bytes"
        );
    }

    #[test]
    fn bad_fingerprint_fails_verification() {
        let mut data = ok_request(false);
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        let req = scan(&data).unwrap();
        assert!(!verify(&data, &req, PWD));
    }

    #[test]
    fn too_many_attributes_are_refused() {
        // 40 unknown 0-length attributes before USERNAME/MI/FP.
        let signed = ok_request(false);
        let mut data = signed[..20].to_vec();
        for _ in 0..40 {
            data.extend_from_slice(&[0x80, 0x99, 0, 0]);
        }
        data.extend_from_slice(&signed[20..]);
        let body = (data.len() - 20) as u16;
        data[2..4].copy_from_slice(&body.to_be_bytes());
        assert!(scan(&data).is_none());
    }
}
