//! WebRTC transport types.
//!
//! Unified with sdp types where possible to avoid duplication (Tiger Style).
//! All types are stack-allocated — no heap allocation.

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// Re-export sdp::MediaType as the canonical MediaType for the webrtc layer.
// Eliminates duplicate enum (Issue #9).
pub use crate::sdp::MediaType;

// Re-export sdp DtlsFingerprint + FingerprintAlgorithm as canonical types.
// Eliminates duplicate struct (Issue #10).
pub use crate::sdp::{DtlsFingerprint as SdpFingerprint, FingerprintAlgorithm};

/// Unique transport identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportId(pub u64);

impl TransportId {
    /// Create new transport ID.
    #[inline]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
    
    /// Get raw ID value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport-{:016x}", self.0)
    }
}

/// Maximum ICE credential length (RFC 8445).
const MAX_ICE_CRED_LEN: usize = 256;

/// ICE parameters for transport setup (stack-allocated).
#[derive(Debug, Clone)]
pub struct IceParameters {
    /// ICE username fragment.
    ufrag_buf: [u8; MAX_ICE_CRED_LEN],
    ufrag_len: u16,
    /// ICE password.
    pwd_buf: [u8; MAX_ICE_CRED_LEN],
    pwd_len: u16,
}

impl IceParameters {
    /// Create new ICE parameters.
    pub fn new(ufrag: &str, pwd: &str) -> Self {
        let mut ufrag_buf = [0u8; MAX_ICE_CRED_LEN];
        let ufrag_len = ufrag.len().min(MAX_ICE_CRED_LEN);
        ufrag_buf[..ufrag_len].copy_from_slice(&ufrag.as_bytes()[..ufrag_len]);

        let mut pwd_buf = [0u8; MAX_ICE_CRED_LEN];
        let pwd_len = pwd.len().min(MAX_ICE_CRED_LEN);
        pwd_buf[..pwd_len].copy_from_slice(&pwd.as_bytes()[..pwd_len]);

        Self {
            ufrag_buf,
            ufrag_len: ufrag_len as u16,
            pwd_buf,
            pwd_len: pwd_len as u16,
        }
    }

    /// Get username fragment.
    pub fn username_fragment(&self) -> &str {
        std::str::from_utf8(&self.ufrag_buf[..self.ufrag_len as usize]).unwrap_or("")
    }

    /// Get password.
    pub fn password(&self) -> &str {
        std::str::from_utf8(&self.pwd_buf[..self.pwd_len as usize]).unwrap_or("")
    }
}

/// DTLS fingerprint for certificate verification (stack-allocated).
///
/// Wraps the SDP fingerprint type and adds convenience constructors
/// for the WebRTC transport layer.
#[derive(Debug, Clone, PartialEq)]
pub struct DtlsFingerprint {
    inner: SdpFingerprint,
}

impl DtlsFingerprint {
    /// Create SHA-256 fingerprint from hex-colon string (e.g. "AB:CD:EF:...").
    pub fn sha256(hex_value: &str) -> Option<Self> {
        let sdp_str = format!("sha-256 {}", hex_value);
        SdpFingerprint::parse(&sdp_str).ok().map(|inner| Self { inner })
    }

    /// Create from SDP format string (e.g., "sha-256 AB:CD:EF:...").
    pub fn from_sdp(s: &str) -> Option<Self> {
        SdpFingerprint::parse(s).ok().map(|inner| Self { inner })
    }

    /// Format for SDP output.
    pub fn to_sdp_string(&self) -> String {
        self.inner.to_sdp()
    }

    /// Get the underlying SDP fingerprint.
    pub fn as_sdp(&self) -> &SdpFingerprint {
        &self.inner
    }

    /// Get algorithm.
    pub fn algorithm(&self) -> FingerprintAlgorithm {
        self.inner.algorithm
    }

    /// Get raw fingerprint bytes.
    pub fn value_bytes(&self) -> &[u8] {
        &self.inner.value[..self.inner.value_len as usize]
    }
}

/// Maximum fingerprints per DTLS parameters.
const MAX_DTLS_FINGERPRINTS: usize = 4;

/// DTLS parameters for transport setup (stack-allocated).
#[derive(Debug, Clone)]
pub struct DtlsParameters {
    /// DTLS role (client/server/auto).
    pub role: DtlsRole,
    /// Certificate fingerprints (fixed array, bounded).
    fingerprints: [Option<DtlsFingerprint>; MAX_DTLS_FINGERPRINTS],
    fingerprint_count: u8,
}

impl DtlsParameters {
    /// Create new DTLS parameters.
    pub fn new(role: DtlsRole) -> Self {
        Self {
            role,
            fingerprints: Default::default(),
            fingerprint_count: 0,
        }
    }
    
    /// Add fingerprint. Returns self for chaining.
    pub fn with_fingerprint(mut self, fp: DtlsFingerprint) -> Self {
        if (self.fingerprint_count as usize) < MAX_DTLS_FINGERPRINTS {
            self.fingerprints[self.fingerprint_count as usize] = Some(fp);
            self.fingerprint_count += 1;
        }
        self
    }

    /// Get fingerprint count.
    pub fn fingerprint_count(&self) -> usize {
        self.fingerprint_count as usize
    }

    /// Get fingerprint by index.
    pub fn fingerprint(&self, index: usize) -> Option<&DtlsFingerprint> {
        if index < self.fingerprint_count as usize {
            self.fingerprints[index].as_ref()
        } else {
            None
        }
    }
}

/// DTLS role in handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// Act as DTLS client.
    Client,
    /// Act as DTLS server.
    Server,
    /// Role determined by ICE controlling/controlled.
    Auto,
}

impl Default for DtlsRole {
    fn default() -> Self {
        Self::Auto
    }
}

/// Transport statistics.
///
/// Uses atomic counters for lock-free updates from concurrent packet processing.
pub struct TransportStats {
    /// Bytes sent.
    pub bytes_sent: AtomicU64,
    /// Bytes received.
    pub bytes_received: AtomicU64,
    /// Packets sent.
    pub packets_sent: AtomicU64,
    /// Packets received.
    pub packets_received: AtomicU64,
    /// RTP packets sent.
    pub rtp_packets_sent: AtomicU64,
    /// RTP packets received.
    pub rtp_packets_received: AtomicU64,
    /// RTCP packets sent.
    pub rtcp_packets_sent: AtomicU64,
    /// RTCP packets received.
    pub rtcp_packets_received: AtomicU64,
    /// SRTP authentication failures.
    pub srtp_auth_failures: AtomicU64,
    /// Replay attacks detected.
    pub replay_attacks: AtomicU64,
    /// ICE candidate pairs checked.
    pub ice_pairs_checked: AtomicU64,
    /// STUN requests sent.
    pub stun_requests_sent: AtomicU64,
    /// STUN responses received.
    pub stun_responses_received: AtomicU64,
}

impl TransportStats {
    /// Create empty stats.
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            rtp_packets_sent: AtomicU64::new(0),
            rtp_packets_received: AtomicU64::new(0),
            rtcp_packets_sent: AtomicU64::new(0),
            rtcp_packets_received: AtomicU64::new(0),
            srtp_auth_failures: AtomicU64::new(0),
            replay_attacks: AtomicU64::new(0),
            ice_pairs_checked: AtomicU64::new(0),
            stun_requests_sent: AtomicU64::new(0),
            stun_responses_received: AtomicU64::new(0),
        }
    }

    /// Create stats from plain u64 values (for per-session snapshot conversion).
    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        packets_sent: u64,
        packets_received: u64,
        bytes_sent: u64,
        bytes_received: u64,
        rtp_packets_sent: u64,
        rtp_packets_received: u64,
        rtcp_packets_sent: u64,
        rtcp_packets_received: u64,
    ) -> Self {
        Self {
            bytes_sent: AtomicU64::new(bytes_sent),
            bytes_received: AtomicU64::new(bytes_received),
            packets_sent: AtomicU64::new(packets_sent),
            packets_received: AtomicU64::new(packets_received),
            rtp_packets_sent: AtomicU64::new(rtp_packets_sent),
            rtp_packets_received: AtomicU64::new(rtp_packets_received),
            rtcp_packets_sent: AtomicU64::new(rtcp_packets_sent),
            rtcp_packets_received: AtomicU64::new(rtcp_packets_received),
            srtp_auth_failures: AtomicU64::new(0),
            replay_attacks: AtomicU64::new(0),
            ice_pairs_checked: AtomicU64::new(0),
            stun_requests_sent: AtomicU64::new(0),
            stun_responses_received: AtomicU64::new(0),
        }
    }
}

impl Default for TransportStats {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransportStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportStats")
            .field("bytes_sent", &self.bytes_sent.load(Ordering::Relaxed))
            .field("bytes_received", &self.bytes_received.load(Ordering::Relaxed))
            .field("packets_sent", &self.packets_sent.load(Ordering::Relaxed))
            .field("packets_received", &self.packets_received.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_id() {
        let id = TransportId::new(0x123456789ABCDEF0);
        assert_eq!(id.value(), 0x123456789ABCDEF0);
        assert!(id.to_string().contains("123456789abcdef0"));
    }

    #[test]
    fn test_ice_parameters() {
        let params = IceParameters::new("user", "pass");
        assert_eq!(params.username_fragment(), "user");
        assert_eq!(params.password(), "pass");
    }

    #[test]
    fn test_dtls_fingerprint() {
        let fp = DtlsFingerprint::sha256("AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90").unwrap();
        assert_eq!(fp.algorithm(), FingerprintAlgorithm::Sha256);
        assert_eq!(fp.value_bytes().len(), 32);

        let sdp = fp.to_sdp_string();
        assert!(sdp.starts_with("sha-256 "));

        let parsed = DtlsFingerprint::from_sdp(&sdp).unwrap();
        assert_eq!(parsed, fp);
    }

    #[test]
    fn test_dtls_parameters() {
        let fp = DtlsFingerprint::sha256("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99").unwrap();
        let params = DtlsParameters::new(DtlsRole::Client)
            .with_fingerprint(fp);
        
        assert_eq!(params.role, DtlsRole::Client);
        assert_eq!(params.fingerprint_count(), 1);
        assert!(params.fingerprint(0).is_some());
        assert!(params.fingerprint(1).is_none());
    }

    #[test]
    fn test_transport_stats() {
        let stats = TransportStats::new();
        stats.bytes_sent.store(1000, Ordering::Relaxed);
        stats.packets_sent.store(10, Ordering::Relaxed);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 1000);
    }
}
