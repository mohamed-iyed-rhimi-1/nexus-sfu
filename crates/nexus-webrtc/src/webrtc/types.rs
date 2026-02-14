//! WebRTC transport types.

use core::fmt;

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

/// Media type for the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Application data (DataChannel).
    Application,
}

/// ICE parameters for transport setup.
#[derive(Debug, Clone)]
pub struct IceParameters {
    /// ICE username fragment.
    pub username_fragment: String,
    /// ICE password.
    pub password: String,
}

impl IceParameters {
    /// Create new ICE parameters.
    pub fn new(ufrag: impl Into<String>, pwd: impl Into<String>) -> Self {
        Self {
            username_fragment: ufrag.into(),
            password: pwd.into(),
        }
    }
}

/// DTLS fingerprint for certificate verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsFingerprint {
    /// Hash algorithm (e.g., "sha-256").
    pub algorithm: String,
    /// Fingerprint value (hex-encoded).
    pub value: String,
}

impl DtlsFingerprint {
    /// Create SHA-256 fingerprint.
    pub fn sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: "sha-256".to_string(),
            value: value.into(),
        }
    }
    
    /// Parse from SDP format (e.g., "sha-256 AB:CD:EF:...").
    pub fn from_sdp(s: &str) -> Option<Self> {
        let mut parts = s.splitn(2, ' ');
        let algorithm = parts.next()?.to_lowercase();
        let value = parts.next()?.to_uppercase();
        Some(Self { algorithm, value })
    }
    
    /// Format for SDP.
    pub fn to_sdp(&self) -> String {
        format!("{} {}", self.algorithm, self.value)
    }
}

/// DTLS parameters for transport setup.
#[derive(Debug, Clone)]
pub struct DtlsParameters {
    /// DTLS role (client/server/auto).
    pub role: DtlsRole,
    /// Certificate fingerprints.
    pub fingerprints: Vec<DtlsFingerprint>,
}

impl DtlsParameters {
    /// Create new DTLS parameters.
    pub fn new(role: DtlsRole) -> Self {
        Self {
            role,
            fingerprints: Vec::new(),
        }
    }
    
    /// Add fingerprint.
    pub fn with_fingerprint(mut self, fp: DtlsFingerprint) -> Self {
        self.fingerprints.push(fp);
        self
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
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportStats {
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// RTP packets sent.
    pub rtp_packets_sent: u64,
    /// RTP packets received.
    pub rtp_packets_received: u64,
    /// RTCP packets sent.
    pub rtcp_packets_sent: u64,
    /// RTCP packets received.
    pub rtcp_packets_received: u64,
    /// SRTP authentication failures.
    pub srtp_auth_failures: u64,
    /// Replay attacks detected.
    pub replay_attacks: u64,
    /// ICE candidate pairs checked.
    pub ice_pairs_checked: u64,
    /// STUN requests sent.
    pub stun_requests_sent: u64,
    /// STUN responses received.
    pub stun_responses_received: u64,
}

impl TransportStats {
    /// Create empty stats.
    pub const fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            rtp_packets_sent: 0,
            rtp_packets_received: 0,
            rtcp_packets_sent: 0,
            rtcp_packets_received: 0,
            srtp_auth_failures: 0,
            replay_attacks: 0,
            ice_pairs_checked: 0,
            stun_requests_sent: 0,
            stun_responses_received: 0,
        }
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
        assert_eq!(params.username_fragment, "user");
        assert_eq!(params.password, "pass");
    }

    #[test]
    fn test_dtls_fingerprint() {
        let fp = DtlsFingerprint::sha256("AB:CD:EF:12:34");
        assert_eq!(fp.algorithm, "sha-256");
        assert_eq!(fp.value, "AB:CD:EF:12:34");
        
        let sdp = fp.to_sdp();
        assert_eq!(sdp, "sha-256 AB:CD:EF:12:34");
        
        let parsed = DtlsFingerprint::from_sdp(&sdp).unwrap();
        assert_eq!(parsed, fp);
    }

    #[test]
    fn test_dtls_parameters() {
        let params = DtlsParameters::new(DtlsRole::Client)
            .with_fingerprint(DtlsFingerprint::sha256("AA:BB:CC"));
        
        assert_eq!(params.role, DtlsRole::Client);
        assert_eq!(params.fingerprints.len(), 1);
    }

    #[test]
    fn test_transport_stats() {
        let mut stats = TransportStats::new();
        stats.bytes_sent = 1000;
        stats.packets_sent = 10;
        assert_eq!(stats.bytes_sent, 1000);
    }
}
