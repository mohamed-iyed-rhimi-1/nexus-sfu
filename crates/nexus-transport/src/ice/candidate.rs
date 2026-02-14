//! ICE Candidate Types and Priority Calculation.
//!
//! Implements RFC 8445 candidate representation and priority formula.
//!
//! # Candidate Types
//!
//! - Host: Local interface address
//! - Server Reflexive: NAT-mapped address (via STUN)
//! - Peer Reflexive: Discovered during connectivity checks
//! - Relay: TURN-allocated address
//!
//! # Priority Calculation (RFC 8445)
//!
//! ```text
//! priority = (2^24) * type_preference +
//!            (2^8)  * local_preference +
//!            (2^0)  * (256 - component_id)
//! ```

use std::net::{IpAddr, SocketAddr};
use std::fmt;

use crate::ice::error::IceError;

/// Candidate type preferences (RFC 8445 Section 5.1.2.2).
pub const TYPE_PREF_HOST: u32 = 126;
pub const TYPE_PREF_PEER_REFLEXIVE: u32 = 110;
pub const TYPE_PREF_SERVER_REFLEXIVE: u32 = 100;
pub const TYPE_PREF_RELAY: u32 = 0;

/// Maximum candidates per gathering.
pub const MAX_CANDIDATES: usize = 32;

/// ICE Candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CandidateType {
    /// Local interface address.
    Host = 0,
    
    /// NAT-mapped address discovered via STUN.
    ServerReflexive = 1,
    
    /// Address discovered during connectivity checks.
    PeerReflexive = 2,
    
    /// TURN relay address.
    Relay = 3,
}

impl CandidateType {
    /// Get type preference value (RFC 8445).
    pub const fn type_preference(self) -> u32 {
        match self {
            Self::Host => TYPE_PREF_HOST,
            Self::PeerReflexive => TYPE_PREF_PEER_REFLEXIVE,
            Self::ServerReflexive => TYPE_PREF_SERVER_REFLEXIVE,
            Self::Relay => TYPE_PREF_RELAY,
        }
    }
    
    /// Parse from SDP string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::ServerReflexive),
            "prflx" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
    
    /// Convert to SDP string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Transport protocol for ICE candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    /// UDP transport.
    Udp = 0,
    
    /// TCP transport (RFC 6544).
    Tcp = 1,
}

impl TransportProtocol {
    /// Parse from SDP string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
    
    /// Convert to SDP string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// ICE Candidate.
///
/// Zero-allocation representation of an ICE candidate.
/// Uses fixed-size fields throughout.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Unique identifier (foundation in SDP).
    /// Format: type + base_addr hash.
    pub foundation: u32,
    
    /// Component ID (1 = RTP, 2 = RTCP).
    pub component: u8,
    
    /// Transport protocol.
    pub transport: TransportProtocol,
    
    /// Priority value (RFC 8445 formula).
    pub priority: u32,
    
    /// Candidate address.
    pub address: SocketAddr,
    
    /// Candidate type.
    pub candidate_type: CandidateType,
    
    /// Related address (for srflx/prflx/relay - the base address).
    pub related_address: Option<SocketAddr>,
    
    /// TCP type (only for TCP candidates).
    pub tcp_type: Option<TcpType>,
    
    /// Local interface index (for internal tracking).
    pub interface_idx: u8,
    
    /// Whether this candidate has been nominated.
    pub nominated: bool,
}

/// TCP candidate type (RFC 6544).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TcpType {
    /// Active - will initiate connection.
    Active = 0,
    
    /// Passive - will accept connection.
    Passive = 1,
    
    /// Simultaneous open.
    SimultaneousOpen = 2,
}

impl TcpType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::SimultaneousOpen => "so",
        }
    }
}

impl Candidate {
    /// Create a new host candidate.
    ///
    /// # Arguments
    ///
    /// * `address` - Local interface address.
    /// * `component` - Component ID (1 = RTP, 2 = RTCP).
    /// * `interface_idx` - Interface index for foundation calculation.
    pub fn new_host(
        address: SocketAddr,
        component: u8,
        interface_idx: u8,
    ) -> Self {
        assert!(component >= 1, "component must be >= 1");
        
        let priority = Self::calculate_priority(
            CandidateType::Host,
            Self::local_preference(&address, interface_idx),
            component,
        );
        
        let foundation = Self::compute_foundation(
            CandidateType::Host,
            address,
            TransportProtocol::Udp,
        );
        
        Self {
            foundation,
            component,
            transport: TransportProtocol::Udp,
            priority,
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
            tcp_type: None,
            interface_idx,
            nominated: false,
        }
    }
    
    /// Create a server reflexive candidate.
    ///
    /// # Arguments
    ///
    /// * `address` - Public (NAT-mapped) address from STUN.
    /// * `base_address` - Local address used to reach STUN server.
    /// * `component` - Component ID.
    /// * `interface_idx` - Interface index.
    pub fn new_server_reflexive(
        address: SocketAddr,
        base_address: SocketAddr,
        component: u8,
        interface_idx: u8,
    ) -> Self {
        assert!(component >= 1, "component must be >= 1");
        
        let priority = Self::calculate_priority(
            CandidateType::ServerReflexive,
            Self::local_preference(&base_address, interface_idx),
            component,
        );
        
        let foundation = Self::compute_foundation(
            CandidateType::ServerReflexive,
            base_address,
            TransportProtocol::Udp,
        );
        
        Self {
            foundation,
            component,
            transport: TransportProtocol::Udp,
            priority,
            address,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(base_address),
            tcp_type: None,
            interface_idx,
            nominated: false,
        }
    }
    
    /// Create a peer reflexive candidate.
    ///
    /// Discovered during connectivity checks when the source address
    /// in a STUN response differs from any known candidate.
    pub fn new_peer_reflexive(
        address: SocketAddr,
        base_address: SocketAddr,
        priority: u32,
        component: u8,
        interface_idx: u8,
    ) -> Self {
        let foundation = Self::compute_foundation(
            CandidateType::PeerReflexive,
            base_address,
            TransportProtocol::Udp,
        );
        
        Self {
            foundation,
            component,
            transport: TransportProtocol::Udp,
            priority,
            address,
            candidate_type: CandidateType::PeerReflexive,
            related_address: Some(base_address),
            tcp_type: None,
            interface_idx,
            nominated: false,
        }
    }
    
    /// Create a relay candidate.
    ///
    /// # Arguments
    ///
    /// * `address` - TURN server allocated address.
    /// * `server_address` - TURN server address.
    /// * `component` - Component ID.
    /// * `interface_idx` - Interface index.
    pub fn new_relay(
        address: SocketAddr,
        server_address: SocketAddr,
        component: u8,
        interface_idx: u8,
    ) -> Self {
        assert!(component >= 1, "component must be >= 1");
        
        let priority = Self::calculate_priority(
            CandidateType::Relay,
            Self::local_preference(&server_address, interface_idx),
            component,
        );
        
        let foundation = Self::compute_foundation(
            CandidateType::Relay,
            server_address,
            TransportProtocol::Udp,
        );
        
        Self {
            foundation,
            component,
            transport: TransportProtocol::Udp,
            priority,
            address,
            candidate_type: CandidateType::Relay,
            related_address: Some(server_address),
            tcp_type: None,
            interface_idx,
            nominated: false,
        }
    }
    
    /// Calculate priority per RFC 8445.
    ///
    /// ```text
    /// priority = (2^24) * type_preference +
    ///            (2^8)  * local_preference +
    ///            (2^0)  * (256 - component_id)
    /// ```
    pub fn calculate_priority(
        candidate_type: CandidateType,
        local_pref: u32,
        component: u8,
    ) -> u32 {
        assert!(local_pref <= 65535, "local_pref must fit in 16 bits");
        assert!(component >= 1, "component must be >= 1");
        
        let type_pref = candidate_type.type_preference();
        
        (type_pref << 24) | ((local_pref & 0xFFFF) << 8) | (256 - component as u32)
    }
    
    /// Calculate local preference.
    ///
    /// Prefers IPv6 over IPv4, and uses interface index for tie-breaking.
    fn local_preference(address: &SocketAddr, interface_idx: u8) -> u32 {
        let ip_pref: u32 = match address.ip() {
            IpAddr::V6(_) => 65535,
            IpAddr::V4(_) => 65534 - (interface_idx as u32 * 256),
        };
        
        ip_pref.min(65535)
    }
    
    /// Compute foundation hash.
    ///
    /// Foundation is the same for candidates that share:
    /// - Same type
    /// - Same base address
    /// - Same transport protocol
    fn compute_foundation(
        candidate_type: CandidateType,
        base_address: SocketAddr,
        transport: TransportProtocol,
    ) -> u32 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        (candidate_type as u8).hash(&mut hasher);
        
        match base_address.ip() {
            IpAddr::V4(ip) => ip.octets().hash(&mut hasher),
            IpAddr::V6(ip) => ip.octets().hash(&mut hasher),
        }
        
        (transport as u8).hash(&mut hasher);
        
        hasher.finish() as u32
    }
    
    /// Check if this is a host candidate.
    pub const fn is_host(&self) -> bool {
        matches!(self.candidate_type, CandidateType::Host)
    }
    
    /// Check if this is a server reflexive candidate.
    pub const fn is_server_reflexive(&self) -> bool {
        matches!(self.candidate_type, CandidateType::ServerReflexive)
    }
    
    /// Check if this is a relay candidate.
    pub const fn is_relay(&self) -> bool {
        matches!(self.candidate_type, CandidateType::Relay)
    }
    
    /// Get the base address for this candidate.
    ///
    /// For host candidates, this is the candidate address.
    /// For others, it's the related address.
    pub fn base_address(&self) -> SocketAddr {
        self.related_address.unwrap_or(self.address)
    }
    
    /// Format as SDP candidate attribute.
    ///
    /// Format: `candidate:foundation component transport priority address port typ type [raddr address rport port]`
    pub fn to_sdp(&self, ufrag: &str) -> String {
        let mut sdp = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type,
        );
        
        if let Some(ref related) = self.related_address {
            sdp.push_str(&format!(" raddr {} rport {}", related.ip(), related.port()));
        }
        
        if let Some(tcp_type) = self.tcp_type {
            sdp.push_str(&format!(" tcptype {}", tcp_type.as_str()));
        }
        
        sdp.push_str(&format!(" ufrag {}", ufrag));
        
        sdp
    }
    
    /// Format as SDP candidate attribute string (without ufrag).
    ///
    /// Format: `candidate:foundation component transport priority address port typ type [raddr address rport port]`
    ///
    /// This is a convenience method that omits the ufrag parameter.
    /// Use `to_sdp()` if you need to include the ufrag.
    pub fn to_sdp_string(&self) -> String {
        let mut sdp = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type,
        );
        
        if let Some(ref related) = self.related_address {
            sdp.push_str(&format!(" raddr {} rport {}", related.ip(), related.port()));
        }
        
        if let Some(tcp_type) = self.tcp_type {
            sdp.push_str(&format!(" tcptype {}", tcp_type.as_str()));
        }
        
        sdp
    }
    
    /// Parse candidate from SDP line.
    pub fn from_sdp(sdp: &str) -> Result<Self, IceError> {
        // Remove "candidate:" or "a=candidate:" prefix
        let line = sdp
            .strip_prefix("a=candidate:")
            .or_else(|| sdp.strip_prefix("candidate:"))
            .unwrap_or(sdp);
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() < 8 {
            return Err(IceError::InvalidCandidate {
                reason: "insufficient parts in SDP",
            });
        }
        
        let foundation: u32 = parts[0].parse().map_err(|_| IceError::InvalidCandidate {
            reason: "invalid foundation",
        })?;
        
        let component: u8 = parts[1].parse().map_err(|_| IceError::InvalidCandidate {
            reason: "invalid component",
        })?;
        
        let transport = TransportProtocol::from_str(parts[2]).ok_or(IceError::InvalidCandidate {
            reason: "invalid transport",
        })?;
        
        let priority: u32 = parts[3].parse().map_err(|_| IceError::InvalidCandidate {
            reason: "invalid priority",
        })?;
        
        let ip: IpAddr = parts[4].parse().map_err(|_| IceError::InvalidCandidate {
            reason: "invalid IP address",
        })?;
        
        let port: u16 = parts[5].parse().map_err(|_| IceError::InvalidCandidate {
            reason: "invalid port",
        })?;
        
        // parts[6] should be "typ"
        if parts[6] != "typ" {
            return Err(IceError::InvalidCandidate {
                reason: "expected 'typ'",
            });
        }
        
        let candidate_type = CandidateType::from_str(parts[7]).ok_or(IceError::InvalidCandidate {
            reason: "invalid candidate type",
        })?;
        
        // Parse optional attributes
        let mut related_address = None;
        let mut tcp_type = None;
        let mut i = 8;
        
        while i < parts.len() {
            match parts[i] {
                "raddr" if i + 1 < parts.len() => {
                    let raddr: IpAddr = parts[i + 1].parse().map_err(|_| IceError::InvalidCandidate {
                        reason: "invalid raddr",
                    })?;
                    
                    // Look for rport
                    if i + 3 < parts.len() && parts[i + 2] == "rport" {
                        let rport: u16 = parts[i + 3].parse().map_err(|_| IceError::InvalidCandidate {
                            reason: "invalid rport",
                        })?;
                        related_address = Some(SocketAddr::new(raddr, rport));
                        i += 4;
                    } else {
                        i += 2;
                    }
                }
                "tcptype" if i + 1 < parts.len() => {
                    tcp_type = match parts[i + 1] {
                        "active" => Some(TcpType::Active),
                        "passive" => Some(TcpType::Passive),
                        "so" => Some(TcpType::SimultaneousOpen),
                        _ => None,
                    };
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
        
        Ok(Self {
            foundation,
            component,
            transport,
            priority,
            address: SocketAddr::new(ip, port),
            candidate_type,
            related_address,
            tcp_type,
            interface_idx: 0,
            nominated: false,
        })
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address &&
        self.candidate_type == other.candidate_type &&
        self.component == other.component
    }
}

impl Eq for Candidate {}

impl std::hash::Hash for Candidate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.candidate_type.hash(state);
        self.component.hash(state);
    }
}

/// Candidate pair for connectivity checks.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate.
    pub local: Candidate,

    /// Remote candidate.
    pub remote: Candidate,

    /// Pair priority (for sorting checklist).
    pub priority: u64,

    /// Pair state.
    pub state: CandidatePairState,

    /// Whether this pair has been nominated.
    pub nominated: bool,

    /// Set when USE-CANDIDATE received but pair not yet Succeeded.
    pub pending_nomination: bool,
}

/// State of a candidate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CandidatePairState {
    /// Waiting to be checked.
    Frozen = 0,
    
    /// Waiting for check to be performed.
    Waiting = 1,
    
    /// Check in progress.
    InProgress = 2,
    
    /// Check succeeded.
    Succeeded = 3,
    
    /// Check failed.
    Failed = 4,
}

impl CandidatePair {
    /// Create a new candidate pair.
    pub fn new(local: Candidate, remote: Candidate, is_controlling: bool) -> Self {
        let priority = Self::calculate_priority(
            local.priority,
            remote.priority,
            is_controlling,
        );
        
        Self {
            local,
            remote,
            priority,
            state: CandidatePairState::Frozen,
            nominated: false,
            pending_nomination: false,
        }
    }
    
    /// Calculate pair priority (RFC 8445 Section 6.1.2.3).
    ///
    /// ```text
    /// pair_priority = 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)
    /// ```
    ///
    /// Where G = controlling priority, D = controlled priority.
    pub fn calculate_priority(local_priority: u32, remote_priority: u32, is_controlling: bool) -> u64 {
        let (g, d) = if is_controlling {
            (local_priority as u64, remote_priority as u64)
        } else {
            (remote_priority as u64, local_priority as u64)
        };
        
        let min = g.min(d);
        let max = g.max(d);
        
        (1u64 << 32) * min + 2 * max + if g > d { 1 } else { 0 }
    }
    
    /// Check if pair is succeeded.
    pub const fn is_succeeded(&self) -> bool {
        matches!(self.state, CandidatePairState::Succeeded)
    }
    
    /// Check if pair is failed.
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, CandidatePairState::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_candidate_priority() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        
        // Priority should use host type preference (126)
        assert!(candidate.priority > 0);
        assert_eq!(candidate.candidate_type, CandidateType::Host);
        
        // For component 1, the low 8 bits should be 255 (256 - 1)
        assert_eq!(candidate.priority & 0xFF, 255);
    }

    #[test]
    fn test_priority_formula() {
        // Test the RFC 8445 formula
        let priority = Candidate::calculate_priority(CandidateType::Host, 65535, 1);
        
        // Expected: (126 << 24) | (65535 << 8) | 255
        let expected = (126u32 << 24) | (65535u32 << 8) | 255;
        assert_eq!(priority, expected);
    }

    #[test]
    fn test_srflx_candidate() {
        let public: SocketAddr = "203.0.113.5:54321".parse().unwrap();
        let base: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        
        let candidate = Candidate::new_server_reflexive(public, base, 1, 0);
        
        assert_eq!(candidate.address, public);
        assert_eq!(candidate.related_address, Some(base));
        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
    }

    #[test]
    fn test_sdp_roundtrip() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        
        let sdp = candidate.to_sdp("testufrag");
        let parsed = Candidate::from_sdp(&sdp).unwrap();
        
        assert_eq!(parsed.address, candidate.address);
        assert_eq!(parsed.component, candidate.component);
        assert_eq!(parsed.candidate_type, candidate.candidate_type);
        assert_eq!(parsed.priority, candidate.priority);
    }

    #[test]
    fn test_pair_priority() {
        let local_priority = 2130706431u32; // Host with high local pref
        let remote_priority = 1694498815u32; // Srflx with lower pref
        
        let pair_priority = CandidatePair::calculate_priority(
            local_priority,
            remote_priority,
            true, // controlling
        );
        
        // G = local (controlling), D = remote
        // pair = 2^32 * min + 2 * max + (G > D ? 1 : 0)
        let expected = (1u64 << 32) * (remote_priority as u64) + 
                       2 * (local_priority as u64) + 1;
        assert_eq!(pair_priority, expected);
    }

    #[test]
    fn test_candidate_type_preference_ordering() {
        // Host should have highest preference
        assert!(CandidateType::Host.type_preference() > CandidateType::PeerReflexive.type_preference());
        assert!(CandidateType::PeerReflexive.type_preference() > CandidateType::ServerReflexive.type_preference());
        assert!(CandidateType::ServerReflexive.type_preference() > CandidateType::Relay.type_preference());
    }
}
