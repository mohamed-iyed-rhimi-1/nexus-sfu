//! TURN types and configuration.
//!
//! Core types for TURN client operations.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{
    CHANNEL_NUMBER_MIN, CHANNEL_NUMBER_MAX,
    MAX_PERMISSIONS, MAX_CHANNEL_BINDINGS,
    PERMISSION_LIFETIME, CHANNEL_BINDING_LIFETIME,
};

// ============================================================================
// Transport Protocol
// ============================================================================

/// Transport protocol for TURN allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    /// UDP (17).
    Udp = 17,
    /// TCP (6).
    Tcp = 6,
}

impl TransportProtocol {
    /// Get protocol number.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
    
    /// Try to create from protocol number.
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            17 => Some(Self::Udp),
            6 => Some(Self::Tcp),
            _ => None,
        }
    }
}

impl Default for TransportProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

// ============================================================================
// Credentials
// ============================================================================

/// TURN server credentials.
///
/// Supports both long-term and short-term credentials.
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    /// Username (max 128 bytes).
    pub username: [u8; 128],
    /// Username length.
    pub username_len: u8,
    /// Password/shared secret (max 128 bytes).
    pub password: [u8; 128],
    /// Password length.
    pub password_len: u8,
    /// Realm (for long-term credentials).
    pub realm: [u8; 128],
    /// Realm length.
    pub realm_len: u8,
}

impl TurnCredentials {
    /// Create new credentials.
    pub fn new(username: &str, password: &str) -> Self {
        let mut creds = Self {
            username: [0u8; 128],
            username_len: 0,
            password: [0u8; 128],
            password_len: 0,
            realm: [0u8; 128],
            realm_len: 0,
        };
        
        let u_len = username.len().min(128);
        let p_len = password.len().min(128);
        
        creds.username[..u_len].copy_from_slice(username.as_bytes());
        creds.username_len = u_len as u8;
        creds.password[..p_len].copy_from_slice(password.as_bytes());
        creds.password_len = p_len as u8;
        
        creds
    }
    
    /// Set realm for long-term credentials.
    pub fn with_realm(mut self, realm: &str) -> Self {
        let len = realm.len().min(128);
        self.realm[..len].copy_from_slice(realm.as_bytes());
        self.realm_len = len as u8;
        self
    }
    
    /// Get username as slice.
    #[inline]
    pub fn username(&self) -> &[u8] {
        &self.username[..self.username_len as usize]
    }
    
    /// Get password as slice.
    #[inline]
    pub fn password(&self) -> &[u8] {
        &self.password[..self.password_len as usize]
    }
    
    /// Get realm as slice.
    #[inline]
    pub fn realm(&self) -> &[u8] {
        &self.realm[..self.realm_len as usize]
    }
    
    /// Check if this uses long-term credentials (has realm).
    #[inline]
    pub fn is_long_term(&self) -> bool {
        self.realm_len > 0
    }
    
    /// Compute key for long-term credentials.
    ///
    /// key = MD5(username ":" realm ":" password)
    pub fn compute_key(&self) -> [u8; 16] {
        use md5::{Md5, Digest};
        
        let mut hasher = Md5::new();
        hasher.update(self.username());
        hasher.update(b":");
        hasher.update(self.realm());
        hasher.update(b":");
        hasher.update(self.password());
        
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result);
        key
    }
}

impl Default for TurnCredentials {
    fn default() -> Self {
        Self {
            username: [0u8; 128],
            username_len: 0,
            password: [0u8; 128],
            password_len: 0,
            realm: [0u8; 128],
            realm_len: 0,
        }
    }
}

// ============================================================================
// Server Info
// ============================================================================

/// TURN server information.
#[derive(Debug, Clone)]
pub struct TurnServerInfo {
    /// Server address.
    pub address: SocketAddr,
    /// Transport protocol to use.
    pub transport: TransportProtocol,
    /// Credentials.
    pub credentials: TurnCredentials,
}

impl TurnServerInfo {
    /// Create new server info.
    pub fn new(address: SocketAddr, credentials: TurnCredentials) -> Self {
        Self {
            address,
            transport: TransportProtocol::Udp,
            credentials,
        }
    }
    
    /// Use TCP transport.
    pub fn with_tcp(mut self) -> Self {
        self.transport = TransportProtocol::Tcp;
        self
    }
}

// ============================================================================
// Relayed Address
// ============================================================================

/// Relayed address obtained from TURN server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayedAddress {
    /// The relay address (on the TURN server).
    pub relay: SocketAddr,
    /// The mapped address (our external address as seen by server).
    pub mapped: SocketAddr,
    /// Allocation lifetime in seconds.
    pub lifetime: u32,
    /// When this address was obtained.
    pub obtained_at: Instant,
}

impl RelayedAddress {
    /// Create new relayed address.
    pub fn new(relay: SocketAddr, mapped: SocketAddr, lifetime: u32) -> Self {
        Self {
            relay,
            mapped,
            lifetime,
            obtained_at: Instant::now(),
        }
    }
    
    /// Check if allocation has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.obtained_at.elapsed() >= Duration::from_secs(self.lifetime as u64)
    }
    
    /// Get remaining lifetime.
    #[inline]
    pub fn remaining_lifetime(&self) -> Duration {
        let elapsed = self.obtained_at.elapsed();
        let total = Duration::from_secs(self.lifetime as u64);
        total.saturating_sub(elapsed)
    }
    
    /// Check if refresh is needed.
    #[inline]
    pub fn needs_refresh(&self, margin_secs: u32) -> bool {
        self.remaining_lifetime() < Duration::from_secs(margin_secs as u64)
    }
}

// ============================================================================
// Permission
// ============================================================================

/// Permission for a peer address.
///
/// Permissions allow traffic from a specific peer IP.
#[derive(Debug, Clone, Copy)]
pub struct Permission {
    /// Peer address (only IP matters, port is ignored).
    pub peer_addr: SocketAddr,
    /// When permission was created.
    pub created_at: Instant,
    /// Permission lifetime.
    pub lifetime: u32,
    /// Whether this permission is active.
    pub active: bool,
}

impl Permission {
    /// Create new permission.
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            created_at: Instant::now(),
            lifetime: PERMISSION_LIFETIME,
            active: true,
        }
    }
    
    /// Check if permission has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(self.lifetime as u64)
    }
    
    /// Refresh permission (reset timer).
    pub fn refresh(&mut self) {
        self.created_at = Instant::now();
    }
    
    /// Get remaining lifetime.
    #[inline]
    pub fn remaining_lifetime(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        let total = Duration::from_secs(self.lifetime as u64);
        total.saturating_sub(elapsed)
    }
}

// ============================================================================
// Channel Binding
// ============================================================================

/// Channel binding for optimized data relay.
///
/// Channel bindings allow using 4-byte ChannelData headers
/// instead of full STUN encapsulation.
#[derive(Debug, Clone, Copy)]
pub struct ChannelBinding {
    /// Channel number (0x4000-0x7FFF).
    pub channel: u16,
    /// Peer address.
    pub peer_addr: SocketAddr,
    /// When binding was created.
    pub created_at: Instant,
    /// Binding lifetime.
    pub lifetime: u32,
    /// Whether this binding is active.
    pub active: bool,
}

impl ChannelBinding {
    /// Create new channel binding.
    pub fn new(channel: u16, peer_addr: SocketAddr) -> Option<Self> {
        if channel < CHANNEL_NUMBER_MIN || channel > CHANNEL_NUMBER_MAX {
            return None;
        }
        
        Some(Self {
            channel,
            peer_addr,
            created_at: Instant::now(),
            lifetime: CHANNEL_BINDING_LIFETIME,
            active: true,
        })
    }
    
    /// Check if channel number is valid.
    #[inline]
    pub const fn is_valid_channel(channel: u16) -> bool {
        channel >= CHANNEL_NUMBER_MIN && channel <= CHANNEL_NUMBER_MAX
    }
    
    /// Check if binding has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(self.lifetime as u64)
    }
    
    /// Refresh binding (reset timer).
    pub fn refresh(&mut self) {
        self.created_at = Instant::now();
    }
    
    /// Get remaining lifetime.
    #[inline]
    pub fn remaining_lifetime(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        let total = Duration::from_secs(self.lifetime as u64);
        total.saturating_sub(elapsed)
    }
}

// ============================================================================
// Permission Table
// ============================================================================

/// Table of active permissions.
#[derive(Debug)]
pub struct PermissionTable {
    /// Permissions array.
    permissions: [Option<Permission>; MAX_PERMISSIONS],
    /// Number of active permissions.
    count: u8,
}

impl PermissionTable {
    /// Create empty permission table.
    pub const fn new() -> Self {
        Self {
            permissions: [None; MAX_PERMISSIONS],
            count: 0,
        }
    }
    
    /// Add or refresh permission.
    pub fn add(&mut self, peer_addr: SocketAddr) -> Result<(), super::TurnError> {
        // Check if already exists
        for perm in self.permissions.iter_mut().flatten() {
            if perm.peer_addr.ip() == peer_addr.ip() {
                perm.refresh();
                return Ok(());
            }
        }
        
        // Find empty slot
        for slot in self.permissions.iter_mut() {
            if slot.is_none() {
                *slot = Some(Permission::new(peer_addr));
                self.count += 1;
                return Ok(());
            }
        }
        
        Err(super::TurnError::MaxPermissionsReached {
            count: self.count as u32,
            max: MAX_PERMISSIONS as u32,
        })
    }
    
    /// Check if permission exists for peer.
    pub fn has_permission(&self, peer_addr: &SocketAddr) -> bool {
        self.permissions.iter().flatten().any(|p| {
            p.active && !p.is_expired() && p.peer_addr.ip() == peer_addr.ip()
        })
    }
    
    /// Remove expired permissions.
    pub fn cleanup_expired(&mut self) -> u8 {
        let mut removed = 0u8;
        for slot in self.permissions.iter_mut() {
            if let Some(perm) = slot {
                if perm.is_expired() {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    removed += 1;
                }
            }
        }
        removed
    }
    
    /// Get permission count.
    #[inline]
    pub const fn count(&self) -> u8 {
        self.count
    }
    
    /// Iterator over active permissions.
    #[allow(dead_code)] // Reserved for permission enumeration in TURN relay
    pub fn iter(&self) -> impl Iterator<Item = &Permission> {
        self.permissions.iter().filter_map(|p| p.as_ref())
    }
}

impl Default for PermissionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Channel Binding Table
// ============================================================================

/// Table of channel bindings.
#[derive(Debug)]
pub struct ChannelBindingTable {
    /// Bindings array.
    bindings: [Option<ChannelBinding>; MAX_CHANNEL_BINDINGS],
    /// Number of active bindings.
    count: u8,
    /// Next channel number to allocate.
    next_channel: u16,
}

impl ChannelBindingTable {
    /// Create empty binding table.
    pub const fn new() -> Self {
        Self {
            bindings: [None; MAX_CHANNEL_BINDINGS],
            count: 0,
            next_channel: CHANNEL_NUMBER_MIN,
        }
    }
    
    /// Allocate next available channel number.
    pub fn allocate_channel(&mut self) -> Option<u16> {
        if self.count as usize >= MAX_CHANNEL_BINDINGS {
            return None;
        }
        
        let channel = self.next_channel;
        self.next_channel = if self.next_channel >= CHANNEL_NUMBER_MAX {
            CHANNEL_NUMBER_MIN
        } else {
            self.next_channel + 1
        };
        
        Some(channel)
    }
    
    /// Add channel binding.
    pub fn add(&mut self, channel: u16, peer_addr: SocketAddr) -> Result<(), super::TurnError> {
        // Validate channel number
        if !ChannelBinding::is_valid_channel(channel) {
            return Err(super::TurnError::InvalidChannelNumber { channel });
        }
        
        // Check if channel already bound
        for binding in self.bindings.iter().flatten() {
            if binding.channel == channel && binding.peer_addr != peer_addr {
                return Err(super::TurnError::ChannelAlreadyBound { channel });
            }
            if binding.peer_addr == peer_addr && binding.channel != channel {
                return Err(super::TurnError::PeerAlreadyBound { 
                    peer: peer_addr, 
                    channel: binding.channel,
                });
            }
        }
        
        // Check if already exists (refresh)
        for binding in self.bindings.iter_mut().flatten() {
            if binding.channel == channel && binding.peer_addr == peer_addr {
                binding.refresh();
                return Ok(());
            }
        }
        
        // Find empty slot
        for slot in self.bindings.iter_mut() {
            if slot.is_none() {
                *slot = ChannelBinding::new(channel, peer_addr);
                self.count += 1;
                return Ok(());
            }
        }
        
        Err(super::TurnError::MaxChannelBindingsReached {
            count: self.count as u32,
            max: MAX_CHANNEL_BINDINGS as u32,
        })
    }
    
    /// Find channel for peer.
    pub fn find_channel(&self, peer_addr: &SocketAddr) -> Option<u16> {
        self.bindings.iter().flatten()
            .find(|b| b.active && !b.is_expired() && b.peer_addr == *peer_addr)
            .map(|b| b.channel)
    }
    
    /// Find peer for channel.
    pub fn find_peer(&self, channel: u16) -> Option<SocketAddr> {
        self.bindings.iter().flatten()
            .find(|b| b.active && !b.is_expired() && b.channel == channel)
            .map(|b| b.peer_addr)
    }
    
    /// Remove expired bindings.
    pub fn cleanup_expired(&mut self) -> u8 {
        let mut removed = 0u8;
        for slot in self.bindings.iter_mut() {
            if let Some(binding) = slot {
                if binding.is_expired() {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    removed += 1;
                }
            }
        }
        removed
    }
    
    /// Get binding count.
    #[inline]
    pub const fn count(&self) -> u8 {
        self.count
    }
    
    /// Iterator over active bindings.
    #[allow(dead_code)] // Reserved for channel binding enumeration in TURN relay
    pub fn iter(&self) -> impl Iterator<Item = &ChannelBinding> {
        self.bindings.iter().filter_map(|b| b.as_ref())
    }
}

impl Default for ChannelBindingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, port as u8)), port)
    }

    #[test]
    fn test_transport_protocol() {
        assert_eq!(TransportProtocol::Udp.as_u8(), 17);
        assert_eq!(TransportProtocol::Tcp.as_u8(), 6);
        assert_eq!(TransportProtocol::from_u8(17), Some(TransportProtocol::Udp));
        assert_eq!(TransportProtocol::from_u8(99), None);
    }

    #[test]
    fn test_credentials() {
        let creds = TurnCredentials::new("user", "pass")
            .with_realm("example.com");
        
        assert_eq!(creds.username(), b"user");
        assert_eq!(creds.password(), b"pass");
        assert_eq!(creds.realm(), b"example.com");
        assert!(creds.is_long_term());
    }

    #[test]
    fn test_credentials_key() {
        let creds = TurnCredentials::new("user", "pass")
            .with_realm("realm");
        
        let key = creds.compute_key();
        assert_eq!(key.len(), 16);
        // MD5("user:realm:pass") - verify it's computed
        assert_ne!(key, [0u8; 16]);
    }

    #[test]
    fn test_permission() {
        let perm = Permission::new(test_addr(5000));
        assert!(!perm.is_expired());
        assert!(perm.active);
    }

    #[test]
    fn test_permission_table() {
        let mut table = PermissionTable::new();
        
        table.add(test_addr(5000)).unwrap();
        table.add(test_addr(5001)).unwrap();
        
        assert_eq!(table.count(), 2);
        assert!(table.has_permission(&test_addr(5000)));
        assert!(table.has_permission(&test_addr(5001)));
        assert!(!table.has_permission(&test_addr(5002)));
    }

    #[test]
    fn test_permission_table_refresh() {
        let mut table = PermissionTable::new();
        
        table.add(test_addr(5000)).unwrap();
        assert_eq!(table.count(), 1);
        
        // Adding same IP should refresh, not add new
        table.add(test_addr(5000)).unwrap();
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn test_channel_binding() {
        let binding = ChannelBinding::new(0x4000, test_addr(5000)).unwrap();
        assert_eq!(binding.channel, 0x4000);
        assert!(!binding.is_expired());
        
        // Invalid channel
        assert!(ChannelBinding::new(0x1000, test_addr(5000)).is_none());
        assert!(ChannelBinding::new(0x8000, test_addr(5000)).is_none());
    }

    #[test]
    fn test_channel_binding_table() {
        let mut table = ChannelBindingTable::new();
        
        let channel = table.allocate_channel().unwrap();
        assert_eq!(channel, CHANNEL_NUMBER_MIN);
        
        table.add(channel, test_addr(5000)).unwrap();
        
        assert_eq!(table.find_channel(&test_addr(5000)), Some(channel));
        assert_eq!(table.find_peer(channel), Some(test_addr(5000)));
    }

    #[test]
    fn test_channel_binding_conflicts() {
        let mut table = ChannelBindingTable::new();
        
        table.add(0x4000, test_addr(5000)).unwrap();
        
        // Same channel, different peer - should fail
        let err = table.add(0x4000, test_addr(5001)).unwrap_err();
        assert!(matches!(err, super::super::TurnError::ChannelAlreadyBound { .. }));
        
        // Same peer, different channel - should fail
        let err = table.add(0x4001, test_addr(5000)).unwrap_err();
        assert!(matches!(err, super::super::TurnError::PeerAlreadyBound { .. }));
    }

    #[test]
    fn test_relayed_address() {
        let relay = test_addr(3478);
        let mapped = test_addr(12345);
        
        let addr = RelayedAddress::new(relay, mapped, 600);
        assert_eq!(addr.relay, relay);
        assert_eq!(addr.mapped, mapped);
        assert!(!addr.is_expired());
        assert!(!addr.needs_refresh(60));
    }
}
