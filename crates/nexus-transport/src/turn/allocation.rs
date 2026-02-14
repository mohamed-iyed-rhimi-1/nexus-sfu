//! TURN Allocation management.
//!
//! Manages the lifecycle of TURN allocations including
//! creation, refresh, and permissions.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::error::TurnError;
use super::types::{
    ChannelBindingTable, PermissionTable, RelayedAddress,
    TurnCredentials, TurnServerInfo,
};
use super::{
    DEFAULT_ALLOCATION_LIFETIME,
    REFRESH_MARGIN_SECONDS,
};

// ============================================================================
// Allocation State
// ============================================================================

/// TURN allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AllocationState {
    /// Initial state, not allocated.
    New = 0,
    
    /// Allocation request sent, waiting for response.
    Allocating = 1,
    
    /// Authentication required (401 received).
    NeedsAuth = 2,
    
    /// Successfully allocated.
    Allocated = 3,
    
    /// Refreshing allocation.
    Refreshing = 4,
    
    /// Allocation failed.
    Failed = 5,
    
    /// Allocation expired or released.
    Expired = 6,
}

impl AllocationState {
    /// Returns true if allocation is active.
    #[inline]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Allocated | Self::Refreshing)
    }
    
    /// Returns true if allocation can send data.
    #[inline]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Allocated)
    }
    
    /// Returns true if this is a terminal state.
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Expired)
    }
}

// ============================================================================
// Pending Transaction
// ============================================================================

/// Type of pending transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// Allocate request.
    Allocate,
    /// Refresh request.
    Refresh,
    /// CreatePermission request.
    CreatePermission,
    /// ChannelBind request.
    ChannelBind,
}

/// Pending TURN transaction.
#[derive(Debug)]
pub struct PendingTransaction {
    /// Transaction ID.
    pub transaction_id: [u8; 12],
    /// Transaction type.
    pub transaction_type: TransactionType,
    /// When request was sent.
    pub sent_at: Instant,
    /// Number of retries.
    pub retries: u8,
    /// Maximum retries.
    pub max_retries: u8,
    /// Retry timeout.
    pub timeout: Duration,
    /// Peer address (for CreatePermission and ChannelBind transactions).
    pub peer_addr: Option<SocketAddr>,
    /// Channel number (for ChannelBind transactions).
    pub channel: Option<u16>,
}

impl PendingTransaction {
    /// Create new pending transaction.
    pub fn new(
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
    ) -> Self {
        Self {
            transaction_id,
            transaction_type,
            sent_at: Instant::now(),
            retries: 0,
            max_retries: 7,
            timeout: Duration::from_millis(500),
            peer_addr: None,
            channel: None,
        }
    }
    
    /// Create new pending transaction with peer address.
    pub fn with_peer(
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            transaction_id,
            transaction_type,
            sent_at: Instant::now(),
            retries: 0,
            max_retries: 7,
            timeout: Duration::from_millis(500),
            peer_addr: Some(peer_addr),
            channel: None,
        }
    }
    
    /// Create new pending transaction with peer address and channel.
    pub fn with_channel(
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
        peer_addr: SocketAddr,
        channel: u16,
    ) -> Self {
        Self {
            transaction_id,
            transaction_type,
            sent_at: Instant::now(),
            retries: 0,
            max_retries: 7,
            timeout: Duration::from_millis(500),
            peer_addr: Some(peer_addr),
            channel: Some(channel),
        }
    }
    
    /// Check if transaction has timed out.
    #[inline]
    pub fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() > self.timeout * (self.retries as u32 + 1)
    }
    
    /// Check if should retry.
    #[inline]
    pub fn should_retry(&self) -> bool {
        self.is_timed_out() && self.retries < self.max_retries
    }
    
    /// Increment retry count.
    pub fn retry(&mut self) {
        self.retries += 1;
        self.sent_at = Instant::now();
    }
}

// ============================================================================
// Allocation
// ============================================================================

/// Maximum pending transactions.
const MAX_PENDING_TRANSACTIONS: usize = 8;

/// TURN Allocation.
///
/// Represents a single TURN allocation with its associated
/// permissions and channel bindings.
pub struct Allocation {
    /// TURN server info.
    server: TurnServerInfo,
    
    /// Current state.
    state: AllocationState,
    
    /// Relayed address (when allocated).
    relayed: Option<RelayedAddress>,
    
    /// Permission table.
    permissions: PermissionTable,
    
    /// Channel binding table.
    channels: ChannelBindingTable,
    
    /// Pending transactions.
    pending: [Option<PendingTransaction>; MAX_PENDING_TRANSACTIONS],
    
    /// Number of pending transactions.
    pending_count: u8,
    
    /// Current nonce from server.
    nonce: [u8; 128],
    
    /// Nonce length.
    nonce_len: u8,
    
    /// Realm from server.
    realm: [u8; 128],
    
    /// Realm length.
    realm_len: u8,
    
    /// Requested lifetime.
    #[allow(dead_code)] // Reserved for allocation refresh logic
    requested_lifetime: u32,
    
    /// Creation time.
    #[allow(dead_code)] // Reserved for allocation expiry tracking
    created_at: Instant,
    
    /// Last activity.
    last_activity: Instant,
    
    /// Statistics: packets relayed.
    packets_relayed: u64,
    
    /// Statistics: bytes relayed.
    bytes_relayed: u64,
}

impl Allocation {
    /// Create new allocation.
    pub fn new(server: TurnServerInfo) -> Self {
        Self {
            server,
            state: AllocationState::New,
            relayed: None,
            permissions: PermissionTable::new(),
            channels: ChannelBindingTable::new(),
            pending: std::array::from_fn(|_| None),
            pending_count: 0,
            nonce: [0u8; 128],
            nonce_len: 0,
            realm: [0u8; 128],
            realm_len: 0,
            requested_lifetime: DEFAULT_ALLOCATION_LIFETIME,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            packets_relayed: 0,
            bytes_relayed: 0,
        }
    }
    
    /// Get current state.
    #[inline]
    pub const fn state(&self) -> AllocationState {
        self.state
    }
    
    /// Get server address.
    #[inline]
    pub fn server_addr(&self) -> SocketAddr {
        self.server.address
    }
    
    /// Get relayed address.
    #[inline]
    pub fn relayed_address(&self) -> Option<&RelayedAddress> {
        self.relayed.as_ref()
    }
    
    /// Get relay address (convenience).
    #[inline]
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.relayed.as_ref().map(|r| r.relay)
    }
    
    /// Get credentials.
    #[inline]
    pub fn credentials(&self) -> &TurnCredentials {
        &self.server.credentials
    }
    
    /// Get current nonce.
    #[inline]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce[..self.nonce_len as usize]
    }
    
    /// Get current realm.
    #[inline]
    pub fn realm(&self) -> &[u8] {
        &self.realm[..self.realm_len as usize]
    }
    
    /// Set nonce from server response.
    pub fn set_nonce(&mut self, nonce: &[u8]) {
        let len = nonce.len().min(128);
        self.nonce[..len].copy_from_slice(&nonce[..len]);
        self.nonce_len = len as u8;
    }
    
    /// Set realm from server response.
    pub fn set_realm(&mut self, realm: &[u8]) {
        let len = realm.len().min(128);
        self.realm[..len].copy_from_slice(&realm[..len]);
        self.realm_len = len as u8;
    }
    
    /// Set state.
    pub fn set_state(&mut self, state: AllocationState) {
        self.state = state;
        self.last_activity = Instant::now();
    }
    
    /// Set relayed address.
    pub fn set_relayed(&mut self, relay: SocketAddr, mapped: SocketAddr, lifetime: u32) {
        self.relayed = Some(RelayedAddress::new(relay, mapped, lifetime));
        self.state = AllocationState::Allocated;
        self.last_activity = Instant::now();
    }
    
    /// Refresh relayed address (update lifetime).
    pub fn refresh_relayed(&mut self, lifetime: u32) {
        if let Some(ref mut relayed) = self.relayed {
            relayed.lifetime = lifetime;
            relayed.obtained_at = Instant::now();
        }
        self.state = AllocationState::Allocated;
        self.last_activity = Instant::now();
    }
    
    /// Check if allocation needs refresh.
    pub fn needs_refresh(&self) -> bool {
        match &self.relayed {
            Some(r) => r.needs_refresh(REFRESH_MARGIN_SECONDS),
            None => false,
        }
    }
    
    /// Check if allocation has expired.
    pub fn is_expired(&self) -> bool {
        match &self.relayed {
            Some(r) => r.is_expired(),
            None => self.state.is_terminal(),
        }
    }
    
    // ========== Permission Management ==========
    
    /// Add permission for peer.
    pub fn add_permission(&mut self, peer: SocketAddr) -> Result<(), TurnError> {
        if !self.state.is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        self.permissions.add(peer)
    }
    
    /// Check if permission exists for peer.
    pub fn has_permission(&self, peer: &SocketAddr) -> bool {
        self.permissions.has_permission(peer)
    }
    
    /// Get permission count.
    #[inline]
    pub fn permission_count(&self) -> u8 {
        self.permissions.count()
    }
    
    // ========== Channel Binding Management ==========
    
    /// Allocate channel number.
    pub fn allocate_channel(&mut self) -> Result<u16, TurnError> {
        if !self.state.is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        
        self.channels.allocate_channel()
            .ok_or(TurnError::MaxChannelBindingsReached {
                count: self.channels.count() as u32,
                max: super::MAX_CHANNEL_BINDINGS as u32,
            })
    }
    
    /// Add channel binding.
    pub fn add_channel_binding(&mut self, channel: u16, peer: SocketAddr) -> Result<(), TurnError> {
        if !self.state.is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        self.channels.add(channel, peer)
    }
    
    /// Find channel for peer.
    pub fn find_channel(&self, peer: &SocketAddr) -> Option<u16> {
        self.channels.find_channel(peer)
    }
    
    /// Find peer for channel.
    pub fn find_peer(&self, channel: u16) -> Option<SocketAddr> {
        self.channels.find_peer(channel)
    }
    
    /// Get channel binding count.
    #[inline]
    pub fn channel_count(&self) -> u8 {
        self.channels.count()
    }
    
    // ========== Transaction Management ==========
    
    /// Add pending transaction.
    pub fn add_transaction(
        &mut self,
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
    ) -> Result<(), TurnError> {
        // Find empty slot
        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(PendingTransaction::new(transaction_id, transaction_type));
                self.pending_count += 1;
                return Ok(());
            }
        }
        
        Err(TurnError::AllocationFailed {
            reason: "too many pending transactions",
        })
    }
    
    /// Add pending transaction with peer address (for CreatePermission).
    pub fn add_transaction_with_peer(
        &mut self,
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
        peer_addr: SocketAddr,
    ) -> Result<(), TurnError> {
        // Precondition: transaction type should be CreatePermission or ChannelBind
        assert!(
            transaction_type == TransactionType::CreatePermission 
            || transaction_type == TransactionType::ChannelBind,
            "peer address only valid for CreatePermission or ChannelBind"
        );
        
        // Find empty slot
        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(PendingTransaction::with_peer(transaction_id, transaction_type, peer_addr));
                self.pending_count += 1;
                return Ok(());
            }
        }
        
        Err(TurnError::AllocationFailed {
            reason: "too many pending transactions",
        })
    }
    
    /// Add pending transaction with peer address and channel (for ChannelBind).
    pub fn add_transaction_with_channel(
        &mut self,
        transaction_id: [u8; 12],
        transaction_type: TransactionType,
        peer_addr: SocketAddr,
        channel: u16,
    ) -> Result<(), TurnError> {
        // Precondition: transaction type should be ChannelBind
        assert!(
            transaction_type == TransactionType::ChannelBind,
            "channel only valid for ChannelBind"
        );
        
        // Find empty slot
        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(PendingTransaction::with_channel(transaction_id, transaction_type, peer_addr, channel));
                self.pending_count += 1;
                return Ok(());
            }
        }
        
        Err(TurnError::AllocationFailed {
            reason: "too many pending transactions",
        })
    }
    
    /// Find pending transaction by ID.
    pub fn find_transaction(&self, transaction_id: &[u8; 12]) -> Option<&PendingTransaction> {
        self.pending.iter().flatten()
            .find(|t| &t.transaction_id == transaction_id)
    }
    
    /// Remove pending transaction.
    pub fn remove_transaction(&mut self, transaction_id: &[u8; 12]) -> Option<PendingTransaction> {
        for slot in self.pending.iter_mut() {
            if let Some(t) = slot {
                if &t.transaction_id == transaction_id {
                    self.pending_count = self.pending_count.saturating_sub(1);
                    return slot.take();
                }
            }
        }
        None
    }
    
    /// Check for timed out transactions.
    pub fn check_timeouts(&mut self) -> Vec<[u8; 12]> {
        let mut timed_out = Vec::new();
        
        for slot in self.pending.iter_mut().flatten() {
            if slot.is_timed_out() && slot.retries >= slot.max_retries {
                timed_out.push(slot.transaction_id);
            }
        }
        
        // Remove timed out transactions
        for id in &timed_out {
            self.remove_transaction(id);
        }
        
        timed_out
    }
    
    // ========== Cleanup ==========
    
    /// Cleanup expired permissions and bindings.
    pub fn cleanup_expired(&mut self) -> (u8, u8) {
        let perms = self.permissions.cleanup_expired();
        let channels = self.channels.cleanup_expired();
        (perms, channels)
    }
    
    // ========== Statistics ==========
    
    /// Record relayed packet.
    pub fn record_packet(&mut self, bytes: usize) {
        self.packets_relayed += 1;
        self.bytes_relayed += bytes as u64;
        self.last_activity = Instant::now();
    }
    
    /// Get statistics.
    pub fn stats(&self) -> (u64, u64) {
        (self.packets_relayed, self.bytes_relayed)
    }
}

impl std::fmt::Debug for Allocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allocation")
            .field("state", &self.state)
            .field("server", &self.server.address)
            .field("relay", &self.relay_addr())
            .field("permissions", &self.permissions.count())
            .field("channels", &self.channels.count())
            .field("packets_relayed", &self.packets_relayed)
            .finish()
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
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
    }
    
    fn test_server() -> TurnServerInfo {
        TurnServerInfo::new(
            test_addr(3478),
            TurnCredentials::new("user", "pass"),
        )
    }

    #[test]
    fn test_allocation_state() {
        assert!(AllocationState::Allocated.is_active());
        assert!(AllocationState::Allocated.can_send());
        assert!(!AllocationState::New.is_active());
        assert!(AllocationState::Failed.is_terminal());
    }

    #[test]
    fn test_allocation_new() {
        let alloc = Allocation::new(test_server());
        assert_eq!(alloc.state(), AllocationState::New);
        assert!(alloc.relay_addr().is_none());
    }

    #[test]
    fn test_allocation_lifecycle() {
        let mut alloc = Allocation::new(test_server());
        
        // Set relayed address
        let relay = test_addr(49152);
        let mapped = test_addr(12345);
        alloc.set_relayed(relay, mapped, 600);
        
        assert_eq!(alloc.state(), AllocationState::Allocated);
        assert_eq!(alloc.relay_addr(), Some(relay));
    }

    #[test]
    fn test_allocation_permissions() {
        let mut alloc = Allocation::new(test_server());
        alloc.set_relayed(test_addr(49152), test_addr(12345), 600);
        
        let peer = test_addr(5000);
        alloc.add_permission(peer).unwrap();
        
        assert!(alloc.has_permission(&peer));
        assert_eq!(alloc.permission_count(), 1);
    }

    #[test]
    fn test_allocation_channels() {
        let mut alloc = Allocation::new(test_server());
        alloc.set_relayed(test_addr(49152), test_addr(12345), 600);
        
        let channel = alloc.allocate_channel().unwrap();
        let peer = test_addr(5000);
        
        alloc.add_channel_binding(channel, peer).unwrap();
        
        assert_eq!(alloc.find_channel(&peer), Some(channel));
        assert_eq!(alloc.find_peer(channel), Some(peer));
    }

    #[test]
    fn test_allocation_transactions() {
        let mut alloc = Allocation::new(test_server());
        
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        alloc.add_transaction(txn_id, TransactionType::Allocate).unwrap();
        
        assert!(alloc.find_transaction(&txn_id).is_some());
        
        let removed = alloc.remove_transaction(&txn_id);
        assert!(removed.is_some());
        assert!(alloc.find_transaction(&txn_id).is_none());
    }

    #[test]
    fn test_pending_transaction() {
        let txn = PendingTransaction::new(
            [0; 12],
            TransactionType::Allocate,
        );
        
        assert!(!txn.is_timed_out());
        assert_eq!(txn.retries, 0);
    }

    #[test]
    fn test_allocation_nonce_realm() {
        let mut alloc = Allocation::new(test_server());
        
        alloc.set_nonce(b"nonce123");
        alloc.set_realm(b"example.com");
        
        assert_eq!(alloc.nonce(), b"nonce123");
        assert_eq!(alloc.realm(), b"example.com");
    }
}
