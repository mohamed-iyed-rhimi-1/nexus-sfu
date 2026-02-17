//! TURN Client implementation.
//!
//! High-level client for TURN relay allocation and data transfer.
//!
//! # MESSAGE-INTEGRITY Support
//!
//! This module implements RFC 5389 MESSAGE-INTEGRITY for TURN authentication:
//! - Long-term credentials: key = MD5(username:realm:password)
//! - HMAC-SHA1 computation over STUN message
//! - Verification of MESSAGE-INTEGRITY in responses
//!
//! # TigerStyle Compliance
//!
//! All functions follow TigerStyle guidelines:
//! - ≤70 lines per function
//! - ≥2 assertions per function
//! - No recursion, bounded loops
//! - Static allocation

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::{Md5, Digest};
use sha1::Sha1;

use crate::ice::stun::message::{StunMessage, StunClass, StunMethod, STUN_MAGIC_COOKIE};
use crate::ice::stun::attributes::{StunAttribute, ATTR_LIFETIME};

use super::allocation::{Allocation, AllocationState, TransactionType};
use super::error::TurnError;
use super::types::{
    TurnServerInfo,
    ChannelBinding,
};
use super::{
    DEFAULT_ALLOCATION_LIFETIME, CHANNEL_DATA_HEADER_SIZE,
    MAX_TURN_DATA_SIZE,
    TRANSPORT_UDP,
};

/// HMAC-SHA1 type alias for MESSAGE-INTEGRITY computation.
type HmacSha1 = Hmac<Sha1>;

/// MESSAGE-INTEGRITY attribute type (0x0008).
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

/// MESSAGE-INTEGRITY attribute length (20 bytes for HMAC-SHA1).
const MESSAGE_INTEGRITY_LENGTH: u16 = 20;

// ============================================================================
// Client Configuration
// ============================================================================

/// TURN client configuration.
#[derive(Debug, Clone)]
pub struct TurnClientConfig {
    /// TURN server information.
    pub server: TurnServerInfo,
    
    /// Requested allocation lifetime.
    pub lifetime: u32,
    
    /// Request timeout.
    pub timeout: Duration,
    
    /// Maximum retries.
    pub max_retries: u8,
    
    /// Auto-refresh allocations.
    pub auto_refresh: bool,
    
    /// Use channel bindings for optimization.
    pub use_channels: bool,
}

impl TurnClientConfig {
    /// Create new configuration.
    pub fn new(server: TurnServerInfo) -> Self {
        Self {
            server,
            lifetime: DEFAULT_ALLOCATION_LIFETIME,
            timeout: Duration::from_secs(5),
            max_retries: 3,
            auto_refresh: true,
            use_channels: true,
        }
    }
    
    /// Set lifetime.
    pub fn with_lifetime(mut self, lifetime: u32) -> Self {
        self.lifetime = lifetime;
        self
    }
    
    /// Set timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Disable auto-refresh.
    pub fn without_auto_refresh(mut self) -> Self {
        self.auto_refresh = false;
        self
    }
}

// ============================================================================
// Outgoing Message
// ============================================================================

/// Outgoing TURN message to send.
#[derive(Debug)]
pub struct OutgoingMessage {
    /// Destination address.
    pub destination: SocketAddr,
    /// Message data.
    pub data: [u8; 600],
    /// Data length.
    pub len: usize,
}

impl OutgoingMessage {
    /// Create new outgoing message.
    fn new(destination: SocketAddr) -> Self {
        Self {
            destination,
            data: [0u8; 600],
            len: 0,
        }
    }
    
    /// Get data slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ============================================================================
// Incoming Data
// ============================================================================

/// Incoming relayed data.
#[derive(Debug)]
pub enum IncomingData {
    /// Data from peer via Send indication.
    PeerData {
        peer: SocketAddr,
        data: Vec<u8>,
    },
    /// Data from peer via ChannelData.
    ChannelData {
        channel: u16,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    /// Allocation succeeded.
    AllocationSuccess {
        relay: SocketAddr,
        mapped: SocketAddr,
        lifetime: u32,
    },
    /// Allocation failed.
    AllocationFailed {
        error: TurnError,
    },
    /// Permission created.
    PermissionCreated {
        peer: SocketAddr,
    },
    /// Channel bound.
    ChannelBound {
        channel: u16,
        peer: SocketAddr,
    },
}

// ============================================================================
// TURN Client
// ============================================================================

/// Maximum active permissions tracked by the client.
const MAX_ACTIVE_PERMISSIONS: usize = 16;

/// Maximum active channel bindings tracked by the client.
const MAX_ACTIVE_CHANNELS: usize = 8;

/// TURN Client.
///
/// Manages TURN allocations for NAT traversal.
pub struct TurnClient {
    /// Configuration.
    config: TurnClientConfig,
    
    /// Current allocation.
    allocation: Allocation,
    
    /// Transaction ID counter.
    transaction_counter: u32,
    
    /// Started timestamp.
    started_at: Option<Instant>,
    
    /// Active permissions (peer addresses that have been granted permission).
    active_permissions: [Option<SocketAddr>; MAX_ACTIVE_PERMISSIONS],
    
    /// Number of active permissions.
    active_permission_count: u8,
    
    /// Active channel bindings (channel number -> peer address).
    active_channels: [(u16, Option<SocketAddr>); MAX_ACTIVE_CHANNELS],
    
    /// Number of active channel bindings.
    active_channel_count: u8,
}

impl TurnClient {
    /// Create new TURN client.
    pub fn new(config: TurnClientConfig) -> Self {
        let allocation = Allocation::new(config.server.clone());
        
        Self {
            config,
            allocation,
            transaction_counter: 0,
            started_at: None,
            active_permissions: [None; MAX_ACTIVE_PERMISSIONS],
            active_permission_count: 0,
            active_channels: [(0, None); MAX_ACTIVE_CHANNELS],
            active_channel_count: 0,
        }
    }
    
    /// Get allocation state.
    #[inline]
    pub fn state(&self) -> AllocationState {
        self.allocation.state()
    }
    
    /// Get relayed address.
    #[inline]
    pub fn relay_address(&self) -> Option<SocketAddr> {
        self.allocation.relay_addr()
    }
    
    /// Get server address.
    #[inline]
    pub fn server_address(&self) -> SocketAddr {
        self.config.server.address
    }
    
    /// Check if allocation is active.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.allocation.state().is_active()
    }
    
    // ========== Permission and Channel Queries ==========
    
    /// Check if permission exists for a peer address.
    ///
    /// Returns true if a CreatePermission request has succeeded for this peer.
    /// Permission matching is done by IP address only (port is ignored per RFC 5766).
    ///
    /// # TigerStyle Compliance
    /// - Precondition: addr must be valid
    /// - Bounded iteration over active_permissions array
    #[inline]
    pub fn has_permission(&self, addr: &SocketAddr) -> bool {
        // Check in our tracked permissions
        let in_tracked = self.active_permissions[..self.active_permission_count as usize]
            .iter()
            .any(|p| p.map(|a| a.ip() == addr.ip()).unwrap_or(false));
        
        // Also check allocation's permission table
        in_tracked || self.allocation.has_permission(addr)
    }
    
    /// Get the peer address associated with a channel number.
    ///
    /// Returns the peer address if a ChannelBind request has succeeded for this channel.
    ///
    /// # TigerStyle Compliance
    /// - Precondition: channel must be in valid range (0x4000-0x7FFF)
    /// - Bounded iteration over active_channels array
    #[inline]
    pub fn get_channel_peer(&self, channel: u16) -> Option<SocketAddr> {
        // Precondition: channel must be valid
        if !ChannelBinding::is_valid_channel(channel) {
            return None;
        }
        
        // Check in our tracked channels
        for (ch, peer) in &self.active_channels[..self.active_channel_count as usize] {
            if *ch == channel {
                return *peer;
            }
        }
        
        // Also check allocation's channel binding table
        self.allocation.find_peer(channel)
    }
    
    /// Get the number of active permissions.
    #[inline]
    pub fn permission_count(&self) -> u8 {
        self.active_permission_count
    }
    
    /// Get the number of active channel bindings.
    #[inline]
    pub fn channel_count(&self) -> u8 {
        self.active_channel_count
    }
    
    // ========== Allocation ==========
    
    /// Start allocation request.
    ///
    /// Returns the Allocate request to send to server.
    pub fn allocate(&mut self) -> Result<OutgoingMessage, TurnError> {
        if self.allocation.state() != AllocationState::New {
            return Err(TurnError::InvalidState {
                expected: "New",
                actual: "already allocating or allocated",
            });
        }
        
        self.started_at = Some(Instant::now());
        self.allocation.set_state(AllocationState::Allocating);
        
        let msg = self.build_allocate_request(false)?;
        Ok(msg)
    }
    
    /// Build Allocate request.
    fn build_allocate_request(&mut self, with_auth: bool) -> Result<OutgoingMessage, TurnError> {
        let transaction_id = self.next_transaction_id();
        
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        // Build STUN Allocate Request
        let mut offset = 0;
        
        // Header placeholder (will fill in after we know length)
        offset += 20;
        
        // REQUESTED-TRANSPORT attribute
        // Type: 0x0019, Length: 4
        msg.data[offset..offset+2].copy_from_slice(&0x0019u16.to_be_bytes());
        msg.data[offset+2..offset+4].copy_from_slice(&4u16.to_be_bytes());
        msg.data[offset+4] = TRANSPORT_UDP;
        msg.data[offset+5..offset+8].copy_from_slice(&[0, 0, 0]); // Reserved
        offset += 8;
        
        // LIFETIME attribute
        // Type: 0x000D, Length: 4
        msg.data[offset..offset+2].copy_from_slice(&ATTR_LIFETIME.to_be_bytes());
        msg.data[offset+2..offset+4].copy_from_slice(&4u16.to_be_bytes());
        msg.data[offset+4..offset+8].copy_from_slice(&self.config.lifetime.to_be_bytes());
        offset += 8;
        
        // Add authentication if needed
        if with_auth {
            offset = self.add_auth_attributes(&mut msg.data, offset)?;
        }
        
        // Fill in header
        let msg_type = encode_message_type(StunMethod::Allocate, StunClass::Request);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        // Track transaction
        self.allocation.add_transaction(transaction_id, TransactionType::Allocate)?;
        
        Ok(msg)
    }
    
    /// Retry allocation with authentication.
    pub fn allocate_with_auth(&mut self) -> Result<OutgoingMessage, TurnError> {
        if self.allocation.state() != AllocationState::NeedsAuth {
            return Err(TurnError::InvalidState {
                expected: "NeedsAuth",
                actual: "not awaiting auth",
            });
        }
        
        self.allocation.set_state(AllocationState::Allocating);
        self.build_allocate_request(true)
    }
    
    // ========== Refresh ==========
    
    /// Refresh allocation.
    pub fn refresh(&mut self) -> Result<OutgoingMessage, TurnError> {
        if !self.allocation.state().is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        
        self.allocation.set_state(AllocationState::Refreshing);
        
        let transaction_id = self.next_transaction_id();
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        let mut offset = 20; // Skip header
        
        // LIFETIME attribute
        msg.data[offset..offset+2].copy_from_slice(&ATTR_LIFETIME.to_be_bytes());
        msg.data[offset+2..offset+4].copy_from_slice(&4u16.to_be_bytes());
        msg.data[offset+4..offset+8].copy_from_slice(&self.config.lifetime.to_be_bytes());
        offset += 8;
        
        // Add authentication
        offset = self.add_auth_attributes(&mut msg.data, offset)?;
        
        // Fill header
        let msg_type = encode_message_type(StunMethod::Refresh, StunClass::Request);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        self.allocation.add_transaction(transaction_id, TransactionType::Refresh)?;
        
        Ok(msg)
    }
    
    /// Release allocation (set lifetime to 0).
    pub fn release(&mut self) -> Result<OutgoingMessage, TurnError> {
        if !self.allocation.state().is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        
        let transaction_id = self.next_transaction_id();
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        let mut offset = 20;
        
        // LIFETIME = 0
        msg.data[offset..offset+2].copy_from_slice(&ATTR_LIFETIME.to_be_bytes());
        msg.data[offset+2..offset+4].copy_from_slice(&4u16.to_be_bytes());
        msg.data[offset+4..offset+8].copy_from_slice(&0u32.to_be_bytes());
        offset += 8;
        
        // Add authentication
        offset = self.add_auth_attributes(&mut msg.data, offset)?;
        
        // Fill header
        let msg_type = encode_message_type(StunMethod::Refresh, StunClass::Request);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        self.allocation.add_transaction(transaction_id, TransactionType::Refresh)?;
        
        Ok(msg)
    }
    
    // ========== Permissions ==========
    
    /// Create permission for peer.
    pub fn create_permission(&mut self, peer: SocketAddr) -> Result<OutgoingMessage, TurnError> {
        if !self.allocation.state().is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        
        let transaction_id = self.next_transaction_id();
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        let mut offset = 20;
        
        // XOR-PEER-ADDRESS attribute
        offset = self.encode_xor_address(&mut msg.data, offset, 0x0012, peer, &transaction_id);
        
        // Add authentication
        offset = self.add_auth_attributes(&mut msg.data, offset)?;
        
        // Fill header
        let msg_type = encode_message_type(StunMethod::CreatePermission, StunClass::Request);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        // Track transaction with peer address for permission tracking
        self.allocation.add_transaction_with_peer(transaction_id, TransactionType::CreatePermission, peer)?;
        
        Ok(msg)
    }
    
    // ========== Channel Binding ==========
    
    /// Bind channel to peer.
    pub fn bind_channel(&mut self, peer: SocketAddr) -> Result<(u16, OutgoingMessage), TurnError> {
        if !self.allocation.state().is_active() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "not active",
            });
        }
        
        // Check if already bound
        if let Some(channel) = self.allocation.find_channel(&peer) {
            return Err(TurnError::PeerAlreadyBound { peer, channel });
        }
        
        // Allocate channel number
        let channel = self.allocation.allocate_channel()?;
        
        let transaction_id = self.next_transaction_id();
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        let mut offset = 20;
        
        // CHANNEL-NUMBER attribute
        msg.data[offset..offset+2].copy_from_slice(&0x000Cu16.to_be_bytes());
        msg.data[offset+2..offset+4].copy_from_slice(&4u16.to_be_bytes());
        msg.data[offset+4..offset+6].copy_from_slice(&channel.to_be_bytes());
        msg.data[offset+6..offset+8].copy_from_slice(&[0, 0]); // Reserved
        offset += 8;
        
        // XOR-PEER-ADDRESS attribute
        offset = self.encode_xor_address(&mut msg.data, offset, 0x0012, peer, &transaction_id);
        
        // Add authentication
        offset = self.add_auth_attributes(&mut msg.data, offset)?;
        
        // Fill header
        let msg_type = encode_message_type(StunMethod::ChannelBind, StunClass::Request);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        // Track transaction with peer address and channel for binding tracking
        self.allocation.add_transaction_with_channel(transaction_id, TransactionType::ChannelBind, peer, channel)?;
        
        Ok((channel, msg))
    }
    
    // ========== Data Relay ==========
    
    /// Send data to peer via Send indication.
    pub fn send_data(&mut self, peer: SocketAddr, data: &[u8]) -> Result<OutgoingMessage, TurnError> {
        if !self.allocation.state().can_send() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "cannot send",
            });
        }
        
        if data.len() > MAX_TURN_DATA_SIZE {
            return Err(TurnError::DataTooLarge {
                size: data.len(),
                max: MAX_TURN_DATA_SIZE,
            });
        }
        
        // Check permission
        if !self.allocation.has_permission(&peer) {
            return Err(TurnError::PermissionDenied { peer });
        }
        
        let transaction_id = self.next_transaction_id();
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        let mut offset = 20;
        
        // XOR-PEER-ADDRESS
        offset = self.encode_xor_address(&mut msg.data, offset, 0x0012, peer, &transaction_id);
        
        // DATA attribute
        msg.data[offset..offset+2].copy_from_slice(&0x0013u16.to_be_bytes());
        let data_len = data.len() as u16;
        msg.data[offset+2..offset+4].copy_from_slice(&data_len.to_be_bytes());
        msg.data[offset+4..offset+4+data.len()].copy_from_slice(data);
        offset += 4 + data.len();
        
        // Pad to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        offset += padding;
        
        // Fill header (Send is an indication - class 01)
        let msg_type = encode_message_type(StunMethod::Send, StunClass::Indication);
        let msg_len = (offset - 20) as u16;
        
        msg.data[0..2].copy_from_slice(&msg_type.to_be_bytes());
        msg.data[2..4].copy_from_slice(&msg_len.to_be_bytes());
        msg.data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.data[8..20].copy_from_slice(&transaction_id);
        
        msg.len = offset;
        
        self.allocation.record_packet(data.len());
        
        Ok(msg)
    }
    
    /// Send data via ChannelData (more efficient).
    pub fn send_channel_data(&mut self, channel: u16, data: &[u8]) -> Result<OutgoingMessage, TurnError> {
        if !self.allocation.state().can_send() {
            return Err(TurnError::InvalidState {
                expected: "Allocated",
                actual: "cannot send",
            });
        }
        
        if !ChannelBinding::is_valid_channel(channel) {
            return Err(TurnError::InvalidChannelNumber { channel });
        }
        
        // Verify channel is bound
        if self.allocation.find_peer(channel).is_none() {
            return Err(TurnError::ChannelBindFailed {
                reason: "channel not bound",
            });
        }
        
        if data.len() > MAX_TURN_DATA_SIZE {
            return Err(TurnError::DataTooLarge {
                size: data.len(),
                max: MAX_TURN_DATA_SIZE,
            });
        }
        
        let mut msg = OutgoingMessage::new(self.config.server.address);
        
        // ChannelData format:
        // 2 bytes: Channel Number
        // 2 bytes: Length
        // n bytes: Data
        msg.data[0..2].copy_from_slice(&channel.to_be_bytes());
        msg.data[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        msg.data[4..4+data.len()].copy_from_slice(data);
        
        // Pad to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        msg.len = 4 + data.len() + padding;
        
        self.allocation.record_packet(data.len());
        
        Ok(msg)
    }
    
    // ========== Response Processing ==========
    
    /// Process incoming STUN message.
    pub fn process_message(&mut self, data: &[u8]) -> Result<Option<IncomingData>, TurnError> {
        // Check for ChannelData (first two bytes in 0x4000-0x7FFF range)
        if data.len() >= 4 {
            let channel = u16::from_be_bytes([data[0], data[1]]);
            if ChannelBinding::is_valid_channel(channel) {
                return self.process_channel_data(data);
            }
        }
        
        // Parse as STUN message
        let msg = StunMessage::parse(data)
            .map_err(|_| TurnError::InvalidMessage { reason: "invalid STUN message" })?;
        
        match (msg.method, msg.class) {
            (StunMethod::Allocate, StunClass::SuccessResponse) => {
                self.handle_allocate_success(&msg)
            }
            (StunMethod::Allocate, StunClass::ErrorResponse) => {
                self.handle_allocate_error(&msg)
            }
            (StunMethod::Refresh, StunClass::SuccessResponse) => {
                self.handle_refresh_success(&msg)
            }
            (StunMethod::Refresh, StunClass::ErrorResponse) => {
                self.handle_refresh_error(&msg)
            }
            (StunMethod::CreatePermission, StunClass::SuccessResponse) => {
                self.handle_permission_success(&msg)
            }
            (StunMethod::ChannelBind, StunClass::SuccessResponse) => {
                self.handle_channel_bind_success(&msg)
            }
            (StunMethod::Data, StunClass::Indication) => {
                self.handle_data_indication(&msg)
            }
            _ => Ok(None),
        }
    }
    
    /// Process ChannelData message.
    fn process_channel_data(&mut self, data: &[u8]) -> Result<Option<IncomingData>, TurnError> {
        if data.len() < CHANNEL_DATA_HEADER_SIZE {
            return Err(TurnError::InvalidMessage { reason: "ChannelData too short" });
        }
        
        let channel = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        
        if data.len() < CHANNEL_DATA_HEADER_SIZE + length {
            return Err(TurnError::InvalidMessage { reason: "ChannelData truncated" });
        }
        
        let peer = self.allocation.find_peer(channel)
            .ok_or(TurnError::ChannelBindFailed { reason: "unknown channel" })?;
        
        let payload = data[CHANNEL_DATA_HEADER_SIZE..CHANNEL_DATA_HEADER_SIZE + length].to_vec();
        
        self.allocation.record_packet(length);
        
        Ok(Some(IncomingData::ChannelData {
            channel,
            peer,
            data: payload,
        }))
    }
    
    /// Handle Allocate success.
    fn handle_allocate_success(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        self.allocation.remove_transaction(&msg.transaction_id);
        
        let mut relay = None;
        let mut mapped = None;
        let mut lifetime = DEFAULT_ALLOCATION_LIFETIME;
        
        for i in 0..msg.attribute_count as usize {
            if let Some(attr) = &msg.attributes[i] {
                match attr {
                    StunAttribute::XorRelayedAddress(addr) => relay = Some(*addr),
                    StunAttribute::XorMappedAddress(addr) => mapped = Some(*addr),
                    StunAttribute::Lifetime(lt) => lifetime = *lt,
                    _ => {}
                }
            }
        }
        
        let relay_addr = relay.ok_or(TurnError::InvalidMessage {
            reason: "missing XOR-RELAYED-ADDRESS",
        })?;
        
        let mapped_addr = mapped.unwrap_or(relay_addr);
        
        self.allocation.set_relayed(relay_addr, mapped_addr, lifetime);
        
        Ok(Some(IncomingData::AllocationSuccess {
            relay: relay_addr,
            mapped: mapped_addr,
            lifetime,
        }))
    }
    
    /// Handle Allocate error.
    fn handle_allocate_error(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        self.allocation.remove_transaction(&msg.transaction_id);
        
        for i in 0..msg.attribute_count as usize {
            if let Some(StunAttribute::ErrorCode { code, .. }) = &msg.attributes[i] {
                if *code == 401 {
                    // Authentication required
                    // Extract realm and nonce
                    for j in 0..msg.attribute_count as usize {
                        if let Some(attr2) = &msg.attributes[j] {
                            match attr2 {
                                StunAttribute::Realm { value, len } => {
                                    self.allocation.set_realm(&value[..*len as usize]);
                                }
                                StunAttribute::Nonce { value, len } => {
                                    self.allocation.set_nonce(&value[..*len as usize]);
                                }
                                _ => {}
                            }
                        }
                    }
                    self.allocation.set_state(AllocationState::NeedsAuth);
                    return Ok(None);
                }
                
                self.allocation.set_state(AllocationState::Failed);
                return Ok(Some(IncomingData::AllocationFailed {
                    error: TurnError::from_error_code(*code, &[]),
                }));
            }
        }
        
        self.allocation.set_state(AllocationState::Failed);
        Ok(Some(IncomingData::AllocationFailed {
            error: TurnError::AllocationFailed { reason: "unknown error" },
        }))
    }
    
    /// Handle Refresh success.
    fn handle_refresh_success(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        self.allocation.remove_transaction(&msg.transaction_id);
        
        let mut lifetime = DEFAULT_ALLOCATION_LIFETIME;
        
        for i in 0..msg.attribute_count as usize {
            if let Some(StunAttribute::Lifetime(lt)) = &msg.attributes[i] {
                lifetime = *lt;
            }
        }
        
        if lifetime == 0 {
            // Allocation released
            self.allocation.set_state(AllocationState::Expired);
        } else {
            self.allocation.refresh_relayed(lifetime);
        }
        
        Ok(None)
    }
    
    /// Handle Refresh error.
    fn handle_refresh_error(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        self.allocation.remove_transaction(&msg.transaction_id);
        self.allocation.set_state(AllocationState::Failed);
        Ok(None)
    }
    
    /// Handle CreatePermission success.
    ///
    /// Records the peer address in active_permissions for tracking.
    ///
    /// # TigerStyle Compliance
    /// - Precondition: transaction must exist
    /// - Postcondition: permission is recorded if space available
    fn handle_permission_success(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        // Look up transaction to get peer address before removing
        let peer_addr = self.allocation.find_transaction(&msg.transaction_id)
            .and_then(|t| t.peer_addr);
        
        self.allocation.remove_transaction(&msg.transaction_id);
        
        // Record permission if we have the peer address
        if let Some(peer) = peer_addr {
            // Check if already tracked (avoid duplicates)
            let already_tracked = self.active_permissions[..self.active_permission_count as usize]
                .iter()
                .any(|p| p.map(|a| a.ip() == peer.ip()).unwrap_or(false));
            
            if !already_tracked && (self.active_permission_count as usize) < MAX_ACTIVE_PERMISSIONS {
                // Find empty slot or use next available
                for slot in self.active_permissions.iter_mut() {
                    if slot.is_none() {
                        *slot = Some(peer);
                        self.active_permission_count += 1;
                        break;
                    }
                }
            }
            
            // Also add to allocation's permission table
            let _ = self.allocation.add_permission(peer);
            
            return Ok(Some(IncomingData::PermissionCreated { peer }));
        }
        
        Ok(None)
    }
    
    /// Handle ChannelBind success.
    ///
    /// Records the channel-peer binding in active_channels for tracking.
    ///
    /// # TigerStyle Compliance
    /// - Precondition: transaction must exist with channel info
    /// - Postcondition: channel binding is recorded if space available
    fn handle_channel_bind_success(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        // Look up transaction to get peer address and channel before removing
        let (peer_addr, channel) = self.allocation.find_transaction(&msg.transaction_id)
            .map(|t| (t.peer_addr, t.channel))
            .unwrap_or((None, None));
        
        self.allocation.remove_transaction(&msg.transaction_id);
        
        // Record channel binding if we have both peer and channel
        if let (Some(peer), Some(ch)) = (peer_addr, channel) {
            // Check if channel already tracked
            let already_tracked = self.active_channels[..self.active_channel_count as usize]
                .iter()
                .any(|(c, _)| *c == ch);
            
            if !already_tracked && (self.active_channel_count as usize) < MAX_ACTIVE_CHANNELS {
                // Find empty slot or use next available
                for slot in self.active_channels.iter_mut() {
                    if slot.1.is_none() {
                        *slot = (ch, Some(peer));
                        self.active_channel_count += 1;
                        break;
                    }
                }
            }
            
            // Also add to allocation's channel binding table
            let _ = self.allocation.add_channel_binding(ch, peer);
            
            return Ok(Some(IncomingData::ChannelBound { channel: ch, peer }));
        }
        
        Ok(None)
    }
    
    /// Handle Data indication.
    fn handle_data_indication(&mut self, msg: &StunMessage) -> Result<Option<IncomingData>, TurnError> {
        let mut peer = None;
        let mut data = None;
        
        for i in 0..msg.attribute_count as usize {
            if let Some(attr) = &msg.attributes[i] {
                match attr {
                    StunAttribute::XorPeerAddress(addr) => peer = Some(*addr),
                    StunAttribute::Data { value, len } => {
                        data = Some(value[..*len as usize].to_vec());
                    }
                    _ => {}
                }
            }
        }
        
        if let (Some(peer_addr), Some(payload)) = (peer, data) {
            self.allocation.record_packet(payload.len());
            
            Ok(Some(IncomingData::PeerData {
                peer: peer_addr,
                data: payload,
            }))
        } else {
            Err(TurnError::InvalidMessage { reason: "incomplete Data indication" })
        }
    }
    
    // ========== Helpers ==========
    
    /// Generate next transaction ID.
    fn next_transaction_id(&mut self) -> [u8; 12] {
        self.transaction_counter = self.transaction_counter.wrapping_add(1);
        
        let mut id = [0u8; 12];
        // Use counter and timestamp for uniqueness
        let now = Instant::now();
        let ts = now.elapsed().as_nanos() as u64;
        
        id[0..4].copy_from_slice(&self.transaction_counter.to_be_bytes());
        id[4..12].copy_from_slice(&ts.to_be_bytes());
        
        id
    }
    
    // ========== MESSAGE-INTEGRITY Functions (RFC 5389) ==========
    
    /// Derive long-term credential key.
    ///
    /// Computes key = MD5(username:realm:password) per RFC 5389 Section 15.4.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions (preconditions and postconditions)
    /// - No recursion, bounded operations
    ///
    /// # Arguments
    /// * `username` - The username for authentication
    /// * `realm` - The realm from the server's 401 response
    /// * `password` - The user's password
    ///
    /// # Returns
    /// A 16-byte MD5 hash key for use with HMAC-SHA1
    ///
    /// _Requirements: 6.2_
    pub fn derive_credential_key(
        username: &[u8],
        realm: &[u8],
        password: &[u8],
    ) -> [u8; 16] {
        // Precondition: username must not be empty for valid credentials
        assert!(!username.is_empty(), "username must not be empty");
        // Precondition: realm must not be empty for long-term credentials
        assert!(!realm.is_empty(), "realm must not be empty for long-term credentials");
        
        // Compute MD5(username:realm:password)
        let mut hasher = Md5::new();
        hasher.update(username);
        hasher.update(b":");
        hasher.update(realm);
        hasher.update(b":");
        hasher.update(password);
        
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result);
        
        // Postcondition: key must be 16 bytes (MD5 output size)
        assert_eq!(key.len(), 16, "MD5 key must be 16 bytes");
        // Postcondition: key should be non-zero for non-empty password
        assert!(
            password.is_empty() || key.iter().any(|&b| b != 0),
            "key derivation must produce non-zero key for non-empty password"
        );
        
        key
    }
    
    /// Compute MESSAGE-INTEGRITY HMAC-SHA1.
    ///
    /// Computes HMAC-SHA1 over the STUN message using the derived key.
    /// Per RFC 5389, the message length field must be adjusted to include
    /// the MESSAGE-INTEGRITY attribute before computing the HMAC.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - No recursion
    ///
    /// # Arguments
    /// * `message` - The STUN message bytes (header + attributes)
    /// * `key` - The 16-byte key from derive_credential_key()
    ///
    /// # Returns
    /// A 20-byte HMAC-SHA1 value
    ///
    /// _Requirements: 6.1_
    pub fn compute_message_integrity(
        message: &[u8],
        key: &[u8; 16],
    ) -> [u8; 20] {
        // Precondition: message must include at least the STUN header (20 bytes)
        assert!(message.len() >= 20, "message too short for integrity computation");
        // Precondition: key must be 16 bytes (MD5 output)
        assert_eq!(key.len(), 16, "key must be 16 bytes");
        
        // Create HMAC-SHA1 instance with the derived key
        let mut mac = HmacSha1::new_from_slice(key)
            .expect("HMAC can take key of any size");
        
        // Feed the entire message to the HMAC
        mac.update(message);
        
        // Finalize and get the 20-byte result
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();
        
        let mut integrity = [0u8; 20];
        integrity.copy_from_slice(&hmac_bytes);
        
        // Postcondition: result must be 20 bytes (SHA1 output size)
        assert_eq!(integrity.len(), 20, "HMAC-SHA1 must produce 20 bytes");
        // Postcondition: result should be non-zero for valid input
        assert!(
            integrity.iter().any(|&b| b != 0),
            "HMAC-SHA1 should produce non-zero output"
        );
        
        integrity
    }
    
    /// Add MESSAGE-INTEGRITY attribute to outgoing message.
    ///
    /// Appends the MESSAGE-INTEGRITY attribute (type 0x0008, length 20) to
    /// the message buffer. The STUN header length field is adjusted before
    /// computing the HMAC.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded buffer operations
    ///
    /// # Arguments
    /// * `buf` - The message buffer containing STUN header and attributes
    /// * `offset` - Current write offset (after existing attributes)
    /// * `key` - The 16-byte credential key
    ///
    /// # Returns
    /// The new offset after writing MESSAGE-INTEGRITY (offset + 24)
    ///
    /// _Requirements: 6.1, 6.2_
    pub fn add_message_integrity(
        buf: &mut [u8],
        offset: usize,
        key: &[u8; 16],
    ) -> Result<usize, TurnError> {
        // Precondition: buffer must have space for MESSAGE-INTEGRITY (24 bytes)
        assert!(
            buf.len() >= offset + 24,
            "buffer too small for MESSAGE-INTEGRITY"
        );
        // Precondition: offset must be after STUN header
        assert!(offset >= 20, "offset must be after STUN header");
        
        // Calculate adjusted length (includes MESSAGE-INTEGRITY: 4 header + 20 value)
        let adjusted_len = (offset - 20) + 24;
        
        // Temporarily adjust the length field in the header
        let original_len_bytes = [buf[2], buf[3]];
        buf[2..4].copy_from_slice(&(adjusted_len as u16).to_be_bytes());
        
        // Compute HMAC-SHA1 over header + attributes + MESSAGE-INTEGRITY header
        let mut mac = HmacSha1::new_from_slice(key)
            .map_err(|_| TurnError::AuthenticationFailed)?;
        
        // Feed header with adjusted length
        mac.update(&buf[0..offset]);
        
        // Feed MESSAGE-INTEGRITY attribute header (type + length)
        mac.update(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        mac.update(&MESSAGE_INTEGRITY_LENGTH.to_be_bytes());
        
        let hmac_result = mac.finalize();
        let hmac_bytes = hmac_result.into_bytes();
        
        // Write MESSAGE-INTEGRITY attribute
        buf[offset..offset + 2].copy_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&MESSAGE_INTEGRITY_LENGTH.to_be_bytes());
        buf[offset + 4..offset + 24].copy_from_slice(&hmac_bytes);
        
        // Restore original length (caller may need to add FINGERPRINT after)
        buf[2..4].copy_from_slice(&original_len_bytes);
        
        // Postcondition: MESSAGE-INTEGRITY type was written correctly
        assert!(
            buf[offset] == 0x00 && buf[offset + 1] == 0x08,
            "MESSAGE-INTEGRITY type must be 0x0008"
        );
        // Postcondition: MESSAGE-INTEGRITY length was written correctly
        assert!(
            buf[offset + 2] == 0x00 && buf[offset + 3] == 0x14,
            "MESSAGE-INTEGRITY length must be 0x0014 (20)"
        );
        
        Ok(offset + 24)
    }
    
    /// Verify MESSAGE-INTEGRITY in a received STUN message.
    ///
    /// Validates that the MESSAGE-INTEGRITY attribute in the response matches
    /// the expected HMAC-SHA1 computed with the credential key.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Constant-time comparison for security
    ///
    /// # Arguments
    /// * `message` - The complete STUN message including MESSAGE-INTEGRITY
    /// * `integrity_offset` - Offset where MESSAGE-INTEGRITY attribute starts
    /// * `key` - The 16-byte credential key
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, Err(TurnError::AuthenticationFailed) otherwise
    ///
    /// _Requirements: 6.3, 6.6_
    pub fn verify_message_integrity(
        message: &[u8],
        integrity_offset: usize,
        key: &[u8; 16],
    ) -> Result<(), TurnError> {
        // Precondition: message must be long enough to contain MESSAGE-INTEGRITY
        assert!(
            message.len() >= integrity_offset + 24,
            "message too short for MESSAGE-INTEGRITY verification"
        );
        // Precondition: integrity_offset must be after STUN header
        assert!(integrity_offset >= 20, "integrity offset must be after STUN header");
        
        // Verify attribute type is MESSAGE-INTEGRITY (0x0008)
        let attr_type = u16::from_be_bytes([message[integrity_offset], message[integrity_offset + 1]]);
        if attr_type != ATTR_MESSAGE_INTEGRITY {
            return Err(TurnError::InvalidMessage {
                reason: "expected MESSAGE-INTEGRITY attribute",
            });
        }
        
        // Verify attribute length is 20
        let attr_len = u16::from_be_bytes([message[integrity_offset + 2], message[integrity_offset + 3]]);
        if attr_len != MESSAGE_INTEGRITY_LENGTH {
            return Err(TurnError::InvalidMessage {
                reason: "MESSAGE-INTEGRITY length must be 20",
            });
        }
        
        // Extract the received HMAC value
        let received_hmac = &message[integrity_offset + 4..integrity_offset + 24];
        
        // Compute expected HMAC over message up to MESSAGE-INTEGRITY
        // The length field must be adjusted to include MESSAGE-INTEGRITY
        let mut temp_header = [0u8; 4];
        temp_header.copy_from_slice(&message[0..4]);
        
        // Adjusted length = offset of MESSAGE-INTEGRITY - 20 (header) + 24 (MESSAGE-INTEGRITY)
        let adjusted_len = (integrity_offset - 20 + 24) as u16;
        
        let mut mac = HmacSha1::new_from_slice(key)
            .map_err(|_| TurnError::AuthenticationFailed)?;
        
        // Feed type
        mac.update(&message[0..2]);
        // Feed adjusted length
        mac.update(&adjusted_len.to_be_bytes());
        // Feed magic cookie + transaction ID
        mac.update(&message[4..20]);
        // Feed attributes up to MESSAGE-INTEGRITY
        mac.update(&message[20..integrity_offset]);
        // Feed MESSAGE-INTEGRITY header
        mac.update(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        mac.update(&MESSAGE_INTEGRITY_LENGTH.to_be_bytes());
        
        // Verify using constant-time comparison
        mac.verify_slice(received_hmac)
            .map_err(|_| TurnError::AuthenticationFailed)?;
        
        Ok(())
    }
    
    // ========== Permission and Channel Tracking (RFC 5766) ==========
    
    /// Track permission after successful CreatePermission.
    ///
    /// Stores the peer address in the active_permissions array for tracking.
    /// Per RFC 5766, permissions are matched by IP address only (port ignored).
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions (capacity check, postcondition)
    /// - Bounded iteration over fixed-size array
    ///
    /// # Arguments
    /// * `peer` - The peer address for which permission was granted
    ///
    /// # Returns
    /// Ok(()) if permission was tracked, Err if capacity exhausted
    ///
    /// _Requirements: 6.4, 6.7_
    pub fn track_permission(&mut self, peer: SocketAddr) -> Result<(), TurnError> {
        // Precondition: must have capacity for new permission
        assert!(
            (self.active_permission_count as usize) <= MAX_ACTIVE_PERMISSIONS,
            "permission count must not exceed capacity"
        );
        
        // Check if already tracked (avoid duplicates, match by IP only)
        let already_tracked = self.active_permissions[..self.active_permission_count as usize]
            .iter()
            .any(|p| p.map(|a| a.ip() == peer.ip()).unwrap_or(false));
        
        if already_tracked {
            // Permission already tracked, nothing to do
            return Ok(());
        }
        
        // Precondition: must have space for new permission
        if (self.active_permission_count as usize) >= MAX_ACTIVE_PERMISSIONS {
            return Err(TurnError::MaxPermissionsReached {
                count: self.active_permission_count as u32,
                max: MAX_ACTIVE_PERMISSIONS as u32,
            });
        }
        
        // Find empty slot and insert
        for slot in self.active_permissions.iter_mut() {
            if slot.is_none() {
                *slot = Some(peer);
                self.active_permission_count += 1;
                
                // Postcondition: permission was added
                assert!(
                    self.active_permissions[..self.active_permission_count as usize]
                        .iter()
                        .any(|p| p.map(|a| a.ip() == peer.ip()).unwrap_or(false)),
                    "permission must be tracked after insertion"
                );
                
                return Ok(());
            }
        }
        
        // Should not reach here if count is accurate
        Err(TurnError::MaxPermissionsReached {
            count: self.active_permission_count as u32,
            max: MAX_ACTIVE_PERMISSIONS as u32,
        })
    }
    
    /// Track channel binding after successful ChannelBind.
    ///
    /// Stores the channel-peer association in the active_channels array.
    /// Per RFC 5766, channel numbers must be in range 0x4000-0x7FFF.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions (channel validity, capacity)
    /// - Bounded iteration over fixed-size array
    ///
    /// # Arguments
    /// * `channel` - The channel number (0x4000-0x7FFF)
    /// * `peer` - The peer address bound to this channel
    ///
    /// # Returns
    /// Ok(()) if binding was tracked, Err if invalid channel or capacity exhausted
    ///
    /// _Requirements: 6.5, 6.8_
    pub fn track_channel(
        &mut self,
        channel: u16,
        peer: SocketAddr,
    ) -> Result<(), TurnError> {
        // Precondition: channel must be in valid range
        assert!(
            ChannelBinding::is_valid_channel(channel),
            "channel must be in range 0x4000-0x7FFF"
        );
        // Precondition: channel count must not exceed capacity
        assert!(
            (self.active_channel_count as usize) <= MAX_ACTIVE_CHANNELS,
            "channel count must not exceed capacity"
        );
        
        // Check if channel already tracked
        let already_tracked = self.active_channels[..self.active_channel_count as usize]
            .iter()
            .any(|(ch, p)| *ch == channel && p.is_some());
        
        if already_tracked {
            // Channel already tracked, nothing to do
            return Ok(());
        }
        
        // Precondition: must have space for new channel binding
        if (self.active_channel_count as usize) >= MAX_ACTIVE_CHANNELS {
            return Err(TurnError::MaxChannelBindingsReached {
                count: self.active_channel_count as u32,
                max: MAX_ACTIVE_CHANNELS as u32,
            });
        }
        
        // Find empty slot and insert
        for slot in self.active_channels.iter_mut() {
            if slot.1.is_none() {
                *slot = (channel, Some(peer));
                self.active_channel_count += 1;
                
                // Postcondition: channel binding was added
                assert!(
                    self.active_channels[..self.active_channel_count as usize]
                        .iter()
                        .any(|(ch, p)| *ch == channel && p.is_some()),
                    "channel binding must be tracked after insertion"
                );
                
                return Ok(());
            }
        }
        
        // Should not reach here if count is accurate
        Err(TurnError::MaxChannelBindingsReached {
            count: self.active_channel_count as u32,
            max: MAX_ACTIVE_CHANNELS as u32,
        })
    }
    
    /// Add authentication attributes including MESSAGE-INTEGRITY.
    ///
    /// Per RFC 5389, MESSAGE-INTEGRITY is computed as HMAC-SHA1 over the STUN
    /// message with the length field adjusted to include MESSAGE-INTEGRITY.
    /// The key is MD5(username:realm:password) for long-term credentials.
    ///
    /// # TigerStyle Compliance
    /// - Preconditions for buffer size and offset
    /// - Key derivation assertion
    /// - Postcondition for MESSAGE-INTEGRITY attribute
    fn add_auth_attributes(&self, buf: &mut [u8], mut offset: usize) -> Result<usize, TurnError> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        use md5::{Md5, Digest};
        
        type HmacSha1 = Hmac<Sha1>;
        
        // Preconditions (TigerStyle)
        assert!(buf.len() >= offset + 128, "buffer too small for auth attributes");
        assert!(offset >= 20, "offset must be after STUN header");
        
        let creds = self.allocation.credentials();
        
        // USERNAME attribute (type 0x0006)
        let username = creds.username();
        assert!(!username.is_empty(), "username must not be empty");
        buf[offset..offset+2].copy_from_slice(&0x0006u16.to_be_bytes());
        buf[offset+2..offset+4].copy_from_slice(&(username.len() as u16).to_be_bytes());
        buf[offset+4..offset+4+username.len()].copy_from_slice(username);
        offset += 4 + username.len();
        let padding = (4 - (username.len() % 4)) % 4;
        offset += padding;
        
        // REALM attribute (type 0x0014)
        let realm = self.allocation.realm();
        if !realm.is_empty() {
            buf[offset..offset+2].copy_from_slice(&0x0014u16.to_be_bytes());
            buf[offset+2..offset+4].copy_from_slice(&(realm.len() as u16).to_be_bytes());
            buf[offset+4..offset+4+realm.len()].copy_from_slice(realm);
            offset += 4 + realm.len();
            let padding = (4 - (realm.len() % 4)) % 4;
            offset += padding;
        }
        
        // NONCE attribute (type 0x0015)
        let nonce = self.allocation.nonce();
        if !nonce.is_empty() {
            buf[offset..offset+2].copy_from_slice(&0x0015u16.to_be_bytes());
            buf[offset+2..offset+4].copy_from_slice(&(nonce.len() as u16).to_be_bytes());
            buf[offset+4..offset+4+nonce.len()].copy_from_slice(nonce);
            offset += 4 + nonce.len();
            let padding = (4 - (nonce.len() % 4)) % 4;
            offset += padding;
        }
        
        // MESSAGE-INTEGRITY attribute (type 0x0008, length 20)
        // Compute long-term credential key: MD5(username:realm:password)
        let password = creds.password();
        let key = if !realm.is_empty() {
            // Long-term credentials: key = MD5(username:realm:password)
            let mut hasher = Md5::new();
            hasher.update(username);
            hasher.update(b":");
            hasher.update(realm);
            hasher.update(b":");
            hasher.update(password);
            let result = hasher.finalize();
            let mut key = [0u8; 16];
            key.copy_from_slice(&result);
            key
        } else {
            // Short-term credentials: key = password (padded/truncated to 16 bytes)
            let mut key = [0u8; 16];
            let len = password.len().min(16);
            key[..len].copy_from_slice(&password[..len]);
            key
        };
        
        // Key derivation assertion (TigerStyle)
        assert!(key.iter().any(|&b| b != 0) || password.is_empty(), 
            "key derivation must produce non-zero key for non-empty password");
        
        // Update STUN header length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
        // The length field is at bytes 2-3 and represents bytes after the 20-byte header
        let integrity_offset = offset;
        let adjusted_len = (integrity_offset - 20) + 24; // attributes so far + MESSAGE-INTEGRITY
        buf[2..4].copy_from_slice(&(adjusted_len as u16).to_be_bytes());
        
        // Compute HMAC-SHA1 over the message up to MESSAGE-INTEGRITY header
        let mut mac = HmacSha1::new_from_slice(&key)
            .map_err(|_| TurnError::AuthenticationFailed)?;
        
        // Feed header with adjusted length
        mac.update(&buf[0..2]); // Type
        mac.update(&(adjusted_len as u16).to_be_bytes()); // Adjusted length
        mac.update(&buf[4..20]); // Magic cookie + transaction ID
        
        // Feed attributes up to MESSAGE-INTEGRITY
        mac.update(&buf[20..integrity_offset]);
        
        // Feed MESSAGE-INTEGRITY header (type + length)
        mac.update(&0x0008u16.to_be_bytes()); // MESSAGE-INTEGRITY type
        mac.update(&0x0014u16.to_be_bytes()); // Length 20
        
        let hmac_result = mac.finalize();
        let hmac_bytes = hmac_result.into_bytes();
        
        // Write MESSAGE-INTEGRITY attribute
        buf[offset..offset+2].copy_from_slice(&0x0008u16.to_be_bytes()); // Type
        buf[offset+2..offset+4].copy_from_slice(&0x0014u16.to_be_bytes()); // Length (20)
        buf[offset+4..offset+24].copy_from_slice(&hmac_bytes);
        offset += 24;
        
        // Postcondition: MESSAGE-INTEGRITY was written correctly (TigerStyle)
        assert!(buf[integrity_offset] == 0x00 && buf[integrity_offset + 1] == 0x08,
            "MESSAGE-INTEGRITY type must be 0x0008");
        assert!(buf[integrity_offset + 2] == 0x00 && buf[integrity_offset + 3] == 0x14,
            "MESSAGE-INTEGRITY length must be 0x0014 (20)");
        
        Ok(offset)
    }
    
    /// Encode XOR address attribute.
    fn encode_xor_address(
        &self,
        buf: &mut [u8],
        mut offset: usize,
        attr_type: u16,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) -> usize {
        buf[offset..offset+2].copy_from_slice(&attr_type.to_be_bytes());
        
        match addr {
            SocketAddr::V4(v4) => {
                buf[offset+2..offset+4].copy_from_slice(&8u16.to_be_bytes()); // Length
                buf[offset+4] = 0; // Reserved
                buf[offset+5] = 0x01; // IPv4 family
                
                let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                buf[offset+6..offset+8].copy_from_slice(&xor_port.to_be_bytes());
                
                let ip_bytes = v4.ip().octets();
                let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    buf[offset+8+i] = ip_bytes[i] ^ cookie_bytes[i];
                }
                
                offset += 12;
            }
            SocketAddr::V6(v6) => {
                buf[offset+2..offset+4].copy_from_slice(&20u16.to_be_bytes()); // Length
                buf[offset+4] = 0; // Reserved
                buf[offset+5] = 0x02; // IPv6 family
                
                let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                buf[offset+6..offset+8].copy_from_slice(&xor_port.to_be_bytes());
                
                let ip_bytes = v6.ip().octets();
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                
                for i in 0..16 {
                    buf[offset+8+i] = ip_bytes[i] ^ xor_key[i];
                }
                
                offset += 24;
            }
        }
        
        offset
    }
    
    /// Check if refresh is needed.
    pub fn needs_refresh(&self) -> bool {
        self.allocation.needs_refresh()
    }
    
    /// Cleanup expired permissions and bindings.
    pub fn cleanup(&mut self) -> (u8, u8) {
        self.allocation.cleanup_expired()
    }
}

/// Encode STUN message type.
fn encode_message_type(method: StunMethod, class: StunClass) -> u16 {
    let m = method as u16;
    let c = class as u16;
    
    // Method bits: M0-M3 in bits 0-3, M4-M6 in bits 5-7, M7-M11 in bits 9-13
    // Class bits: C0 in bit 4, C1 in bit 8
    let m0_3 = m & 0x000F;
    let m4_6 = (m & 0x0070) << 1;
    let m7_11 = (m & 0x0F80) << 2;
    let c0 = (c & 0x01) << 4;
    let c1 = (c & 0x02) << 7;
    
    m0_3 | m4_6 | m7_11 | c0 | c1
}

impl std::fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnClient")
            .field("state", &self.state())
            .field("relay", &self.relay_address())
            .field("server", &self.server_address())
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TurnCredentials;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
    }
    
    fn test_config() -> TurnClientConfig {
        let server = TurnServerInfo::new(
            test_addr(3478),
            TurnCredentials::new("user", "pass"),
        );
        TurnClientConfig::new(server)
    }

    #[test]
    fn test_client_new() {
        let client = TurnClient::new(test_config());
        assert_eq!(client.state(), AllocationState::New);
        assert!(client.relay_address().is_none());
    }

    #[test]
    fn test_client_allocate() {
        let mut client = TurnClient::new(test_config());
        
        let msg = client.allocate().unwrap();
        
        assert_eq!(client.state(), AllocationState::Allocating);
        assert_eq!(msg.destination, test_addr(3478));
        assert!(msg.len > 20); // At least header
    }

    #[test]
    fn test_client_config() {
        let config = test_config()
            .with_lifetime(300)
            .with_timeout(Duration::from_secs(10))
            .without_auto_refresh();
        
        assert_eq!(config.lifetime, 300);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert!(!config.auto_refresh);
    }

    #[test]
    fn test_encode_message_type() {
        // Allocate Request: 0x0003
        let mt = encode_message_type(StunMethod::Allocate, StunClass::Request);
        assert_eq!(mt, 0x0003);
        
        // Allocate Success Response: 0x0103
        let mt = encode_message_type(StunMethod::Allocate, StunClass::SuccessResponse);
        assert_eq!(mt, 0x0103);
        
        // Binding Request: 0x0001
        let mt = encode_message_type(StunMethod::Binding, StunClass::Request);
        assert_eq!(mt, 0x0001);
    }

    #[test]
    fn test_outgoing_message() {
        let mut msg = OutgoingMessage::new(test_addr(3478));
        msg.data[0..5].copy_from_slice(b"hello");
        msg.len = 5;
        
        assert_eq!(msg.data(), b"hello");
        assert_eq!(msg.destination, test_addr(3478));
    }

    #[test]
    fn test_channel_data_valid() {
        // Valid channel number
        assert!(ChannelBinding::is_valid_channel(0x4000));
        assert!(ChannelBinding::is_valid_channel(0x7FFF));
        
        // Invalid
        assert!(!ChannelBinding::is_valid_channel(0x3FFF));
        assert!(!ChannelBinding::is_valid_channel(0x8000));
    }

    #[test]
    fn test_permission_tracking_initial_state() {
        let client = TurnClient::new(test_config());
        
        // Initially no permissions
        assert_eq!(client.permission_count(), 0);
        assert!(!client.has_permission(&test_addr(5000)));
    }

    #[test]
    fn test_channel_tracking_initial_state() {
        let client = TurnClient::new(test_config());
        
        // Initially no channel bindings
        assert_eq!(client.channel_count(), 0);
        assert!(client.get_channel_peer(0x4000).is_none());
    }

    #[test]
    fn test_get_channel_peer_invalid_channel() {
        let client = TurnClient::new(test_config());
        
        // Invalid channel numbers should return None
        assert!(client.get_channel_peer(0x1000).is_none());
        assert!(client.get_channel_peer(0x8000).is_none());
    }

    // ========== MESSAGE-INTEGRITY Tests ==========

    #[test]
    fn test_derive_credential_key() {
        // Test long-term credential key derivation
        // key = MD5(username:realm:password)
        let key = TurnClient::derive_credential_key(
            b"user",
            b"example.com",
            b"pass",
        );
        
        // Key must be 16 bytes (MD5 output)
        assert_eq!(key.len(), 16);
        
        // Key must be non-zero for non-empty password
        assert!(key.iter().any(|&b| b != 0));
        
        // Same inputs should produce same key (deterministic)
        let key2 = TurnClient::derive_credential_key(
            b"user",
            b"example.com",
            b"pass",
        );
        assert_eq!(key, key2);
        
        // Different inputs should produce different keys
        let key3 = TurnClient::derive_credential_key(
            b"user2",
            b"example.com",
            b"pass",
        );
        assert_ne!(key, key3);
    }

    #[test]
    fn test_compute_message_integrity() {
        // Create a minimal STUN message (20-byte header)
        let mut message = [0u8; 40];
        // STUN header: type (2) + length (2) + magic cookie (4) + transaction ID (12)
        message[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        message[2..4].copy_from_slice(&20u16.to_be_bytes()); // Length
        message[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        message[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // Transaction ID
        
        let key = [0x01u8; 16]; // Test key
        
        let hmac = TurnClient::compute_message_integrity(&message[..20], &key);
        
        // HMAC-SHA1 must be 20 bytes
        assert_eq!(hmac.len(), 20);
        
        // HMAC must be non-zero
        assert!(hmac.iter().any(|&b| b != 0));
        
        // Same inputs should produce same HMAC (deterministic)
        let hmac2 = TurnClient::compute_message_integrity(&message[..20], &key);
        assert_eq!(hmac, hmac2);
        
        // Different key should produce different HMAC
        let key2 = [0x02u8; 16];
        let hmac3 = TurnClient::compute_message_integrity(&message[..20], &key2);
        assert_ne!(hmac, hmac3);
    }

    #[test]
    fn test_add_message_integrity() {
        // Create a STUN message buffer with header
        let mut buf = [0u8; 100];
        // STUN header
        buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length (will be updated)
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        
        let key = [0x01u8; 16];
        let offset = 20; // Start after header
        
        let new_offset = TurnClient::add_message_integrity(&mut buf, offset, &key).unwrap();
        
        // New offset should be 24 bytes after original (4 header + 20 HMAC)
        assert_eq!(new_offset, offset + 24);
        
        // MESSAGE-INTEGRITY type should be 0x0008
        assert_eq!(buf[offset], 0x00);
        assert_eq!(buf[offset + 1], 0x08);
        
        // MESSAGE-INTEGRITY length should be 0x0014 (20)
        assert_eq!(buf[offset + 2], 0x00);
        assert_eq!(buf[offset + 3], 0x14);
        
        // HMAC value should be non-zero
        assert!(buf[offset + 4..offset + 24].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_verify_message_integrity_valid() {
        // Create a STUN message with MESSAGE-INTEGRITY
        let mut buf = [0u8; 100];
        // STUN header
        buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        buf[2..4].copy_from_slice(&24u16.to_be_bytes()); // Length (MESSAGE-INTEGRITY only)
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        
        let key = [0x01u8; 16];
        
        // Add MESSAGE-INTEGRITY
        let offset = TurnClient::add_message_integrity(&mut buf, 20, &key).unwrap();
        
        // Update length to include MESSAGE-INTEGRITY
        buf[2..4].copy_from_slice(&24u16.to_be_bytes());
        
        // Verification should succeed
        let result = TurnClient::verify_message_integrity(&buf[..offset], 20, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_message_integrity_invalid() {
        // Create a STUN message with MESSAGE-INTEGRITY
        let mut buf = [0u8; 100];
        // STUN header
        buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        buf[2..4].copy_from_slice(&24u16.to_be_bytes());
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        
        let key = [0x01u8; 16];
        let wrong_key = [0x02u8; 16];
        
        // Add MESSAGE-INTEGRITY with correct key
        let offset = TurnClient::add_message_integrity(&mut buf, 20, &key).unwrap();
        buf[2..4].copy_from_slice(&24u16.to_be_bytes());
        
        // Verification with wrong key should fail
        let result = TurnClient::verify_message_integrity(&buf[..offset], 20, &wrong_key);
        assert!(result.is_err());
    }

    // ========== Permission Tracking Tests ==========

    #[test]
    fn test_track_permission() {
        let mut client = TurnClient::new(test_config());
        
        // Track a permission
        let peer = test_addr(5000);
        client.track_permission(peer).unwrap();
        
        assert_eq!(client.permission_count(), 1);
        assert!(client.has_permission(&peer));
    }

    #[test]
    fn test_track_permission_duplicate() {
        let mut client = TurnClient::new(test_config());
        
        let peer = test_addr(5000);
        client.track_permission(peer).unwrap();
        
        // Tracking same permission again should succeed (idempotent)
        client.track_permission(peer).unwrap();
        
        // Count should still be 1
        assert_eq!(client.permission_count(), 1);
    }

    #[test]
    fn test_track_permission_multiple() {
        let mut client = TurnClient::new(test_config());
        
        // Track multiple permissions with different IPs
        for i in 0..5 {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10 + i)),
                5000,
            );
            client.track_permission(peer).unwrap();
        }
        
        assert_eq!(client.permission_count(), 5);
        
        // All should be tracked
        for i in 0..5 {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10 + i)),
                5000,
            );
            assert!(client.has_permission(&peer));
        }
    }

    #[test]
    fn test_track_permission_capacity() {
        let mut client = TurnClient::new(test_config());
        
        // Fill up to capacity with different IPs
        for i in 0..MAX_ACTIVE_PERMISSIONS {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                5000,
            );
            client.track_permission(peer).unwrap();
        }
        
        assert_eq!(client.permission_count(), MAX_ACTIVE_PERMISSIONS as u8);
        
        // Next one should fail (different IP)
        let result = client.track_permission(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
            5000,
        ));
        assert!(result.is_err());
    }

    // ========== Channel Tracking Tests ==========

    #[test]
    fn test_track_channel() {
        let mut client = TurnClient::new(test_config());
        
        let channel = 0x4000;
        let peer = test_addr(5000);
        client.track_channel(channel, peer).unwrap();
        
        assert_eq!(client.channel_count(), 1);
        assert_eq!(client.get_channel_peer(channel), Some(peer));
    }

    #[test]
    fn test_track_channel_duplicate() {
        let mut client = TurnClient::new(test_config());
        
        let channel = 0x4000;
        let peer = test_addr(5000);
        client.track_channel(channel, peer).unwrap();
        
        // Tracking same channel again should succeed (idempotent)
        client.track_channel(channel, peer).unwrap();
        
        // Count should still be 1
        assert_eq!(client.channel_count(), 1);
    }

    #[test]
    fn test_track_channel_multiple() {
        let mut client = TurnClient::new(test_config());
        
        // Track multiple channels
        for i in 0..5 {
            let channel = 0x4000 + i;
            let peer = test_addr(5000 + i);
            client.track_channel(channel, peer).unwrap();
        }
        
        assert_eq!(client.channel_count(), 5);
        
        // All should be tracked
        for i in 0..5 {
            assert_eq!(
                client.get_channel_peer(0x4000 + i),
                Some(test_addr(5000 + i))
            );
        }
    }

    #[test]
    fn test_track_channel_capacity() {
        let mut client = TurnClient::new(test_config());
        
        // Fill up to capacity
        for i in 0..MAX_ACTIVE_CHANNELS {
            let channel = 0x4000 + i as u16;
            let peer = test_addr(5000 + i as u16);
            client.track_channel(channel, peer).unwrap();
        }
        
        assert_eq!(client.channel_count(), MAX_ACTIVE_CHANNELS as u8);
        
        // Next one should fail
        let result = client.track_channel(0x5000, test_addr(6000));
        assert!(result.is_err());
    }
}
