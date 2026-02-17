//! WebRTC transport management.
//!
//! Manages multiple WebRTC sessions with UDP socket handling, packet demultiplexing,
//! and session routing with bounded operations.
//!
//! # TigerStyle Compliance
//!
//! - Bounded iterations (max sessions)
//! - Explicit state checking
//! - Address association on ICE success
//! - Timeout-based cleanup
//! - Consent freshness checks (RFC 7675)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;

use super::demux::{PacketType, demux_and_validate, recover_from_malformed_packet, RecoveryAction};
use super::error::WebRtcError;
use super::session::{WebRtcSession, SessionConfig, SessionState, IncomingData, MAX_SESSIONS};
use super::types::{TransportId, TransportStats, DtlsParameters};

use nexus_transport::ice::stun::{STUN_HEADER_SIZE, ATTR_USERNAME};

// ============================================================================
// Constants
// ============================================================================

/// Default consent timeout in seconds (RFC 7675).
const DEFAULT_CONSENT_TIMEOUT_SECS: u64 = 30;

/// Result type for routing a packet to a known session.
type RouteResult = Result<Option<Option<(TransportId, IncomingData)>>, WebRtcError>;

/// Maximum address mappings (prevent memory exhaustion).
const MAX_ADDRESS_MAPPINGS: usize = 10000;

// ============================================================================
// Transport State
// ============================================================================

/// Transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// Transport created.
    New,
    /// Transport running.
    Running,
    /// Transport stopped.
    Stopped,
}

// ============================================================================
// Transport Configuration
// ============================================================================

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Bind address for UDP socket.
    pub bind_addr: SocketAddr,
    /// Maximum sessions.
    pub max_sessions: usize,
    /// Worker threads.
    pub worker_threads: usize,
    /// Consent timeout in seconds (RFC 7675).
    pub consent_timeout_secs: u64,
    /// STUN server addresses for ICE candidate gathering.
    pub stun_servers: Vec<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            max_sessions: MAX_SESSIONS,
            worker_threads: 4,
            consent_timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
            stun_servers: vec![
                "74.125.250.129:19302".to_string(),
                "74.125.250.130:19302".to_string(),
            ],
        }
    }
}

impl TransportConfig {
    /// Create with specific bind address.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }
    
    /// Set maximum sessions.
    ///
    /// # Panics
    /// Panics if max is 0 or greater than MAX_SESSIONS (1000).
    pub fn with_max_sessions(mut self, max: usize) -> Self {
        assert!(max >= 1, "max_sessions must be >= 1");
        assert!(max <= MAX_SESSIONS, "max_sessions must be <= {} (plan requirement)", MAX_SESSIONS);
        self.max_sessions = max;
        self
    }
    
    /// Set consent timeout.
    pub fn with_consent_timeout(mut self, secs: u64) -> Self {
        self.consent_timeout_secs = secs;
        self
    }
    
    /// Validate the configuration.
    ///
    /// Returns an error if max_sessions is invalid (< 1 or > 1000).
    pub fn validate(&self) -> Result<(), WebRtcError> {
        if self.max_sessions < 1 {
            return Err(WebRtcError::InvalidConfig);
        }
        if self.max_sessions > MAX_SESSIONS {
            return Err(WebRtcError::InvalidConfig);
        }
        if self.consent_timeout_secs < 5 || self.consent_timeout_secs > 300 {
            return Err(WebRtcError::InvalidConfig);
        }
        Ok(())
    }
}

// ============================================================================
// WebRTC Transport
// ============================================================================

/// WebRTC transport manager.
///
/// Manages UDP socket and multiple WebRTC sessions.
///
/// # Lock-Free Architecture (P1-2)
///
/// Uses interior mutability to eliminate global RwLock contention:
/// - `ArcSwap` routing maps for lock-free address/ufrag lookups on hot path
/// - `DashMap` + per-session `Mutex` for fine-grained session access
/// - Hot path (RTP/RTCP): atomic load + DashMap shard read + per-session mutex (~25ns)
/// - Cold path (ICE/DTLS/lifecycle): same per-session mutex, ArcSwap::rcu for routing updates
///
/// Two packets for different sessions never contend. The orchestrator doing
/// ICE/DTLS on session A does not block RTP decryption on session B.
pub struct WebRtcTransport {
    /// Configuration.
    config: TransportConfig,

    /// Transport state (atomic for lock-free reads).
    state: Mutex<TransportState>,

    /// Active sessions by ID — per-session Mutex for fine-grained locking.
    /// Hot path locks only the single session being processed.
    sessions: DashMap<TransportId, Mutex<WebRtcSession>>,

    /// Session lookup by remote address — lock-free via ArcSwap.
    /// Updated via copy-on-write on session create/remove/address association.
    addr_to_session: ArcSwap<HashMap<SocketAddr, TransportId>>,

    /// Map from local ICE ufrag to session ID — lock-free via ArcSwap.
    ufrag_to_session: ArcSwap<HashMap<String, TransportId>>,

    /// Next session ID.
    next_id: AtomicU64,

    /// Aggregate statistics (atomic counters for lock-free updates).
    stats: TransportStats,
}

impl WebRtcTransport {
    /// Create new transport.
    ///
    /// # TigerStyle
    /// - Precondition: max_sessions > 0 and <= MAX_SESSIONS
    /// - Postcondition: state is New
    ///
    /// # Errors
    /// Returns InvalidConfig if max_sessions is out of range [1, 1000].
    pub fn new(config: TransportConfig) -> Result<Self, WebRtcError> {
        // Validate configuration
        config.validate()?;
        
        // Precondition: max_sessions must be positive and bounded
        assert!(config.max_sessions >= 1, "max_sessions must be >= 1");
        assert!(config.max_sessions <= MAX_SESSIONS, "max_sessions must be <= {}", MAX_SESSIONS);
        
        // Precondition: consent timeout must be reasonable
        assert!(config.consent_timeout_secs >= 5 && config.consent_timeout_secs <= 300,
            "consent_timeout_secs must be between 5 and 300");
        
        let result = Self {
            config,
            state: Mutex::new(TransportState::New),
            sessions: DashMap::new(),
            addr_to_session: ArcSwap::from_pointee(HashMap::new()),
            ufrag_to_session: ArcSwap::from_pointee(HashMap::new()),
            next_id: AtomicU64::new(1),
            stats: TransportStats::new(),
        };
        
        // Postcondition: state must be New
        assert_eq!(*result.state.lock(), TransportState::New);
        
        Ok(result)
    }
    
    /// Get transport state.
    #[inline]
    pub fn state(&self) -> TransportState {
        *self.state.lock()
    }
    
    /// Get session count.
    #[inline]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    
    /// Get aggregate statistics.
    #[inline]
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }
    
    /// Start transport.
    ///
    /// # TigerStyle
    /// - Precondition: state must be New
    /// - Postcondition: state is Running
    pub fn start(&self) -> Result<(), WebRtcError> {
        let mut state = self.state.lock();
        // Precondition: must be in New state
        if *state != TransportState::New {
            return Err(WebRtcError::AlreadyStarted);
        }
        
        *state = TransportState::Running;
        
        // Postcondition: state must be Running
        assert_eq!(*state, TransportState::Running);
        
        Ok(())
    }
    
    /// Stop transport.
    ///
    /// # TigerStyle
    /// - Postcondition: state is Stopped
    /// - Postcondition: all sessions closed
    pub fn stop(&self) {
        *self.state.lock() = TransportState::Stopped;
        
        // Close all sessions
        for entry in self.sessions.iter() {
            entry.value().lock().close();
        }
        
        // Postcondition: state must be Stopped
        assert_eq!(*self.state.lock(), TransportState::Stopped);
    }
    
    /// Create new session.
    ///
    /// # TigerStyle
    /// - Precondition: state must be Running
    /// - Precondition: session count < max_sessions
    /// - Postcondition: session count increased by 1
    pub fn create_session(
        &self,
        dtls_params: DtlsParameters,
    ) -> Result<TransportId, WebRtcError> {
        // Precondition: transport must be running
        if *self.state.lock() != TransportState::Running {
            return Err(WebRtcError::InvalidState);
        }
        
        // Precondition: session count must be below limit
        let count_before = self.sessions.len();
        if count_before >= self.config.max_sessions {
            tracing::warn!(
                count = count_before,
                max = self.config.max_sessions,
                "Session limit reached, rejecting new session"
            );
            return Err(WebRtcError::TooManySessions);
        }
        
        let id = TransportId::new(self.next_id.fetch_add(1, Ordering::SeqCst));
        
        // Convert DtlsParameters role to DTLS role
        let dtls_role = match dtls_params.role {
            crate::webrtc::types::DtlsRole::Client => nexus_transport::dtls::DtlsRole::Client,
            crate::webrtc::types::DtlsRole::Server => nexus_transport::dtls::DtlsRole::Server,
            crate::webrtc::types::DtlsRole::Auto => nexus_transport::dtls::DtlsRole::Server, // Default to server
        };
        
        let session_config = SessionConfig {
            id,
            ice_role: nexus_transport::ice::IceRole::Controlling, // SFU is the sole offerer (RFC 8445 §5.2)
            dtls_role,
            remote_addr: None,
            srtp_profile: nexus_transport::srtp::ProtectionProfile::AeadAes128Gcm,
            consent_timeout_secs: self.config.consent_timeout_secs,
            stun_servers: self.config.stun_servers.clone(),
            ..SessionConfig::default()
        };
        
        let mut session = WebRtcSession::new(session_config)?;
        
        // Initialize ICE agent immediately so credentials are available for SDP.
        // DTLS fingerprint is already cached from session construction (RFC 4572).
        session.initialize_ice()?;
        
        // Extract local ufrag for O(1) STUN routing before inserting session
        let local_ufrag = session.local_ice_credentials().local_ufrag.clone();
        assert!(!local_ufrag.is_empty(), "Local ufrag must be non-empty after ICE init");
        
        self.sessions.insert(id, Mutex::new(session));
        
        // Update ufrag routing map via copy-on-write
        self.ufrag_to_session.rcu(|current| {
            let mut new_map = (**current).clone();
            new_map.insert(local_ufrag.clone(), id);
            Arc::new(new_map)
        });
        
        // Postcondition: session count must have increased
        let count_after = self.sessions.len();
        assert_eq!(count_after, count_before + 1, "Session count must increase by 1");
        // Postcondition: ufrag map must contain the new session
        assert!(self.ufrag_to_session.load().contains_key(&local_ufrag), "Ufrag map must contain new session");
        
        tracing::info!(session_id = id.value(), ufrag = %local_ufrag, "Created new WebRTC session");
        
        Ok(id)
    }
    
    /// Access a session by ID, calling the provided closure with a mutable reference.
    ///
    /// This is the primary session access method. It locks only the target session,
    /// never the entire transport. Two concurrent calls for different sessions
    /// never contend.
    ///
    /// # Returns
    /// `None` if session does not exist, otherwise `Some(closure_result)`.
    #[inline]
    pub fn with_session_mut<F, R>(&self, id: TransportId, f: F) -> Option<R>
    where
        F: FnOnce(&mut WebRtcSession) -> R,
    {
        self.sessions.get(&id).map(|entry| {
            let mut session = entry.value().lock();
            f(&mut session)
        })
    }

    /// Access a session by ID, calling the provided closure with a shared reference.
    ///
    /// # Returns
    /// `None` if session does not exist, otherwise `Some(closure_result)`.
    #[inline]
    pub fn with_session<F, R>(&self, id: TransportId, f: F) -> Option<R>
    where
        F: FnOnce(&WebRtcSession) -> R,
    {
        self.sessions.get(&id).map(|entry| {
            let session = entry.value().lock();
            f(&*session)
        })
    }
    
    /// Remove session.
    ///
    /// # TigerStyle
    /// - Postcondition: session is closed
    /// - Postcondition: address mappings removed
    pub fn remove_session(&self, id: TransportId) -> bool {
        if let Some((_, session_mutex)) = self.sessions.remove(&id) {
            session_mutex.lock().close();
            
            // Remove address mappings via copy-on-write
            self.addr_to_session.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.retain(|_, v| *v != id);
                Arc::new(new_map)
            });
            
            // Remove ufrag mapping via copy-on-write
            self.ufrag_to_session.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.retain(|_, v| *v != id);
                Arc::new(new_map)
            });
            
            tracing::info!(session_id = id.value(), "Removed WebRTC session");
            
            true
        } else {
            false
        }
    }
    
    // ========================================================================
    // Address Association
    // ========================================================================
    
    /// Associate remote address with session.
    ///
    /// # TigerStyle
    /// - Precondition: session exists for id
    /// - Postcondition: address is mapped
    pub fn associate_address(&self, addr: SocketAddr, id: TransportId) {
        // Precondition: session must exist
        assert!(self.sessions.contains_key(&id), "Session must exist for address association");
        
        // Bound address mappings to prevent memory exhaustion
        if self.addr_to_session.load().len() >= MAX_ADDRESS_MAPPINGS {
            tracing::warn!("Address mapping limit reached, skipping association");
            return;
        }
        
        // Update via copy-on-write
        self.addr_to_session.rcu(|current| {
            let mut new_map = (**current).clone();
            new_map.insert(addr, id);
            Arc::new(new_map)
        });
        
        // Postcondition: address must be mapped
        assert_eq!(self.addr_to_session.load().get(&addr), Some(&id));
        
        tracing::debug!(session_id = id.value(), address = %addr, "Associated address with session");
    }
    
    /// Find session by remote address.
    ///
    /// # TigerStyle
    /// - Inline for performance (hot path)
    /// - Lock-free: ArcSwap atomic pointer load (~1ns)
    #[inline]
    pub fn find_session_by_addr(&self, addr: &SocketAddr) -> Option<TransportId> {
        self.addr_to_session.load().get(addr).copied()
    }
    
    // ========================================================================
    // Packet Processing
    // ========================================================================
    
    /// Process incoming packet.
    ///
    /// Routes to appropriate session based on source address.
    /// For unknown addresses, tries ufrag-based lookup for STUN.
    ///
    /// # Lock-Free Hot Path
    ///
    /// RTP/RTCP packets (>99% of traffic) follow this path:
    /// 1. `ArcSwap::load()` — atomic pointer load (~1ns)
    /// 2. `HashMap::get()` — O(1) address lookup
    /// 3. `DashMap::get()` — lock-free shard read (~10ns)
    /// 4. `Mutex::lock()` — per-session lock (~10ns uncontended)
    ///
    /// Total: ~25ns, zero contention with other sessions or orchestrator.
    pub fn process_packet(
        &self,
        data: &[u8],
        from: SocketAddr,
        out: &mut [u8],
    ) -> Result<Option<(TransportId, IncomingData)>, WebRtcError> {
        if data.is_empty() {
            return Err(WebRtcError::PacketTooShort);
        }
        
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
        
        // Early validation - demux and validate before routing
        let (packet_type, validation) = demux_and_validate(data);
        
        // Debug log for incoming STUN packets
        if packet_type == PacketType::Stun {
            tracing::debug!(
                from = %from,
                len = data.len(),
                "Received STUN packet"
            );
        }
        
        // Handle malformed packets at transport level
        if !validation.valid {
            let action = recover_from_malformed_packet(data, packet_type, &validation);
            
            match action {
                RecoveryAction::Drop { packet_type: pt, reason } => {
                    tracing::debug!(
                        packet_type = ?pt,
                        reason = %reason,
                        from = %from,
                        "Transport dropping malformed packet"
                    );
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::RequestRetransmit { packet_type: pt } => {
                    tracing::debug!(
                        packet_type = ?pt,
                        from = %from,
                        "Transport: malformed packet may need retransmit"
                    );
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::ResetConnection { reason } => {
                    tracing::warn!(
                        reason = %reason,
                        from = %from,
                        "Transport: malformed packet, connection may need reset"
                    );
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::LogAndContinue { packet_type: pt, warning } => {
                    tracing::warn!(
                        packet_type = ?pt,
                        warning = %warning,
                        from = %from,
                        "Transport: continuing despite malformed packet"
                    );
                    // Continue - packet is processable despite warning
                }
            }
        }
        
        // Fast path: find session by address (lock-free ArcSwap load)
        if let Some(result) = self.route_to_known_session(data, from, out)? {
            return Ok(result);
        }
        
        // Slow path: try ufrag-based lookup for STUN binding requests only
        if packet_type != PacketType::Stun {
            return Ok(None);
        }
        
        self.route_stun_by_ufrag(data, from, out)
    }
    
    /// Route packet to known session (fast path).
    ///
    /// # Lock-Free Design
    /// - ArcSwap::load() for address lookup (~1ns)
    /// - DashMap::get() for session access (~10ns)
    /// - Mutex::lock() on single session (~10ns)
    fn route_to_known_session(
        &self,
        data: &[u8],
        from: SocketAddr,
        out: &mut [u8],
    ) -> RouteResult {
        if data.is_empty() {
            return Err(WebRtcError::PacketTooShort);
        }
        
        // Lock-free address lookup
        let addr_map = self.addr_to_session.load();
        let id = match addr_map.get(&from) {
            Some(&id) => id,
            None => return Ok(None),
        };
        
        // Per-session lock — only this session is locked
        let entry = match self.sessions.get(&id) {
            Some(e) => e,
            None => return Ok(None),
        };
        
        let mut session = entry.value().lock();
        
        let ptype = super::demux::PacketType::classify(data);
        if ptype == super::demux::PacketType::Dtls {
            tracing::info!(
                session_id = id.value(),
                from = %from,
                len = data.len(),
                first_byte = data[0],
                session_state = ?session.state(),
                "DTLS packet routed to known session"
            );
        }
        let result = session.process_incoming(data, from, out)?;
        match result {
            IncomingData::Rtp(_) => {
                self.stats.rtp_packets_received.fetch_add(1, Ordering::Relaxed);
                Ok(Some(Some((id, result))))
            }
            IncomingData::Rtcp(_) => {
                self.stats.rtcp_packets_received.fetch_add(1, Ordering::Relaxed);
                Ok(Some(Some((id, result))))
            }
            IncomingData::None => {
                Ok(Some(None))
            }
            other => {
                Ok(Some(Some((id, other))))
            }
        }
    }
    
    /// Route STUN packet by USERNAME attribute for O(1) session lookup.
    ///
    /// Extracts the USERNAME attribute from raw STUN bytes, parses the
    /// `local_ufrag` portion, and looks up the session by ufrag.
    ///
    /// # TigerStyle
    /// - Bounded attribute parsing loop (max 16 iterations)
    /// - O(1) HashMap lookup instead of brute-force
    /// - Caller must ensure packet_type is Stun before calling
    fn route_stun_by_ufrag(
        &self,
        data: &[u8],
        from: SocketAddr,
        out: &mut [u8],
    ) -> Result<Option<(TransportId, IncomingData)>, WebRtcError> {
        // Precondition: data must be a valid STUN packet (at least header size)
        if data.len() < STUN_HEADER_SIZE {
            return Ok(None);
        }
        // Precondition: caller should only call for STUN packets
        debug_assert_eq!(PacketType::classify(data), PacketType::Stun, "route_stun_by_ufrag only for STUN");
        
        // Extract USERNAME from raw STUN bytes without full parse.
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let end = STUN_HEADER_SIZE + msg_len;
        if end > data.len() {
            tracing::debug!(from = %from, "STUN message length exceeds packet, dropping");
            return Ok(None);
        }
        
        let mut offset = STUN_HEADER_SIZE;
        let mut username_str: Option<&str> = None;
        
        // Bounded loop: max 16 attribute iterations (TigerStyle)
        const MAX_ATTR_ITERATIONS: usize = 16;
        for _i in 0..MAX_ATTR_ITERATIONS {
            if offset + 4 > end {
                break;
            }
            
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + attr_len > end {
                break;
            }
            
            if attr_type == ATTR_USERNAME {
                if let Ok(s) = std::str::from_utf8(&data[offset..offset + attr_len]) {
                    username_str = Some(s);
                }
                break;
            }
            
            // Advance with 4-byte padding
            offset += (attr_len + 3) & !3;
        }
        
        let username = match username_str {
            Some(u) => u,
            None => {
                tracing::debug!(from = %from, "No USERNAME attribute in STUN packet, dropping");
                return Ok(None);
            }
        };
        
        // Parse local_ufrag from "local_ufrag:remote_ufrag"
        let local_ufrag = match username.split_once(':') {
            Some((local, _)) => local,
            None => {
                tracing::debug!(from = %from, username = %username, "USERNAME missing ':' separator, dropping");
                return Ok(None);
            }
        };
        
        // Lock-free O(1) lookup by ufrag
        let ufrag_map = self.ufrag_to_session.load();
        let session_id = match ufrag_map.get(local_ufrag) {
            Some(&id) => id,
            None => {
                tracing::debug!(from = %from, ufrag = %local_ufrag, "No session for ufrag, dropping");
                return Ok(None);
            }
        };
        
        // Per-session lock
        let entry = match self.sessions.get(&session_id) {
            Some(e) => e,
            None => {
                tracing::debug!(session_id = session_id.value(), "Stale ufrag mapping, session gone");
                return Ok(None);
            }
        };
        
        let mut session = entry.value().lock();
        
        match session.process_incoming(data, from, out) {
            Ok(incoming @ IncomingData::Stun(_)) | Ok(incoming @ IncomingData::StunAndDtls(_, _)) => {
                // Drop session lock before updating routing map
                drop(session);
                drop(entry);
                
                // Associate address with this session via copy-on-write
                self.addr_to_session.rcu(|current| {
                    let mut new_map = (**current).clone();
                    new_map.insert(from, session_id);
                    Arc::new(new_map)
                });
                
                tracing::info!(
                    session_id = session_id.value(),
                    address = %from,
                    ufrag = %local_ufrag,
                    "Routed STUN by ufrag, associated address"
                );
                
                Ok(Some((session_id, incoming)))
            }
            Ok(IncomingData::None) => {
                drop(session);
                drop(entry);
                
                self.addr_to_session.rcu(|current| {
                    let mut new_map = (**current).clone();
                    new_map.insert(from, session_id);
                    Arc::new(new_map)
                });
                Ok(None)
            }
            Ok(other) => Ok(Some((session_id, other))),
            Err(e) => {
                tracing::debug!(
                    session_id = session_id.value(),
                    error = ?e,
                    "STUN processing error for ufrag-matched session"
                );
                Err(e)
            }
        }
    }
    
    // ========================================================================
    // Send Operations
    // ========================================================================
    
    /// Send RTP packet through session.
    ///
    /// # TigerStyle
    /// - Precondition: session exists and is established
    /// - Postcondition: stats updated
    pub fn send_rtp(
        &self,
        session_id: TransportId,
        rtp_data: &[u8],
    ) -> Result<Vec<u8>, WebRtcError> {
        if rtp_data.len() < 12 {
            return Err(WebRtcError::PacketTooShort);
        }
        
        let entry = self.sessions.get(&session_id)
            .ok_or(WebRtcError::InvalidState)?;
        let mut session = entry.value().lock();
        
        // Buffer must accommodate MAX_PACKET_SIZE + auth tag overhead
        let mut buffer = vec![0u8; rtp_data.len() + 64];
        let len = rtp_data.len();
        buffer[..len].copy_from_slice(rtp_data);
        
        let protected_len = session.protect_rtp(&mut buffer, len)?;
        
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(protected_len as u64, Ordering::Relaxed);
        self.stats.rtp_packets_sent.fetch_add(1, Ordering::Relaxed);
        
        Ok(buffer[..protected_len].to_vec())
    }
    
    /// Send RTCP packet through session.
    ///
    /// # TigerStyle
    /// - Precondition: session exists and is established
    /// - Postcondition: stats updated
    pub fn send_rtcp(
        &self,
        session_id: TransportId,
        rtcp_data: &[u8],
    ) -> Result<Vec<u8>, WebRtcError> {
        if rtcp_data.len() < 8 {
            return Err(WebRtcError::PacketTooShort);
        }
        
        let entry = self.sessions.get(&session_id)
            .ok_or(WebRtcError::InvalidState)?;
        let mut session = entry.value().lock();
        
        // Buffer must accommodate data + SRTCP index (4) + auth tag overhead
        let mut buffer = vec![0u8; rtcp_data.len() + 64];
        let len = rtcp_data.len();
        buffer[..len].copy_from_slice(rtcp_data);
        
        let protected_len = session.protect_rtcp(&mut buffer, len)?;
        
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(protected_len as u64, Ordering::Relaxed);
        self.stats.rtcp_packets_sent.fetch_add(1, Ordering::Relaxed);
        
        Ok(buffer[..protected_len].to_vec())
    }
    
    // ========================================================================
    // Session Management
    // ========================================================================
    
    /// Get all session IDs.
    pub fn session_ids(&self) -> Vec<TransportId> {
        self.sessions.iter().map(|entry| *entry.key()).collect()
    }
    
    /// Get connected session count.
    pub fn connected_session_count(&self) -> usize {
        self.sessions.iter()
            .filter(|entry| entry.value().lock().state() == SessionState::Established)
            .count()
    }
    
    /// Cleanup disconnected sessions.
    ///
    /// # TigerStyle
    /// - Bounded iteration
    /// - Returns count of removed sessions
    pub fn cleanup_disconnected(&self) -> usize {
        let disconnected: Vec<_> = self.sessions.iter()
            .filter(|entry| {
                let state = entry.value().lock().state();
                matches!(state, SessionState::Failed | SessionState::Closed)
            })
            .map(|entry| *entry.key())
            .collect();
        
        let count = disconnected.len();
        for id in disconnected {
            self.remove_session(id);
        }
        
        if count > 0 {
            tracing::info!(count, "Cleaned up disconnected sessions");
        }
        
        count
    }
    
    // ========================================================================
    // Timeout-Based Cleanup
    // ========================================================================
    
    /// Cleanup timed out sessions.
    pub fn cleanup_timed_out_sessions(&self) -> Vec<TransportId> {
        let mut timed_out = Vec::new();
        
        for entry in self.sessions.iter() {
            if entry.value().lock().check_state_timeouts().is_err() {
                timed_out.push(*entry.key());
            }
        }
        
        let removed: Vec<_> = timed_out.iter()
            .filter(|id| self.remove_session(**id))
            .copied()
            .collect();
        
        if !removed.is_empty() {
            tracing::info!(count = removed.len(), "Cleaned up timed-out sessions");
        }
        
        removed
    }
    
    /// Check consent freshness for all sessions.
    ///
    /// RFC 7675: Marks sessions with stale consent as failed.
    pub fn check_consent_freshness(&self) -> Vec<TransportId> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        let timeout_ns = self.config.consent_timeout_secs * 1_000_000_000;
        
        let mut stale = Vec::new();
        
        for entry in self.sessions.iter() {
            let session = entry.value().lock();
            if session.state() != SessionState::Established {
                continue;
            }
            
            let last_activity = session.last_activity_ns();
            let idle_ns = now_ns.saturating_sub(last_activity);
            
            if idle_ns > timeout_ns {
                stale.push(*entry.key());
                tracing::warn!(
                    session_id = entry.key().value(),
                    idle_secs = idle_ns / 1_000_000_000,
                    "Session consent stale"
                );
            }
        }
        
        // Close and remove stale sessions
        let mut failed = Vec::new();
        for id in stale {
            if let Some(entry) = self.sessions.get(&id) {
                entry.value().lock().close();
                failed.push(id);
            }
        }
        
        for id in &failed {
            self.remove_session(*id);
        }
        
        if !failed.is_empty() {
            tracing::info!(count = failed.len(), "Closed sessions with stale consent");
        }
        
        failed
    }
    
    /// Cleanup idle sessions that have not had activity for the specified timeout.
    pub fn cleanup_idle_sessions(&self, idle_timeout_secs: u64) -> Vec<TransportId> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        let timeout_ns = idle_timeout_secs * 1_000_000_000;
        
        let idle: Vec<_> = self.sessions.iter()
            .filter(|entry| {
                let last_activity = entry.value().lock().last_activity_ns();
                now_ns.saturating_sub(last_activity) > timeout_ns
            })
            .map(|entry| *entry.key())
            .collect();
        
        let removed_ids = idle.clone();
        for id in idle {
            self.remove_session(id);
        }
        
        if !removed_ids.is_empty() {
            tracing::info!(count = removed_ids.len(), "Cleaned up idle sessions");
        }
        
        removed_ids
    }
}

impl std::fmt::Debug for WebRtcTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcTransport")
            .field("state", &*self.state.lock())
            .field("session_count", &self.sessions.len())
            .field("address_mappings", &self.addr_to_session.load().len())
            .field("stats", &self.stats)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::DtlsRole;

    #[test]
    fn test_transport_creation() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        
        assert_eq!(transport.state(), TransportState::New);
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_transport_start_stop() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        
        transport.start().unwrap();
        assert_eq!(transport.state(), TransportState::Running);
        
        transport.stop();
        assert_eq!(transport.state(), TransportState::Stopped);
    }

    #[test]
    fn test_create_session() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        let dtls = DtlsParameters::new(DtlsRole::Server);
        
        let id = transport.create_session(dtls).unwrap();
        
        assert_eq!(transport.session_count(), 1);
        assert!(transport.with_session(id, |_| ()).is_some());
    }

    #[test]
    fn test_remove_session() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let id = transport.create_session(dtls).unwrap();
        
        transport.remove_session(id);
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_address_association() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let id = transport.create_session(dtls).unwrap();
        
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        transport.associate_address(addr, id);
        
        assert_eq!(transport.find_session_by_addr(&addr), Some(id));
    }

    #[test]
    fn test_max_sessions() {
        let config = TransportConfig::default().with_max_sessions(2);
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create 2 sessions (max)
        for _i in 0..2 {
            let dtls = DtlsParameters::new(DtlsRole::Server);
            transport.create_session(dtls).unwrap();
        }
        
        // Third should fail with TooManySessions
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let result = transport.create_session(dtls);
        assert!(matches!(result, Err(WebRtcError::TooManySessions)));
    }

    #[test]
    fn test_session_ids() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        let mut ids = Vec::new();
        for _i in 0..3 {
            let dtls = DtlsParameters::new(DtlsRole::Server);
            ids.push(transport.create_session(dtls).unwrap());
        }
        
        let retrieved_ids = transport.session_ids();
        assert_eq!(retrieved_ids.len(), 3);
        for id in ids {
            assert!(retrieved_ids.contains(&id));
        }
    }
    
    #[test]
    fn test_cleanup_idle_sessions() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create a session
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let id = transport.create_session(dtls).unwrap();
        
        assert_eq!(transport.session_count(), 1);
        
        // With a very short timeout, session should be cleaned up
        std::thread::sleep(std::time::Duration::from_millis(10));
        let removed = transport.cleanup_idle_sessions(0);
        
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], id);
        assert_eq!(transport.session_count(), 0);
    }
    
    #[test]
    fn test_cleanup_idle_sessions_keeps_active() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create a session
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let id = transport.create_session(dtls).unwrap();
        
        // With a long timeout, session should NOT be cleaned up
        let removed = transport.cleanup_idle_sessions(3600); // 1 hour
        
        assert!(removed.is_empty());
        assert_eq!(transport.session_count(), 1);
        assert!(transport.with_session(id, |_| ()).is_some());
    }
    
    #[test]
    fn test_cleanup_timed_out_sessions() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create a session
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let _id = transport.create_session(dtls).unwrap();
        
        // Session is in New state, no timeout should occur
        let removed = transport.cleanup_timed_out_sessions();
        assert!(removed.is_empty());
    }
    
    #[test]
    fn test_consent_freshness_check() {
        let config = TransportConfig::default().with_consent_timeout(30);
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create a session
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let _id = transport.create_session(dtls).unwrap();
        
        // Session is in New state, consent check shouldn't affect it
        let failed = transport.check_consent_freshness();
        assert!(failed.is_empty());
    }
    
    #[test]
    fn test_connected_session_count() {
        let config = TransportConfig::default();
        let transport = WebRtcTransport::new(config).unwrap();
        transport.start().unwrap();
        
        // Create sessions
        let dtls = DtlsParameters::new(DtlsRole::Server);
        let _id = transport.create_session(dtls).unwrap();
        
        // No sessions are established yet
        assert_eq!(transport.connected_session_count(), 0);
    }
}

// ============================================================================
// Compile-Time Assertions
// ============================================================================

const _: () = assert!(
    MAX_SESSIONS <= 10000,
    "MAX_SESSIONS must be bounded to prevent memory exhaustion"
);

const _: () = assert!(
    MAX_ADDRESS_MAPPINGS <= 100000,
    "MAX_ADDRESS_MAPPINGS must be bounded"
);

const _: () = assert!(
    DEFAULT_CONSENT_TIMEOUT_SECS >= 5 && DEFAULT_CONSENT_TIMEOUT_SECS <= 300,
    "Consent timeout must be between 5 and 300 seconds"
);
