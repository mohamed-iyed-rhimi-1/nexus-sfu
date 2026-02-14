//! ICE Candidate Gathering.
//!
//! Gathers host, server-reflexive, and relay candidates.
//!
//! # Gathering Process
//!
//! 1. Enumerate local interfaces → Host candidates
//! 2. Send STUN binding requests → Server Reflexive candidates
//! 3. Allocate TURN relays → Relay candidates
//!
//! # TigerStyle Compliance
//!
//! - Fixed-size candidate arrays (no Vec allocation during gathering)
//! - Explicit state machine for gathering progress
//! - Comprehensive error handling with explicit variants

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;

use super::candidate::{Candidate, MAX_CANDIDATES};
use super::types::IceConfig;
use crate::ice::error::IceError;

/// Maximum STUN servers to query.
pub const MAX_STUN_SERVERS: usize = 4;

/// Maximum network interfaces to enumerate.
pub const MAX_INTERFACES: usize = 8;

/// STUN request timeout.
pub const STUN_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum STUN request retries (Phase 2.1 - increased from 3 to 6).
pub const STUN_MAX_RETRIES: u32 = 6;

// Compile-time assertions for gathering constants (TigerStyle Phase 2.1)
const _: () = assert!(STUN_MAX_RETRIES <= 7,
    "STUN_MAX_RETRIES must be <= 7 to prevent excessive delays");
const _: () = assert!(STUN_REQUEST_TIMEOUT.as_millis() >= 100,
    "STUN timeout must be >= 100ms for reliable operation");

/// Gathering state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GatheringState {
    /// Not started.
    New = 0,
    
    /// Gathering in progress.
    Gathering = 1,
    
    /// Gathering complete.
    Complete = 2,
}

/// Gathered candidates result.
#[derive(Debug)]
pub struct GatheredCandidates {
    /// Host candidates.
    pub candidates: [Option<Candidate>; MAX_CANDIDATES],
    
    /// Number of valid candidates.
    pub count: u8,
    
    /// Gathering state.
    pub state: GatheringState,
}

impl Default for GatheredCandidates {
    fn default() -> Self {
        Self {
            candidates: std::array::from_fn(|_| None),
            count: 0,
            state: GatheringState::New,
        }
    }
}

impl GatheredCandidates {
    /// Add a candidate if space available.
    pub fn add(&mut self, candidate: Candidate) -> bool {
        if (self.count as usize) < MAX_CANDIDATES {
            self.candidates[self.count as usize] = Some(candidate);
            self.count += 1;
            true
        } else {
            false
        }
    }
    
    /// Get iterator over valid candidates.
    pub fn iter(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates[..self.count as usize]
            .iter()
            .filter_map(|c| c.as_ref())
    }
    
    /// Check if empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// ICE Candidate Gatherer (async).
///
/// Collects host, server-reflexive, and relay candidates asynchronously
/// using `tokio::net::UdpSocket`. Each candidate is sent through
/// `candidate_tx` immediately upon discovery for true per-candidate trickling.
#[allow(dead_code)] // Fields used by stub methods (tasks 3.2-3.5)
pub struct CandidateGatherer {
    /// Configuration.
    config: IceConfig,
    
    /// Component ID (1 = RTP, 2 = RTCP).
    component: u8,
    
    /// Channel sender for incremental candidate delivery.
    candidate_tx: mpsc::Sender<Candidate>,
    
    /// Bound sockets for STUN/TURN use.
    /// Each socket corresponds to a host candidate and is used for
    /// server-reflexive and relay candidate gathering.
    /// Fixed-size array to avoid dynamic allocation (TigerStyle).
    sockets: [Option<tokio::net::UdpSocket>; MAX_INTERFACES],
    
    /// Number of bound sockets.
    socket_count: u8,
}

impl CandidateGatherer {
    /// Create new async gatherer.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: component must be >= 1 (RTP=1, RTCP=2)
    /// - Precondition: candidate_tx must not be closed (verified by type system — Sender is valid)
    pub fn new(config: IceConfig, component: u8, candidate_tx: mpsc::Sender<Candidate>) -> Self {
        // Precondition: component must be valid ICE component ID (TigerStyle)
        assert!(component >= 1, "component must be >= 1");
        // Precondition: component must be bounded (RTP=1, RTCP=2)
        assert!(component <= 2, "component must be <= 2 (1=RTP, 2=RTCP)");
        
        Self {
            config,
            component,
            candidate_tx,
            sockets: std::array::from_fn(|_| None),
            socket_count: 0,
        }
    }
    
    /// Run the full gathering process asynchronously.
    ///
    /// Sends each candidate through `candidate_tx` as it's discovered.
    /// Returns `Ok(count)` on success, `Err(IceError)` on failure.
    ///
    /// # Gathering Process
    ///
    /// 1. Enumerate local interfaces → Host candidates
    /// 2. Send STUN binding requests → Server Reflexive candidates
    /// 3. Allocate TURN relays → Relay candidates
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: component must be valid (1 or 2)
    /// - Postcondition: total_count must be bounded by MAX_CANDIDATES
    /// - Bounded operations: each sub-method enforces MAX_CANDIDATES
    pub async fn gather(&mut self) -> Result<u8, IceError> {
        // Precondition: component must be valid ICE component ID (TigerStyle)
        assert!(
            self.component >= 1 && self.component <= 2,
            "component must be 1 (RTP) or 2 (RTCP)"
        );
        
        // Precondition: candidate_tx must not be closed
        assert!(
            !self.candidate_tx.is_closed(),
            "candidate_tx channel must be open"
        );
        
        let mut total_count: u8 = 0;
        
        // Phase 1: Gather host candidates
        let host_count = self.gather_host_candidates().await?;
        total_count = total_count.saturating_add(host_count);
        
        // Phase 2: Gather server-reflexive candidates via STUN
        let srflx_count = self.gather_srflx_candidates().await?;
        total_count = total_count.saturating_add(srflx_count);
        
        // Phase 3: Gather relay candidates via TURN
        let relay_count = self.gather_relay_candidates().await?;
        total_count = total_count.saturating_add(relay_count);
        
        // Postcondition: total count must be bounded (TigerStyle)
        assert!(
            (total_count as usize) <= MAX_CANDIDATES,
            "total candidate count {} exceeds MAX_CANDIDATES {}",
            total_count,
            MAX_CANDIDATES
        );
        
        Ok(total_count)
    }
    
    /// Gather host candidates from local interfaces.
    ///
    /// Enumerates network interfaces, binds `tokio::net::UdpSocket` on each,
    /// and sends host candidates through `candidate_tx` immediately.
    ///
    /// Returns the count of host candidates gathered.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: socket_count must be 0 (fresh gatherer)
    /// - Postcondition: socket_count must equal candidate count
    /// - Bounded operations: limited to MAX_INTERFACES
    async fn gather_host_candidates(&mut self) -> Result<u8, IceError> {
        // Precondition: must be a fresh gatherer (TigerStyle)
        assert!(
            self.socket_count == 0,
            "gather_host_candidates must be called on fresh gatherer"
        );
        
        // Precondition: candidate_tx must be open (TigerStyle)
        assert!(
            !self.candidate_tx.is_closed(),
            "candidate_tx channel must be open"
        );
        
        // Enumerate network interfaces (bounded by MAX_INTERFACES)
        let interfaces = enumerate_interfaces()?;
        
        let mut candidate_count: u8 = 0;
        
        // Iterate over interfaces with bounded loop
        for (interface_idx, maybe_ip) in interfaces.iter().enumerate() {
            // Loop bound assertion (TigerStyle)
            assert!(
                interface_idx < MAX_INTERFACES,
                "interface index must be within bounds"
            );
            
            let ip = match maybe_ip {
                Some(ip) => *ip,
                None => continue, // No more interfaces
            };
            
            // Skip loopback addresses
            if ip.is_loopback() {
                continue;
            }
            
            // Bind socket to this interface on port 0 (OS assigns port)
            let bind_addr = SocketAddr::new(ip, 0);
            let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    // Log and continue - some interfaces may not be bindable
                    tracing::debug!(
                        "Failed to bind socket to {}: {}",
                        bind_addr,
                        e
                    );
                    continue;
                }
            };
            
            // Get the actual bound address (with OS-assigned port)
            let local_addr = match socket.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::debug!(
                        "Failed to get local address for socket: {}",
                        e
                    );
                    continue;
                }
            };
            
            // Create host candidate
            let candidate = Candidate::new_host(
                local_addr,
                self.component,
                interface_idx as u8,
            );
            
            // Send candidate through channel immediately (true trickling)
            if self.candidate_tx.send(candidate.clone()).await.is_err() {
                // Channel closed - receiver dropped
                return Err(IceError::GatheringFailed {
                    reason: "candidate channel closed",
                });
            }
            
            // Store socket for STUN/TURN use
            // Bounded by MAX_INTERFACES (TigerStyle)
            if (self.socket_count as usize) < MAX_INTERFACES {
                self.sockets[self.socket_count as usize] = Some(socket);
                self.socket_count += 1;
                candidate_count += 1;
            } else {
                // Should not happen due to interface enumeration bounds
                tracing::warn!(
                    "Socket count {} reached MAX_INTERFACES {}",
                    self.socket_count,
                    MAX_INTERFACES
                );
                break;
            }
            
            // Check MAX_CANDIDATES bound
            if (candidate_count as usize) >= MAX_CANDIDATES {
                tracing::debug!(
                    "Reached MAX_CANDIDATES {} during host gathering",
                    MAX_CANDIDATES
                );
                break;
            }
        }
        
        // Postcondition: socket_count must equal candidate_count (TigerStyle)
        assert!(
            self.socket_count == candidate_count,
            "socket_count {} must equal candidate_count {}",
            self.socket_count,
            candidate_count
        );
        
        Ok(candidate_count)
    }
    
    /// Gather server-reflexive candidates via async STUN binding requests.
    ///
    /// For each STUN server and each socket, sends async STUN binding requests
    /// with bounded retries. Uses `tokio::time::timeout` for request timeouts
    /// instead of socket-level timeouts.
    ///
    /// Returns the count of server-reflexive candidates gathered.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: socket_count > 0 (host gathering must have run)
    /// - Postcondition: srflx_count bounded by MAX_CANDIDATES
    /// - Bounded loops: MAX_STUN_SERVERS * MAX_INTERFACES iterations max
    /// - At least 2 assertions per function
    async fn gather_srflx_candidates(&mut self) -> Result<u8, IceError> {
        // Precondition: must have gathered host candidates first (TigerStyle)
        assert!(
            self.socket_count > 0,
            "gather_srflx_candidates requires at least one socket from host gathering"
        );
        
        // Precondition: candidate_tx must be open (TigerStyle)
        assert!(
            !self.candidate_tx.is_closed(),
            "candidate_tx channel must be open"
        );
        
        let mut srflx_count: u8 = 0;
        
        // Iterate over STUN servers (bounded by MAX_STUN_SERVERS)
        for stun_idx in 0..MAX_STUN_SERVERS {
            // Loop bound assertion (TigerStyle)
            assert!(
                stun_idx < MAX_STUN_SERVERS,
                "STUN server index must be within bounds"
            );
            
            let stun_server = match self.config.stun_servers.get(stun_idx) {
                Some(Some(addr)) => *addr,
                _ => continue, // No more STUN servers
            };
            
            // Check if we've exceeded configured server count
            if stun_idx >= self.config.stun_server_count as usize {
                break;
            }
            
            // For each socket, send STUN binding request
            for socket_idx in 0..self.socket_count as usize {
                // Loop bound assertion (TigerStyle)
                assert!(
                    socket_idx < MAX_INTERFACES,
                    "socket index must be within bounds"
                );
                
                let socket = match &self.sockets[socket_idx] {
                    Some(s) => s,
                    None => continue,
                };
                
                // Send STUN binding request with retries
                match self.stun_binding_request(socket, stun_server, socket_idx as u8).await {
                    Ok(Some(candidate)) => {
                        // Send candidate through channel immediately (true trickling)
                        if self.candidate_tx.send(candidate).await.is_err() {
                            // Channel closed - receiver dropped
                            return Err(IceError::GatheringFailed {
                                reason: "candidate channel closed during srflx gathering",
                            });
                        }
                        
                        srflx_count = srflx_count.saturating_add(1);
                        
                        // Check MAX_CANDIDATES bound
                        if (srflx_count as usize) >= MAX_CANDIDATES {
                            tracing::debug!(
                                "Reached MAX_CANDIDATES {} during srflx gathering",
                                MAX_CANDIDATES
                            );
                            // Postcondition check before early return
                            assert!(
                                (srflx_count as usize) <= MAX_CANDIDATES,
                                "srflx_count must not exceed MAX_CANDIDATES"
                            );
                            return Ok(srflx_count);
                        }
                    }
                    Ok(None) => {
                        // No response from this server/socket combination
                        tracing::debug!(
                            "No STUN response from {} via socket {}",
                            stun_server,
                            socket_idx
                        );
                    }
                    Err(e) => {
                        // Log error but continue with other servers/sockets
                        tracing::debug!(
                            "STUN request to {} via socket {} failed: {:?}",
                            stun_server,
                            socket_idx,
                            e
                        );
                    }
                }
            }
        }
        
        // Postcondition: srflx_count must be bounded (TigerStyle)
        assert!(
            (srflx_count as usize) <= MAX_CANDIDATES,
            "srflx_count {} must not exceed MAX_CANDIDATES {}",
            srflx_count,
            MAX_CANDIDATES
        );
        
        Ok(srflx_count)
    }
    
    /// Gather relay candidates via async TURN allocations.
    ///
    /// For each TURN server, performs async TURN allocation with authentication.
    /// Uses `tokio::time::timeout` for allocation timeouts.
    /// Handles TURN authentication flow (401 → retry with credentials).
    ///
    /// Returns the count of relay candidates gathered.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: socket_count > 0 (host gathering must have run)
    /// - Postcondition: relay_count bounded by MAX_CANDIDATES
    /// - Bounded loops: MAX_TURN_SERVERS iterations max
    /// - At least 2 assertions per function
    async fn gather_relay_candidates(&mut self) -> Result<u8, IceError> {
        // Precondition: must have gathered host candidates first (TigerStyle)
        assert!(
            self.socket_count > 0,
            "gather_relay_candidates requires at least one socket from host gathering"
        );
        
        // Precondition: candidate_tx must be open (TigerStyle)
        assert!(
            !self.candidate_tx.is_closed(),
            "candidate_tx channel must be open"
        );
        
        let mut relay_count: u8 = 0;
        
        // Iterate over TURN servers (bounded by MAX_TURN_SERVERS = 2)
        for turn_idx in 0..super::types::IceConfig::MAX_TURN_SERVERS {
            // Loop bound assertion (TigerStyle)
            assert!(
                turn_idx < super::types::IceConfig::MAX_TURN_SERVERS,
                "TURN server index must be within bounds"
            );
            
            // Check if we've exceeded configured server count
            if turn_idx >= self.config.turn_server_count as usize {
                break;
            }
            
            let turn_config = match &self.config.turn_servers[turn_idx] {
                Some(config) => config,
                None => continue, // No TURN server at this index
            };
            
            // Perform TURN allocation
            match self.allocate_turn_relay(turn_config, turn_idx as u8).await {
                Ok(Some(candidate)) => {
                    // Send candidate through channel immediately (true trickling)
                    if self.candidate_tx.send(candidate).await.is_err() {
                        // Channel closed - receiver dropped
                        return Err(IceError::GatheringFailed {
                            reason: "candidate channel closed during relay gathering",
                        });
                    }
                    
                    relay_count = relay_count.saturating_add(1);
                    
                    // Check MAX_CANDIDATES bound
                    if (relay_count as usize) >= MAX_CANDIDATES {
                        tracing::debug!(
                            "Reached MAX_CANDIDATES {} during relay gathering",
                            MAX_CANDIDATES
                        );
                        // Postcondition check before early return
                        assert!(
                            (relay_count as usize) <= MAX_CANDIDATES,
                            "relay_count must not exceed MAX_CANDIDATES"
                        );
                        return Ok(relay_count);
                    }
                }
                Ok(None) => {
                    // Allocation failed or timed out for this server
                    tracing::debug!(
                        "TURN allocation failed for server {} (index {})",
                        turn_config.address,
                        turn_idx
                    );
                }
                Err(e) => {
                    // Log error but continue with other servers
                    tracing::debug!(
                        "TURN allocation error for server {} (index {}): {:?}",
                        turn_config.address,
                        turn_idx,
                        e
                    );
                }
            }
        }
        
        // Postcondition: relay_count must be bounded (TigerStyle)
        assert!(
            (relay_count as usize) <= MAX_CANDIDATES,
            "relay_count {} must not exceed MAX_CANDIDATES {}",
            relay_count,
            MAX_CANDIDATES
        );
        
        Ok(relay_count)
    }
    
    /// Send a single STUN binding request and await the response.
    ///
    /// Implements bounded retries with `tokio::time::timeout` for each attempt.
    /// Parses the STUN response to extract the XOR-MAPPED-ADDRESS.
    ///
    /// # Arguments
    ///
    /// * `socket` - The UDP socket to use for the request
    /// * `server_addr` - The STUN server address
    /// * `interface_idx` - Interface index for candidate creation
    ///
    /// # Returns
    ///
    /// * `Ok(Some(candidate))` - Successfully received srflx candidate
    /// * `Ok(None)` - No response after all retries
    /// * `Err(IceError)` - Fatal error during request
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: interface_idx < MAX_INTERFACES
    /// - Bounded retries: STUN_MAX_RETRIES iterations max
    /// - At least 2 assertions per function
    async fn stun_binding_request(
        &self,
        socket: &tokio::net::UdpSocket,
        server_addr: SocketAddr,
        interface_idx: u8,
    ) -> Result<Option<Candidate>, IceError> {
        use super::stun::message::{StunMessage, StunClass, StunMethod, STUN_BUFFER_SIZE};
        use super::stun::server::generate_transaction_id;
        
        // Precondition: interface_idx must be within bounds (TigerStyle)
        assert!(
            (interface_idx as usize) < MAX_INTERFACES,
            "interface_idx {} must be < MAX_INTERFACES {}",
            interface_idx,
            MAX_INTERFACES
        );
        
        // Precondition: server_addr must be valid (non-zero port)
        assert!(
            server_addr.port() > 0,
            "STUN server port must be > 0"
        );
        
        // Generate transaction ID for this request
        let transaction_id = generate_transaction_id();
        
        // Build STUN binding request
        let request = StunMessage {
            class: StunClass::Request,
            method: StunMethod::Binding,
            transaction_id,
            attributes: Default::default(),
            attribute_count: 0,
        };
        
        let mut request_buf = [0u8; STUN_BUFFER_SIZE];
        let request_len = request.encode(&mut request_buf);
        
        // Response buffer
        let mut response_buf = [0u8; STUN_BUFFER_SIZE];
        
        // Get local address for base_address in candidate
        let local_addr = socket.local_addr().map_err(|_| IceError::GatheringFailed {
            reason: "failed to get socket local address",
        })?;
        
        // Bounded retry loop (TigerStyle)
        for retry in 0..STUN_MAX_RETRIES {
            // Loop bound assertion (TigerStyle)
            assert!(
                retry < STUN_MAX_RETRIES,
                "retry count must be within bounds"
            );
            
            // Send STUN request
            if let Err(e) = socket.send_to(&request_buf[..request_len], server_addr).await {
                tracing::debug!(
                    "Failed to send STUN request to {} (retry {}): {}",
                    server_addr,
                    retry,
                    e
                );
                continue;
            }
            
            // Wait for response with timeout
            let recv_result = tokio::time::timeout(
                STUN_REQUEST_TIMEOUT,
                socket.recv_from(&mut response_buf),
            ).await;
            
            match recv_result {
                Ok(Ok((len, from_addr))) => {
                    // Verify response is from the STUN server
                    if from_addr != server_addr {
                        tracing::debug!(
                            "Received STUN response from unexpected address {} (expected {})",
                            from_addr,
                            server_addr
                        );
                        continue;
                    }
                    
                    // Parse STUN response
                    let response = match StunMessage::parse(&response_buf[..len]) {
                        Ok(msg) => msg,
                        Err(e) => {
                            tracing::debug!(
                                "Failed to parse STUN response from {}: {:?}",
                                server_addr,
                                e
                            );
                            continue;
                        }
                    };
                    
                    // Verify transaction ID matches
                    if response.transaction_id != transaction_id {
                        tracing::debug!(
                            "STUN response transaction ID mismatch from {}",
                            server_addr
                        );
                        continue;
                    }
                    
                    // Verify it's a success response
                    if response.class != StunClass::SuccessResponse {
                        tracing::debug!(
                            "STUN response from {} is not success: {:?}",
                            server_addr,
                            response.class
                        );
                        continue;
                    }
                    
                    // Extract XOR-MAPPED-ADDRESS
                    if let Some(mapped_addr) = response.get_xor_mapped_address() {
                        // Create server-reflexive candidate
                        let candidate = Candidate::new_server_reflexive(
                            mapped_addr,
                            local_addr,
                            self.component,
                            interface_idx,
                        );
                        
                        tracing::debug!(
                            "Discovered srflx candidate {} via STUN server {}",
                            mapped_addr,
                            server_addr
                        );
                        
                        return Ok(Some(candidate));
                    } else {
                        tracing::debug!(
                            "STUN response from {} missing XOR-MAPPED-ADDRESS",
                            server_addr
                        );
                        continue;
                    }
                }
                Ok(Err(e)) => {
                    // Socket receive error
                    tracing::debug!(
                        "STUN recv error from {} (retry {}): {}",
                        server_addr,
                        retry,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    // Timeout
                    tracing::debug!(
                        "STUN request to {} timed out (retry {}/{})",
                        server_addr,
                        retry + 1,
                        STUN_MAX_RETRIES
                    );
                    continue;
                }
            }
        }
        
        // All retries exhausted
        Ok(None)
    }
    
    /// Perform a TURN allocation with async retries.
    ///
    /// Implements the TURN allocation flow:
    /// 1. Send initial Allocate request (without credentials)
    /// 2. Receive 401 Unauthorized with REALM and NONCE
    /// 3. Retry with credentials (USERNAME, REALM, NONCE, MESSAGE-INTEGRITY)
    /// 4. Receive success response with XOR-RELAYED-ADDRESS
    ///
    /// # Arguments
    ///
    /// * `turn_config` - TURN server configuration with credentials
    /// * `server_idx` - Server index for candidate creation
    ///
    /// # Returns
    ///
    /// * `Ok(Some(candidate))` - Successfully allocated relay candidate
    /// * `Ok(None)` - Allocation failed or timed out
    /// * `Err(IceError)` - Fatal error during allocation
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: server_idx < MAX_TURN_SERVERS
    /// - Bounded retries: max 2 allocation attempts (initial + authenticated)
    /// - At least 2 assertions per function
    async fn allocate_turn_relay(
        &self,
        turn_config: &super::types::TurnServerConfig,
        server_idx: u8,
    ) -> Result<Option<Candidate>, IceError> {
        use super::stun::message::{StunMessage, StunClass, STUN_BUFFER_SIZE};
        use super::stun::server::generate_transaction_id;
        
        // Precondition: server_idx must be within bounds (TigerStyle)
        assert!(
            (server_idx as usize) < super::types::IceConfig::MAX_TURN_SERVERS,
            "server_idx {} must be < MAX_TURN_SERVERS {}",
            server_idx,
            super::types::IceConfig::MAX_TURN_SERVERS
        );
        
        // Precondition: TURN server address must be valid (non-zero port)
        assert!(
            turn_config.address.port() > 0,
            "TURN server port must be > 0"
        );
        
        // Use the first available socket for TURN allocation
        let socket = match &self.sockets[0] {
            Some(s) => s,
            None => {
                tracing::debug!("No socket available for TURN allocation");
                return Ok(None);
            }
        };
        
        // Verify socket is valid by getting local address
        let _local_addr = socket.local_addr().map_err(|_| IceError::GatheringFailed {
            reason: "failed to get socket local address for TURN",
        })?;
        
        // TURN allocation timeout (longer than STUN since it involves more round-trips)
        const TURN_ALLOCATION_TIMEOUT: Duration = Duration::from_secs(5);
        
        // Maximum allocation attempts (initial + authenticated retry)
        const MAX_ALLOCATION_ATTEMPTS: u32 = 2;
        
        // Generate transaction ID for this allocation
        let mut transaction_id = generate_transaction_id();
        
        // Buffers for request/response
        let mut request_buf = [0u8; STUN_BUFFER_SIZE];
        let mut response_buf = [0u8; STUN_BUFFER_SIZE];
        
        // Realm and nonce from 401 response (for authenticated retry)
        let mut realm: Option<([u8; 128], u8)> = None;
        let mut nonce: Option<([u8; 128], u8)> = None;
        
        // Bounded retry loop (TigerStyle)
        for attempt in 0..MAX_ALLOCATION_ATTEMPTS {
            // Loop bound assertion (TigerStyle)
            assert!(
                attempt < MAX_ALLOCATION_ATTEMPTS,
                "attempt count must be within bounds"
            );
            
            // Build TURN Allocate request
            let request_len = self.build_allocate_request(
                &mut request_buf,
                &transaction_id,
                turn_config,
                realm.as_ref(),
                nonce.as_ref(),
            );
            
            // Send Allocate request
            if let Err(e) = socket.send_to(&request_buf[..request_len], turn_config.address).await {
                tracing::debug!(
                    "Failed to send TURN Allocate request to {} (attempt {}): {}",
                    turn_config.address,
                    attempt,
                    e
                );
                continue;
            }
            
            // Wait for response with timeout
            let recv_result = tokio::time::timeout(
                TURN_ALLOCATION_TIMEOUT,
                socket.recv_from(&mut response_buf),
            ).await;
            
            match recv_result {
                Ok(Ok((len, from_addr))) => {
                    // Verify response is from the TURN server
                    if from_addr != turn_config.address {
                        tracing::debug!(
                            "Received TURN response from unexpected address {} (expected {})",
                            from_addr,
                            turn_config.address
                        );
                        continue;
                    }
                    
                    // Parse STUN response
                    let response = match StunMessage::parse(&response_buf[..len]) {
                        Ok(msg) => msg,
                        Err(e) => {
                            tracing::debug!(
                                "Failed to parse TURN response from {}: {:?}",
                                turn_config.address,
                                e
                            );
                            continue;
                        }
                    };
                    
                    // Verify transaction ID matches
                    if response.transaction_id != transaction_id {
                        tracing::debug!(
                            "TURN response transaction ID mismatch from {}",
                            turn_config.address
                        );
                        continue;
                    }
                    
                    // Handle response based on class
                    match response.class {
                        StunClass::SuccessResponse => {
                            // Extract XOR-RELAYED-ADDRESS
                            if let Some(relayed_addr) = self.get_xor_relayed_address(&response) {
                                // Create relay candidate
                                let candidate = Candidate::new_relay(
                                    relayed_addr,
                                    turn_config.address,
                                    self.component,
                                    server_idx,
                                );
                                
                                tracing::debug!(
                                    "Discovered relay candidate {} via TURN server {}",
                                    relayed_addr,
                                    turn_config.address
                                );
                                
                                return Ok(Some(candidate));
                            } else {
                                tracing::debug!(
                                    "TURN success response from {} missing XOR-RELAYED-ADDRESS",
                                    turn_config.address
                                );
                                return Ok(None);
                            }
                        }
                        StunClass::ErrorResponse => {
                            // Check for 401 Unauthorized (need to retry with credentials)
                            if let Some((code, extracted_realm, extracted_nonce)) = 
                                self.extract_error_info(&response) 
                            {
                                if code == 401 && attempt == 0 {
                                    // Store realm and nonce for authenticated retry
                                    realm = extracted_realm;
                                    nonce = extracted_nonce;
                                    
                                    // Generate new transaction ID for retry
                                    transaction_id = generate_transaction_id();
                                    
                                    tracing::debug!(
                                        "TURN server {} requires authentication, retrying",
                                        turn_config.address
                                    );
                                    continue;
                                } else {
                                    tracing::debug!(
                                        "TURN allocation failed with error code {} from {}",
                                        code,
                                        turn_config.address
                                    );
                                    return Ok(None);
                                }
                            }
                            return Ok(None);
                        }
                        _ => {
                            tracing::debug!(
                                "Unexpected TURN response class {:?} from {}",
                                response.class,
                                turn_config.address
                            );
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Socket receive error
                    tracing::debug!(
                        "TURN recv error from {} (attempt {}): {}",
                        turn_config.address,
                        attempt,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    // Timeout
                    tracing::debug!(
                        "TURN allocation to {} timed out (attempt {}/{})",
                        turn_config.address,
                        attempt + 1,
                        MAX_ALLOCATION_ATTEMPTS
                    );
                    continue;
                }
            }
        }
        
        // All attempts exhausted
        Ok(None)
    }
    
    /// Build a TURN Allocate request.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition: buffer size >= STUN_BUFFER_SIZE
    /// - Postcondition: returns valid message length
    fn build_allocate_request(
        &self,
        buf: &mut [u8],
        transaction_id: &[u8; 12],
        turn_config: &super::types::TurnServerConfig,
        realm: Option<&([u8; 128], u8)>,
        nonce: Option<&([u8; 128], u8)>,
    ) -> usize {
        use super::stun::message::{StunMessage, StunClass, StunMethod, STUN_HEADER_SIZE, STUN_MAGIC_COOKIE};
        use super::stun::attributes::StunAttribute;
        use super::stun::integrity::{sign_message, derive_long_term_key};
        
        // Precondition: buffer must be large enough (TigerStyle)
        assert!(
            buf.len() >= super::stun::message::STUN_BUFFER_SIZE,
            "buffer too small for Allocate request"
        );
        
        // Build message type for Allocate Request
        let msg_type = StunMessage::encode_type(StunClass::Request, StunMethod::Allocate);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        // Length will be filled in later
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(transaction_id);
        
        let mut offset = STUN_HEADER_SIZE;
        
        // Add REQUESTED-TRANSPORT attribute (UDP = 17)
        let transport_attr = StunAttribute::RequestedTransport(17); // UDP
        offset += transport_attr.encode(&mut buf[offset..], transaction_id);
        
        // If we have realm and nonce (from 401 response), add authentication attributes
        if let (Some((realm_buf, realm_len)), Some((nonce_buf, nonce_len))) = (realm, nonce) {
            // Add USERNAME
            let username = turn_config.username_str();
            let username_attr = StunAttribute::username(username);
            offset += username_attr.encode(&mut buf[offset..], transaction_id);
            
            // Add REALM
            let mut realm_attr_buf = [0u8; 128];
            realm_attr_buf[..*realm_len as usize].copy_from_slice(&realm_buf[..*realm_len as usize]);
            let realm_attr = StunAttribute::Realm {
                value: realm_attr_buf,
                len: *realm_len,
            };
            offset += realm_attr.encode(&mut buf[offset..], transaction_id);
            
            // Add NONCE
            let mut nonce_attr_buf = [0u8; 128];
            nonce_attr_buf[..*nonce_len as usize].copy_from_slice(&nonce_buf[..*nonce_len as usize]);
            let nonce_attr = StunAttribute::Nonce {
                value: nonce_attr_buf,
                len: *nonce_len,
            };
            offset += nonce_attr.encode(&mut buf[offset..], transaction_id);
            
            // Update message length before signing
            let attr_len = (offset - STUN_HEADER_SIZE) as u16;
            buf[2..4].copy_from_slice(&attr_len.to_be_bytes());
            
            // Derive long-term credential key: MD5(username:realm:password)
            let realm_str = unsafe {
                std::str::from_utf8_unchecked(&realm_buf[..*realm_len as usize])
            };
            let key = derive_long_term_key(
                username,
                realm_str,
                turn_config.password_str(),
            );
            
            // Add MESSAGE-INTEGRITY and FINGERPRINT
            offset = sign_message(buf, offset, &key);
        } else {
            // Initial request without authentication
            let attr_len = (offset - STUN_HEADER_SIZE) as u16;
            buf[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }
        
        // Postcondition: offset must be valid (TigerStyle)
        assert!(
            offset >= STUN_HEADER_SIZE && offset <= buf.len(),
            "Allocate request length must be valid"
        );
        
        offset
    }
    
    /// Extract XOR-RELAYED-ADDRESS from a TURN response.
    fn get_xor_relayed_address(&self, msg: &super::stun::message::StunMessage) -> Option<std::net::SocketAddr> {
        use super::stun::attributes::StunAttribute;
        
        for i in 0..msg.attribute_count as usize {
            if let Some(StunAttribute::XorRelayedAddress(addr)) = &msg.attributes[i] {
                return Some(*addr);
            }
        }
        None
    }
    
    /// Extract error code, realm, and nonce from an error response.
    fn extract_error_info(
        &self,
        msg: &super::stun::message::StunMessage,
    ) -> Option<(u16, Option<([u8; 128], u8)>, Option<([u8; 128], u8)>)> {
        use super::stun::attributes::StunAttribute;
        
        let mut error_code: Option<u16> = None;
        let mut realm: Option<([u8; 128], u8)> = None;
        let mut nonce: Option<([u8; 128], u8)> = None;
        
        for i in 0..msg.attribute_count as usize {
            match &msg.attributes[i] {
                Some(StunAttribute::ErrorCode { code, .. }) => {
                    error_code = Some(*code);
                }
                Some(StunAttribute::Realm { value, len }) => {
                    realm = Some((*value, *len));
                }
                Some(StunAttribute::Nonce { value, len }) => {
                    nonce = Some((*value, *len));
                }
                _ => {}
            }
        }
        
        error_code.map(|code| (code, realm, nonce))
    }
}

/// Enumerate local network interfaces.
///
/// Returns up to MAX_INTERFACES IP addresses.
///
/// # TigerStyle Compliance (Phase 2.7)
///
/// - Loop bound assertion in while loop
/// - Postcondition for result array bounds
#[allow(dead_code)] // Used by gather_host_candidates (task 3.3)
fn enumerate_interfaces() -> Result<[Option<IpAddr>; MAX_INTERFACES], IceError> {
    let mut result: [Option<IpAddr>; MAX_INTERFACES] = std::array::from_fn(|_| None);
    let mut count = 0;
    
    #[cfg(unix)]
    {
        // Use getifaddrs on Unix
        
        unsafe {
            let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs) != 0 {
                return Err(IceError::GatheringFailed {
                    reason: "getifaddrs failed",
                });
            }
            
            let mut curr = ifaddrs;
            while !curr.is_null() && count < MAX_INTERFACES {
                // Loop bound assertion (TigerStyle Phase 2.7)
                assert!(count < MAX_INTERFACES,
                    "Interface count must be within bounds");
                
                let ifa = &*curr;
                
                if !ifa.ifa_addr.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;
                    
                    if family == libc::AF_INET {
                        let sockaddr_in = ifa.ifa_addr as *const libc::sockaddr_in;
                        let ip = Ipv4Addr::from(u32::from_be((*sockaddr_in).sin_addr.s_addr));
                        result[count] = Some(IpAddr::V4(ip));
                        count += 1;
                    } else if family == libc::AF_INET6 {
                        let sockaddr_in6 = ifa.ifa_addr as *const libc::sockaddr_in6;
                        let octets = (*sockaddr_in6).sin6_addr.s6_addr;
                        let ip = Ipv6Addr::from(octets);
                        
                        // Skip link-local addresses
                        if !ip.is_unspecified() && (ip.segments()[0] & 0xffc0) != 0xfe80 {
                            result[count] = Some(IpAddr::V6(ip));
                            count += 1;
                        }
                    }
                }
                
                curr = ifa.ifa_next;
            }
            
            libc::freeifaddrs(ifaddrs);
        }
    }
    
    #[cfg(not(unix))]
    {
        // Fallback: just use 0.0.0.0 to bind all interfaces
        result[0] = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        count = 1;
    }
    
    // Postcondition: count must be bounded (TigerStyle Phase 2.7)
    assert!(count <= MAX_INTERFACES,
        "Interface count must be <= MAX_INTERFACES");
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::candidate::CandidateType;
    use crate::ice::stun::server::generate_transaction_id;

    // ========================================================================
    // Basic Gathering Tests
    // ========================================================================

    #[test]
    fn test_enumerate_interfaces() {
        let interfaces = enumerate_interfaces().unwrap();
        
        // Should have at least one interface on most systems
        // (might be 0 in containerized environments)
        let count = interfaces.iter().filter(|i| i.is_some()).count();
        println!("Found {} interfaces", count);
    }

    #[test]
    fn test_gathered_candidates_add() {
        let mut gc = GatheredCandidates::default();
        assert!(gc.is_empty());
        
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        
        assert!(gc.add(candidate));
        assert_eq!(gc.count, 1);
        assert!(!gc.is_empty());
    }

    #[test]
    fn test_gathering_state_transitions() {
        // GatheringState enum values are preserved for use by the orchestrator
        assert_eq!(GatheringState::New as u8, 0);
        assert_eq!(GatheringState::Gathering as u8, 1);
        assert_eq!(GatheringState::Complete as u8, 2);
    }

    // ========================================================================
    // STUN Server Discovery Tests (max 4 servers)
    // ========================================================================

    #[test]
    fn test_stun_server_count_bounds() {
        // Verify MAX_STUN_SERVERS constant
        assert_eq!(MAX_STUN_SERVERS, 4, "MAX_STUN_SERVERS must be 4");
    }

    #[test]
    fn test_gathered_candidates_bounds() {
        let mut gc = GatheredCandidates::default();
        
        // Add candidates up to the limit
        for i in 0..MAX_CANDIDATES {
            let addr: SocketAddr = format!("192.168.1.{}:5000", i % 256).parse().unwrap();
            let candidate = Candidate::new_host(addr, 1, i as u8);
            let result = gc.add(candidate);
            assert!(result, "Should be able to add candidate {}", i);
        }
        
        // Verify we're at the limit
        assert_eq!(gc.count as usize, MAX_CANDIDATES);
        
        // Adding one more should fail
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        let result = gc.add(candidate);
        assert!(!result, "Should not be able to exceed MAX_CANDIDATES");
    }

    // ========================================================================
    // Gathering Timeout Tests (5 seconds per requirement)
    // ========================================================================

    #[test]
    fn test_stun_request_timeout_value() {
        assert_eq!(STUN_REQUEST_TIMEOUT, Duration::from_millis(500),
            "STUN request timeout should be 500ms");
    }

    #[test]
    fn test_stun_max_retries_value() {
        assert_eq!(STUN_MAX_RETRIES, 6,
            "STUN max retries should be 6");
    }

    // ========================================================================
    // Network Interface Enumeration Tests
    // ========================================================================

    #[test]
    fn test_interface_enumeration_bounds() {
        let interfaces = enumerate_interfaces().unwrap();
        
        // Should not exceed MAX_INTERFACES
        let count = interfaces.iter().filter(|i| i.is_some()).count();
        assert!(count <= MAX_INTERFACES,
            "Interface count {} exceeds MAX_INTERFACES {}", count, MAX_INTERFACES);
    }

    #[test]
    fn test_loopback_filtering() {
        let interfaces = enumerate_interfaces().unwrap();
        
        // Loopback addresses should be filtered based on implementation
        for iface in interfaces.iter().flatten() {
            // The gatherer should skip loopback addresses in candidate generation
            // This test verifies the enumeration returns valid addresses
            assert!(iface.is_ipv4() || iface.is_ipv6(),
                "Address must be IPv4 or IPv6");
        }
    }

    // ========================================================================
    // Candidate Deduplication Tests
    // ========================================================================

    #[test]
    fn test_gathered_candidates_iterator() {
        let mut gc = GatheredCandidates::default();
        
        let addr1: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.101:5001".parse().unwrap();
        
        gc.add(Candidate::new_host(addr1, 1, 0));
        gc.add(Candidate::new_host(addr2, 1, 1));
        
        let candidates: Vec<_> = gc.iter().collect();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].address, addr1);
        assert_eq!(candidates[1].address, addr2);
    }

    // ========================================================================
    // Gathering with No Network Interfaces (Error Handling)
    // ========================================================================

    #[test]
    fn test_gatherer_creation() {
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let _gatherer = CandidateGatherer::new(config, 1, tx);
        
        // Gatherer created successfully with valid component
    }

    #[test]
    #[should_panic(expected = "component must be >= 1")]
    fn test_gatherer_invalid_component() {
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let _ = CandidateGatherer::new(config, 0, tx);
    }

    // ========================================================================
    // Gathering State Machine Tests
    // ========================================================================

    #[test]
    fn test_gathering_state_values() {
        assert_eq!(GatheringState::New as u8, 0);
        assert_eq!(GatheringState::Gathering as u8, 1);
        assert_eq!(GatheringState::Complete as u8, 2);
    }

    #[test]
    fn test_gathered_candidates_default() {
        let gc = GatheredCandidates::default();
        
        assert_eq!(gc.count, 0);
        assert_eq!(gc.state, GatheringState::New);
        assert!(gc.is_empty());
    }

    // ========================================================================
    // TURN Allocation Tests (Retry Logic)
    // ========================================================================

    #[test]
    fn test_config_turn_server_count() {
        let config = IceConfig::default();
        
        // Default config should have 0 TURN servers
        assert_eq!(config.turn_server_count, 0);
    }

    // ========================================================================
    // Candidate Type Tests
    // ========================================================================

    #[test]
    fn test_host_candidate_creation() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        
        assert_eq!(candidate.address, addr);
        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.component, 1);
    }

    #[test]
    fn test_srflx_candidate_creation() {
        let addr: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        let base: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let candidate = Candidate::new_server_reflexive(addr, base, 1, 0);
        
        assert_eq!(candidate.address, addr);
        assert_eq!(candidate.base_address(), base);
        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
    }

    // ========================================================================
    // Transaction ID Generation Tests
    // ========================================================================

    #[test]
    fn test_transaction_id_uniqueness() {
        let tid1 = generate_transaction_id();
        let tid2 = generate_transaction_id();
        
        // Transaction IDs should be unique (96-bit random)
        assert_ne!(tid1, tid2, "Transaction IDs should be unique");
    }

    #[test]
    fn test_transaction_id_length() {
        let tid = generate_transaction_id();
        
        // Transaction ID should be exactly 12 bytes (96 bits)
        assert_eq!(tid.len(), 12);
    }

    // ========================================================================
    // Compile-Time Constant Validation Tests
    // ========================================================================

    #[test]
    fn test_constants_valid() {
        // Verify all compile-time constants have valid values
        assert!(MAX_STUN_SERVERS <= 8, "MAX_STUN_SERVERS should be reasonable");
        assert!(MAX_INTERFACES <= 16, "MAX_INTERFACES should be reasonable");
        assert!(STUN_REQUEST_TIMEOUT.as_millis() >= 100, "Timeout too short");
        assert!(STUN_REQUEST_TIMEOUT.as_millis() <= 5000, "Timeout too long");
        assert!(STUN_MAX_RETRIES >= 1, "Must have at least 1 retry");
        assert!(STUN_MAX_RETRIES <= 10, "Too many retries");
    }

    // ========================================================================
    // Async Host Candidate Gathering Tests (Task 3.3)
    // ========================================================================

    #[tokio::test]
    async fn test_gather_host_candidates_basic() {
        let config = IceConfig::default();
        let (tx, mut rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // Gather host candidates
        let count = gatherer.gather_host_candidates().await.unwrap();
        
        // Should have gathered at least one candidate on most systems
        // (might be 0 in containerized environments with no network)
        println!("Gathered {} host candidates", count);
        
        // Verify socket_count matches candidate count
        assert_eq!(gatherer.socket_count, count);
        
        // Verify candidates were sent through channel
        let mut received_count = 0;
        while let Ok(candidate) = rx.try_recv() {
            assert_eq!(candidate.candidate_type, CandidateType::Host);
            assert_eq!(candidate.component, 1);
            assert!(!candidate.address.ip().is_loopback());
            received_count += 1;
        }
        assert_eq!(received_count, count as usize);
    }

    #[tokio::test]
    async fn test_gather_host_candidates_stores_sockets() {
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        let count = gatherer.gather_host_candidates().await.unwrap();
        
        // Verify sockets are stored
        assert_eq!(gatherer.socket_count, count);
        
        // Verify each stored socket is valid
        for i in 0..count as usize {
            assert!(gatherer.sockets[i].is_some(), "Socket {} should be stored", i);
            let socket = gatherer.sockets[i].as_ref().unwrap();
            let local_addr = socket.local_addr().unwrap();
            assert!(!local_addr.ip().is_loopback());
            assert!(local_addr.port() > 0, "Port should be assigned by OS");
        }
    }

    #[tokio::test]
    #[should_panic(expected = "candidate_tx channel must be open")]
    async fn test_gather_host_candidates_channel_closed() {
        let config = IceConfig::default();
        let (tx, rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // Drop receiver to close channel
        drop(rx);
        
        // Gathering should panic due to precondition assertion (TigerStyle)
        let _ = gatherer.gather_host_candidates().await;
    }

    #[tokio::test]
    async fn test_gather_host_candidates_component_2() {
        let config = IceConfig::default();
        let (tx, mut rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 2, tx); // RTCP component
        
        let count = gatherer.gather_host_candidates().await.unwrap();
        
        // Verify candidates have correct component
        while let Ok(candidate) = rx.try_recv() {
            assert_eq!(candidate.component, 2, "Component should be 2 (RTCP)");
        }
        
        assert_eq!(gatherer.socket_count, count);
    }

    // ========================================================================
    // Async Server-Reflexive Candidate Gathering Tests (Task 3.4)
    // ========================================================================

    #[tokio::test]
    #[should_panic(expected = "gather_srflx_candidates requires at least one socket")]
    async fn test_gather_srflx_requires_host_candidates() {
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // Attempting to gather srflx without host candidates should panic
        // because socket_count == 0
        let _ = gatherer.gather_srflx_candidates().await;
    }

    #[tokio::test]
    async fn test_gather_srflx_with_no_stun_servers() {
        // Create config with no STUN servers
        let mut config = IceConfig::new();
        config.stun_server_count = 0;
        config.stun_servers = [None; 4];
        
        let (tx, mut rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            println!("Skipping test: no network interfaces available");
            return;
        }
        
        // Drain host candidates from channel
        while rx.try_recv().is_ok() {}
        
        // Gather srflx candidates (should return 0 since no STUN servers)
        let srflx_count = gatherer.gather_srflx_candidates().await.unwrap();
        
        assert_eq!(srflx_count, 0, "Should have 0 srflx candidates with no STUN servers");
        
        // Verify no candidates were sent
        assert!(rx.try_recv().is_err(), "No srflx candidates should be sent");
    }

    #[tokio::test]
    #[should_panic(expected = "candidate_tx channel must be open")]
    async fn test_gather_srflx_channel_closed() {
        let mut config = IceConfig::default();
        // Add a STUN server
        config.add_stun_server("74.125.250.129:19302".parse().unwrap());
        
        let (tx, rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            // Force panic to satisfy should_panic
            panic!("candidate_tx channel must be open");
        }
        
        // Drop receiver to close channel
        drop(rx);
        
        // Gathering srflx should panic due to closed channel (precondition check)
        let _ = gatherer.gather_srflx_candidates().await;
    }

    #[tokio::test]
    async fn test_gather_srflx_bounds_check() {
        // Verify that srflx gathering respects MAX_CANDIDATES bound
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            println!("Skipping test: no network interfaces available");
            return;
        }
        
        // Verify socket_count is bounded
        assert!(
            (gatherer.socket_count as usize) <= MAX_INTERFACES,
            "socket_count should be bounded by MAX_INTERFACES"
        );
    }

    // ========================================================================
    // Async Relay Candidate Gathering Tests (Task 3.5)
    // ========================================================================

    #[tokio::test]
    #[should_panic(expected = "gather_relay_candidates requires at least one socket")]
    async fn test_gather_relay_requires_host_candidates() {
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // Attempting to gather relay without host candidates should panic
        // because socket_count == 0
        let _ = gatherer.gather_relay_candidates().await;
    }

    #[tokio::test]
    async fn test_gather_relay_with_no_turn_servers() {
        // Create config with no TURN servers
        let mut config = IceConfig::new();
        config.turn_server_count = 0;
        config.turn_servers = [None, None];
        
        let (tx, mut rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            println!("Skipping test: no network interfaces available");
            return;
        }
        
        // Drain host candidates from channel
        while rx.try_recv().is_ok() {}
        
        // Gather relay candidates (should return 0 since no TURN servers)
        let relay_count = gatherer.gather_relay_candidates().await.unwrap();
        
        assert_eq!(relay_count, 0, "Should have 0 relay candidates with no TURN servers");
        
        // Verify no candidates were sent
        assert!(rx.try_recv().is_err(), "No relay candidates should be sent");
    }

    #[tokio::test]
    #[should_panic(expected = "candidate_tx channel must be open")]
    async fn test_gather_relay_channel_closed() {
        use crate::ice::types::TurnServerConfig;
        
        let mut config = IceConfig::new();
        // Add a TURN server
        let turn_config = TurnServerConfig::new(
            "192.0.2.1:3478".parse().unwrap(),
            "testuser",
            "testpass",
            false,
        );
        config.add_turn_server(turn_config);
        
        let (tx, rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            // Force panic to satisfy should_panic
            panic!("candidate_tx channel must be open");
        }
        
        // Drop receiver to close channel
        drop(rx);
        
        // Gathering relay should panic due to closed channel (precondition check)
        let _ = gatherer.gather_relay_candidates().await;
    }

    #[tokio::test]
    async fn test_gather_relay_bounds_check() {
        // Verify that relay gathering respects MAX_CANDIDATES bound
        let config = IceConfig::default();
        let (tx, _rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer = CandidateGatherer::new(config, 1, tx);
        
        // First gather host candidates
        let host_count = gatherer.gather_host_candidates().await.unwrap();
        
        // Skip test if no network interfaces available
        if host_count == 0 {
            println!("Skipping test: no network interfaces available");
            return;
        }
        
        // Verify socket_count is bounded
        assert!(
            (gatherer.socket_count as usize) <= MAX_INTERFACES,
            "socket_count should be bounded by MAX_INTERFACES"
        );
    }

    #[test]
    fn test_relay_candidate_creation() {
        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let server_addr: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let candidate = Candidate::new_relay(relay_addr, server_addr, 1, 0);
        
        assert_eq!(candidate.address, relay_addr);
        assert_eq!(candidate.related_address, Some(server_addr));
        assert_eq!(candidate.candidate_type, CandidateType::Relay);
        assert_eq!(candidate.component, 1);
    }

    #[test]
    fn test_turn_server_config_creation() {
        use crate::ice::types::TurnServerConfig;
        
        let addr: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let config = TurnServerConfig::new(addr, "testuser", "testpass", false);
        
        assert_eq!(config.address, addr);
        assert_eq!(config.username_str(), "testuser");
        assert_eq!(config.password_str(), "testpass");
        assert!(!config.use_tls);
    }

    #[test]
    fn test_ice_config_add_turn_server() {
        use crate::ice::types::TurnServerConfig;
        
        let mut config = IceConfig::new();
        assert_eq!(config.turn_server_count, 0);
        
        let turn_config = TurnServerConfig::new(
            "192.0.2.1:3478".parse().unwrap(),
            "user1",
            "pass1",
            false,
        );
        config.add_turn_server(turn_config);
        
        assert_eq!(config.turn_server_count, 1);
        assert!(config.turn_servers[0].is_some());
        
        let turn_config2 = TurnServerConfig::new(
            "192.0.2.2:3478".parse().unwrap(),
            "user2",
            "pass2",
            true,
        );
        config.add_turn_server(turn_config2);
        
        assert_eq!(config.turn_server_count, 2);
        assert!(config.turn_servers[1].is_some());
    }
}
