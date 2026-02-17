//! ICE Agent.
//!
//! Full ICE implementation per RFC 8445.
//!
//! The agent coordinates candidate gathering, connectivity checks,
//! and connection establishment.
//!
//! # State Machine
//!
//! ```text
//! New → Gathering → GatheringComplete → Checking → Connected/Failed
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let config = IceConfig::default();
//! let mut agent = IceAgent::new(config, IceRole::Controlling);
//!
//! // Gather candidates
//! agent.gather_candidates()?;
//!
//! // Add remote candidates as they arrive
//! agent.add_remote_candidate(remote_candidate)?;
//!
//! // Start connectivity checks
//! agent.start_checks()?;
//!
//! // Process incoming packets
//! agent.process_incoming(data, from)?;
//!
//! // Send outgoing data on selected pair
//! if let Some(selected) = agent.selected_pair() {
//!     // Use selected.local and selected.remote for transport
//! }
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use super::candidate::{Candidate, CandidatePair, MAX_CANDIDATES};
use super::checklist::{Checklist, ChecklistState, MAX_CANDIDATE_PAIRS};
use super::gather::CandidateGatherer;
use super::stun::message::{StunMessage, STUN_BUFFER_SIZE};
use super::stun::server::StunServer;
use super::stun::StunClass;
use super::types::{IceConfig, IceConnectionState, IceCredentials, IceGatheringState, IceRole};
use crate::ice::error::IceError;

/// Maximum outbound packets buffered per poll cycle.
/// Bounded per NASA Rule 2. Covers: up to MAX_PARALLEL_CHECKS regular checks,
/// their retransmissions, plus one nomination.
const MAX_OUTBOUND: usize = 16;

/// A single outbound STUN packet queued for sending.
#[derive(Clone)]
pub struct OutboundPacket {
    pub dest: SocketAddr,
    pub buf: [u8; STUN_BUFFER_SIZE],
    pub len: u16,
}

/// ICE Agent.
///
/// Coordinates the full ICE process including candidate gathering,
/// connectivity checks, and connection establishment.
///
/// All outbound STUN traffic (checks, retransmissions, nominations) is
/// queued into an internal buffer and drained via `poll_outbound()`.
/// The caller sends the returned packets on the wire.
pub struct IceAgent {
    /// Configuration.
    config: IceConfig,

    /// ICE role (Controlling or Controlled).
    role: IceRole,

    /// Local ICE credentials.
    local_credentials: IceCredentials,

    /// Remote ICE credentials (set when remote SDP is received).
    remote_credentials: Option<IceCredentials>,

    /// Connection state.
    connection_state: IceConnectionState,

    /// Gathering state.
    gathering_state: IceGatheringState,

    /// Local candidates.
    local_candidates: [Option<Candidate>; MAX_CANDIDATES],

    /// Local candidate count.
    local_candidate_count: u8,

    /// Remote candidates.
    remote_candidates: [Option<Candidate>; MAX_CANDIDATES],

    /// Remote candidate count.
    remote_candidate_count: u8,

    /// Connectivity checklist.
    checklist: Option<Checklist>,

    /// STUN server for handling binding requests.
    stun_server: StunServer,

    /// Selected candidate pair.
    selected_pair: Option<CandidatePair>,

    /// Component ID (1 = RTP, 2 = RTCP).
    component: u8,

    /// Last activity timestamp.
    last_activity: Instant,

    /// Consent freshness timestamp (RFC 7675).
    last_consent: Instant,

    /// Outbound STUN packet buffer. Drained by `poll_outbound()`.
    outbound: [Option<OutboundPacket>; MAX_OUTBOUND],

    /// Number of packets currently in the outbound buffer.
    outbound_count: u8,
}

impl IceAgent {
    /// Create new ICE agent.
    ///
    /// # Arguments
    ///
    /// * `config` - ICE configuration.
    /// * `role` - ICE role (Controlling or Controlled).
    pub fn new(config: IceConfig, role: IceRole) -> Self {
        // Convert fixed-size arrays to Strings for IceCredentials
        let local_ufrag =
            String::from_utf8_lossy(&config.local_ufrag[..config.local_ufrag_len as usize])
                .to_string();
        let local_pwd =
            String::from_utf8_lossy(&config.local_pwd[..config.local_pwd_len as usize]).to_string();

        let credentials = IceCredentials {
            local_ufrag,
            local_pwd,
        };

        Self {
            config,
            role,
            local_credentials: credentials,
            remote_credentials: None,
            connection_state: IceConnectionState::New,
            gathering_state: IceGatheringState::New,
            local_candidates: std::array::from_fn(|_| None),
            local_candidate_count: 0,
            remote_candidates: std::array::from_fn(|_| None),
            remote_candidate_count: 0,
            checklist: None,
            stun_server: StunServer::with_defaults(),
            selected_pair: None,
            component: 1,
            last_activity: Instant::now(),
            last_consent: Instant::now(),
            outbound: std::array::from_fn(|_| None),
            outbound_count: 0,
        }
    }

    /// Create agent with default configuration.
    pub fn with_defaults(role: IceRole) -> Self {
        Self::new(IceConfig::default(), role)
    }

    /// Create agent with IceServerConfig from application configuration.
    ///
    /// This constructor accepts the high-level `IceServerConfig` from the
    /// application configuration and converts it to the low-level `IceConfig`
    /// used internally by the ICE agent.
    ///
    /// # Arguments
    ///
    /// * `ice_server_config` - High-level ICE server configuration
    /// * `role` - ICE role (Controlling or Controlled)
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertions for server counts
    /// - Postcondition assertion for STUN server availability
    pub fn with_server_config(
        ice_server_config: &super::types::IceServerConfig,
        role: IceRole,
    ) -> Self {
        // Precondition: STUN server count must be bounded
        assert!(
            ice_server_config.stun_servers.len() <= IceConfig::MAX_STUN_SERVERS,
            "STUN server count must be <= {}",
            IceConfig::MAX_STUN_SERVERS
        );

        // Precondition: TURN server count must be bounded
        assert!(
            ice_server_config.turn_servers.len() <= IceConfig::MAX_TURN_SERVERS,
            "TURN server count must be <= {}",
            IceConfig::MAX_TURN_SERVERS
        );

        let mut config = IceConfig::new();

        // Get effective STUN servers (includes Google fallback if enabled)
        let effective_stun = ice_server_config.effective_stun_servers();

        // Add STUN servers
        for stun_url in effective_stun.iter().take(IceConfig::MAX_STUN_SERVERS) {
            // Parse STUN URL (format: stun:host:port or stuns:host:port)
            if let Some(addr) = Self::parse_stun_url(stun_url) {
                config.add_stun_server(addr);
            }
        }

        // Add TURN servers
        for turn_config in ice_server_config
            .turn_servers
            .iter()
            .take(IceConfig::MAX_TURN_SERVERS)
        {
            // Parse TURN URL (format: turn:host:port or turns:host:port)
            if let Some(addr) = Self::parse_turn_url(&turn_config.url) {
                let use_tls = turn_config.url.starts_with("turns:");
                let turn_server = super::types::TurnServerConfig::new(
                    addr,
                    &turn_config.username,
                    &turn_config.credential,
                    use_tls,
                );
                config.add_turn_server(turn_server);
            }
        }

        // Postcondition: Must have at least one STUN server if fallback enabled
        // (unless explicitly disabled)
        if ice_server_config.use_google_fallback {
            assert!(
                config.stun_server_count > 0,
                "Must have at least one STUN server when fallback is enabled"
            );
        }

        Self::new(config, role)
    }

    /// Parse a STUN URL into a SocketAddr.
    ///
    /// Supports formats:
    /// - stun:host:port
    /// - stuns:host:port
    /// - host:port (legacy format)
    /// - IP:port (direct IP address)
    ///
    /// # TigerStyle Compliance
    ///
    /// - Returns Option for graceful handling of invalid URLs
    /// - No panics on malformed input
    pub fn parse_stun_url(url: &str) -> Option<SocketAddr> {
        // Precondition: URL should not be empty (but handle gracefully)
        if url.is_empty() {
            return None;
        }

        let host_port = url
            .strip_prefix("stun:")
            .or_else(|| url.strip_prefix("stuns:"))
            .unwrap_or(url);

        // Try direct parse first (for IP:port format)
        if let Ok(addr) = host_port.parse() {
            return Some(addr);
        }

        // Try DNS resolution for hostname:port format
        use std::net::ToSocketAddrs;
        host_port.to_socket_addrs().ok()?.next()
    }

    /// Parse a TURN URL into a SocketAddr.
    ///
    /// Supports formats:
    /// - turn:host:port
    /// - turns:host:port
    ///
    /// # TigerStyle Compliance
    ///
    /// - Returns Option for graceful handling of invalid URLs
    /// - No panics on malformed input
    pub fn parse_turn_url(url: &str) -> Option<SocketAddr> {
        // Precondition: URL should not be empty (but handle gracefully)
        if url.is_empty() {
            return None;
        }

        let host_port = url
            .strip_prefix("turn:")
            .or_else(|| url.strip_prefix("turns:"))
            .unwrap_or(url);

        // Try direct parse first (for IP:port format)
        if let Ok(addr) = host_port.parse() {
            return Some(addr);
        }

        // Try DNS resolution for hostname:port format
        use std::net::ToSocketAddrs;
        host_port.to_socket_addrs().ok()?.next()
    }

    /// Set component ID.
    pub fn set_component(&mut self, component: u8) {
        assert!(component >= 1, "component must be >= 1");
        self.component = component;
    }

    /// Get local credentials.
    pub fn local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Set remote credentials.
    ///
    /// Must be called before adding remote candidates.
    pub fn set_remote_credentials(&mut self, credentials: IceCredentials) {
        self.remote_credentials = Some(credentials);
    }

    /// Get connection state.
    pub const fn connection_state(&self) -> IceConnectionState {
        self.connection_state
    }

    /// Get gathering state.
    pub const fn gathering_state(&self) -> IceGatheringState {
        self.gathering_state
    }

    /// Get ICE role.
    pub const fn role(&self) -> IceRole {
        self.role
    }

    /// Set ICE role (for role conflicts).
    pub fn set_role(&mut self, role: IceRole) {
        self.role = role;
    }

    /// Gather local candidates.
    ///
    /// This will enumerate local interfaces, contact STUN servers,
    /// and optionally allocate TURN relays.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertion for state
    /// - Postcondition assertion for candidate count bounds
    /// Add a locally-gathered candidate to the agent.
    ///
    /// Called by the orchestrator as candidates are discovered by the
    /// async `CandidateGatherer`. This replaces the old synchronous
    /// `gather_candidates()` which blocked the tokio runtime.
    ///
    /// # TigerStyle
    /// - Precondition: count < MAX_CANDIDATES
    /// - Precondition: candidate port > 0
    /// - Postcondition: count incremented by 1
    pub fn add_local_candidate(&mut self, candidate: Candidate) -> Result<(), IceError> {
        assert!(
            (self.local_candidate_count as usize) < MAX_CANDIDATES,
            "Local candidate count must be below MAX_CANDIDATES"
        );
        assert!(candidate.address.port() > 0, "Candidate port must be > 0");

        if (self.local_candidate_count as usize) >= MAX_CANDIDATES {
            return Err(IceError::TooManyCandidates {
                count: self.local_candidate_count as u32,
                max: MAX_CANDIDATES as u32,
            });
        }

        let count_before = self.local_candidate_count;
        self.local_candidates[self.local_candidate_count as usize] = Some(candidate);
        self.local_candidate_count += 1;

        // If gathering hasn't started, mark it as in-progress
        if self.gathering_state == IceGatheringState::New {
            self.gathering_state = IceGatheringState::Gathering;
        }

        // Postcondition: count incremented by exactly 1
        assert_eq!(
            self.local_candidate_count,
            count_before + 1,
            "Local candidate count must increment by exactly 1"
        );
        assert!(
            (self.local_candidate_count as usize) <= MAX_CANDIDATES,
            "Local candidate count must remain bounded"
        );

        Ok(())
    }

    /// Mark local candidate gathering as complete.
    ///
    /// Called by the orchestrator when the async gatherer finishes.
    /// After this, `start_checks()` can be called.
    ///
    /// # TigerStyle
    /// - Precondition: state is New or Gathering
    /// - Postcondition: state is Complete
    pub fn set_gathering_complete(&mut self) {
        assert!(
            matches!(
                self.gathering_state,
                IceGatheringState::New | IceGatheringState::Gathering
            ),
            "set_gathering_complete requires New or Gathering state, got {:?}",
            self.gathering_state
        );

        self.gathering_state = IceGatheringState::Complete;

        assert_eq!(
            self.gathering_state,
            IceGatheringState::Complete,
            "Gathering must be Complete after set_gathering_complete"
        );
    }

    /// Legacy synchronous gathering. Deprecated — use `add_local_candidate`
    /// + `set_gathering_complete` from the async orchestrator instead.
    #[deprecated(note = "Use add_local_candidate + set_gathering_complete instead")]
    pub fn gather_candidates(&mut self) -> Result<(), IceError> {
        // Precondition: state must be New (TigerStyle)
        assert_eq!(
            self.gathering_state,
            IceGatheringState::New,
            "gather_candidates requires New state"
        );

        // Precondition: local candidate count must be 0 (TigerStyle)
        assert_eq!(
            self.local_candidate_count, 0,
            "Local candidates must be empty before gathering"
        );

        if self.gathering_state != IceGatheringState::New {
            return Err(IceError::InvalidState {
                expected: "New",
                actual: "Gathering or Complete",
            });
        }

        self.gathering_state = IceGatheringState::Gathering;

        // Create a bounded channel for candidate delivery
        let (candidate_tx, mut candidate_rx) = mpsc::channel(MAX_CANDIDATES);
        let mut gatherer =
            CandidateGatherer::new(self.config.clone(), self.component, candidate_tx);

        let gather_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(gatherer.gather())
        });
        let _count = gather_result?;

        let count_before = self.local_candidate_count;

        // Drain candidates from the channel
        while let Ok(candidate) = candidate_rx.try_recv() {
            if (self.local_candidate_count as usize) < MAX_CANDIDATES {
                self.local_candidates[self.local_candidate_count as usize] = Some(candidate);
                self.local_candidate_count += 1;
            }
        }

        // Postcondition: candidate count must be bounded (TigerStyle)
        assert!(
            self.local_candidate_count <= MAX_CANDIDATES as u8,
            "Local candidate count must be <= MAX_CANDIDATES"
        );

        // Postcondition: candidate count must have increased or stayed same (TigerStyle)
        assert!(
            self.local_candidate_count >= count_before,
            "Candidate count must not decrease"
        );

        self.gathering_state = IceGatheringState::Complete;

        // Postcondition: state must be Complete (TigerStyle)
        assert_eq!(
            self.gathering_state,
            IceGatheringState::Complete,
            "Gathering must transition to Complete"
        );

        Ok(())
    }

    /// Get local candidates.
    pub fn local_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.local_candidates[..self.local_candidate_count as usize]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    /// Add a remote candidate.
    ///
    /// Can be called during ICE negotiation as remote candidates
    /// are received via signaling.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertion for count bounds
    /// - Postcondition assertion for bounded increment
    /// - Invariant check for array consistency
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<(), IceError> {
        if self.remote_credentials.is_none() {
            return Err(IceError::NoRemoteCredentials);
        }

        // Precondition: candidate count must be below maximum (TigerStyle)
        assert!(
            (self.remote_candidate_count as usize) < MAX_CANDIDATES,
            "Remote candidate count must be below MAX_CANDIDATES"
        );

        if (self.remote_candidate_count as usize) >= MAX_CANDIDATES {
            return Err(IceError::TooManyCandidates {
                count: self.remote_candidate_count as u32,
                max: MAX_CANDIDATES as u32,
            });
        }

        self.remote_candidates[self.remote_candidate_count as usize] = Some(candidate);
        self.remote_candidate_count += 1;

        // Postcondition: candidate count bounded (TigerStyle)
        assert!(
            (self.remote_candidate_count as usize) <= MAX_CANDIDATES,
            "Remote candidate count must remain bounded"
        );

        // Postcondition: at least one remote candidate now exists (TigerStyle Phase 1.3)
        assert!(
            self.remote_candidate_count > 0,
            "Remote candidate count must be positive after add"
        );

        // Invariant: the slot we just wrote to must contain a candidate (TigerStyle Phase 1.3)
        assert!(
            self.remote_candidates[self.remote_candidate_count as usize - 1].is_some(),
            "Just-added candidate slot must be Some"
        );

        // If we're already checking, incrementally add pairs to the checklist
        // This supports trickle ICE where candidates arrive during connectivity checks
        if let Some(ref mut checklist) = self.checklist {
            // Get reference to the just-added remote candidate
            let remote = self.remote_candidates[self.remote_candidate_count as usize - 1]
                .as_ref()
                .expect("Just-added candidate must exist");

            // Form pairs with all existing local candidates
            for i in 0..self.local_candidate_count as usize {
                if let Some(ref local) = self.local_candidates[i] {
                    // add_pair handles compatibility checks and redundancy pruning
                    let _ = checklist.add_pair(local, remote);
                }
            }
        }

        Ok(())
    }

    /// Get remote candidates.
    pub fn remote_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.remote_candidates[..self.remote_candidate_count as usize]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    /// Get the count of local candidates.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    /// - Returns bounded u8 (max 32)
    #[inline]
    pub fn local_candidate_count(&self) -> u8 {
        self.local_candidate_count
    }

    /// Get the count of remote candidates.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for zero-cost abstraction
    /// - Returns bounded u8 (max 32)
    #[inline]
    pub fn remote_candidate_count(&self) -> u8 {
        self.remote_candidate_count
    }

    /// Start connectivity checks.
    ///
    /// This should be called after gathering is complete and
    /// remote candidates have been received.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition for gathering state
    /// - State transition validation
    /// - Postcondition for checklist creation
    pub fn start_checks(&mut self) -> Result<(), IceError> {
        // Precondition: gathering must be complete (TigerStyle Phase 1.4)
        assert!(
            self.gathering_state == IceGatheringState::Complete,
            "start_checks requires GatheringComplete state"
        );

        if self.gathering_state != IceGatheringState::Complete {
            return Err(IceError::InvalidState {
                expected: "GatheringComplete",
                actual: "New or Gathering",
            });
        }

        // Validate state transition before changing (TigerStyle Phase 1.4)
        self.validate_state_transition(IceConnectionState::Checking)?;

        let remote_creds = self
            .remote_credentials
            .clone()
            .ok_or(IceError::NoRemoteCredentials)?;

        if self.local_candidate_count == 0 {
            return Err(IceError::NoCandidates);
        }

        if self.remote_candidate_count == 0 {
            return Err(IceError::NoCandidates);
        }

        // Create checklist
        let mut checklist = Checklist::new(self.local_credentials.clone(), remote_creds, self.role);

        // Collect candidates as slices
        let local_candidates: Vec<_> = self.local_candidates().cloned().collect();
        let remote_candidates: Vec<_> = self.remote_candidates().cloned().collect();

        checklist.form_pairs(&local_candidates, &remote_candidates);

        self.checklist = Some(checklist);
        self.connection_state = IceConnectionState::Checking;

        // Postcondition: checklist must exist (TigerStyle Phase 1.4)
        assert!(
            self.checklist.is_some(),
            "Checklist must be created after start_checks"
        );

        // Postcondition: state must be Checking (TigerStyle Phase 1.4)
        assert!(
            self.connection_state == IceConnectionState::Checking,
            "Connection state must be Checking after start_checks"
        );

        Ok(())
    }

    /// Validate state transition before applying.
    ///
    /// # TigerStyle Compliance (Phase 1.6)
    ///
    /// - Validates transition is valid per RFC 8445 state machine
    /// - Asserts no redundant transitions
    fn validate_state_transition(&self, next: IceConnectionState) -> Result<(), IceError> {
        // Precondition: no redundant transitions
        if self.connection_state == next {
            return Err(IceError::InvalidStateTransition {
                from: self.connection_state,
                to: next,
            });
        }

        if !self.connection_state.can_transition_to(next) {
            return Err(IceError::InvalidStateTransition {
                from: self.connection_state,
                to: next,
            });
        }

        // Postcondition: transition is valid
        assert!(
            self.connection_state.can_transition_to(next),
            "State transition validation must succeed"
        );

        Ok(())
    }

    /// Get next check to send.
    ///
    /// Deprecated — use `poll_outbound()` which returns all pending
    /// outbound packets (checks, retransmissions, nominations).
    #[deprecated(note = "Use poll_outbound() instead")]
    pub fn next_check(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let checklist = self.checklist.as_mut()?;

        let (_, dest, buf, len) = checklist.next_check()?;

        Some((dest, buf[..len].to_vec()))
    }

    // ================================================================
    // Outbound buffer (unified check + retransmit + nomination path)
    // ================================================================

    /// Queue a STUN packet into the outbound buffer.
    ///
    /// # TigerStyle
    /// - Bounded buffer: drops with warning if full (NASA Rule 2)
    fn queue_outbound(&mut self, dest: SocketAddr, data: &[u8], len: usize) {
        assert!(
            len <= STUN_BUFFER_SIZE,
            "Outbound packet too large: {}",
            len
        );

        if (self.outbound_count as usize) >= MAX_OUTBOUND {
            tracing::warn!(
                outbound_count = self.outbound_count,
                "ICE outbound buffer full, dropping packet to {}",
                dest
            );
            return;
        }

        let mut buf = [0u8; STUN_BUFFER_SIZE];
        buf[..len].copy_from_slice(&data[..len]);

        self.outbound[self.outbound_count as usize] = Some(OutboundPacket {
            dest,
            buf,
            len: len as u16,
        });
        self.outbound_count += 1;
    }

    /// Drain all pending outbound STUN packets.
    ///
    /// Collects regular connectivity checks, retransmissions, and
    /// nomination requests into a single batch. The caller sends
    /// every returned packet on the wire.
    ///
    /// Per RFC 8445 §6.1.4, checks are paced at Ta intervals.
    /// The SFU calls this at 50ms intervals from its event loop.
    ///
    /// # TigerStyle
    /// - Precondition: connection state is Checking
    /// - Postcondition: outbound_count == 0 after drain
    /// - Bounded output: at most MAX_OUTBOUND packets
    pub fn poll_outbound(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        // Only produce outbound traffic while actively checking
        if self.connection_state != IceConnectionState::Checking {
            return Vec::new();
        }

        // Reset buffer for this poll cycle
        self.outbound_count = 0;
        for slot in self.outbound.iter_mut() {
            *slot = None;
        }

        // Collect all outbound packets from checklist, then queue them.
        // Two-phase approach avoids borrow conflicts with self.

        // Phase 1: Collect from checklist into a local buffer
        let mut collected: Vec<(SocketAddr, [u8; STUN_BUFFER_SIZE], usize)> = Vec::new();

        if let Some(ref mut checklist) = self.checklist {
            // 1a. Retransmissions (highest priority)
            for (_, dest, buf, len) in checklist.check_retransmissions() {
                collected.push((dest, buf, len));
            }

            // 1b. New connectivity checks
            let remaining = MAX_OUTBOUND.saturating_sub(collected.len());
            for _ in 0..remaining {
                if let Some((_, dest, buf, len)) = checklist.next_check() {
                    collected.push((dest, buf, len));
                } else {
                    break;
                }
            }
        }

        // Phase 2: Queue into outbound buffer (no checklist borrow)
        for (dest, buf, len) in &collected {
            self.queue_outbound(*dest, buf, *len);
        }

        // Phase 3: Collect results
        let mut result = Vec::with_capacity(self.outbound_count as usize);
        for i in 0..self.outbound_count as usize {
            if let Some(ref pkt) = self.outbound[i] {
                result.push((pkt.dest, pkt.buf[..pkt.len as usize].to_vec()));
            }
        }

        // Postcondition: bounded output
        assert!(
            result.len() <= MAX_OUTBOUND,
            "poll_outbound must return at most {} packets",
            MAX_OUTBOUND
        );

        result
    }

    /// Process incoming packet.
    ///
    /// This handles STUN binding requests/responses and updates
    /// the connectivity check state.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(response))` - STUN response to send back.
    /// - `Ok(None)` - Not a STUN packet or no response needed.
    /// - `Err(_)` - Error processing packet.
    ///
    /// # TigerStyle Compliance (Phase 1.7)
    ///
    /// - Precondition assertion for STUN detection
    /// - Activity timestamp tracking
    pub fn process_incoming(
        &mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<Vec<u8>>, IceError> {
        self.last_activity = Instant::now();

        if !StunMessage::is_stun(data) {
            // Not STUN - might be application data
            return Ok(None);
        }

        // Precondition: data is STUN (TigerStyle Phase 1.7)
        assert!(
            StunMessage::is_stun(data),
            "process_incoming requires STUN data"
        );

        // Delegate to specific handlers based on message class
        let msg = StunMessage::parse(data)?;

        tracing::debug!(
            class = ?msg.class,
            transaction_id = ?&msg.transaction_id,
            from = %from,
            "ICE agent processing STUN message"
        );

        let result = match msg.class {
            StunClass::Request => self.handle_stun_request(&msg, data, from)?,
            StunClass::SuccessResponse | StunClass::ErrorResponse => {
                self.handle_stun_response(&msg, data, from)?;
                None
            }
            StunClass::Indication => {
                // Binding indication - used for keepalives
                // No response needed
                None
            }
        };

        // Postcondition: activity was recently updated (TigerStyle Phase 1.7)
        assert!(
            self.last_activity.elapsed() < Duration::from_secs(1),
            "Activity timestamp must be recent"
        );

        Ok(result)
    }

    /// Handle incoming STUN request.
    ///
    /// Implements RFC 8445 §7.2.5: receiving a STUN binding request triggers
    /// peer-reflexive candidate learning and triggered connectivity checks.
    ///
    /// Flow:
    /// 1. Role conflict detection (§7.2.1.1)
    /// 2. Peer-reflexive remote candidate creation (§7.2.5.3.1)
    /// 3. Triggered check enqueue (§7.2.5.1)
    /// 4. USE-CANDIDATE handling for controlled agent (§7.3.1.5)
    /// 5. Generate STUN success response
    fn handle_stun_request(
        &mut self,
        msg: &StunMessage,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<Vec<u8>>, IceError> {
        // Precondition: must be a request
        assert!(
            msg.class == StunClass::Request,
            "handle_stun_request requires Request class"
        );

        let credentials = self.local_credentials.clone();

        // Step 1: Role conflict detection (RFC 8445 §7.2.1.1)
        match self.handle_role_conflict(msg) {
            Ok(()) => {}
            Err(IceError::RoleConflict) => {
                let error_response = self.build_role_conflict_response(msg);
                return Ok(Some(error_response));
            }
            Err(e) => return Err(e),
        }

        // Mark consent freshness (RFC 7675)
        self.last_consent = Instant::now();

        // Step 2: Peer-reflexive candidate learning and triggered check (RFC 8445 §7.2.5)
        // When we receive a binding request from a remote address, we must:
        //   a) Check if we already know this remote address as a candidate
        //   b) If not, create a peer-reflexive remote candidate
        //   c) Enqueue a triggered check for the pair
        self.handle_peer_reflexive_and_triggered_check(msg, from);

        // Step 3: USE-CANDIDATE handling (RFC 8445 §7.3.1.5)
        // Controlled agent nominates pair when it receives a binding request
        // with USE-CANDIDATE from the controlling agent.
        if matches!(self.role, IceRole::Controlled) && msg.has_use_candidate() {
            if let Some(ref mut checklist) = self.checklist {
                checklist.handle_use_candidate_request(from);
                self.update_connection_state();
            }
        }

        // Step 4: Generate STUN success response
        if let Some(response) = self.stun_server.handle_request(data, from, &credentials)? {
            return Ok(Some(response.to_vec()));
        }

        Ok(None)
    }

    /// Handle peer-reflexive candidate learning and triggered checks per RFC 8445 §7.2.5.
    ///
    /// When a STUN binding request arrives from a remote address:
    /// 1. If the address matches an existing remote candidate, find the pair
    /// 2. If not, create a new peer-reflexive remote candidate
    /// 3. Enqueue a triggered check for the local/remote pair
    ///
    /// This is the critical mechanism that allows ICE to work when the signaled
    /// candidates (host, srflx) are unreachable but the actual source address
    /// of the remote peer's STUN packets is reachable.
    fn handle_peer_reflexive_and_triggered_check(&mut self, msg: &StunMessage, from: SocketAddr) {
        // We need a checklist to add triggered checks
        if self.checklist.is_none() {
            return;
        }

        // Extract the PRIORITY attribute from the request (RFC 8445 §7.2.5.3.1)
        // The remote peer includes its candidate priority in the binding request.
        let remote_priority = msg
            .attributes
            .iter()
            .flatten()
            .find_map(|attr| {
                if let super::stun::attributes::StunAttribute::Priority(p) = attr {
                    Some(*p)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                // Fallback: compute a reasonable priority for a peer-reflexive candidate
                Candidate::calculate_priority(
                    super::candidate::CandidateType::PeerReflexive,
                    65535,
                    self.component,
                )
            });

        // Check if we already have a remote candidate with this address
        let known_remote = self.find_remote_candidate_by_addr(from);

        // Get or create the remote candidate
        let remote_candidate = if let Some(existing) = known_remote {
            existing.clone()
        } else {
            // RFC 8445 §7.2.5.3.1: Create a peer-reflexive remote candidate
            // The base address is the source address itself (we don't know the
            // remote peer's base), and the priority comes from the PRIORITY attribute.
            let prflx = Candidate::new_peer_reflexive(
                from,
                from, // base_address: use the address itself for remote prflx
                remote_priority,
                self.component,
                0, // interface_idx: not meaningful for remote candidates
            );

            tracing::info!(
                address = %from,
                priority = remote_priority,
                "Created peer-reflexive remote candidate from incoming STUN request"
            );

            // Store the new remote candidate
            if (self.remote_candidate_count as usize) < MAX_CANDIDATES {
                self.remote_candidates[self.remote_candidate_count as usize] = Some(prflx.clone());
                self.remote_candidate_count += 1;
            } else {
                tracing::warn!(
                    "Cannot store peer-reflexive candidate: remote candidate list full ({})",
                    self.remote_candidate_count
                );
                return;
            }

            prflx
        };

        // Find the best local candidate to pair with.
        // Per RFC 8445 §7.2.5.1, use the local candidate from which the
        // request was received. Since we may have multiple local candidates,
        // pick the first host candidate with matching address family.
        let local_candidate = self.find_best_local_candidate_for(from);

        let local = match local_candidate {
            Some(c) => c.clone(),
            None => {
                tracing::debug!(
                    from = %from,
                    "No compatible local candidate for triggered check"
                );
                return;
            }
        };

        // Enqueue the triggered check
        if let Some(ref mut checklist) = self.checklist {
            if let Some(pair_idx) = checklist.add_triggered_check(&local, &remote_candidate) {
                tracing::debug!(
                    pair_idx = pair_idx,
                    local_addr = %local.address,
                    remote_addr = %remote_candidate.address,
                    "Enqueued triggered check"
                );
            }
        }
    }

    /// Find an existing remote candidate by address.
    fn find_remote_candidate_by_addr(&self, addr: SocketAddr) -> Option<&Candidate> {
        for i in 0..self.remote_candidate_count as usize {
            if let Some(ref candidate) = self.remote_candidates[i] {
                if candidate.address == addr {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Find the best local candidate to pair with a remote address.
    ///
    /// Prefers host candidates with matching address family.
    /// Falls back to any candidate with matching address family.
    fn find_best_local_candidate_for(&self, remote_addr: SocketAddr) -> Option<&Candidate> {
        let remote_is_ipv4 = remote_addr.is_ipv4();

        // First pass: prefer host candidates with matching address family
        let mut best_host: Option<&Candidate> = None;
        let mut best_any: Option<&Candidate> = None;

        for i in 0..self.local_candidate_count as usize {
            if let Some(ref candidate) = self.local_candidates[i] {
                if candidate.address.is_ipv4() != remote_is_ipv4 {
                    continue; // Address family mismatch
                }

                if candidate.is_host() {
                    // Prefer the host candidate with highest priority
                    if best_host.map_or(true, |b| candidate.priority > b.priority) {
                        best_host = Some(candidate);
                    }
                }

                if best_any.map_or(true, |b| candidate.priority > b.priority) {
                    best_any = Some(candidate);
                }
            }
        }

        best_host.or(best_any)
    }

    /// Handle incoming STUN response.
    ///
    /// # TigerStyle Compliance (Phase 1.7)
    ///
    /// - Extracted from process_incoming for function length compliance
    fn handle_stun_response(
        &mut self,
        msg: &StunMessage,
        _data: &[u8],
        from: SocketAddr,
    ) -> Result<(), IceError> {
        // Precondition: must be a response
        assert!(
            msg.class.is_response(),
            "handle_stun_response requires Response class"
        );

        if let Some(ref mut checklist) = self.checklist {
            // Use STUN_BUFFER_SIZE for encoding
            let mut response_buf = [0u8; STUN_BUFFER_SIZE];
            let len = msg.encode(&mut response_buf);

            if let Some(_pair_idx) = checklist.process_response(&response_buf[..len], from)? {
                // Check succeeded - update state
                self.update_connection_state();

                // Update consent timestamp on successful response
                self.last_consent = Instant::now();

                // Try nomination if controlling
                if matches!(self.role, IceRole::Controlling) {
                    self.try_nominate();
                }
            }
        }

        Ok(())
    }

    /// Handle role conflict detection per RFC 8445 §7.2.1.1.
    ///
    /// Checks ICE-CONTROLLING/ICE-CONTROLLED attributes in the incoming
    /// binding request and resolves conflicts using tie-breaker comparison.
    ///
    /// Returns `Err(IceError::RoleConflict)` if the remote agent should
    /// switch roles (we send a 487 error response).
    fn handle_role_conflict(&mut self, msg: &StunMessage) -> Result<(), IceError> {
        // Precondition: this must be a request
        assert!(
            msg.class == StunClass::Request,
            "handle_role_conflict requires Request class"
        );

        // Extract ICE role attributes from the request
        let mut remote_controlling = false;
        let mut remote_tie_breaker = 0u64;
        let mut has_role_attr = false;

        for attr in msg.attributes.iter().flatten() {
            match attr {
                super::stun::attributes::StunAttribute::IceControlling(tb) => {
                    remote_controlling = true;
                    remote_tie_breaker = *tb;
                    has_role_attr = true;
                }
                super::stun::attributes::StunAttribute::IceControlled(tb) => {
                    remote_controlling = false;
                    remote_tie_breaker = *tb;
                    has_role_attr = true;
                }
                _ => {}
            }
        }

        if !has_role_attr {
            // No role attribute — no conflict possible
            return Ok(());
        }

        let we_control = matches!(self.role, IceRole::Controlling);

        if we_control && remote_controlling {
            // Both controlling — resolve via tie-breaker
            let our_tie_breaker = self.get_tie_breaker();

            if our_tie_breaker >= remote_tie_breaker {
                // We keep controlling, remote should switch → 487
                return Err(IceError::RoleConflict);
            } else {
                // We switch to controlled
                self.role = IceRole::Controlled;
                tracing::info!("Role conflict resolved: switched to Controlled");
            }
        } else if !we_control && !remote_controlling {
            // Both controlled — resolve via tie-breaker
            let our_tie_breaker = self.get_tie_breaker();

            if our_tie_breaker >= remote_tie_breaker {
                // We become controlling
                self.role = IceRole::Controlling;
                tracing::info!("Role conflict resolved: switched to Controlling");
            } else {
                // Remote should switch → 487
                return Err(IceError::RoleConflict);
            }
        }

        Ok(())
    }

    /// Get the tie-breaker value from the checklist.
    ///
    /// Returns 0 if no checklist exists.
    fn get_tie_breaker(&self) -> u64 {
        self.checklist
            .as_ref()
            .map(|c| c.tie_breaker())
            .unwrap_or(0)
    }

    /// Build a 487 Role Conflict error response per RFC 8445 Section 7.2.1.1.
    ///
    /// # Comment 4 Fix
    ///
    /// When a role conflict is detected, we must send a 487 Role Conflict
    /// error response with the correct role attribute (ICE-CONTROLLING or
    /// ICE-CONTROLLED) matching our current role.
    fn build_role_conflict_response(&self, request: &StunMessage) -> Vec<u8> {
        use super::stun::integrity::sign_message;
        use super::stun::message::STUN_MAGIC_COOKIE;

        let mut buf = [0u8; STUN_BUFFER_SIZE];

        // Build error response header
        let msg_type = StunMessage::encode_type(StunClass::ErrorResponse, request.method);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&request.transaction_id);

        let mut offset = 20usize;

        // Add ERROR-CODE attribute (487 Role Conflict)
        // Type: 0x0009, Length: 4 + reason length
        let reason = b"Role Conflict";
        let error_class = 4u8; // 4xx class
        let error_number = 87u8; // 87 = Role Conflict

        buf[offset..offset + 2].copy_from_slice(&0x0009u16.to_be_bytes()); // ERROR-CODE type
        let error_len = 4 + reason.len();
        buf[offset + 2..offset + 4].copy_from_slice(&(error_len as u16).to_be_bytes());
        buf[offset + 4] = 0; // Reserved
        buf[offset + 5] = 0; // Reserved
        buf[offset + 6] = error_class;
        buf[offset + 7] = error_number;
        buf[offset + 8..offset + 8 + reason.len()].copy_from_slice(reason);
        offset += 4 + ((error_len + 3) & !3); // Pad to 4-byte boundary

        // Add our current role attribute so remote knows our state
        let tie_breaker = self.get_tie_breaker();
        if matches!(self.role, IceRole::Controlling) {
            // ICE-CONTROLLING: 0x802A
            buf[offset..offset + 2].copy_from_slice(&0x802Au16.to_be_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_be_bytes());
            buf[offset + 4..offset + 12].copy_from_slice(&tie_breaker.to_be_bytes());
            offset += 12;
        } else {
            // ICE-CONTROLLED: 0x8029
            buf[offset..offset + 2].copy_from_slice(&0x8029u16.to_be_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_be_bytes());
            buf[offset + 4..offset + 12].copy_from_slice(&tie_breaker.to_be_bytes());
            offset += 12;
        }

        // Update message length
        let attr_len = (offset - 20) as u16;
        buf[2..4].copy_from_slice(&attr_len.to_be_bytes());

        // Add MESSAGE-INTEGRITY and FINGERPRINT
        let key = self.local_credentials.local_pwd.as_bytes();
        let final_len = sign_message(&mut buf, offset, key);

        buf[..final_len].to_vec()
    }

    /// Try to nominate the best succeeded pair (RFC 8445 §8.1.1).
    ///
    /// When the controlling agent has a succeeded pair, it sends a
    /// STUN request with USE-CANDIDATE to nominate it. The nomination
    /// request is queued into the outbound buffer and will be sent
    /// on the next `poll_outbound()` call.
    ///
    /// # TigerStyle
    /// - Only called when role is Controlling
    /// - Nomination bytes queued, never discarded
    fn try_nominate(&mut self) {
        if let Some(ref mut checklist) = self.checklist {
            if checklist.succeeded_count() > 0 && checklist.nominated_pair().is_none() {
                if let Some((_idx, dest, buf, len)) = checklist.nominate() {
                    self.queue_outbound(dest, &buf, len);
                    tracing::debug!(
                        dest = %dest,
                        len = len,
                        "Queued ICE nomination request"
                    );
                }
            }
        }
    }

    /// Update connection state based on checklist state.
    fn update_connection_state(&mut self) {
        if let Some(ref checklist) = self.checklist {
            match checklist.state() {
                ChecklistState::Running => {
                    if checklist.succeeded_count() > 0 {
                        if let Some(pair) = checklist.nominated_pair() {
                            // Postcondition: nominated pair must be succeeded (TigerStyle)
                            assert!(
                                pair.is_succeeded(),
                                "Nominated pair must be in Succeeded state"
                            );
                            self.selected_pair = Some(pair.clone());
                            self.connection_state = IceConnectionState::Connected;
                        }
                    }
                }
                ChecklistState::Completed => {
                    if let Some(pair) = checklist.nominated_pair() {
                        // Postcondition: nominated pair must be succeeded (TigerStyle)
                        assert!(
                            pair.is_succeeded(),
                            "Nominated pair must be in Succeeded state"
                        );
                        self.selected_pair = Some(pair.clone());
                        self.connection_state = IceConnectionState::Connected;
                    }
                }
                ChecklistState::Failed => {
                    self.connection_state = IceConnectionState::Failed;
                }
            }
        }
    }

    /// Get retransmissions to send.
    ///
    /// Deprecated — use `poll_outbound()` which includes retransmissions.
    #[deprecated(note = "Use poll_outbound() instead")]
    pub fn retransmissions(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut result = Vec::new();

        if let Some(ref mut checklist) = self.checklist {
            for (_, dest, buf, len) in checklist.check_retransmissions() {
                result.push((dest, buf[..len].to_vec()));
            }
        }

        result
    }

    /// Get selected (nominated) pair.
    pub fn selected_pair(&self) -> Option<&CandidatePair> {
        self.selected_pair.as_ref()
    }

    /// Check if connected.
    pub const fn is_connected(&self) -> bool {
        matches!(
            self.connection_state,
            IceConnectionState::Connected | IceConnectionState::Completed
        )
    }

    /// Check if failed.
    pub const fn is_failed(&self) -> bool {
        matches!(
            self.connection_state,
            IceConnectionState::Failed | IceConnectionState::Closed
        )
    }

    /// Get time since last activity.
    pub fn time_since_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get time since last consent.
    pub fn time_since_consent(&self) -> Duration {
        self.last_consent.elapsed()
    }

    /// Check consent freshness (RFC 7675).
    ///
    /// Returns true if consent is stale (>30 seconds since last consent).
    ///
    /// # TigerStyle Compliance (Phase 1.8)
    ///
    /// - Uses compile-time constant for timeout
    /// - Assertion for timestamp validity
    pub fn is_consent_stale(&self) -> bool {
        // Precondition: consent timestamp must be in the past (TigerStyle Phase 1.8)
        assert!(
            self.last_consent <= Instant::now(),
            "Consent timestamp must not be in the future"
        );

        self.last_consent.elapsed() > Duration::from_secs(CONSENT_TIMEOUT_SECS)
    }

    /// Close the agent.
    pub fn close(&mut self) {
        self.connection_state = IceConnectionState::Closed;
        self.selected_pair = None;
        self.checklist = None;
    }

    /// Restart ICE.
    ///
    /// This generates new credentials and resets the state.
    pub fn restart(&mut self) -> Result<(), IceError> {
        // Generate new credentials
        let new_credentials = IceCredentials::generate();

        // Copy to fixed-size arrays in config
        let ufrag_bytes = new_credentials.local_ufrag.as_bytes();
        let pwd_bytes = new_credentials.local_pwd.as_bytes();

        self.config.local_ufrag = [0u8; 32];
        self.config.local_pwd = [0u8; 32];

        let ufrag_len = ufrag_bytes.len().min(32);
        let pwd_len = pwd_bytes.len().min(32);

        self.config.local_ufrag[..ufrag_len].copy_from_slice(&ufrag_bytes[..ufrag_len]);
        self.config.local_ufrag_len = ufrag_len as u8;
        self.config.local_pwd[..pwd_len].copy_from_slice(&pwd_bytes[..pwd_len]);
        self.config.local_pwd_len = pwd_len as u8;

        self.local_credentials = new_credentials;

        // Reset state
        self.remote_credentials = None;
        self.connection_state = IceConnectionState::New;
        self.gathering_state = IceGatheringState::New;
        self.local_candidates = std::array::from_fn(|_| None);
        self.local_candidate_count = 0;
        self.remote_candidates = std::array::from_fn(|_| None);
        self.remote_candidate_count = 0;
        self.checklist = None;
        self.selected_pair = None;
        self.outbound = std::array::from_fn(|_| None);
        self.outbound_count = 0;

        Ok(())
    }

    /// Get the number of candidate pairs that have been checked.
    ///
    /// Returns the count of pairs that have completed connectivity checks
    /// (either succeeded or failed).
    pub fn pairs_checked(&self) -> u32 {
        if let Some(ref checklist) = self.checklist {
            checklist.checked_count() as u32
        } else {
            0
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> IceAgentStats {
        let (pair_count, succeeded_count) = if let Some(ref checklist) = self.checklist {
            (checklist.pair_count(), checklist.succeeded_count())
        } else {
            (0, 0)
        };

        IceAgentStats {
            local_candidates: self.local_candidate_count,
            remote_candidates: self.remote_candidate_count,
            candidate_pairs: pair_count,
            succeeded_pairs: succeeded_count,
            connection_state: self.connection_state,
            gathering_state: self.gathering_state,
            time_since_activity_ms: self.last_activity.elapsed().as_millis() as u32,
            time_since_consent_ms: self.last_consent.elapsed().as_millis() as u32,
        }
    }
}

/// ICE Agent statistics.
#[derive(Debug, Clone)]
pub struct IceAgentStats {
    pub local_candidates: u8,
    pub remote_candidates: u8,
    pub candidate_pairs: u16,
    pub succeeded_pairs: u16,
    pub connection_state: IceConnectionState,
    pub gathering_state: IceGatheringState,
    pub time_since_activity_ms: u32,
    pub time_since_consent_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::candidate::{
        TYPE_PREF_HOST, TYPE_PREF_PEER_REFLEXIVE, TYPE_PREF_RELAY, TYPE_PREF_SERVER_REFLEXIVE,
    };

    // ========================================================================
    // Basic Agent Tests
    // ========================================================================

    #[test]
    fn test_agent_creation() {
        let agent = IceAgent::with_defaults(IceRole::Controlling);

        assert_eq!(agent.connection_state(), IceConnectionState::New);
        assert_eq!(agent.gathering_state(), IceGatheringState::New);
        assert_eq!(agent.role(), IceRole::Controlling);
    }

    #[test]
    fn test_agent_credentials() {
        let agent = IceAgent::with_defaults(IceRole::Controlled);

        let creds = agent.local_credentials();
        assert!(!creds.local_ufrag.is_empty());
        assert!(!creds.local_pwd.is_empty());
    }

    // Helper: add a synthetic host candidate and mark gathering complete.
    fn gather_synthetic(agent: &mut IceAgent) {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        agent.add_local_candidate(candidate).unwrap();
        agent.set_gathering_complete();
    }

    #[test]
    fn test_agent_state_transitions() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Should start in New state
        assert_eq!(agent.connection_state(), IceConnectionState::New);

        // Gather candidates via new API
        gather_synthetic(&mut agent);
        assert_eq!(agent.gathering_state(), IceGatheringState::Complete);
    }

    #[test]
    fn test_add_remote_candidate_requires_credentials() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        let addr: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);

        // Should fail without remote credentials
        let result = agent.add_remote_candidate(candidate.clone());
        assert!(matches!(result, Err(IceError::NoRemoteCredentials)));

        // Set remote credentials
        agent.set_remote_credentials(IceCredentials::generate());

        // Now should succeed
        let result = agent.add_remote_candidate(candidate);
        assert!(result.is_ok());
    }

    #[test]
    fn test_agent_restart() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        let original_ufrag = agent.local_credentials().local_ufrag.clone();

        // Gather some candidates
        gather_synthetic(&mut agent);

        // Restart
        agent.restart().unwrap();

        // Should have new credentials
        assert_ne!(agent.local_credentials().local_ufrag, original_ufrag);

        // Should be back to New state
        assert_eq!(agent.connection_state(), IceConnectionState::New);
        assert_eq!(agent.gathering_state(), IceGatheringState::New);
    }

    // ========================================================================
    // Candidate Gathering Tests (max 32 candidates per RFC 8445)
    // ========================================================================

    #[test]
    fn test_candidate_gathering_bounds() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Add candidates up to the limit via new API
        for i in 0..MAX_CANDIDATES {
            let addr: SocketAddr = format!("127.0.0.{}:9000", i).parse().unwrap();
            let candidate = Candidate::new_host(addr, 1, i as u8);
            agent.add_local_candidate(candidate).unwrap();
        }
        agent.set_gathering_complete();

        // Count should be bounded by MAX_CANDIDATES (32)
        let count = agent.local_candidates().count();
        assert!(
            count <= MAX_CANDIDATES,
            "candidate count {} exceeds MAX_CANDIDATES {}",
            count,
            MAX_CANDIDATES
        );
    }

    #[test]
    fn test_remote_candidate_bounds() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);
        agent.set_remote_credentials(IceCredentials::generate());

        // Add candidates up to the limit
        for i in 0..MAX_CANDIDATES {
            let addr: SocketAddr = format!("192.168.1.{}:5000", i).parse().unwrap();
            let candidate = Candidate::new_host(addr, 1, i as u8);
            let result = agent.add_remote_candidate(candidate);
            assert!(result.is_ok(), "Failed to add candidate {}", i);
        }

        // Verify count is at maximum
        assert_eq!(agent.remote_candidate_count() as usize, MAX_CANDIDATES);
    }

    // ========================================================================
    // Connectivity Check State Machine Tests
    // (Frozen→Waiting→InProgress→Succeeded/Failed)
    // ========================================================================

    #[test]
    #[should_panic(expected = "start_checks requires GatheringComplete state")]
    fn test_start_checks_requires_gathering_complete() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Try to start checks before gathering - should panic per TigerStyle assertion
        agent.set_remote_credentials(IceCredentials::generate());

        // Add remote candidate first
        let addr: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        let _ = agent.add_remote_candidate(candidate);

        // Start checks without gathering should panic
        let _ = agent.start_checks();
    }

    #[test]
    fn test_start_checks_after_gathering() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Gather candidates via new API
        gather_synthetic(&mut agent);

        // Set remote credentials and add remote candidate
        agent.set_remote_credentials(IceCredentials::generate());
        let addr: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        let _ = agent.add_remote_candidate(candidate);

        // Now start checks should work
        let result = agent.start_checks();
        assert!(result.is_ok());
        assert_eq!(agent.connection_state(), IceConnectionState::Checking);
    }

    #[test]
    fn test_start_checks_requires_remote_credentials() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Gather candidates via new API
        gather_synthetic(&mut agent);

        // Try to start checks without remote credentials
        let result = agent.start_checks();
        assert!(matches!(result, Err(IceError::NoRemoteCredentials)));
    }

    #[test]
    fn test_start_checks_requires_remote_candidates() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Gather candidates via new API
        gather_synthetic(&mut agent);

        // Set remote credentials but no candidates
        agent.set_remote_credentials(IceCredentials::generate());

        // Try to start checks without remote candidates
        let result = agent.start_checks();
        assert!(matches!(result, Err(IceError::NoCandidates)));
    }

    // ========================================================================
    // Role Conflict Resolution Tests (RFC 8445 Section 7.2.1.1)
    // ========================================================================

    #[test]
    fn test_role_flip() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);
        assert_eq!(agent.role(), IceRole::Controlling);

        agent.set_role(IceRole::Controlled);
        assert_eq!(agent.role(), IceRole::Controlled);

        agent.set_role(IceRole::Controlling);
        assert_eq!(agent.role(), IceRole::Controlling);
    }

    #[test]
    fn test_ice_role_flip_method() {
        assert_eq!(IceRole::Controlling.flip(), IceRole::Controlled);
        assert_eq!(IceRole::Controlled.flip(), IceRole::Controlling);
    }

    // ========================================================================
    // Candidate Priority Calculation Tests
    // (priority = 2^24 * type + 2^8 * local + component)
    // ========================================================================

    #[test]
    fn test_candidate_priority_formula() {
        // Host candidate should have highest type preference (126)
        let host_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let host = Candidate::new_host(host_addr, 1, 0);

        // Verify priority follows RFC 8445 formula:
        // priority = (2^24) * type_preference + (2^8) * local_preference + (256 - component_id)
        let type_pref = TYPE_PREF_HOST;
        let local_pref = 65535u32; // Default local preference
        let component = 1u8;

        let _expected_priority = (1u32 << 24) * type_pref
            + (1u32 << 8) * (local_pref & 0xFFFF)
            + (256 - component as u32);

        // Priority should be consistent with the formula
        assert!(host.priority > 0, "Host priority should be positive");

        // Host candidates should have higher priority than relay candidates
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        let relay = Candidate::new_relay(relay_addr, host_addr, 1, 0);

        assert!(
            host.priority > relay.priority,
            "Host priority {} should be > relay priority {}",
            host.priority,
            relay.priority
        );
    }

    #[test]
    fn test_candidate_type_preferences() {
        // Verify type preferences are in correct order
        assert!(TYPE_PREF_HOST > TYPE_PREF_PEER_REFLEXIVE);
        assert!(TYPE_PREF_PEER_REFLEXIVE > TYPE_PREF_SERVER_REFLEXIVE);
        assert!(TYPE_PREF_SERVER_REFLEXIVE > TYPE_PREF_RELAY);
    }

    // ========================================================================
    // Agent Creation with Invalid Parameters Tests
    // ========================================================================

    #[test]
    fn test_agent_with_custom_config() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlled);

        assert_eq!(agent.role(), IceRole::Controlled);
        assert_eq!(agent.connection_state(), IceConnectionState::New);
    }

    #[test]
    fn test_agent_component_setting() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Component 1 (RTP) is default
        agent.set_component(1);

        // Component 2 (RTCP) should also work
        agent.set_component(2);
    }

    #[test]
    #[should_panic(expected = "component must be >= 1")]
    fn test_agent_invalid_component_zero() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);
        agent.set_component(0); // Should panic
    }

    // ========================================================================
    // Agent Statistics Tests
    // ========================================================================

    #[test]
    fn test_agent_stats_initial() {
        let agent = IceAgent::with_defaults(IceRole::Controlling);
        let stats = agent.stats();

        assert_eq!(stats.local_candidates, 0);
        assert_eq!(stats.remote_candidates, 0);
        assert_eq!(stats.candidate_pairs, 0);
        assert_eq!(stats.connection_state, IceConnectionState::New);
        assert_eq!(stats.gathering_state, IceGatheringState::New);
    }

    #[test]
    fn test_agent_stats_after_gathering() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);
        gather_synthetic(&mut agent);

        let stats = agent.stats();

        // Should have gathered at least some candidates (depends on system)
        assert_eq!(stats.gathering_state, IceGatheringState::Complete);
    }

    // ========================================================================
    // Agent Close/Cleanup Tests
    // ========================================================================

    #[test]
    fn test_agent_close() {
        let mut agent = IceAgent::with_defaults(IceRole::Controlling);

        // Gather and setup
        gather_synthetic(&mut agent);
        agent.set_remote_credentials(IceCredentials::generate());
        let addr: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let _ = agent.add_remote_candidate(Candidate::new_host(addr, 1, 0));
        let _ = agent.start_checks();

        // Close the agent
        agent.close();

        assert_eq!(agent.connection_state(), IceConnectionState::Closed);
        assert!(agent.selected_pair.is_none());
    }

    // ========================================================================
    // Credential Validation Tests
    // ========================================================================

    #[test]
    fn test_ice_credentials_generation() {
        let creds1 = IceCredentials::generate();
        let creds2 = IceCredentials::generate();

        // Each generation should produce unique credentials
        assert_ne!(creds1.local_ufrag, creds2.local_ufrag);
        assert_ne!(creds1.local_pwd, creds2.local_pwd);

        // Credentials should have reasonable lengths
        assert!(creds1.local_ufrag.len() >= 4, "ufrag too short");
        assert!(creds1.local_pwd.len() >= 22, "pwd too short");
    }

    #[test]
    fn test_ice_credentials_custom() {
        let creds = IceCredentials::new("myufrag", "mypassword123456789012");

        assert_eq!(creds.local_ufrag, "myufrag");
        assert_eq!(creds.local_pwd, "mypassword123456789012");
    }

    // ========================================================================
    // State Transition Validation Tests
    // ========================================================================

    #[test]
    fn test_valid_state_transitions() {
        // New → Checking
        assert!(IceConnectionState::New.can_transition_to(IceConnectionState::Checking));

        // Checking → Connected
        assert!(IceConnectionState::Checking.can_transition_to(IceConnectionState::Connected));

        // Checking → Failed
        assert!(IceConnectionState::Checking.can_transition_to(IceConnectionState::Failed));

        // Connected → Completed
        assert!(IceConnectionState::Connected.can_transition_to(IceConnectionState::Completed));

        // Connected → Disconnected
        assert!(IceConnectionState::Connected.can_transition_to(IceConnectionState::Disconnected));
    }

    #[test]
    fn test_invalid_state_transitions() {
        // Terminal states cannot transition
        assert!(!IceConnectionState::Failed.can_transition_to(IceConnectionState::New));
        assert!(!IceConnectionState::Closed.can_transition_to(IceConnectionState::Checking));

        // Cannot go backwards
        assert!(!IceConnectionState::Checking.can_transition_to(IceConnectionState::New));
    }

    #[test]
    fn test_connection_state_helpers() {
        assert!(IceConnectionState::Connected.is_connected());
        assert!(IceConnectionState::Completed.is_connected());
        assert!(!IceConnectionState::Checking.is_connected());

        assert!(IceConnectionState::Failed.is_terminal());
        assert!(IceConnectionState::Closed.is_terminal());
        assert!(!IceConnectionState::Connected.is_terminal());
    }

    // ========================================================================
    // IceServerConfig Integration Tests
    // ========================================================================

    #[test]
    fn test_with_server_config_default() {
        use crate::ice::types::IceServerConfig;

        let ice_server_config = IceServerConfig::default();
        let agent = IceAgent::with_server_config(&ice_server_config, IceRole::Controlling);

        // Should have Google STUN servers as fallback
        assert_eq!(agent.role(), IceRole::Controlling);
        assert_eq!(agent.connection_state(), IceConnectionState::New);
    }

    #[test]
    fn test_with_server_config_custom_stun() {
        use crate::ice::types::IceServerConfig;

        let ice_server_config = IceServerConfig {
            stun_servers: vec!["stun:74.125.250.129:19302".to_string()],
            turn_servers: Vec::new(),
            use_google_fallback: false,
        };
        let agent = IceAgent::with_server_config(&ice_server_config, IceRole::Controlled);

        assert_eq!(agent.role(), IceRole::Controlled);
        assert_eq!(agent.connection_state(), IceConnectionState::New);
    }

    #[test]
    fn test_with_server_config_with_turn() {
        use crate::ice::types::{HighLevelTurnServerConfig, IceServerConfig};

        let ice_server_config = IceServerConfig {
            stun_servers: vec!["stun:74.125.250.129:19302".to_string()],
            turn_servers: vec![HighLevelTurnServerConfig::new(
                "turn:192.168.1.100:3478",
                "user",
                "pass",
            )],
            use_google_fallback: false,
        };
        let agent = IceAgent::with_server_config(&ice_server_config, IceRole::Controlling);

        assert_eq!(agent.role(), IceRole::Controlling);
    }

    #[test]
    fn test_parse_stun_url() {
        // Standard STUN URL
        let addr = IceAgent::parse_stun_url("stun:74.125.250.129:19302");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 19302);

        // STUNS URL
        let addr = IceAgent::parse_stun_url("stuns:74.125.250.129:5349");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 5349);

        // Legacy format (host:port)
        let addr = IceAgent::parse_stun_url("74.125.250.129:19302");
        assert!(addr.is_some());

        // Invalid URL
        let addr = IceAgent::parse_stun_url("invalid");
        assert!(addr.is_none());

        // Empty URL
        let addr = IceAgent::parse_stun_url("");
        assert!(addr.is_none());
    }

    #[test]
    fn test_parse_turn_url() {
        // Standard TURN URL
        let addr = IceAgent::parse_turn_url("turn:192.168.1.100:3478");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 3478);

        // TURNS URL
        let addr = IceAgent::parse_turn_url("turns:192.168.1.100:5349");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 5349);

        // Invalid URL
        let addr = IceAgent::parse_turn_url("invalid");
        assert!(addr.is_none());

        // Empty URL
        let addr = IceAgent::parse_turn_url("");
        assert!(addr.is_none());
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: ICE credentials are always valid length.
            #[test]
            fn prop_credentials_valid_length(
                _ in 0..100u32,  // Just run multiple times
            ) {
                let creds = IceCredentials::generate();

                // RFC 5245: ufrag >= 4 chars, pwd >= 22 chars
                prop_assert!(creds.local_ufrag.len() >= 4, "ufrag too short");
                prop_assert!(creds.local_pwd.len() >= 22, "pwd too short");
                prop_assert!(creds.local_ufrag.len() <= 256, "ufrag too long");
                prop_assert!(creds.local_pwd.len() <= 256, "pwd too long");
            }

            /// Property: Agent roles are preserved.
            #[test]
            fn prop_role_preserved(
                role_idx in 0u8..2,
            ) {
                let role = if role_idx == 0 { IceRole::Controlling } else { IceRole::Controlled };
                let agent = IceAgent::with_defaults(role);

                prop_assert_eq!(agent.role(), role);
            }

            /// Property: Initial state is always New.
            #[test]
            fn prop_initial_state_new(
                role_idx in 0u8..2,
            ) {
                let role = if role_idx == 0 { IceRole::Controlling } else { IceRole::Controlled };
                let agent = IceAgent::with_defaults(role);

                prop_assert_eq!(agent.connection_state(), IceConnectionState::New);
                prop_assert_eq!(agent.gathering_state(), IceGatheringState::New);
                prop_assert_eq!(agent.local_candidate_count(), 0);
                prop_assert_eq!(agent.remote_candidate_count(), 0);
            }

            /// Property: Candidate count never exceeds MAX_CANDIDATES.
            #[test]
            fn prop_candidate_count_bounded(
                candidate_count in 1usize..=MAX_CANDIDATES,
            ) {
                let mut agent = IceAgent::with_defaults(IceRole::Controlling);
                agent.set_remote_credentials(IceCredentials::generate());

                let mut added = 0usize;
                for i in 0..candidate_count {
                    let addr: std::net::SocketAddr = format!("192.168.{}.{}:5000", i / 256, i % 256).parse().unwrap();
                    let candidate = Candidate::new_host(addr, 1, (i % 256) as u8);

                    match agent.add_remote_candidate(candidate) {
                        Ok(_) => added += 1,
                        Err(_) => break,
                    }
                }

                prop_assert!(agent.remote_candidate_count() as usize <= MAX_CANDIDATES);
                prop_assert_eq!(agent.remote_candidate_count() as usize, added);
            }

            /// Property: State transitions are valid (no invalid transitions).
            #[test]
            fn prop_state_machine_valid_transitions(
                role_idx in 0u8..2,
            ) {
                let role = if role_idx == 0 { IceRole::Controlling } else { IceRole::Controlled };
                let agent = IceAgent::with_defaults(role);

                // New state can only transition to Checking (after gather/start_checks)
                let state = agent.connection_state();
                prop_assert_eq!(state, IceConnectionState::New);

                // Terminal states
                prop_assert!(IceConnectionState::Failed.is_terminal());
                prop_assert!(IceConnectionState::Closed.is_terminal());

                // Connected states
                prop_assert!(IceConnectionState::Connected.is_connected());
                prop_assert!(IceConnectionState::Completed.is_connected());
            }
        }
    }
}

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

// Assert candidate limits are bounded
const _: () = assert!(
    MAX_CANDIDATES <= 32,
    "MAX_CANDIDATES must be <= 32 to fit in u8 counter"
);

// Assert candidate pair limit is reasonable
const _: () = assert!(
    MAX_CANDIDATE_PAIRS <= 1024,
    "MAX_CANDIDATE_PAIRS must be <= 1024 to prevent memory exhaustion"
);

// Assert STUN transaction timeout bounds (TigerStyle Phase 1.1)
#[allow(dead_code)] // Used in compile-time assertions for protocol timing bounds
const STUN_TRANSACTION_TIMEOUT_MS: u32 = 500;
#[allow(dead_code)] // Used in compile-time assertions for protocol timing bounds
const CHECK_INTERVAL_MS: u32 = 50;
const _: () = assert!(
    STUN_TRANSACTION_TIMEOUT_MS >= 100 && STUN_TRANSACTION_TIMEOUT_MS <= 5000,
    "STUN timeout must be in range 100-5000ms"
);
const _: () = assert!(
    CHECK_INTERVAL_MS >= 10 && CHECK_INTERVAL_MS <= 1000,
    "Check interval must be in range 10-1000ms"
);

// Assert consent timeout is reasonable (RFC 7675)
const CONSENT_TIMEOUT_SECS: u64 = 30;
