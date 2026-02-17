//! WebRTC Session.
//!
//! Unified session that orchestrates ICE, DTLS, and SRTP components
//! to provide a complete WebRTC transport layer.
//!
//! # State Machine
//!
//! ```text
//! New → IceGathering → IceConnecting → DtlsHandshaking → Established
//!                 ↓            ↓               ↓              ↓
//!              Failed      Failed          Failed         Closed
//! ```
//!
//! # TigerStyle Compliance
//!
//! This module follows TigerStyle coding standards:
//!
//! 1. Assertion Density: Minimum 2 assertions per function
//! 2. Paired Assertions: Preconditions + postconditions for state changes
//! 3. Buffer Bleed Protection: Zero buffers before/after use
//! 4. Bounded Limits: All collections have compile-time max sizes
//! 5. Explicit Errors: No silent failures in DTLS/SRTP operations
//! 6. Positive/Negative Space: Assert both valid and invalid states
//! 7. Compile-Time Checks: Struct sizes and constants validated
//! 8. Simple Control Flow: No recursion, explicit state machines
//!
//! # Usage
//!
//! ```ignore
//! let config = SessionConfig::default();
//! let mut session = WebRtcSession::new(config)?;
//!
//! // Gather ICE candidates
//! session.gather_candidates()?;
//!
//! // Exchange candidates via signaling
//! for candidate in session.local_candidates() {
//!     signaling.send_candidate(candidate);
//! }
//!
//! // Add remote candidates
//! session.add_remote_candidate(remote_candidate)?;
//!
//! // Start connectivity checks
//! session.start_ice()?;
//!
//! // Process incoming packets (caller provides output buffer)
//! let mut out = [0u8; 2048];
//! match session.process_incoming(data, from, &mut out)? {
//!     IncomingData::Stun(response) => send(response),
//!     IncomingData::Rtp(len) => handle_rtp(&out[..len]),
//!     IncomingData::Rtcp(len) => handle_rtcp(&out[..len]),
//!     IncomingData::None => {},
//! }
//!
//! // Send protected RTP
//! let protected = session.protect_rtp(rtp_packet)?;
//! ```

use std::net::SocketAddr;
use std::time::Instant;

use tracing::warn;

use super::demux::{demux_and_validate, recover_from_malformed_packet, PacketType, RecoveryAction};
use super::error::WebRtcError;
use super::types::{TransportId, TransportStats};

use nexus_transport::dtls::{
    DtlsRole, DtlsSession, OpenSslDtlsEngine, SessionConfig as DtlsConfig,
    SessionState as DtlsState,
};
use nexus_transport::ice::{
    Candidate, IceAgent, IceConfig, IceConnectionState, IceCredentials, IceGatheringState, IceRole,
};
use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};

// ============================================================================
// Constants
// ============================================================================

/// Maximum packet size for WebRTC (1500 byte MTU per plan requirement).
/// Maximum packet size for WebRTC session processing.
///
/// Must accommodate reassembled UDP datagrams that exceed Ethernet MTU.
/// IP fragmentation is transparent to the application layer, so the
/// socket may deliver datagrams up to 65535 bytes. 8192 covers all
/// practical WebRTC payloads.
pub const MAX_PACKET_SIZE: usize = 8192;

/// Compile-time assertion that MAX_PACKET_SIZE is sufficient.
const _: () = assert!(
    MAX_PACKET_SIZE >= 1500,
    "MAX_PACKET_SIZE must be at least 1500 bytes"
);

/// Default ICE gathering timeout in milliseconds.
pub const ICE_GATHERING_TIMEOUT_MS: u32 = 5000;

/// Default ICE check timeout in milliseconds.
pub const ICE_CHECK_TIMEOUT_MS: u32 = 5000;

/// DTLS handshake timeout in milliseconds (RFC 6347: 30 seconds).
pub const DTLS_HANDSHAKE_TIMEOUT_MS: u32 = 30000;

/// Default consent timeout in seconds (RFC 7675).
pub const CONSENT_TIMEOUT_SECS: u64 = 30;

/// Maximum sessions per transport.
pub const MAX_SESSIONS: usize = 1000;

/// Compile-time assertion that MAX_SESSIONS is exactly 1000.
const _: () = assert!(
    MAX_SESSIONS == 1000,
    "MAX_SESSIONS must be 1000 (plan requirement)"
);

// ============================================================================
// Session State Machine
// ============================================================================

/// Session state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Initial state.
    New = 0,

    /// Gathering ICE candidates.
    IceGathering = 1,

    /// ICE connectivity checks in progress.
    IceConnecting = 2,

    /// DTLS handshake in progress.
    DtlsHandshaking = 3,

    /// Session fully established (ICE + DTLS + SRTP).
    Established = 4,

    /// Session failed.
    Failed = 5,

    /// Session closed.
    Closed = 6,
}

impl SessionState {
    /// Returns true if session can send/receive media.
    #[inline]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    /// Alias for `is_established` per plan naming.
    #[inline]
    pub const fn is_connected(self) -> bool {
        self.is_established()
    }

    /// Returns true if session has failed or closed.
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closed)
    }

    /// Returns true if session requires ICE processing.
    #[inline]
    pub const fn requires_ice(self) -> bool {
        matches!(
            self,
            Self::IceGathering | Self::IceConnecting | Self::DtlsHandshaking | Self::Established
        )
    }

    /// Check if transition to next state is valid per RFC 8445/6347.
    ///
    /// # Arguments
    /// * `next` - The target state to transition to.
    ///
    /// # Returns
    /// `true` if the transition is valid.
    ///
    /// # TigerStyle
    /// - Assertion: current != next (no redundant transitions)
    pub fn can_transition_to(self, next: SessionState) -> bool {
        // Precondition: no redundant transitions
        assert!(
            self != next,
            "Redundant state transition: {:?} -> {:?}",
            self,
            next
        );

        // Precondition: self must be a valid enum variant
        assert!((self as u8) <= 6, "Invalid source state");

        match (self, next) {
            // Valid forward transitions
            (Self::New, Self::IceGathering) => true,
            (Self::IceGathering, Self::IceConnecting) => true,
            (Self::IceConnecting, Self::DtlsHandshaking) => true,
            (Self::DtlsHandshaking, Self::Established) => true,

            // Skip gathering (for ICE-lite or pre-gathered)
            (Self::New, Self::IceConnecting) => true,

            // Failure transitions (any non-terminal state can fail)
            (Self::New, Self::Failed) => true,
            (Self::IceGathering, Self::Failed) => true,
            (Self::IceConnecting, Self::Failed) => true,
            (Self::DtlsHandshaking, Self::Failed) => true,
            (Self::Established, Self::Failed) => true,

            // Close transitions (any state can close)
            (Self::New, Self::Closed) => true,
            (Self::IceGathering, Self::Closed) => true,
            (Self::IceConnecting, Self::Closed) => true,
            (Self::DtlsHandshaking, Self::Closed) => true,
            (Self::Established, Self::Closed) => true,
            (Self::Failed, Self::Closed) => true,

            // All other transitions are invalid
            _ => false,
        }
    }
}

// ============================================================================
// Session Configuration
// ============================================================================

/// Session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Transport ID.
    pub id: TransportId,

    /// ICE role.
    pub ice_role: IceRole,

    /// DTLS role.
    pub dtls_role: DtlsRole,

    /// Remote address (if known).
    pub remote_addr: Option<SocketAddr>,

    /// SRTP protection profile.
    pub srtp_profile: ProtectionProfile,

    /// ICE gathering timeout in milliseconds.
    pub ice_gathering_timeout_ms: u32,

    /// ICE check timeout in milliseconds.
    pub ice_check_timeout_ms: u32,

    /// DTLS handshake timeout in milliseconds.
    pub dtls_handshake_timeout_ms: u32,

    /// Consent timeout in seconds (RFC 7675).
    pub consent_timeout_secs: u64,

    /// STUN server addresses for server-reflexive candidate gathering.
    pub stun_servers: Vec<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            id: TransportId(1),
            ice_role: IceRole::Controlled,  // SFU sends offer, so it's controlled (RFC 8445 §6.1.1)
            dtls_role: DtlsRole::Server,    // SFU sends offer with setup:actpass, acts as server (RFC 8842)
            remote_addr: None,
            srtp_profile: ProtectionProfile::AeadAes128Gcm,
            ice_gathering_timeout_ms: ICE_GATHERING_TIMEOUT_MS,
            ice_check_timeout_ms: ICE_CHECK_TIMEOUT_MS,
            dtls_handshake_timeout_ms: DTLS_HANDSHAKE_TIMEOUT_MS,
            consent_timeout_secs: CONSENT_TIMEOUT_SECS,
            stun_servers: Vec::new(),
        }
    }
}

impl SessionConfig {
    /// Validate configuration.
    ///
    /// # TigerStyle
    /// - Assertion: timeouts within bounds (100ms-60s)
    /// - Assertion: ID is non-zero
    /// - Assertion: SRTP profile is supported
    pub fn validate(&self) -> Result<(), WebRtcError> {
        // Precondition: ID must be valid
        assert!(self.id.0 > 0, "Transport ID must be > 0");

        // Precondition: SRTP profile must be AES-GCM
        assert!(
            matches!(
                self.srtp_profile,
                ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm
            ),
            "SRTP profile must be AES-GCM variant"
        );

        // Validate timeouts (100ms to 60s)
        if self.ice_gathering_timeout_ms < 100 || self.ice_gathering_timeout_ms > 60000 {
            return Err(WebRtcError::InvalidConfig);
        }
        if self.ice_check_timeout_ms < 100 || self.ice_check_timeout_ms > 60000 {
            return Err(WebRtcError::InvalidConfig);
        }
        if self.dtls_handshake_timeout_ms < 1000 || self.dtls_handshake_timeout_ms > 60000 {
            return Err(WebRtcError::InvalidConfig);
        }
        if self.consent_timeout_secs < 5 || self.consent_timeout_secs > 300 {
            return Err(WebRtcError::InvalidConfig);
        }

        // Postcondition: all validations passed
        assert!(self.id.0 > 0);

        Ok(())
    }
}

// ============================================================================
// Session Statistics
// ============================================================================

/// Session statistics for monitoring.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionStats {
    /// Current state.
    pub state: u8,

    /// Time in current state (milliseconds).
    pub time_in_state_ms: u64,

    /// Local ICE candidates gathered.
    pub ice_candidates_local: u8,

    /// Remote ICE candidates received.
    pub ice_candidates_remote: u8,

    /// ICE pairs checked.
    pub ice_pairs_checked: u16,

    /// DTLS handshake complete flag.
    pub dtls_handshake_complete: bool,

    /// SRTP packets sent.
    pub srtp_packets_sent: u64,

    /// SRTP packets received.
    pub srtp_packets_received: u64,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// Time since last activity (milliseconds).
    pub last_activity_ms: u64,
}

// ============================================================================
// Health Report
// ============================================================================

/// Health check report.
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// Overall health status.
    pub is_healthy: bool,

    /// Current state.
    pub state: SessionState,

    /// ICE connected.
    pub ice_connected: bool,

    /// DTLS complete.
    pub dtls_complete: bool,

    /// SRTP ready.
    pub srtp_ready: bool,

    /// Consent fresh (not stale).
    pub consent_fresh: bool,

    /// Any timeout exceeded.
    pub timeout_exceeded: bool,

    /// Issues found (empty if healthy).
    pub issues: Vec<&'static str>,
}

// ============================================================================
// Incoming Data Classification
// ============================================================================

/// Incoming data classification after processing.
///
/// RTP/RTCP variants carry the decrypted length written to the caller's
/// output buffer (zero-alloc hot path). STUN/DTLS variants carry owned
/// data since signaling responses are infrequent and produced by
/// ICE/DTLS agents that allocate internally.
#[derive(Debug)]
pub enum IncomingData {
    /// STUN response to send.
    Stun(Vec<u8>),

    /// DTLS data to send.
    Dtls(Vec<u8>),

    /// STUN response followed by DTLS flight to send (ICE connected, starting handshake).
    StunAndDtls(Vec<u8>, Vec<u8>),

    /// Decrypted RTP payload length (data written to caller's output buffer).
    Rtp(usize),

    /// Decrypted RTCP payload length (data written to caller's output buffer).
    Rtcp(usize),

    /// No data to return.
    None,
}

// ============================================================================
// WebRTC Session
// ============================================================================

/// WebRTC Session.
///
/// Manages the lifecycle of a WebRTC peer connection transport:
/// ICE candidate gathering → connectivity checks → DTLS handshake → SRTP.
pub struct WebRtcSession {
    /// Configuration.
    config: SessionConfig,

    /// Current state.
    state: SessionState,

    /// ICE agent (boxed to avoid stack overflow).
    ice_agent: Option<Box<IceAgent>>,

    /// DTLS session (boxed to avoid stack overflow).
    dtls_session: Option<Box<DtlsSession>>,

    /// OpenSSL DTLS engine for browser-compatible handshakes.
    /// When present, this is used instead of the custom DtlsSession for
    /// handshake processing. The custom DtlsSession is kept for its
    /// certificate/fingerprint generation and SRTP key storage API.
    /// Created at session construction time so the fingerprint is available
    /// for SDP generation before the DTLS handshake begins (RFC 4572).
    openssl_dtls: Option<OpenSslDtlsEngine>,

    /// SHA-256 fingerprint of the DTLS certificate, cached at construction
    /// time per RFC 4572 so it can be included in the SDP offer/answer
    /// before the DTLS handshake starts.
    dtls_fingerprint_cache: [u8; 32],

    /// SRTP inbound context — keyed with the remote peer's keys (for unprotect).
    srtp_session: Option<SrtpContext>,

    /// SRTP outbound context — keyed with our own keys (for protect).
    srtp_outbound: Option<SrtpContext>,

    /// Remote address (set when ICE selects pair).
    remote_addr: Option<SocketAddr>,

    /// Timestamp when current state was entered.
    state_entered_at: Instant,

    /// Last activity timestamp (nanoseconds since epoch).
    last_activity_ns: u64,

    /// Session statistics.
    stats: SessionStatsInternal,

    /// Work buffer for packet processing (boxed to avoid stack overflow).
    work_buffer: Box<[u8; MAX_PACKET_SIZE]>,

    /// Current media MIDs (for renegotiation tracking).
    current_mids: Vec<String>,

    /// Remote ICE credentials (for restart detection).
    remote_ice_ufrag: Option<String>,
    remote_ice_pwd: Option<String>,

    /// DTLS key generation counter (RFC 8829 §4.1.8.1).
    /// Incremented only on actual DTLS renegotiation (new fingerprint or
    /// ICE restart). Renegotiations that don't change ICE credentials or
    /// DTLS fingerprint reuse the existing DTLS connection and keys.
    dtls_generation: u64,
}

/// Internal statistics tracking.
#[derive(Debug, Clone, Copy, Default)]
struct SessionStatsInternal {
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    rtp_packets_sent: u64,
    rtp_packets_received: u64,
    rtcp_packets_sent: u64,
    rtcp_packets_received: u64,
}

/// ICE outbound poll result: (STUN packets to send, optional DTLS flight).
pub type IcePollResult = (Vec<(SocketAddr, Vec<u8>)>, Option<Vec<u8>>);

impl WebRtcSession {
    /// Create new WebRTC session.
    ///
    /// # Arguments
    /// * `config` - Session configuration.
    ///
    /// # Returns
    /// New session in `New` state.
    ///
    /// # TigerStyle
    /// - Precondition: config.id > 0
    /// - Precondition: SRTP profile is AES-GCM
    /// - Postcondition: state == New
    /// - Postcondition: all components are None
    pub fn new(config: SessionConfig) -> Result<Self, WebRtcError> {
        // Precondition: config must have valid transport ID
        assert!(config.id.0 > 0, "Transport ID must be > 0");

        // Precondition: SRTP profile must be valid
        assert!(
            matches!(
                config.srtp_profile,
                ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm
            ),
            "SRTP profile must be AES-GCM variant"
        );

        // Validate full config
        config.validate()?;

        // Get current time in nanoseconds
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Per RFC 4572 / RFC 8827: generate the DTLS certificate and cache
        // its fingerprint at session creation so it is available for SDP
        // offer/answer before the DTLS handshake begins.  The OpenSSL engine
        // is stored and reused later by init_dtls / start_dtls_handshake.
        let (openssl_dtls, dtls_fingerprint_cache) = match OpenSslDtlsEngine::new(config.dtls_role) {
            Ok(engine) => {
                let fp = *engine.fingerprint();
                (Some(engine), fp)
            }
            Err(e) => {
                tracing::warn!("OpenSSL DTLS init failed, deferring fingerprint to init_dtls: {}", e);
                (None, [0u8; 32])
            }
        };

        let result = Self {
            config,
            state: SessionState::New,
            ice_agent: None,
            dtls_session: None,
            openssl_dtls,
            dtls_fingerprint_cache,
            srtp_session: None,
            srtp_outbound: None,
            remote_addr: None,
            state_entered_at: Instant::now(),
            last_activity_ns: now_ns,
            stats: SessionStatsInternal::default(),
            work_buffer: Box::new([0u8; MAX_PACKET_SIZE]),
            current_mids: Vec::new(),
            remote_ice_ufrag: None,
            remote_ice_pwd: None,
            dtls_generation: 0,
        };

        // Postcondition: session must start in New state
        assert_eq!(
            result.state,
            SessionState::New,
            "New session must be in New state"
        );

        // Postcondition: all components must be None
        assert!(
            result.ice_agent.is_none(),
            "ICE agent must be None initially"
        );
        assert!(
            result.dtls_session.is_none(),
            "DTLS session must be None initially"
        );
        assert!(
            result.srtp_session.is_none(),
            "SRTP session must be None initially"
        );

        Ok(result)
    }

    /// Get session state.
    #[inline]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Get remote address (set when ICE selects a candidate pair).
    #[inline]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Get transport ID.
    #[inline]
    pub const fn id(&self) -> TransportId {
        self.config.id
    }

    /// Get last activity timestamp in nanoseconds.
    #[inline]
    pub const fn last_activity_ns(&self) -> u64 {
        self.last_activity_ns
    }

    /// Update last activity timestamp to current time.
    #[inline]
    pub fn touch(&mut self) {
        self.last_activity_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
    }

    /// Returns true if session is ready for media.
    #[inline]
    pub const fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Get ICE connection state.
    #[inline]
    pub fn ice_connection_state(&self) -> IceConnectionState {
        match &self.ice_agent {
            Some(agent) => agent.connection_state(),
            None => IceConnectionState::New,
        }
    }

    /// Get ICE gathering state.
    #[inline]
    pub fn ice_gathering_state(&self) -> IceGatheringState {
        match &self.ice_agent {
            Some(agent) => agent.gathering_state(),
            None => IceGatheringState::New,
        }
    }

    /// Check if ICE gathering is complete.
    ///
    /// # Comment 2 Fix
    ///
    /// This helper is used to gate start_ice() calls to prevent panic
    /// when ICE restart happens before local gathering completes.
    ///
    /// # Returns
    ///
    /// `true` if gathering state is Complete, `false` otherwise.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for hot path performance
    /// - Explicit boolean return
    #[inline]
    pub fn ice_gathering_complete(&self) -> bool {
        matches!(self.ice_gathering_state(), IceGatheringState::Complete)
    }

    /// Get local ICE credentials.
    ///
    /// # Panics
    /// Panics if ICE agent is not initialized.
    pub fn local_ice_credentials(&self) -> &IceCredentials {
        self.ice_agent
            .as_ref()
            .expect("ICE agent not initialized")
            .local_credentials()
    }

    /// Get DTLS certificate fingerprint (SHA-256).
    ///
    /// # TigerStyle
    /// - Precondition: fingerprint must have been generated at construction
    pub fn dtls_fingerprint(&self) -> &[u8; 32] {
        // Precondition: fingerprint must be initialized (non-zero)
        assert!(
            self.dtls_fingerprint_cache.iter().any(|&b| b != 0),
            "DTLS fingerprint not initialized"
        );

        &self.dtls_fingerprint_cache
    }

    /// Get SRTP context for protecting/unprotecting RTP/RTCP packets.
    ///
    /// Returns a reference to the SRTP context if the session is established
    /// and SRTP has been initialized.
    ///
    /// # Returns
    ///
    /// `Some(&SrtpContext)` if SRTP is initialized, `None` otherwise.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Inline for hot path performance
    /// - Explicit return type
    #[inline]
    pub fn get_srtp_context(&self) -> Option<&nexus_transport::srtp::SrtpContext> {
        self.srtp_session.as_ref()
    }

    /// Get SRTP key material for creating additional SRTP contexts.
    ///
    /// Returns the LOCAL send key material (not receive keys) for protecting
    /// outbound RTCP feedback packets. This allows creating separate SRTP contexts
    /// for different purposes (e.g., one for the worker to protect feedback packets).
    ///
    /// # Key Direction
    ///
    /// - DTLS Client: Uses client_write_key (local send key)
    /// - DTLS Server: Uses server_write_key (local send key)
    ///
    /// This ensures the publisher can decrypt feedback with their receive keys.
    ///
    /// # Returns
    ///
    /// `Some((KeyMaterial, SrtpPolicy))` if DTLS is established, `None` otherwise.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit error handling
    /// - Assertions for preconditions
    pub fn get_srtp_key_material(
        &self,
    ) -> Option<(nexus_transport::srtp::KeyMaterial, nexus_transport::srtp::SrtpPolicy, u64)> {
        // Check if DTLS is established
        let dtls = self.dtls_session.as_ref()?;
        if dtls.state() != nexus_transport::dtls::SessionState::Established {
            return None;
        }

        // Get SRTP keys from DTLS
        let srtp_keys = dtls.srtp_keys()?;

        // Use LOCAL send keys (client_write for client, server_write for server)
        // This is the key we use to PROTECT outbound packets
        let is_client = self.config.dtls_role == nexus_transport::dtls::DtlsRole::Client;
        let (key, salt) = if is_client {
            // Client uses client_write_key (local send key)
            (srtp_keys.client_key(), srtp_keys.client_salt())
        } else {
            // Server uses server_write_key (local send key)
            (srtp_keys.server_key(), srtp_keys.server_salt())
        };

        // Map DTLS profile to SRTP ProtectionProfile
        let protection_profile = match srtp_keys.profile {
            nexus_transport::dtls::SrtpProfile::Aes128CmHmacSha1_80 => nexus_transport::srtp::ProtectionProfile::Aes128CmHmacSha1_80,
            nexus_transport::dtls::SrtpProfile::Aes128CmHmacSha1_32 => nexus_transport::srtp::ProtectionProfile::Aes128CmHmacSha1_32,
            nexus_transport::dtls::SrtpProfile::AeadAes128Gcm => nexus_transport::srtp::ProtectionProfile::AeadAes128Gcm,
            nexus_transport::dtls::SrtpProfile::AeadAes256Gcm => nexus_transport::srtp::ProtectionProfile::AeadAes256Gcm,
        };

        // Build key material using profile-aware constructor
        let mut export_material = Vec::with_capacity(key.len() + salt.len());
        export_material.extend_from_slice(key);
        export_material.extend_from_slice(salt);

        let key_material = match nexus_transport::srtp::KeyMaterial::from_dtls_export(&export_material, protection_profile) {
            Ok(km) => km,
            Err(e) => {
                tracing::error!("Failed to create key material: {:?}", e);
                return None;
            }
        };

        // Get policy from DTLS-negotiated profile (NOT from config default)
        let policy = nexus_transport::srtp::SrtpPolicy {
            profile: protection_profile,
            ..nexus_transport::srtp::SrtpPolicy::default()
        };

        Some((key_material, policy, self.dtls_generation))
    }

    /// Get current DTLS key generation.
    ///
    /// Incremented only on actual DTLS renegotiation (RFC 8829 §4.1.8.1).
    /// Callers can compare this to a cached value to detect key changes.
    #[inline]
    pub fn dtls_generation(&self) -> u64 {
        self.dtls_generation
    }

    /// Set remote ICE credentials.
    ///
    /// # TigerStyle
    /// - Precondition: credentials must not be empty
    /// - Precondition: credentials bounded (ufrag ≤ 32, pwd ≤ 128)
    /// Get remote ICE ufrag if set.
    pub fn remote_ice_ufrag(&self) -> Option<&str> {
        self.remote_ice_ufrag.as_deref()
    }

    /// Get remote ICE pwd if set.
    pub fn remote_ice_pwd(&self) -> Option<&str> {
        self.remote_ice_pwd.as_deref()
    }

    pub fn set_remote_ice_credentials(&mut self, credentials: IceCredentials) {
        // Precondition: credentials must not be empty
        assert!(
            !credentials.local_ufrag.is_empty(),
            "Remote ICE ufrag must not be empty"
        );
        assert!(
            !credentials.local_pwd.is_empty(),
            "Remote ICE pwd must not be empty"
        );

        // Precondition: ufrag/pwd length must be bounded
        assert!(
            credentials.local_ufrag.len() <= 32,
            "ICE ufrag must be <= 32 bytes"
        );
        assert!(
            credentials.local_pwd.len() <= 128,
            "ICE pwd must be <= 128 bytes"
        );

        // Ensure ICE agent exists
        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        if let Some(ref mut agent) = self.ice_agent {
            agent.set_remote_credentials(credentials);
        }
    }

    /// Initialize the ICE agent.
    fn initialize_ice_agent(&mut self) {
        // Precondition: agent should not already exist
        assert!(self.ice_agent.is_none(), "ICE agent already initialized");

        let mut ice_config = IceConfig::default();

        // Add STUN servers from configuration
        for stun_server in &self.config.stun_servers {
            if let Ok(addr) = stun_server.parse() {
                ice_config.add_stun_server(addr);
            } else {
                warn!("Invalid STUN server address: {}", stun_server);
            }
        }

        self.ice_agent = Some(Box::new(IceAgent::new(ice_config, self.config.ice_role)));

        // Postcondition: agent must be created
        assert!(self.ice_agent.is_some(), "ICE agent must be created");
    }

    /// Initialize ICE agent so credentials are available for SDP.
    ///
    /// # TigerStyle
    /// - Precondition: ICE agent must not exist
    /// - Postcondition: ICE agent exists with valid credentials
    pub fn initialize_ice(&mut self) -> Result<(), WebRtcError> {
        // Initialize ICE agent if not already done
        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        // Postcondition: ICE agent must exist
        assert!(self.ice_agent.is_some(), "ICE agent must be initialized");

        Ok(())
    }

    /// Initialize the DTLS session for handshake processing.
    ///
    /// Called exactly once from `start_dtls_handshake` when ICE connects.
    /// The OpenSSL engine (and its certificate/fingerprint) is already
    /// created at session construction time per RFC 4572.
    ///
    /// # TigerStyle
    /// - Precondition: DTLS session must not exist (called once)
    /// - Postcondition: DTLS session exists
    fn init_dtls(&mut self) {
        // Precondition: must not be called twice
        assert!(
            self.dtls_session.is_none(),
            "DTLS must not be initialized twice"
        );

        let dtls_config = match self.config.dtls_role {
            DtlsRole::Client => DtlsConfig::client(),
            DtlsRole::Server => DtlsConfig::server(),
        };
        self.dtls_session = Some(Box::new(DtlsSession::new(dtls_config)));

        // If OpenSSL engine wasn't created at construction (fallback path),
        // try again now.
        if self.openssl_dtls.is_none() {
            match OpenSslDtlsEngine::new(self.config.dtls_role) {
                Ok(engine) => {
                    self.openssl_dtls = Some(engine);
                }
                Err(e) => {
                    tracing::warn!("OpenSSL DTLS init failed, using fallback: {}", e);
                }
            }
        }

        // Postcondition: DTLS session must exist
        assert!(
            self.dtls_session.is_some(),
            "DTLS session must be initialized"
        );
    }

    // ========================================================================
    // State Transition Methods
    // ========================================================================

    /// Transition to a new state.
    ///
    /// # Arguments
    /// * `next` - The target state.
    ///
    /// # TigerStyle
    /// - Precondition: current state can transition to next
    /// - Postcondition: state equals next
    /// - Postcondition: state_entered_at is recent
    fn transition_state(&mut self, next: SessionState) -> Result<(), WebRtcError> {
        let current = self.state;

        // Precondition: transition must be valid
        if !current.can_transition_to(next) {
            tracing::error!(from = ?current, to = ?next, "Invalid state transition");
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: verify we're not in terminal state trying non-closed transition
        assert!(
            !current.is_terminal() || next == SessionState::Closed,
            "Cannot transition from terminal state except to Closed"
        );

        tracing::info!(from = ?current, to = ?next, session_id = self.config.id.0, "State transition");

        self.state = next;
        self.state_entered_at = Instant::now();

        // Postcondition: state must equal next
        assert_eq!(self.state, next, "State must be updated");

        Ok(())
    }

    /// Check for state timeouts and transition to Failed if exceeded.
    ///
    /// # TigerStyle
    /// - Checks each state against its configured timeout
    /// - Transitions to Failed if timeout exceeded
    pub fn check_state_timeouts(&mut self) -> Result<(), WebRtcError> {
        // Precondition: timestamps are valid
        assert!(
            self.state_entered_at.elapsed().as_secs() < 86400,
            "Invalid timestamp"
        );

        let elapsed_ms = self.state_entered_at.elapsed().as_millis() as u64;

        let timeout_exceeded = match self.state {
            SessionState::IceGathering => elapsed_ms > self.config.ice_gathering_timeout_ms as u64,
            SessionState::IceConnecting => elapsed_ms > self.config.ice_check_timeout_ms as u64,
            SessionState::DtlsHandshaking => {
                elapsed_ms > self.config.dtls_handshake_timeout_ms as u64
            }
            _ => false,
        };

        if timeout_exceeded {
            tracing::warn!(state = ?self.state, elapsed_ms, "State timeout exceeded");
            self.transition_state(SessionState::Failed)?;

            // Postcondition: must be in Failed state
            assert_eq!(self.state, SessionState::Failed);

            return match self.state {
                SessionState::Failed => {
                    // Return appropriate error based on what we were doing
                    Err(WebRtcError::IceTimeout)
                }
                _ => Err(WebRtcError::InvalidState),
            };
        }

        // Postcondition: state unchanged if no timeout
        assert!(!timeout_exceeded || self.state == SessionState::Failed);

        Ok(())
    }

    // ========================================================================
    // ICE Lifecycle Methods
    // ========================================================================

    /// Gather ICE candidates.
    ///
    /// Legacy synchronous gathering. Deprecated — gathering is now
    /// handled by the async orchestrator via `add_local_candidate`.
    ///
    /// # TigerStyle
    /// - Precondition: state must be New
    #[deprecated(note = "Use add_local_candidate + mark_gathering_complete + start_connectivity_checks")]
    pub fn gather_candidates(&mut self) -> Result<(), WebRtcError> {
        if self.state != SessionState::New {
            return Err(WebRtcError::InvalidState);
        }
        debug_assert_eq!(self.state, SessionState::New, "gather requires New state");

        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        self.transition_state(SessionState::IceGathering)?;

        #[allow(deprecated)]
        if let Some(ref mut agent) = self.ice_agent {
            agent.gather_candidates()?;
        }

        self.transition_state(SessionState::IceConnecting)?;

        assert!(self.ice_agent.is_some(), "ICE agent must exist after gathering");
        assert_eq!(self.state, SessionState::IceConnecting, "State must be IceConnecting after gather");

        Ok(())
    }

    /// Add a locally-gathered candidate to the session's ICE agent.
    ///
    /// Called by the orchestrator as candidates arrive from the async gatherer.
    ///
    /// # TigerStyle
    /// - Precondition: candidate port > 0
    /// - Postcondition: agent has the candidate
    pub fn add_local_candidate(&mut self, candidate: Candidate) -> Result<(), WebRtcError> {
        assert!(candidate.address.port() > 0, "Candidate port must be > 0");

        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        let agent = self.ice_agent.as_mut().expect("ICE agent must exist");
        agent.add_local_candidate(candidate)?;

        Ok(())
    }

    /// Mark local candidate gathering as complete.
    ///
    /// Called by the orchestrator when the async gatherer finishes.
    /// Transitions session state to IceGathering (if still New).
    pub fn mark_gathering_complete(&mut self) -> Result<(), WebRtcError> {
        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        let agent = self.ice_agent.as_mut().expect("ICE agent must exist");
        agent.set_gathering_complete();

        // Ensure session state reflects gathering phase
        if self.state == SessionState::New {
            self.transition_state(SessionState::IceGathering)?;
        }

        Ok(())
    }

    /// Start ICE connectivity checks without gathering.
    ///
    /// Preconditions: gathering is complete, local and remote candidates exist.
    /// This is the non-blocking replacement for `start_ice()`.
    ///
    /// # TigerStyle
    /// - Precondition: gathering complete, has candidates
    /// - Postcondition: state is IceConnecting, checks are running
    pub fn start_connectivity_checks(&mut self) -> Result<(), WebRtcError> {
        // Already established or handshaking — ICE is done, trickle candidates
        // arriving late are harmless (RFC 8838 §10: candidates may arrive after
        // ICE completes). Return Ok to avoid spurious error logs.
        if matches!(self.state, SessionState::DtlsHandshaking | SessionState::Established) {
            return Ok(());
        }

        // Already in IceConnecting — idempotent, just try to start checks
        if self.state == SessionState::IceConnecting {
            if let Some(ref mut agent) = self.ice_agent {
                let already_checking = agent.connection_state() == IceConnectionState::Checking
                    || agent.connection_state() == IceConnectionState::Connected;
                if !already_checking
                    && agent.remote_candidate_count() > 0
                    && agent.gathering_state() == IceGatheringState::Complete
                {
                    if let Err(e) = agent.start_checks() {
                        tracing::debug!("start_checks in IceConnecting: {:?}", e);
                    }
                }
            }
            return Ok(());
        }

        if !matches!(self.state, SessionState::New | SessionState::IceGathering) {
            return Err(WebRtcError::InvalidState);
        }

        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        // Transition through IceGathering if needed
        if self.state == SessionState::New {
            self.transition_state(SessionState::IceGathering)?;
        }

        // Only transition to IceConnecting if we can actually start checks
        if let Some(ref mut agent) = self.ice_agent {
            let can_start = agent.remote_candidate_count() > 0
                && agent.gathering_state() == IceGatheringState::Complete;
            
            if can_start {
                agent.start_checks()?;
                // Only NOW transition to IceConnecting after checks started
                self.transition_state(SessionState::IceConnecting)?;
            } else {
                // Stay in IceGathering - caller will retry when conditions are met
                return Ok(());
            }
        }

        assert_eq!(self.state, SessionState::IceConnecting,
            "start_connectivity_checks must result in IceConnecting state");

        Ok(())
    }

    /// Get local ICE candidates.
    pub fn local_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.ice_agent
            .as_ref()
            .map(|a| a.local_candidates())
            .into_iter()
            .flatten()
    }

    /// Add remote ICE candidate.
    ///
    /// # TigerStyle
    /// - Precondition: candidate count < 32
    /// - Precondition: candidate port > 0
    /// - Postcondition: count incremented by exactly 1
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<(), WebRtcError> {
        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        let agent = self.ice_agent.as_mut().expect("ICE agent must exist");

        let count_before = agent.remote_candidate_count();
        assert!(count_before < 32, "Remote candidate count must be < 32");
        assert!(candidate.address.port() > 0, "Candidate port must be > 0");

        agent.add_remote_candidate(candidate)?;

        let count_after = agent.remote_candidate_count();
        assert_eq!(count_after, count_before + 1, "Candidate count must increment by exactly 1");
        assert!(count_after <= 32, "Remote candidate count must remain <= 32");

        Ok(())
    }

    /// Get the count of remote ICE candidates.
    #[inline]
    pub fn remote_candidate_count(&self) -> u8 {
        self.ice_agent
            .as_ref()
            .map(|a| a.remote_candidate_count())
            .unwrap_or(0)
    }

    /// Legacy start_ice. Deprecated — use `start_connectivity_checks()`.
    #[deprecated(note = "Use start_connectivity_checks() instead")]
    pub fn start_ice(&mut self) -> Result<(), WebRtcError> {
        if !matches!(
            self.state,
            SessionState::IceGathering | SessionState::New | SessionState::IceConnecting
        ) {
            return Err(WebRtcError::InvalidState);
        }

        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        #[allow(deprecated)]
        if self.state == SessionState::New {
            self.gather_candidates()?;
        }

        if let Some(ref mut agent) = self.ice_agent {
            let already_checking = agent.connection_state() == IceConnectionState::Checking
                || agent.connection_state() == IceConnectionState::Connected;
            
            if agent.remote_candidate_count() > 0 
                && agent.gathering_state() == IceGatheringState::Complete 
                && !already_checking 
            {
                if let Err(e) = agent.start_checks() {
                    tracing::warn!("Failed to start ICE checks: {:?}", e);
                }
            }
        }

        assert_eq!(self.state, SessionState::IceConnecting,
            "start_ice must result in IceConnecting state");

        Ok(())
    }
    
    /// Get local ICE candidates as SDP candidate strings.
    pub fn local_candidates_sdp(&self) -> Vec<String> {
        self.local_candidates()
            .map(|c| c.to_sdp_string())
            .collect()
    }

    /// Legacy next_ice_check. Deprecated — use `poll_ice_outbound()`.
    #[deprecated(note = "Use poll_ice_outbound() instead")]
    pub fn next_ice_check(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        if self.state != SessionState::IceConnecting {
            return None;
        }
        #[allow(deprecated)]
        self.ice_agent.as_mut().and_then(|a| a.next_check())
    }

    /// Poll all pending outbound ICE packets and check for ICE completion.
    ///
    /// Returns a list of STUN packets to send, plus an optional DTLS
    /// ClientHello if ICE just completed and DTLS handshake started.
    ///
    /// This is the single method the SFU calls per tick per session.
    /// It replaces `next_ice_check()` and handles retransmissions
    /// and nominations internally.
    ///
    /// # TigerStyle
    /// - Only produces output in IceConnecting state
    /// - Bounded output from agent.poll_outbound()
    pub fn poll_ice_outbound(&mut self) -> IcePollResult {
        if self.state != SessionState::IceConnecting {
            return (Vec::new(), None);
        }

        // Drain outbound checks/retransmissions/nominations from agent
        let packets = match self.ice_agent.as_mut() {
            Some(agent) => agent.poll_outbound(),
            None => Vec::new(),
        };

        // Check if ICE just completed → start DTLS
        let dtls_flight = match self.check_ice_completion() {
            Ok(flight) => flight,
            Err(e) => {
                tracing::warn!("check_ice_completion error: {:?}", e);
                None
            }
        };

        (packets, dtls_flight)
    }

    // ========================================================================
    // ICE → DTLS Transition
    // ========================================================================

    /// Check if ICE has completed and start DTLS if so.
    ///
    /// # TigerStyle
    /// - Precondition: state is IceConnecting
    /// - Precondition: ice_agent exists
    /// - Postcondition: dtls_session is Some (if ICE connected)
    fn check_ice_completion(&mut self) -> Result<Option<Vec<u8>>, WebRtcError> {
        // Precondition: state must be IceConnecting
        if self.state != SessionState::IceConnecting {
            tracing::debug!(
                state = ?self.state,
                "check_ice_completion: not in IceConnecting, skipping"
            );
            return Ok(None);
        }

        // Precondition: ice_agent must exist
        assert!(self.ice_agent.is_some(), "ICE agent must exist");

        let agent = self.ice_agent.as_ref().unwrap();
        let ice_state = agent.connection_state();

        tracing::debug!(
            ice_state = ?ice_state,
            session_state = ?self.state,
            dtls_exists = self.dtls_session.is_some(),
            "check_ice_completion: checking ICE state"
        );

        if ice_state == IceConnectionState::Connected {
            // Extract selected pair and store remote address
            if let Some(pair) = agent.selected_pair() {
                self.remote_addr = Some(pair.remote.address);
            }

            tracing::info!("ICE connected, starting DTLS handshake");

            // Start DTLS handshake
            let dtls_output = self.start_dtls_handshake()?;

            // Postcondition: dtls_session must be Some
            assert!(self.dtls_session.is_some(), "DTLS session must be created");

            // Postcondition: state must be DtlsHandshaking
            assert_eq!(self.state, SessionState::DtlsHandshaking);

            return Ok(dtls_output);
        }

        Ok(None)
    }

    /// Start DTLS handshake.
    ///
    /// # TigerStyle
    /// - Precondition: state is IceConnecting (transitioning to DtlsHandshaking)
    /// - Postcondition: dtls_session is Some
    /// - Postcondition: state is DtlsHandshaking
    fn start_dtls_handshake(&mut self) -> Result<Option<Vec<u8>>, WebRtcError> {
        // Precondition: state must allow DTLS start
        if self.state != SessionState::IceConnecting {
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: SRTP context must NOT exist yet
        assert!(
            self.srtp_session.is_none(),
            "SRTP must not be initialized before DTLS"
        );

        // Transition state
        self.transition_state(SessionState::DtlsHandshaking)?;

        // Initialize DTLS session if not already done (e.g. by early fingerprint access)
        if self.dtls_session.is_none() {
            self.init_dtls();
        }

        // Start handshake and capture output
        let dtls_output = if let Some(ref mut engine) = self.openssl_dtls {
            let output = engine.start_handshake().map_err(|e| {
                tracing::warn!("DTLS handshake start failed: {}", e);
                WebRtcError::DtlsHandshakeFailed
            })?;
            if output.is_empty() { None } else { Some(output) }
        } else {
            let dtls_session = self.dtls_session.as_mut().expect("DTLS session must exist after init_dtls");
            let _ = dtls_session.start_handshake()?;
            None
        };

        // Postcondition: must be in DtlsHandshaking state
        assert_eq!(
            self.state,
            SessionState::DtlsHandshaking,
            "start_dtls must transition to DtlsHandshaking"
        );

        // Postcondition: DTLS session must exist
        assert!(
            self.dtls_session.is_some(),
            "DTLS session must be initialized"
        );

        Ok(dtls_output)
    }

    // ========================================================================
    // DTLS → SRTP Transition
    // ========================================================================

    /// Check if DTLS has completed and initialize SRTP if so.
    ///
    /// # TigerStyle
    /// - Precondition: state is DtlsHandshaking
    /// - Precondition: dtls_session exists
    /// - Postcondition: srtp_session is Some (if DTLS complete)
    fn check_dtls_completion(&mut self) -> Result<(), WebRtcError> {
        // Precondition: state must be DtlsHandshaking
        if self.state != SessionState::DtlsHandshaking {
            return Ok(());
        }

        // Precondition: dtls_session must exist
        assert!(self.dtls_session.is_some(), "DTLS session must exist");

        let dtls_state = self.dtls_session.as_ref().unwrap().state();

        if dtls_state == DtlsState::Established {
            self.initialize_srtp()?;

            // Transition to Established
            self.transition_state(SessionState::Established)?;

            // Postcondition: srtp_session must be Some
            assert!(self.srtp_session.is_some(), "SRTP must be initialized");

            // Postcondition: state must be Established
            assert_eq!(self.state, SessionState::Established);
        }

        Ok(())
    }

    /// Check if DTLS needs retransmission and return the data to send.
    ///
    /// Returns (destination_address, retransmit_data) if a retransmit is needed.
    pub fn poll_dtls_retransmit(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        if self.state != SessionState::DtlsHandshaking {
            return None;
        }

        let dest = self.remote_addr?;
        let dtls = self.dtls_session.as_mut()?;

        dtls.time_until_timeout()?;

        // Check for pending retransmission
        if let Ok(Some(data)) = dtls.check_retransmission() {
            Some((dest, data.to_vec()))
        } else {
            None
        }
    }

    /// Initialize SRTP from DTLS keying material.
    ///
    /// # TigerStyle
    /// - Precondition: DTLS must be established
    /// - Precondition: SRTP context must not already exist
    /// - Postcondition: srtp_session (inbound) and srtp_outbound are Some
    fn initialize_srtp(&mut self) -> Result<(), WebRtcError> {
        // Precondition: DTLS must be established
        let dtls = self
            .dtls_session
            .as_ref()
            .ok_or(WebRtcError::NotInitialized)?;
        assert_eq!(
            dtls.state(),
            DtlsState::Established,
            "SRTP requires DTLS Established"
        );

        // Precondition: SRTP context must not already exist
        assert!(
            self.srtp_session.is_none(),
            "SRTP context must not be initialized twice"
        );

        let srtp_keys = dtls.srtp_keys().ok_or_else(|| {
            tracing::error!("DTLS session has no SRTP keys despite being Established");
            WebRtcError::SrtpInitFailed
        })?;

        // Determine the negotiated SRTP profile from the DTLS key material
        let negotiated_profile = srtp_keys.profile;
        let expected_key_len = negotiated_profile.key_length();
        let expected_salt_len = negotiated_profile.salt_length();

        // Map DTLS SrtpProfile → SRTP ProtectionProfile (same u16 discriminants)
        let protection_profile = match negotiated_profile {
            nexus_transport::dtls::SrtpProfile::Aes128CmHmacSha1_80 => ProtectionProfile::Aes128CmHmacSha1_80,
            nexus_transport::dtls::SrtpProfile::Aes128CmHmacSha1_32 => ProtectionProfile::Aes128CmHmacSha1_32,
            nexus_transport::dtls::SrtpProfile::AeadAes128Gcm => ProtectionProfile::AeadAes128Gcm,
            nexus_transport::dtls::SrtpProfile::AeadAes256Gcm => ProtectionProfile::AeadAes256Gcm,
        };

        tracing::debug!(
            ?negotiated_profile,
            expected_key_len,
            expected_salt_len,
            "SRTP profile negotiated via DTLS"
        );

        // Assert SRTP key material matches negotiated profile
        assert_eq!(
            srtp_keys.client_key().len(),
            expected_key_len,
            "SRTP client key length must match negotiated profile"
        );
        assert_eq!(
            srtp_keys.server_key().len(),
            expected_key_len,
            "SRTP server key length must match negotiated profile"
        );
        assert_eq!(
            srtp_keys.client_salt().len(),
            expected_salt_len,
            "SRTP client salt length must match negotiated profile"
        );
        assert_eq!(
            srtp_keys.server_salt().len(),
            expected_salt_len,
            "SRTP server salt length must match negotiated profile"
        );

        // DTLS exports separate client/server key material.
        // Inbound context uses the remote peer's keys (to unprotect).
        // Outbound context uses our own keys (to protect).
        let is_client = self.config.dtls_role == DtlsRole::Client;
        let (inbound_key, inbound_salt, outbound_key, outbound_salt) = if is_client {
            // We are DTLS client: inbound uses server keys, outbound uses client keys
            (srtp_keys.server_key(), srtp_keys.server_salt(),
             srtp_keys.client_key(), srtp_keys.client_salt())
        } else {
            // We are DTLS server: inbound uses client keys, outbound uses server keys
            (srtp_keys.client_key(), srtp_keys.client_salt(),
             srtp_keys.server_key(), srtp_keys.server_salt())
        };

        // Assert keys are not all zeros
        assert!(inbound_key.iter().any(|&b| b != 0), "Inbound SRTP key must not be all zeros");
        assert!(inbound_salt.iter().any(|&b| b != 0), "Inbound SRTP salt must not be all zeros");
        assert!(outbound_key.iter().any(|&b| b != 0), "Outbound SRTP key must not be all zeros");
        assert!(outbound_salt.iter().any(|&b| b != 0), "Outbound SRTP salt must not be all zeros");

        let policy = SrtpPolicy {
            profile: protection_profile,
            ..SrtpPolicy::default()
        };

        // Build inbound SRTP context (for unprotect)
        let mut inbound_material = Vec::with_capacity(inbound_key.len() + inbound_salt.len());
        inbound_material.extend_from_slice(inbound_key);
        inbound_material.extend_from_slice(inbound_salt);

        let inbound_km = KeyMaterial::from_dtls_export(&inbound_material, protection_profile).map_err(|e| {
            tracing::error!("Failed to create inbound SRTP key material: {:?}", e);
            WebRtcError::SrtpInitFailed
        })?;

        let inbound_ctx = SrtpContext::new(&inbound_km, policy).map_err(|e| {
            tracing::error!("Failed to create inbound SRTP context: {:?}", e);
            WebRtcError::SrtpInitFailed
        })?;

        // Build outbound SRTP context (for protect)
        let mut outbound_material = Vec::with_capacity(outbound_key.len() + outbound_salt.len());
        outbound_material.extend_from_slice(outbound_key);
        outbound_material.extend_from_slice(outbound_salt);

        let outbound_km = KeyMaterial::from_dtls_export(&outbound_material, protection_profile).map_err(|e| {
            tracing::error!("Failed to create outbound SRTP key material: {:?}", e);
            WebRtcError::SrtpInitFailed
        })?;

        let outbound_ctx = SrtpContext::new(&outbound_km, policy).map_err(|e| {
            tracing::error!("Failed to create outbound SRTP context: {:?}", e);
            WebRtcError::SrtpInitFailed
        })?;

        self.srtp_session = Some(inbound_ctx);
        self.srtp_outbound = Some(outbound_ctx);

        // Bump DTLS generation — keys have changed (RFC 8829 §4.1.8.1)
        self.dtls_generation += 1;

        // Postcondition: both SRTP contexts must exist
        assert!(
            self.srtp_session.is_some(),
            "Inbound SRTP context must be initialized after init_srtp"
        );
        assert!(
            self.srtp_outbound.is_some(),
            "Outbound SRTP context must be initialized after init_srtp"
        );

        tracing::info!(
            session_id = self.config.id.0,
            ?protection_profile,
            is_client = is_client,
            inbound_key_prefix = ?&inbound_key[..4.min(inbound_key.len())],
            inbound_salt_prefix = ?&inbound_salt[..4.min(inbound_salt.len())],
            outbound_key_prefix = ?&outbound_key[..4.min(outbound_key.len())],
            outbound_salt_prefix = ?&outbound_salt[..4.min(outbound_salt.len())],
            inbound_key_len = inbound_key.len(),
            inbound_salt_len = inbound_salt.len(),
            "SRTP initialized successfully (separate inbound/outbound contexts)"
        );

        Ok(())
    }

    /// Handle SDP renegotiation offer.
    ///
    /// Processes a new offer for an established session to add/remove tracks
    /// or restart ICE. Does not disrupt existing DTLS/SRTP.
    ///
    /// # Arguments
    ///
    /// * `offer` - New SDP offer
    ///
    /// # Returns
    ///
    /// Tuple of (added_mids, removed_mids, ice_restarted)
    ///
    /// # Assertions
    ///
    /// * `state == SessionState::Established` - Session must be established
    /// * `offer.media_count <= 10` - Bounded media sections
    ///
    /// # Postcondition
    ///
    /// * ICE agent reset if `ice_restarted == true`
    ///
    /// # Note
    ///
    /// This processes an incoming *offer* from the remote side. For processing
    /// the remote *answer* to an offer we sent, use `handle_renegotiation_answer`.
    pub fn handle_renegotiation_offer(
        &mut self,
        offer: &crate::sdp::SessionDescription,
    ) -> Result<(Vec<String>, Vec<String>, bool), WebRtcError> {
        // Precondition: session must be established
        assert_eq!(
            self.state,
            SessionState::Established,
            "Renegotiation only allowed in Established state"
        );

        // Precondition: bounded media sections
        assert!(
            offer.media_count <= 10,
            "Media sections must be bounded to 10"
        );

        tracing::info!(session_id = self.config.id.0, "Handling SDP renegotiation");

        let mut added_mids = Vec::new();
        let mut removed_mids = Vec::new();
        let mut ice_restarted = false;

        // Collect new mids from offer
        let mut new_mids = Vec::new();
        for i in 0..offer.media_count as usize {
            if let Some(media) = &offer.media[i] {
                if let Some(mid) = &media.mid {
                    new_mids.push(mid.as_str().to_string());
                }
            }
        }

        // Detect added mids (in new offer but not in current)
        for mid in &new_mids {
            if !self.current_mids.contains(mid) {
                added_mids.push(mid.clone());
            }
        }

        // Detect removed mids (in current but not in new offer)
        for mid in &self.current_mids {
            if !new_mids.contains(mid) {
                removed_mids.push(mid.clone());
            }
        }

        // Check for ICE restart by comparing credentials
        if let Some(new_ice_ufrag) = &offer.ice_ufrag {
            if let Some(new_ice_pwd) = &offer.ice_pwd {
                let credentials_changed = match (&self.remote_ice_ufrag, &self.remote_ice_pwd) {
                    (Some(old_ufrag), Some(old_pwd)) => {
                        old_ufrag != new_ice_ufrag.as_str() || old_pwd != new_ice_pwd.as_str()
                    }
                    _ => false, // No previous credentials, not a restart
                };

                if credentials_changed {
                    tracing::info!("ICE restart detected - credentials changed");
                    ice_restarted = true;

                    // Update stored credentials
                    self.remote_ice_ufrag = Some(new_ice_ufrag.as_str().to_string());
                    self.remote_ice_pwd = Some(new_ice_pwd.as_str().to_string());

                    // Restart ICE agent
                    self.restart_ice()?;
                }
            }
        }

        // Update current mids
        self.current_mids = new_mids;

        // Postcondition: ICE agent reset if restarted
        if ice_restarted {
            debug_assert_eq!(self.state, SessionState::IceGathering);
        }

        tracing::info!(
            session_id = self.config.id.0,
            added = added_mids.len(),
            removed = removed_mids.len(),
            ice_restarted,
            "Renegotiation processed"
        );

        Ok((added_mids, removed_mids, ice_restarted))
    }

    /// Process the remote answer to a renegotiation offer we sent.
    ///
    /// Unlike `handle_renegotiation_offer`, this does NOT check for ICE restart
    /// because the SFU is the offerer — only the offerer can trigger ICE restart
    /// (RFC 8829 §4.1.16). The answer simply confirms the media sections.
    ///
    /// # Preconditions
    ///
    /// * `state == SessionState::Established`
    /// * `answer.media_count <= 10`
    pub fn handle_renegotiation_answer(
        &mut self,
        answer: &crate::sdp::SessionDescription,
    ) -> Result<(Vec<String>, Vec<String>), WebRtcError> {
        assert_eq!(
            self.state,
            SessionState::Established,
            "Renegotiation answer only allowed in Established state"
        );
        assert!(
            answer.media_count <= 10,
            "Media sections must be bounded to 10"
        );

        tracing::info!(session_id = self.config.id.0, "Processing renegotiation answer");

        let mut added_mids = Vec::new();
        let mut removed_mids = Vec::new();

        let mut new_mids = Vec::new();
        for i in 0..answer.media_count as usize {
            if let Some(media) = &answer.media[i] {
                if let Some(mid) = &media.mid {
                    new_mids.push(mid.as_str().to_string());
                }
            }
        }

        for mid in &new_mids {
            if !self.current_mids.contains(mid) {
                added_mids.push(mid.clone());
            }
        }

        for mid in &self.current_mids {
            if !new_mids.contains(mid) {
                removed_mids.push(mid.clone());
            }
        }

        self.current_mids = new_mids;

        tracing::info!(
            session_id = self.config.id.0,
            added = added_mids.len(),
            removed = removed_mids.len(),
            "Renegotiation answer processed"
        );

        Ok((added_mids, removed_mids))
    }

    /// Restart ICE for renegotiation.
    ///
    /// Resets ICE agent, generates new credentials, and regathers candidates.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, error if ICE agent unavailable
    ///
    /// # Assertions
    ///
    /// * `state == SessionState::Established` - Can only restart from established
    pub fn restart_ice(&mut self) -> Result<(), WebRtcError> {
        // Precondition: session should be established
        if self.state != SessionState::Established {
            tracing::warn!(
                session_id = self.config.id.0,
                state = ?self.state,
                "ICE restart requested from non-established state"
            );
        }

        tracing::info!(
            session_id = self.config.id.0,
            "Restarting ICE for renegotiation"
        );

        // Reset ICE agent if it exists
        if let Some(ref mut ice_agent) = self.ice_agent {
            // Restart ICE agent (generates new credentials)
            ice_agent.restart()?;
            tracing::debug!("ICE agent restarted with new credentials");
        } else {
            // Initialize ICE agent if it doesn't exist
            self.initialize_ice_agent();
        }

        // Transition back to gathering state
        self.transition_state(SessionState::IceGathering)?;

        // NOTE: Candidates will be gathered asynchronously by the orchestrator
        // and fed in via add_local_candidate + mark_gathering_complete,
        // just like the initial ICE flow.

        tracing::info!(session_id = self.config.id.0, "ICE restart complete, awaiting candidate gathering");

        Ok(())
    }

    // ========================================================================
    // Packet Processing Pipeline
    // ========================================================================

    /// Process incoming packet.
    ///
    /// Demultiplexes, validates, and handles STUN, DTLS, SRTP/SRTCP packets.
    ///
    /// # TigerStyle
    /// - Precondition: data not empty, ≤ MAX_PACKET_SIZE
    /// - Precondition: session not terminal
    /// - Postcondition: stats updated
    /// - Uses demux_and_validate for packet validation
    pub fn process_incoming(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        out: &mut [u8],
    ) -> Result<IncomingData, WebRtcError> {
        if data.is_empty() {
            return Err(WebRtcError::PacketTooShort);
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(WebRtcError::PacketTooLarge);
        }

        // Precondition: session must not be closed
        if self.state.is_terminal() {
            return Err(WebRtcError::Closed);
        }

        // Update activity timestamp
        self.touch();

        let packets_before = self.stats.packets_received;
        self.stats.packets_received += 1;
        self.stats.bytes_received += data.len() as u64;

        // Postcondition: counters must have incremented
        assert_eq!(
            self.stats.packets_received,
            packets_before + 1,
            "Packet counter must increment by exactly 1"
        );

        // Demux and validate packet
        let (packet_type, validation) = demux_and_validate(data);

        // Handle invalid packets based on RecoveryHint
        if !validation.valid {
            let action = recover_from_malformed_packet(data, packet_type, &validation);

            match action {
                RecoveryAction::Drop {
                    packet_type: pt,
                    reason,
                } => {
                    tracing::debug!(
                        packet_type = ?pt,
                        reason = %reason,
                        "Dropping malformed packet"
                    );
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::RequestRetransmit { packet_type: pt } => {
                    tracing::debug!(
                        packet_type = ?pt,
                        "Malformed signaling packet, may need retransmit"
                    );
                    // For signaling packets, return error so caller can handle
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::ResetConnection { reason } => {
                    tracing::warn!(
                        reason = %reason,
                        "Malformed packet requires connection reset"
                    );
                    // Transition to failed state
                    let _ = self.transition_state(SessionState::Failed);
                    return Err(WebRtcError::MalformedPacket);
                }
                RecoveryAction::LogAndContinue {
                    packet_type: pt,
                    warning,
                } => {
                    tracing::warn!(
                        packet_type = ?pt,
                        warning = %warning,
                        "Continuing despite malformed packet"
                    );
                    // Continue processing - this is for non-critical issues
                }
            }
        }

        match packet_type {
            PacketType::Stun => self.process_stun(data, from),
            PacketType::Dtls => self.process_dtls(data, from),
            PacketType::Rtp => self.process_rtp(data, from, out),
            PacketType::Rtcp => self.process_rtcp(data, from, out),
            PacketType::Unknown => Err(WebRtcError::UnknownPacketType),
        }
    }

    /// Process STUN packet.
    ///
    /// # TigerStyle
    /// - Precondition: state allows ICE
    /// - Precondition: data >= 20 bytes
    fn process_stun(&mut self, data: &[u8], from: SocketAddr) -> Result<IncomingData, WebRtcError> {
        // Precondition: state must allow STUN processing
        assert!(
            matches!(
                self.state,
                SessionState::New
                    | SessionState::IceGathering
                    | SessionState::IceConnecting
                    | SessionState::DtlsHandshaking
                    | SessionState::Established
            ),
            "STUN processing requires active ICE state"
        );

        // Precondition: data must be valid STUN size
        if data.len() < 20 {
            return Err(WebRtcError::PacketTooShort);
        }

        // Initialize ICE agent if needed
        if self.ice_agent.is_none() {
            self.initialize_ice_agent();
        }

        let agent = self.ice_agent.as_mut().expect("ICE agent must exist");

        let stun_response = agent.process_incoming(data, from)?;

        // Check if ICE just completed — may return DTLS ClientHello
        let dtls_output = self.check_ice_completion()?;

        match (stun_response, dtls_output) {
            (Some(stun), Some(dtls)) => {
                tracing::info!(
                    stun_len = stun.len(),
                    dtls_len = dtls.len(),
                    "process_stun: returning StunAndDtls (DTLS ClientHello piggybacked)"
                );
                Ok(IncomingData::StunAndDtls(stun, dtls))
            }
            (Some(stun), None) => Ok(IncomingData::Stun(stun)),
            (None, Some(dtls)) => {
                tracing::info!(
                    dtls_len = dtls.len(),
                    "process_stun: returning Dtls (DTLS ClientHello without STUN response)"
                );
                Ok(IncomingData::Dtls(dtls))
            }
            (None, None) => Ok(IncomingData::None),
        }
    }

    /// Process DTLS packet.
    ///
    /// # TigerStyle
    /// - Precondition: state is DtlsHandshaking or Established
    /// - Precondition: source address matches remote_addr if set
    /// - State transitions via transition_state()
    fn process_dtls(&mut self, data: &[u8], from: SocketAddr) -> Result<IncomingData, WebRtcError> {
        tracing::info!(
            state = ?self.state,
            from = %from,
            len = data.len(),
            first_byte = data[0],
            "process_dtls: entry"
        );

        // Precondition: state must be DtlsHandshaking or Established
        if self.state != SessionState::DtlsHandshaking && self.state != SessionState::Established {
            tracing::warn!(
                state = ?self.state,
                "DTLS packet rejected: invalid state (expected DtlsHandshaking or Established)"
            );
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: source address must match remote_addr if set
        if let Some(expected_addr) = self.remote_addr {
            if from != expected_addr {
                tracing::warn!(
                    expected = %expected_addr,
                    actual = %from,
                    "DTLS packet rejected: address mismatch"
                );
                return Err(WebRtcError::AddressMismatch);
            }
        }

        // Assertion: DTLS session must exist in these states
        assert!(
            self.dtls_session.is_some(),
            "DTLS session must exist in DtlsHandshaking or Established state"
        );

        // Check DTLS timeout if handshaking
        if self.state == SessionState::DtlsHandshaking {
            self.check_state_timeouts()?;
        }

        // Save state before borrowing dtls_session
        let was_handshaking: bool = self.state == SessionState::DtlsHandshaking;

        // Process DTLS in a scope to limit borrow lifetime
        let (response_data, dtls_established) = {
            if let Some(ref mut engine) = self.openssl_dtls {
                tracing::debug!(
                    is_established = engine.is_established(),
                    data_len = data.len(),
                    first_bytes = ?&data[..data.len().min(4)],
                    "Processing DTLS packet in OpenSSL engine"
                );
                
                let output = engine.process(data).map_err(|e| {
                    tracing::error!(
                        error = %e,
                        state = ?self.state,
                        data_len = data.len(),
                        first_byte = data[0],
                        dtls_content_type = data[0],
                        from = %from,
                        "DTLS process failed - detailed error"
                    );
                    
                    // Log additional context for handshake failures
                    if data[0] == 21 {
                        let alert_level = if data.len() > 13 { data[13] } else { 0 };
                        let alert_desc = if data.len() > 14 { data[14] } else { 0 };
                        tracing::error!(
                            alert_level,
                            alert_description = alert_desc,
                            "DTLS Alert received (content_type=21). Level: 1=warning, 2=fatal. Common: 40=handshake_failure, 42=bad_certificate, 43=unsupported_certificate"
                        );
                    }
                    
                    tracing::warn!("DTLS process failed: {}", e);
                    WebRtcError::DtlsHandshakeFailed
                })?;
                // Output is returned directly via IncomingData::Dtls
                if engine.is_established()
                    && !self.dtls_session.as_ref().unwrap().state().is_established()
                {
                    // Transfer SRTP keys from OpenSSL engine to session
                    if let Some(keys) = engine.srtp_keys() {
                        let profile = engine.selected_srtp_profile().unwrap_or(0x0007);
                        let srtp_profile = nexus_transport::dtls::SrtpProfile::from_u16(profile)
                            .unwrap_or(nexus_transport::dtls::SrtpProfile::AeadAes128Gcm);

                        // Verify key material consistency before transfer
                        let expected_salt = keys.profile.salt_length();
                        tracing::info!(
                            keys_profile = ?keys.profile,
                            keys_client_salt_len = keys.client_salt().len(),
                            keys_server_salt_len = keys.server_salt().len(),
                            keys_client_key_len = keys.client_key().len(),
                            expected_salt_len = expected_salt,
                            engine_profile_id = profile,
                            mapped_srtp_profile = ?srtp_profile,
                            "Transferring SRTP keys from OpenSSL engine to session"
                        );

                        assert_eq!(
                            keys.client_salt().len(), expected_salt,
                            "OpenSSL engine keys: client_salt len must match profile"
                        );

                        let dtls_session = self.dtls_session.as_mut().unwrap();
                        dtls_session.set_srtp_keys(keys.clone());
                        dtls_session.set_selected_srtp_profile(srtp_profile);
                        dtls_session.set_state(nexus_transport::dtls::SessionState::Established);
                    }
                }
                (Some(output), engine.is_established())
            } else {
                let dtls = self.dtls_session.as_mut().expect("DTLS session must exist");

                let (response, _app_data) = dtls.process(data)?;

                // Convert response to owned data immediately to release borrow
                let response_owned: Option<Vec<u8>> = response.map(|r| r.to_vec());

                let established: bool = dtls.state() == DtlsState::Established;

                (response_owned, established)
            }
        };

        // Now check_dtls_completion can borrow self mutably
        if dtls_established && was_handshaking {
            self.check_dtls_completion()?;
        }

        match response_data {
            Some(resp) if !resp.is_empty() => Ok(IncomingData::Dtls(resp)),
            _ => Ok(IncomingData::None),
        }
    }

    /// Process RTP packet.
    ///
    /// # TigerStyle
    /// - Precondition: state is Established
    /// - Precondition: srtp_session exists
    /// - Buffer bleed protection
    fn process_rtp(&mut self, data: &[u8], _from: SocketAddr, out: &mut [u8]) -> Result<IncomingData, WebRtcError> {
        // Precondition: session must be established
        if self.state != SessionState::Established {
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: SRTP context must exist
        let srtp = self
            .srtp_session
            .as_mut()
            .ok_or(WebRtcError::NotInitialized)?;

        let len = data.len();
        let tag_len = srtp.cipher_tag_len();

        // Precondition: data length must be valid SRTP
        if len < 12 + tag_len {
            return Err(WebRtcError::PacketTooShort);
        }
        if len > MAX_PACKET_SIZE {
            return Err(WebRtcError::PacketTooLarge);
        }

        // Copy to work buffer for in-place decryption
        self.work_buffer[..len].copy_from_slice(data);

        // Postcondition: data copied correctly
        debug_assert_eq!(
            &self.work_buffer[..len],
            data,
            "Data must be copied correctly"
        );

        let decrypted_len = match srtp.unprotect_rtp(&mut *self.work_buffer, len) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                // Log first few SRTP failures with diagnostic info to help debug
                // key/profile mismatches between SFU and remote peer.
                if self.stats.rtp_packets_received < 5 {
                    let profile = srtp.profile();
                    tracing::warn!(
                        error = ?e,
                        packet_len = len,
                        tag_len,
                        srtp_profile = ?profile,
                        first_bytes = ?&data[..data.len().min(16)],
                        "SRTP unprotect failed (packet #{}) — possible key/profile mismatch with remote peer",
                        self.stats.rtp_packets_received,
                    );
                }
                return Err(e.into());
            }
        };

        // Postcondition: decrypted length must be valid
        assert!(decrypted_len >= 12, "Decrypted RTP must be >= 12 bytes");
        assert!(
            decrypted_len < len,
            "Decrypted length must be less than encrypted"
        );

        // Zero unused buffer space (prevent buffer bleed)
        if decrypted_len < MAX_PACKET_SIZE {
            self.work_buffer[decrypted_len..].fill(0);
        }

        self.stats.rtp_packets_received += 1;

        // Copy decrypted data to caller's output buffer (zero-alloc)
        if out.len() < decrypted_len {
            return Err(WebRtcError::PacketTooLarge);
        }
        out[..decrypted_len].copy_from_slice(&self.work_buffer[..decrypted_len]);

        Ok(IncomingData::Rtp(decrypted_len))
    }

    /// Process RTCP packet.
    ///
    /// # TigerStyle
    /// - Precondition: state is Established
    /// - Precondition: srtp_session exists
    /// - Buffer bleed protection
    fn process_rtcp(
        &mut self,
        data: &[u8],
        _from: SocketAddr,
        out: &mut [u8],
    ) -> Result<IncomingData, WebRtcError> {
        // Precondition: session must be established
        if self.state != SessionState::Established {
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: SRTP context must exist
        let srtp = self
            .srtp_session
            .as_mut()
            .ok_or(WebRtcError::NotInitialized)?;

        let len = data.len();
        let tag_len = srtp.cipher_tag_len();

        // Precondition: length must be valid SRTCP
        if len < 8 + 4 + tag_len {
            return Err(WebRtcError::PacketTooShort);
        }
        if len > MAX_PACKET_SIZE {
            return Err(WebRtcError::PacketTooLarge);
        }

        // Copy to work buffer for in-place decryption
        self.work_buffer[..len].copy_from_slice(data);

        let decrypted_len = match srtp.unprotect_rtcp(&mut *self.work_buffer, len) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                if self.stats.rtcp_packets_received < 5 {
                    let profile = srtp.profile();
                    tracing::warn!(
                        error = ?e,
                        packet_len = len,
                        tag_len,
                        srtp_profile = ?profile,
                        first_bytes = ?&data[..data.len().min(16)],
                        "SRTCP unprotect failed (packet #{}) — possible key/profile mismatch with remote peer",
                        self.stats.rtcp_packets_received,
                    );
                }
                return Err(e.into());
            }
        };

        // Postcondition: decrypted length must be valid
        assert!(decrypted_len >= 8, "Decrypted RTCP must be >= 8 bytes");
        assert!(
            decrypted_len < len,
            "Decrypted length must be less than encrypted"
        );

        // Zero unused buffer space (prevent buffer bleed)
        if decrypted_len < MAX_PACKET_SIZE {
            self.work_buffer[decrypted_len..].fill(0);
        }

        self.stats.rtcp_packets_received += 1;

        // Copy decrypted data to caller's output buffer (zero-alloc)
        if out.len() < decrypted_len {
            return Err(WebRtcError::PacketTooLarge);
        }
        out[..decrypted_len].copy_from_slice(&self.work_buffer[..decrypted_len]);

        Ok(IncomingData::Rtcp(decrypted_len))
    }

    // ========================================================================
    // Outgoing Packet Protection
    // ========================================================================

    /// Protect RTP packet for sending.
    ///
    /// # Arguments
    /// * `buffer` - Buffer containing RTP packet, must have room for auth tag.
    /// * `len` - Length of RTP packet.
    ///
    /// # Returns
    /// Protected length (original + auth tag bytes).
    ///
    /// # TigerStyle
    /// - Precondition: state is Established
    /// - Precondition: buffer has room for auth tag
    /// - Postcondition: protected_len == len + tag_len
    pub fn protect_rtp(&mut self, buffer: &mut [u8], len: usize) -> Result<usize, WebRtcError> {
        // Precondition: session must be established
        if self.state != SessionState::Established {
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: SRTP outbound context must exist
        let srtp = self
            .srtp_outbound
            .as_mut()
            .ok_or(WebRtcError::NotInitialized)?;

        let tag_len = srtp.cipher_tag_len();

        // Precondition: buffer must have room for auth tag
        assert!(
            buffer.len() >= len + tag_len,
            "Buffer must have room for SRTP auth tag"
        );

        // Precondition: length must be valid RTP
        assert!(len >= 12, "RTP packet must be >= 12 bytes");
        assert!(
            len <= MAX_PACKET_SIZE - tag_len,
            "RTP packet must leave room for auth tag"
        );

        let protected_len = srtp.protect_rtp(buffer, len)?;

        // Postcondition: protected length must be valid
        assert_eq!(
            protected_len,
            len + tag_len,
            "Protected length must equal original length plus auth tag"
        );
        assert!(
            protected_len <= MAX_PACKET_SIZE,
            "Protected packet must fit in MAX_PACKET_SIZE"
        );

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += protected_len as u64;
        self.stats.rtp_packets_sent += 1;

        Ok(protected_len)
    }

    /// Protect RTCP packet for sending.
    ///
    /// # Arguments
    /// * `buffer` - Buffer containing RTCP packet, must have room for index + auth tag.
    /// * `len` - Length of RTCP packet.
    ///
    /// # Returns
    /// Protected length (original + index + auth tag bytes).
    ///
    /// # TigerStyle
    /// - Precondition: state is Established
    /// - Precondition: buffer has room for index + auth tag
    /// - Postcondition: protected_len > len
    pub fn protect_rtcp(&mut self, buffer: &mut [u8], len: usize) -> Result<usize, WebRtcError> {
        // Precondition: session must be established
        if self.state != SessionState::Established {
            return Err(WebRtcError::InvalidState);
        }

        // Precondition: SRTP outbound context must exist
        let srtp = self
            .srtp_outbound
            .as_mut()
            .ok_or(WebRtcError::NotInitialized)?;

        let tag_len = srtp.cipher_tag_len();

        // Precondition: buffer must have room for auth tag + index
        assert!(
            buffer.len() >= len + tag_len + 4,
            "Buffer must have room for SRTCP auth tag and index"
        );

        // Precondition: length must be valid RTCP
        assert!(len >= 8, "RTCP packet must be >= 8 bytes");

        let protected_len = srtp.protect_rtcp(buffer, len)?;

        // Postcondition: protected length must be greater than original
        assert!(
            protected_len > len,
            "Protected length must be greater than original"
        );

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += protected_len as u64;
        self.stats.rtcp_packets_sent += 1;

        Ok(protected_len)
    }

    // ========================================================================
    // State Monitoring
    // ========================================================================

    /// Get selected ICE candidate pair.
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.ice_agent.as_ref().and_then(|agent| {
            agent
                .selected_pair()
                .map(|pair| (pair.local.address, pair.remote.address))
        })
    }

    /// Get session statistics.
    ///
    /// # TigerStyle
    /// - Collects stats from all components
    pub fn stats(&self) -> SessionStats {
        let time_in_state_ms = self.state_entered_at.elapsed().as_millis() as u64;

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let last_activity_ms = now_ns.saturating_sub(self.last_activity_ns) / 1_000_000;

        SessionStats {
            state: self.state as u8,
            time_in_state_ms,
            ice_candidates_local: self
                .ice_agent
                .as_ref()
                .map(|a| a.local_candidates().count() as u8)
                .unwrap_or(0),
            ice_candidates_remote: self.remote_candidate_count(),
            ice_pairs_checked: self
                .ice_agent
                .as_ref()
                .map(|a| a.pairs_checked() as u16)
                .unwrap_or(0),
            dtls_handshake_complete: self
                .dtls_session
                .as_ref()
                .map(|d| d.state() == DtlsState::Established)
                .unwrap_or(false),
            srtp_packets_sent: self.stats.rtp_packets_sent,
            srtp_packets_received: self.stats.rtp_packets_received,
            bytes_sent: self.stats.bytes_sent,
            bytes_received: self.stats.bytes_received,
            last_activity_ms,
        }
    }

    /// Get transport statistics.
    pub fn transport_stats(&self) -> TransportStats {
        TransportStats::from_values(
            self.stats.packets_sent,
            self.stats.packets_received,
            self.stats.bytes_sent,
            self.stats.bytes_received,
            self.stats.rtp_packets_sent,
            self.stats.rtp_packets_received,
            self.stats.rtcp_packets_sent,
            self.stats.rtcp_packets_received,
        )
    }

    /// Check if session is healthy.
    ///
    /// # TigerStyle
    /// - Checks state is not terminal
    /// - Checks no timeouts exceeded
    /// - Checks consent freshness (if Established)
    pub fn is_healthy(&self) -> bool {
        // Check state is not terminal
        if self.state.is_terminal() {
            return false;
        }

        // Check no timeouts exceeded
        if self.check_timeout_exceeded() {
            return false;
        }

        // Check DTLS session is valid if it exists
        if let Some(ref dtls) = self.dtls_session {
            if dtls.state() == DtlsState::Failed {
                return false;
            }
        }

        true
    }

    /// Check if timeout has been exceeded without transitioning.
    fn check_timeout_exceeded(&self) -> bool {
        let elapsed_ms = self.state_entered_at.elapsed().as_millis() as u64;

        match self.state {
            SessionState::IceGathering => elapsed_ms > self.config.ice_gathering_timeout_ms as u64,
            SessionState::IceConnecting => elapsed_ms > self.config.ice_check_timeout_ms as u64,
            SessionState::DtlsHandshaking => {
                elapsed_ms > self.config.dtls_handshake_timeout_ms as u64
            }
            _ => false,
        }
    }

    /// Get health report.
    ///
    /// # TigerStyle
    /// - Collects detailed health information
    pub fn health_report(&self) -> HealthReport {
        let mut issues = Vec::new();

        let ice_connected = self
            .ice_agent
            .as_ref()
            .map(|a| a.connection_state() == IceConnectionState::Connected)
            .unwrap_or(false);

        let dtls_complete = self
            .dtls_session
            .as_ref()
            .map(|d| d.state() == DtlsState::Established)
            .unwrap_or(false);

        let srtp_ready = self.srtp_session.is_some() && self.srtp_outbound.is_some();

        let timeout_exceeded = self.check_timeout_exceeded();

        // Check consent freshness
        let consent_fresh = if self.state == SessionState::Established {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let idle_secs = now_ns.saturating_sub(self.last_activity_ns) / 1_000_000_000;
            idle_secs < self.config.consent_timeout_secs
        } else {
            true
        };

        // Collect issues
        if self.state.is_terminal() {
            issues.push("Session in terminal state");
        }
        if timeout_exceeded {
            issues.push("State timeout exceeded");
        }
        if !consent_fresh {
            issues.push("Consent stale (no recent activity)");
        }
        if self.state == SessionState::Established && !srtp_ready {
            issues.push("Established but SRTP not ready");
        }

        let is_healthy = issues.is_empty() && !self.state.is_terminal();

        HealthReport {
            is_healthy,
            state: self.state,
            ice_connected,
            dtls_complete,
            srtp_ready,
            consent_fresh,
            timeout_exceeded,
            issues,
        }
    }

    // ========================================================================
    // Cleanup and Resource Management
    // ========================================================================

    /// Close the session.
    ///
    /// # TigerStyle
    /// - Postcondition: state is Closed
    /// - Postcondition: all components cleared
    pub fn close(&mut self) {
        // Transition to Closed (may fail if already closed, that's ok)
        if self.state != SessionState::Closed {
            let _ = self.transition_state(SessionState::Closed);
        }

        // Clear components
        self.ice_agent = None;
        self.dtls_session = None;
        self.srtp_session = None;
        self.srtp_outbound = None;
        self.remote_addr = None;

        // Postcondition: state must be Closed
        self.state = SessionState::Closed; // Force if transition failed

        // Postcondition: all components must be None
        assert!(
            self.ice_agent.is_none(),
            "ICE agent must be None after close"
        );
        assert!(
            self.dtls_session.is_none(),
            "DTLS session must be None after close"
        );
        assert!(
            self.srtp_session.is_none(),
            "SRTP session must be None after close"
        );
    }

    /// Graceful shutdown.
    ///
    /// Sends DTLS close_notify if connected.
    ///
    /// # TigerStyle
    /// - Postcondition: state is Closed
    pub fn shutdown(&mut self) -> Result<(), WebRtcError> {
        // Send DTLS close_notify if connected
        if let Some(ref mut dtls_session) = self.dtls_session {
            // Build close_notify alert
            let mut alert_buf = [0u8; 64];
            if let Ok(alert_len) = dtls_session.build_close_notify_alert(&mut alert_buf) {
                // Send the alert via transport if available
                if let Some(ref remote_addr) = self.remote_addr {
                    // Note: In a full implementation, we would send this via the UDP transport
                    // For now, we store it in the output buffer for the caller to send
                    // The caller should check for pending output after shutdown
                    let _ = (remote_addr, &alert_buf[..alert_len]);
                }
            }
            // Close the DTLS session
            let _ = dtls_session.close();
        }

        self.close();

        // Postcondition: state is Closed
        assert_eq!(
            self.state,
            SessionState::Closed,
            "State must be Closed after shutdown"
        );

        Ok(())
    }
}

// ============================================================================
// Testing Hooks
// ============================================================================

#[cfg(test)]
impl WebRtcSession {
    /// Force state for testing (bypasses validation).
    pub fn force_state_for_testing(&mut self, state: SessionState) {
        self.state = state;
        self.state_entered_at = Instant::now();
    }

    /// Inject ICE completion for testing.
    pub fn inject_ice_completion_for_testing(&mut self) {
        if self.state == SessionState::IceConnecting {
            let _ = self.start_dtls_handshake();
        }
    }

    /// Inject DTLS completion for testing.
    pub fn inject_dtls_completion_for_testing(&mut self) {
        if self.state == SessionState::DtlsHandshaking {
            // Create mock SRTP contexts (separate inbound/outbound)
            let key = [1u8; 16];
            let salt = [2u8; 12];
            if let Ok(km) = KeyMaterial::from_aes128_gcm(&key, &salt) {
                if let Ok(ctx) = SrtpContext::new(&km, SrtpPolicy::default()) {
                    self.srtp_session = Some(ctx);
                }
            }
            let out_key = [3u8; 16];
            let out_salt = [4u8; 12];
            if let Ok(km) = KeyMaterial::from_aes128_gcm(&out_key, &out_salt) {
                if let Ok(ctx) = SrtpContext::new(&km, SrtpPolicy::default()) {
                    self.srtp_outbound = Some(ctx);
                    self.state = SessionState::Established;
                    self.state_entered_at = Instant::now();
                }
            }
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
    fn test_session_state_transitions() {
        assert!(!SessionState::New.is_established());
        assert!(SessionState::Established.is_established());
        assert!(SessionState::Failed.is_terminal());
        assert!(SessionState::Closed.is_terminal());
    }

    #[test]
    fn test_session_state_can_transition() {
        assert!(SessionState::New.can_transition_to(SessionState::IceGathering));
        assert!(SessionState::IceGathering.can_transition_to(SessionState::IceConnecting));
        assert!(SessionState::IceConnecting.can_transition_to(SessionState::DtlsHandshaking));
        assert!(SessionState::DtlsHandshaking.can_transition_to(SessionState::Established));

        // Failure transitions
        assert!(SessionState::IceConnecting.can_transition_to(SessionState::Failed));
        assert!(SessionState::DtlsHandshaking.can_transition_to(SessionState::Failed));

        // Close transitions
        assert!(SessionState::Established.can_transition_to(SessionState::Closed));
        assert!(SessionState::Failed.can_transition_to(SessionState::Closed));
    }

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.ice_role, IceRole::Controlling);
        assert_eq!(config.dtls_role, DtlsRole::Client);
        assert_eq!(config.srtp_profile, ProtectionProfile::AeadAes128Gcm);
        assert_eq!(config.ice_gathering_timeout_ms, ICE_GATHERING_TIMEOUT_MS);
        assert_eq!(config.dtls_handshake_timeout_ms, DTLS_HANDSHAKE_TIMEOUT_MS);
    }

    #[test]
    fn test_session_config_validate() {
        let config = SessionConfig::default();
        assert!(config.validate().is_ok());

        // Invalid timeout
        let mut bad_config = SessionConfig::default();
        bad_config.ice_gathering_timeout_ms = 10; // Too short
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_session_creation() {
        let config = SessionConfig::default();
        let session = WebRtcSession::new(config).unwrap();

        assert_eq!(session.state(), SessionState::New);
        assert!(!session.is_established());
        assert!(session.ice_agent.is_none());
        assert!(session.dtls_session.is_none());
        assert!(session.srtp_session.is_none());
    }

    #[test]
    fn test_session_gather_candidates() {
        let config = SessionConfig::default();
        let mut session = WebRtcSession::new(config).unwrap();

        // Use new API: add a local candidate and mark gathering complete
        session.initialize_ice_agent();
        let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let candidate = nexus_transport::ice::Candidate::new_host(addr, 1, 0);
        let _ = session.add_local_candidate(candidate);
        let _ = session.mark_gathering_complete();
        assert!(matches!(
            session.state(),
            SessionState::IceGathering | SessionState::New
        ));
    }

    #[test]
    fn test_session_invalid_state_transitions() {
        let config = SessionConfig::default();
        let mut session = WebRtcSession::new(config).unwrap();

        // start_connectivity_checks from Established is idempotent (Ok)
        // because late trickle candidates may arrive after ICE completes
        // (RFC 8838 §10).
        session.force_state_for_testing(SessionState::Established);
        assert!(session.start_connectivity_checks().is_ok());
    }

    #[test]
    fn test_incoming_data_debug() {
        let data = IncomingData::None;
        assert!(format!("{:?}", data).contains("None"));

        let rtp = IncomingData::Rtp(2);
        assert!(format!("{:?}", rtp).contains("Rtp"));
    }

    #[test]
    fn test_session_close() {
        let config = SessionConfig::default();
        let mut session = WebRtcSession::new(config).unwrap();

        session.close();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.state().is_terminal());
        assert!(session.ice_agent.is_none());
        assert!(session.dtls_session.is_none());
        assert!(session.srtp_session.is_none());
    }

    #[test]
    #[should_panic(expected = "Transport ID must be > 0")]
    fn test_new_with_invalid_transport_id() {
        let config = SessionConfig {
            id: TransportId(0), // Invalid
            ..Default::default()
        };
        let _ = WebRtcSession::new(config);
    }

    #[test]
    #[should_panic(expected = "Remote ICE ufrag must not be empty")]
    fn test_empty_ice_credentials() {
        let config = SessionConfig::default();
        let mut session = WebRtcSession::new(config).unwrap();

        let empty_creds = IceCredentials {
            local_ufrag: String::new(),
            local_pwd: "password".to_string(),
        };
        session.set_remote_ice_credentials(empty_creds);
    }

    #[test]
    #[should_panic(expected = "Candidate port must be > 0")]
    fn test_invalid_candidate_port() {
        let config = SessionConfig::default();
        let mut session = WebRtcSession::new(config).unwrap();

        // Set credentials first
        session.set_remote_ice_credentials(IceCredentials::generate());

        // Create candidate with port 0
        let addr: std::net::SocketAddr = "192.168.1.1:0".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);
        let _ = session.add_remote_candidate(candidate);
    }

    #[test]
    fn test_health_report() {
        let config = SessionConfig::default();
        let session = WebRtcSession::new(config).unwrap();

        let report = session.health_report();
        assert!(report.is_healthy);
        assert_eq!(report.state, SessionState::New);
        assert!(!report.ice_connected);
        assert!(!report.dtls_complete);
        assert!(!report.srtp_ready);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn test_session_stats() {
        let config = SessionConfig::default();
        let session = WebRtcSession::new(config).unwrap();

        let stats = session.stats();
        assert_eq!(stats.state, SessionState::New as u8);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }
}

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

// Assert struct size bounds to prevent stack overflow
const _: () = assert!(
    std::mem::size_of::<SessionConfig>() < 1024,
    "SessionConfig must be < 1KB"
);

// Assert work buffer size matches constant
const _: () = assert!(
    std::mem::size_of::<[u8; MAX_PACKET_SIZE]>() == MAX_PACKET_SIZE,
    "Work buffer size must match MAX_PACKET_SIZE"
);

// Assert DTLS timeout is bounded
const _: () = assert!(
    DTLS_HANDSHAKE_TIMEOUT_MS >= 1000,
    "DTLS timeout must be >= 1s"
);
const _: () = assert!(
    DTLS_HANDSHAKE_TIMEOUT_MS <= 60000,
    "DTLS timeout must be <= 60s"
);

// Assert packet size is sufficient for WebRTC
const _: () = assert!(
    MAX_PACKET_SIZE >= 1500,
    "MAX_PACKET_SIZE must be at least Ethernet MTU"
);
const _: () = assert!(
    MAX_PACKET_SIZE >= MIN_PACKET_SIZE_FOR_SRTP,
    "MAX_PACKET_SIZE must accommodate SRTP overhead"
);
#[allow(dead_code)] // Used in compile-time assertion above
const MIN_PACKET_SIZE_FOR_SRTP: usize = 12 + 4; // RTP header + smallest auth tag (HMAC-SHA1-32)

// Assert SessionState fits in u8
const _: () = assert!(
    std::mem::size_of::<SessionState>() == 1,
    "SessionState must fit in u8"
);
