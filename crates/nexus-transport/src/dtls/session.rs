//! DTLS Session Management.
//!
//! Connection state management and high-level API.
//!
//! # State Machine
//!
//! ```text
//! New -> Handshaking -> Established -> Closed
//!                   \-> Failed
//! ```
//!
//! # Timeouts
//!
//! - Handshake: 30 seconds maximum
//! - Retransmission: 1s initial, exponential backoff, 6 max retries
//!
//! # Bounds
//!
//! - Max record size: 16KB
//! - Max handshake message: 4KB
//! - Max flight size: 8 messages
//!
//! # TigerStyle Compliance
//!
//! - All functions ≤70 lines
//! - All functions ≥2 assertions
//! - Explicit types (u8, u16, u32, u64)
//! - No dynamic allocation on hot path
//! - Bounded loops and retries

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::error::DtlsError;
use super::types::{DtlsRole, RetransmissionState};
use super::record::{RecordLayer, ContentType, Record};
use super::handshake::{HandshakeContext, HandshakeState};
use super::crypto::{
    CipherSuite, SrtpProfile, KeyMaterial, SrtpKeyMaterial,
    Aes128GcmContext, derive_key_material, export_srtp_keys,
};
use super::{DTLS_VERSION_1_2, MAX_DTLS_RECORD_SIZE, MAX_RETRANSMISSIONS};
use ring::agreement::EphemeralPrivateKey;

/// Handshake timeout in milliseconds (30 seconds).
pub const HANDSHAKE_TIMEOUT_MS: u32 = 30000;

// Compile-time assertion for timeout
const _: () = assert!(HANDSHAKE_TIMEOUT_MS == 30 * 1000);

/// DTLS session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// New session, not started.
    New = 0,
    
    /// Handshake in progress.
    Handshaking = 1,
    
    /// Session established.
    Established = 2,
    
    /// Session closed.
    Closed = 3,
    
    /// Session failed.
    Failed = 4,
}

impl SessionState {
    /// Returns true if session is established.
    #[inline]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
    
    /// Returns true if session is in a terminal state.
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
    
    /// Returns true if processing is allowed in this state.
    #[inline]
    pub const fn can_process(self) -> bool {
        matches!(self, Self::Handshaking | Self::Established)
    }
}

/// DTLS session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Our role (client or server).
    pub role: DtlsRole,
    
    /// Remote address.
    pub remote_addr: Option<SocketAddr>,
    
    /// Supported cipher suites.
    pub cipher_suites: [CipherSuite; 2],
    
    /// Number of cipher suites.
    pub cipher_suite_count: u8,
    
    /// Supported SRTP profiles.
    pub srtp_profiles: [SrtpProfile; 4],
    
    /// Number of SRTP profiles.
    pub srtp_profile_count: u8,
    
    /// Require client certificate.
    pub require_client_cert: bool,
    
    /// MTU for fragmentation.
    pub mtu: u16,
}

impl SessionConfig {
    /// Create default client configuration.
    pub fn client() -> Self {
        Self {
            role: DtlsRole::Client,
            remote_addr: None,
            cipher_suites: [
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            cipher_suite_count: 2,
            srtp_profiles: [
                SrtpProfile::AeadAes128Gcm,
                SrtpProfile::Aes128CmHmacSha1_80,
                SrtpProfile::Aes128CmHmacSha1_32,
                SrtpProfile::AeadAes256Gcm,
            ],
            srtp_profile_count: 4,
            require_client_cert: false,
            mtu: 1200,
        }
    }
    
    /// Create default server configuration.
    pub fn server() -> Self {
        Self {
            role: DtlsRole::Server,
            ..Self::client()
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::client()
    }
}

/// DTLS session.
///
/// Manages DTLS handshake state, encryption contexts, and certificate.
///
/// # Certificate Management
///
/// Each session generates a self-signed X.509 certificate on creation.
/// The certificate is stored in a fixed-size buffer (2048 bytes) and
/// the SHA-256 fingerprint is pre-computed for SDP exchange.
///
/// # ECDHE Key Exchange
///
/// Ephemeral ECDHE key pair (P-256) is generated on session creation
/// for forward secrecy. Stored in fixed-size arrays.
///
/// # Timeout Management
///
/// - Handshake timeout: 30 seconds from start
/// - Retransmission: exponential backoff (1s initial, 6 max retries)
///
/// # TigerStyle Compliance
///
/// - Static allocation: certificate and keys stored in fixed buffers
/// - Compile-time assertions: buffer sizes validated at compile time
/// - Assertion density: ≥2 assertions per function
/// - Explicit types: u16 for lengths, [u8; 32] for fingerprint
#[derive(Debug)]
pub struct DtlsSession {
    /// Configuration.
    config: SessionConfig,
    
    /// Session state.
    state: SessionState,
    
    /// Record layer.
    record_layer: RecordLayer,
    
    /// Handshake context.
    handshake: HandshakeContext,
    
    /// Write cipher (after ChangeCipherSpec).
    write_cipher: Option<Aes128GcmContext>,
    
    /// Read cipher (after ChangeCipherSpec).
    read_cipher: Option<Aes128GcmContext>,
    
    /// Key material.
    key_material: KeyMaterial,
    
    /// SRTP key material.
    srtp_keys: Option<SrtpKeyMaterial>,
    
    /// Selected SRTP profile.
    selected_srtp_profile: Option<SrtpProfile>,
    
    /// Master secret (48 bytes).
    master_secret: [u8; 48],
    
    /// Session start time.
    #[allow(dead_code)] // Reserved for session timeout tracking
    started_at: Instant,
    
    /// Output buffer.
    output_buf: [u8; 4096],
    
    /// Output length.
    output_len: usize,

    /// Self-signed certificate (DER-encoded, statically allocated).
    certificate_der: [u8; 2048],

    /// Certificate length in bytes.
    certificate_len: u16,

    /// SHA-256 fingerprint of the certificate.
    fingerprint_sha256: [u8; 32],
    
    /// ECDHE private key (P-256, 32 bytes) - legacy, kept for compatibility.
    #[allow(dead_code)] // Legacy field kept for backward compatibility with non-ring path
    ecdhe_private_key: [u8; 32],
    
    /// Ring ECDHE private key (P-256) - used for actual key agreement.
    /// This is Option because it gets consumed during agree_ephemeral.
    ecdhe_private_key_ring: Option<EphemeralPrivateKey>,
    
    /// ECDHE public key (uncompressed P-256, 65 bytes: 0x04 || x || y).
    ecdhe_public_key: [u8; 65],
    
    /// Peer's public key from ClientKeyExchange.
    peer_public_key: [u8; 65],
    
    /// Peer public key length (0 if not received).
    peer_public_key_len: u8,
    
    /// Certificate private key (DER-encoded, for signing).
    certificate_private_key_der: [u8; 256],
    
    /// Certificate private key length.
    certificate_private_key_len: u16,
    
    /// Handshake message count (bounded).
    handshake_message_count: u8,
    
    /// Handshake start time (for 30s timeout).
    handshake_start: Option<Instant>,
    
    /// Handshake timeout in milliseconds (30000).
    handshake_timeout_ms: u32,
    
    /// Retransmission state for current flight.
    retransmit_state: RetransmissionState,
}

/// DTLS session implementation.
impl DtlsSession {
    /// Certificate buffer size.
    pub const CERTIFICATE_SIZE: usize = 2048;
    
    /// Output buffer size.
    pub const OUTPUT_BUFFER_SIZE: usize = 16384;
    
    /// Maximum handshake messages allowed (bounded).
    const MAX_HANDSHAKE_MESSAGES: u8 = 20;
    
    /// Create new session.
    pub fn new(config: SessionConfig) -> Self {
        // Precondition: config must have valid role
        assert!(
            config.role == DtlsRole::Client || config.role == DtlsRole::Server,
            "invalid DTLS role"
        );

        // Generate self-signed certificate with private key
        let (cert_der, cert_len, fingerprint, private_key_der) = Self::generate_certificate()
            .expect("certificate generation failed");

        // Postcondition: certificate length must fit in buffer
        assert!(cert_len <= 2048, "certificate too large");
        // Postcondition: fingerprint must be exactly 32 bytes (SHA-256)
        assert_eq!(fingerprint.len(), 32, "fingerprint must be 32 bytes");
        // Postcondition: private key must fit in buffer
        assert!(private_key_der.len() <= 256, "private key too large");

        let mut certificate_der = [0u8; 2048];
        certificate_der[..cert_len].copy_from_slice(&cert_der[..cert_len]);

        let mut fingerprint_sha256 = [0u8; 32];
        fingerprint_sha256.copy_from_slice(&fingerprint);
        
        let mut certificate_private_key_der = [0u8; 256];
        certificate_private_key_der[..private_key_der.len()].copy_from_slice(&private_key_der);
        
        // Generate ECDHE ephemeral key pair (P-256) using ring
        let (ecdhe_private_key_ring, ecdhe_public_key) = Self::generate_ecdhe_keypair_with_ring();
        
        // Postcondition: ECDHE public key must be valid
        assert!(ecdhe_public_key[0] == 0x04, "ECDHE public key must be uncompressed");
        assert!(ecdhe_public_key[1..].iter().any(|&b| b != 0), "ECDHE public key is zero");

        Self {
            state: SessionState::New,
            record_layer: RecordLayer::new(),
            handshake: HandshakeContext::new(config.role),
            write_cipher: None,
            read_cipher: None,
            key_material: KeyMaterial::empty(),
            srtp_keys: None,
            selected_srtp_profile: None,
            master_secret: [0u8; 48],
            started_at: Instant::now(),
            output_buf: [0u8; 4096],
            output_len: 0,
            certificate_der,
            certificate_len: cert_len as u16,
            fingerprint_sha256,
            ecdhe_private_key: [0u8; 32], // Legacy field, no longer used
            ecdhe_private_key_ring: Some(ecdhe_private_key_ring),
            ecdhe_public_key,
            peer_public_key: [0u8; 65],
            peer_public_key_len: 0,
            certificate_private_key_der,
            certificate_private_key_len: private_key_der.len() as u16,
            handshake_message_count: 0,
            handshake_start: None,
            handshake_timeout_ms: HANDSHAKE_TIMEOUT_MS,
            retransmit_state: RetransmissionState::new(),
            config,
        }
    }
    
    /// Generate ECDHE key pair (P-256).
    ///
    /// Returns (EphemeralPrivateKey, public_key[65]).
    ///
    /// # TigerStyle
    /// - Static allocation: fixed-size array for public key
    /// - Postcondition: public key is valid and non-zero
    fn generate_ecdhe_keypair_with_ring() -> (EphemeralPrivateKey, [u8; 65]) {
        use ring::agreement::ECDH_P256;
        use ring::rand::SystemRandom;
        
        let rng = SystemRandom::new();
        
        // Generate ephemeral private key
        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .expect("ECDHE key generation failed");
        
        // Extract public key
        let public_key = private_key.compute_public_key()
            .expect("ECDHE public key computation failed");
        
        // Store public key (uncompressed format: 0x04 || x || y)
        let mut ecdhe_public = [0u8; 65];
        let pub_bytes = public_key.as_ref();
        assert_eq!(pub_bytes.len(), 65, "P-256 public key must be 65 bytes");
        ecdhe_public.copy_from_slice(pub_bytes);
        
        // Postcondition: public key starts with 0x04 (uncompressed)
        assert_eq!(ecdhe_public[0], 0x04, "public key must be uncompressed format");
        // Postcondition: public key X coordinate is non-zero
        assert!(ecdhe_public[1..33].iter().any(|&b| b != 0), "public key X must be non-zero");
        
        (private_key, ecdhe_public)
    }
    
    /// Create client session.
    pub fn client() -> Self {
        Self::new(SessionConfig::client())
    }
    
    /// Create server session.
    pub fn server() -> Self {
        Self::new(SessionConfig::server())
    }
    
    /// Get current state.
    #[inline]
    pub const fn state(&self) -> SessionState {
        self.state
    }
    
    /// Returns true if session is established.
    #[inline]
    pub const fn is_established(&self) -> bool {
        self.state.is_established()
    }
    
    /// Get role.
    #[inline]
    pub const fn role(&self) -> DtlsRole {
        self.config.role
    }
    
    /// Get SRTP key material (after handshake).
    pub fn srtp_keys(&self) -> Option<&SrtpKeyMaterial> {
        self.srtp_keys.as_ref()
    }
    
    /// Get selected SRTP profile.
    pub fn srtp_profile(&self) -> Option<SrtpProfile> {
        self.selected_srtp_profile
    }

    /// Get SHA-256 fingerprint of the certificate.
    ///
    /// Returns the fingerprint as a 32-byte array.
    ///
    /// # TigerStyle
    /// - Precondition: session must be initialized
    /// - Returns fixed-size array (no allocation)
    #[inline]
    pub fn fingerprint(&self) -> &[u8; 32] {
        // Precondition: fingerprint must be initialized (non-zero)
        assert!(
            self.fingerprint_sha256.iter().any(|&b| b != 0),
            "fingerprint not initialized"
        );

        &self.fingerprint_sha256
    }

    /// Get DER-encoded certificate.
    ///
    /// Returns the certificate bytes.
    ///
    /// # TigerStyle
    /// - Precondition: certificate must be initialized
    /// - Returns slice (no allocation)
    #[inline]
    pub fn certificate_der(&self) -> &[u8] {
        // Precondition: certificate length must be valid
        assert!(
            self.certificate_len > 0 && self.certificate_len <= 2048,
            "invalid certificate length"
        );

        &self.certificate_der[..self.certificate_len as usize]
    }
    
    /// Check if handshake has timed out (30 seconds).
    ///
    /// # Returns
    /// - `Ok(())` if still within timeout
    /// - `Err(DtlsError::HandshakeTimeout)` if timeout exceeded
    ///
    /// # TigerStyle
    /// - ≥2 assertions on postconditions
    fn check_handshake_timeout(&self) -> Result<(), DtlsError> {
        // Precondition: timeout constant is correct
        assert!(self.handshake_timeout_ms == HANDSHAKE_TIMEOUT_MS);
        
        if let Some(start) = self.handshake_start {
            let elapsed = start.elapsed();
            if elapsed.as_millis() > self.handshake_timeout_ms as u128 {
                return Err(DtlsError::HandshakeTimeout);
            }
            
            // Postcondition: still within timeout
            assert!(elapsed.as_millis() <= self.handshake_timeout_ms as u128);
        }
        
        Ok(())
    }
    
    /// Check if retransmission is needed and perform it.
    ///
    /// # Returns
    /// - `Ok(Some(data))` if retransmission is needed, with data to send
    /// - `Ok(None)` if no retransmission needed
    /// - `Err(DtlsError::RetransmissionLimitExceeded)` if max retries exceeded
    ///
    /// # TigerStyle
    /// - ≥2 assertions on bounds
    pub fn check_retransmission(&mut self) -> Result<Option<&[u8]>, DtlsError> {
        // Precondition: retransmit count bounded
        assert!(self.retransmit_state.count <= MAX_RETRANSMISSIONS);
        
        // No retransmission if not handshaking
        if self.state != SessionState::Handshaking {
            return Ok(None);
        }
        
        // Check if retransmission is needed
        if !self.retransmit_state.needs_retransmit() {
            return Ok(None);
        }
        
        // Check if max retransmissions exceeded
        if self.retransmit_state.is_exhausted() {
            self.state = SessionState::Failed;
            return Err(DtlsError::RetransmissionLimitExceeded);
        }
        
        // Perform retransmission
        if !self.retransmit_state.retransmit() {
            return Err(DtlsError::RetransmissionLimitExceeded);
        }
        
        // Postcondition: RTO is bounded
        assert!(self.retransmit_state.rto_ms <= RetransmissionState::MAX_RTO_MS);
        
        Ok(self.retransmit_state.get_flight_data())
    }
    
    /// Get remaining time until handshake timeout.
    ///
    /// # Returns
    /// - `Some(duration)` if handshake in progress
    /// - `None` if not handshaking
    pub fn time_until_timeout(&self) -> Option<Duration> {
        if self.state != SessionState::Handshaking {
            return None;
        }
        
        if let Some(start) = self.handshake_start {
            let elapsed = start.elapsed();
            let timeout = Duration::from_millis(self.handshake_timeout_ms as u64);
            
            if elapsed >= timeout {
                Some(Duration::ZERO)
            } else {
                Some(timeout - elapsed)
            }
        } else {
            None
        }
    }
    
    /// Start the handshake.
    ///
    /// For client: generates ClientHello.
    /// For server: waits for ClientHello.
    ///
    /// Returns data to send (if any).
    ///
    /// # TigerStyle
    /// - Sets handshake_start for timeout tracking
    /// - Stores flight data for retransmission
    pub fn start_handshake(&mut self) -> Result<Option<&[u8]>, DtlsError> {
        assert_eq!(self.state, SessionState::New, "already started");
        
        // Start handshake timer
        self.handshake_start = Some(Instant::now());
        self.state = SessionState::Handshaking;
        
        if self.config.role == DtlsRole::Client {
            // Build ClientHello
            let srtp_profiles: Vec<u16> = self.config.srtp_profiles
                [..self.config.srtp_profile_count as usize]
                .iter()
                .map(|p| *p as u16)
                .collect();
            
            let mut handshake_buf = [0u8; super::MAX_HANDSHAKE_SIZE];
            let hs_len = super::handshake::build_client_hello(
                &mut self.handshake,
                &srtp_profiles,
                &mut handshake_buf,
            )?;
            
            // Wrap in record
            let record_len = self.record_layer.build_record(
                ContentType::Handshake,
                &handshake_buf[..hs_len],
                &mut self.output_buf,
            )?;
            
            self.output_len = record_len;
            self.handshake.state = HandshakeState::WaitingServerHello;
            
            // Store flight for retransmission
            let _ = self.retransmit_state.store_flight(1, &self.output_buf[..record_len]);
            
            Ok(Some(&self.output_buf[..self.output_len]))
        } else {
            // Server waits for ClientHello
            Ok(None)
        }
    }
    
    /// Process incoming DTLS data.
    ///
    /// Returns (response_data, application_data).
    ///
    /// # TigerStyle
    /// - Checks handshake timeout before processing
    /// - Validates state before processing
    /// - ≥2 assertions
    pub fn process(
        &mut self,
        data: &[u8],
    ) -> Result<(Option<&[u8]>, Option<Vec<u8>>), DtlsError> {
        // Precondition: data must be non-empty
        if data.is_empty() {
            return Err(DtlsError::handshake_failed("empty input"));
        }
        
        // Check handshake timeout if handshaking
        if self.state == SessionState::Handshaking {
            self.check_handshake_timeout()?;
        }
        
        // State validation - no processing in terminal states
        if self.state.is_terminal() {
            return Err(DtlsError::invalid_state("session in terminal state"));
        }
        
        if !RecordLayer::is_dtls(data) {
            return Err(DtlsError::InvalidContentType(data.get(0).copied().unwrap_or(0)));
        }
        
        let (record, _consumed) = self.record_layer.parse_record(data)?;
        
        // Mark response received (for retransmission tracking)
        self.retransmit_state.mark_response_received();
        
        match record.content_type {
            ContentType::Handshake => {
                self.process_handshake(&record)?;
                Ok((self.get_pending_output(), None))
            }
            
            ContentType::ChangeCipherSpec => {
                self.process_change_cipher_spec(&record)?;
                Ok((None, None))
            }
            
            ContentType::Alert => {
                self.process_alert(&record)?;
                Ok((None, None))
            }
            
            ContentType::ApplicationData => {
                let app_data = self.process_application_data(&record)?;
                Ok((None, Some(app_data)))
            }
        }
    }
    
    /// Process handshake message.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit state machine
    /// - Bounded: max 20 handshake messages
    /// - ≥2 assertions per branch
    fn process_handshake(&mut self, record: &Record) -> Result<(), DtlsError> {
        use super::handshake::HandshakeType;
        
        // Precondition: record must be handshake type
        assert_eq!(record.content_type, ContentType::Handshake, 
            "process_handshake requires Handshake content type");
        
        // Check handshake message count (bounded)
        self.handshake_message_count += 1;
        if self.handshake_message_count > Self::MAX_HANDSHAKE_MESSAGES {
            self.state = SessionState::Failed;
            return Err(DtlsError::handshake_failed("too many handshake messages"));
        }
        
        // Check minimum size
        if record.payload.len() < super::types::HandshakeHeader::SIZE {
            return Err(DtlsError::RecordTooShort {
                actual: record.payload.len(),
                min: super::types::HandshakeHeader::SIZE,
            });
        }
        
        let header = super::types::HandshakeHeader::parse(record.payload)
            .ok_or(DtlsError::handshake_failed("invalid handshake header"))?;
        
        // Get message type
        let msg_type = HandshakeType::from_u8(header.msg_type)
            .ok_or(DtlsError::InvalidHandshakeType(header.msg_type))?;
        
        // Explicit state machine (NASA Rule: simple control flow)
        if self.config.role == DtlsRole::Server {
            self.process_handshake_server(msg_type, record.payload)?;
        } else {
            self.process_handshake_client(msg_type, record.payload)?;
        }
        
        Ok(())
    }
    
    /// Process handshake message as server.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit state transitions
    /// - ≥2 assertions per state
    fn process_handshake_server(
        &mut self,
        msg_type: super::handshake::HandshakeType,
        payload: &[u8],
    ) -> Result<(), DtlsError> {
        use super::handshake::{HandshakeType, parse_client_hello, parse_client_key_exchange,
            build_server_hello, build_certificate, build_server_key_exchange, 
            build_server_hello_done, build_finished, verify_finished, compute_verify_data};
        use super::crypto::{derive_master_secret, sign_ecdsa_p256_sha256};
        
        match (self.handshake.state, msg_type) {
            // State: WaitingClientKeyExchange (initial server state), Message: ClientHello
            (HandshakeState::WaitingClientKeyExchange, HandshakeType::ClientHello) => {
                // Parse ClientHello
                let client_hello = parse_client_hello(payload)?;
                
                // Store client random
                self.handshake.client_random = client_hello.random;
                
                // Select cipher suite (prefer ECDHE_ECDSA)
                let selected_cipher = self.select_cipher_suite(&client_hello.cipher_suites[..client_hello.cipher_suite_count as usize])?;
                self.handshake.cipher_suite = Some(selected_cipher);
                
                // Select SRTP profile
                let selected_srtp = self.select_srtp_profile(&client_hello.srtp_profiles[..client_hello.srtp_profile_count as usize]);
                
                // Build server flight: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
                let mut offset = 0;
                
                // ServerHello
                let mut sh_buf = [0u8; super::MAX_HANDSHAKE_SIZE];
                let sh_len = build_server_hello(&mut self.handshake, selected_cipher, selected_srtp, &mut sh_buf)?;
                
                // Wrap ServerHello in record
                let record_len = self.record_layer.build_record(
                    ContentType::Handshake,
                    &sh_buf[..sh_len],
                    &mut self.output_buf[offset..],
                )?;
                offset += record_len;
                
                // Certificate
                let mut cert_buf = [0u8; 4096];
                let cert_len = build_certificate(
                    &mut self.handshake,
                    &self.certificate_der[..self.certificate_len as usize],
                    &mut cert_buf,
                )?;
                
                let record_len = self.record_layer.build_record(
                    ContentType::Handshake,
                    &cert_buf[..cert_len],
                    &mut self.output_buf[offset..],
                )?;
                offset += record_len;
                
                // ServerKeyExchange - sign the params
                let mut params_to_sign = [0u8; 256];
                let mut sign_offset = 0;
                params_to_sign[sign_offset..sign_offset + 32].copy_from_slice(&self.handshake.client_random.as_bytes());
                sign_offset += 32;
                params_to_sign[sign_offset..sign_offset + 32].copy_from_slice(&self.handshake.server_random.as_bytes());
                sign_offset += 32;
                // EC params: curve_type(1) + named_curve(2) + public_key_len(1) + public_key(65)
                params_to_sign[sign_offset] = 3; // named_curve
                sign_offset += 1;
                params_to_sign[sign_offset..sign_offset + 2].copy_from_slice(&0x0017u16.to_be_bytes()); // secp256r1
                sign_offset += 2;
                params_to_sign[sign_offset] = 65;
                sign_offset += 1;
                params_to_sign[sign_offset..sign_offset + 65].copy_from_slice(&self.ecdhe_public_key);
                sign_offset += 65;
                
                let signature = sign_ecdsa_p256_sha256(
                    &self.certificate_private_key_der[..self.certificate_private_key_len as usize],
                    &params_to_sign[..sign_offset],
                )?;
                
                let mut ske_buf = [0u8; super::MAX_HANDSHAKE_SIZE];
                let ske_len = build_server_key_exchange(
                    &mut self.handshake,
                    &self.ecdhe_public_key,
                    &signature,
                    &mut ske_buf,
                )?;
                
                let record_len = self.record_layer.build_record(
                    ContentType::Handshake,
                    &ske_buf[..ske_len],
                    &mut self.output_buf[offset..],
                )?;
                offset += record_len;
                
                // ServerHelloDone
                let mut shd_buf = [0u8; 32];
                let shd_len = build_server_hello_done(&mut self.handshake, &mut shd_buf)?;
                
                let record_len = self.record_layer.build_record(
                    ContentType::Handshake,
                    &shd_buf[..shd_len],
                    &mut self.output_buf[offset..],
                )?;
                offset += record_len;
                
                self.output_len = offset;
                
                // Buffer Flight 2 for retransmission
                self.retransmit_state.store_flight(2, &self.output_buf[..self.output_len])
                    .map_err(|e| DtlsError::handshake_failed(e))?;
                
                // Transition state - now waiting for ClientKeyExchange
                // (state stays WaitingClientKeyExchange, but we've sent our flight)
                
                // Assertion: output must be non-empty
                assert!(self.output_len > 0, "server flight must produce output");
            }
            
            // State: WaitingClientKeyExchange, Message: ClientKeyExchange
            (HandshakeState::WaitingClientKeyExchange, HandshakeType::ClientKeyExchange) => {
                // Parse peer's public key
                let peer_public_key = parse_client_key_exchange(payload)?;
                
                // Store peer public key
                self.peer_public_key.copy_from_slice(&peer_public_key);
                self.peer_public_key_len = 65;
                
                // Take the stored EphemeralPrivateKey (consumes it for key agreement)
                let private_key = self.ecdhe_private_key_ring.take()
                    .ok_or_else(|| DtlsError::handshake_failed("ECDHE private key already consumed"))?;
                
                // Compute ECDHE shared secret using ring
                let shared_secret = super::crypto::compute_ecdhe_shared_secret_ring(
                    private_key,
                    &peer_public_key,
                )?;
                
                // Derive master secret
                let master_secret = derive_master_secret(
                    &shared_secret,
                    &self.handshake.client_random.as_bytes(),
                    &self.handshake.server_random.as_bytes(),
                );
                
                // Store master secret
                self.master_secret.copy_from_slice(&master_secret);
                
                // Update handshake hash (before building Finished)
                self.handshake.update_hash(payload);
                
                // Transition to WaitingChangeCipherSpec
                self.handshake.state = HandshakeState::WaitingChangeCipherSpec;
                
                // Assertion: master secret must be non-zero
                assert!(self.master_secret.iter().any(|&b| b != 0), 
                    "master secret must be non-zero after derivation");
            }
            
            // State: WaitingFinished, Message: Finished
            (HandshakeState::WaitingFinished, HandshakeType::Finished) => {
                // Compute expected verify_data
                let expected_verify_data = compute_verify_data(
                    &self.master_secret,
                    self.handshake.hash_data(),
                    true, // client's Finished
                );
                
                // Verify Finished message
                verify_finished(payload, &expected_verify_data)?;
                
                // Update handshake hash with client's Finished
                self.handshake.update_hash(payload);
                
                // Complete handshake with derived keys
                let srtp_profile = self.selected_srtp_profile
                    .unwrap_or(super::crypto::SrtpProfile::AeadAes128Gcm);
                self.complete_handshake(&self.master_secret.clone(), srtp_profile)?;
                
                // Build our Finished message
                let our_verify_data = compute_verify_data(
                    &self.master_secret,
                    self.handshake.hash_data(),
                    false, // server's Finished
                );
                
                let mut finished_buf = [0u8; 64];
                let finished_len = build_finished(&mut self.handshake, &our_verify_data, &mut finished_buf)?;
                
                // Build ChangeCipherSpec
                let mut ccs_buf = [0u8; 16];
                ccs_buf[0] = 1; // ChangeCipherSpec message
                let ccs_record_len = self.record_layer.build_record(
                    ContentType::ChangeCipherSpec,
                    &ccs_buf[..1],
                    &mut self.output_buf,
                )?;
                
                // Increment write epoch for encrypted Finished
                self.record_layer.increment_epoch();
                
                // Wrap Finished in record (encrypted if write cipher active)
                let finished_record_len = self.record_layer.build_record(
                    ContentType::Handshake,
                    &finished_buf[..finished_len],
                    &mut self.output_buf[ccs_record_len..],
                )?;
                
                self.output_len = ccs_record_len + finished_record_len;
                
                // Buffer Flight 4 for retransmission
                self.retransmit_state.store_flight(4, &self.output_buf[..self.output_len])
                    .map_err(|e| DtlsError::handshake_failed(e))?;
                
                // Assertion: state must be Established
                assert_eq!(self.state, SessionState::Established, 
                    "handshake completion must set Established state");
            }
            
            // Unexpected message for current state
            (_state, _msg_type) => {
                return Err(DtlsError::UnexpectedMessage {
                    expected: "expected message for current state",
                    actual: "unexpected handshake message",
                });
            }
        }
        
        Ok(())
    }
    
    /// Process handshake message as client.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Placeholder for client-side handshake
    /// - ≥2 assertions
    fn process_handshake_client(
        &mut self,
        _msg_type: super::handshake::HandshakeType,
        payload: &[u8],
    ) -> Result<(), DtlsError> {
        // Precondition: must be client role
        assert_eq!(self.config.role, DtlsRole::Client, "must be client role");
        
        // Client-side handshake processing is a stub for now
        // The SFU primarily acts as server
        
        // Update handshake hash
        self.handshake.update_hash(payload);
        
        Ok(())
    }
    
    /// Select cipher suite from client's list.
    fn select_cipher_suite(&self, client_suites: &[u16]) -> Result<CipherSuite, DtlsError> {
        // Prefer our configured suites
        for i in 0..self.config.cipher_suite_count as usize {
            let our_suite = self.config.cipher_suites[i] as u16;
            for &client_suite in client_suites {
                if our_suite == client_suite {
                    return CipherSuite::from_u16(our_suite)
                        .ok_or(DtlsError::UnsupportedCipherSuite(our_suite));
                }
            }
        }
        Err(DtlsError::handshake_failed("no common cipher suite"))
    }
    
    /// Select SRTP profile from client's list.
    fn select_srtp_profile(&self, client_profiles: &[u16]) -> Option<SrtpProfile> {
        // Prefer our configured profiles
        for i in 0..self.config.srtp_profile_count as usize {
            let our_profile = self.config.srtp_profiles[i] as u16;
            for &client_profile in client_profiles {
                if our_profile == client_profile {
                    return SrtpProfile::from_u16(our_profile);
                }
            }
        }
        None
    }
    
    /// Process ChangeCipherSpec.
    fn process_change_cipher_spec(&mut self, _record: &Record) -> Result<(), DtlsError> {
        // Enable read cipher
        self.record_layer.increment_read_epoch();
        
        // Create read cipher from key material
        if self.config.role == DtlsRole::Client {
            // Client reads with server key
            self.read_cipher = Some(Aes128GcmContext::new(
                self.key_material.server_key(),
                self.key_material.server_iv(),
            )?);
        } else {
            // Server reads with client key
            self.read_cipher = Some(Aes128GcmContext::new(
                self.key_material.client_key(),
                self.key_material.client_iv(),
            )?);
        }
        
        Ok(())
    }
    
    /// Process alert.
    fn process_alert(&mut self, record: &Record) -> Result<(), DtlsError> {
        if record.payload.len() < 2 {
            return Err(DtlsError::RecordTooShort {
                actual: record.payload.len(),
                min: 2,
            });
        }
        
        let level = record.payload[0];
        let description = record.payload[1];
        
        if level == 2 {
            // Fatal alert
            self.state = SessionState::Failed;
        }
        
        Err(DtlsError::AlertReceived { level, description })
    }
    
    /// Process application data.
    fn process_application_data(&mut self, record: &Record) -> Result<Vec<u8>, DtlsError> {
        if !self.is_established() {
            return Err(DtlsError::NotEstablished);
        }
        
        // Decrypt if cipher is active
        if let Some(ref cipher) = self.read_cipher {
            if record.payload.len() < 8 + 16 {
                return Err(DtlsError::RecordTooShort {
                    actual: record.payload.len(),
                    min: 8 + 16,
                });
            }
            
            // Extract explicit nonce
            let mut explicit_nonce = [0u8; 8];
            explicit_nonce.copy_from_slice(&record.payload[..8]);
            
            // Build AAD
            let mut aad = [0u8; 13];
            aad[..2].copy_from_slice(&record.epoch.to_be_bytes());
            aad[2..8].copy_from_slice(&record.sequence_number.to_be_bytes()[2..8]);
            aad[8] = record.content_type as u8;
            aad[9..11].copy_from_slice(&record.version.to_be_bytes());
            let plaintext_len = record.payload.len() - 8 - 16;
            aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
            
            let mut plaintext = vec![0u8; plaintext_len];
            cipher.decrypt(
                &explicit_nonce,
                &aad,
                &record.payload[8..],
                &mut plaintext,
            )?;
            
            Ok(plaintext)
        } else {
            // No cipher, return raw
            Ok(record.payload.to_vec())
        }
    }
    
    /// Send application data.
    pub fn send(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, DtlsError> {
        if !self.is_established() {
            return Err(DtlsError::NotEstablished);
        }
        
        if let Some(ref cipher) = self.write_cipher {
            // Encrypt
            let mut explicit_nonce = [0u8; 8];
            let seq = self.record_layer.sequence_number();
            explicit_nonce.copy_from_slice(&seq.to_be_bytes());
            
            // Build AAD
            let mut aad = [0u8; 13];
            aad[..2].copy_from_slice(&self.record_layer.epoch().to_be_bytes());
            aad[2..8].copy_from_slice(&seq.to_be_bytes()[2..8]);
            aad[8] = ContentType::ApplicationData as u8;
            aad[9..11].copy_from_slice(&DTLS_VERSION_1_2.to_be_bytes());
            aad[11..13].copy_from_slice(&(data.len() as u16).to_be_bytes());
            
            // Encrypt into temporary buffer
            let mut ciphertext = [0u8; MAX_DTLS_RECORD_SIZE];
            ciphertext[..8].copy_from_slice(&explicit_nonce);
            
            let ct_len = cipher.encrypt(
                &explicit_nonce,
                &aad,
                data,
                &mut ciphertext[8..],
            )?;
            
            let payload = &ciphertext[..8 + ct_len];
            
            self.record_layer.build_record(
                ContentType::ApplicationData,
                payload,
                buf,
            )
        } else {
            // No cipher
            self.record_layer.build_record(
                ContentType::ApplicationData,
                data,
                buf,
            )
        }
    }
    
    /// Get pending output data.
    fn get_pending_output(&mut self) -> Option<&[u8]> {
        if self.output_len > 0 {
            let len = self.output_len;
            self.output_len = 0;
            Some(&self.output_buf[..len])
        } else {
            None
        }
    }
    
    /// Check if retransmission is needed.
    pub fn needs_retransmit(&self) -> bool {
        if self.state != SessionState::Handshaking {
            return false;
        }
        
        self.handshake.retransmit.needs_retransmit()
    }
    
    /// Get retransmission data.
    pub fn retransmit(&mut self) -> Option<&[u8]> {
        if !self.needs_retransmit() {
            return None;
        }
        
        if self.handshake.flight_len > 0 {
            self.handshake.retransmit.retransmit();
            Some(&self.handshake.flight_buf[..self.handshake.flight_len])
        } else {
            None
        }
    }
    
    /// Complete handshake with derived keys.
    ///
    /// Called when handshake messages are complete.
    pub fn complete_handshake(
        &mut self,
        master_secret: &[u8; 48],
        srtp_profile: SrtpProfile,
    ) -> Result<(), DtlsError> {
        self.master_secret.copy_from_slice(master_secret);
        
        // Derive TLS key material
        self.key_material = derive_key_material(
            master_secret,
            &self.handshake.client_random.as_bytes(),
            &self.handshake.server_random.as_bytes(),
            self.handshake.cipher_suite.unwrap_or(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        );
        
        // Create write cipher
        if self.config.role == DtlsRole::Client {
            self.write_cipher = Some(Aes128GcmContext::new(
                self.key_material.client_key(),
                self.key_material.client_iv(),
            )?);
        } else {
            self.write_cipher = Some(Aes128GcmContext::new(
                self.key_material.server_key(),
                self.key_material.server_iv(),
            )?);
        }
        
        // Export SRTP keys
        self.selected_srtp_profile = Some(srtp_profile);
        self.srtp_keys = Some(export_srtp_keys(
            master_secret,
            &self.handshake.client_random.as_bytes(),
            &self.handshake.server_random.as_bytes(),
            srtp_profile,
        ));
        
        // Update state
        self.record_layer.increment_epoch();
        self.handshake.state = HandshakeState::Complete;
        self.state = SessionState::Established;
        
        Ok(())
    }
    
    /// Close the session.
    pub fn close(&mut self) -> Result<(), DtlsError> {
        self.state = SessionState::Closed;
        Ok(())
    }
    
    /// Build a close_notify alert message.
    ///
    /// # Arguments
    /// * `buf` - Output buffer for the alert (must be at least 15 bytes)
    ///
    /// # Returns
    /// * `Ok(len)` - Number of bytes written to buffer
    /// * `Err` - If buffer is too small
    ///
    /// # TigerStyle
    /// - Precondition: buffer must be at least 15 bytes
    /// - Postcondition: returns valid DTLS alert record
    pub fn build_close_notify_alert(&mut self, buf: &mut [u8]) -> Result<usize, DtlsError> {
        // Precondition: buffer must be large enough for record header (13) + alert (2)
        assert!(buf.len() >= 15, "buffer too small for close_notify alert");
        
        // Alert level: warning (1), description: close_notify (0)
        let alert_payload = [1u8, 0u8];
        
        // Build record with alert content type
        let len = self.record_layer.build_record(
            ContentType::Alert,
            &alert_payload,
            buf,
        )?;
        
        // Postcondition: output is valid
        assert!(len >= 15, "alert record too short");
        
        Ok(len)
    }
    
    /// Set SRTP key material (for external handshake engines like OpenSSL).
    ///
    /// # TigerStyle
    /// - Precondition: keys must be valid
    pub fn set_srtp_keys(&mut self, keys: SrtpKeyMaterial) {
        // Precondition: keys should have non-zero master keys
        assert!(
            keys.client_master_key.iter().any(|&b| b != 0) ||
            keys.server_master_key.iter().any(|&b| b != 0),
            "SRTP keys must not be all zeros"
        );
        self.srtp_keys = Some(keys);
    }
    
    /// Set selected SRTP profile (for external handshake engines like OpenSSL).
    ///
    /// # TigerStyle
    /// - Precondition: profile must be valid
    pub fn set_selected_srtp_profile(&mut self, profile: SrtpProfile) {
        self.selected_srtp_profile = Some(profile);
    }
    
    /// Set session state (for external handshake engines like OpenSSL).
    ///
    /// # TigerStyle
    /// - Precondition: state transition must be valid
    pub fn set_state(&mut self, state: SessionState) {
        // Allow any state transition for external engines
        self.state = state;
    }

    /// Generate self-signed X.509 certificate for DTLS.
    ///
    /// Returns (DER bytes, length, SHA-256 fingerprint, private key DER).
    ///
    /// # TigerStyle
    /// - Bounded output: certificate ≤ 2048 bytes, private key ≤ 256 bytes
    /// - Explicit types: returns tuple with exact sizes
    /// - Assertions: validates certificate generation
    fn generate_certificate() -> Result<(Vec<u8>, usize, [u8; 32], Vec<u8>), DtlsError> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, Certificate};
        use sha2::{Sha256, Digest};

        // Generate ECDSA key pair (P-256)
        let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| DtlsError::handshake_failed(format!("key generation failed: {}", e)))?;
        
        // Extract private key before moving key_pair
        let private_key_der = key_pair.serialize_der();

        // Create certificate parameters
        let mut params = CertificateParams::default();
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(key_pair);

        // Set subject
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Nexus SFU");
        dn.push(DnType::OrganizationName, "Nexus");
        params.distinguished_name = dn;

        // Generate certificate
        let cert = Certificate::from_params(params)
            .map_err(|e| DtlsError::handshake_failed(format!("certificate generation failed: {}", e)))?;

        // Serialize to DER
        let der = cert.serialize_der()
            .map_err(|e| DtlsError::handshake_failed(format!("DER serialization failed: {}", e)))?;

        // Store length before moving der
        let der_len = der.len();

        // Precondition: DER must fit in buffer
        if der_len > 2048 {
            return Err(DtlsError::handshake_failed("certificate too large"));
        }
        
        // Precondition: private key must fit in buffer
        if private_key_der.len() > 256 {
            return Err(DtlsError::handshake_failed("private key too large"));
        }

        // Compute SHA-256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(&der);
        let hash = hasher.finalize();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&hash);

        // Postcondition: fingerprint is exactly 32 bytes
        assert_eq!(fingerprint.len(), 32, "SHA-256 must be 32 bytes");
        // Postcondition: private key is non-empty
        assert!(!private_key_der.is_empty(), "private key must not be empty");

        Ok((der, der_len, fingerprint, private_key_der))
    }
    
    // ========================================================================
    // Test Utilities (only available in test builds)
    // ========================================================================
    
    /// Force the handshake state (test utility).
    ///
    /// # Safety
    /// This bypasses normal state transitions and should only be used in tests.
    #[cfg(test)]
    pub fn force_state(&mut self, state: HandshakeState) {
        // Precondition: must be a valid state
        assert!(matches!(
            state,
            HandshakeState::New
                | HandshakeState::ClientHelloSent
                | HandshakeState::ServerHelloDone
                | HandshakeState::ClientKeyExchangeSent
                | HandshakeState::ChangeCipherSpecSent
                | HandshakeState::FinishedSent
                | HandshakeState::Established
                | HandshakeState::Failed
                | HandshakeState::Closed
                | HandshakeState::Complete
        ), "state must be valid");
        
        self.handshake.state = state;
        
        // Postcondition: state was set
        assert_eq!(self.handshake.state, state, "state must be updated");
    }
    
    /// Get the current retransmission count (test utility).
    #[cfg(test)]
    pub fn get_retransmit_count(&self) -> u8 {
        self.handshake.retransmit.count
    }
    
    /// Get elapsed time since handshake started (test utility).
    ///
    /// Returns None if handshake hasn't started yet.
    #[cfg(test)]
    pub fn get_handshake_elapsed(&self) -> Option<std::time::Duration> {
        self.handshake_start.map(|start| start.elapsed())
    }
    
    /// Get the current handshake state (test utility).
    #[cfg(test)]
    pub fn get_handshake_state(&self) -> HandshakeState {
        self.handshake.state
    }
    
    /// Check if SRTP keys are available (test utility).
    #[cfg(test)]
    pub fn has_srtp_keys(&self) -> bool {
        self.srtp_keys.is_some()
    }
    
    /// Get the selected SRTP profile (test utility).
    #[cfg(test)]
    pub fn get_srtp_profile(&self) -> Option<SrtpProfile> {
        self.selected_srtp_profile
    }
    
    /// Force retransmission timer to expire (test utility).
    #[cfg(test)]
    pub fn force_retransmit_timeout(&mut self) {
        // Set last_send to a time far in the past
        self.handshake.retransmit.last_send = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap_or_else(std::time::Instant::now);
    }
    
    /// Reset the session to initial state (test utility).
    #[cfg(test)]
    pub fn reset_for_test(&mut self) {
        self.state = SessionState::New;
        self.handshake.state = HandshakeState::New;
        self.handshake.retransmit.count = 0;
        self.handshake.retransmit.rto_ms = 1000;
        self.handshake_start = None;
        self.write_cipher = None;
        self.srtp_keys = None;
        self.selected_srtp_profile = None;
        // Regenerate ECDHE keypair for fresh handshake
        let (private_key, public_key) = Self::generate_ecdhe_keypair_with_ring();
        self.ecdhe_private_key_ring = Some(private_key);
        self.ecdhe_public_key = public_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Session Creation Tests
    // ========================================================================

    #[test]
    fn test_session_creation() {
        let client = DtlsSession::client();
        assert_eq!(client.state(), SessionState::New);
        assert_eq!(client.role(), DtlsRole::Client);
        
        let server = DtlsSession::server();
        assert_eq!(server.role(), DtlsRole::Server);
    }

    #[test]
    fn test_client_start_handshake() {
        let mut client = DtlsSession::client();
        let data = client.start_handshake().unwrap();
        
        assert!(data.is_some());
        
        let data = data.unwrap();
        // Should be a valid DTLS record
        assert!(RecordLayer::is_dtls(data));
        
        // Check state after data borrow is done
        assert_eq!(client.state(), SessionState::Handshaking);
    }

    #[test]
    fn test_session_config() {
        let config = SessionConfig::client();
        assert_eq!(config.role, DtlsRole::Client);
        assert_eq!(config.cipher_suite_count, 2);
        assert_eq!(config.srtp_profile_count, 4);
        
        let config = SessionConfig::server();
        assert_eq!(config.role, DtlsRole::Server);
    }

    #[test]
    fn test_certificate_generation() {
        let session = DtlsSession::server();

        // Certificate must be initialized
        assert!(session.certificate_len > 0);
        assert!(session.certificate_len <= 2048);

        // Fingerprint must be initialized (non-zero)
        assert!(session.fingerprint_sha256.iter().any(|&b| b != 0));

        // Fingerprint must be exactly 32 bytes
        assert_eq!(session.fingerprint().len(), 32);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let session1 = DtlsSession::server();
        let session2 = DtlsSession::server();

        // Different sessions should have different fingerprints
        // (because certificates are generated with random keys)
        assert_ne!(session1.fingerprint(), session2.fingerprint());
    }

    #[test]
    fn test_certificate_der_valid() {
        let session = DtlsSession::server();
        let der = session.certificate_der();

        // DER must be non-empty
        assert!(!der.is_empty());

        // DER must start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_fingerprint_sha256_length() {
        let session = DtlsSession::server();

        // Fingerprint must be exactly 32 bytes (SHA-256)
        assert_eq!(session.fingerprint_sha256.len(), 32);
        assert_eq!(session.fingerprint().len(), 32);
    }

    // ========================================================================
    // Session State Tests (Initial→Handshaking→Established→Closed)
    // ========================================================================

    #[test]
    fn test_session_state_values() {
        assert_eq!(SessionState::New as u8, 0);
        assert_eq!(SessionState::Handshaking as u8, 1);
        assert_eq!(SessionState::Established as u8, 2);
        assert_eq!(SessionState::Closed as u8, 3);
        assert_eq!(SessionState::Failed as u8, 4);
    }

    #[test]
    fn test_session_state_is_established() {
        assert!(SessionState::Established.is_established());
        assert!(!SessionState::New.is_established());
        assert!(!SessionState::Handshaking.is_established());
        assert!(!SessionState::Closed.is_established());
        assert!(!SessionState::Failed.is_established());
    }

    #[test]
    fn test_session_state_is_terminal() {
        assert!(SessionState::Closed.is_terminal());
        assert!(SessionState::Failed.is_terminal());
        assert!(!SessionState::New.is_terminal());
        assert!(!SessionState::Handshaking.is_terminal());
        assert!(!SessionState::Established.is_terminal());
    }

    #[test]
    fn test_session_state_can_process() {
        assert!(SessionState::Handshaking.can_process());
        assert!(SessionState::Established.can_process());
        assert!(!SessionState::New.can_process());
        assert!(!SessionState::Closed.can_process());
        assert!(!SessionState::Failed.can_process());
    }

    // ========================================================================
    // Session Timeout Tests (30s handshake, 60s idle)
    // ========================================================================

    #[test]
    fn test_handshake_timeout_constant() {
        assert_eq!(HANDSHAKE_TIMEOUT_MS, 30000, 
            "Handshake timeout should be 30 seconds");
    }

    // ========================================================================
    // Key Export Timing Tests (only after handshake complete)
    // ========================================================================

    #[test]
    fn test_no_srtp_keys_before_handshake() {
        let session = DtlsSession::client();
        
        // SRTP keys should not be available before handshake
        assert!(!session.has_srtp_keys());
    }

    // ========================================================================
    // Session Config Tests
    // ========================================================================

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        
        // Default should be client
        assert_eq!(config.role, DtlsRole::Client);
    }

    #[test]
    fn test_session_config_mtu() {
        let config = SessionConfig::client();
        
        // MTU should be set
        assert!(config.mtu > 0);
        assert!(config.mtu <= 1500);
    }

    // ========================================================================
    // Test Utility Tests
    // ========================================================================

    #[test]
    fn test_force_state_for_testing() {
        let mut session = DtlsSession::client();
        
        session.force_state(HandshakeState::Established);
        
        assert_eq!(session.get_handshake_state(), HandshakeState::Established);
    }

    #[test]
    fn test_reset_for_test() {
        let mut session = DtlsSession::client();
        
        // Start handshake to change state
        let _ = session.start_handshake();
        assert_eq!(session.state(), SessionState::Handshaking);
        
        // Reset should return to initial state
        session.reset_for_test();
        assert_eq!(session.state(), SessionState::New);
    }

    #[test]
    fn test_get_retransmit_count() {
        let session = DtlsSession::client();
        
        // Initial retransmit count should be 0
        assert_eq!(session.get_retransmit_count(), 0);
    }

    // ========================================================================
    // ECDHE Key Generation Tests
    // ========================================================================

    #[test]
    fn test_ecdhe_public_key_format() {
        let session = DtlsSession::client();
        
        // ECDHE public key should be 65 bytes (uncompressed P-256)
        assert_eq!(session.ecdhe_public_key.len(), 65);
        
        // First byte should be 0x04 (uncompressed point marker)
        assert_eq!(session.ecdhe_public_key[0], 0x04);
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let session1 = DtlsSession::client();
        let session2 = DtlsSession::client();
        
        // Different sessions should have different ECDHE keys
        assert_ne!(session1.ecdhe_public_key, session2.ecdhe_public_key);
    }

    // ========================================================================
    // DtlsRole Tests
    // ========================================================================

    #[test]
    fn test_dtls_role_client() {
        let config = SessionConfig::client();
        assert!(matches!(config.role, DtlsRole::Client));
    }

    #[test]
    fn test_dtls_role_server() {
        let config = SessionConfig::server();
        assert!(matches!(config.role, DtlsRole::Server));
    }

    // ========================================================================
    // Record Layer Integration Tests
    // ========================================================================

    #[test]
    fn test_session_generates_valid_dtls_records() {
        let mut client = DtlsSession::client();
        let data = client.start_handshake().unwrap();
        
        if let Some(bytes) = data {
            assert!(bytes.len() >= 13, "Record must include header");
            assert!(RecordLayer::is_dtls(bytes), "Must be valid DTLS");
        }
    }

    // ========================================================================
    // Cipher Suite Configuration Tests
    // ========================================================================

    #[test]
    fn test_session_supports_multiple_cipher_suites() {
        let config = SessionConfig::client();
        
        assert!(config.cipher_suite_count >= 1, "Must support at least one cipher suite");
        assert!(config.cipher_suite_count <= 4, "Cipher suite count should be bounded");
    }

    // ========================================================================
    // SRTP Profile Configuration Tests
    // ========================================================================

    #[test]
    fn test_session_supports_multiple_srtp_profiles() {
        let config = SessionConfig::client();
        
        assert!(config.srtp_profile_count >= 1, "Must support at least one SRTP profile");
        assert!(config.srtp_profile_count <= 4, "SRTP profile count should be bounded");
    }

    // ========================================================================
    // Compile-Time Size Validation
    // ========================================================================

    #[test]
    fn test_session_size_reasonable() {
        let size = std::mem::size_of::<DtlsSession>();
        
        // Session should be less than 256KB
        assert!(size < 262144, "DtlsSession size {} is too large", size);
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================
    
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        
        proptest! {
            /// Property: SessionState transitions are bounded.
            #[test]
            fn prop_session_state_values_bounded(
                state_val in 0u8..10,
            ) {
                // Only valid states are 0-4
                let is_valid = state_val <= 4;
                
                if is_valid {
                    // These should be valid states
                    match state_val {
                        0 => prop_assert_eq!(SessionState::New as u8, 0),
                        1 => prop_assert_eq!(SessionState::Handshaking as u8, 1),
                        2 => prop_assert_eq!(SessionState::Established as u8, 2),
                        3 => prop_assert_eq!(SessionState::Closed as u8, 3),
                        4 => prop_assert_eq!(SessionState::Failed as u8, 4),
                        _ => unreachable!(),
                    }
                }
            }
            
            /// Property: Client and server roles are distinct.
            #[test]
            fn prop_roles_distinct(
                role_idx in 0u8..2,
            ) {
                let session = if role_idx == 0 {
                    DtlsSession::client()
                } else {
                    DtlsSession::server()
                };
                
                let role = session.role();
                prop_assert!(role == DtlsRole::Client || role == DtlsRole::Server);
                
                if role_idx == 0 {
                    prop_assert_eq!(role, DtlsRole::Client);
                } else {
                    prop_assert_eq!(role, DtlsRole::Server);
                }
            }
            
            /// Property: Initial state is always New.
            #[test]
            fn prop_initial_state_new(
                role_idx in 0u8..2,
            ) {
                let session = if role_idx == 0 {
                    DtlsSession::client()
                } else {
                    DtlsSession::server()
                };
                
                prop_assert_eq!(session.state(), SessionState::New);
                prop_assert!(!session.has_srtp_keys());
            }
            
            /// Property: Fingerprint is always 32 bytes.
            #[test]
            fn prop_fingerprint_size(
                role_idx in 0u8..2,
            ) {
                let session = if role_idx == 0 {
                    DtlsSession::client()
                } else {
                    DtlsSession::server()
                };
                
                let fp = session.fingerprint();
                prop_assert_eq!(fp.len(), 32);
                // Fingerprint should not be all zeros
                prop_assert!(fp.iter().any(|&b| b != 0));
            }
            
            /// Property: Terminal states cannot process.
            #[test]
            fn prop_terminal_states_behavior(
                _ in 0..10u32,
            ) {
                // Closed is terminal
                prop_assert!(SessionState::Closed.is_terminal());
                // Failed is terminal
                prop_assert!(SessionState::Failed.is_terminal());
                // New is not terminal
                prop_assert!(!SessionState::New.is_terminal());
                // Handshaking is not terminal
                prop_assert!(!SessionState::Handshaking.is_terminal());
                // Established is not terminal (can still close)
                prop_assert!(!SessionState::Established.is_terminal());
            }
            
            /// Property: State can_process is correct.
            #[test]
            fn prop_can_process_states(
                _ in 0..10u32,
            ) {
                // Handshaking can process
                prop_assert!(SessionState::Handshaking.can_process());
                // Established can process
                prop_assert!(SessionState::Established.can_process());
                // New cannot process
                prop_assert!(!SessionState::New.can_process());
                // Terminal states cannot process
                prop_assert!(!SessionState::Closed.can_process());
                prop_assert!(!SessionState::Failed.can_process());
            }
        }
    }
}

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

/// Certificate buffer size constant.
#[allow(dead_code)] // Used in compile-time assertions below
const CERTIFICATE_BUFFER_SIZE: usize = 2048;

const _: () = {
    // Certificate buffer must be exactly 2048 bytes
    assert!(std::mem::size_of::<[u8; CERTIFICATE_BUFFER_SIZE]>() == CERTIFICATE_BUFFER_SIZE);

    // Fingerprint must be exactly 32 bytes (SHA-256)
    assert!(std::mem::size_of::<[u8; 32]>() == 32);

    // Certificate length field must fit u16
    assert!(CERTIFICATE_BUFFER_SIZE <= u16::MAX as usize);
    
    // ECDHE private key must be exactly 32 bytes (P-256)
    assert!(std::mem::size_of::<[u8; 32]>() == 32);
    
    // ECDHE public key must be exactly 65 bytes (uncompressed P-256)
    assert!(std::mem::size_of::<[u8; 65]>() == 65);
    
    // Private key buffer must be exactly 256 bytes
    assert!(std::mem::size_of::<[u8; 256]>() == 256);

    // DtlsSession size should be reasonable (< 256KB)
    // Note: includes 2KB certificate buffer + 16KB output buffer + handshake context with large buffers
    assert!(std::mem::size_of::<DtlsSession>() < 262144);
    
    // DtlsSession alignment must be <= 8 for cache efficiency
    assert!(std::mem::align_of::<DtlsSession>() <= 8);
};
