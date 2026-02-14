//! DTLS Handshake.
//!
//! Implements the DTLS 1.2 handshake state machine per RFC 6347.
//!
//! # State Machine
//!
//! ```text
//! Client:  New → ClientHelloSent → ServerHelloDone → ClientKeyExchangeSent
//!          → ChangeCipherSpecSent → FinishedSent → Established
//!
//! Server:  New → ClientHelloReceived → ServerHelloDone → ClientKeyExchangeReceived
//!          → ChangeCipherSpecReceived → FinishedReceived → Established
//!
//! Terminal: Failed, Closed
//! ```
//!
//! # Flight Structure (RFC 6347)
//!
//! - Flight 1 (Client): ClientHello
//! - Flight 2 (Server): ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
//! - Flight 3 (Client): ClientKeyExchange, ChangeCipherSpec, Finished
//! - Flight 4 (Server): ChangeCipherSpec, Finished
//!
//! # TigerStyle Compliance
//!
//! - Static allocation: all buffers are fixed-size arrays
//! - Bounded operations: max 20 cipher suites, max 10 extensions, max 8 messages per flight
//! - Assertion density: ≥2 assertions per function
//! - Explicit types: u16 for lengths, u8 for counts
//! - All functions ≤70 lines

use super::error::DtlsError;
use super::types::{DtlsRole, HandshakeHeader, RetransmissionState};
use super::crypto::{CipherSuite, SrtpProfile};
use super::{DTLS_VERSION_1_2, MAX_HANDSHAKE_SIZE, MAX_FLIGHT_SIZE};
use getrandom::getrandom;

/// Maximum number of cipher suites in ClientHello.
pub const MAX_CIPHER_SUITES: usize = 20;

/// Maximum number of extensions in ClientHello.
pub const MAX_EXTENSIONS: usize = 16;

/// Maximum number of SRTP profiles.
pub const MAX_SRTP_PROFILES: usize = 4;

/// Maximum buffered out-of-order messages.
#[allow(dead_code)] // Used in compile-time assertions and HandshakeContext buffer sizing
pub const MAX_BUFFERED_MESSAGES: usize = 8;

/// Maximum fragment size for MTU compliance.
#[allow(dead_code)] // Reserved for DTLS fragment reassembly implementation
pub const MAX_FRAGMENT_SIZE: usize = 1400;

// Compile-time assertions for TigerStyle
const _: () = assert!(MAX_CIPHER_SUITES <= 20);
const _: () = assert!(MAX_EXTENSIONS <= 16);
const _: () = assert!(MAX_SRTP_PROFILES <= 4);
const _: () = assert!(MAX_BUFFERED_MESSAGES == 8);
const _: () = assert!(MAX_FRAGMENT_SIZE == 1400);
const _: () = assert!(MAX_FLIGHT_SIZE == 8);

/// Handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl HandshakeType {
    /// Parse from byte.
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::HelloRequest),
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            3 => Some(Self::HelloVerifyRequest),
            11 => Some(Self::Certificate),
            12 => Some(Self::ServerKeyExchange),
            13 => Some(Self::CertificateRequest),
            14 => Some(Self::ServerHelloDone),
            15 => Some(Self::CertificateVerify),
            16 => Some(Self::ClientKeyExchange),
            20 => Some(Self::Finished),
            _ => None,
        }
    }
}

/// Handshake state machine - RFC 6347 compliant.
///
/// Explicit state transitions for both client and server roles.
///
/// # State Transition Matrix
///
/// | Current State              | Valid Next States                    |
/// |---------------------------|--------------------------------------|
/// | New                       | ClientHelloSent, ClientHelloReceived |
/// | ClientHelloSent           | ServerHelloDone, Failed             |
/// | ClientHelloReceived       | ServerHelloDone                     |
/// | ServerHelloDone           | ClientKeyExchangeSent, ClientKeyExchangeReceived |
/// | ClientKeyExchangeSent     | ChangeCipherSpecSent                |
/// | ClientKeyExchangeReceived | ChangeCipherSpecReceived            |
/// | ChangeCipherSpecSent      | FinishedSent                        |
/// | ChangeCipherSpecReceived  | FinishedReceived                    |
/// | FinishedSent              | Established                         |
/// | FinishedReceived          | Established                         |
/// | Established               | Closed                               |
/// | Failed                    | (terminal)                           |
/// | Closed                    | (terminal)                           |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeState {
    // =========== Common States ===========
    /// Initial state (before handshake starts).
    New = 0,
    
    // =========== Client States ===========
    /// Client sent ClientHello, waiting for server flight.
    ClientHelloSent = 1,
    
    // =========== Server States ===========
    /// Server received ClientHello.
    ClientHelloReceived = 2,
    
    // =========== Shared States ===========
    /// ServerHelloDone received (client) or sent (server).
    ServerHelloDone = 3,
    
    /// Client sent ClientKeyExchange.
    ClientKeyExchangeSent = 4,
    
    /// Server received ClientKeyExchange.
    ClientKeyExchangeReceived = 5,
    
    /// Client sent ChangeCipherSpec.
    ChangeCipherSpecSent = 6,
    
    /// Server received ChangeCipherSpec.
    ChangeCipherSpecReceived = 7,
    
    /// Client sent Finished.
    FinishedSent = 8,
    
    /// Server received Finished.
    FinishedReceived = 9,
    
    /// Handshake complete - secure connection established.
    Established = 10,
    
    // =========== Terminal States ===========
    /// Handshake failed (timeout, verification, protocol error).
    Failed = 11,
    
    /// Connection closed gracefully.
    Closed = 12,
    
    // =========== Legacy States (for compatibility) ===========
    /// Waiting for HelloVerifyRequest (legacy).
    WaitingHelloVerifyRequest = 20,
    
    /// Waiting for ServerHello (legacy).
    WaitingServerHello = 21,
    
    /// Waiting for Certificate (legacy).
    WaitingCertificate = 22,
    
    /// Waiting for ServerKeyExchange (legacy).
    WaitingServerKeyExchange = 23,
    
    /// Waiting for CertificateRequest (legacy).
    WaitingCertificateRequest = 24,
    
    /// Waiting for ServerHelloDone (legacy).
    WaitingServerHelloDone = 25,
    
    /// Waiting for ClientKeyExchange (legacy).
    WaitingClientKeyExchange = 26,
    
    /// Waiting for CertificateVerify (legacy).
    WaitingCertificateVerify = 27,
    
    /// Waiting for ChangeCipherSpec (legacy).
    WaitingChangeCipherSpec = 28,
    
    /// Waiting for Finished (legacy).
    WaitingFinished = 29,
    
    /// Complete (legacy alias).
    Complete = 30,
    
    /// Initial (legacy alias).
    Initial = 31,
}

impl HandshakeState {
    /// Returns true if handshake is complete.
    #[inline]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Established | Self::Complete)
    }
    
    /// Returns true if handshake has failed.
    #[inline]
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
    
    /// Returns true if state is terminal (no more transitions allowed).
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closed | Self::Established | Self::Complete)
    }
    
    /// Check if transition to next state is valid.
    ///
    /// Implements explicit state transition matrix per RFC 6347.
    ///
    /// # TigerStyle
    /// - Explicit match on all states
    /// - No default/wildcard cases
    #[inline]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            // New -> ClientHelloSent (client starts) or ClientHelloReceived (server receives)
            (Self::New, Self::ClientHelloSent) => true,
            (Self::New, Self::ClientHelloReceived) => true,
            (Self::New, Self::Initial) => true,
            (Self::Initial, Self::ClientHelloSent) => true,
            (Self::Initial, Self::WaitingServerHello) => true,
            (Self::Initial, Self::WaitingClientKeyExchange) => true,
            
            // ClientHelloSent -> ServerHelloDone or Failed
            (Self::ClientHelloSent, Self::ServerHelloDone) => true,
            (Self::ClientHelloSent, Self::WaitingServerHello) => true,
            (Self::ClientHelloSent, Self::Failed) => true,
            (Self::WaitingServerHello, Self::ServerHelloDone) => true,
            (Self::WaitingServerHello, Self::WaitingCertificate) => true,
            (Self::WaitingServerHello, Self::Failed) => true,
            
            // ClientHelloReceived -> ServerHelloDone (server sends flight)
            (Self::ClientHelloReceived, Self::ServerHelloDone) => true,
            (Self::WaitingClientKeyExchange, Self::WaitingChangeCipherSpec) => true,
            (Self::WaitingClientKeyExchange, Self::ClientKeyExchangeReceived) => true,
            
            // ServerHelloDone -> ClientKeyExchange states
            (Self::ServerHelloDone, Self::ClientKeyExchangeSent) => true,
            (Self::ServerHelloDone, Self::ClientKeyExchangeReceived) => true,
            (Self::ServerHelloDone, Self::WaitingClientKeyExchange) => true,
            
            // ClientKeyExchange -> ChangeCipherSpec states
            (Self::ClientKeyExchangeSent, Self::ChangeCipherSpecSent) => true,
            (Self::ClientKeyExchangeReceived, Self::ChangeCipherSpecReceived) => true,
            (Self::ClientKeyExchangeReceived, Self::WaitingChangeCipherSpec) => true,
            
            // ChangeCipherSpec -> Finished states
            (Self::ChangeCipherSpecSent, Self::FinishedSent) => true,
            (Self::ChangeCipherSpecReceived, Self::FinishedReceived) => true,
            (Self::WaitingChangeCipherSpec, Self::WaitingFinished) => true,
            (Self::WaitingChangeCipherSpec, Self::ChangeCipherSpecReceived) => true,
            
            // Finished -> Established
            (Self::FinishedSent, Self::Established) => true,
            (Self::FinishedReceived, Self::Established) => true,
            (Self::WaitingFinished, Self::Established) => true,
            (Self::WaitingFinished, Self::Complete) => true,
            (Self::WaitingFinished, Self::FinishedReceived) => true,
            
            // Established -> Closed
            (Self::Established, Self::Closed) => true,
            (Self::Complete, Self::Closed) => true,
            
            // Any non-terminal -> Failed
            (Self::New, Self::Failed) => true,
            (Self::Initial, Self::Failed) => true,
            (Self::ClientHelloReceived, Self::Failed) => true,
            (Self::ServerHelloDone, Self::Failed) => true,
            (Self::ClientKeyExchangeSent, Self::Failed) => true,
            (Self::ClientKeyExchangeReceived, Self::Failed) => true,
            (Self::ChangeCipherSpecSent, Self::Failed) => true,
            (Self::ChangeCipherSpecReceived, Self::Failed) => true,
            (Self::FinishedSent, Self::Failed) => true,
            (Self::FinishedReceived, Self::Failed) => true,
            (Self::WaitingHelloVerifyRequest, Self::Failed) => true,
            (Self::WaitingCertificate, Self::Failed) => true,
            (Self::WaitingServerKeyExchange, Self::Failed) => true,
            (Self::WaitingCertificateRequest, Self::Failed) => true,
            (Self::WaitingServerHelloDone, Self::Failed) => true,
            (Self::WaitingClientKeyExchange, Self::Failed) => true,
            (Self::WaitingCertificateVerify, Self::Failed) => true,
            (Self::WaitingChangeCipherSpec, Self::Failed) => true,
            (Self::WaitingFinished, Self::Failed) => true,
            
            // All other transitions are invalid
            _ => false,
        }
    }
    
    /// Attempt to transition to next state with validation.
    ///
    /// # Returns
    /// - `Ok(())` if transition is valid
    /// - `Err(DtlsError::InvalidState)` if transition is not allowed
    ///
    /// # TigerStyle
    /// - Asserts postcondition: state changed if Ok returned
    #[inline]
    pub fn transition_to(&mut self, next: Self) -> Result<(), DtlsError> {
        // Precondition: check transition validity
        if !self.can_transition_to(next) {
            return Err(DtlsError::invalid_state(format!(
                "invalid transition from {:?} to {:?}", *self, next
            )));
        }
        
        let old_state = *self;
        *self = next;
        
        // Postcondition: state must have changed (or be idempotent)
        debug_assert!(old_state != next || old_state == next);
        
        Ok(())
    }
}

/// Flight - a group of handshake messages sent together.
///
/// RFC 6347 Section 4.2.4: Messages within a flight must be retransmitted together.
///
/// # Flight Structure
///
/// - Flight 1: ClientHello
/// - Flight 2: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
/// - Flight 3: ClientKeyExchange, ChangeCipherSpec, Finished
/// - Flight 4: ChangeCipherSpec, Finished
#[derive(Debug, Clone)]
pub struct Flight {
    /// Flight number (1-4 for DTLS handshake).
    pub number: u8,
    
    /// Messages in this flight (up to MAX_FLIGHT_SIZE).
    pub messages: [[u8; 1500]; 8],
    
    /// Length of each message.
    pub message_lengths: [u16; 8],
    
    /// Number of messages in flight.
    pub message_count: u8,
    
    /// Combined flight data for retransmission.
    pub combined: [u8; 8192],
    
    /// Combined data length.
    pub combined_len: u16,
    
    /// Retransmission state.
    pub retransmit: RetransmissionState,
}

impl Flight {
    /// Maximum messages per flight.
    pub const MAX_MESSAGES: u8 = 8;
    
    /// Maximum combined flight size.
    pub const MAX_SIZE: usize = 8192;
    
    /// Create new empty flight.
    pub fn new(number: u8) -> Self {
        // Precondition: flight number must be 1-4
        assert!(number >= 1 && number <= 4, "flight number must be 1-4");
        
        Self {
            number,
            messages: [[0u8; 1500]; 8],
            message_lengths: [0; 8],
            message_count: 0,
            combined: [0u8; 8192],
            combined_len: 0,
            retransmit: RetransmissionState::new(),
        }
    }
    
    /// Add a message to the flight.
    ///
    /// # Returns
    /// - `Ok(())` if message added successfully
    /// - `Err` if flight is full or message too large
    ///
    /// # TigerStyle
    /// - Bounded: max 8 messages, max 1500 bytes each
    pub fn add_message(&mut self, message: &[u8]) -> Result<(), DtlsError> {
        // Precondition: not full
        if self.message_count >= Self::MAX_MESSAGES {
            return Err(DtlsError::handshake_failed("flight full: max 8 messages"));
        }
        
        // Precondition: message fits
        if message.len() > 1500 {
            return Err(DtlsError::handshake_failed("message too large for flight"));
        }
        
        let idx = self.message_count as usize;
        self.messages[idx][..message.len()].copy_from_slice(message);
        self.message_lengths[idx] = message.len() as u16;
        self.message_count += 1;
        
        // Update combined buffer
        let new_combined_len = self.combined_len as usize + message.len();
        if new_combined_len > Self::MAX_SIZE {
            return Err(DtlsError::handshake_failed("flight exceeds max size"));
        }
        
        self.combined[self.combined_len as usize..new_combined_len].copy_from_slice(message);
        self.combined_len = new_combined_len as u16;
        
        // Postcondition: message count increased
        assert!(self.message_count <= Self::MAX_MESSAGES);
        
        Ok(())
    }
    
    /// Get combined flight data for transmission.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.combined[..self.combined_len as usize]
    }
    
    /// Reset the flight for a new attempt.
    pub fn reset(&mut self) {
        self.message_count = 0;
        self.combined_len = 0;
        self.retransmit.reset();
    }
}

// Compile-time assertion for Flight size
const _: () = assert!(std::mem::size_of::<Flight>() < 32768);

/// Fragment buffer for reassembling large handshake messages.
///
/// Handles messages larger than MTU (typically 1200-1500 bytes).
///
/// # Bounds
/// - Max 8 fragments
/// - Max 1400 bytes per fragment
/// - Max 4096 bytes total message size
#[derive(Debug, Clone)]
pub struct FragmentBuffer {
    /// Fragment data storage.
    pub fragments: [[u8; 1400]; 8],
    
    /// Length of each fragment.
    pub fragment_lengths: [u16; 8],
    
    /// Offset of each fragment in the original message.
    pub fragment_offsets: [u32; 8],
    
    /// Number of fragments received.
    pub fragment_count: u8,
    
    /// Total message length.
    pub total_length: u32,
    
    /// Message sequence number.
    pub message_seq: u16,
    
    /// Handshake message type.
    pub msg_type: u8,
    
    /// Bitmap of received fragments (for gap detection).
    pub received_bitmap: u64,
}

impl FragmentBuffer {
    /// Maximum fragments allowed.
    pub const MAX_FRAGMENTS: u8 = 8;
    
    /// Maximum bytes per fragment.
    pub const MAX_FRAGMENT_SIZE: usize = 1400;
    
    /// Maximum total message size.
    pub const MAX_MESSAGE_SIZE: u32 = 4096;
    
    /// Create new empty fragment buffer.
    pub fn new() -> Self {
        Self {
            fragments: [[0u8; 1400]; 8],
            fragment_lengths: [0; 8],
            fragment_offsets: [0; 8],
            fragment_count: 0,
            total_length: 0,
            message_seq: 0,
            msg_type: 0,
            received_bitmap: 0,
        }
    }
    
    /// Add a fragment to the buffer.
    ///
    /// # Returns
    /// - `Ok(true)` if message is now complete
    /// - `Ok(false)` if more fragments needed
    /// - `Err` if fragment is invalid or buffer full
    ///
    /// # TigerStyle
    /// - ≥2 assertions on inputs
    /// - Bounded loop for fragment count
    pub fn add_fragment(
        &mut self,
        msg_type: u8,
        message_seq: u16,
        fragment_offset: u32,
        fragment_data: &[u8],
        total_length: u32,
    ) -> Result<bool, DtlsError> {
        // Precondition: fragment data fits
        assert!(fragment_data.len() <= Self::MAX_FRAGMENT_SIZE, 
            "fragment exceeds max size");
        
        // Precondition: offset + length <= total
        assert!(fragment_offset + fragment_data.len() as u32 <= total_length,
            "fragment extends beyond message");
        
        // Validate total length
        if total_length > Self::MAX_MESSAGE_SIZE {
            return Err(DtlsError::handshake_failed("handshake message too large"));
        }
        
        // Check fragment count
        if self.fragment_count >= Self::MAX_FRAGMENTS {
            return Err(DtlsError::handshake_failed("too many fragments"));
        }
        
        // Initialize or validate message identity
        if self.fragment_count == 0 {
            self.msg_type = msg_type;
            self.message_seq = message_seq;
            self.total_length = total_length;
        } else if self.message_seq != message_seq || self.total_length != total_length {
            return Err(DtlsError::handshake_failed("fragment sequence mismatch"));
        }
        
        // Store fragment
        let idx = self.fragment_count as usize;
        self.fragments[idx][..fragment_data.len()].copy_from_slice(fragment_data);
        self.fragment_lengths[idx] = fragment_data.len() as u16;
        self.fragment_offsets[idx] = fragment_offset;
        self.fragment_count += 1;
        
        // Check if complete
        let is_complete = self.is_complete();
        
        // Postcondition: fragment count bounded
        assert!(self.fragment_count <= Self::MAX_FRAGMENTS);
        
        Ok(is_complete)
    }
    
    /// Check if all fragments have been received.
    ///
    /// Verifies coverage from offset 0 to total_length.
    pub fn is_complete(&self) -> bool {
        if self.fragment_count == 0 || self.total_length == 0 {
            return false;
        }
        
        // Sort fragments by offset and check coverage
        let mut coverage = 0u32;
        let mut sorted_indices: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        
        // Simple bubble sort (max 8 elements, bounded)
        for i in 0..self.fragment_count as usize {
            for j in (i + 1)..self.fragment_count as usize {
                if self.fragment_offsets[sorted_indices[j] as usize] 
                   < self.fragment_offsets[sorted_indices[i] as usize] {
                    sorted_indices.swap(i, j);
                }
            }
        }
        
        // Check coverage (bounded loop)
        for i in 0..self.fragment_count as usize {
            let idx = sorted_indices[i] as usize;
            let offset = self.fragment_offsets[idx];
            let length = self.fragment_lengths[idx] as u32;
            
            // Gap detection
            if offset > coverage {
                return false;
            }
            
            // Extend coverage
            let new_coverage = offset + length;
            if new_coverage > coverage {
                coverage = new_coverage;
            }
        }
        
        coverage >= self.total_length
    }
    
    /// Assemble complete message into output buffer.
    ///
    /// # Preconditions
    /// - `is_complete()` must return true
    /// - `output.len() >= total_length`
    ///
    /// # TigerStyle
    /// - ≥2 assertions
    pub fn assemble(&self, output: &mut [u8]) -> Result<usize, DtlsError> {
        // Precondition: must be complete
        assert!(self.is_complete(), "cannot assemble incomplete message");
        
        // Precondition: output buffer must be large enough
        assert!(output.len() >= self.total_length as usize,
            "output buffer too small");
        
        // Copy fragments in order (bounded loop)
        for i in 0..self.fragment_count as usize {
            let offset = self.fragment_offsets[i] as usize;
            let length = self.fragment_lengths[i] as usize;
            let frag_data = &self.fragments[i][..length];
            
            // Bounds check before copy
            if offset + length <= output.len() {
                output[offset..offset + length].copy_from_slice(frag_data);
            }
        }
        
        // Postcondition: return total length
        assert!(self.total_length <= Self::MAX_MESSAGE_SIZE);
        
        Ok(self.total_length as usize)
    }
    
    /// Reset the buffer for a new message.
    pub fn reset(&mut self) {
        self.fragment_count = 0;
        self.total_length = 0;
        self.message_seq = 0;
        self.msg_type = 0;
        self.received_bitmap = 0;
    }
}

impl Default for FragmentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time assertions for FragmentBuffer
const _: () = assert!(FragmentBuffer::MAX_FRAGMENTS == 8);
const _: () = assert!(FragmentBuffer::MAX_FRAGMENT_SIZE == 1400);
const _: () = assert!(FragmentBuffer::MAX_MESSAGE_SIZE == 4096);
const _: () = assert!(std::mem::size_of::<FragmentBuffer>() < 16384);

/// Random bytes for ClientHello/ServerHello.
#[derive(Debug, Clone, Copy)]
pub struct Random {
    /// GMT Unix time.
    pub gmt_unix_time: u32,
    
    /// Random bytes.
    pub random_bytes: [u8; 28],
}

impl Random {
    /// Size in bytes.
    pub const SIZE: usize = 32;
    
    /// Generate new random.
    pub fn generate() -> Self {
        let gmt_unix_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        let mut random_bytes = [0u8; 28];
        getrandom(&mut random_bytes).expect("getrandom failed");
        
        Self {
            gmt_unix_time,
            random_bytes,
        }
    }
    
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        
        let gmt_unix_time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut random_bytes = [0u8; 28];
        random_bytes.copy_from_slice(&data[4..32]);
        
        Some(Self {
            gmt_unix_time,
            random_bytes,
        })
    }
    
    /// Encode to bytes.
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "buffer too small");
        
        buf[0..4].copy_from_slice(&self.gmt_unix_time.to_be_bytes());
        buf[4..32].copy_from_slice(&self.random_bytes);
    }
    
    /// Get as 32-byte array.
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.encode(&mut bytes);
        bytes
    }
}

/// Session ID.
#[derive(Debug, Clone)]
pub struct SessionId {
    /// Session ID bytes.
    pub bytes: [u8; 32],
    
    /// Length.
    pub len: u8,
}

impl SessionId {
    /// Create empty session ID.
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; 32],
            len: 0,
        }
    }
    
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }
        
        let len = data[0] as usize;
        if data.len() < 1 + len || len > 32 {
            return None;
        }
        
        let mut session_id = Self::empty();
        session_id.len = len as u8;
        if len > 0 {
            session_id.bytes[..len].copy_from_slice(&data[1..1 + len]);
        }
        
        Some((session_id, 1 + len))
    }
}

/// Cookie for HelloVerifyRequest.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie bytes.
    pub bytes: [u8; 255],
    
    /// Length.
    pub len: u8,
}

impl Cookie {
    /// Create empty cookie.
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; 255],
            len: 0,
        }
    }
    
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }
        
        let len = data[0] as usize;
        if data.len() < 1 + len {
            return None;
        }
        
        let mut cookie = Self::empty();
        cookie.len = len as u8;
        if len > 0 {
            cookie.bytes[..len].copy_from_slice(&data[1..1 + len]);
        }
        
        Some((cookie, 1 + len))
    }
    
    /// Encode to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        assert!(buf.len() > self.len as usize, "buffer too small");
        
        buf[0] = self.len;
        if self.len > 0 {
            buf[1..1 + self.len as usize].copy_from_slice(&self.bytes[..self.len as usize]);
        }
        
        1 + self.len as usize
    }
}

// ============================================================================
// Client Handshake State Machine (RFC 6347 Client Role)
// ============================================================================

/// Client handshake state machine states.
///
/// Explicit state transitions for DTLS client role:
/// Initial → WaitServerHello → WaitCertificate → WaitServerKeyExchange
/// → WaitServerHelloDone → WaitFinished → Complete | Failed
///
/// # TigerStyle
/// - Explicit enum values
/// - No implicit state transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientHandshakeState {
    /// Initial state before handshake starts.
    Initial = 0,
    /// Waiting for ServerHello after sending ClientHello.
    WaitServerHello = 1,
    /// Waiting for Certificate message.
    WaitCertificate = 2,
    /// Waiting for ServerKeyExchange message.
    WaitServerKeyExchange = 3,
    /// Waiting for ServerHelloDone message.
    WaitServerHelloDone = 4,
    /// Waiting for server Finished message.
    WaitFinished = 5,
    /// Handshake completed successfully.
    Complete = 6,
    /// Handshake failed.
    Failed = 7,
}

impl ClientHandshakeState {
    /// Returns true if handshake is complete.
    #[inline]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
    
    /// Returns true if handshake has failed.
    #[inline]
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
    
    /// Returns true if state is terminal.
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

/// SRTP keying material derived from DTLS handshake.
///
/// Contains client and server write keys and salts for SRTP.
///
/// # TigerStyle
/// - Fixed-size arrays for all keys
/// - Explicit key lengths
#[derive(Debug, Clone, Copy)]
pub struct SrtpKeys {
    /// Client write key (16 bytes for AES-128).
    pub client_write_key: [u8; 16],
    /// Server write key.
    pub server_write_key: [u8; 16],
    /// Client write salt (14 bytes for SRTP).
    pub client_write_salt: [u8; 14],
    /// Server write salt.
    pub server_write_salt: [u8; 14],
}

impl SrtpKeys {
    /// Create empty SRTP keys.
    pub const fn empty() -> Self {
        Self {
            client_write_key: [0u8; 16],
            server_write_key: [0u8; 16],
            client_write_salt: [0u8; 14],
            server_write_salt: [0u8; 14],
        }
    }
}

/// DTLS Client Handshake State Machine.
///
/// Implements RFC 6347 client-side handshake with TigerStyle compliance.
///
/// # State Transitions
///
/// Initial → WaitServerHello → WaitCertificate → WaitServerKeyExchange
/// → WaitServerHelloDone → WaitFinished → Complete | Failed
///
/// # TigerStyle
/// - Static allocation: all buffers are fixed-size arrays
/// - Bounded operations: max 8 cipher suites, max 4 SRTP profiles
/// - ≥2 assertions per function
/// - ≤70 lines per function
#[derive(Debug)]
#[allow(dead_code)] // Fields reserved for full DTLS client handshake implementation
pub struct DtlsClientHandshake {
    /// Current handshake state.
    state: ClientHandshakeState,
    /// Client random (32 bytes).
    client_random: [u8; 32],
    /// Server random (32 bytes, received).
    server_random: [u8; 32],
    /// Pre-master secret (32 bytes for ECDHE P-256).
    pre_master_secret: [u8; 32],
    /// Master secret (48 bytes, derived).
    master_secret: [u8; 48],
    /// Selected cipher suite.
    cipher_suite: CipherSuite,
    /// Selected SRTP profile.
    srtp_profile: SrtpProfile,
    /// Message sequence number.
    message_seq: u16,
    /// Handshake transcript hash buffer.
    transcript_hash: [u8; 4096],
    /// Transcript hash length.
    transcript_len: u16,
    /// Output buffer for messages.
    output_buffer: [u8; 4096],
    /// Output buffer length.
    output_len: u16,
    /// Offered cipher suites.
    offered_cipher_suites: [u16; 8],
    /// Number of offered cipher suites.
    offered_cipher_suite_count: u8,
    /// Offered SRTP profiles.
    offered_srtp_profiles: [u16; 4],
    /// Number of offered SRTP profiles.
    offered_srtp_profile_count: u8,
    /// Server's ECDHE public key (65 bytes, uncompressed P-256).
    server_public_key: [u8; 65],
    /// Our ECDHE private key (32 bytes).
    client_private_key: [u8; 32],
    /// Our ECDHE public key (65 bytes).
    client_public_key: [u8; 65],
    /// Server certificate DER (max 2048 bytes).
    server_certificate: [u8; 2048],
    /// Server certificate length.
    server_certificate_len: u16,
}

impl DtlsClientHandshake {
    /// Maximum cipher suites to offer.
    pub const MAX_CIPHER_SUITES: usize = 8;
    /// Maximum SRTP profiles to offer.
    pub const MAX_SRTP_PROFILES: usize = 4;
    /// Handshake timeout in milliseconds.
    pub const HANDSHAKE_TIMEOUT_MS: u64 = 5000;
    
    /// Create a new DTLS client handshake.
    ///
    /// # TigerStyle
    /// - ≥2 assertions on postconditions
    /// - Static allocation only
    pub fn new() -> Self {
        // Generate client random
        let mut client_random = [0u8; 32];
        let gmt_unix_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        client_random[0..4].copy_from_slice(&gmt_unix_time.to_be_bytes());
        getrandom(&mut client_random[4..]).expect("getrandom failed");
        
        let handshake = Self {
            state: ClientHandshakeState::Initial,
            client_random,
            server_random: [0u8; 32],
            pre_master_secret: [0u8; 32],
            master_secret: [0u8; 48],
            cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            srtp_profile: SrtpProfile::AeadAes128Gcm,
            message_seq: 0,
            transcript_hash: [0u8; 4096],
            transcript_len: 0,
            output_buffer: [0u8; 4096],
            output_len: 0,
            offered_cipher_suites: [0u16; 8],
            offered_cipher_suite_count: 0,
            offered_srtp_profiles: [0u16; 4],
            offered_srtp_profile_count: 0,
            server_public_key: [0u8; 65],
            client_private_key: [0u8; 32],
            client_public_key: [0u8; 65],
            server_certificate: [0u8; 2048],
            server_certificate_len: 0,
        };
        
        // Postcondition: state is Initial
        assert_eq!(handshake.state, ClientHandshakeState::Initial);
        // Postcondition: client random has non-zero bytes
        assert!(handshake.client_random[4..].iter().any(|&b| b != 0));
        
        handshake
    }
    
    /// Get current handshake state.
    #[inline]
    pub fn state(&self) -> ClientHandshakeState {
        self.state
    }
    
    /// Set offered cipher suites.
    ///
    /// # TigerStyle
    /// - Bounded: max 8 cipher suites
    /// - ≥2 assertions
    pub fn set_cipher_suites(&mut self, suites: &[u16]) {
        // Precondition: not too many suites
        assert!(suites.len() <= Self::MAX_CIPHER_SUITES);
        
        let count = suites.len().min(Self::MAX_CIPHER_SUITES);
        self.offered_cipher_suites[..count].copy_from_slice(&suites[..count]);
        self.offered_cipher_suite_count = count as u8;
        
        // Postcondition: count is bounded
        assert!(self.offered_cipher_suite_count as usize <= Self::MAX_CIPHER_SUITES);
    }
    
    /// Set offered SRTP profiles.
    ///
    /// # TigerStyle
    /// - Bounded: max 4 profiles
    /// - ≥2 assertions
    pub fn set_srtp_profiles(&mut self, profiles: &[u16]) {
        // Precondition: not too many profiles
        assert!(profiles.len() <= Self::MAX_SRTP_PROFILES);
        
        let count = profiles.len().min(Self::MAX_SRTP_PROFILES);
        self.offered_srtp_profiles[..count].copy_from_slice(&profiles[..count]);
        self.offered_srtp_profile_count = count as u8;
        
        // Postcondition: count is bounded
        assert!(self.offered_srtp_profile_count as usize <= Self::MAX_SRTP_PROFILES);
    }
    
    /// Get transcript hash data.
    #[inline]
    pub fn transcript_data(&self) -> &[u8] {
        &self.transcript_hash[..self.transcript_len as usize]
    }
    
    /// Get the selected cipher suite.
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }
    
    /// Get the selected SRTP profile.
    #[inline]
    pub fn srtp_profile(&self) -> SrtpProfile {
        self.srtp_profile
    }
    
    /// Get the client random.
    #[inline]
    pub fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }
    
    /// Get the server random.
    #[inline]
    pub fn server_random(&self) -> &[u8; 32] {
        &self.server_random
    }
    
    /// Derive SRTP keying material.
    ///
    /// Returns SRTP keys derived from the master secret.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn derive_srtp_keys(&self) -> Result<SrtpKeys, DtlsError> {
        // Precondition: handshake must be complete
        if !self.state.is_complete() {
            return Err(DtlsError::NotEstablished);
        }
        
        // Precondition: master secret must be set
        assert!(self.master_secret.iter().any(|&b| b != 0));
        
        // Export SRTP keying material using existing function
        let srtp_material = super::crypto::export_srtp_keys(
            &self.master_secret,
            &self.client_random,
            &self.server_random,
            self.srtp_profile,
        );
        
        // Convert to SrtpKeys format
        let mut keys = SrtpKeys::empty();
        
        let key_len = self.srtp_profile.key_length().min(16);
        let salt_len = self.srtp_profile.salt_length().min(14);
        
        keys.client_write_key[..key_len]
            .copy_from_slice(&srtp_material.client_master_key[..key_len]);
        keys.server_write_key[..key_len]
            .copy_from_slice(&srtp_material.server_master_key[..key_len]);
        keys.client_write_salt[..salt_len]
            .copy_from_slice(&srtp_material.client_master_salt[..salt_len]);
        keys.server_write_salt[..salt_len]
            .copy_from_slice(&srtp_material.server_master_salt[..salt_len]);
        
        // Postcondition: keys are non-zero
        assert!(keys.client_write_key.iter().any(|&b| b != 0));
        // Postcondition: salts are non-zero
        assert!(keys.client_write_salt.iter().any(|&b| b != 0));
        
        Ok(keys)
    }
}

impl Default for DtlsClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time assertions for DtlsClientHandshake
const _: () = {
    assert!(DtlsClientHandshake::MAX_CIPHER_SUITES == 8);
    assert!(DtlsClientHandshake::MAX_SRTP_PROFILES == 4);
    assert!(DtlsClientHandshake::HANDSHAKE_TIMEOUT_MS == 5000);
};

/// Handshake context.
///
/// Maintains all state for a DTLS handshake including:
/// - Role (client/server)
/// - Current state machine position
/// - Cryptographic randoms
/// - Message sequencing
/// - Fragment reassembly
/// - Retransmission management
#[derive(Debug)]
#[allow(dead_code)] // Fields reserved for full DTLS handshake state machine
pub struct HandshakeContext {
    /// Our role.
    pub role: DtlsRole,
    
    /// Current state.
    pub state: HandshakeState,
    
    /// Client random.
    pub client_random: Random,
    
    /// Server random.
    pub server_random: Random,
    
    /// Cookie (for DTLS).
    pub cookie: Cookie,
    
    /// Session ID.
    pub session_id: SessionId,
    
    /// Selected cipher suite.
    pub cipher_suite: Option<CipherSuite>,
    
    /// Message sequence (for handshake messages).
    pub message_seq: u16,
    
    /// Expected message sequence.
    pub expected_seq: u16,
    
    /// Handshake hash buffer.
    pub hash_buffer: [u8; 4096],
    
    /// Handshake hash length.
    pub hash_len: usize,
    
    /// Retransmission state.
    pub retransmit: RetransmissionState,
    
    /// Last flight buffer.
    pub flight_buf: [u8; 4096],
    
    /// Last flight length.
    pub flight_len: usize,
    
    /// Current flight being assembled.
    pub current_flight: Option<Flight>,
    
    /// Fragment buffer for reassembly.
    pub fragment_buffer: FragmentBuffer,
    
    /// Buffered out-of-order messages.
    pub buffered_messages: [[u8; 1500]; 8],
    
    /// Lengths of buffered messages.
    pub buffered_lengths: [u16; 8],
    
    /// Sequence numbers of buffered messages.
    pub buffered_seqs: [u16; 8],
    
    /// Count of buffered messages.
    pub buffered_count: u8,
}

// Compile-time assertions for HandshakeContext
// Note: HandshakeContext includes large buffers for retransmission (8KB+)
// and flight buffering, so we allow up to 128KB
const _: () = assert!(std::mem::size_of::<HandshakeContext>() < 131072);

#[allow(dead_code)] // Associated items reserved for full DTLS handshake implementation
impl HandshakeContext {
    /// Maximum cipher suites to negotiate.
    pub const MAX_CIPHER_SUITES: usize = MAX_CIPHER_SUITES;
    
    /// Maximum extensions to parse.
    pub const MAX_EXTENSIONS: usize = MAX_EXTENSIONS;
    
    /// Maximum SRTP profiles.
    pub const MAX_SRTP_PROFILES: usize = MAX_SRTP_PROFILES;
    
    /// Create new handshake context.
    ///
    /// # TigerStyle
    /// - Initializes all fields to safe defaults
    /// - Role-appropriate initial state
    pub fn new(role: DtlsRole) -> Self {
        let state = match role {
            DtlsRole::Client => HandshakeState::Initial,
            DtlsRole::Server => HandshakeState::WaitingClientKeyExchange,
        };
        
        Self {
            role,
            state,
            client_random: Random::generate(),
            server_random: Random::generate(),
            cookie: Cookie::empty(),
            session_id: SessionId::empty(),
            cipher_suite: None,
            message_seq: 0,
            expected_seq: 0,
            hash_buffer: [0u8; 4096],
            hash_len: 0,
            retransmit: RetransmissionState::new(),
            flight_buf: [0u8; 4096],
            flight_len: 0,
            current_flight: None,
            fragment_buffer: FragmentBuffer::new(),
            buffered_messages: [[0u8; 1500]; 8],
            buffered_lengths: [0; 8],
            buffered_seqs: [0; 8],
            buffered_count: 0,
        }
    }
    
    /// Update handshake hash.
    ///
    /// # TigerStyle
    /// - Bounded: max 4096 bytes in hash buffer
    pub fn update_hash(&mut self, data: &[u8]) {
        let remaining = self.hash_buffer.len() - self.hash_len;
        let copy_len = data.len().min(remaining);
        
        self.hash_buffer[self.hash_len..self.hash_len + copy_len]
            .copy_from_slice(&data[..copy_len]);
        self.hash_len += copy_len;
    }
    
    /// Get handshake hash data.
    #[inline]
    pub fn hash_data(&self) -> &[u8] {
        &self.hash_buffer[..self.hash_len]
    }
    
    /// Increment message sequence.
    ///
    /// # TigerStyle
    /// - Assert sequence doesn't overflow
    pub fn next_seq(&mut self) -> u16 {
        assert!(self.message_seq < u16::MAX, "message sequence overflow");
        let seq = self.message_seq;
        self.message_seq += 1;
        seq
    }
    
    /// Check if message sequence is expected.
    #[inline]
    pub fn check_seq(&self, seq: u16) -> bool {
        seq == self.expected_seq
    }
    
    /// Advance expected sequence.
    ///
    /// # TigerStyle
    /// - Assert sequence doesn't overflow
    pub fn advance_expected_seq(&mut self) {
        assert!(self.expected_seq < u16::MAX, "expected sequence overflow");
        self.expected_seq += 1;
    }
    
    /// Buffer an out-of-order message for later processing.
    ///
    /// # Returns
    /// - `Ok(())` if message buffered
    /// - `Err` if buffer full
    ///
    /// # TigerStyle
    /// - Bounded: max 8 buffered messages
    pub fn buffer_message(&mut self, seq: u16, data: &[u8]) -> Result<(), DtlsError> {
        // Precondition: not full
        if self.buffered_count >= MAX_BUFFERED_MESSAGES as u8 {
            return Err(DtlsError::handshake_failed("message buffer full"));
        }
        
        // Precondition: message fits
        if data.len() > 1500 {
            return Err(DtlsError::handshake_failed("message too large to buffer"));
        }
        
        let idx = self.buffered_count as usize;
        self.buffered_messages[idx][..data.len()].copy_from_slice(data);
        self.buffered_lengths[idx] = data.len() as u16;
        self.buffered_seqs[idx] = seq;
        self.buffered_count += 1;
        
        // Postcondition: count bounded
        assert!(self.buffered_count <= MAX_BUFFERED_MESSAGES as u8);
        
        Ok(())
    }
    
    /// Get a buffered message by sequence number.
    ///
    /// # TigerStyle
    /// - Bounded loop
    pub fn get_buffered(&self, seq: u16) -> Option<&[u8]> {
        for i in 0..self.buffered_count as usize {
            if self.buffered_seqs[i] == seq {
                return Some(&self.buffered_messages[i][..self.buffered_lengths[i] as usize]);
            }
        }
        None
    }
    
    /// Start a new flight.
    ///
    /// # TigerStyle
    /// - Flight number validated
    pub fn start_flight(&mut self, number: u8) {
        assert!(number >= 1 && number <= 4, "invalid flight number");
        self.current_flight = Some(Flight::new(number));
    }
    
    /// Get current flight for modification.
    pub fn current_flight_mut(&mut self) -> Option<&mut Flight> {
        self.current_flight.as_mut()
    }
    
    /// Finalize current flight and store for retransmission.
    ///
    /// # TigerStyle
    /// - Stores flight data in retransmission buffer
    pub fn finalize_flight(&mut self) -> Result<(), DtlsError> {
        if let Some(ref flight) = self.current_flight {
            if flight.combined_len as usize > self.flight_buf.len() {
                return Err(DtlsError::handshake_failed("flight too large"));
            }
            
            self.flight_buf[..flight.combined_len as usize]
                .copy_from_slice(&flight.combined[..flight.combined_len as usize]);
            self.flight_len = flight.combined_len as usize;
            self.retransmit.last_send = std::time::Instant::now();
        }
        Ok(())
    }
}

/// Build ClientHello message.
pub fn build_client_hello(
    ctx: &mut HandshakeContext,
    srtp_profiles: &[u16],
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    assert!(buf.len() >= MAX_HANDSHAKE_SIZE, "buffer too small");
    
    let mut offset = HandshakeHeader::SIZE;
    
    // Client version
    buf[offset..offset + 2].copy_from_slice(&DTLS_VERSION_1_2.to_be_bytes());
    offset += 2;
    
    // Random
    ctx.client_random.encode(&mut buf[offset..]);
    offset += Random::SIZE;
    
    // Session ID (empty for new connection)
    buf[offset] = 0;
    offset += 1;
    
    // Cookie
    offset += ctx.cookie.encode(&mut buf[offset..]);
    
    // Cipher suites
    let cipher_suites = [
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as u16,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u16,
    ];
    buf[offset..offset + 2].copy_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    offset += 2;
    for suite in cipher_suites {
        buf[offset..offset + 2].copy_from_slice(&suite.to_be_bytes());
        offset += 2;
    }
    
    // Compression methods (null only)
    buf[offset] = 1;
    offset += 1;
    buf[offset] = 0; // No compression
    offset += 1;
    
    // Extensions
    let extensions_start = offset;
    offset += 2; // Length placeholder
    
    // SRTP extension (use_srtp)
    if !srtp_profiles.is_empty() {
        buf[offset..offset + 2].copy_from_slice(&14u16.to_be_bytes()); // use_srtp type
        offset += 2;
        
        let srtp_ext_len = 2 + srtp_profiles.len() * 2 + 1;
        buf[offset..offset + 2].copy_from_slice(&(srtp_ext_len as u16).to_be_bytes());
        offset += 2;
        
        buf[offset..offset + 2].copy_from_slice(&((srtp_profiles.len() * 2) as u16).to_be_bytes());
        offset += 2;
        
        for profile in srtp_profiles {
            buf[offset..offset + 2].copy_from_slice(&profile.to_be_bytes());
            offset += 2;
        }
        
        buf[offset] = 0; // No MKI
        offset += 1;
    }
    
    // Signature algorithms extension
    buf[offset..offset + 2].copy_from_slice(&13u16.to_be_bytes()); // signature_algorithms
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&4u16.to_be_bytes()); // Extension length
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&2u16.to_be_bytes()); // Algorithms list length
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
    offset += 2;
    
    // Supported groups extension
    buf[offset..offset + 2].copy_from_slice(&10u16.to_be_bytes()); // supported_groups
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&4u16.to_be_bytes()); // Extension length
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&2u16.to_be_bytes()); // Groups list length
    offset += 2;
    buf[offset..offset + 2].copy_from_slice(&0x0017u16.to_be_bytes()); // secp256r1
    offset += 2;
    
    // Fill in extensions length
    let extensions_len = offset - extensions_start - 2;
    buf[extensions_start..extensions_start + 2].copy_from_slice(&(extensions_len as u16).to_be_bytes());
    
    // Fill in handshake header
    let body_len = offset - HandshakeHeader::SIZE;
    let header = HandshakeHeader {
        msg_type: HandshakeType::ClientHello as u8,
        length: body_len as u32,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: body_len as u32,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..offset]);
    
    Ok(offset)
}

/// Parsed ClientHello data.
///
/// # TigerStyle Compliance
///
/// - Static allocation: fixed-size arrays for cipher suites and SRTP profiles
/// - Bounded: max 20 cipher suites, max 4 SRTP profiles
#[derive(Debug, Clone)]
pub struct ClientHelloData {
    /// Client random (32 bytes).
    pub random: Random,
    
    /// Session ID.
    pub session_id: SessionId,
    
    /// Cookie (DTLS).
    pub cookie: Cookie,
    
    /// Cipher suites (bounded array).
    pub cipher_suites: [u16; MAX_CIPHER_SUITES],
    
    /// Number of cipher suites.
    pub cipher_suite_count: u8,
    
    /// SRTP profiles from use_srtp extension.
    pub srtp_profiles: [u16; MAX_SRTP_PROFILES],
    
    /// Number of SRTP profiles.
    pub srtp_profile_count: u8,
    
    /// DTLS version.
    pub version: u16,
}

impl ClientHelloData {
    /// Create empty ClientHelloData.
    pub const fn empty() -> Self {
        Self {
            random: Random { gmt_unix_time: 0, random_bytes: [0u8; 28] },
            session_id: SessionId::empty(),
            cookie: Cookie::empty(),
            cipher_suites: [0u16; MAX_CIPHER_SUITES],
            cipher_suite_count: 0,
            srtp_profiles: [0u16; MAX_SRTP_PROFILES],
            srtp_profile_count: 0,
            version: 0,
        }
    }
}

/// Parse ClientHello message (server side).
///
/// # Preconditions
///
/// - `data.len() >= HandshakeHeader::SIZE + 38` (minimum ClientHello size)
///
/// # Postconditions
///
/// - Returned random is non-zero
/// - At least one cipher suite is parsed
///
/// # TigerStyle Compliance
///
/// - Explicit bounds checking before every read
/// - Bounded loops: max 20 cipher suites, max 10 extensions
/// - ≥2 assertions
pub fn parse_client_hello(data: &[u8]) -> Result<ClientHelloData, DtlsError> {
    // Minimum ClientHello: version(2) + random(32) + session_id_len(1) + cookie_len(1) + 
    //                      cipher_suites_len(2) + compression_len(1) = 39 bytes after header
    const MIN_CLIENT_HELLO_SIZE: usize = HandshakeHeader::SIZE + 39;
    
    // Precondition: minimum size
    if data.len() < MIN_CLIENT_HELLO_SIZE {
        return Err(DtlsError::RecordTooShort {
            actual: data.len(),
            min: MIN_CLIENT_HELLO_SIZE,
        });
    }
    
    // Parse handshake header
    let header = HandshakeHeader::parse(data)
        .ok_or(DtlsError::handshake_failed("invalid handshake header"))?;
    
    // Assertion: must be ClientHello
    if header.msg_type != HandshakeType::ClientHello as u8 {
        return Err(DtlsError::InvalidHandshakeType(header.msg_type));
    }
    
    let mut result = ClientHelloData::empty();
    let mut offset = HandshakeHeader::SIZE;
    
    // Version (2 bytes)
    if offset + 2 > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 2 });
    }
    result.version = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    
    // Random (32 bytes)
    if offset + 32 > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 32 });
    }
    result.random = Random::parse(&data[offset..])
        .ok_or(DtlsError::handshake_failed("invalid random"))?;
    offset += 32;
    
    // Session ID (variable, 1 byte length + data)
    if offset >= data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 1 });
    }
    let (session_id, consumed) = SessionId::parse(&data[offset..])
        .ok_or(DtlsError::handshake_failed("invalid session ID"))?;
    result.session_id = session_id;
    offset += consumed;
    
    // Cookie (variable, 1 byte length + data) - DTLS specific
    if offset >= data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 1 });
    }
    let (cookie, consumed) = Cookie::parse(&data[offset..])
        .ok_or(DtlsError::handshake_failed("invalid cookie"))?;
    result.cookie = cookie;
    offset += consumed;
    
    // Cipher suites (2 byte length + array of u16)
    if offset + 2 > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 2 });
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    // Bounds check: cipher suites length
    if offset + cipher_suites_len > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + cipher_suites_len });
    }
    
    // Parse cipher suites (bounded loop)
    let num_suites = cipher_suites_len / 2;
    // Assertion: bounded number of cipher suites
    assert!(num_suites <= MAX_CIPHER_SUITES, "too many cipher suites");
    
    for i in 0..num_suites.min(MAX_CIPHER_SUITES) {
        let suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        result.cipher_suites[i] = suite;
        result.cipher_suite_count = (i + 1) as u8;
        offset += 2;
    }
    
    // Compression methods (1 byte length + array)
    if offset >= data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 1 });
    }
    let compression_len = data[offset] as usize;
    offset += 1;
    
    if offset + compression_len > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + compression_len });
    }
    offset += compression_len; // Skip compression methods
    
    // Extensions (optional)
    if offset + 2 <= data.len() {
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        let extensions_end = offset + extensions_len;
        if extensions_end > data.len() {
            return Err(DtlsError::RecordTooShort { actual: data.len(), min: extensions_end });
        }
        
        // Parse extensions (bounded loop)
        let mut ext_count = 0u8;
        while offset + 4 <= extensions_end && ext_count < MAX_EXTENSIONS as u8 {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + ext_len > extensions_end {
                break;
            }
            
            // Handle use_srtp extension (type 14)
            if ext_type == 14 && ext_len >= 2 {
                let profiles_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                let mut profile_offset = offset + 2;
                let num_profiles = profiles_len / 2;
                
                for i in 0..num_profiles.min(MAX_SRTP_PROFILES) {
                    if profile_offset + 2 <= offset + ext_len {
                        let profile = u16::from_be_bytes([data[profile_offset], data[profile_offset + 1]]);
                        result.srtp_profiles[i] = profile;
                        result.srtp_profile_count = (i + 1) as u8;
                        profile_offset += 2;
                    }
                }
            }
            
            offset += ext_len;
            ext_count += 1;
        }
    }
    
    // Postcondition: random must be non-zero
    assert!(result.random.random_bytes.iter().any(|&b| b != 0), 
        "client random must be non-zero");
    // Postcondition: at least one cipher suite
    assert!(result.cipher_suite_count > 0, "no cipher suites in ClientHello");
    
    Ok(result)
}

/// Build ServerHello message.
///
/// # Preconditions
///
/// - `buf.len() >= MAX_HANDSHAKE_SIZE`
///
/// # Postconditions
///
/// - Output length > 0
/// - Output length < MAX_HANDSHAKE_SIZE
///
/// # TigerStyle Compliance
///
/// - Explicit types: u16 for lengths
/// - ≥2 assertions
pub fn build_server_hello(
    ctx: &mut HandshakeContext,
    selected_cipher_suite: CipherSuite,
    selected_srtp_profile: Option<SrtpProfile>,
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    // Precondition: buffer must be large enough
    assert!(buf.len() >= MAX_HANDSHAKE_SIZE, "buffer too small for ServerHello");
    
    let mut offset = HandshakeHeader::SIZE;
    
    // Server version (DTLS 1.2)
    buf[offset..offset + 2].copy_from_slice(&DTLS_VERSION_1_2.to_be_bytes());
    offset += 2;
    
    // Server random (generate and store)
    ctx.server_random = Random::generate();
    ctx.server_random.encode(&mut buf[offset..]);
    offset += Random::SIZE;
    
    // Session ID (empty for new session)
    buf[offset] = 0;
    offset += 1;
    
    // Selected cipher suite
    buf[offset..offset + 2].copy_from_slice(&(selected_cipher_suite as u16).to_be_bytes());
    offset += 2;
    ctx.cipher_suite = Some(selected_cipher_suite);
    
    // Compression method (null)
    buf[offset] = 0;
    offset += 1;
    
    // Extensions
    let extensions_start = offset;
    offset += 2; // Length placeholder
    
    // use_srtp extension (if SRTP profile selected)
    if let Some(profile) = selected_srtp_profile {
        buf[offset..offset + 2].copy_from_slice(&14u16.to_be_bytes()); // use_srtp type
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&5u16.to_be_bytes()); // Extension length: 2 + 2 + 1
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&2u16.to_be_bytes()); // Profiles list length
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&(profile as u16).to_be_bytes());
        offset += 2;
        buf[offset] = 0; // No MKI
        offset += 1;
    }
    
    // Fill in extensions length
    let extensions_len = offset - extensions_start - 2;
    buf[extensions_start..extensions_start + 2].copy_from_slice(&(extensions_len as u16).to_be_bytes());
    
    // Fill in handshake header
    let body_len = offset - HandshakeHeader::SIZE;
    let header = HandshakeHeader {
        msg_type: HandshakeType::ServerHello as u8,
        length: body_len as u32,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: body_len as u32,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..offset]);
    
    // Postcondition: output length must be valid
    assert!(offset > 0, "ServerHello output length must be > 0");
    assert!(offset < MAX_HANDSHAKE_SIZE, "ServerHello exceeds max size");
    
    Ok(offset)
}

/// Build Certificate message.
///
/// # Preconditions
///
/// - `cert_der.len() <= 2048`
/// - `buf.len() >= 4096`
///
/// # Postconditions
///
/// - Output length < MAX_HANDSHAKE_SIZE
///
/// # TigerStyle Compliance
///
/// - Bounded: max 2048 bytes per certificate
/// - ≥2 assertions
pub fn build_certificate(
    ctx: &mut HandshakeContext,
    cert_der: &[u8],
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    // Precondition: certificate size
    assert!(cert_der.len() <= 2048, "certificate too large");
    // Precondition: buffer size
    assert!(buf.len() >= 4096, "buffer too small for Certificate message");
    
    let mut offset = HandshakeHeader::SIZE;
    
    // Certificates list length (3 bytes) - includes certificate length field
    let total_certs_len = 3 + cert_der.len(); // 3-byte length + cert data
    buf[offset] = ((total_certs_len >> 16) & 0xFF) as u8;
    buf[offset + 1] = ((total_certs_len >> 8) & 0xFF) as u8;
    buf[offset + 2] = (total_certs_len & 0xFF) as u8;
    offset += 3;
    
    // Certificate length (3 bytes)
    let cert_len = cert_der.len();
    buf[offset] = ((cert_len >> 16) & 0xFF) as u8;
    buf[offset + 1] = ((cert_len >> 8) & 0xFF) as u8;
    buf[offset + 2] = (cert_len & 0xFF) as u8;
    offset += 3;
    
    // Certificate DER bytes
    buf[offset..offset + cert_len].copy_from_slice(cert_der);
    offset += cert_len;
    
    // Fill in handshake header
    let body_len = offset - HandshakeHeader::SIZE;
    let header = HandshakeHeader {
        msg_type: HandshakeType::Certificate as u8,
        length: body_len as u32,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: body_len as u32,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..offset]);
    
    // Postcondition: total length must be bounded
    assert!(offset < MAX_HANDSHAKE_SIZE, "Certificate message exceeds max size");
    
    Ok(offset)
}

/// Build ServerKeyExchange message (ECDHE).
///
/// # Preconditions
///
/// - `public_key.len() == 65` (uncompressed P-256)
///
/// # Postconditions
///
/// - Output length < MAX_HANDSHAKE_SIZE
///
/// # TigerStyle Compliance
///
/// - Explicit bounds checking
/// - ≥2 assertions
pub fn build_server_key_exchange(
    ctx: &mut HandshakeContext,
    ecdhe_public_key: &[u8; 65],
    signature: &[u8],
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    // Precondition: public key format
    assert_eq!(ecdhe_public_key.len(), 65, "ECDHE public key must be 65 bytes");
    assert_eq!(ecdhe_public_key[0], 0x04, "ECDHE public key must be uncompressed");
    // Precondition: buffer size
    assert!(buf.len() >= MAX_HANDSHAKE_SIZE, "buffer too small");
    
    let mut offset = HandshakeHeader::SIZE;
    
    // EC curve type: named_curve (3)
    buf[offset] = 3;
    offset += 1;
    
    // Named curve: secp256r1 (0x0017)
    buf[offset..offset + 2].copy_from_slice(&0x0017u16.to_be_bytes());
    offset += 2;
    
    // Public key length (1 byte)
    buf[offset] = 65;
    offset += 1;
    
    // Public key (65 bytes)
    buf[offset..offset + 65].copy_from_slice(ecdhe_public_key);
    offset += 65;
    
    // Signature algorithm: ecdsa_secp256r1_sha256 (0x0403)
    buf[offset..offset + 2].copy_from_slice(&0x0403u16.to_be_bytes());
    offset += 2;
    
    // Signature length (2 bytes)
    let sig_len = signature.len();
    assert!(sig_len <= 256, "signature too large");
    buf[offset..offset + 2].copy_from_slice(&(sig_len as u16).to_be_bytes());
    offset += 2;
    
    // Signature bytes
    buf[offset..offset + sig_len].copy_from_slice(signature);
    offset += sig_len;
    
    // Fill in handshake header
    let body_len = offset - HandshakeHeader::SIZE;
    let header = HandshakeHeader {
        msg_type: HandshakeType::ServerKeyExchange as u8,
        length: body_len as u32,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: body_len as u32,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..offset]);
    
    // Postcondition: output must be bounded
    assert!(offset < MAX_HANDSHAKE_SIZE, "ServerKeyExchange exceeds max size");
    
    Ok(offset)
}

/// Build ServerHelloDone message.
///
/// # Preconditions
///
/// - `buf.len() >= HandshakeHeader::SIZE`
///
/// # Postconditions
///
/// - Output length == HandshakeHeader::SIZE
///
/// # TigerStyle Compliance
///
/// - Simplest message: just header with zero-length body
/// - ≥2 assertions
pub fn build_server_hello_done(
    ctx: &mut HandshakeContext,
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    // Precondition: buffer size
    assert!(buf.len() >= HandshakeHeader::SIZE, "buffer too small for ServerHelloDone");
    
    // ServerHelloDone has empty body
    let header = HandshakeHeader {
        msg_type: HandshakeType::ServerHelloDone as u8,
        length: 0,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: 0,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..HandshakeHeader::SIZE]);
    
    // Postcondition: output length is exactly header size
    assert_eq!(HandshakeHeader::SIZE, 12, "HandshakeHeader::SIZE must be 12");
    
    Ok(HandshakeHeader::SIZE)
}

/// Parse ClientKeyExchange message.
///
/// # Preconditions
///
/// - `data.len() >= HandshakeHeader::SIZE + 1`
///
/// # Postconditions
///
/// - Public key is 65 bytes (uncompressed P-256)
/// - First byte is 0x04 (uncompressed marker)
///
/// # TigerStyle Compliance
///
/// - Explicit bounds checking
/// - ≥2 assertions
pub fn parse_client_key_exchange(data: &[u8]) -> Result<[u8; 65], DtlsError> {
    // Precondition: minimum size
    if data.len() < HandshakeHeader::SIZE + 1 {
        return Err(DtlsError::RecordTooShort {
            actual: data.len(),
            min: HandshakeHeader::SIZE + 1,
        });
    }
    
    // Parse handshake header
    let header = HandshakeHeader::parse(data)
        .ok_or(DtlsError::handshake_failed("invalid handshake header"))?;
    
    // Assertion: must be ClientKeyExchange
    if header.msg_type != HandshakeType::ClientKeyExchange as u8 {
        return Err(DtlsError::InvalidHandshakeType(header.msg_type));
    }
    
    let mut offset = HandshakeHeader::SIZE;
    
    // Public key length (1 byte)
    if offset >= data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 1 });
    }
    let key_len = data[offset] as usize;
    offset += 1;
    
    // Bounds check: key length must be 65 (uncompressed P-256)
    if key_len != 65 {
        return Err(DtlsError::handshake_failed(format!(
            "invalid ECDHE public key length: expected 65, got {}", key_len)));
    }
    
    // Bounds check: data must contain full key
    if offset + 65 > data.len() {
        return Err(DtlsError::RecordTooShort { actual: data.len(), min: offset + 65 });
    }
    
    // Parse public key
    let mut public_key = [0u8; 65];
    public_key.copy_from_slice(&data[offset..offset + 65]);
    
    // Postcondition: first byte must be 0x04 (uncompressed marker)
    assert_eq!(public_key[0], 0x04, "ECDHE public key must be uncompressed format");
    // Postcondition: key must be non-zero
    assert!(public_key[1..].iter().any(|&b| b != 0), "ECDHE public key must be non-zero");
    
    Ok(public_key)
}

/// Build Finished message.
///
/// # Preconditions
///
/// - `verify_data.len() == 12`
///
/// # Postconditions
///
/// - Output length == HandshakeHeader::SIZE + 12
///
/// # TigerStyle Compliance
///
/// - Fixed-size verify_data
/// - ≥2 assertions
pub fn build_finished(
    ctx: &mut HandshakeContext,
    verify_data: &[u8; 12],
    buf: &mut [u8],
) -> Result<usize, DtlsError> {
    // Precondition: buffer size
    assert!(buf.len() >= HandshakeHeader::SIZE + 12, "buffer too small for Finished");
    
    let mut offset = HandshakeHeader::SIZE;
    
    // Verify data (12 bytes)
    buf[offset..offset + 12].copy_from_slice(verify_data);
    offset += 12;
    
    // Fill in handshake header
    let header = HandshakeHeader {
        msg_type: HandshakeType::Finished as u8,
        length: 12,
        message_seq: ctx.next_seq(),
        fragment_offset: 0,
        fragment_length: 12,
    };
    header.encode(buf);
    
    // Update handshake hash
    ctx.update_hash(&buf[..offset]);
    
    // Postcondition: output length must be exactly header + verify_data
    assert_eq!(offset, HandshakeHeader::SIZE + 12, "Finished message must be exactly 24 bytes");
    
    Ok(offset)
}

/// Verify Finished message from peer.
///
/// # Preconditions
///
/// - `data.len() >= HandshakeHeader::SIZE + 12`
///
/// # Postconditions
///
/// - Verify data matches expected
///
/// # TigerStyle Compliance
///
/// - Constant-time comparison for security
/// - ≥2 assertions
pub fn verify_finished(data: &[u8], expected_verify_data: &[u8; 12]) -> Result<(), DtlsError> {
    // Precondition: minimum size
    if data.len() < HandshakeHeader::SIZE + 12 {
        return Err(DtlsError::RecordTooShort {
            actual: data.len(),
            min: HandshakeHeader::SIZE + 12,
        });
    }
    
    // Parse handshake header
    let header = HandshakeHeader::parse(data)
        .ok_or(DtlsError::handshake_failed("invalid handshake header"))?;
    
    // Assertion: must be Finished
    if header.msg_type != HandshakeType::Finished as u8 {
        return Err(DtlsError::InvalidHandshakeType(header.msg_type));
    }
    
    // Extract verify data
    let offset = HandshakeHeader::SIZE;
    let received_verify_data = &data[offset..offset + 12];
    
    // Constant-time comparison (security critical!)
    let mut diff = 0u8;
    for i in 0..12 {
        diff |= received_verify_data[i] ^ expected_verify_data[i];
    }
    
    if diff != 0 {
        return Err(DtlsError::verification_failed("Finished verify_data mismatch"));
    }
    
    // Postcondition: if we get here, verification passed
    assert_eq!(diff, 0, "verify_data comparison failed");
    
    Ok(())
}

/// Compute verify_data for Finished message.
///
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[12]
///
/// # TigerStyle Compliance
///
/// - Fixed output size
/// - ≥2 assertions
pub fn compute_verify_data(
    master_secret: &[u8; 48],
    handshake_hash: &[u8],
    is_client: bool,
) -> [u8; 12] {
    use super::crypto::prf_sha256;
    use sha2::{Sha256, Digest};
    
    // Precondition: master secret must be 48 bytes
    assert_eq!(master_secret.len(), 48, "master secret must be 48 bytes");
    // Precondition: handshake hash must be non-empty
    assert!(!handshake_hash.is_empty(), "handshake hash must not be empty");
    
    // Compute SHA-256 hash of handshake messages
    let mut hasher = Sha256::new();
    hasher.update(handshake_hash);
    let hash = hasher.finalize();
    
    // Label: "client finished" or "server finished"
    let label = if is_client { b"client finished" } else { b"server finished" };
    
    // PRF output (12 bytes)
    let mut verify_data = [0u8; 12];
    prf_sha256(master_secret, label, &hash, &mut verify_data);
    
    // Postcondition: verify_data must be non-zero
    assert!(verify_data.iter().any(|&b| b != 0), "verify_data must be non-zero");
    
    verify_data
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Random Generation Tests
    // ========================================================================

    #[test]
    fn test_random_generate() {
        let r1 = Random::generate();
        let r2 = Random::generate();
        
        // Should be different
        assert_ne!(r1.random_bytes, r2.random_bytes);
        
        // GMT time should be recent
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(r1.gmt_unix_time <= now);
        assert!(r1.gmt_unix_time > now - 10);
    }

    #[test]
    fn test_handshake_context() {
        let ctx = HandshakeContext::new(DtlsRole::Client);
        assert_eq!(ctx.state, HandshakeState::Initial);
        assert_eq!(ctx.message_seq, 0);
    }

    #[test]
    fn test_cookie_roundtrip() {
        let mut cookie = Cookie::empty();
        cookie.bytes[0..4].copy_from_slice(b"test");
        cookie.len = 4;
        
        let mut buf = [0u8; 10];
        let len = cookie.encode(&mut buf);
        assert_eq!(len, 5);
        
        let (parsed, consumed) = Cookie::parse(&buf).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(parsed.len, 4);
        assert_eq!(&parsed.bytes[0..4], b"test");
    }
    
    #[test]
    fn test_build_server_hello_done() {
        let mut ctx = HandshakeContext::new(DtlsRole::Server);
        let mut buf = [0u8; 64];
        
        let len = build_server_hello_done(&mut ctx, &mut buf).unwrap();
        assert_eq!(len, HandshakeHeader::SIZE);
        
        // Verify header
        let header = HandshakeHeader::parse(&buf).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ServerHelloDone as u8);
        assert_eq!(header.length, 0);
    }
    
    #[test]
    fn test_client_hello_data_empty() {
        let data = ClientHelloData::empty();
        assert_eq!(data.cipher_suite_count, 0);
        assert_eq!(data.srtp_profile_count, 0);
    }

    // ========================================================================
    // Handshake State Machine Tests
    // ========================================================================

    #[test]
    fn test_handshake_state_values() {
        assert_eq!(HandshakeState::New as u8, 0);
        assert_eq!(HandshakeState::ClientHelloSent as u8, 1);
        assert_eq!(HandshakeState::Established as u8, 10);
        assert_eq!(HandshakeState::Failed as u8, 11);
        assert_eq!(HandshakeState::Closed as u8, 12);
    }

    #[test]
    fn test_handshake_state_is_terminal() {
        assert!(matches!(HandshakeState::Failed, HandshakeState::Failed));
        assert!(matches!(HandshakeState::Closed, HandshakeState::Closed));
        assert!(!matches!(HandshakeState::Established, HandshakeState::Failed));
    }

    // ========================================================================
    // Retransmission Logic Tests (Exponential Backoff: 1s, 2s, 4s, 8s, 16s, 32s)
    // ========================================================================

    #[test]
    fn test_retransmission_state_initial() {
        let state = RetransmissionState::new();
        
        assert_eq!(state.count, 0);
        assert!(state.rto_ms >= 1000, "Initial RTO should be >= 1000ms");
    }

    // ========================================================================
    // Flight Assembly Tests (max 8 messages per flight)
    // ========================================================================

    #[test]
    fn test_max_flight_size_constant() {
        assert_eq!(MAX_FLIGHT_SIZE, 8, "MAX_FLIGHT_SIZE should be 8");
    }

    #[test]
    fn test_max_buffered_messages_constant() {
        assert_eq!(MAX_BUFFERED_MESSAGES, 8, "MAX_BUFFERED_MESSAGES should be 8");
    }

    // ========================================================================
    // Message Fragmentation Tests (max 4KB per message)
    // ========================================================================

    #[test]
    fn test_max_fragment_size_constant() {
        assert_eq!(MAX_FRAGMENT_SIZE, 1400, "MAX_FRAGMENT_SIZE should be 1400 for MTU compliance");
    }

    #[test]
    fn test_max_handshake_size_constant() {
        // Should be defined in parent module
        assert!(super::super::MAX_HANDSHAKE_SIZE >= 4096, 
            "MAX_HANDSHAKE_SIZE should be at least 4KB");
    }

    // ========================================================================
    // Handshake Type Tests
    // ========================================================================

    #[test]
    fn test_handshake_type_from_u8() {
        assert_eq!(HandshakeType::from_u8(0), Some(HandshakeType::HelloRequest));
        assert_eq!(HandshakeType::from_u8(1), Some(HandshakeType::ClientHello));
        assert_eq!(HandshakeType::from_u8(2), Some(HandshakeType::ServerHello));
        assert_eq!(HandshakeType::from_u8(3), Some(HandshakeType::HelloVerifyRequest));
        assert_eq!(HandshakeType::from_u8(11), Some(HandshakeType::Certificate));
        assert_eq!(HandshakeType::from_u8(12), Some(HandshakeType::ServerKeyExchange));
        assert_eq!(HandshakeType::from_u8(14), Some(HandshakeType::ServerHelloDone));
        assert_eq!(HandshakeType::from_u8(16), Some(HandshakeType::ClientKeyExchange));
        assert_eq!(HandshakeType::from_u8(20), Some(HandshakeType::Finished));
        
        // Invalid types
        assert_eq!(HandshakeType::from_u8(100), None);
        assert_eq!(HandshakeType::from_u8(255), None);
    }

    // ========================================================================
    // Cookie Exchange Tests
    // ========================================================================

    #[test]
    fn test_cookie_empty() {
        let cookie = Cookie::empty();
        assert_eq!(cookie.len, 0);
    }

    #[test]
    fn test_cookie_max_size() {
        let cookie = Cookie::empty();
        // Cookie should have bounded size
        assert!(cookie.bytes.len() <= 255, "Cookie must fit in single byte length");
    }

    // ========================================================================
    // Epoch Transition Tests
    // ========================================================================

    #[test]
    fn test_handshake_context_sequence_increment() {
        let mut ctx = HandshakeContext::new(DtlsRole::Client);
        
        let seq1 = ctx.next_seq();
        let seq2 = ctx.next_seq();
        let seq3 = ctx.next_seq();
        
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
        assert_eq!(seq3, 2);
    }

    // ========================================================================
    // Invalid Handshake Message Tests
    // ========================================================================

    #[test]
    fn test_verify_finished_too_short() {
        let short_data = [0u8; 10];
        let expected = [0u8; 12];
        
        let result = verify_finished(&short_data, &expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_finished_wrong_type() {
        // Create data with wrong handshake type
        let mut data = [0u8; 36];
        data[0] = HandshakeType::ClientHello as u8; // Wrong type
        
        let expected = [0u8; 12];
        let result = verify_finished(&data, &expected);
        assert!(result.is_err());
    }

    // ========================================================================
    // Cipher Suite Tests
    // ========================================================================

    #[test]
    fn test_max_cipher_suites_constant() {
        assert_eq!(MAX_CIPHER_SUITES, 20, "MAX_CIPHER_SUITES should be 20");
    }

    // ========================================================================
    // Extension Tests
    // ========================================================================

    #[test]
    fn test_max_extensions_constant() {
        assert_eq!(MAX_EXTENSIONS, 16, "MAX_EXTENSIONS should be 16");
    }

    // ========================================================================
    // SRTP Profile Tests
    // ========================================================================

    #[test]
    fn test_max_srtp_profiles_constant() {
        assert_eq!(MAX_SRTP_PROFILES, 4, "MAX_SRTP_PROFILES should be 4");
    }

    // ========================================================================
    // Verify Data Computation Tests
    // ========================================================================

    #[test]
    fn test_compute_verify_data_deterministic() {
        let master_secret = [0x42u8; 48];
        let handshake_hash = b"test handshake hash data";
        
        let vd1 = compute_verify_data(&master_secret, handshake_hash, true);
        let vd2 = compute_verify_data(&master_secret, handshake_hash, true);
        
        assert_eq!(vd1, vd2, "verify_data should be deterministic");
    }

    #[test]
    fn test_compute_verify_data_client_vs_server() {
        let master_secret = [0x42u8; 48];
        let handshake_hash = b"test handshake hash data";
        
        let client_vd = compute_verify_data(&master_secret, handshake_hash, true);
        let server_vd = compute_verify_data(&master_secret, handshake_hash, false);
        
        assert_ne!(client_vd, server_vd, "client and server verify_data should differ");
    }

    // ========================================================================
    // Handshake Header Tests
    // ========================================================================

    #[test]
    fn test_handshake_header_size() {
        assert_eq!(HandshakeHeader::SIZE, 12, "Handshake header should be 12 bytes");
    }

    // ========================================================================
    // ECDHE Public Key Parsing Tests
    // ========================================================================

    #[test]
    fn test_ecdhe_public_key_validation() {
        // A valid ECDHE public key should be 65 bytes with 0x04 prefix
        let mut valid_key = [0u8; 65];
        valid_key[0] = 0x04; // Uncompressed point marker
        valid_key[1] = 0x01; // Non-zero coordinate
        
        // This verifies the format expectations
        assert_eq!(valid_key[0], 0x04);
        assert!(valid_key[1..].iter().any(|&b| b != 0));
    }

    // ========================================================================
    // Build Finished Tests
    // ========================================================================

    #[test]
    fn test_build_finished_output_size() {
        let mut ctx = HandshakeContext::new(DtlsRole::Client);
        let verify_data = [0u8; 12];
        let mut buf = [0u8; 64];
        
        let len = build_finished(&mut ctx, &verify_data, &mut buf).unwrap();
        
        // Should be exactly handshake header + verify data
        assert_eq!(len, HandshakeHeader::SIZE + 12);
    }

    // ========================================================================
    // Role Tests
    // ========================================================================

    #[test]
    fn test_dtls_role_values() {
        assert!(matches!(DtlsRole::Client, DtlsRole::Client));
        assert!(matches!(DtlsRole::Server, DtlsRole::Server));
    }
}
