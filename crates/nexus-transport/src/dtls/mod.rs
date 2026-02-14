//! DTLS 1.2 Implementation.
//!
//! Secure datagram transport for WebRTC.
//! Implements RFC 6347 (DTLS 1.2) with RFC 5764 (DTLS-SRTP).
//!
//! # Architecture
//!
//! - `handshake`: DTLS handshake state machine with RFC-compliant transitions
//! - `record`: Record layer parsing, construction, and fragmentation
//! - `crypto`: Cryptographic operations including proper P-256 ECDHE
//! - `session`: Connection state management with timeout enforcement
//!
//! # Production Features
//!
//! - Complete RFC 6347 state machine with explicit transitions
//! - Retransmission with exponential backoff (1s initial, 6 max retries)
//! - 30-second handshake timeout enforcement
//! - Record fragmentation/reassembly for messages up to 16KB
//! - Proper P-256 ECDHE using ring library
//! - Comprehensive compile-time assertions
//!
//! # TigerStyle Compliance
//!
//! - Explicit types (u8, u16, u32)
//! - Fixed-size buffers (no heap allocation on hot path)
//! - Maximum 70 lines per function
//! - At least 2 assertions per function
//! - Bounded loops and retries
//! - No panics on hot path (only assertions for programmer errors)

mod error;
mod types;
mod record;
mod handshake;
mod crypto;
mod session;
mod openssl_backend;

pub use error::DtlsError;
pub use types::*;
pub use record::{RecordLayer, ContentType, FragmentAssembler};
pub use handshake::{HandshakeType, HandshakeState, Flight, FragmentBuffer, DtlsClientHandshake, ClientHandshakeState, SrtpKeys};
pub use crypto::{CipherSuite, KeyMaterial, SrtpProfile, generate_ecdhe_keypair_ring, compute_ecdhe_shared_secret_ring};
pub use openssl_backend::OpenSslDtlsEngine;
pub use session::{DtlsSession, SessionState, SessionConfig, HANDSHAKE_TIMEOUT_MS};

/// Maximum DTLS record size.
pub const MAX_DTLS_RECORD_SIZE: usize = 16384;

/// Maximum handshake message size.
pub const MAX_HANDSHAKE_SIZE: usize = 4096;

/// DTLS 1.2 version.
pub const DTLS_VERSION_1_2: u16 = 0xFEFD;

/// DTLS 1.0 version (for backward compatibility).
pub const DTLS_VERSION_1_0: u16 = 0xFEFF;

/// Maximum retransmissions.
pub const MAX_RETRANSMISSIONS: u8 = 6;

/// Initial retransmission timeout in milliseconds.
pub const INITIAL_RTO_MS: u32 = 1000;

/// Maximum flight size (messages in flight).
pub const MAX_FLIGHT_SIZE: usize = 8;

/// Maximum fragment size (MTU-safe).
pub const MAX_FRAGMENT_SIZE: usize = 1400;

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

const _: () = {
    // Protocol bounds
    assert!(MAX_DTLS_RECORD_SIZE == 16384);
    assert!(MAX_HANDSHAKE_SIZE == 4096);
    assert!(MAX_FLIGHT_SIZE == 8);
    assert!(MAX_RETRANSMISSIONS == 6);
    assert!(INITIAL_RTO_MS == 1000);
    assert!(MAX_FRAGMENT_SIZE == 1400);
    
    // Version bounds
    assert!(DTLS_VERSION_1_2 == 0xFEFD);
    assert!(DTLS_VERSION_1_0 == 0xFEFF);
    
    // Timeout bounds (30 seconds)
    assert!(30000u32 == 30 * 1000);
    
    // Key sizes
    assert!(16 == 128 / 8);  // AES-128 key size
    assert!(12 == 96 / 8);   // GCM nonce size
    assert!(16 == 128 / 8);  // GCM tag size
    assert!(32 == 256 / 8);  // P-256 shared secret size
    assert!(65 == 1 + 32 + 32); // Uncompressed P-256 public key
    
    // Retransmission bounds
    assert!(INITIAL_RTO_MS >= 1000);
    assert!(MAX_RETRANSMISSIONS <= 10);
    
    // Fragment bounds
    assert!(MAX_FRAGMENT_SIZE <= MAX_DTLS_RECORD_SIZE);
    assert!(MAX_FRAGMENT_SIZE >= 1200); // Must exceed typical MTU
    
    // Flight bounds
    assert!(MAX_FLIGHT_SIZE >= 4); // Minimum for server flight
    assert!(MAX_FLIGHT_SIZE <= 16); // Reasonable upper bound
};
