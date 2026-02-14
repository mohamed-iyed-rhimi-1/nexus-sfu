//! ICE (Interactive Connectivity Establishment) implementation.
//!
//! Implements RFC 8445 for NAT traversal in WebRTC connections.
//! This module provides candidate gathering, connectivity checks,
//! and ICE state machine management.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        ICE Agent                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
//! │  │   Gatherer   │  │  CheckList   │  │    STUN      │          │
//! │  │              │──▶│              │──▶│   Server    │          │
//! │  └──────────────┘  └──────────────┘  └──────────────┘          │
//! │         │                 │                  │                  │
//! │         ▼                 ▼                  ▼                  │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                  Candidate Pairs                         │   │
//! │  │  (sorted by priority, checked for connectivity)          │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - All memory pre-allocated at initialization
//! - Explicit u32/u64 types (no usize on hot paths)
//! - Comprehensive assertions on all boundaries
//! - Zero dynamic allocation after init

pub mod stun;
pub mod candidate;
pub mod agent;
pub mod checklist;
pub mod gather;
pub mod error;
pub mod types;

pub use agent::IceAgent;
pub use candidate::{Candidate, CandidateType, CandidatePair, CandidatePairState};
pub use checklist::{Checklist, ChecklistState};
pub use error::IceError;
pub use gather::{CandidateGatherer, GatheredCandidates, GatheringState};
pub use stun::{StunMessage, StunAttribute, StunClass, StunMethod};
pub use types::{
    IceConfig, IceRole, IceConnectionState, IceGatheringState, IceCredentials,
    TurnServerConfig, TransportType,
    // High-level application config types
    IceServerConfig, HighLevelTurnServerConfig, GOOGLE_STUN_SERVERS,
    MAX_STUN_SERVERS_CONFIG, MAX_TURN_SERVERS_CONFIG,
};

/// Maximum candidates per ICE agent.
/// Bounded to prevent memory exhaustion attacks.
/// Aligned with internal MAX_CANDIDATES in candidate.rs.
pub const MAX_CANDIDATES: u32 = 32;

/// Maximum candidate pairs per checklist.
/// Follows RFC 8445 recommendation and aligns with internal limits.
pub const MAX_CANDIDATE_PAIRS: u32 = 100;

/// Maximum pending STUN transactions.
pub const MAX_PENDING_TRANSACTIONS: u32 = 32;

/// Default STUN transaction timeout in milliseconds.
pub const STUN_TRANSACTION_TIMEOUT_MS: u32 = 500;

/// Default connectivity check interval in milliseconds.
pub const CHECK_INTERVAL_MS: u32 = 50;

/// ICE username fragment length (characters).
pub const UFRAG_LENGTH: u32 = 8;

/// ICE password length (characters).
pub const PWD_LENGTH: u32 = 32;

// Compile-time assertions for constants
const _: () = {
    assert!(MAX_CANDIDATES > 0, "MAX_CANDIDATES must be positive");
    assert!(MAX_CANDIDATES <= 256, "MAX_CANDIDATES must fit in u8");
    assert!(MAX_CANDIDATE_PAIRS >= MAX_CANDIDATES, "pairs >= candidates");
    assert!(UFRAG_LENGTH >= 4, "ufrag must be >= 4 chars per RFC");
    assert!(PWD_LENGTH >= 22, "pwd must be >= 22 chars per RFC");
};

// ============================================================================
// Phase 5: Comprehensive Compile-Time Assertions (TigerStyle)
// ============================================================================

/// Additional compile-time validation for ICE constants.
const _ICE_COMPILE_TIME_CHECKS: () = {
    // RFC 8445 Section 14.1: candidate limits
    assert!(MAX_CANDIDATES >= 1 && MAX_CANDIDATES <= 256,
        "MAX_CANDIDATES must be 1-256 per RFC 8445");
    
    // MAX_CANDIDATE_PAIRS is capped at 100, not dependent on MAX_CANDIDATES^2
    assert!(MAX_CANDIDATE_PAIRS == 100,
        "MAX_CANDIDATE_PAIRS must be capped at 100 per RFC 8445");
    
    // Transaction limits reasonable
    assert!(MAX_PENDING_TRANSACTIONS >= 4 && MAX_PENDING_TRANSACTIONS <= 64,
        "Pending transactions should be 4-64 for practical use");
    
    // STUN timeout reasonable per RFC 5389
    assert!(STUN_TRANSACTION_TIMEOUT_MS >= 100 && STUN_TRANSACTION_TIMEOUT_MS <= 5000,
        "STUN timeout should be 100-5000ms");
    
    // Check interval reasonable for real-time
    assert!(CHECK_INTERVAL_MS >= 10 && CHECK_INTERVAL_MS <= 500,
        "Check interval should be 10-500ms for real-time");
    
    // RFC 5245 Section 15.4: ufrag and pwd requirements
    assert!(UFRAG_LENGTH >= 4 && UFRAG_LENGTH <= 256,
        "UFRAG length must be 4-256 per RFC");
    assert!(PWD_LENGTH >= 22 && PWD_LENGTH <= 256,
        "PWD length must be 22-256 per RFC");
    
    // Ensure reasonable memory bounds
    // Each candidate ~128 bytes, so MAX_CANDIDATES * 128 should be reasonable
    assert!(MAX_CANDIDATES as usize * 128 <= 32768,
        "Candidate storage should not exceed 32KB");
};
