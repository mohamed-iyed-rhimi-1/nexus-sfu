//! CRDT Error types for nexus-state
//!
//! This module defines error types following TigerStyle principles:
//! - Explicit error codes with compile-time uniqueness
//! - Bounded error states with clear transitions
//! - Comprehensive error context for debugging

use std::io;

use thiserror::Error;

/// Error code constants for CRDT operations (2001-2010 range)
/// Each error code must be unique across the crate
pub mod error_codes {
    /// Capacity exhausted error code
    pub const CAPACITY_EXHAUSTED: u32 = 2001;
    /// Invalid actor ID error code
    pub const INVALID_ACTOR_ID: u32 = 2002;
    /// Invalid timestamp error code
    pub const INVALID_TIMESTAMP: u32 = 2003;
    /// Merge conflict error code
    pub const MERGE_CONFLICT: u32 = 2004;
    /// Tombstone overflow error code
    pub const TOMBSTONE_OVERFLOW: u32 = 2005;
    /// Element not found error code
    pub const ELEMENT_NOT_FOUND: u32 = 2006;
    /// Duplicate element error code
    pub const DUPLICATE_ELEMENT: u32 = 2007;
    /// Invalid dot error code
    pub const INVALID_DOT: u32 = 2008;
    /// Overflow error code
    pub const OVERFLOW: u32 = 2009;
    /// Invalid state error code
    pub const INVALID_STATE: u32 = 2010;

    // Gossip error codes (2011-2020 range)
    /// Peer capacity exhausted error code
    pub const PEER_CAPACITY_EXHAUSTED: u32 = 2011;
    /// Invalid state transition error code
    pub const INVALID_STATE_TRANSITION: u32 = 2012;
    /// Peer not found error code
    pub const PEER_NOT_FOUND: u32 = 2013;
    /// Message too large error code
    pub const MESSAGE_TOO_LARGE: u32 = 2014;
    /// Invalid message error code
    pub const INVALID_MESSAGE: u32 = 2015;
    /// Transport error code
    pub const TRANSPORT_ERROR: u32 = 2016;
    /// Config error code
    pub const CONFIG_ERROR: u32 = 2017;

    // Compile-time uniqueness assertion
    const _: () = {
        let codes = [
            CAPACITY_EXHAUSTED,
            INVALID_ACTOR_ID,
            INVALID_TIMESTAMP,
            MERGE_CONFLICT,
            TOMBSTONE_OVERFLOW,
            ELEMENT_NOT_FOUND,
            DUPLICATE_ELEMENT,
            INVALID_DOT,
            OVERFLOW,
            INVALID_STATE,
            PEER_CAPACITY_EXHAUSTED,
            INVALID_STATE_TRANSITION,
            PEER_NOT_FOUND,
            MESSAGE_TOO_LARGE,
            INVALID_MESSAGE,
            TRANSPORT_ERROR,
            CONFIG_ERROR,
        ];
        
        let mut i = 0;
        while i < codes.len() {
            let mut j = i + 1;
            while j < codes.len() {
                assert!(codes[i] != codes[j], "Duplicate error codes detected");
                j += 1;
            }
            i += 1;
        }
        
        // Ensure all codes are in valid range
        let mut k = 0;
        while k < codes.len() {
            assert!(codes[k] >= 2001 && codes[k] <= 2020, "Error code out of range");
            k += 1;
        }
    };
}

/// Errors that can occur during CRDT operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CrdtError {
    /// Fixed-size collection has reached maximum capacity
    #[error("Capacity exhausted: collection full at {capacity} elements (code: {code})", code = error_codes::CAPACITY_EXHAUSTED)]
    CapacityExhausted {
        /// Maximum capacity that was reached
        capacity: u32,
    },

    /// Actor ID is outside valid range
    #[error("Invalid actor ID: {actor_id} exceeds maximum (code: {code})", code = error_codes::INVALID_ACTOR_ID)]
    InvalidActorId {
        /// The invalid actor ID
        actor_id: u64,
    },

    /// Timestamp ordering violation
    #[error("Invalid timestamp: {timestamp} violates ordering constraint (code: {code})", code = error_codes::INVALID_TIMESTAMP)]
    InvalidTimestamp {
        /// The invalid timestamp
        timestamp: u64,
    },

    /// Merge operation violated an invariant
    #[error("Merge conflict: {reason} (code: {code})", code = error_codes::MERGE_CONFLICT)]
    MergeConflict {
        /// Static description of the conflict
        reason: &'static str,
    },

    /// Tombstone array has reached maximum capacity
    #[error("Tombstone overflow: {count} tombstones exceed maximum {max} (code: {code})", code = error_codes::TOMBSTONE_OVERFLOW)]
    TombstoneOverflow {
        /// Current tombstone count
        count: u32,
        /// Maximum allowed tombstones
        max: u32,
    },

    /// Element was not found in the collection
    #[error("Element not found (code: {code})", code = error_codes::ELEMENT_NOT_FOUND)]
    ElementNotFound,

    /// Duplicate element detected when not allowed
    #[error("Duplicate element detected (code: {code})", code = error_codes::DUPLICATE_ELEMENT)]
    DuplicateElement,

    /// Invalid dot (actor_id, clock) pair
    #[error("Invalid dot: actor_id={actor_id}, clock={clock} (code: {code})", code = error_codes::INVALID_DOT)]
    InvalidDot {
        /// Actor ID component of the dot
        actor_id: u64,
        /// Clock component of the dot
        clock: u64,
    },

    /// Arithmetic overflow detected
    #[error("Overflow detected in operation (code: {code})", code = error_codes::OVERFLOW)]
    Overflow,

    /// Invalid internal state detected
    #[error("Invalid state: {reason} (code: {code})", code = error_codes::INVALID_STATE)]
    InvalidState {
        /// Description of the invalid state
        reason: &'static str,
    },
}

/// Errors that can occur during gossip protocol operations
#[derive(Error, Debug)]
pub enum GossipError {
    /// Peer capacity exhausted (max peers reached)
    #[error("Peer capacity exhausted: max {max} peers (code: {code})", code = error_codes::PEER_CAPACITY_EXHAUSTED)]
    PeerCapacityExhausted {
        /// Maximum peer capacity
        max: usize,
    },

    /// Invalid state transition in SWIM state machine
    #[error("Invalid state transition from {from} to {to} (code: {code})", code = error_codes::INVALID_STATE_TRANSITION)]
    InvalidStateTransition {
        /// Current state name
        from: &'static str,
        /// Attempted new state name
        to: &'static str,
    },

    /// Peer not found in membership list
    #[error("Peer not found: actor_id={actor_id} (code: {code})", code = error_codes::PEER_NOT_FOUND)]
    PeerNotFound {
        /// Actor ID of the missing peer
        actor_id: u64,
    },

    /// Message exceeds maximum size
    #[error("Message too large: {size} bytes exceeds max {max} (code: {code})", code = error_codes::MESSAGE_TOO_LARGE)]
    MessageTooLarge {
        /// Actual message size
        size: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// Invalid message format
    #[error("Invalid message format: {reason} (code: {code})", code = error_codes::INVALID_MESSAGE)]
    InvalidMessage {
        /// Description of the format error
        reason: String,
    },

    /// Transport (I/O) error
    #[error("Transport error: {0} (code: {code})", code = error_codes::TRANSPORT_ERROR)]
    Transport(#[from] io::Error),

    /// Configuration error
    #[error("Configuration error: {0} (code: {code})", code = error_codes::CONFIG_ERROR)]
    Config(String),
}

impl GossipError {
    /// Returns the error code for this error
    #[inline]
    pub const fn code(&self) -> u32 {
        match self {
            Self::PeerCapacityExhausted { .. } => error_codes::PEER_CAPACITY_EXHAUSTED,
            Self::InvalidStateTransition { .. } => error_codes::INVALID_STATE_TRANSITION,
            Self::PeerNotFound { .. } => error_codes::PEER_NOT_FOUND,
            Self::MessageTooLarge { .. } => error_codes::MESSAGE_TOO_LARGE,
            Self::InvalidMessage { .. } => error_codes::INVALID_MESSAGE,
            Self::Transport(_) => error_codes::TRANSPORT_ERROR,
            Self::Config(_) => error_codes::CONFIG_ERROR,
        }
    }

    /// Returns true if this error is recoverable (transient)
    #[inline]
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    /// Returns true if this error indicates a configuration problem
    #[inline]
    pub fn is_config_error(&self) -> bool {
        matches!(self, Self::Config(_))
    }
}

impl CrdtError {
    /// Returns the error code for this error
    #[inline]
    pub const fn code(&self) -> u32 {
        match self {
            Self::CapacityExhausted { .. } => error_codes::CAPACITY_EXHAUSTED,
            Self::InvalidActorId { .. } => error_codes::INVALID_ACTOR_ID,
            Self::InvalidTimestamp { .. } => error_codes::INVALID_TIMESTAMP,
            Self::MergeConflict { .. } => error_codes::MERGE_CONFLICT,
            Self::TombstoneOverflow { .. } => error_codes::TOMBSTONE_OVERFLOW,
            Self::ElementNotFound => error_codes::ELEMENT_NOT_FOUND,
            Self::DuplicateElement => error_codes::DUPLICATE_ELEMENT,
            Self::InvalidDot { .. } => error_codes::INVALID_DOT,
            Self::Overflow => error_codes::OVERFLOW,
            Self::InvalidState { .. } => error_codes::INVALID_STATE,
        }
    }

    /// Returns true if this error indicates a capacity limit was reached
    #[inline]
    pub const fn is_capacity_error(&self) -> bool {
        matches!(
            self,
            Self::CapacityExhausted { .. } | Self::TombstoneOverflow { .. }
        )
    }

    /// Returns true if this error indicates invalid input
    #[inline]
    pub const fn is_input_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidActorId { .. }
                | Self::InvalidTimestamp { .. }
                | Self::InvalidDot { .. }
        )
    }
}

/// Result type for CRDT operations
pub type CrdtResult<T> = Result<T, CrdtError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_in_range() {
        // Assert all error codes are in expected range
        assert!(error_codes::CAPACITY_EXHAUSTED >= 2001);
        assert!(error_codes::CAPACITY_EXHAUSTED <= 2010);
        assert!(error_codes::INVALID_STATE >= 2001);
        assert!(error_codes::INVALID_STATE <= 2010);
    }

    #[test]
    fn test_error_code_method() {
        let err = CrdtError::CapacityExhausted { capacity: 100 };
        assert_eq!(err.code(), error_codes::CAPACITY_EXHAUSTED);

        let err = CrdtError::InvalidActorId { actor_id: 999 };
        assert_eq!(err.code(), error_codes::INVALID_ACTOR_ID);

        let err = CrdtError::TombstoneOverflow { count: 50, max: 40 };
        assert_eq!(err.code(), error_codes::TOMBSTONE_OVERFLOW);
    }

    #[test]
    fn test_is_capacity_error() {
        assert!(CrdtError::CapacityExhausted { capacity: 100 }.is_capacity_error());
        assert!(CrdtError::TombstoneOverflow { count: 50, max: 40 }.is_capacity_error());
        assert!(!CrdtError::InvalidActorId { actor_id: 999 }.is_capacity_error());
    }

    #[test]
    fn test_is_input_error() {
        assert!(CrdtError::InvalidActorId { actor_id: 999 }.is_input_error());
        assert!(CrdtError::InvalidTimestamp { timestamp: 0 }.is_input_error());
        assert!(CrdtError::InvalidDot { actor_id: 0, clock: 0 }.is_input_error());
        assert!(!CrdtError::CapacityExhausted { capacity: 100 }.is_input_error());
    }

    #[test]
    fn test_error_display() {
        let err = CrdtError::CapacityExhausted { capacity: 100 };
        let msg = format!("{}", err);
        assert!(msg.contains("100"));
        assert!(msg.contains("2001"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = CrdtError::CapacityExhausted { capacity: 100 };
        let err2 = CrdtError::CapacityExhausted { capacity: 100 };
        let err3 = CrdtError::CapacityExhausted { capacity: 200 };
        
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }
}
