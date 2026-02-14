//! CRDT (Conflict-free Replicated Data Types) implementations
//!
//! This module provides three core CRDT types for distributed state management:
//!
//! - [`GCounter`] - Grow-only counter, can only be incremented
//! - [`LWWReg`] - Last-Writer-Wins register, resolves conflicts by timestamp
//! - [`Orswot`] - Observed-Remove Set, supports add and remove with tombstones
//!
//! All implementations follow TigerStyle principles:
//! - Pre-allocated, fixed-size data structures
//! - Zero allocation after initialization
//! - Atomic operations for concurrent access
//! - Comprehensive assertions on positive and negative space
//! - Bounded loops with explicit limits
//!
//! # CRDT Properties
//!
//! All CRDTs in this module satisfy the mathematical properties required for
//! strong eventual consistency:
//!
//! - **Commutativity**: `merge(A, B) = merge(B, A)`
//! - **Associativity**: `merge(merge(A, B), C) = merge(A, merge(B, C))`
//! - **Idempotence**: `merge(A, A) = A`
//!
//! These properties ensure that replicas will converge to the same state
//! regardless of the order in which operations are applied.
//!
//! # Example
//!
//! ```
//! use nexus_state::crdt::{GCounter, LWWReg, Orswot};
//! use nexus_state::types::Dot;
//!
//! // GCounter - distributed counting
//! let counter = GCounter::new();
//! counter.increment(0, 5);
//! counter.increment(1, 3);
//! assert_eq!(counter.value(), 8);
//!
//! // LWWReg - distributed register
//! let mut reg = LWWReg::new(0u32, 1);
//! reg.set(42, 100, 1);
//! assert_eq!(reg.get(), 42);
//!
//! // Orswot - distributed set
//! let mut set: Orswot<u32> = Orswot::new();
//! set.add(42, Dot::new(1, 1)).unwrap();
//! assert!(set.contains(&42));
//! ```

mod gcounter;
mod lwwreg;
mod orswot;

pub use gcounter::{GCounter, GCounterSnapshot};
pub use lwwreg::{LWWReg, LWWRegSnapshot, MAX_VALUE_SIZE};
pub use orswot::{Orswot, OrswotSnapshot};
