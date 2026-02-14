#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::declare_interior_mutable_const)]

//! # nexus-state
//!
//! CRDT-based distributed state management for Nexus SFU.
//!
//! This crate provides conflict-free replicated data types (CRDTs) designed for
//! high-performance, distributed state synchronization in WebRTC SFU applications.
//!
//! ## Features
//!
//! - **Zero allocation after init**: All data structures use pre-allocated, fixed-size arrays
//! - **Lock-free operations**: Atomic operations for concurrent access
//! - **Bounded complexity**: All loops have explicit bounds, all operations are O(n) or better
//! - **TigerStyle compliance**: Comprehensive assertions, explicit error handling
//! - **Property-tested**: Mathematical CRDT properties verified via proptest
//!
//! ## CRDT Types
//!
//! ### GCounter (Grow-Only Counter)
//!
//! A distributed counter that can only be incremented. Each node has its own counter,
//! and the total value is the sum of all node counters. Ideal for:
//! - Packet counts
//! - Message counts
//! - Connection statistics
//!
//! ```
//! use nexus_state::crdt::GCounter;
//!
//! let counter = GCounter::new();
//! counter.increment(0, 5);  // Node 0 increments by 5
//! counter.increment(1, 3);  // Node 1 increments by 3
//! assert_eq!(counter.value(), 8);
//! ```
//!
//! ### LWWReg (Last-Writer-Wins Register)
//!
//! A register that resolves concurrent writes by choosing the write with the highest
//! timestamp. Ties are broken by actor ID. Ideal for:
//! - Track metadata (bitrate, codec)
//! - Participant state (name, avatar)
//! - Configuration values
//!
//! ```
//! use nexus_state::crdt::LWWReg;
//!
//! let mut reg = LWWReg::new(0u32, 1);
//! reg.set(42, 100, 1);  // Write 42 with timestamp 100
//! reg.set(99, 50, 2);   // Ignored: older timestamp
//! assert_eq!(reg.get(), 42);
//! ```
//!
//! ### Orswot (Observed-Remove Set)
//!
//! A set that supports both add and remove operations. Uses tombstones to prevent
//! removed elements from being resurrected. Ideal for:
//! - Participant sets
//! - Track subscriptions
//! - Room membership
//!
//! ```
//! use nexus_state::crdt::Orswot;
//! use nexus_state::types::Dot;
//!
//! let mut set: Orswot<u32> = Orswot::new();
//! set.add(42, Dot::new(1, 1)).unwrap();
//! assert!(set.contains(&42));
//!
//! set.remove(&42, Dot::new(1, 2)).unwrap();
//! assert!(!set.contains(&42));
//! ```
//!
//! ## Memory Model
//!
//! All CRDTs use fixed-capacity, pre-allocated data structures:
//!
//! - `GCounter`: Array of 256 atomic counters (2KB)
//! - `LWWReg<T>`: Single value + 16 bytes metadata
//! - `Orswot<T>`: 10,000 element slots + 5,000 tombstone slots
//!
//! This ensures:
//! - Predictable memory usage
//! - No allocation during hot paths
//! - Cache-friendly access patterns
//!
//! ## Concurrency Model
//!
//! - `GCounter`: Fully lock-free, uses `AtomicU64` for all counters
//! - `LWWReg`: Uses `AtomicU64` for timestamp/writer, requires `&mut` for value updates
//! - `Orswot`: Uses `AtomicU32` for counts, requires `&mut` for element operations
//!
//! ## Error Handling
//!
//! All fallible operations return `CrdtResult<T>`:
//!
//! ```
//! use nexus_state::crdt::Orswot;
//! use nexus_state::types::Dot;
//! use nexus_state::error::CrdtError;
//!
//! let mut set: Orswot<u32> = Orswot::new();
//!
//! // Capacity errors
//! // After filling 10,000 elements:
//! // let result = set.add(elem, dot);
//! // assert!(matches!(result, Err(CrdtError::CapacityExhausted { .. })));
//! ```
//!
//! ## Capacity Limits
//!
//! | Constant | Value | Description |
//! |----------|-------|-------------|
//! | `MAX_ACTORS` | 256 | Maximum nodes in cluster |
//! | `MAX_ELEMENTS` | 10,000 | Maximum Orswot set size |
//! | `MAX_TOMBSTONES` | 5,000 | Maximum Orswot tombstones |
//! | `MAX_VALUE_SIZE` | 256 | Maximum LWWReg value size in bytes |

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod crdt;
pub mod distributed_state;
pub mod error;
pub mod gossip;
pub mod types;

// Re-export commonly used items at crate root
pub use crdt::{GCounter, LWWReg, Orswot};
pub use distributed_state::{
    DistributedState, DistributedStateConfig, RoomMetadata, RoomRegistry,
    MAX_ROOMS, MAX_TRACKS, MAX_SUBSCRIPTIONS, MAX_PARTICIPANTS_PER_ROOM,
};
pub use error::{CrdtError, CrdtResult, GossipError};
pub use gossip::{GossipConfig, PeerInfo, SeedPeer, StateUpdate, MAX_PIGGYBACK_UPDATES, MAX_SEED_PEERS};
pub use gossip::SwimProtocol;
pub use types::{ActorId, Dot, VectorClock, VersionVector, MAX_ACTORS, MAX_ELEMENTS, MAX_TOMBSTONES};
