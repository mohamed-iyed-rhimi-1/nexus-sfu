//! State management module for Nexus SFU.
//!
//! This module contains state management components including:
//! - ForwardTable: BPF map wrapper for XDP packet forwarding
//!
//! # Architecture
//!
//! The state module manages shared state that bridges kernel-space
//! XDP processing with user-space control logic.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    User Space (Rust)                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ForwardTable                                                │
//! │    │                                                         │
//! │    ├── insert(ssrc, entry)  ──► BPF map update              │
//! │    ├── remove(ssrc)         ──► BPF map delete              │
//! │    └── insert_batch(...)    ──► BPF batch update            │
//! └─────────────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Kernel Space (BPF)                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  forward_table (BPF_MAP_TYPE_HASH)                          │
//! │    SSRC ──► ForwardEntry (MAC, IP, port, ifindex)           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Requirements Coverage
//!
//! - Requirement 19.4: ForwardTable manages BPF map entries
//! - Requirement 19.5: Batch insert/remove operations

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub mod forward_table;

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use forward_table::{ForwardTable, ForwardEntry, XdpError};

// Provide stub types when XDP is not available
#[cfg(not(all(target_os = "linux", feature = "xdp")))]
mod forward_table_stub;

#[cfg(not(all(target_os = "linux", feature = "xdp")))]
pub use forward_table_stub::{ForwardTable, ForwardEntry, XdpError};
