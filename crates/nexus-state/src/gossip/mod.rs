//! SWIM Gossip Protocol for Distributed State Synchronization
//!
//! This module implements the SWIM (Scalable Weakly-consistent Infection-style Membership)
//! protocol for peer-to-peer cluster membership and state propagation.
//!
//! ## Protocol Overview
//!
//! SWIM provides:
//! - **Failure Detection**: Probes peers with ping/ack, uses indirect probes via other nodes
//! - **Membership Dissemination**: Piggybacks state updates on protocol messages
//! - **Scalable Gossip**: O(log n) convergence time for cluster-wide state propagation
//!
//! ## State Machine
//!
//! Each peer follows this state machine:
//!
//! ```text
//! [*] --> Alive: add_peer()
//!
//! Alive --> Suspect: ping_timeout
//! Suspect --> Alive: refutation (higher incarnation)
//! Suspect --> Dead: suspect_timeout
//! Dead --> Alive: resurrection (higher incarnation)
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        SwimProtocol                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  membership: MembershipList     - Peer state machine            │
//! │  transport: GossipTransport     - UDP send/recv with batching   │
//! │  piggyback_queue: VecDeque      - Pending state updates         │
//! │  pending_pings: HashMap         - Outstanding ping requests     │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## TigerStyle Compliance
//!
//! - All loops have fixed upper bounds (MAX_PEERS, MAX_PIGGYBACK_UPDATES)
//! - No recursion (iterative algorithms only)
//! - Explicit u64/u32 sizing (no usize except for array indexing)
//! - Assertions on all function arguments and return values
//! - All memory pre-allocated at initialization
//!
//! ## Usage
//!
//! ```ignore
//! use nexus_state::gossip::{SwimProtocol, GossipConfig};
//! use std::net::SocketAddr;
//!
//! // Create protocol instance
//! let config = GossipConfig::default();
//! let bind_addr: SocketAddr = "0.0.0.0:7946".parse().unwrap();
//! let mut protocol = SwimProtocol::new(1, bind_addr, config)?;
//!
//! // Add seed peers
//! protocol.add_seed_peer(2, "192.168.1.2:7946".parse().unwrap())?;
//! protocol.add_seed_peer(3, "192.168.1.3:7946".parse().unwrap())?;
//!
//! // Run protocol loop
//! loop {
//!     protocol.run_probe_cycle()?;
//!     protocol.recv_loop_iteration()?;
//! }
//! ```

mod config;
mod membership;
mod protocol;
mod transport;
pub mod types;

// Re-export public API
pub use config::{GossipConfig, SeedPeer, MAX_SEED_PEERS};
pub use membership::MembershipList;
pub use protocol::ProtocolStats;
pub use protocol::{PendingPing, RelayEvent, SwimProtocol};
pub use transport::{GossipTransport, TransportStats};
pub use types::{
    GossipMessage, PeerInfo, PeerState, StateUpdate,
    MAX_MESSAGE_SIZE, MAX_PEERS, MAX_PIGGYBACK_UPDATES,
    GOSSIP_FANOUT, PING_TIMEOUT_MS, PROBE_INTERVAL_MS, SUSPECT_TIMEOUT_MS,
};
