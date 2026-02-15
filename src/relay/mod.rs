//! Inter-node RTP relay for SFU cascade.
//!
//! When a subscriber is on node-B but the track lives on node-A,
//! node-A forwards packets to node-B via a `RelayLink`. Node-B's
//! `RelayReceiver` injects them into the local worker pool for fan-out.
//!
//! # Architecture
//!
//! ```text
//! Node-A (track owner)              Node-B (has subscribers)
//! ┌────────────────┐                ┌────────────────┐
//! │ forward_to_sub │  UDP relay     │ RelayReceiver  │
//! │  (is_relay=T)  │ ────────────►  │  inject into   │
//! │  RelayLink     │  port 10001    │  worker pool   │
//! └────────────────┘                └────────────────┘
//! ```
//!
//! # TigerStyle + NASA Compliance
//!
//! - No recursion
//! - All loops bounded
//! - ≥2 assertions per public function
//! - Explicit error handling

pub mod link;
pub mod manager;

pub use link::RelayLink;
pub use manager::RelayManager;
