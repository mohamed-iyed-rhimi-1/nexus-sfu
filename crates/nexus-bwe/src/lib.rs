#![deny(warnings)]

//! Bandwidth Estimation (BWE) for Nexus SFU
//!
//! Implements Google Congestion Control (GCC) combining delay-based and
//! loss-based bandwidth estimation with probing and track allocation.
//!
//! # Architecture
//!
//! - `gcc.rs`: Main GCC controller orchestrating all components
//! - `delay.rs`: Delay-based BWE with Kalman filter
//! - `loss.rs`: Loss-based BWE with AIMD
//! - `rtt.rs`: RTT estimation with exponential smoothing
//! - `probe.rs`: Bandwidth probing for capacity discovery
//! - `allocation.rs`: Priority-based bitrate allocation across tracks
//! - `feedback.rs`: RTCP Transport-Wide Congestion Control parsing
//! - `coordinator.rs`: Bandwidth coordinator bridging GCC and TrackActor system
//! - `speaker.rs`: Speaker detection for priority allocation
//! - `remb.rs`: REMB packet generation
//! - `types.rs`: Common types and constants
//!
//! # TigerStyle Compliance
//!
//! - Zero allocation after initialization
//! - All loops have fixed bounds
//! - Explicitly-sized types (u32, u64, f64)
//! - Comprehensive assertions for invariants
//! - Lock-free atomic operations

mod allocation;
mod coordinator;
mod delay;
mod feedback;
mod gcc;
mod loss;
mod probe;
mod remb;
mod rtt;
mod speaker;
mod types;

pub use allocation::{SimulcastLayer, TrackAllocation, TrackPriority};
pub use coordinator::BandwidthCoordinator;
pub use delay::{
    DelayBasedBweDetector, DelayBasedBweState, KalmanFilter,
    DEFAULT_DELAY_GRADIENT_THRESHOLD, DEFAULT_OVERUSE_TIME_THRESHOLD_MS,
};
pub use feedback::{PacketArrivalInfo, TransportFeedback, MAX_FEEDBACK_PACKETS};
pub use gcc::{CongestionController, GccStats, GccStatsSnapshot};
pub use loss::{AimdConfig, LossBasedBweDetector, LossBasedBweState, LossSample};
pub use probe::{ProbeController, ProbeState};
pub use remb::RembGenerator;
pub use rtt::RttEstimator;
pub use speaker::{MediaKind, SpeakerDetector};
pub use types::{BandwidthEstimate, BweState};
