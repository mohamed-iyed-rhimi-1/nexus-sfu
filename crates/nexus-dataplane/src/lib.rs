//! nexus-dataplane: the SFU's media data plane.
//!
//! A shard owns sessions, published tracks and subscriptions, answers ICE-lite
//! binding requests, decrypts SRTP from publishers and forwards rewritten,
//! re-encrypted RTP to subscribers (`docs/design/dataplane-v1.md`).
//!
//! The control plane drives a shard only through [`Command`]s and learns what
//! happened through [`Event`]s. All code below [`Shard::iterate`] takes `now`
//! as an argument and never reads the clock.
//!
//! [`Dataplane::start`] binds one UDP socket per shard and runs each shard
//! on its own thread; the control plane talks to them only through
//! [`DataplaneHandle`]. Tests drive a [`Shard`] directly on [`MemIo`].

#![deny(warnings)]
#![deny(unsafe_code)]

pub mod command;
pub mod config;
pub mod ext;
mod handle;
pub mod ice;
pub mod ids;
pub mod placement;
pub mod pool;
pub mod rewrite;
mod rng;
pub mod rtcp;
mod sched;
mod session;
pub mod shard;
mod slab;
mod subscription;
mod track;
pub mod xs;

pub use command::{
    CodecParams, Command, Event, EventSink, ExtIds, ExtMap, IceParams, PtMap, Refused,
    RejectReason, SelectReason, SrtpInstall, SubSpec, TrackSpec,
};
pub use config::{
    default_pool_buffers, min_pool_buffers, ConfigError, DataplaneConfig, FixedMemory, ShardConfig,
    MAX_SHARDS_SUPPORTED,
};
pub use handle::{
    bind_shard_socket, CommandQueueFull, Dataplane, DataplaneError, DataplaneHandle, ShardInfo,
    EVENT_CHANNEL_CAPACITY, SHARD_STACK_SIZE,
};
pub use ids::{
    CnameValue, MidValue, SessionId, ShardId, SubscriptionId, TrackId, TrackRef, MAX_SHARDS,
};
pub use placement::{Placement, RoomAffine, RoomAffineLimits, ShardLoad, SingleShard};
pub use pool::{BufRef, BufferPool, Loan, PoolRegion, BUF_SIZE};
pub use session::{MAX_SUBS_PER_SESSION, MAX_TRACKS_PER_SESSION};
#[cfg(target_os = "linux")]
pub use shard::io::{udp_gro_enabled, LinuxIo};
pub use shard::io::{
    Datagram, DatagramIo, MemIo, PlatformIo, PortableIo, RecvBatch, RecvResult, SendBatch, Sent,
    RECV_BATCH, SEND_BATCH,
};
pub use shard::stats::{ShardCounters, ShardStats, ShardStatsSnapshot};
pub use shard::{IterationStats, Shard, ShardSnapshot};
pub use xs::{mesh_bytes, XsMesh, XsMsg, XsPorts, XS_BUDGET, XS_CREDIT, XS_RING};

/// In-memory sizes of the shard's per-session, per-track and per-subscription
/// entries, for the memory bench's structural report (`benches/memory.rs`).
#[doc(hidden)]
pub mod sizes {
    /// One session slot.
    pub const SESSION: usize = std::mem::size_of::<crate::session::Session>();
    /// One published-track slot.
    pub const PUBLISHED_TRACK: usize = std::mem::size_of::<crate::track::PublishedTrack>();
    /// One subscription slot.
    pub const SUBSCRIPTION: usize = std::mem::size_of::<crate::subscription::Subscription>();
    /// One mirror track (a track published on another shard).
    pub const MIRROR_TRACK: usize = std::mem::size_of::<crate::track::MirrorTrack>();
    /// One slot of the mirror slab (the mirror plus the slot's generation).
    pub const MIRROR_TRACK_SLOT: usize = crate::slab::slot_size::<crate::track::MirrorTrack>();
    /// One entry of the mirror id map.
    pub const MIRROR_ID_ENTRY: usize =
        std::mem::size_of::<(crate::ids::TrackId, crate::session::MirrorIdx)>();
}
