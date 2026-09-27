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
//! Phase 1.2 builds the shard logic on [`MemIo`]; sockets, threads and the
//! control-plane handle come in 1.3.

#![deny(warnings)]
#![deny(unsafe_code)]

pub mod command;
pub mod config;
pub mod ext;
pub mod ice;
pub mod ids;
pub mod pool;
pub mod rewrite;
mod rng;
pub mod rtcp;
mod session;
pub mod shard;
mod slab;
mod subscription;
mod track;

pub use command::{
    CodecParams, Command, Event, EventSink, ExtIds, ExtMap, IceParams, PtMap, RejectReason,
    SelectReason, SrtpInstall, SubSpec, TrackSpec,
};
pub use config::{ConfigError, ShardConfig};
pub use ids::{
    CnameValue, MidValue, SessionId, ShardId, SubscriptionId, TrackId, TrackRef, MAX_SHARDS,
};
pub use pool::{BufRef, BufferPool, BUF_SIZE};
pub use shard::io::{
    Datagram, DatagramIo, MemIo, RecvBatch, RecvResult, SendBatch, RECV_BATCH, SEND_BATCH,
};
pub use shard::stats::{ShardCounters, ShardStats, ShardStatsSnapshot};
pub use shard::{IterationStats, Shard, ShardSnapshot};
