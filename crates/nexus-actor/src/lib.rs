//! Nexus Actor System
//!
//! Provides actor-based architecture for media tracks with:
//! - Independent lifecycle management
//! - Message-based communication
//! - State machine enforcement
//! - Supervision and health monitoring
//! - Location-independent addressing
//!
//! # Architecture
//!
//! The actor system is built around `TrackActor`, which represents a media track
//! as an independent actor with its own lifecycle, message queue, and state machine.
//!
//! ## Key Components

#![allow(clippy::unnecessary_cast)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::map_entry)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::len_zero)]
#![allow(clippy::needless_return)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::unwrap_or_default)]
#![deny(warnings)]
//!
//! - `TrackActor`: Independent actor representing a media track
//! - `ActorRegistry`: Maps TrackId -> WorkerId for message routing
//! - `ActorSupervisor`: Health monitoring and restart policy enforcement
//!
//! ## State Machine
//!
//! Actors follow a strict state machine:
//! - `Initializing` -> `Active`: After successful initialization
//! - `Active` -> `Migrating`: When migration begins
//! - `Active` -> `Terminated`: On graceful shutdown
//! - `Migrating` -> `Active`: After successful migration
//! - `Migrating` -> `Terminated`: On shutdown during migration
//!
//! ## Message Protocol
//!
//! Actors communicate via typed messages (`TrackActorMessage`):
//! - `Subscribe/Unsubscribe`: Manage subscribers
//! - `ProcessPacket`: Handle incoming RTP packets
//! - `BeginMigration/CompleteMigration`: Migration protocol
//! - `Terminate`: Graceful shutdown
//! - `HealthCheck`: Supervision ping
//!
//! # Example
//!
//! ```rust
//! use nexus_actor::{TrackActor, TrackActorMessage, MediaKind, ActorState};
//!
//! // Spawn a new track actor
//! let (mut actor, sender) = TrackActor::spawn(
//!     1,              // track_id
//!     100,            // participant_id
//!     12345,          // ssrc
//!     MediaKind::Video,
//!     0,              // worker_id
//! );
//!
//! assert_eq!(actor.state(), ActorState::Active);
//!
//! // Send a terminate message to stop the actor
//! sender.send(TrackActorMessage::Terminate).unwrap();
//!
//! // Process messages - returns false when actor terminates
//! let should_continue = actor.process_messages();
//! assert!(!should_continue);
//! assert_eq!(actor.state(), ActorState::Terminated);
//! ```

pub mod manager;
pub mod message;
pub mod metrics;
pub mod migration_executor;
pub mod migration_queue;
pub mod participant;
pub mod registry;
pub mod room;
pub mod supervisor;
pub mod track;
pub mod types;

// Re-export main types at crate root
pub use manager::{ActorError, ActorManager, DistributedState};
pub use message::{
    ConnectionState, MigrationSnapshot, PacketSlot, ParticipantActorMessage, RoomActorMessage,
    RoomStats, SubscriberSnapshot, TrackActorMessage, TrackActorResponse, TrackStatsSnapshot,
};
pub use metrics::MigrationMetrics;
pub use migration_executor::{
    MigrationError, MigrationExecutor, MigrationResult, WorkerPool, MAX_MIGRATION_SIZE,
    MAX_MIGRATION_SUBSCRIBERS, RING_BUFFER_SIZE,
};
pub use migration_queue::{MigrationQueue, MigrationRequest};
pub use participant::ParticipantActor;
pub use registry::{ActorId, ActorRegistry, ActorType};
pub use room::RoomActor;
pub use supervisor::ActorSupervisor;
pub use track::{MigrationEvent, PacketRingBuffer, Subscriber, SubscriberList, TrackActor};
pub use types::{
    ActorHealth, ActorState, MediaKind, MigrationId, MigrationSeqNum, ParticipantId,
    RestartPolicy, RoomId, Ssrc, TrackId, WorkerId, MAX_ACTORS_PER_WORKER, MAX_ACTOR_QUEUE_SIZE,
    MAX_CONCURRENT_MIGRATIONS, MAX_HEALTH_CHECKS_PER_ITERATION, MAX_MESSAGES_PER_ITERATION,
    MAX_MIGRATION_RETRIES, MAX_PARTICIPANTS, MAX_PARTICIPANTS_PER_ROOM, MAX_ROOMS,
    MAX_SUBSCRIPTIONS_PER_PARTICIPANT, MAX_TRACKS, MAX_TRACKS_PER_PARTICIPANT,
    MAX_TRACKS_PER_ROOM, MAX_WORKERS, MIGRATION_GRAVITY_THRESHOLD_PERCENT,
    MIGRATION_REBALANCE_INTERVAL_SECS, MIGRATION_TIMEOUT_SECS,
};
