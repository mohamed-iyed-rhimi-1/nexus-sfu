#![allow(clippy::len_zero)]
#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::let_and_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::eq_op)]
#![allow(clippy::get_first)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::result_large_err)]
#![deny(warnings)]

//! # nexus-transport
//!
//! Standalone transport layer for Nexus SFU.
//!
//! Contains UDP I/O (io_uring on Linux, kqueue on macOS), ICE agent,
//! DTLS handshake, SRTP encryption, PacketArena, RingBuffer, and
//! BatchSender. Depends only on nexus-core and nexus-media.
//!
//! # Module Structure
//!
//! - `arena` — Pre-allocated memory pool for zero-allocation packet handling
//! - `ring_buffer` — Lock-free SPSC ring buffer for per-track packet storage
//! - `udp` — UDP transport with platform-specific I/O (io_uring/kqueue)
//! - `io_uring` — Dedicated io_uring transport with SQPOLL and multishot receive
//! - `batch` — BatchSender for sendmmsg-based multi-packet transmission
//! - `ice` — ICE agent, STUN client/server, and candidate gathering
//! - `dtls` — DTLS handshake and session management
//! - `srtp` — SRTP encryption and decryption
//! - `socket_config` — High-performance socket configuration (16MB buffers, GRO/GSO)
//! - `gro` — GRO (Generic Receive Offload) packet splitter
//! - `gso` — GSO (Generic Segmentation Offload) batch sender

pub mod arena;
pub mod ring_buffer;
pub mod udp;
pub mod io_uring;
pub mod batch;
pub mod ice;
pub mod dtls;
pub mod srtp;
pub mod socket_config;
pub mod gro;
pub mod gso;
pub mod media_transport;
pub mod turn;

#[cfg(test)]
mod arena_proptest;

#[cfg(test)]
mod arena_refcount_proptest;

// Re-export key types at crate root for convenience.
pub use arena::{
    PacketArena, PacketSlot, SLOT_SIZE_BYTES,
    ArenaPartition, PartitionedPacketSlot, create_partitions,
};
pub use ring_buffer::RingBuffer;
pub use batch::{
    BatchSender, BatchSenderStats, BatchSenderStatsSnapshot,
};
pub use udp::{
    RecvPacket, ReceiveMode, TransportConfig, TransportStats,
    TransportStatsSnapshot, UdpTransport,
};

// Re-export io_uring types.
pub use io_uring::{
    IoUringTransport, IoUringConfig, IoUringRecvPacket,
    IoUringStats, IoUringStatsSnapshot, IoUringReceiveMode,
    create_transport_with_fallback,
};

// Re-export ICE types.
pub use ice::{
    IceAgent, IceConfig, IceRole, IceCredentials,
    IceConnectionState, IceGatheringState, IceError,
    Candidate, CandidateType, CandidatePair, CandidatePairState,
    CandidateGatherer, GatheredCandidates, GatheringState,
    Checklist, ChecklistState,
    StunMessage, StunAttribute, StunClass, StunMethod,
};

// Re-export DTLS types.
pub use dtls::{
    DtlsError, DtlsSession, SessionState, SessionConfig,
    CipherSuite as DtlsCipherSuite, KeyMaterial as DtlsKeyMaterial,
    SrtpProfile, RecordLayer, ContentType,
    HandshakeType, HandshakeState,
};

// Re-export SRTP types.
pub use srtp::{
    SrtpContext, SrtpSession, SrtpSessionPool, SrtpStats,
    SrtpError, SrtpKeys, KeyDerivation,
    KeyMaterial as SrtpKeyMaterial,
    ReplayProtection, AesGcmCipher, AesCmHmacCipher, SrtpCipher,
    CipherSuite as SrtpCipherSuite,
};

// Re-export socket configuration types.
pub use socket_config::{
    configure_socket_buffers, configure_high_performance_socket,
    enable_gro, check_gso_available,
    SocketBufferInfo, DEFAULT_BUFFER_SIZE, MIN_ACCEPTABLE_BUFFER_SIZE,
};

// Re-export GRO types.
pub use gro::{
    GroSplitter, GroPacketIterator, GroStats,
    parse_gro_size_from_cmsg,
    MAX_GRO_SEGMENT_SIZE, MIN_GRO_SEGMENT_SIZE,
};

// Re-export GSO types.
pub use gso::{
    GsoBatchSender, GsoStats, GsoStatsSnapshot,
    MAX_GSO_SEGMENTS, MAX_GSO_BUFFER_SIZE,
};

// Re-export media transport types.
pub use media_transport::{
    MediaTransport, TransportMode, MediaRecvPacket,
};

// Re-export TURN types.
pub use turn::{
    TurnClient, TurnClientConfig, TurnError,
    Allocation, AllocationState,
    TurnCredentials, TurnServerInfo, Permission, ChannelBinding,
    RelayedAddress, TransportProtocol,
    DEFAULT_ALLOCATION_LIFETIME, MAX_ALLOCATION_LIFETIME, MIN_ALLOCATION_LIFETIME,
    PERMISSION_LIFETIME, CHANNEL_BINDING_LIFETIME,
    CHANNEL_NUMBER_MIN, CHANNEL_NUMBER_MAX,
    MAX_PERMISSIONS, MAX_CHANNEL_BINDINGS,
    CHANNEL_DATA_HEADER_SIZE, MAX_TURN_DATA_SIZE,
    REFRESH_MARGIN_SECONDS, TRANSPORT_UDP, TRANSPORT_TCP,
};
