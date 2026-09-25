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
pub mod batch;
pub mod dtls;
pub mod gro;
pub mod gso;
pub mod ice;
pub mod io_uring;
pub mod media_transport;
pub mod ring_buffer;
pub mod socket_config;
pub mod srtp;
pub mod turn;
pub mod udp;

#[cfg(test)]
mod arena_proptest;

#[cfg(test)]
mod arena_refcount_proptest;

// Re-export key types at crate root for convenience.
pub use arena::{
    create_partitions, ArenaPartition, PacketArena, PacketSlot, PartitionedPacketSlot,
    SLOT_SIZE_BYTES,
};
pub use batch::{BatchSender, BatchSenderStats, BatchSenderStatsSnapshot};
pub use ring_buffer::RingBuffer;
pub use udp::{
    ReceiveMode, RecvPacket, TransportConfig, TransportStats, TransportStatsSnapshot, UdpTransport,
};

// Re-export io_uring types.
pub use io_uring::{
    create_transport_with_fallback, IoUringConfig, IoUringReceiveMode, IoUringRecvPacket,
    IoUringStats, IoUringStatsSnapshot, IoUringTransport,
};

// Re-export ICE types.
pub use ice::{
    Candidate, CandidateGatherer, CandidatePair, CandidatePairState, CandidateType, Checklist,
    ChecklistState, GatheredCandidates, GatheringState, IceAgent, IceConfig, IceConnectionState,
    IceCredentials, IceError, IceGatheringState, IceRole, StunAttribute, StunClass, StunMessage,
    StunMethod,
};

// Re-export DTLS types.
pub use dtls::{
    CipherSuite as DtlsCipherSuite, ContentType, DtlsError, DtlsSession, HandshakeState,
    HandshakeType, KeyMaterial as DtlsKeyMaterial, RecordLayer, SessionConfig, SessionState,
    SrtpProfile,
};

// Re-export SRTP types.
pub use srtp::{
    AesCmHmacCipher, AesGcmCipher, CipherSuite as SrtpCipherSuite, KeyDerivation,
    KeyMaterial as SrtpKeyMaterial, ReplayProtection, SrtpCipher, SrtpContext, SrtpError, SrtpKeys,
    SrtpSession, SrtpSessionPool, SrtpStats,
};

// Re-export socket configuration types.
pub use socket_config::{
    check_gso_available, configure_high_performance_socket, configure_socket_buffers, enable_gro,
    SocketBufferInfo, DEFAULT_BUFFER_SIZE, MIN_ACCEPTABLE_BUFFER_SIZE,
};

// Re-export GRO types.
pub use gro::{
    parse_gro_size_from_cmsg, GroPacketIterator, GroSplitter, GroStats, MAX_GRO_SEGMENT_SIZE,
    MIN_GRO_SEGMENT_SIZE,
};

// Re-export GSO types.
pub use gso::{GsoBatchSender, GsoStats, GsoStatsSnapshot, MAX_GSO_BUFFER_SIZE, MAX_GSO_SEGMENTS};

// Re-export media transport types.
pub use media_transport::{MediaRecvPacket, MediaTransport, TransportMode};

// Re-export TURN types.
pub use turn::{
    Allocation, AllocationState, ChannelBinding, Permission, RelayedAddress, TransportProtocol,
    TurnClient, TurnClientConfig, TurnCredentials, TurnError, TurnServerInfo,
    CHANNEL_BINDING_LIFETIME, CHANNEL_DATA_HEADER_SIZE, CHANNEL_NUMBER_MAX, CHANNEL_NUMBER_MIN,
    DEFAULT_ALLOCATION_LIFETIME, MAX_ALLOCATION_LIFETIME, MAX_CHANNEL_BINDINGS, MAX_PERMISSIONS,
    MAX_TURN_DATA_SIZE, MIN_ALLOCATION_LIFETIME, PERMISSION_LIFETIME, REFRESH_MARGIN_SECONDS,
    TRANSPORT_TCP, TRANSPORT_UDP,
};
