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
//! The protocol pieces the SFU's two planes share:
//!
//! - `srtp` — SRTP/SRTCP per direction (`SrtpInbound`, `SrtpOutbound`, used by the
//!   shard) and `SrtpContext` (the reference the tests and peers use)
//! - `dtls` — the OpenSSL DTLS engine the control plane runs handshakes with, its
//!   shared certificate, and the exported SRTP keying material
//! - `ice` — STUN encoding, parsing and integrity (the shard's STUN scan and the test
//!   peers), candidates, and host interface enumeration
//! - `socket_config` — socket buffer sizes (and GRO/GSO options, unused by the shard)
//! - `gro`, `gso` — GRO splitting and GSO sending helpers (not used by the shard)
//!
//! The old data plane's transport (arena, ring buffer, UDP and io_uring transports,
//! batch sender, ICE agent, pure-Rust DTLS) was removed in Phase 1 (C5).

pub mod dtls;
pub mod gro;
pub mod gso;
pub mod ice;
pub mod socket_config;
pub mod srtp;

// Re-export ICE types.
pub use ice::{
    Candidate, CandidateGatherer, CandidatePair, CandidatePairState, CandidateType,
    GatheredCandidates, GatheringState, IceConfig, IceConnectionState, IceCredentials, IceError,
    IceGatheringState, IceRole, StunAttribute, StunClass, StunMessage, StunMethod,
};

// Re-export DTLS types.
pub use dtls::{
    DtlsCertificate, DtlsError, DtlsRole, OpenSslDtlsEngine,
    SrtpKeyMaterial as DtlsSrtpKeyMaterial, SrtpProfile,
};

// Re-export SRTP types.
pub use srtp::{
    AesCmHmacCipher, AesGcmCipher, CipherSuite as SrtpCipherSuite, KeyDerivation,
    KeyMaterial as SrtpKeyMaterial, ReplayProtection, SrtpCipher, SrtpContext, SrtpError,
    SrtpInbound, SrtpKeys, SrtpOutbound, SrtpSession, SrtpSessionPool, SrtpStats,
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
