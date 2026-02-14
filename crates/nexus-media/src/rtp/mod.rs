//! RTP (Real-time Transport Protocol) packet parsing.
//!
//! Implements parsing and serialization of RTP headers according to
//! RFC 3550. All operations are inline with zero allocation for hot
//! path performance.
//!
//! # SIMD Acceleration
//!
//! The `parse_simd()` method auto-selects the fastest implementation:
//! - **x86_64 with SSE4.1**: 128-bit SIMD loads (~10-15ns/packet)
//! - **aarch64 NEON**: NEON intrinsics (~10-15ns/packet)
//! - **Fallback**: Standard byte-by-byte parsing (~50-80ns/packet)
//!
//! # RTP Header Format (RFC 3550)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           synchronization source (SSRC) identifier            |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! |            contributing source (CSRC) identifiers             |
//! |                             ....                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

pub mod header;
pub mod packet;

pub use header::RtpHeader;
pub use header::{
    RTP_CSRC_SIZE_BYTES, RTP_HEADER_MIN_SIZE_BYTES,
    RTP_MAX_CSRC_COUNT, RTP_VERSION,
};
