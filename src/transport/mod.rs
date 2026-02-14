//! UDP Transport Layer for Nexus SFU.
//!
//! # Transport Selection (io_uring-first)
//!
//! Similar to signaling (QUIC-first with WebSocket fallback), the transport
//! layer uses io_uring as the default on Linux with automatic fallback:
//!
//! 1. **io_uring** (default on Linux): High-performance kernel-bypassing I/O
//!    - SQPOLL for kernel-side submission polling
//!    - Multishot receive for batch packet reception
//!    - 16MB socket buffers, GRO, GSO enabled
//!
//! 2. **recvmmsg/sendmmsg** (fallback): Standard batch syscalls
//!    - Used when io_uring is unavailable or fails
//!    - Also used on non-Linux platforms (macOS uses kqueue)
//!
//! The canonical implementation now lives in `crates/nexus-transport/`.
//! This module provides backward-compatible re-exports.
//!
//! # XDP Support
//!
//! On Linux with the `xdp` feature enabled, this module also provides
//! AF_XDP socket support for zero-copy packet I/O.

// Re-export all transport types from nexus-transport crate
pub use nexus_transport::batch::{BatchSender, BatchSenderStats, BatchSenderStatsSnapshot};
pub use nexus_transport::udp::{
    ReceiveMode, RecvPacket, TransportConfig, TransportStats, TransportStatsSnapshot, UdpTransport,
};
pub use nexus_transport::media_transport::{MediaTransport, TransportMode, MediaRecvPacket};
pub use nexus_transport::io_uring::{
    IoUringTransport, IoUringConfig, IoUringRecvPacket, IoUringStats, IoUringStatsSnapshot,
    IoUringReceiveMode, create_transport_with_fallback,
};

// XDP support (Linux only, stays in src/ as it's application-specific)
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub mod af_xdp;

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use af_xdp::{
    AfXdpConfig, AfXdpPacket, AfXdpSocket, AfXdpStats, AfXdpStatsSnapshot, DEFAULT_FRAME_SIZE,
    DEFAULT_NUM_FRAMES, MAX_BATCH_PACKETS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.recv_buffer_size_bytes, 16 * 1024 * 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_transport_stats_new() {
        let stats = TransportStats::new();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_received, 0);
    }

    #[test]
    fn test_udp_transport_bind() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = UdpTransport::bind(addr, config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_batch_sender_is_available() {
        let available = BatchSender::is_batch_send_available();
        #[cfg(target_os = "linux")]
        assert!(available);
        #[cfg(not(target_os = "linux"))]
        assert!(!available);
    }

    #[test]
    fn test_media_transport_bind() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = MediaTransport::bind(addr, config);
        assert!(transport.is_ok());
    }
}
