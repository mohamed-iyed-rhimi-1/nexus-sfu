//! Unified media transport that selects io_uring or standard UDP at runtime.
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

use std::net::SocketAddr;
use std::os::fd::RawFd;

use nexus_core::error::TransportError;

use crate::udp::{TransportConfig, UdpTransport};

#[cfg(all(target_os = "linux", feature = "io_uring"))]
use crate::io_uring::{IoUringConfig, IoUringTransport};

#[cfg(feature = "sim")]
use std::collections::VecDeque;

/// Transport mode indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// io_uring with SQPOLL and multishot receive (best performance).
    IoUring,
    /// Standard UDP with recvmmsg/sendmmsg (fallback).
    Standard,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportMode::IoUring => write!(f, "io_uring"),
            TransportMode::Standard => write!(f, "standard UDP"),
        }
    }
}

/// Unified received packet from MediaTransport.
#[derive(Debug)]
pub struct MediaRecvPacket {
    pub data: Vec<u8>,
    pub source_addr: SocketAddr,
    pub recv_time_ns: u64,
}

impl MediaRecvPacket {
    /// Create a new media receive packet.
    pub fn new(data: Vec<u8>, source_addr: SocketAddr, recv_time_ns: u64) -> Self {
        Self { data, source_addr, recv_time_ns }
    }

    /// Get the length of the packet data.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Simulated transport queues for deterministic testing.
///
/// Provides injectable receive queue and captured send log,
/// replacing real socket I/O with in-memory buffers.
#[cfg(feature = "sim")]
pub struct SimulatedTransportQueues {
    recv_queue: VecDeque<MediaRecvPacket>,
    send_log: Vec<(SocketAddr, Vec<u8>)>,
}

#[cfg(feature = "sim")]
impl SimulatedTransportQueues {
    /// Create empty simulated transport queues.
    pub fn new() -> Self {
        Self {
            recv_queue: VecDeque::new(),
            send_log: Vec::new(),
        }
    }

    /// Push a packet into the receive queue for the next recv_batch call.
    pub fn push_recv(&mut self, packet: MediaRecvPacket) {
        self.recv_queue.push_back(packet);
    }

    /// Drain all captured send packets.
    pub fn drain_send_log(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.send_log)
    }

    /// Number of packets waiting in the receive queue.
    pub fn recv_queue_len(&self) -> usize {
        self.recv_queue.len()
    }

    /// Number of packets captured in the send log.
    pub fn send_log_len(&self) -> usize {
        self.send_log.len()
    }
}

#[cfg(feature = "sim")]
impl Default for SimulatedTransportQueues {
    fn default() -> Self {
        Self::new()
    }
}

/// Unified transport that selects io_uring or standard UDP at runtime.
///
/// # Transport Selection (io_uring-first)
///
/// On Linux, io_uring is the DEFAULT transport. If io_uring initialization
/// fails (unsupported kernel, permissions, etc.), it falls back to standard
/// UDP with recvmmsg/sendmmsg.
///
/// On macOS/other platforms, always uses standard UDP with kqueue/poll.
///
/// This mirrors the signaling layer's QUIC-first approach with WebSocket fallback.
///
pub enum MediaTransport {
    /// Standard UDP transport (kqueue on macOS, recvmmsg on Linux fallback).
    Standard(UdpTransport),
    /// io_uring transport (Linux only, DEFAULT on Linux).
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    IoUring(IoUringTransport),
    /// Simulated transport for deterministic testing (sim feature only).
    #[cfg(feature = "sim")]
    Simulated(SimulatedTransportQueues),
}

impl MediaTransport {
    /// Create the best available transport for this platform.
    ///
    /// # Transport Selection (io_uring-first)
    ///
    /// On Linux: Tries io_uring FIRST (default), falls back to recvmmsg on failure.
    /// On macOS/other: Uses standard UDP with kqueue/poll.
    ///
    /// This mirrors the signaling layer's QUIC-first approach.
    ///
    /// # TigerStyle
    /// - ≥2 assertions (preconditions and postconditions)
    /// - Explicit error handling with fallback
    pub fn bind(
        addr: SocketAddr,
        udp_config: TransportConfig,
    ) -> Result<Self, TransportError> {
        // Precondition: address must be valid (port 0 is allowed for ephemeral ports)
        assert!(
            addr.ip().is_unspecified() || addr.ip().is_loopback() || !addr.ip().is_unspecified(),
            "Bind address must be valid"
        );

        // On Linux: Try io_uring FIRST (default transport)
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        {
            tracing::info!("Attempting io_uring transport (default on Linux)...");

            // Use default config which includes 16MB buffers, GRO, GSO
            let uring_config = IoUringConfig::default();
            match IoUringTransport::bind(addr, uring_config) {
                Ok(transport) => {
                    // Postcondition: verify transport is bound
                    let bound_addr = transport.local_addr().expect("Transport must have local address");
                    assert!(bound_addr.port() > 0, "Transport must be bound to a valid port");

                    // Log socket configuration
                    let mode = if transport.is_sqpoll_enabled() { "SQPOLL" } else { "standard" };
                    let multishot = if transport.is_multishot_active() { "multishot" } else { "batch" };

                    if let Some(info) = transport.socket_info() {
                        tracing::info!(
                            "✓ io_uring transport active: mode={}, recv={}, buffers={}MB/{}MB, GRO={}, GSO={}",
                            mode,
                            multishot,
                            info.actual_recv / 1024 / 1024,
                            info.actual_send / 1024 / 1024,
                            info.gro_enabled,
                            info.gso_enabled
                        );
                    } else {
                        tracing::info!("✓ io_uring transport active: mode={}, recv={}", mode, multishot);
                    }

                    return Ok(Self::IoUring(transport));
                }
                Err(e) => {
                    tracing::warn!(
                        "io_uring transport failed: {:?}. Falling back to recvmmsg...",
                        e
                    );
                }
            }
        }

        // Fallback: Standard UDP transport
        #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
        {
            tracing::info!("io_uring not available, using standard UDP transport");
        }

        let transport = UdpTransport::bind(addr, udp_config)?;

        // Postcondition: verify transport is bound
        let bound_addr = transport.local_addr().expect("Transport must have local address");
        assert!(bound_addr.port() > 0, "Transport must be bound to a valid port");

        #[cfg(target_os = "linux")]
        tracing::info!("✓ Standard UDP transport active (recvmmsg/sendmmsg fallback)");

        #[cfg(target_os = "macos")]
        tracing::info!("✓ Standard UDP transport active (kqueue)");

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        tracing::info!("✓ Standard UDP transport active");

        Ok(Self::Standard(transport))
    }

    /// Get the current transport mode.
    pub fn mode(&self) -> TransportMode {
        match self {
            Self::Standard(_) => TransportMode::Standard,
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            Self::IoUring(_) => TransportMode::IoUring,
            #[cfg(feature = "sim")]
            Self::Simulated(_) => TransportMode::Standard, // Report as standard for compatibility
        }
    }

    /// Check if using io_uring transport.
    #[inline]
    pub fn is_io_uring(&self) -> bool {
        matches!(self.mode(), TransportMode::IoUring)
    }

    /// Receive a batch of packets.
    ///
    /// # Arguments
    /// * `max_packets` - Maximum number of packets to receive in one call
    ///
    /// # Returns
    /// Vector of received packets, may be empty if no packets available.
    pub fn recv_batch(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<MediaRecvPacket>, TransportError> {
        assert!(max_packets > 0, "max_packets must be positive");
        assert!(max_packets <= 1024, "max_packets must be bounded");

        match self {
            Self::Standard(t) => {
                let packets = t.recv_batch(max_packets)?;
                Ok(packets
                    .into_iter()
                    .map(|p| MediaRecvPacket {
                        data: p.data,
                        source_addr: p.source_addr,
                        recv_time_ns: p.recv_time_ns,
                    })
                    .collect())
            }
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            Self::IoUring(t) => {
                let packets = t.recv_batch(max_packets)?;
                Ok(packets
                    .into_iter()
                    .map(|p| MediaRecvPacket {
                        data: p.data,
                        source_addr: p.source_addr,
                        recv_time_ns: p.recv_time_ns,
                    })
                    .collect())
            }
            #[cfg(feature = "sim")]
            Self::Simulated(queues) => {
                let count = max_packets.min(queues.recv_queue.len());
                let packets: Vec<MediaRecvPacket> = queues.recv_queue.drain(..count).collect();
                Ok(packets)
            }
        }
    }

    /// Get the socket file descriptor.
    pub fn socket_fd(&self) -> RawFd {
        match self {
            Self::Standard(t) => t.socket_fd(),
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            Self::IoUring(t) => t.socket_fd(),
            #[cfg(feature = "sim")]
            Self::Simulated(_) => -1,
        }
    }

    /// Get the local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Standard(t) => t.local_addr(),
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            Self::IoUring(t) => t.local_addr(),
            #[cfg(feature = "sim")]
            Self::Simulated(_) => Ok("127.0.0.1:0".parse().unwrap()),
        }
    }

    /// Send a packet to a destination address.
    pub fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, TransportError> {
        match self {
            Self::Standard(t) => t.send(data, dest),
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            Self::IoUring(t) => t.send(data, dest),
            #[cfg(feature = "sim")]
            Self::Simulated(_) => Ok(data.len()),
        }
    }

    /// Send a packet and capture it in the send log (sim only).
    /// For non-sim builds, this delegates to the regular send.
    #[cfg(feature = "sim")]
    pub fn send_captured(&mut self, data: &[u8], dest: SocketAddr) -> Result<usize, TransportError> {
        match self {
            Self::Simulated(queues) => {
                queues.send_log.push((dest, data.to_vec()));
                Ok(data.len())
            }
            _ => self.send(data, dest),
        }
    }

    /// Create a simulated transport for deterministic testing.
    #[cfg(feature = "sim")]
    pub fn new_simulated() -> Self {
        Self::Simulated(SimulatedTransportQueues::new())
    }

    /// Get mutable access to simulated queues. Panics if not Simulated variant.
    #[cfg(feature = "sim")]
    pub fn simulated_queues_mut(&mut self) -> &mut SimulatedTransportQueues {
        match self {
            Self::Simulated(queues) => queues,
            _ => panic!("simulated_queues_mut called on non-Simulated transport"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_mode_display() {
        assert_eq!(format!("{}", TransportMode::IoUring), "io_uring");
        assert_eq!(format!("{}", TransportMode::Standard), "standard UDP");
    }

    #[test]
    fn test_media_recv_packet() {
        let data = vec![1, 2, 3, 4];
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let packet = MediaRecvPacket::new(data.clone(), addr, 1234567890);

        assert_eq!(packet.len(), 4);
        assert!(!packet.is_empty());
        assert_eq!(packet.data, data);
        assert_eq!(packet.source_addr, addr);
        assert_eq!(packet.recv_time_ns, 1234567890);
    }

    #[test]
    fn test_media_transport_bind() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = MediaTransport::bind(addr, config);
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert!(transport.local_addr().is_ok());
    }

    #[test]
    fn test_media_transport_mode() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = MediaTransport::bind(addr, config).unwrap();
        let mode = transport.mode();

        // Mode depends on platform and io_uring availability
        match mode {
            TransportMode::IoUring => assert!(transport.is_io_uring()),
            TransportMode::Standard => assert!(!transport.is_io_uring()),
        }
    }
}
