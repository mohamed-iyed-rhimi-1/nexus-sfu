//! UDP transport for SWIM gossip protocol.
//!
//! This module provides `GossipTransport` for sending and receiving gossip
//! messages over UDP. It supports batch sending via `sendmmsg` on Linux
//! for improved performance.
//!
//! ## Features
//!
//! - Non-blocking UDP socket with configurable buffer sizes
//! - Batch sending using sendmmsg on Linux (falls back to sendto on other platforms)
//! - Atomic statistics for monitoring
//!
//! ## TigerStyle Compliance
//!
//! - All buffer sizes are bounded by constants
//! - Socket operations have explicit error handling
//! - Atomic counters for lock-free statistics

use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use super::types::{GossipMessage, MAX_MESSAGE_SIZE};
use crate::error::GossipError;

/// Maximum batch size for sendmmsg operations
const MAX_BATCH_SIZE: usize = 64;

/// Default socket buffer size (1MB)
const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024;

/// Statistics for transport operations.
///
/// All counters are atomic for lock-free access from multiple threads.
#[derive(Debug, Default)]
pub struct TransportStats {
    /// Total messages sent successfully
    pub messages_sent: AtomicU64,
    /// Total messages received successfully
    pub messages_received: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total send errors
    pub send_errors: AtomicU64,
    /// Total receive errors
    pub recv_errors: AtomicU64,
}

impl TransportStats {
    /// Create new statistics with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful send.
    #[inline]
    pub fn record_send(&self, bytes: u64) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a send error.
    #[inline]
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful receive.
    #[inline]
    pub fn record_recv(&self, bytes: u64) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a receive error.
    #[inline]
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> TransportStatsSnapshot {
        TransportStatsSnapshot {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.send_errors.store(0, Ordering::Relaxed);
        self.recv_errors.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of transport statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportStatsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
}

/// UDP transport for gossip messages.
///
/// Handles sending and receiving gossip messages over UDP with support
/// for batch sending on Linux.
pub struct GossipTransport {
    /// UDP socket for communication
    socket: UdpSocket,
    /// Raw file descriptor for sendmmsg syscall (Linux only)
    #[cfg(target_os = "linux")]
    socket_fd: std::os::fd::RawFd,
    /// Local bind address
    local_addr: SocketAddr,
    /// Reusable send buffer
    send_buffer: [u8; MAX_MESSAGE_SIZE],
    /// Reusable receive buffer
    recv_buffer: [u8; MAX_MESSAGE_SIZE],
    /// Transport statistics
    stats: TransportStats,
}

impl GossipTransport {
    /// Create a new transport bound to the given address.
    ///
    /// # Arguments
    /// * `bind_addr` - Address to bind the UDP socket to
    ///
    /// # Returns
    /// A new transport instance or an error
    ///
    /// # Errors
    /// Returns `GossipError::Transport` if socket creation fails
    pub fn new(bind_addr: SocketAddr) -> Result<Self, GossipError> {
        // Create UDP socket
        let socket = UdpSocket::bind(bind_addr)?;

        // Set non-blocking mode
        socket.set_nonblocking(true)?;

        // Set socket buffer sizes
        Self::set_socket_buffers(&socket)?;

        // Get actual bound address (in case port 0 was used)
        let local_addr = socket.local_addr()?;

        // Get raw file descriptor (Linux only for sendmmsg)
        #[cfg(target_os = "linux")]
        let socket_fd = {
            let fd = socket.as_raw_fd();
            // Postcondition: socket_fd is valid
            assert!(fd >= 0, "socket_fd must be valid (>= 0)");
            fd
        };

        Ok(Self {
            socket,
            #[cfg(target_os = "linux")]
            socket_fd,
            local_addr,
            send_buffer: [0u8; MAX_MESSAGE_SIZE],
            recv_buffer: [0u8; MAX_MESSAGE_SIZE],
            stats: TransportStats::new(),
        })
    }

    /// Set socket send and receive buffer sizes.
    fn set_socket_buffers(socket: &UdpSocket) -> Result<(), io::Error> {
        // Platform-specific buffer sizing
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let size = DEFAULT_BUFFER_SIZE as libc::c_int;

            unsafe {
                let result = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if result < 0 {
                    // Non-fatal: continue with default buffer size
                }

                let result = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if result < 0 {
                    // Non-fatal: continue with default buffer size
                }
            }
        }

        Ok(())
    }

    /// Returns the local address the socket is bound to.
    #[inline]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a reference to the transport statistics.
    #[inline]
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Send a message to the specified destination.
    ///
    /// # Arguments
    /// * `msg` - Message to send
    /// * `dest` - Destination address
    ///
    /// # Returns
    /// `Ok(())` on success, or error
    pub fn send(&mut self, msg: &GossipMessage, dest: SocketAddr) -> Result<(), GossipError> {
        let encoded = msg.encode();
        let size = encoded.len();

        // Precondition: message fits in buffer
        assert!(size > 0, "encoded message must not be empty");
        assert!(
            size <= MAX_MESSAGE_SIZE,
            "encoded message size {} exceeds MAX_MESSAGE_SIZE {}",
            size,
            MAX_MESSAGE_SIZE
        );

        // Copy to send buffer (for potential retries)
        self.send_buffer[..size].copy_from_slice(&encoded);

        match self.socket.send_to(&self.send_buffer[..size], dest) {
            Ok(sent) => {
                self.stats.record_send(sent as u64);
                Ok(())
            }
            Err(e) => {
                self.stats.record_send_error();
                // WouldBlock is expected in non-blocking mode
                if e.kind() == ErrorKind::WouldBlock {
                    return Ok(()); // Silently drop - will retry next cycle
                }
                Err(GossipError::Transport(e))
            }
        }
    }

    /// Send multiple messages in a batch.
    ///
    /// Uses sendmmsg on Linux for efficiency, falls back to individual
    /// sends on other platforms.
    ///
    /// # Arguments
    /// * `messages` - Slice of (message, destination) pairs
    ///
    /// # Returns
    /// Number of messages sent successfully
    ///
    /// # Panics
    /// Panics if `messages.len() > MAX_BATCH_SIZE`
    pub fn send_batch(&mut self, messages: &[(GossipMessage, SocketAddr)]) -> Result<u32, GossipError> {
        assert!(
            messages.len() <= MAX_BATCH_SIZE,
            "batch size {} exceeds MAX_BATCH_SIZE {}",
            messages.len(),
            MAX_BATCH_SIZE
        );

        if messages.is_empty() {
            return Ok(0);
        }

        #[cfg(target_os = "linux")]
        {
            self.send_batch_sendmmsg(messages)
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.send_batch_sendto(messages)
        }
    }

    /// Send batch using sendmmsg on Linux.
    #[cfg(target_os = "linux")]
    fn send_batch_sendmmsg(&mut self, messages: &[(GossipMessage, SocketAddr)]) -> Result<u32, GossipError> {
        let num_messages = messages.len();

        // Encode all messages
        let mut encoded_messages: Vec<Vec<u8>> = Vec::with_capacity(num_messages);
        for (msg, _) in messages {
            encoded_messages.push(msg.encode());
        }

        // Prepare iovec and mmsghdr structures
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(num_messages);
        let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(num_messages);
        let mut sockaddrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(num_messages);
        let mut sockaddr_lens: Vec<libc::socklen_t> = Vec::with_capacity(num_messages);

        for (i, (_, dest)) in messages.iter().enumerate() {
            // Create iovec for packet data
            let iov = libc::iovec {
                iov_base: encoded_messages[i].as_ptr() as *mut libc::c_void,
                iov_len: encoded_messages[i].len(),
            };
            iovecs.push(iov);

            // Create sockaddr for destination
            let mut storage: libc::sockaddr_storage = unsafe { MaybeUninit::zeroed().assume_init() };
            let sockaddr_len = match dest {
                SocketAddr::V4(addr) => {
                    let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
                    unsafe {
                        (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                        (*sa).sin_port = addr.port().to_be();
                        (*sa).sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
                    }
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                }
                SocketAddr::V6(addr) => {
                    let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
                    unsafe {
                        (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                        (*sa).sin6_port = addr.port().to_be();
                        (*sa).sin6_flowinfo = addr.flowinfo();
                        (*sa).sin6_addr.s6_addr = addr.ip().octets();
                        (*sa).sin6_scope_id = addr.scope_id();
                    }
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                }
            };
            sockaddrs.push(storage);
            sockaddr_lens.push(sockaddr_len);
        }

        // Build mmsghdr array
        for i in 0..iovecs.len() {
            let mut msghdr: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
            msghdr.msg_name = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
            msghdr.msg_namelen = sockaddr_lens[i];
            msghdr.msg_iov = &mut iovecs[i];
            msghdr.msg_iovlen = 1;

            let mmsghdr = libc::mmsghdr {
                msg_hdr: msghdr,
                msg_len: 0,
            };
            msghdrs.push(mmsghdr);
        }

        // Call sendmmsg
        let result = unsafe {
            libc::sendmmsg(
                self.socket_fd,
                msghdrs.as_mut_ptr(),
                msghdrs.len() as libc::c_uint,
                0,
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            self.stats.send_errors.fetch_add(num_messages as u64, Ordering::Relaxed);
            return Err(GossipError::Transport(err));
        }

        let sent = result as u32;
        let failed = (num_messages as u32).saturating_sub(sent);

        // Update statistics
        let mut total_bytes = 0u64;
        for i in 0..(sent as usize) {
            total_bytes += encoded_messages[i].len() as u64;
        }
        self.stats.messages_sent.fetch_add(sent as u64, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(total_bytes, Ordering::Relaxed);
        self.stats.send_errors.fetch_add(failed as u64, Ordering::Relaxed);

        Ok(sent)
    }

    /// Send batch using individual sendto calls (fallback for non-Linux).
    #[cfg(not(target_os = "linux"))]
    fn send_batch_sendto(&mut self, messages: &[(GossipMessage, SocketAddr)]) -> Result<u32, GossipError> {
        let mut sent = 0u32;

        for (msg, dest) in messages {
            match self.send(msg, *dest) {
                Ok(()) => sent += 1,
                Err(_) => {
                    // Continue with remaining messages
                }
            }
        }

        Ok(sent)
    }

    /// Receive a message (non-blocking).
    ///
    /// # Returns
    /// `Ok((message, source_addr))` if a message was received,
    /// `Err` with WouldBlock if no message available,
    /// `Err` with other error on failure.
    pub fn recv(&mut self) -> Result<(GossipMessage, SocketAddr), GossipError> {
        match self.socket.recv_from(&mut self.recv_buffer) {
            Ok((size, source)) => {
                assert!(size > 0, "received message must not be empty");

                self.stats.record_recv(size as u64);

                let msg = GossipMessage::decode(&self.recv_buffer[..size])
                    .map_err(|e| GossipError::InvalidMessage { reason: e.to_string() })?;

                Ok((msg, source))
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock {
                    self.stats.record_recv_error();
                }
                Err(GossipError::Transport(e))
            }
        }
    }

    /// Receive a message with timeout.
    ///
    /// # Arguments
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Returns
    /// `Ok((message, source_addr))` if a message was received,
    /// `Err` if timeout or error.
    pub fn recv_timeout(&mut self, timeout_ms: u64) -> Result<(GossipMessage, SocketAddr), GossipError> {
        // Set timeout
        let timeout = Duration::from_millis(timeout_ms);
        self.socket.set_read_timeout(Some(timeout))?;

        let result = self.recv();

        // Restore non-blocking mode
        self.socket.set_nonblocking(true)?;

        result
    }

    /// Try to receive a message, returning None if no message available.
    ///
    /// This is a convenience method that treats WouldBlock as a normal case.
    pub fn try_recv(&mut self) -> Option<(GossipMessage, SocketAddr)> {
        match self.recv() {
            Ok(result) => Some(result),
            Err(GossipError::Transport(ref e)) if e.kind() == ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::types::StateUpdate;
    use crate::types::Dot;

    fn localhost_addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn test_transport_new() {
        let transport = GossipTransport::new(localhost_addr()).unwrap();
        #[cfg(target_os = "linux")]
        assert!(transport.socket_fd >= 0);
        assert!(transport.local_addr.port() > 0);
    }

    #[test]
    fn test_transport_local_addr() {
        let transport = GossipTransport::new(localhost_addr()).unwrap();
        let addr = transport.local_addr();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_transport_send_recv() {
        let mut transport1 = GossipTransport::new(localhost_addr()).unwrap();
        let mut transport2 = GossipTransport::new(localhost_addr()).unwrap();

        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 42,
            piggyback: vec![],
        };

        // Send from transport1 to transport2
        transport1.send(&msg, transport2.local_addr()).unwrap();

        // Give a small delay for the message to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Receive on transport2
        let (received, source) = transport2.recv_timeout(100).unwrap();

        assert_eq!(received, msg);
        assert_eq!(source.ip(), transport1.local_addr().ip());
    }

    #[test]
    fn test_transport_send_recv_with_piggyback() {
        let mut transport1 = GossipTransport::new(localhost_addr()).unwrap();
        let mut transport2 = GossipTransport::new(localhost_addr()).unwrap();

        let dot = Dot::new(1, 5);
        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 100,
            piggyback: vec![StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: 42,
                dot,
            }],
        };

        transport1.send(&msg, transport2.local_addr()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let (received, _) = transport2.recv_timeout(100).unwrap();
        assert_eq!(received, msg);
    }

    #[test]
    fn test_transport_try_recv_empty() {
        let mut transport = GossipTransport::new(localhost_addr()).unwrap();
        let result = transport.try_recv();
        assert!(result.is_none());
    }

    #[test]
    fn test_transport_stats() {
        let mut transport1 = GossipTransport::new(localhost_addr()).unwrap();
        let transport2 = GossipTransport::new(localhost_addr()).unwrap();

        let msg = GossipMessage::Dead { actor_id: 5 };

        transport1.send(&msg, transport2.local_addr()).unwrap();

        let stats = transport1.stats().snapshot();
        assert_eq!(stats.messages_sent, 1);
        assert!(stats.bytes_sent > 0);
        assert_eq!(stats.send_errors, 0);
    }

    #[test]
    fn test_transport_stats_reset() {
        let stats = TransportStats::new();
        stats.record_send(100);
        stats.record_recv(200);
        stats.record_send_error();

        stats.reset();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.messages_sent, 0);
        assert_eq!(snapshot.bytes_sent, 0);
        assert_eq!(snapshot.messages_received, 0);
        assert_eq!(snapshot.send_errors, 0);
    }

    #[test]
    fn test_send_batch_empty() {
        let mut transport = GossipTransport::new(localhost_addr()).unwrap();
        let sent = transport.send_batch(&[]).unwrap();
        assert_eq!(sent, 0);
    }

    #[test]
    fn test_send_batch_single() {
        let mut transport1 = GossipTransport::new(localhost_addr()).unwrap();
        let mut transport2 = GossipTransport::new(localhost_addr()).unwrap();

        let msg = GossipMessage::Alive {
            actor_id: 3,
            incarnation: 7,
        };

        let sent = transport1
            .send_batch(&[(msg.clone(), transport2.local_addr())])
            .unwrap();
        assert_eq!(sent, 1);

        std::thread::sleep(std::time::Duration::from_millis(10));

        let (received, _) = transport2.recv_timeout(100).unwrap();
        assert_eq!(received, msg);
    }

    #[test]
    fn test_send_batch_multiple() {
        let mut transport1 = GossipTransport::new(localhost_addr()).unwrap();
        let mut transport2 = GossipTransport::new(localhost_addr()).unwrap();

        let messages: Vec<(GossipMessage, SocketAddr)> = (0..5)
            .map(|i| {
                (
                    GossipMessage::Suspect {
                        actor_id: i,
                        incarnation: i * 10,
                    },
                    transport2.local_addr(),
                )
            })
            .collect();

        let sent = transport1.send_batch(&messages).unwrap();
        assert_eq!(sent, 5);

        std::thread::sleep(std::time::Duration::from_millis(50));

        // Receive all messages
        let mut received_count = 0;
        for _ in 0..10 {
            match transport2.try_recv() {
                Some(_) => received_count += 1,
                None => break,
            }
        }
        assert_eq!(received_count, 5);
    }

    #[test]
    #[should_panic(expected = "batch size")]
    fn test_send_batch_exceeds_max() {
        let mut transport = GossipTransport::new(localhost_addr()).unwrap();
        let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let messages: Vec<(GossipMessage, SocketAddr)> = (0..MAX_BATCH_SIZE + 1)
            .map(|i| (GossipMessage::Dead { actor_id: i as u64 }, dest))
            .collect();

        let _ = transport.send_batch(&messages);
    }
}
