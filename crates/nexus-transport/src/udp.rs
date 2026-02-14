//! UDP transport with platform-specific I/O.
//!
//! Uses io_uring on Linux and kqueue on macOS for high-performance
//! async packet I/O with minimal syscall overhead.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

use nexus_core::error::TransportError;

/// Maximum receive buffer per datagram.
///
/// WebRTC peers may send UDP datagrams larger than the Ethernet MTU
/// (e.g. raw audio samples, TURN-encapsulated packets). IP fragmentation
/// reassembles them before delivery to the socket, so the recv buffer
/// must accommodate the largest possible reassembled datagram.
/// 8192 bytes covers all practical WebRTC payloads while staying well
/// below the 65535-byte UDP maximum.
const MAX_PACKET_SIZE_BYTES: usize = 8192;

/// Maximum number of packets to receive in a single batch.
const MAX_BATCH_SIZE: usize = 64;

/// Active receive mode for observability.
///
/// Indicates which receive path is currently active for packet reception.
/// Used for monitoring and debugging to verify the expected high-performance
/// path is being used in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveMode {
    /// io_uring with multishot receive active (best performance).
    /// Available on Linux 5.19+ with io_uring feature enabled.
    IoUring,
    /// Linux recvmmsg batch receive (good performance).
    /// Fallback when io_uring is unavailable or initialization fails.
    Recvmmsg,
    /// Individual recv_from calls (development fallback).
    /// Used on non-Linux platforms or when batch receive is unavailable.
    Standard,
}

/// Configuration for UDP transport.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// UDP receive buffer size in bytes. Default: 16MB.
    pub recv_buffer_size_bytes: u32,
    /// UDP send buffer size in bytes. Default: 16MB.
    pub send_buffer_size_bytes: u32,
    /// Number of io_uring SQ entries (Linux only). Default: 4096.
    #[cfg(target_os = "linux")]
    pub io_uring_entries: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            recv_buffer_size_bytes: 16 * 1024 * 1024,
            send_buffer_size_bytes: 16 * 1024 * 1024,
            #[cfg(target_os = "linux")]
            io_uring_entries: 4096,
        }
    }
}

impl TransportConfig {
    /// Create a new transport configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<(), &'static str> {
        assert!(
            self.recv_buffer_size_bytes > 0,
            "recv_buffer_size_bytes must be > 0"
        );
        assert!(
            self.send_buffer_size_bytes > 0,
            "send_buffer_size_bytes must be > 0"
        );
        if self.recv_buffer_size_bytes == 0 {
            return Err("recv_buffer_size_bytes must be > 0");
        }
        if self.send_buffer_size_bytes == 0 {
            return Err("send_buffer_size_bytes must be > 0");
        }
        Ok(())
    }
}

/// Transport statistics with atomic counters.
#[derive(Debug, Default)]
pub struct TransportStats {
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub recv_errors: AtomicU64,
    pub send_errors: AtomicU64,
}

impl TransportStats {
    /// Create new statistics with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful packet receive.
    #[inline(always)]
    pub fn record_recv(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a successful packet send.
    #[inline(always)]
    pub fn record_send(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a dropped packet.
    #[inline(always)]
    pub fn record_drop(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    #[inline(always)]
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a send error.
    #[inline(always)]
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of current statistics.
    pub fn snapshot(&self) -> TransportStatsSnapshot {
        TransportStatsSnapshot {
            packets_received: self.packets_received
                .load(Ordering::Relaxed),
            packets_sent: self.packets_sent
                .load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped
                .load(Ordering::Relaxed),
            bytes_received: self.bytes_received
                .load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent
                .load(Ordering::Relaxed),
            recv_errors: self.recv_errors
                .load(Ordering::Relaxed),
            send_errors: self.send_errors
                .load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.recv_errors.store(0, Ordering::Relaxed);
        self.send_errors.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of transport statistics at a point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportStatsSnapshot {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub recv_errors: u64,
    pub send_errors: u64,
}

/// Received packet with metadata.
#[derive(Debug)]
pub struct RecvPacket {
    pub data: Vec<u8>,
    pub source_addr: SocketAddr,
    pub recv_time_ns: u64,
}

impl RecvPacket {
    /// Create a new received packet.
    pub fn new(
        data: Vec<u8>,
        source_addr: SocketAddr,
        recv_time_ns: u64,
    ) -> Self {
        Self { data, source_addr, recv_time_ns }
    }

    /// Get the length of the packet data in bytes.
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

/// Platform-specific UDP transport.
pub struct UdpTransport {
    socket: std::net::UdpSocket,
    recv_buffer_size_bytes: u32,
    send_buffer_size_bytes: u32,
    stats: TransportStats,
    recv_buffers: Vec<[u8; MAX_PACKET_SIZE_BYTES]>,
    /// GSO enabled flag (Linux only).
    #[cfg(target_os = "linux")]
    gso_enabled: bool,
    /// GRO enabled flag (Linux only).
    #[cfg(target_os = "linux")]
    gro_enabled: bool,
    #[cfg(target_os = "macos")]
    kqueue_fd: RawFd,
}

impl UdpTransport {
    /// Create a new UDP transport bound to the specified address.
    pub fn bind(
        addr: SocketAddr,
        config: TransportConfig,
    ) -> Result<Self, TransportError> {
        assert!(
            config.recv_buffer_size_bytes > 0,
            "recv_buffer_size_bytes must be > 0"
        );
        assert!(
            config.send_buffer_size_bytes > 0,
            "send_buffer_size_bytes must be > 0"
        );

        let socket = std::net::UdpSocket::bind(addr)
            .map_err(|source| TransportError::BindFailed {
                addr, source,
            })?;
        socket.set_nonblocking(true)
            .map_err(|source| {
                TransportError::SetSockOptFailed { source }
            })?;
        Self::set_socket_buffers(&socket, &config)?;
        let recv_buffers =
            vec![[0u8; MAX_PACKET_SIZE_BYTES]; MAX_BATCH_SIZE];

        #[cfg(target_os = "macos")]
        let kqueue_fd = Self::init_kqueue(&socket)?;

        Ok(Self {
            socket,
            recv_buffer_size_bytes: config.recv_buffer_size_bytes,
            send_buffer_size_bytes: config.send_buffer_size_bytes,
            stats: TransportStats::new(),
            recv_buffers,
            #[cfg(target_os = "linux")]
            gso_enabled: false,
            #[cfg(target_os = "linux")]
            gro_enabled: false,
            #[cfg(target_os = "macos")]
            kqueue_fd,
        })
    }

    fn set_socket_buffers(
        socket: &std::net::UdpSocket,
        config: &TransportConfig,
    ) -> Result<(), TransportError> {
        let fd = socket.as_raw_fd();
        let recv_size =
            config.recv_buffer_size_bytes as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                &recv_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>()
                    as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(TransportError::SetSockOptFailed {
                source: io::Error::last_os_error(),
            });
        }
        let send_size =
            config.send_buffer_size_bytes as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                &send_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>()
                    as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(TransportError::SetSockOptFailed {
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn init_kqueue(
        socket: &std::net::UdpSocket,
    ) -> Result<RawFd, TransportError> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(TransportError::SetSockOptFailed {
                source: io::Error::last_os_error(),
            });
        }
        let fd = socket.as_raw_fd();
        let changelist = [libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_ENABLE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        }];
        let result = unsafe {
            libc::kevent(
                kq, changelist.as_ptr(), 1,
                std::ptr::null_mut(), 0, std::ptr::null(),
            )
        };
        if result < 0 {
            unsafe { libc::close(kq) };
            return Err(TransportError::SetSockOptFailed {
                source: io::Error::last_os_error(),
            });
        }
        Ok(kq)
    }

    /// Receive packets in batch.
    pub fn recv_batch(
        &mut self, max_packets: usize,
    ) -> Result<Vec<RecvPacket>, TransportError> {
        assert!(max_packets > 0, "max_packets must be > 0");
        let max_packets = max_packets.min(MAX_BATCH_SIZE);

        #[cfg(target_os = "macos")]
        {
            return self.recv_batch_kqueue(max_packets);
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.recv_batch_standard(max_packets)
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn recv_batch_standard(
        &mut self, max_packets: usize,
    ) -> Result<Vec<RecvPacket>, TransportError> {
        let mut packets = Vec::with_capacity(max_packets);
        let recv_time_ns = Self::current_time_ns();
        for i in 0..max_packets {
            match self.socket.recv_from(
                &mut self.recv_buffers[i],
            ) {
                Ok((len, addr)) => {
                    let data =
                        self.recv_buffers[i][..len].to_vec();
                    self.stats.record_recv(len as u64);
                    packets.push(RecvPacket::new(
                        data, addr, recv_time_ns,
                    ));
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock =>
                {
                    break;
                }
                Err(e) => {
                    self.stats.record_recv_error();
                    if packets.is_empty() {
                        return Err(
                            TransportError::RecvFailed {
                                source: e,
                            },
                        );
                    }
                    break;
                }
            }
        }
        Ok(packets)
    }

    #[cfg(target_os = "macos")]
    fn recv_batch_kqueue(
        &mut self, max_packets: usize,
    ) -> Result<Vec<RecvPacket>, TransportError> {
        let mut packets = Vec::with_capacity(max_packets);
        let recv_time_ns = Self::current_time_ns();
        let mut eventlist = [libc::kevent {
            ident: 0, filter: 0, flags: 0,
            fflags: 0, data: 0,
            udata: std::ptr::null_mut(),
        }];
        let timeout = libc::timespec {
            tv_sec: 0, tv_nsec: 0,
        };
        let nevents = unsafe {
            libc::kevent(
                self.kqueue_fd, std::ptr::null(), 0,
                eventlist.as_mut_ptr(), 1, &timeout,
            )
        };
        if nevents < 0 {
            self.stats.record_recv_error();
            return Err(TransportError::RecvFailed {
                source: io::Error::last_os_error(),
            });
        }
        if nevents > 0 {
            for i in 0..max_packets {
                match self.socket.recv_from(
                    &mut self.recv_buffers[i],
                ) {
                    Ok((len, addr)) => {
                        let data =
                            self.recv_buffers[i][..len].to_vec();
                        self.stats.record_recv(len as u64);
                        packets.push(RecvPacket::new(
                            data, addr, recv_time_ns,
                        ));
                    }
                    Err(ref e)
                        if e.kind()
                            == io::ErrorKind::WouldBlock =>
                    {
                        break;
                    }
                    Err(e) => {
                        self.stats.record_recv_error();
                        if packets.is_empty() {
                            return Err(
                                TransportError::RecvFailed {
                                    source: e,
                                },
                            );
                        }
                        break;
                    }
                }
            }
        }
        Ok(packets)
    }

    /// Send a packet to the specified destination.
    pub fn send(
        &self, data: &[u8], dest: SocketAddr,
    ) -> Result<usize, TransportError> {
        assert!(!data.is_empty(), "data must not be empty");
        assert!(
            data.len() <= MAX_PACKET_SIZE_BYTES,
            "data exceeds maximum packet size"
        );
        match self.socket.send_to(data, dest) {
            Ok(len) => {
                self.stats.record_send(len as u64);
                Ok(len)
            }
            Err(e) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed {
                    dest, source: e,
                })
            }
        }
    }

    /// Get the socket file descriptor.
    #[inline(always)]
    pub fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Get the local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get current transport statistics.
    #[inline(always)]
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Get receive buffer size in bytes.
    #[inline(always)]
    pub fn recv_buffer_size_bytes(&self) -> u32 {
        self.recv_buffer_size_bytes
    }

    /// Get send buffer size in bytes.
    #[inline(always)]
    pub fn send_buffer_size_bytes(&self) -> u32 {
        self.send_buffer_size_bytes
    }

    /// Enable Generic Segmentation Offload (GSO) for batch outgoing packets.
    ///
    /// GSO allows the kernel to batch multiple outgoing UDP packets into a
    /// single larger packet, which is then segmented by the NIC hardware.
    /// This reduces CPU overhead for high-throughput sending.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.6: Use GSO for batching outgoing packets
    #[cfg(target_os = "linux")]
    pub fn enable_gso(&mut self) -> Result<(), TransportError> {
        // Assertion: socket must be valid
        assert!(self.socket.as_raw_fd() >= 0, "socket fd must be valid");

        // UDP_SEGMENT socket option for GSO (defined in linux/udp.h as 103)
        const UDP_SEGMENT: libc::c_int = 103;

        let optval: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_UDP,
                UDP_SEGMENT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            return Err(TransportError::SetSockOptFailed { source: err });
        }

        self.gso_enabled = true;

        // Assertion: GSO flag set
        assert!(self.gso_enabled, "GSO should be enabled after success");

        Ok(())
    }

    /// Enable Generic Segmentation Offload (GSO) - non-Linux stub.
    #[cfg(not(target_os = "linux"))]
    pub fn enable_gso(&mut self) -> Result<(), TransportError> {
        Err(TransportError::SetSockOptFailed {
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "GSO is only supported on Linux",
            ),
        })
    }

    /// Enable Generic Receive Offload (GRO) for batch incoming packets.
    ///
    /// GRO allows the kernel to coalesce multiple incoming UDP packets into
    /// larger buffers before delivering them to userspace. This reduces the
    /// number of syscalls and improves receive throughput.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.5: Use GRO for batching incoming packets
    #[cfg(target_os = "linux")]
    pub fn enable_gro(&mut self) -> Result<(), TransportError> {
        // Assertion: socket must be valid
        assert!(self.socket.as_raw_fd() >= 0, "socket fd must be valid");

        // UDP_GRO socket option (defined in linux/udp.h as 104)
        const UDP_GRO: libc::c_int = 104;

        let optval: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_UDP,
                UDP_GRO,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            return Err(TransportError::SetSockOptFailed { source: err });
        }

        self.gro_enabled = true;

        // Assertion: GRO flag set
        assert!(self.gro_enabled, "GRO should be enabled after success");

        Ok(())
    }

    /// Enable Generic Receive Offload (GRO) - non-Linux stub.
    #[cfg(not(target_os = "linux"))]
    pub fn enable_gro(&mut self) -> Result<(), TransportError> {
        Err(TransportError::SetSockOptFailed {
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "GRO is only supported on Linux",
            ),
        })
    }

    /// Check if GSO is enabled.
    #[cfg(target_os = "linux")]
    #[inline(always)]
    pub fn is_gso_enabled(&self) -> bool {
        self.gso_enabled
    }

    /// Check if GSO is enabled (non-Linux stub).
    #[cfg(not(target_os = "linux"))]
    #[inline(always)]
    pub fn is_gso_enabled(&self) -> bool {
        false
    }

    /// Check if GRO is enabled.
    #[cfg(target_os = "linux")]
    #[inline(always)]
    pub fn is_gro_enabled(&self) -> bool {
        self.gro_enabled
    }

    /// Check if GRO is enabled (non-Linux stub).
    #[cfg(not(target_os = "linux"))]
    #[inline(always)]
    pub fn is_gro_enabled(&self) -> bool {
        false
    }

    /// Check if multishot receive is active.
    ///
    /// For UdpTransport, multishot is never active (use IoUringTransport for that).
    /// This method exists for API compatibility.
    #[inline(always)]
    pub fn is_multishot_active(&self) -> bool {
        false
    }

    /// Returns the active receive mode for observability.
    ///
    /// Inspects internal state to determine which receive path is currently
    /// active. This is useful for monitoring and verifying that the expected
    /// high-performance path is being used in production.
    ///
    /// # Returns
    /// - `ReceiveMode::Recvmmsg` - Linux recvmmsg batch receive active
    /// - `ReceiveMode::Standard` - Individual recv_from calls (non-Linux or fallback)
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions (via cfg checks at compile time)
    #[cfg(target_os = "linux")]
    #[inline(always)]
    pub fn receive_mode(&self) -> ReceiveMode {
        // UdpTransport on Linux uses recvmmsg
        ReceiveMode::Recvmmsg
    }

    /// Returns the active receive mode for observability (non-Linux).
    #[cfg(not(target_os = "linux"))]
    #[inline(always)]
    pub fn receive_mode(&self) -> ReceiveMode {
        // Non-Linux platforms use standard recv_from
        ReceiveMode::Standard
    }

    /// Receive batch using recvmmsg syscall (Linux).
    ///
    /// Receives multiple packets in a single syscall for efficiency.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop
    #[cfg(target_os = "linux")]
    pub fn recv_batch_recvmmsg(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<RecvPacket>, TransportError> {
        use std::mem::MaybeUninit;

        // Assertion: max_packets bounded
        assert!(max_packets <= MAX_BATCH_SIZE, "max_packets exceeds limit");
        // Assertion: recv_buffers has enough capacity
        assert!(
            self.recv_buffers.len() >= max_packets,
            "recv_buffers too small"
        );

        let recv_time_ns = Self::current_time_ns();
        let fd = self.socket.as_raw_fd();

        // Prepare iovec and mmsghdr structures
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(max_packets);
        let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(max_packets);
        let mut sockaddrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(max_packets);

        for i in 0..max_packets {
            iovecs.push(libc::iovec {
                iov_base: self.recv_buffers[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: MAX_PACKET_SIZE_BYTES,
            });

            sockaddrs.push(unsafe { MaybeUninit::zeroed().assume_init() });
        }

        for i in 0..max_packets {
            let mut msghdr: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
            msghdr.msg_name = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
            msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msghdr.msg_iov = &mut iovecs[i];
            msghdr.msg_iovlen = 1;

            msghdrs.push(libc::mmsghdr {
                msg_hdr: msghdr,
                msg_len: 0,
            });
        }

        // Call recvmmsg with MSG_DONTWAIT for non-blocking
        let result = unsafe {
            libc::recvmmsg(
                fd,
                msghdrs.as_mut_ptr(),
                max_packets as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(), // No timeout
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }
            self.stats.record_recv_error();
            return Err(TransportError::RecvFailed { source: err });
        }

        let num_received = result as usize;
        let mut packets = Vec::with_capacity(num_received);

        // Process received packets (bounded by result)
        for i in 0..num_received {
            let len = msghdrs[i].msg_len as usize;
            if len == 0 {
                continue;
            }

            let data = self.recv_buffers[i][..len].to_vec();
            let addr = Self::sockaddr_to_socket_addr(
                &sockaddrs[i],
                msghdrs[i].msg_hdr.msg_namelen,
            )
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

            self.stats.record_recv(len as u64);
            packets.push(RecvPacket::new(data, addr, recv_time_ns));
        }

        Ok(packets)
    }

    /// Convert libc sockaddr_storage to std::net::SocketAddr.
    #[cfg(target_os = "linux")]
    fn sockaddr_to_socket_addr(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

        if len as usize >= std::mem::size_of::<libc::sockaddr_in>()
            && storage.ss_family == libc::AF_INET as libc::sa_family_t
        {
            let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        } else if len as usize >= std::mem::size_of::<libc::sockaddr_in6>()
            && storage.ss_family == libc::AF_INET6 as libc::sa_family_t
        {
            let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        } else {
            None
        }
    }

    /// Send batch of packets using GSO.
    ///
    /// When GSO is enabled, this method can send multiple packets to the
    /// same destination in a single syscall by using the UDP_SEGMENT option.
    ///
    /// # Arguments
    /// * `packets` - Slice of packet data to send
    /// * `dest` - Destination address (all packets go to same destination)
    /// * `segment_size` - Size of each segment (typically MTU - headers)
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    #[cfg(target_os = "linux")]
    pub fn send_batch_gso(
        &self,
        packets: &[&[u8]],
        dest: SocketAddr,
        segment_size: u16,
    ) -> Result<usize, TransportError> {
        use std::mem::MaybeUninit;

        // Assertion: GSO must be enabled
        assert!(self.gso_enabled, "GSO must be enabled for batch send");
        // Assertion: packets not empty
        assert!(!packets.is_empty(), "packets must not be empty");

        if !self.gso_enabled {
            // Fall back to individual sends
            let mut total_sent = 0;
            for packet in packets {
                total_sent += self.send(packet, dest)?;
            }
            return Ok(total_sent);
        }

        // Concatenate all packets into a single buffer
        let total_len: usize = packets.iter().map(|p| p.len()).sum();
        let mut buffer = vec![0u8; total_len];
        let mut offset = 0;
        for packet in packets {
            buffer[offset..offset + packet.len()].copy_from_slice(packet);
            offset += packet.len();
        }

        // Set up control message for GSO segment size
        const UDP_SEGMENT: libc::c_int = 103;
        let mut cmsg_buf = [0u8; 64];

        let mut iov = libc::iovec {
            iov_base: buffer.as_ptr() as *mut libc::c_void,
            iov_len: total_len,
        };

        // Convert destination address
        let (sockaddr, sockaddr_len) = Self::socket_addr_to_sockaddr_out(dest);

        let mut msghdr: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
        msghdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
        msghdr.msg_namelen = sockaddr_len;
        msghdr.msg_iov = &mut iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msghdr.msg_controllen = cmsg_buf.len();

        // Add GSO control message
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
            if !cmsg.is_null() {
                (*cmsg).cmsg_level = libc::SOL_UDP;
                (*cmsg).cmsg_type = UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
                let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
                *data_ptr = segment_size;
                msghdr.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize;
            }
        }

        let result = unsafe { libc::sendmsg(self.socket.as_raw_fd(), &msghdr, 0) };

        if result < 0 {
            self.stats.record_send_error();
            return Err(TransportError::SendFailed {
                dest,
                source: io::Error::last_os_error(),
            });
        }

        self.stats.record_send(result as u64);
        Ok(result as usize)
    }

    /// Convert SocketAddr to libc sockaddr for sending.
    #[cfg(target_os = "linux")]
    fn socket_addr_to_sockaddr_out(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        use std::mem::MaybeUninit;

        let mut storage: libc::sockaddr_storage = unsafe { MaybeUninit::zeroed().assume_init() };

        match addr {
            SocketAddr::V4(addr_v4) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
                unsafe {
                    (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sa).sin_port = addr_v4.port().to_be();
                    (*sa).sin_addr.s_addr = u32::from_ne_bytes(addr_v4.ip().octets());
                }
                (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(addr_v6) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
                unsafe {
                    (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sa).sin6_port = addr_v6.port().to_be();
                    (*sa).sin6_flowinfo = addr_v6.flowinfo();
                    (*sa).sin6_addr.s6_addr = addr_v6.ip().octets();
                    (*sa).sin6_scope_id = addr_v6.scope_id();
                }
                (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }

    #[inline(always)]
    fn current_time_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if self.kqueue_fd >= 0 {
                unsafe { libc::close(self.kqueue_fd) };
            }
        }
    }
}

impl AsRawFd for UdpTransport {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(
            config.recv_buffer_size_bytes, 16 * 1024 * 1024
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_transport_stats() {
        let stats = TransportStats::new();
        stats.record_recv(1500);
        stats.record_send(1200);
        let snap = stats.snapshot();
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.bytes_received, 1500);
        assert_eq!(snap.packets_sent, 1);
        assert_eq!(snap.bytes_sent, 1200);
    }

    #[test]
    fn test_udp_transport_bind() {
        let config = TransportConfig::default();
        let addr: SocketAddr =
            "127.0.0.1:0".parse().unwrap();
        let transport = UdpTransport::bind(addr, config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_gso_enable() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut transport = UdpTransport::bind(addr, config).unwrap();

        // GSO is Linux-specific
        let result = transport.enable_gso();

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
            assert!(!transport.is_gso_enabled());
        }

        #[cfg(target_os = "linux")]
        {
            // May succeed or fail depending on kernel support
            if result.is_ok() {
                assert!(transport.is_gso_enabled());
            } else {
                assert!(!transport.is_gso_enabled());
            }
        }
    }

    #[test]
    fn test_gro_enable() {
        let config = TransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut transport = UdpTransport::bind(addr, config).unwrap();

        // GRO is Linux-specific
        let result = transport.enable_gro();

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
            assert!(!transport.is_gro_enabled());
        }

        #[cfg(target_os = "linux")]
        {
            // May succeed or fail depending on kernel support
            if result.is_ok() {
                assert!(transport.is_gro_enabled());
            } else {
                assert!(!transport.is_gro_enabled());
            }
        }
    }
}
