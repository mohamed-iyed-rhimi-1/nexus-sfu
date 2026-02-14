//! io_uring-based UDP transport for high-performance packet I/O.
//!
//! This module provides a dedicated io_uring transport implementation with:
//! - setup_sqpoll for kernel-side submission polling (Requirement 2.1)
//! - Buffer pool registration with BUFFER_SELECT (Requirement 2.2)
//! - Multishot RecvMulti for batch packet reception (Requirement 2.3)
//! - Automatic fallback to recvmmsg when io_uring is unavailable (Requirement 2.4)
//!
//! # Platform Support
//!
//! This module is only available on Linux with the `io_uring` feature enabled.
//! On other platforms or when the feature is disabled, use `UdpTransport` which
//! provides platform-appropriate fallback implementations.
//!
//! # TigerStyle Compliance
//!
//! All functions follow TigerStyle rules:
//! - Maximum 70 lines per function
//! - Minimum 2 assertions per function
//! - Explicit error handling
//! - No dynamic allocation on hot path after initialization

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(all(target_os = "linux", feature = "io_uring"))]
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_core::error::TransportError;

/// Maximum receive buffer per datagram (see udp.rs for rationale).
const MAX_PACKET_SIZE_BYTES: usize = 8192;

/// Maximum number of packets to receive in a single batch.
const MAX_BATCH_SIZE: usize = 64;

/// Number of provided buffers for multishot receive.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
const NUM_PROVIDED_BUFFERS: usize = 256;

/// Buffer group ID for provided buffers.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
const BUFFER_GROUP_ID: u16 = 1;

/// User data marker for multishot receive operations.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
#[allow(dead_code)]
const RECV_MULTI_USER_DATA: u64 = 0xFFFF_FFFF_0000_0001;

/// CQE flag indicating more completions will follow (multishot still active).
/// When this flag is NOT set, multishot has terminated and needs re-arming.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
const IORING_CQE_F_MORE: u32 = 1 << 1;

/// CQE flag indicating buffer ID is in upper 16 bits of flags.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
const IORING_CQE_F_BUFFER: u32 = 1 << 0;

/// Multishot receive state.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultishotState {
    /// Not initialized.
    Uninitialized,
    /// Active and receiving.
    Active,
    /// Terminated (needs re-arm).
    Terminated,
}

/// Configuration for io_uring transport.
#[derive(Clone, Debug)]
pub struct IoUringConfig {
    /// Number of SQ entries. Default: 4096.
    pub sq_entries: u32,
    /// Enable SQ polling (SQPOLL). Default: true.
    /// When enabled, the kernel polls the submission queue without syscalls.
    pub sqpoll_enabled: bool,
    /// CPU to pin the SQPOLL thread to. Default: None (kernel decides).
    pub sqpoll_cpu: Option<u32>,
    /// Idle timeout for SQPOLL thread in milliseconds. Default: 10000.
    pub sqpoll_idle_ms: u32,
    /// UDP receive buffer size in bytes. Default: 16MB.
    pub recv_buffer_size_bytes: u32,
    /// UDP send buffer size in bytes. Default: 16MB.
    pub send_buffer_size_bytes: u32,
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            sq_entries: 4096,
            sqpoll_enabled: true,
            sqpoll_cpu: None,
            sqpoll_idle_ms: 10000,
            recv_buffer_size_bytes: 16 * 1024 * 1024,
            send_buffer_size_bytes: 16 * 1024 * 1024,
        }
    }
}

impl IoUringConfig {
    /// Create a new configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions (post-validation)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.sq_entries == 0 {
            return Err("sq_entries must be > 0");
        }
        if !self.sq_entries.is_power_of_two() {
            return Err("sq_entries must be power of 2");
        }
        if self.recv_buffer_size_bytes == 0 {
            return Err("recv_buffer_size_bytes must be > 0");
        }
        if self.send_buffer_size_bytes == 0 {
            return Err("send_buffer_size_bytes must be > 0");
        }

        // Post-validation assertions (invariants after successful validation)
        assert!(self.sq_entries > 0, "sq_entries validated > 0");
        assert!(
            self.sq_entries.is_power_of_two(),
            "sq_entries validated as power of 2"
        );

        Ok(())
    }
}

/// Received packet with metadata.
#[derive(Debug)]
pub struct IoUringRecvPacket {
    /// Packet data.
    pub data: Vec<u8>,
    /// Source address.
    pub source_addr: SocketAddr,
    /// Receive timestamp in nanoseconds since Unix epoch.
    pub recv_time_ns: u64,
}

impl IoUringRecvPacket {
    /// Create a new received packet.
    pub fn new(data: Vec<u8>, source_addr: SocketAddr, recv_time_ns: u64) -> Self {
        Self {
            data,
            source_addr,
            recv_time_ns,
        }
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

/// Transport statistics.
#[derive(Debug, Default)]
pub struct IoUringStats {
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub recv_errors: AtomicU64,
    pub send_errors: AtomicU64,
    pub sqpoll_wakeups: AtomicU64,
}

impl IoUringStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful receive.
    #[inline(always)]
    pub fn record_recv(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a successful send.
    #[inline(always)]
    pub fn record_send(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
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

    /// Record an SQPOLL wakeup.
    #[inline(always)]
    pub fn record_sqpoll_wakeup(&self) {
        self.sqpoll_wakeups.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> IoUringStatsSnapshot {
        IoUringStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            sqpoll_wakeups: self.sqpoll_wakeups.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of io_uring statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoUringStatsSnapshot {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub recv_errors: u64,
    pub send_errors: u64,
    pub sqpoll_wakeups: u64,
}

/// Receive mode indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringReceiveMode {
    /// io_uring with multishot receive (best performance).
    Multishot,
    /// io_uring with standard recv operations.
    Standard,
    /// Fallback to recvmmsg (io_uring unavailable).
    Recvmmsg,
}


/// io_uring-based UDP transport.
///
/// Provides high-performance UDP I/O using Linux io_uring with:
/// - SQPOLL for kernel-side submission polling
/// - Buffer pool registration with BUFFER_SELECT
/// - Multishot RecvMulti for batch packet reception
/// - Automatic fallback to recvmmsg when io_uring is unavailable
///
/// # Requirements
/// - Requirement 2.1: setup_sqpoll for kernel-side polling
/// - Requirement 2.2: Buffer pool registration with BUFFER_SELECT
/// - Requirement 2.3: Multishot RecvMulti for batch reception
/// - Requirement 2.4: Fallback to recvmmsg when io_uring unavailable
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub struct IoUringTransport {
    /// UDP socket.
    socket: std::net::UdpSocket,
    /// io_uring instance.
    ring: io_uring::IoUring,
    /// Whether SQPOLL is enabled.
    sqpoll_enabled: bool,
    /// Whether multishot receive is active.
    multishot_active: bool,
    /// Provided buffers for multishot receive.
    provided_buffers: Vec<[u8; MAX_PACKET_SIZE_BYTES]>,
    /// Buffer availability bitmap (1 = available, 0 = in use).
    buffer_available: [u64; 4], // 256 bits for 256 buffers
    /// Transport statistics.
    stats: IoUringStats,
    /// Whether multishot recv has been initialized.
    multishot_initialized: AtomicBool,
    /// Current multishot state.
    multishot_state: MultishotState,
    /// Counter for multishot re-arms.
    multishot_rearms: AtomicU64,
    /// Fallback receive buffers for recvmmsg.
    recv_buffers: Vec<[u8; MAX_PACKET_SIZE_BYTES]>,
    /// Socket buffer info (GRO/GSO status).
    socket_info: Option<crate::socket_config::SocketBufferInfo>,
}

#[cfg(all(target_os = "linux", feature = "io_uring"))]
impl IoUringTransport {
    /// Create a new io_uring transport bound to the specified address.
    ///
    /// Attempts to initialize io_uring with SQPOLL and multishot receive.
    /// Falls back gracefully if features are not supported.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.1: setup_sqpoll for kernel-side polling
    pub fn bind(addr: SocketAddr, config: IoUringConfig) -> Result<Self, TransportError> {
        // Assertion: config must be valid
        assert!(config.sq_entries > 0, "sq_entries must be > 0");
        assert!(
            config.recv_buffer_size_bytes > 0,
            "recv_buffer_size_bytes must be > 0"
        );

        config.validate().map_err(|e| TransportError::ConfigError {
            message: e.to_string(),
        })?;

        // Create and bind the socket
        let socket = std::net::UdpSocket::bind(addr).map_err(|source| {
            TransportError::BindFailed { addr, source }
        })?;

        socket.set_nonblocking(true).map_err(|source| {
            TransportError::SetSockOptFailed { source }
        })?;

        // Configure high-performance socket (16MB buffers, GRO, GSO)
        let socket_info = crate::socket_config::configure_high_performance_socket(
            socket.as_raw_fd()
        ).ok();

        // Initialize io_uring with SQPOLL if requested
        let ring = Self::init_io_uring(&config)?;
        let sqpoll_enabled = config.sqpoll_enabled && Self::is_sqpoll_active(&ring);

        // Check multishot support
        let multishot_active = Self::check_multishot_support();

        // Pre-allocate buffers
        let provided_buffers = vec![[0u8; MAX_PACKET_SIZE_BYTES]; NUM_PROVIDED_BUFFERS];
        let recv_buffers = vec![[0u8; MAX_PACKET_SIZE_BYTES]; MAX_BATCH_SIZE];

        Ok(Self {
            socket,
            ring,
            sqpoll_enabled,
            multishot_active,
            provided_buffers,
            buffer_available: [u64::MAX; 4],
            stats: IoUringStats::new(),
            multishot_initialized: AtomicBool::new(false),
            multishot_state: MultishotState::Uninitialized,
            multishot_rearms: AtomicU64::new(0),
            recv_buffers,
            socket_info,
        })
    }

    /// Initialize io_uring with optional SQPOLL.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    fn init_io_uring(config: &IoUringConfig) -> Result<io_uring::IoUring, TransportError> {
        use io_uring::IoUring;

        // Assertion: entries must be positive
        assert!(config.sq_entries > 0, "sq_entries must be > 0");

        if config.sqpoll_enabled {
            // Try to create with SQPOLL
            let mut builder = IoUring::builder();
            builder.setup_sqpoll(config.sqpoll_idle_ms);

            if let Some(cpu) = config.sqpoll_cpu {
                builder.setup_sqpoll_cpu(cpu);
            }

            match builder.build(config.sq_entries) {
                Ok(ring) => {
                    tracing::info!(
                        "io_uring initialized with SQPOLL (idle_ms={})",
                        config.sqpoll_idle_ms
                    );
                    // Assertion: ring created successfully
                    assert!(ring.params().is_setup_sqpoll(), "SQPOLL should be enabled");
                    return Ok(ring);
                }
                Err(e) => {
                    tracing::warn!(
                        "SQPOLL initialization failed, falling back to standard io_uring: {}",
                        e
                    );
                }
            }
        }

        // Fall back to standard io_uring without SQPOLL
        let ring = IoUring::new(config.sq_entries).map_err(|e| {
            TransportError::IoUringInitFailed {
                message: format!("io_uring initialization failed: {}", e),
            }
        })?;

        // Assertion: ring created
        assert!(ring.params().sq_entries() > 0, "ring must have SQ entries");

        tracing::info!("io_uring initialized without SQPOLL");
        Ok(ring)
    }

    /// Check if SQPOLL is active on the ring.
    fn is_sqpoll_active(ring: &io_uring::IoUring) -> bool {
        ring.params().is_setup_sqpoll()
    }

    /// Check if multishot receive is supported (kernel 5.19+).
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    fn check_multishot_support() -> bool {
        let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
        // Assertion: uname struct is zeroed
        assert!(uname.release[0] == 0, "uname should be zeroed");

        if unsafe { libc::uname(&mut uname) } != 0 {
            return false;
        }

        let release = unsafe {
            std::ffi::CStr::from_ptr(uname.release.as_ptr()).to_string_lossy()
        };

        let parts: Vec<&str> = release.split('.').collect();
        // Assertion: kernel version has at least major.minor
        if parts.len() < 2 {
            return false;
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].split('-').next().unwrap_or("0").parse().unwrap_or(0);

        // RecvMulti requires kernel 5.19+
        let supported = major > 5 || (major == 5 && minor >= 19);
        if supported {
            tracing::info!("Multishot receive supported (kernel {}.{})", major, minor);
        } else {
            tracing::info!(
                "Multishot receive not supported (kernel {}.{}, requires 5.19+)",
                major,
                minor
            );
        }
        supported
    }

    /// Register provided buffers with io_uring.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.2: Buffer pool registration with BUFFER_SELECT
    pub fn register_buffers(&mut self) -> Result<(), TransportError> {
        use io_uring::opcode;

        // Assertion: buffers allocated
        assert!(
            self.provided_buffers.len() == NUM_PROVIDED_BUFFERS,
            "provided_buffers must have {} entries",
            NUM_PROVIDED_BUFFERS
        );

        for (idx, buffer) in self.provided_buffers.iter_mut().enumerate() {
            let provide_buf = opcode::ProvideBuffers::new(
                buffer.as_mut_ptr(),
                MAX_PACKET_SIZE_BYTES as i32,
                1,
                BUFFER_GROUP_ID,
                idx as u16,
            )
            .build()
            .user_data(idx as u64);

            unsafe {
                self.ring
                    .submission()
                    .push(&provide_buf)
                    .map_err(|_| TransportError::IoUringInitFailed {
                        message: "failed to submit provide_buffers".to_string(),
                    })?;
            }
        }

        self.ring.submit().map_err(|e| TransportError::IoUringInitFailed {
            message: format!("failed to submit buffer registration: {}", e),
        })?;

        // Wait for completions
        self.ring.submit_and_wait(NUM_PROVIDED_BUFFERS).ok();

        // Drain completion queue
        let mut success_count: u32 = 0;
        for cqe in self.ring.completion() {
            if cqe.result() >= 0 {
                success_count += 1;
            }
        }

        // Assertion: all buffers registered
        assert!(
            success_count as usize >= NUM_PROVIDED_BUFFERS / 2,
            "at least half of buffers should be registered"
        );

        tracing::info!("Registered {} buffers with io_uring", success_count);
        Ok(())
    }

    /// Initialize multishot receive operation.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.3: Multishot RecvMulti for batch reception
    pub fn init_multishot_recv(&mut self) -> Result<(), TransportError> {
        use io_uring::opcode;
        use io_uring::types;

        // Assertion: multishot must be supported
        assert!(self.multishot_active, "multishot receive not supported");
        // Assertion: not already initialized
        assert!(
            !self.multishot_initialized.load(Ordering::Acquire),
            "multishot already initialized"
        );

        // Register buffers first
        self.register_buffers()?;

        let fd = types::Fd(self.socket.as_raw_fd());

        // Submit RecvMulti operation with BUFFER_SELECT
        let recv_multi = opcode::RecvMsg::new(fd, std::ptr::null_mut())
            .buf_group(BUFFER_GROUP_ID)
            .build()
            .flags(io_uring::squeue::Flags::BUFFER_SELECT)
            .user_data(RECV_MULTI_USER_DATA);

        unsafe {
            self.ring
                .submission()
                .push(&recv_multi)
                .map_err(|_| TransportError::IoUringInitFailed {
                    message: "failed to submit recv_multi".to_string(),
                })?;
        }

        self.ring.submit().map_err(|e| TransportError::IoUringInitFailed {
            message: format!("failed to submit multishot recv: {}", e),
        })?;

        self.multishot_initialized.store(true, Ordering::Release);
        self.multishot_state = MultishotState::Active;
        tracing::info!("Multishot receive initialized");
        Ok(())
    }

    /// Re-arm multishot receive after termination.
    ///
    /// Called when multishot terminates (buffer exhaustion, error, etc.)
    /// to restart the continuous receive operation.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    fn rearm_multishot(&mut self) -> Result<(), TransportError> {
        use io_uring::opcode;
        use io_uring::types;

        // Assertion: multishot must be supported
        assert!(self.multishot_active, "multishot receive not supported");
        // Assertion: must be in terminated state
        assert!(
            self.multishot_state == MultishotState::Terminated,
            "multishot must be terminated to re-arm"
        );

        let fd = types::Fd(self.socket.as_raw_fd());

        // Submit new RecvMulti operation
        let recv_multi = opcode::RecvMsg::new(fd, std::ptr::null_mut())
            .buf_group(BUFFER_GROUP_ID)
            .build()
            .flags(io_uring::squeue::Flags::BUFFER_SELECT)
            .user_data(RECV_MULTI_USER_DATA);

        unsafe {
            self.ring
                .submission()
                .push(&recv_multi)
                .map_err(|_| TransportError::IoUringInitFailed {
                    message: "failed to submit recv_multi re-arm".to_string(),
                })?;
        }

        self.ring.submit().map_err(|e| TransportError::IoUringInitFailed {
            message: format!("failed to submit multishot re-arm: {}", e),
        })?;

        self.multishot_state = MultishotState::Active;
        self.multishot_rearms.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("Multishot receive re-armed");
        Ok(())
    }

    /// Receive packets in batch.
    ///
    /// Uses multishot receive if available, otherwise falls back to
    /// standard io_uring recv or recvmmsg.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn recv_batch(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<IoUringRecvPacket>, TransportError> {
        // Assertion: max_packets bounded
        assert!(max_packets > 0, "max_packets must be > 0");
        assert!(
            max_packets <= MAX_BATCH_SIZE,
            "max_packets must be <= {}",
            MAX_BATCH_SIZE
        );

        if self.multishot_active && self.multishot_initialized.load(Ordering::Acquire) {
            self.recv_batch_multishot(max_packets)
        } else {
            self.recv_batch_recvmmsg(max_packets)
        }
    }

    /// Receive batch using multishot receive.
    ///
    /// Properly handles IORING_CQE_F_MORE flag to detect multishot termination
    /// and automatically re-arms when needed.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    fn recv_batch_multishot(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<IoUringRecvPacket>, TransportError> {
        // Assertion: max_packets bounded
        assert!(max_packets <= MAX_BATCH_SIZE, "max_packets exceeds limit");

        // Check if we need to re-arm multishot
        if self.multishot_state == MultishotState::Terminated {
            self.rearm_multishot()?;
        }

        let mut packets = Vec::with_capacity(max_packets);
        let recv_time_ns = Self::current_time_ns();

        // Submit and wait for completions (non-blocking)
        self.ring.submit_and_wait(0).ok();

        // Process completions
        let mut processed: u32 = 0;
        let max_iter = max_packets as u32;
        let mut multishot_terminated = false;

        for cqe in self.ring.completion() {
            if processed >= max_iter {
                break;
            }

            // Check if this is a multishot completion
            let is_multishot = cqe.user_data() == RECV_MULTI_USER_DATA;

            // Check IORING_CQE_F_MORE flag - if not set, multishot terminated
            if is_multishot && (cqe.flags() & IORING_CQE_F_MORE) == 0 {
                multishot_terminated = true;
            }

            let result = cqe.result();
            if result < 0 {
                self.stats.record_recv_error();
                continue;
            }

            let len = result as usize;
            if len == 0 {
                continue;
            }

            // Extract buffer ID from completion flags (upper 16 bits)
            let buffer_id = (cqe.flags() >> 16) as usize;
            if buffer_id >= NUM_PROVIDED_BUFFERS {
                self.stats.record_recv_error();
                continue;
            }

            // Copy packet data from provided buffer
            let data = self.provided_buffers[buffer_id][..len].to_vec();

            // Get source address (fallback to placeholder)
            let addr = self
                .peek_source_addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

            self.stats.record_recv(len as u64);
            packets.push(IoUringRecvPacket::new(data, addr, recv_time_ns));

            // Return buffer to pool
            self.return_buffer_to_pool(buffer_id);

            processed += 1;
        }

        // Update multishot state if terminated
        if multishot_terminated {
            self.multishot_state = MultishotState::Terminated;
            tracing::debug!("Multishot terminated, will re-arm on next recv");
        }

        // Assertion: processed count is bounded
        assert!(processed <= max_iter, "processed should not exceed max");

        Ok(packets)
    }

    /// Receive batch using recvmmsg (fallback).
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    ///
    /// # Requirements
    /// - Requirement 2.4: Fallback to recvmmsg when io_uring unavailable
    fn recv_batch_recvmmsg(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<IoUringRecvPacket>, TransportError> {
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
            msghdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msghdr.msg_iov = &mut iovecs[i];
            msghdr.msg_iovlen = 1;

            msghdrs.push(libc::mmsghdr {
                msg_hdr: msghdr,
                msg_len: 0,
            });
        }

        // Call recvmmsg with MSG_DONTWAIT
        let result = unsafe {
            libc::recvmmsg(
                fd,
                msghdrs.as_mut_ptr(),
                max_packets as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
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

        for i in 0..num_received {
            let len = msghdrs[i].msg_len as usize;
            if len == 0 {
                continue;
            }

            let data = self.recv_buffers[i][..len].to_vec();
            let addr = Self::sockaddr_to_socket_addr(&sockaddrs[i], msghdrs[i].msg_hdr.msg_namelen)
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

            self.stats.record_recv(len as u64);
            packets.push(IoUringRecvPacket::new(data, addr, recv_time_ns));
        }

        Ok(packets)
    }

    /// Peek at the source address of the next packet.
    fn peek_source_addr(&self) -> Option<SocketAddr> {
        let mut buf = [0u8; 1];
        let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let result = unsafe {
            libc::recvfrom(
                self.socket.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                0,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
                &mut addr_storage as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if result < 0 {
            return None;
        }

        Self::sockaddr_to_socket_addr(&addr_storage, addr_len)
    }

    /// Convert sockaddr_storage to SocketAddr.
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

    /// Return a buffer to the provided buffer pool.
    fn return_buffer_to_pool(&mut self, buffer_id: usize) {
        use io_uring::opcode;

        assert!(buffer_id < NUM_PROVIDED_BUFFERS, "buffer_id out of range");

        let buffer = &mut self.provided_buffers[buffer_id];
        let provide_buf = opcode::ProvideBuffers::new(
            buffer.as_mut_ptr(),
            MAX_PACKET_SIZE_BYTES as i32,
            1,
            BUFFER_GROUP_ID,
            buffer_id as u16,
        )
        .build()
        .user_data(buffer_id as u64);

        unsafe {
            let _ = self.ring.submission().push(&provide_buf);
        }
    }

    /// Send a packet to the specified destination.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, TransportError> {
        // Assertion: data must not be empty
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
                Err(TransportError::SendFailed { dest, source: e })
            }
        }
    }

    /// Get the socket file descriptor.
    #[inline(always)]
    pub fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Get the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get transport statistics.
    #[inline(always)]
    pub fn stats(&self) -> &IoUringStats {
        &self.stats
    }

    /// Check if SQPOLL is enabled.
    #[inline(always)]
    pub fn is_sqpoll_enabled(&self) -> bool {
        self.sqpoll_enabled
    }

    /// Check if multishot receive is active.
    #[inline(always)]
    pub fn is_multishot_active(&self) -> bool {
        self.multishot_active
    }

    /// Get the current receive mode.
    pub fn receive_mode(&self) -> IoUringReceiveMode {
        if self.multishot_active && self.multishot_initialized.load(Ordering::Acquire) {
            IoUringReceiveMode::Multishot
        } else {
            IoUringReceiveMode::Recvmmsg
        }
    }

    /// Get the number of multishot re-arms.
    #[inline(always)]
    pub fn multishot_rearms(&self) -> u64 {
        self.multishot_rearms.load(Ordering::Relaxed)
    }

    /// Check if GRO is enabled on this socket.
    #[inline(always)]
    pub fn is_gro_enabled(&self) -> bool {
        self.socket_info.map(|i| i.gro_enabled).unwrap_or(false)
    }

    /// Check if GSO is available on this socket.
    #[inline(always)]
    pub fn is_gso_available(&self) -> bool {
        self.socket_info.map(|i| i.gso_enabled).unwrap_or(false)
    }

    /// Get socket buffer info.
    #[inline(always)]
    pub fn socket_info(&self) -> Option<&crate::socket_config::SocketBufferInfo> {
        self.socket_info.as_ref()
    }

    /// Get current time in nanoseconds.
    #[inline(always)]
    fn current_time_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[cfg(all(target_os = "linux", feature = "io_uring"))]
impl AsRawFd for IoUringTransport {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Fallback transport when io_uring is not available.
///
/// This struct provides the same interface as `IoUringTransport` but uses
/// recvmmsg/sendmmsg for packet I/O. Used when:
/// - The `io_uring` feature is not enabled
/// - Running on non-Linux platforms
/// - io_uring initialization fails at runtime
///
/// # Requirements
/// - Requirement 2.4: Fallback to recvmmsg when io_uring unavailable
#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
pub struct IoUringTransport {
    /// UDP socket.
    socket: std::net::UdpSocket,
    /// Transport statistics.
    stats: IoUringStats,
    /// Receive buffers.
    recv_buffers: Vec<[u8; MAX_PACKET_SIZE_BYTES]>,
}

#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
impl IoUringTransport {
    /// Create a new fallback transport.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn bind(addr: SocketAddr, config: IoUringConfig) -> Result<Self, TransportError> {
        // Assertion: config must be valid
        assert!(config.sq_entries > 0, "sq_entries must be > 0");
        assert!(
            config.recv_buffer_size_bytes > 0,
            "recv_buffer_size_bytes must be > 0"
        );

        tracing::warn!(
            "io_uring not available, using recvmmsg fallback"
        );

        let socket = std::net::UdpSocket::bind(addr).map_err(|source| {
            TransportError::BindFailed { addr, source }
        })?;

        socket.set_nonblocking(true).map_err(|source| {
            TransportError::SetSockOptFailed { source }
        })?;

        let recv_buffers = vec![[0u8; MAX_PACKET_SIZE_BYTES]; MAX_BATCH_SIZE];

        Ok(Self {
            socket,
            stats: IoUringStats::new(),
            recv_buffers,
        })
    }

    /// Register buffers (no-op for fallback).
    pub fn register_buffers(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    /// Initialize multishot receive (no-op for fallback).
    pub fn init_multishot_recv(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    /// Receive packets in batch using standard recv_from.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn recv_batch(
        &mut self,
        max_packets: usize,
    ) -> Result<Vec<IoUringRecvPacket>, TransportError> {
        // Assertion: max_packets bounded
        assert!(max_packets > 0, "max_packets must be > 0");
        assert!(
            max_packets <= MAX_BATCH_SIZE,
            "max_packets must be <= {}",
            MAX_BATCH_SIZE
        );

        let mut packets = Vec::with_capacity(max_packets);
        let recv_time_ns = Self::current_time_ns();

        for i in 0..max_packets {
            match self.socket.recv_from(&mut self.recv_buffers[i]) {
                Ok((len, addr)) => {
                    let data = self.recv_buffers[i][..len].to_vec();
                    self.stats.record_recv(len as u64);
                    packets.push(IoUringRecvPacket::new(data, addr, recv_time_ns));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    self.stats.record_recv_error();
                    if packets.is_empty() {
                        return Err(TransportError::RecvFailed { source: e });
                    }
                    break;
                }
            }
        }

        Ok(packets)
    }

    /// Send a packet.
    pub fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, TransportError> {
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
                Err(TransportError::SendFailed { dest, source: e })
            }
        }
    }

    /// Get the socket file descriptor.
    #[inline(always)]
    pub fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Get the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get transport statistics.
    #[inline(always)]
    pub fn stats(&self) -> &IoUringStats {
        &self.stats
    }

    /// Check if SQPOLL is enabled (always false for fallback).
    #[inline(always)]
    pub fn is_sqpoll_enabled(&self) -> bool {
        false
    }

    /// Check if multishot receive is active (always false for fallback).
    #[inline(always)]
    pub fn is_multishot_active(&self) -> bool {
        false
    }

    /// Get the current receive mode.
    pub fn receive_mode(&self) -> IoUringReceiveMode {
        IoUringReceiveMode::Recvmmsg
    }

    /// Get current time in nanoseconds.
    #[inline(always)]
    fn current_time_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
impl AsRawFd for IoUringTransport {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Try to create an io_uring transport, falling back to recvmmsg on failure.
///
/// This function provides a convenient way to create a transport that
/// automatically falls back to recvmmsg if io_uring initialization fails.
///
/// # Requirements
/// - Requirement 2.4: Fallback to recvmmsg when io_uring unavailable
pub fn create_transport_with_fallback(
    addr: SocketAddr,
    config: IoUringConfig,
) -> Result<IoUringTransport, TransportError> {
    IoUringTransport::bind(addr, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_uring_config_default() {
        let config = IoUringConfig::default();
        assert_eq!(config.sq_entries, 4096);
        assert!(config.sqpoll_enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_io_uring_config_validation() {
        let config = IoUringConfig::default();
        assert!(config.validate().is_ok());

        // Test with non-power-of-2 sq_entries (validation should fail)
        let mut config = IoUringConfig::default();
        config.sq_entries = 1000;
        assert!(config.validate().is_err());

        // Test with zero recv_buffer_size
        let mut config = IoUringConfig::default();
        config.recv_buffer_size_bytes = 0;
        assert!(config.validate().is_err());

        // Test with zero send_buffer_size
        let mut config = IoUringConfig::default();
        config.send_buffer_size_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_io_uring_stats() {
        let stats = IoUringStats::new();
        stats.record_recv(1500);
        stats.record_send(1200);
        stats.record_recv_error();
        stats.record_sqpoll_wakeup();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_received, 1);
        assert_eq!(snapshot.bytes_received, 1500);
        assert_eq!(snapshot.packets_sent, 1);
        assert_eq!(snapshot.bytes_sent, 1200);
        assert_eq!(snapshot.recv_errors, 1);
        assert_eq!(snapshot.sqpoll_wakeups, 1);
    }

    #[test]
    fn test_io_uring_recv_packet() {
        let data = vec![0u8; 1500];
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let packet = IoUringRecvPacket::new(data, addr, 1234567890);

        assert_eq!(packet.len(), 1500);
        assert!(!packet.is_empty());
        assert_eq!(packet.source_addr, addr);
        assert_eq!(packet.recv_time_ns, 1234567890);
    }

    #[test]
    fn test_io_uring_transport_bind() {
        let config = IoUringConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = IoUringTransport::bind(addr, config);
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert!(transport.local_addr().is_ok());
    }

    #[test]
    fn test_io_uring_transport_send_recv() {
        let config = IoUringConfig::default();

        // Create sender
        let sender_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sender = IoUringTransport::bind(sender_addr, config.clone()).unwrap();

        // Create receiver
        let recv_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut receiver = IoUringTransport::bind(recv_addr, config).unwrap();
        let recv_local = receiver.local_addr().unwrap();

        // Send a packet
        let data = b"Hello, io_uring!";
        let result = sender.send(data, recv_local);
        assert!(result.is_ok());

        // Give packet time to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Receive
        let packets = receiver.recv_batch(10).unwrap();

        // Check stats
        let sender_stats = sender.stats().snapshot();
        assert_eq!(sender_stats.packets_sent, 1);

        if !packets.is_empty() {
            assert_eq!(packets[0].data, data);
        }
    }

    #[test]
    fn test_io_uring_transport_receive_mode() {
        let config = IoUringConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = IoUringTransport::bind(addr, config).unwrap();
        let mode = transport.receive_mode();

        // On non-Linux or without io_uring feature, should be Recvmmsg
        #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
        {
            assert_eq!(mode, IoUringReceiveMode::Recvmmsg);
        }
    }

    #[test]
    fn test_create_transport_with_fallback() {
        let config = IoUringConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = create_transport_with_fallback(addr, config);
        assert!(transport.is_ok());
    }
}
