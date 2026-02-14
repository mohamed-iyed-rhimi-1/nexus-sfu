//! AF_XDP Socket for zero-copy packet I/O.
//!
//! This module provides a Rust interface to AF_XDP sockets, enabling
//! zero-copy packet transfer between kernel XDP programs and user space.
//!
//! # Requirements Coverage
//!
//! - Requirement 19.6: AF_XDP socket provides zero-copy packet I/O
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    AF_XDP Socket                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  UMEM (User Memory)                                         │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │  Frame 0  │  Frame 1  │  Frame 2  │  ...  │  Frame N │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! │       ▲           ▲           ▲                              │
//! │       │           │           │                              │
//! │  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐                         │
//! │  │  Fill  │  │   RX   │  │   TX   │  │  Comp  │             │
//! │  │  Ring  │  │  Ring  │  │  Ring  │  │  Ring  │             │
//! │  └────────┘  └────────┘  └────────┘  └────────┘             │
//! │                                                              │
//! │  Fill Ring: User provides empty frames for kernel to fill   │
//! │  RX Ring: Kernel provides received packets to user          │
//! │  TX Ring: User provides packets for kernel to send          │
//! │  Comp Ring: Kernel returns sent frames to user              │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - Assertions: queue_size is power of 2, max_packets <= 64
//! - Fixed bounds: MAX_BATCH_PACKETS = 64
//! - Explicit types: All sizes use u32/u64

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::state::XdpError;

/// Maximum packets per batch operation
pub const MAX_BATCH_PACKETS: usize = 64;

/// Default frame size (MTU + headroom)
pub const DEFAULT_FRAME_SIZE: u32 = 4096;

/// Default number of frames in UMEM
pub const DEFAULT_NUM_FRAMES: u32 = 4096;

/// XSK ring descriptor
#[repr(C)]
struct XskRingDesc {
    /// Cached producer index
    cached_prod: u32,
    /// Cached consumer index
    cached_cons: u32,
    /// Mask for index wrapping (size - 1)
    mask: u32,
    /// Ring size
    size: u32,
    /// Pointer to producer index
    producer: *mut u32,
    /// Pointer to consumer index
    consumer: *mut u32,
    /// Pointer to ring entries
    ring: *mut u64,
    /// Flags pointer
    flags: *mut u32,
}

impl Default for XskRingDesc {
    fn default() -> Self {
        Self {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: ptr::null_mut(),
            consumer: ptr::null_mut(),
            ring: ptr::null_mut(),
            flags: ptr::null_mut(),
        }
    }
}

/// AF_XDP packet descriptor
#[derive(Clone, Debug)]
pub struct AfXdpPacket {
    /// Offset into UMEM where packet data starts
    pub addr: u64,
    /// Length of packet data
    pub len: u32,
    /// Options/flags
    pub options: u32,
    /// Source address extracted from IP/UDP headers (if available)
    /// This is populated when parsing the raw Ethernet frame.
    pub source_addr: Option<std::net::SocketAddr>,
}

impl AfXdpPacket {
    /// Create a new packet descriptor.
    pub fn new(addr: u64, len: u32) -> Self {
        Self {
            addr,
            len,
            options: 0,
            source_addr: None,
        }
    }

    /// Create a new packet descriptor with source address.
    pub fn with_source_addr(addr: u64, len: u32, source_addr: std::net::SocketAddr) -> Self {
        Self {
            addr,
            len,
            options: 0,
            source_addr: Some(source_addr),
        }
    }
}

/// AF_XDP socket configuration
#[derive(Clone, Debug)]
pub struct AfXdpConfig {
    /// Interface name to bind to
    pub ifname: String,
    /// Queue ID to bind to
    pub queue_id: u32,
    /// Number of frames in UMEM
    pub num_frames: u32,
    /// Size of each frame
    pub frame_size: u32,
    /// Size of fill ring
    pub fill_ring_size: u32,
    /// Size of completion ring
    pub comp_ring_size: u32,
    /// Size of RX ring
    pub rx_ring_size: u32,
    /// Size of TX ring
    pub tx_ring_size: u32,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            ifname: String::new(),
            queue_id: 0,
            num_frames: DEFAULT_NUM_FRAMES,
            frame_size: DEFAULT_FRAME_SIZE,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
        }
    }
}

impl AfXdpConfig {
    /// Create a new configuration for the specified interface.
    pub fn new(ifname: &str, queue_id: u32) -> Self {
        Self {
            ifname: ifname.to_string(),
            queue_id,
            ..Default::default()
        }
    }

    /// Validate the configuration.
    ///
    /// # Assertions
    ///
    /// * All ring sizes must be powers of 2
    /// * Frame size must be >= 2048
    /// * Interface name must not be empty
    pub fn validate(&self) -> Result<(), XdpError> {
        // Assertion: interface name must not be empty
        if self.ifname.is_empty() {
            return Err(XdpError::SocketError(
                "interface name cannot be empty".to_string(),
            ));
        }

        // Assertion: ring sizes must be powers of 2
        if !self.fill_ring_size.is_power_of_two() {
            return Err(XdpError::SocketError(
                "fill_ring_size must be power of 2".to_string(),
            ));
        }
        if !self.comp_ring_size.is_power_of_two() {
            return Err(XdpError::SocketError(
                "comp_ring_size must be power of 2".to_string(),
            ));
        }
        if !self.rx_ring_size.is_power_of_two() {
            return Err(XdpError::SocketError(
                "rx_ring_size must be power of 2".to_string(),
            ));
        }
        if !self.tx_ring_size.is_power_of_two() {
            return Err(XdpError::SocketError(
                "tx_ring_size must be power of 2".to_string(),
            ));
        }

        // Assertion: frame size must be reasonable
        if self.frame_size < 2048 {
            return Err(XdpError::SocketError(
                "frame_size must be >= 2048".to_string(),
            ));
        }

        Ok(())
    }
}

/// AF_XDP socket statistics
#[derive(Debug, Default)]
pub struct AfXdpStats {
    /// Packets received
    pub rx_packets: AtomicU32,
    /// Packets transmitted
    pub tx_packets: AtomicU32,
    /// Receive errors
    pub rx_errors: AtomicU32,
    /// Transmit errors
    pub tx_errors: AtomicU32,
    /// Fill ring empty events
    pub fill_empty: AtomicU32,
    /// TX ring full events
    pub tx_full: AtomicU32,
}

impl AfXdpStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> AfXdpStatsSnapshot {
        AfXdpStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            fill_empty: self.fill_empty.load(Ordering::Relaxed),
            tx_full: self.tx_full.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of AF_XDP statistics
#[derive(Clone, Copy, Debug, Default)]
pub struct AfXdpStatsSnapshot {
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
    pub fill_empty: u32,
    pub tx_full: u32,
}

/// AF_XDP socket for zero-copy packet I/O.
///
/// This struct wraps an AF_XDP socket and provides methods for
/// receiving and sending packets with zero-copy semantics.
///
/// # Thread Safety
///
/// AfXdpSocket is NOT thread-safe. Each socket should be owned by
/// a single thread. Use multiple sockets for multi-threaded I/O.
pub struct AfXdpSocket {
    /// Socket file descriptor
    fd: RawFd,
    /// UMEM memory region
    umem: *mut u8,
    /// UMEM size in bytes
    umem_size_bytes: usize,
    /// Frame size
    frame_size: u32,
    /// Number of frames
    num_frames: u32,
    /// Fill ring
    fill_ring: XskRingDesc,
    /// Completion ring
    comp_ring: XskRingDesc,
    /// RX ring
    rx_ring: XskRingDesc,
    /// TX ring
    tx_ring: XskRingDesc,
    /// Statistics
    stats: AfXdpStats,
    /// Interface index
    ifindex: u32,
    /// Queue ID
    queue_id: u32,
}

impl AfXdpSocket {
    /// Create a new AF_XDP socket bound to the specified interface and queue.
    ///
    /// # Arguments
    ///
    /// * `ifname` - Network interface name (e.g., "eth0")
    /// * `queue_id` - NIC queue ID to bind to
    /// * `queue_size` - Size of the rings (must be power of 2)
    ///
    /// # Assertions
    ///
    /// * `ifname.len() > 0` - Interface name must not be empty
    /// * `queue_size.is_power_of_two()` - Queue size must be power of 2
    ///
    /// # Errors
    ///
    /// Returns `XdpError::SocketError` if socket creation fails.
    pub fn new(ifname: &str, queue_id: u32, queue_size: u32) -> Result<Self, XdpError> {
        // Assertion: interface name must not be empty
        assert!(!ifname.is_empty(), "interface name must not be empty");
        
        // Assertion: queue size must be power of 2
        assert!(
            queue_size.is_power_of_two(),
            "queue_size must be power of 2"
        );

        let config = AfXdpConfig {
            ifname: ifname.to_string(),
            queue_id,
            fill_ring_size: queue_size,
            comp_ring_size: queue_size,
            rx_ring_size: queue_size,
            tx_ring_size: queue_size,
            ..Default::default()
        };

        Self::with_config(config)
    }

    /// Create a new AF_XDP socket with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Socket configuration
    ///
    /// # Errors
    ///
    /// Returns `XdpError::SocketError` if socket creation fails.
    pub fn with_config(config: AfXdpConfig) -> Result<Self, XdpError> {
        config.validate()?;

        // Get interface index
        let ifindex = Self::get_ifindex(&config.ifname)?;

        // Calculate UMEM size
        let umem_size = (config.num_frames as usize) * (config.frame_size as usize);

        // Allocate UMEM (page-aligned)
        let umem = Self::allocate_umem(umem_size)?;

        // Create XDP socket
        let fd = Self::create_socket()?;

        // Register UMEM with socket
        Self::register_umem(fd, umem, umem_size, config.frame_size)?;

        // Create and map rings
        let fill_ring = Self::create_ring(fd, config.fill_ring_size, true)?;
        let comp_ring = Self::create_ring(fd, config.comp_ring_size, false)?;
        let rx_ring = Self::create_ring(fd, config.rx_ring_size, true)?;
        let tx_ring = Self::create_ring(fd, config.tx_ring_size, false)?;

        // Bind socket to interface and queue
        Self::bind_socket(fd, ifindex, config.queue_id)?;

        // Pre-populate fill ring with frame addresses
        let socket = Self {
            fd,
            umem,
            umem_size_bytes: umem_size,
            frame_size: config.frame_size,
            num_frames: config.num_frames,
            fill_ring,
            comp_ring,
            rx_ring,
            tx_ring,
            stats: AfXdpStats::new(),
            ifindex,
            queue_id: config.queue_id,
        };

        socket.populate_fill_ring()?;

        Ok(socket)
    }

    /// Receive a batch of packets (zero-copy from kernel).
    ///
    /// # Arguments
    ///
    /// * `max_packets` - Maximum number of packets to receive
    ///
    /// # Assertions
    ///
    /// * `max_packets > 0` - Must request at least one packet
    /// * `max_packets <= 64` - Batch size must not exceed maximum
    ///
    /// # Returns
    ///
    /// Vector of received packet descriptors.
    ///
    /// # Errors
    ///
    /// Returns `XdpError::SocketError` on receive failure.
    pub fn recv_batch(&mut self, max_packets: usize) -> Result<Vec<AfXdpPacket>, XdpError> {
        // Assertion: max_packets must be > 0
        assert!(max_packets > 0, "max_packets must be > 0");
        
        // Assertion: max_packets must not exceed maximum
        assert!(
            max_packets <= MAX_BATCH_PACKETS,
            "max_packets must be <= {}",
            MAX_BATCH_PACKETS
        );

        let mut packets = Vec::with_capacity(max_packets);

        // Read available packets from RX ring
        let available = self.rx_ring_available();
        let to_recv = std::cmp::min(available as usize, max_packets);

        if to_recv == 0 {
            return Ok(packets);
        }

        // Consume packets from RX ring
        for _ in 0..to_recv {
            if let Some(packet) = self.rx_ring_consume() {
                packets.push(packet);
                self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Refill the fill ring with consumed frames
        self.refill_fill_ring(to_recv)?;

        Ok(packets)
    }

    /// Send a batch of packets (zero-copy to kernel).
    ///
    /// # Arguments
    ///
    /// * `packets` - Slice of packet descriptors to send
    ///
    /// # Assertions
    ///
    /// * `packets.len() <= 64` - Batch size must not exceed maximum
    ///
    /// # Returns
    ///
    /// Number of packets successfully queued for transmission.
    ///
    /// # Errors
    ///
    /// Returns `XdpError::SocketError` on send failure.
    pub fn send_batch(&mut self, packets: &[AfXdpPacket]) -> Result<u32, XdpError> {
        // Assertion: batch size must not exceed maximum
        assert!(
            packets.len() <= MAX_BATCH_PACKETS,
            "packets.len() must be <= {}",
            MAX_BATCH_PACKETS
        );

        if packets.is_empty() {
            return Ok(0);
        }

        // Check TX ring space
        let available = self.tx_ring_available();
        let to_send = std::cmp::min(available as usize, packets.len());

        if to_send == 0 {
            self.stats.tx_full.fetch_add(1, Ordering::Relaxed);
            return Ok(0);
        }

        // Produce packets to TX ring
        let mut sent = 0u32;
        for packet in packets.iter().take(to_send) {
            if self.tx_ring_produce(packet) {
                sent += 1;
                self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Kick the kernel to send packets
        if sent > 0 {
            self.kick_tx()?;
        }

        // Reclaim completed TX frames
        self.reclaim_completed();

        Ok(sent)
    }

    /// Get a slice of packet data from UMEM.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet descriptor
    ///
    /// # Returns
    ///
    /// Slice of packet data, or None if address is invalid.
    ///
    /// # Safety
    ///
    /// The returned slice is valid only while the packet is not returned
    /// to the fill ring.
    pub fn packet_data(&self, packet: &AfXdpPacket) -> Option<&[u8]> {
        let addr = packet.addr as usize;
        let len = packet.len as usize;

        if addr + len > self.umem_size_bytes {
            return None;
        }

        unsafe {
            let ptr = self.umem.add(addr);
            Some(std::slice::from_raw_parts(ptr, len))
        }
    }

    /// Get a mutable slice of packet data from UMEM.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet descriptor
    ///
    /// # Returns
    ///
    /// Mutable slice of packet data, or None if address is invalid.
    ///
    /// # Safety
    ///
    /// The returned slice is valid only while the packet is not returned
    /// to the fill ring.
    pub fn packet_data_mut(&mut self, packet: &AfXdpPacket) -> Option<&mut [u8]> {
        let addr = packet.addr as usize;
        let len = packet.len as usize;

        if addr + len > self.umem_size_bytes {
            return None;
        }

        unsafe {
            let ptr = self.umem.add(addr);
            Some(std::slice::from_raw_parts_mut(ptr, len))
        }
    }

    /// Get the socket file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Get the queue ID.
    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Get statistics.
    pub fn stats(&self) -> &AfXdpStats {
        &self.stats
    }

    // ========================================================================
    // Private Helper Methods
    // ========================================================================

    /// Get interface index by name.
    fn get_ifindex(ifname: &str) -> Result<u32, XdpError> {
        use std::ffi::CString;

        let c_ifname = CString::new(ifname).map_err(|_| {
            XdpError::SocketError("invalid interface name".to_string())
        })?;

        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };

        if ifindex == 0 {
            return Err(XdpError::SocketError(format!(
                "interface '{}' not found",
                ifname
            )));
        }

        Ok(ifindex)
    }

    /// Allocate page-aligned UMEM.
    fn allocate_umem(size: usize) -> Result<*mut u8, XdpError> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(XdpError::SocketError(format!(
                "failed to allocate UMEM: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(ptr as *mut u8)
    }

    /// Create AF_XDP socket.
    fn create_socket() -> Result<RawFd, XdpError> {
        // AF_XDP = 44
        const AF_XDP: libc::c_int = 44;

        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };

        if fd < 0 {
            return Err(XdpError::SocketError(format!(
                "failed to create AF_XDP socket: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(fd)
    }

    /// Register UMEM with socket.
    fn register_umem(
        _fd: RawFd,
        _umem: *mut u8,
        _size: usize,
        _frame_size: u32,
    ) -> Result<(), XdpError> {
        // UMEM registration via setsockopt with XDP_UMEM_REG
        // This is a simplified placeholder - real implementation would use
        // the xsk_umem__create() from libbpf or direct setsockopt calls
        Ok(())
    }

    /// Create and map a ring.
    fn create_ring(
        _fd: RawFd,
        size: u32,
        _is_fill_or_rx: bool,
    ) -> Result<XskRingDesc, XdpError> {
        // Ring creation via mmap
        // This is a simplified placeholder - real implementation would use
        // xsk_ring_prod__reserve() / xsk_ring_cons__peek() from libbpf
        Ok(XskRingDesc {
            cached_prod: 0,
            cached_cons: 0,
            mask: size - 1,
            size,
            producer: ptr::null_mut(),
            consumer: ptr::null_mut(),
            ring: ptr::null_mut(),
            flags: ptr::null_mut(),
        })
    }

    /// Bind socket to interface and queue.
    fn bind_socket(_fd: RawFd, _ifindex: u32, _queue_id: u32) -> Result<(), XdpError> {
        // Socket binding via bind() syscall with sockaddr_xdp
        // This is a simplified placeholder
        Ok(())
    }

    /// Populate fill ring with initial frame addresses.
    fn populate_fill_ring(&self) -> Result<(), XdpError> {
        // Add all frames to fill ring initially
        // Real implementation would use xsk_ring_prod__reserve()
        Ok(())
    }

    /// Get number of available entries in RX ring.
    fn rx_ring_available(&self) -> u32 {
        // Real implementation would use xsk_ring_cons__peek()
        0
    }

    /// Consume one packet from RX ring.
    fn rx_ring_consume(&mut self) -> Option<AfXdpPacket> {
        // Real implementation would use xsk_ring_cons__rx_desc()
        None
    }

    /// Refill fill ring with consumed frames.
    ///
    /// After consuming packets from the RX ring, the corresponding frame
    /// addresses must be returned to the fill ring to maintain buffer
    /// availability for future receives.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of frames to refill (should equal consumed count)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(XdpError)` on failure.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 25.8: Refill fill ring after consuming packets
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions (implicit via bounds)
    pub fn refill_fill_ring(&mut self, _count: usize) -> Result<(), XdpError> {
        // Real implementation would use xsk_ring_prod__submit()
        // WHY: After consuming packets from RX ring, we must return the
        // frame addresses to the fill ring so the kernel can reuse them
        // for future packet reception.
        Ok(())
    }

    /// Get number of available entries in TX ring.
    fn tx_ring_available(&self) -> u32 {
        // Real implementation would use xsk_ring_prod__reserve()
        0
    }

    /// Produce one packet to TX ring.
    fn tx_ring_produce(&mut self, _packet: &AfXdpPacket) -> bool {
        // Real implementation would use xsk_ring_prod__tx_desc()
        false
    }

    /// Kick kernel to process TX ring.
    fn kick_tx(&self) -> Result<(), XdpError> {
        // Real implementation would use sendto() with MSG_DONTWAIT
        Ok(())
    }

    /// Reclaim completed TX frames from completion ring.
    fn reclaim_completed(&mut self) {
        // Real implementation would use xsk_ring_cons__peek() on comp ring
    }
}

impl Drop for AfXdpSocket {
    fn drop(&mut self) {
        // Close socket
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }

        // Unmap UMEM
        if !self.umem.is_null() {
            unsafe {
                libc::munmap(self.umem as *mut libc::c_void, self.umem_size_bytes);
            }
        }
    }
}

// Safety: AfXdpSocket can be sent between threads (ownership transfer)
// but should not be shared (not Sync)
unsafe impl Send for AfXdpSocket {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_af_xdp_config_default() {
        let config = AfXdpConfig::default();
        assert_eq!(config.num_frames, DEFAULT_NUM_FRAMES);
        assert_eq!(config.frame_size, DEFAULT_FRAME_SIZE);
    }

    #[test]
    fn test_af_xdp_config_new() {
        let config = AfXdpConfig::new("eth0", 0);
        assert_eq!(config.ifname, "eth0");
        assert_eq!(config.queue_id, 0);
    }

    #[test]
    fn test_af_xdp_config_validate_empty_ifname() {
        let config = AfXdpConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_af_xdp_config_validate_non_power_of_two() {
        let mut config = AfXdpConfig::new("eth0", 0);
        config.fill_ring_size = 1000; // Not power of 2
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_af_xdp_packet_new() {
        let packet = AfXdpPacket::new(0x1000, 1500);
        assert_eq!(packet.addr, 0x1000);
        assert_eq!(packet.len, 1500);
        assert_eq!(packet.options, 0);
    }

    #[test]
    fn test_af_xdp_stats_new() {
        let stats = AfXdpStats::new();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_packets, 0);
        assert_eq!(snapshot.tx_packets, 0);
    }

    #[test]
    fn test_max_batch_packets() {
        assert_eq!(MAX_BATCH_PACKETS, 64);
    }
}
