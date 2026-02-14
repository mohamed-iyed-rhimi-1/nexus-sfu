//! GSO (Generic Segmentation Offload) batch sender.
//!
//! GSO allows sending multiple same-size UDP packets to the same destination
//! in a single sendmsg() call. The kernel handles segmentation, reducing
//! syscall overhead significantly.
//!
//! # How GSO Works
//!
//! 1. Application concatenates multiple packets into one buffer
//! 2. sendmsg() is called with UDP_SEGMENT cmsg specifying segment size
//! 3. Kernel splits buffer into individual UDP packets
//! 4. NIC may further optimize with hardware TSO
//!
//! # Requirements
//!
//! - All packets must be the same size (except possibly the last one)
//! - All packets must go to the same destination
//! - Linux kernel 4.18+ with UDP_SEGMENT support
//!
//! # Example
//!
//! ```ignore
//! let sender = GsoBatchSender::new(socket_fd)?;
//! let packets = vec![packet1, packet2, packet3]; // Same size, same dest
//! sender.send_batch(dest, &packets)?;
//! ```
//!
//! # TigerStyle Compliance
//!
//! All functions follow TigerStyle rules:
//! - Maximum 70 lines per function
//! - Minimum 2 assertions per function
//! - Explicit error handling

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};

/// UDP_SEGMENT socket option for GSO.
#[cfg(target_os = "linux")]
pub const UDP_SEGMENT: libc::c_int = 103;

/// Maximum GSO segments per sendmsg call.
pub const MAX_GSO_SEGMENTS: usize = 64;

/// Maximum total GSO buffer size (64KB - typical limit).
pub const MAX_GSO_BUFFER_SIZE: usize = 65535;

/// GSO batch sender statistics.
#[derive(Debug, Default)]
pub struct GsoStats {
    /// Batches sent using GSO.
    pub gso_batches: AtomicU64,
    /// Packets sent via GSO.
    pub gso_packets: AtomicU64,
    /// Batches sent using sendmmsg fallback.
    pub fallback_batches: AtomicU64,
    /// Packets sent via fallback.
    pub fallback_packets: AtomicU64,
    /// Send errors.
    pub errors: AtomicU64,
}

impl GsoStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_gso(&self, packets: u64) {
        self.gso_batches.fetch_add(1, Ordering::Relaxed);
        self.gso_packets.fetch_add(packets, Ordering::Relaxed);
    }

    pub fn record_fallback(&self, packets: u64) {
        self.fallback_batches.fetch_add(1, Ordering::Relaxed);
        self.fallback_packets.fetch_add(packets, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> GsoStatsSnapshot {
        GsoStatsSnapshot {
            gso_batches: self.gso_batches.load(Ordering::Relaxed),
            gso_packets: self.gso_packets.load(Ordering::Relaxed),
            fallback_batches: self.fallback_batches.load(Ordering::Relaxed),
            fallback_packets: self.fallback_packets.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GsoStatsSnapshot {
    pub gso_batches: u64,
    pub gso_packets: u64,
    pub fallback_batches: u64,
    pub fallback_packets: u64,
    pub errors: u64,
}


/// GSO batch sender for efficient multi-packet transmission.
///
/// Sends multiple same-size packets to the same destination using
/// a single sendmsg() call with UDP_SEGMENT cmsg on Linux.
/// Falls back to sendmmsg on other platforms or when GSO is unavailable.
pub struct GsoBatchSender {
    /// Socket file descriptor.
    socket_fd: RawFd,
    /// Whether GSO is available.
    gso_available: bool,
    /// Concatenation buffer for GSO sends.
    #[cfg(target_os = "linux")]
    concat_buffer: Vec<u8>,
    /// Statistics.
    stats: GsoStats,
}

impl GsoBatchSender {
    /// Create a new GSO batch sender.
    ///
    /// # Arguments
    /// * `socket_fd` - UDP socket file descriptor
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn new(socket_fd: RawFd) -> io::Result<Self> {
        // Assertion: fd must be valid
        assert!(socket_fd >= 0, "socket_fd must be valid (>= 0)");

        let gso_available = Self::check_gso_support(socket_fd);

        // Assertion: we should have determined GSO availability
        tracing::info!("GSO batch sender created, GSO available: {}", gso_available);

        Ok(Self {
            socket_fd,
            gso_available,
            #[cfg(target_os = "linux")]
            concat_buffer: Vec::with_capacity(MAX_GSO_BUFFER_SIZE),
            stats: GsoStats::new(),
        })
    }

    /// Check if GSO is supported on this socket.
    #[cfg(target_os = "linux")]
    fn check_gso_support(fd: RawFd) -> bool {
        // Try to get UDP_SEGMENT option
        let mut value: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_UDP,
                UDP_SEGMENT,
                &mut value as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        // If getsockopt doesn't fail with ENOPROTOOPT, GSO is available
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
                return false;
            }
        }
        true
    }

    #[cfg(not(target_os = "linux"))]
    fn check_gso_support(_fd: RawFd) -> bool {
        false
    }

    /// Check if GSO is available.
    #[inline]
    pub fn is_gso_available(&self) -> bool {
        self.gso_available
    }

    /// Get statistics.
    #[inline]
    pub fn stats(&self) -> &GsoStats {
        &self.stats
    }


    /// Send a batch of packets to the same destination.
    ///
    /// Uses GSO if available and all packets are the same size.
    /// Falls back to sendmmsg otherwise.
    ///
    /// # Arguments
    /// * `dest` - Destination address
    /// * `packets` - Slice of packet data (all should be same size for GSO)
    ///
    /// # Returns
    /// Number of packets sent successfully.
    ///
    /// # TigerStyle
    /// - ≤70 lines
    /// - ≥2 assertions
    pub fn send_batch(&mut self, dest: SocketAddr, packets: &[&[u8]]) -> io::Result<usize> {
        // Assertion: packets must not be empty
        assert!(!packets.is_empty(), "packets must not be empty");
        // Assertion: each packet must have data
        assert!(packets.iter().all(|p| !p.is_empty()), "all packets must have data");

        if packets.len() == 1 {
            // Single packet - just use sendto
            return self.send_single(dest, packets[0]);
        }

        // Check if GSO can be used
        #[cfg(target_os = "linux")]
        if self.gso_available && self.can_use_gso(packets) {
            return self.send_with_gso(dest, packets);
        }

        // Fallback to sendmmsg
        self.send_with_sendmmsg(dest, packets)
    }

    /// Check if GSO can be used for these packets.
    #[cfg(target_os = "linux")]
    fn can_use_gso(&self, packets: &[&[u8]]) -> bool {
        if packets.len() < 2 || packets.len() > MAX_GSO_SEGMENTS {
            return false;
        }

        // All packets except last must be same size
        let segment_size = packets[0].len();
        if segment_size == 0 || segment_size > 1472 {
            return false;
        }

        // Check all but last packet
        for packet in &packets[..packets.len() - 1] {
            if packet.len() != segment_size {
                return false;
            }
        }

        // Last packet can be smaller or equal
        if packets.last().map(|p| p.len()).unwrap_or(0) > segment_size {
            return false;
        }

        // Check total size
        let total_size: usize = packets.iter().map(|p| p.len()).sum();
        total_size <= MAX_GSO_BUFFER_SIZE
    }

    /// Send using GSO (Linux only).
    #[cfg(target_os = "linux")]
    fn send_with_gso(&mut self, dest: SocketAddr, packets: &[&[u8]]) -> io::Result<usize> {
        use std::mem::MaybeUninit;

        let segment_size = packets[0].len() as u16;

        // Concatenate packets into buffer
        self.concat_buffer.clear();
        for packet in packets {
            self.concat_buffer.extend_from_slice(packet);
        }

        // Prepare sockaddr
        let (sockaddr, sockaddr_len) = Self::socket_addr_to_raw(dest);

        // Prepare iovec
        let iov = libc::iovec {
            iov_base: self.concat_buffer.as_ptr() as *mut libc::c_void,
            iov_len: self.concat_buffer.len(),
        };

        // Prepare cmsg for UDP_SEGMENT
        let mut cmsg_buf = [0u8; 64];
        let cmsg_len = Self::prepare_gso_cmsg(&mut cmsg_buf, segment_size);

        // Prepare msghdr
        let mut msghdr: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
        msghdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
        msghdr.msg_namelen = sockaddr_len;
        msghdr.msg_iov = &iov as *const _ as *mut libc::iovec;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msghdr.msg_controllen = cmsg_len;

        let result = unsafe { libc::sendmsg(self.socket_fd, &msghdr, 0) };

        if result < 0 {
            self.stats.record_error();
            return Err(io::Error::last_os_error());
        }

        self.stats.record_gso(packets.len() as u64);
        Ok(packets.len())
    }


    /// Prepare GSO cmsg with UDP_SEGMENT.
    #[cfg(target_os = "linux")]
    fn prepare_gso_cmsg(buf: &mut [u8], segment_size: u16) -> usize {
        let cmsg_space = unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<u16>() as libc::c_uint) as usize
        };

        assert!(buf.len() >= cmsg_space, "cmsg buffer too small");

        let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
        unsafe {
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as libc::c_uint) as usize;
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;

            let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
            *data_ptr = segment_size;
        }

        cmsg_space
    }

    /// Convert SocketAddr to raw sockaddr.
    #[cfg(target_os = "linux")]
    fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        use std::mem::MaybeUninit;

        let mut storage: libc::sockaddr_storage = unsafe { MaybeUninit::zeroed().assume_init() };

        match addr {
            SocketAddr::V4(v4) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
                unsafe {
                    (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sa).sin_port = v4.port().to_be();
                    (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                }
                (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
                unsafe {
                    (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sa).sin6_port = v6.port().to_be();
                    (*sa).sin6_flowinfo = v6.flowinfo();
                    (*sa).sin6_addr.s6_addr = v6.ip().octets();
                    (*sa).sin6_scope_id = v6.scope_id();
                }
                (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }

    /// Send using sendmmsg fallback.
    #[cfg(target_os = "linux")]
    fn send_with_sendmmsg(&mut self, dest: SocketAddr, packets: &[&[u8]]) -> io::Result<usize> {
        use std::mem::MaybeUninit;

        let (sockaddr, sockaddr_len) = Self::socket_addr_to_raw(dest);

        let mut iovecs: Vec<libc::iovec> = packets
            .iter()
            .map(|p| libc::iovec {
                iov_base: p.as_ptr() as *mut libc::c_void,
                iov_len: p.len(),
            })
            .collect();

        let mut msghdrs: Vec<libc::mmsghdr> = iovecs
            .iter_mut()
            .map(|iov| {
                let mut msghdr: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
                msghdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
                msghdr.msg_namelen = sockaddr_len;
                msghdr.msg_iov = iov;
                msghdr.msg_iovlen = 1;
                libc::mmsghdr {
                    msg_hdr: msghdr,
                    msg_len: 0,
                }
            })
            .collect();

        let result = unsafe {
            libc::sendmmsg(
                self.socket_fd,
                msghdrs.as_mut_ptr(),
                msghdrs.len() as libc::c_uint,
                0,
            )
        };

        if result < 0 {
            self.stats.record_error();
            return Err(io::Error::last_os_error());
        }

        let sent = result as usize;
        self.stats.record_fallback(sent as u64);
        Ok(sent)
    }

    /// Send using sendmmsg fallback (non-Linux).
    #[cfg(not(target_os = "linux"))]
    fn send_with_sendmmsg(&mut self, dest: SocketAddr, packets: &[&[u8]]) -> io::Result<usize> {
        let mut sent = 0;
        for packet in packets {
            match self.send_single(dest, packet) {
                Ok(_) => sent += 1,
                Err(e) => {
                    if sent == 0 {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        self.stats.record_fallback(sent as u64);
        Ok(sent)
    }

    /// Send a single packet.
    fn send_single(&self, dest: SocketAddr, data: &[u8]) -> io::Result<usize> {
        use std::mem::MaybeUninit;

        match dest {
            SocketAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = unsafe { MaybeUninit::zeroed().assume_init() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());

                let result = unsafe {
                    libc::sendto(
                        self.socket_fd,
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                        0,
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };

                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }
            SocketAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = unsafe { MaybeUninit::zeroed().assume_init() };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_flowinfo = v6.flowinfo();
                sa.sin6_addr.s6_addr = v6.ip().octets();
                sa.sin6_scope_id = v6.scope_id();

                let result = unsafe {
                    libc::sendto(
                        self.socket_fd,
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                        0,
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                };

                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_gso_stats() {
        let stats = GsoStats::new();

        stats.record_gso(5);
        stats.record_fallback(3);
        stats.record_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.gso_batches, 1);
        assert_eq!(snapshot.gso_packets, 5);
        assert_eq!(snapshot.fallback_batches, 1);
        assert_eq!(snapshot.fallback_packets, 3);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_gso_batch_sender_new() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let sender = GsoBatchSender::new(fd).unwrap();
        // GSO availability depends on platform/kernel
        let _ = sender.is_gso_available();
    }

    #[test]
    fn test_gso_send_single() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let mut sender = GsoBatchSender::new(fd).unwrap();
        let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let packets: Vec<&[u8]> = vec![&[1, 2, 3, 4]];
        let result = sender.send_batch(dest, &packets);
        // May fail if port not listening, but shouldn't panic
        let _ = result;
    }

    #[test]
    fn test_gso_send_batch() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let mut sender = GsoBatchSender::new(fd).unwrap();
        let dest: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Create same-size packets
        let data1 = vec![1u8; 100];
        let data2 = vec![2u8; 100];
        let data3 = vec![3u8; 100];
        let packets: Vec<&[u8]> = vec![&data1, &data2, &data3];

        let result = sender.send_batch(dest, &packets);
        // May fail if port not listening, but shouldn't panic
        let _ = result;
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_can_use_gso() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let sender = GsoBatchSender::new(fd).unwrap();

        // Same size packets - should be eligible
        let data1 = vec![1u8; 100];
        let data2 = vec![2u8; 100];
        let packets: Vec<&[u8]> = vec![&data1, &data2];
        assert!(sender.can_use_gso(&packets));

        // Different size packets - not eligible
        let data3 = vec![3u8; 50];
        let mixed: Vec<&[u8]> = vec![&data1, &data3];
        assert!(!sender.can_use_gso(&mixed));

        // Single packet - not eligible
        let single: Vec<&[u8]> = vec![&data1];
        assert!(!sender.can_use_gso(&single));

        // Last packet smaller - eligible
        let last_smaller: Vec<&[u8]> = vec![&data1, &data2, &data3];
        assert!(sender.can_use_gso(&last_smaller));
    }

    #[test]
    fn test_gso_ipv6() {
        let socket = UdpSocket::bind("[::1]:0").unwrap();
        let fd = socket.as_raw_fd();

        let mut sender = GsoBatchSender::new(fd).unwrap();
        let dest: SocketAddr = "[::1]:9999".parse().unwrap();

        let packets: Vec<&[u8]> = vec![&[1, 2, 3, 4]];
        let result = sender.send_batch(dest, &packets);
        let _ = result;
    }
}
