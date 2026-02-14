//! BatchSender for sendmmsg-based multi-packet transmission.
//!
//! Accumulates packets and sends them in a single syscall
//! to reduce overhead and increase throughput.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::arena::PacketSlot;

/// Maximum batch size limit.
const MAX_BATCH_SIZE_LIMIT: u32 = 64;
/// Default batch size.
const DEFAULT_BATCH_SIZE: u32 = 64;
/// Default flush interval in microseconds (1ms).
const DEFAULT_FLUSH_INTERVAL_US: u32 = 1000;

/// Statistics for batch sender operations.
#[derive(Debug, Default)]
pub struct BatchSenderStats {
    pub batches_sent: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_failed: AtomicU64,
    pub avg_batch_size_scaled: AtomicU32,
}

impl BatchSenderStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful batch send.
    #[inline(always)]
    pub fn record_batch(
        &self, batch_size: u32,
        packets_sent: u32, packets_failed: u32,
    ) {
        self.batches_sent.fetch_add(1, Ordering::Relaxed);
        self.packets_sent.fetch_add(
            packets_sent as u64, Ordering::Relaxed,
        );
        self.packets_failed.fetch_add(
            packets_failed as u64, Ordering::Relaxed,
        );
        let current_avg = self.avg_batch_size_scaled
            .load(Ordering::Relaxed);
        let new_avg =
            (current_avg * 90 / 100) + (batch_size * 10);
        self.avg_batch_size_scaled
            .store(new_avg, Ordering::Relaxed);
    }

    /// Get the average batch size.
    #[inline(always)]
    pub fn avg_batch_size(&self) -> f32 {
        self.avg_batch_size_scaled
            .load(Ordering::Relaxed) as f32 / 100.0
    }

    /// Get snapshot of current statistics.
    pub fn snapshot(&self) -> BatchSenderStatsSnapshot {
        BatchSenderStatsSnapshot {
            batches_sent: self.batches_sent
                .load(Ordering::Relaxed),
            packets_sent: self.packets_sent
                .load(Ordering::Relaxed),
            packets_failed: self.packets_failed
                .load(Ordering::Relaxed),
            avg_batch_size: self.avg_batch_size(),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.batches_sent.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_failed.store(0, Ordering::Relaxed);
        self.avg_batch_size_scaled
            .store(0, Ordering::Relaxed);
    }
}

/// Snapshot of batch sender statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BatchSenderStatsSnapshot {
    pub batches_sent: u64,
    pub packets_sent: u64,
    pub packets_failed: u64,
    pub avg_batch_size: f32,
}

/// Batches packets for efficient sendmmsg transmission.
pub struct BatchSender {
    socket_fd: RawFd,
    batches: HashMap<SocketAddr, Vec<PacketSlot>>,
    max_batch_size: u32,
    flush_interval_us: u32,
    last_flush_ns: AtomicU64,
    pending_count: u32,
    stats: BatchSenderStats,
    #[cfg(feature = "sim")]
    simulated: bool,
    #[cfg(feature = "sim")]
    captured: Vec<(SocketAddr, PacketSlot)>,
}

impl BatchSender {
    /// Returns true if batch sending (sendmmsg) is available on this platform.
    ///
    /// This const fn allows compile-time and runtime verification that the
    /// efficient sendmmsg code path is available. Returns true on Linux,
    /// false on all other platforms.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if BatchSender::is_batch_send_available() {
    ///     println!("Using efficient sendmmsg batch sending");
    /// } else {
    ///     println!("Falling back to individual sendto calls");
    /// }
    /// ```
    #[inline(always)]
    pub const fn is_batch_send_available() -> bool {
        cfg!(target_os = "linux")
    }

    /// Create a new batch sender for the given socket.
    pub fn new(
        socket_fd: RawFd,
        max_batch_size: u32,
        flush_interval_us: u32,
    ) -> Self {
        assert!(
            max_batch_size > 0,
            "max_batch_size must be > 0"
        );
        assert!(
            max_batch_size <= MAX_BATCH_SIZE_LIMIT,
            "max_batch_size must be <= {}",
            MAX_BATCH_SIZE_LIMIT
        );
        Self {
            socket_fd,
            batches: HashMap::new(),
            max_batch_size,
            flush_interval_us,
            last_flush_ns: AtomicU64::new(
                Self::current_time_ns(),
            ),
            pending_count: 0,
            stats: BatchSenderStats::new(),
            #[cfg(feature = "sim")]
            simulated: false,
            #[cfg(feature = "sim")]
            captured: Vec::new(),
        }
    }

    /// Create a simulated batch sender that captures packets instead of sending.
    #[cfg(feature = "sim")]
    pub fn new_simulated() -> Self {
        Self {
            socket_fd: -1,
            batches: HashMap::new(),
            max_batch_size: DEFAULT_BATCH_SIZE,
            flush_interval_us: DEFAULT_FLUSH_INTERVAL_US,
            last_flush_ns: AtomicU64::new(0),
            pending_count: 0,
            stats: BatchSenderStats::new(),
            simulated: true,
            captured: Vec::new(),
        }
    }

    /// Create with default settings.
    pub fn with_defaults(socket_fd: RawFd) -> Self {
        Self::new(
            socket_fd,
            DEFAULT_BATCH_SIZE,
            DEFAULT_FLUSH_INTERVAL_US,
        )
    }

    /// Queue a packet for sending.
    pub fn queue(
        &mut self, dest: SocketAddr, packet: PacketSlot,
    ) {
        assert!(
            packet.len() > 0,
            "packet data_len_bytes must be > 0"
        );
        #[cfg(feature = "sim")]
        if self.simulated {
            self.captured.push((dest, packet));
            self.pending_count += 1;
            return;
        }
        let batch = self.batches
            .entry(dest)
            .or_insert_with(Vec::new);
        batch.push(packet);
        self.pending_count += 1;
    }

    /// Check if flush is needed.
    pub fn should_flush(&self) -> bool {
        if self.pending_count >= self.max_batch_size {
            return true;
        }
        let now_ns = Self::current_time_ns();
        let last_flush =
            self.last_flush_ns.load(Ordering::Relaxed);
        let elapsed_us =
            (now_ns.saturating_sub(last_flush)) / 1000;
        elapsed_us >= self.flush_interval_us as u64
    }

    /// Flush all pending batches.
    pub fn flush(&mut self) -> (u32, u32) {
        if self.pending_count == 0 {
            return (0, 0);
        }

        #[cfg(feature = "sim")]
        if self.simulated {
            let sent = self.pending_count;
            self.pending_count = 0;
            self.stats.record_batch(sent, sent, 0);
            return (sent, 0);
        }

        assert!(
            self.socket_fd >= 0,
            "socket_fd must be valid (>= 0)"
        );
        let total_packets = self.pending_count;

        #[cfg(target_os = "linux")]
        let (sent, failed) = self.flush_sendmmsg();

        #[cfg(not(target_os = "linux"))]
        let (sent, failed) = self.flush_sendto();

        self.stats.record_batch(
            total_packets, sent, failed,
        );
        self.batches.clear();
        self.pending_count = 0;
        self.last_flush_ns.store(
            Self::current_time_ns(), Ordering::Relaxed,
        );
        (sent, failed)
    }

    #[cfg(target_os = "linux")]
    fn flush_sendmmsg(&mut self) -> (u32, u32) {
        use std::mem::MaybeUninit;

        let mut packets: Vec<(&PacketSlot, SocketAddr)> =
            Vec::with_capacity(self.pending_count as usize);
        for (dest, batch) in &self.batches {
            for packet in batch {
                packets.push((packet, *dest));
            }
        }
        if packets.is_empty() {
            return (0, 0);
        }
        let num_packets = packets.len();
        let mut iovecs: Vec<libc::iovec> =
            Vec::with_capacity(num_packets);
        let mut msghdrs: Vec<libc::mmsghdr> =
            Vec::with_capacity(num_packets);
        let mut sockaddrs: Vec<libc::sockaddr_storage> =
            Vec::with_capacity(num_packets);
        let mut sockaddr_lens: Vec<libc::socklen_t> =
            Vec::with_capacity(num_packets);

        for (packet, dest) in &packets {
            let iov = libc::iovec {
                iov_base: packet.data().as_ptr()
                    as *mut libc::c_void,
                iov_len: packet.len() as usize,
            };
            iovecs.push(iov);
            let mut storage: libc::sockaddr_storage =
                unsafe { MaybeUninit::zeroed().assume_init() };
            let sockaddr_len = match dest {
                SocketAddr::V4(addr) => {
                    let sa = &mut storage as *mut _
                        as *mut libc::sockaddr_in;
                    unsafe {
                        (*sa).sin_family =
                            libc::AF_INET as libc::sa_family_t;
                        (*sa).sin_port = addr.port().to_be();
                        (*sa).sin_addr.s_addr =
                            u32::from_ne_bytes(
                                addr.ip().octets(),
                            );
                    }
                    std::mem::size_of::<libc::sockaddr_in>()
                        as libc::socklen_t
                }
                SocketAddr::V6(addr) => {
                    let sa = &mut storage as *mut _
                        as *mut libc::sockaddr_in6;
                    unsafe {
                        (*sa).sin6_family =
                            libc::AF_INET6
                                as libc::sa_family_t;
                        (*sa).sin6_port = addr.port().to_be();
                        (*sa).sin6_flowinfo = addr.flowinfo();
                        (*sa).sin6_addr.s6_addr =
                            addr.ip().octets();
                        (*sa).sin6_scope_id = addr.scope_id();
                    }
                    std::mem::size_of::<libc::sockaddr_in6>()
                        as libc::socklen_t
                }
            };
            sockaddrs.push(storage);
            sockaddr_lens.push(sockaddr_len);
        }

        for i in 0..iovecs.len() {
            let mut msghdr: libc::msghdr =
                unsafe { MaybeUninit::zeroed().assume_init() };
            msghdr.msg_name = &mut sockaddrs[i] as *mut _
                as *mut libc::c_void;
            msghdr.msg_namelen = sockaddr_lens[i];
            msghdr.msg_iov = &mut iovecs[i];
            msghdr.msg_iovlen = 1;
            let mmsghdr = libc::mmsghdr {
                msg_hdr: msghdr,
                msg_len: 0,
            };
            msghdrs.push(mmsghdr);
        }

        let result = unsafe {
            libc::sendmmsg(
                self.socket_fd,
                msghdrs.as_mut_ptr(),
                msghdrs.len() as libc::c_uint,
                0,
            )
        };
        if result < 0 {
            return (0, num_packets as u32);
        }
        let sent = result as u32;
        let failed = (num_packets as u32).saturating_sub(sent);
        (sent, failed)
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_sendto(&mut self) -> (u32, u32) {
        let mut sent = 0u32;
        let mut failed = 0u32;
        for (dest, batch) in &self.batches {
            for packet in batch {
                if self.send_single(packet.data(), *dest) {
                    sent += 1;
                } else {
                    failed += 1;
                }
            }
        }
        (sent, failed)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_single(
        &self, data: &[u8], dest: SocketAddr,
    ) -> bool {
        use std::mem::MaybeUninit;
        match dest {
            SocketAddr::V4(addr) => {
                let mut sa: libc::sockaddr_in =
                    unsafe { MaybeUninit::zeroed().assume_init() };
                sa.sin_family =
                    libc::AF_INET as libc::sa_family_t;
                sa.sin_port = addr.port().to_be();
                sa.sin_addr.s_addr =
                    u32::from_ne_bytes(addr.ip().octets());
                let result = unsafe {
                    libc::sendto(
                        self.socket_fd,
                        data.as_ptr()
                            as *const libc::c_void,
                        data.len(), 0,
                        &sa as *const _
                            as *const libc::sockaddr,
                        std::mem::size_of::<
                            libc::sockaddr_in,
                        >() as libc::socklen_t,
                    )
                };
                result >= 0
            }
            SocketAddr::V6(addr) => {
                let mut sa: libc::sockaddr_in6 =
                    unsafe { MaybeUninit::zeroed().assume_init() };
                sa.sin6_family =
                    libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = addr.port().to_be();
                sa.sin6_flowinfo = addr.flowinfo();
                sa.sin6_addr.s6_addr = addr.ip().octets();
                sa.sin6_scope_id = addr.scope_id();
                let result = unsafe {
                    libc::sendto(
                        self.socket_fd,
                        data.as_ptr()
                            as *const libc::c_void,
                        data.len(), 0,
                        &sa as *const _
                            as *const libc::sockaddr,
                        std::mem::size_of::<
                            libc::sockaddr_in6,
                        >() as libc::socklen_t,
                    )
                };
                result >= 0
            }
        }
    }

    /// Get current statistics.
    #[inline(always)]
    pub fn stats(&self) -> &BatchSenderStats {
        &self.stats
    }

    /// Get the number of pending packets.
    #[inline(always)]
    pub fn pending_count(&self) -> u32 {
        self.pending_count
    }

    /// Get the number of destinations.
    #[inline(always)]
    pub fn destination_count(&self) -> usize {
        self.batches.len()
    }

    /// Get the maximum batch size.
    #[inline(always)]
    pub fn max_batch_size(&self) -> u32 {
        self.max_batch_size
    }

    /// Get the flush interval in microseconds.
    #[inline(always)]
    pub fn flush_interval_us(&self) -> u32 {
        self.flush_interval_us
    }

    /// Drain all captured (dest, packet) pairs from simulated mode.
    /// Returns an empty vec if not in simulated mode.
    #[cfg(feature = "sim")]
    pub fn drain_captured(&mut self) -> Vec<(SocketAddr, PacketSlot)> {
        std::mem::take(&mut self.captured)
    }

    /// Check if this batch sender is in simulated mode.
    #[cfg(feature = "sim")]
    pub fn is_simulated(&self) -> bool {
        self.simulated
    }

    #[inline(always)]
    fn current_time_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_sender_stats_new() {
        let stats = BatchSenderStats::new();
        let snap = stats.snapshot();
        assert_eq!(snap.batches_sent, 0);
        assert_eq!(snap.packets_sent, 0);
    }

    #[test]
    fn test_batch_sender_new() {
        let sender = BatchSender::new(3, 32, 500);
        assert_eq!(sender.max_batch_size(), 32);
        assert_eq!(sender.flush_interval_us(), 500);
        assert_eq!(sender.pending_count(), 0);
    }

    #[test]
    fn test_batch_sender_queue() {
        use crate::arena::PacketArena;
        let arena = PacketArena::new(1).unwrap();
        let mut sender = BatchSender::new(3, 64, 1000);
        let mut slot = arena.alloc().unwrap();
        slot.data_mut()[0..4].copy_from_slice(&[1, 2, 3, 4]);
        slot.set_len(4);
        let dest: SocketAddr =
            "192.168.1.1:5000".parse().unwrap();
        sender.queue(dest, slot);
        assert_eq!(sender.pending_count(), 1);
        assert_eq!(sender.destination_count(), 1);
    }

    #[test]
    fn test_is_batch_send_available() {
        // Verify is_batch_send_available returns expected value for current platform
        let available = BatchSender::is_batch_send_available();
        
        #[cfg(target_os = "linux")]
        assert!(available, "is_batch_send_available should return true on Linux");
        
        #[cfg(not(target_os = "linux"))]
        assert!(!available, "is_batch_send_available should return false on non-Linux");
    }

    #[test]
    fn test_is_batch_send_available_is_const() {
        // Verify the function can be used in const context
        const BATCH_AVAILABLE: bool = BatchSender::is_batch_send_available();
        
        // The value should match runtime check
        assert_eq!(BATCH_AVAILABLE, BatchSender::is_batch_send_available());
    }
}
