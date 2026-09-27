//! `LinuxIo`: `recvmmsg` / `sendmmsg` into and out of pool buffers (note §3.5),
//! and the other Linux syscalls of the shard thread. The only module of the
//! crate with `unsafe`; every block says why it is sound.
//!
//! Based on `benches/udp_floor.rs`, which is IPv4-only and never reads the
//! source address, `msg_len` or `msg_flags`. The header arrays are allocated
//! once; every pointer in them is set right before the call that uses it, so
//! a stale pointer is never passed to the kernel.

use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};

use super::{
    normalize_source, send_buffer_full, socket_destination, Datagram, DatagramIo, RecvBatch,
    RecvResult, SendBatch, Sent, RECV_BATCH, SEND_BATCH,
};
use crate::pool::{BufRef, BufferPool, BUF_SIZE};

/// Batched socket I/O with `recvmmsg` / `sendmmsg`.
pub struct LinuxIo {
    socket: UdpSocket,
    socket_is_v6: bool,
    rx_headers: Box<[libc::mmsghdr; RECV_BATCH]>,
    rx_iovecs: Box<[libc::iovec; RECV_BATCH]>,
    rx_names: Box<[libc::sockaddr_storage; RECV_BATCH]>,
    rx_bufs: [Option<BufRef>; RECV_BATCH],
    tx_headers: Box<[libc::mmsghdr; SEND_BATCH]>,
    tx_iovecs: Box<[libc::iovec; SEND_BATCH]>,
    tx_names: Box<[libc::sockaddr_storage; SEND_BATCH]>,
}

// SAFETY: the raw pointers inside the header arrays point only into this
// struct's own boxes and the caller's pool, and are rewritten before every
// syscall; nothing reads them between calls. Moving the struct to the shard
// thread moves every object they refer to, or leaves them unused.
unsafe impl Send for LinuxIo {}

/// Types for which all-zero bytes are a valid value.
///
/// # Safety
///
/// Implement only for plain C structs of integers and raw pointers: no
/// references, `NonNull`, enums or other types with invalid zero patterns.
unsafe trait Zeroable {}

// SAFETY: plain C structs of integers and raw pointers; zero is a null
// pointer or a zero length/family, all valid values.
unsafe impl Zeroable for libc::mmsghdr {}
// SAFETY: as above.
unsafe impl Zeroable for libc::iovec {}
// SAFETY: as above (integers and padding only).
unsafe impl Zeroable for libc::sockaddr_storage {}

/// A zeroed C struct array on the heap.
fn zeroed_box<T: Zeroable, const N: usize>() -> Box<[T; N]> {
    // SAFETY: `T: Zeroable`, so an array of all-zero `T`s is valid.
    Box::new(unsafe { std::mem::zeroed() })
}

impl LinuxIo {
    /// Takes a socket and makes it non-blocking. Refuses a socket with
    /// UDP_GRO on: the kernel would coalesce datagrams into reads larger
    /// than a pool buffer, and they would all be dropped as truncated.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        if udp_gro_enabled(socket.as_raw_fd())? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP_GRO is on for the shard socket",
            ));
        }
        socket.set_nonblocking(true)?;
        let socket_is_v6 = socket.local_addr()?.is_ipv6();
        Ok(Self {
            socket,
            socket_is_v6,
            rx_headers: zeroed_box(),
            rx_iovecs: zeroed_box(),
            rx_names: zeroed_box(),
            rx_bufs: [None; RECV_BATCH],
            tx_headers: zeroed_box(),
            tx_iovecs: zeroed_box(),
            tx_names: zeroed_box(),
        })
    }

    /// The socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Points receive slot `i` at `buf` and resets its lengths and flags.
    fn arm_rx(&mut self, i: usize, pool: &mut BufferPool, buf: BufRef) {
        self.rx_bufs[i] = Some(buf);
        self.rx_iovecs[i] = libc::iovec {
            iov_base: pool.buf_mut(buf).as_mut_ptr().cast(),
            iov_len: BUF_SIZE,
        };
        let header = &mut self.rx_headers[i];
        header.msg_hdr.msg_name = (&mut self.rx_names[i] as *mut libc::sockaddr_storage).cast();
        header.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        header.msg_hdr.msg_iov = &mut self.rx_iovecs[i];
        header.msg_hdr.msg_iovlen = 1;
        header.msg_hdr.msg_control = std::ptr::null_mut();
        header.msg_hdr.msg_controllen = 0;
        header.msg_hdr.msg_flags = 0;
        header.msg_len = 0;
    }

    /// Points send slot `i` at datagram `d`.
    fn arm_tx(&mut self, i: usize, pool: &mut BufferPool, d: Datagram) {
        let dest = socket_destination(d.addr, self.socket_is_v6);
        let name_len = write_sockaddr(dest, &mut self.tx_names[i]);
        self.tx_iovecs[i] = libc::iovec {
            iov_base: pool.buf_mut(d.buf).as_mut_ptr().cast(),
            iov_len: d.len,
        };
        let header = &mut self.tx_headers[i];
        header.msg_hdr.msg_name = (&mut self.tx_names[i] as *mut libc::sockaddr_storage).cast();
        header.msg_hdr.msg_namelen = name_len;
        header.msg_hdr.msg_iov = &mut self.tx_iovecs[i];
        header.msg_hdr.msg_iovlen = 1;
        header.msg_hdr.msg_control = std::ptr::null_mut();
        header.msg_hdr.msg_controllen = 0;
        header.msg_hdr.msg_flags = 0;
        header.msg_len = 0;
    }

    /// One `recvmmsg` into the first `armed` slots: the number received, 0
    /// with `would_block` when drained.
    fn recvmmsg(&mut self, armed: usize) -> io::Result<(usize, bool)> {
        debug_assert!(armed > 0 && armed <= RECV_BATCH);
        let fd = self.socket.as_raw_fd();
        // SAFETY: the first `armed` headers were set by `arm_rx` in this call
        // and point at live iovecs, names and pool buffers of `BUF_SIZE`
        // bytes; the kernel writes at most `armed` headers.
        let rc = unsafe {
            libc::recvmmsg(
                fd,
                self.rx_headers.as_mut_ptr(),
                armed as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if rc >= 0 {
            debug_assert!(rc as usize <= armed);
            return Ok((rc as usize, false));
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::WouldBlock => Ok((0, true)),
            io::ErrorKind::Interrupted => Ok((0, false)),
            _ => Err(err),
        }
    }

    /// One `sendmmsg` of slots `start..end`: the number the kernel took.
    fn sendmmsg(&mut self, start: usize, end: usize) -> io::Result<usize> {
        debug_assert!(start < end && end <= SEND_BATCH);
        let fd = self.socket.as_raw_fd();
        let headers = &mut self.tx_headers[start..end];
        // SAFETY: slots `start..end` were set by `arm_tx` in this flush and
        // point at live iovecs, names and pool buffers of the stated
        // lengths; the kernel only reads them (and writes `msg_len`).
        let rc =
            unsafe { libc::sendmmsg(fd, headers.as_mut_ptr(), headers.len() as libc::c_uint, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        debug_assert!(rc as usize <= end - start);
        Ok(rc as usize)
    }
}

impl DatagramIo for LinuxIo {
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult> {
        let room = (RecvBatch::CAPACITY - rx.len()).min(pool.available());
        if room == 0 {
            return Ok(RecvResult::default());
        }
        for i in 0..room {
            let buf = pool.take().expect("pool.available() checked above");
            self.arm_rx(i, pool, buf);
        }
        let outcome = self.recvmmsg(room);
        let received = *outcome.as_ref().unwrap_or(&(0, false));
        let mut result = RecvResult {
            would_block: received.1,
            ..RecvResult::default()
        };
        for i in 0..room {
            let buf = self.rx_bufs[i].take().expect("armed slot");
            if i >= received.0 {
                pool.put(buf);
                continue;
            }
            let header = &self.rx_headers[i];
            let source = read_sockaddr(&self.rx_names[i], header.msg_hdr.msg_namelen);
            let truncated = header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
            match source {
                Some(addr) if !truncated => {
                    let len = header.msg_len as usize;
                    debug_assert!(len <= BUF_SIZE);
                    let addr = normalize_source(addr);
                    rx.push(Datagram { buf, len, addr });
                    result.received += 1;
                }
                Some(_) => {
                    result.truncated += 1;
                    pool.put(buf);
                }
                None => {
                    result.unreadable += 1;
                    pool.put(buf);
                }
            }
        }
        outcome.map(|_| result)
    }

    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent {
        let count = tx.len();
        for i in 0..count {
            self.arm_tx(i, pool, tx.get(i));
        }
        let mut sent = Sent::default();
        let mut start = 0;
        // Every round sends at least one datagram, drops one, or ends the
        // flush; interrupts are retried within the same bound.
        for _ in 0..2 * count + 1 {
            if start == count {
                break;
            }
            match self.sendmmsg(start, count) {
                Ok(0) => break,
                Ok(n) => {
                    // The kernel wrote each sent message's byte count.
                    let headers = &self.tx_headers[start..start + n];
                    sent.bytes += headers.iter().map(|h| h.msg_len as usize).sum::<usize>();
                    sent.datagrams += n;
                    start += n;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // Socket buffer full: the rest is dropped (counted).
                Err(e) if send_buffer_full(&e) => break,
                // This destination only (unreachable, wrong family).
                Err(_) => start += 1,
            }
        }
        for d in tx.iter() {
            pool.put(d.buf);
        }
        tx.clear();
        debug_assert!(sent.datagrams <= count);
        sent
    }
}

/// Writes `addr` into `out` as a `sockaddr_in` / `sockaddr_in6`; returns
/// its length.
fn write_sockaddr(addr: SocketAddr, out: &mut libc::sockaddr_storage) -> libc::socklen_t {
    let storage = (out as *mut libc::sockaddr_storage).cast::<u8>();
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_storage` is larger than and aligned for
            // every socket address type; the write stays inside `out`.
            unsafe { storage.cast::<libc::sockaddr_in>().write(sin) };
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above.
            unsafe { storage.cast::<libc::sockaddr_in6>().write(sin6) };
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// The address the kernel wrote into `name`, `None` for another family or
/// a short length.
fn read_sockaddr(name: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    let storage = (name as *const libc::sockaddr_storage).cast::<u8>();
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET if len >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says `sockaddr_in`, the kernel wrote at
            // least its size, and `sockaddr_storage` is aligned for it.
            let sin = unsafe { &*storage.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddrV4::new(ip, u16::from_be(sin.sin_port)).into())
        }
        libc::AF_INET6 if len >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for `sockaddr_in6`.
            let sin6 = unsafe { &*storage.cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddrV6::new(ip, port, sin6.sin6_flowinfo, sin6.sin6_scope_id).into())
        }
        _ => None,
    }
}

/// Whether UDP_GRO is on for the socket. The shard never enables it: GRO
/// would coalesce datagrams into reads larger than a pool buffer. A kernel
/// without the option (before 5.0) cannot have it on: `ENOPROTOOPT` is
/// `Ok(false)`.
#[doc(hidden)]
pub fn udp_gro_enabled(fd: RawFd) -> io::Result<bool> {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are live locals of the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_UDP,
            nexus_transport::socket_config::UDP_GRO,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(value != 0)
}

/// SCHED_FIFO at `priority` (1..=99, checked by the config) for the calling
/// thread. Copied from `src/worker/pool.rs` with the priority validated by
/// the caller instead of asserted.
pub fn set_realtime_scheduling(priority: u8) -> Result<(), String> {
    debug_assert!((1..=99).contains(&priority));
    if !crate::sched::has_cap_sys_nice() {
        return Err("CAP_SYS_NICE capability not available".to_string());
    }
    let param = libc::sched_param {
        sched_priority: libc::c_int::from(priority),
    };
    // SAFETY: `param` is a live, initialised `sched_param`; pid 0 is the
    // calling thread.
    let rc = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(format!(
            "sched_setscheduler(SCHED_FIFO, {priority}) failed: {err}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::conformance;
    use super::*;

    #[test]
    fn conforms() {
        conformance::run_all(|socket| LinuxIo::new(socket).expect("linux io"));
    }

    #[test]
    fn sockaddr_round_trip() {
        let mut storage: libc::sockaddr_storage = *zeroed_box::<_, 1>().first().unwrap();
        for addr in [
            "192.0.2.1:5000",
            "[2001:db8::7]:6000",
            "[::ffff:192.0.2.1]:7",
        ] {
            let addr: SocketAddr = addr.parse().unwrap();
            let len = write_sockaddr(addr, &mut storage);
            assert_eq!(read_sockaddr(&storage, len), Some(addr));
        }
        assert_eq!(read_sockaddr(&storage, 4), None, "short length");
    }

    #[test]
    fn a_fresh_socket_has_gro_off() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(!udp_gro_enabled(socket.as_raw_fd()).unwrap());
    }

    #[test]
    fn a_socket_with_gro_on_is_refused() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let on = nexus_transport::socket_config::enable_gro(socket.as_raw_fd()).unwrap();
        if !on {
            eprintln!("skipped: kernel without UDP_GRO");
            return;
        }
        assert!(udp_gro_enabled(socket.as_raw_fd()).unwrap());
        let err = LinuxIo::new(socket).err().expect("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
