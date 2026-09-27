//! Datagram I/O backends (note §3.5): `LinuxIo` (`recvmmsg`/`sendmmsg`),
//! `PortableIo` (`recv_from`/`send_to`, macOS) and `MemIo` (tests).
//!
//! Both socket backends report IPv4 peers of a dual-stack (`::`) socket as
//! `SocketAddr::V4`, and send to them through their v4-mapped form, so the
//! shard, its events and the announced candidates agree on one address.

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};

use crate::pool::{BufRef, BufferPool, BUF_SIZE};

// The only module allowed `unsafe`: Linux syscalls, each block with a
// `// SAFETY:` comment.
#[cfg(test)]
mod conformance;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) mod linux;
mod portable;

#[cfg(target_os = "linux")]
pub use linux::{udp_gro_enabled, LinuxIo};
pub use portable::PortableIo;

/// The socket backend of this platform.
#[cfg(target_os = "linux")]
pub type PlatformIo = LinuxIo;
/// The socket backend of this platform.
#[cfg(not(target_os = "linux"))]
pub type PlatformIo = PortableIo;

/// A received source address as the shard sees it: an IPv4 peer of a
/// dual-stack socket (`::ffff:a.b.c.d`) becomes `V4`.
pub fn normalize_source(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// A destination as the socket needs it: an IPv6 socket sends to an IPv4
/// peer through the v4-mapped address.
pub fn socket_destination(addr: SocketAddr, socket_is_v6: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if socket_is_v6 => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

/// A send error after which the rest of the batch is dropped (the socket
/// buffer is full); any other error drops only the datagram that caused it.
pub(crate) fn send_buffer_full(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::ENOBUFS)
}

/// Most datagrams received per iteration.
pub const RECV_BATCH: usize = 64;
/// Most datagrams queued before a send flush.
pub const SEND_BATCH: usize = 256;

/// A datagram in a pool buffer.
#[derive(Clone, Copy, Debug)]
pub struct Datagram {
    /// The buffer.
    pub buf: BufRef,
    /// Bytes used.
    pub len: usize,
    /// Source (receive) or destination (send).
    pub addr: SocketAddr,
}

macro_rules! batch {
    ($(#[$doc:meta])* $name:ident, $cap:expr) => {
        $(#[$doc])*
        pub struct $name {
            items: Vec<Datagram>,
        }

        impl $name {
            /// Most datagrams in the batch.
            pub const CAPACITY: usize = $cap;

            /// An empty batch; its storage is allocated once, here.
            pub fn new() -> Self {
                Self { items: Vec::with_capacity($cap) }
            }

            /// Datagrams in the batch.
            pub fn len(&self) -> usize {
                self.items.len()
            }

            /// No datagram in the batch.
            pub fn is_empty(&self) -> bool {
                self.items.is_empty()
            }

            /// The batch holds `CAPACITY` datagrams.
            pub fn is_full(&self) -> bool {
                self.items.len() == $cap
            }

            /// The `i`-th datagram.
            pub fn get(&self, i: usize) -> Datagram {
                self.items[i]
            }

            /// Appends a datagram; the batch must not be full (never grows).
            pub fn push(&mut self, datagram: Datagram) {
                assert!(!self.is_full());
                debug_assert!(datagram.len <= BUF_SIZE);
                self.items.push(datagram);
            }

            /// Empties the batch; the caller has returned the buffers.
            pub fn clear(&mut self) {
                self.items.clear();
            }

            /// The datagrams.
            pub fn iter(&self) -> impl Iterator<Item = &Datagram> {
                self.items.iter()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

batch!(
    /// Datagrams received in one iteration.
    RecvBatch,
    RECV_BATCH
);
batch!(
    /// Datagrams waiting to be sent.
    SendBatch,
    SEND_BATCH
);

/// Result of one receive call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvResult {
    /// Datagrams added to the batch.
    pub received: usize,
    /// The source is drained (the next call would block).
    pub would_block: bool,
    /// Datagrams larger than a pool buffer, dropped (`MSG_TRUNC`).
    pub truncated: usize,
    /// Datagrams taken from the socket but dropped because their source
    /// address could not be read (unknown family, short length).
    pub unreadable: usize,
}

impl RecvResult {
    /// Datagrams taken from the socket, kept or dropped: any of them is
    /// work, so the shard must not park after this call.
    pub fn taken(&self) -> usize {
        self.received + self.truncated + self.unreadable
    }
}

/// Result of one flush.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sent {
    /// Datagrams the kernel took.
    pub datagrams: usize,
    /// Their bytes.
    pub bytes: usize,
}

/// How a shard receives and sends datagrams.
pub trait DatagramIo {
    /// Receives up to the batch's free room into pool buffers. Never blocks.
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult>;

    /// Sends every datagram in `tx`, returns their buffers to the pool and
    /// empties `tx`. Returns what was sent; the rest was dropped.
    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent;
}

struct Captured {
    addr: SocketAddr,
    start: usize,
    len: usize,
}

/// In-memory I/O for tests: datagrams queued by the test, output captured.
///
/// Output bytes go into one flat buffer, so a `MemIo` built with enough
/// capacity does not allocate while the shard runs (`tests/alloc.rs`).
#[derive(Default)]
pub struct MemIo {
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    out_bytes: Vec<u8>,
    out: Vec<Captured>,
    /// Inbound datagrams over `BUF_SIZE`, dropped (as `MSG_TRUNC` on Linux).
    pub dropped_oversize: u64,
}

impl MemIo {
    /// An empty `MemIo`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Room for `inbound` queued datagrams and `datagrams` captured ones of
    /// `bytes` bytes in total.
    pub fn with_capacity(inbound: usize, datagrams: usize, bytes: usize) -> Self {
        Self {
            inbound: VecDeque::with_capacity(inbound),
            out_bytes: Vec::with_capacity(bytes),
            out: Vec::with_capacity(datagrams),
            dropped_oversize: 0,
        }
    }

    /// Queues a datagram from `from`.
    pub fn push_inbound(&mut self, from: SocketAddr, bytes: Vec<u8>) {
        self.inbound.push_back((from, bytes));
    }

    /// Datagrams queued and not yet received.
    pub fn inbound_len(&self) -> usize {
        self.inbound.len()
    }

    /// Captured output, in send order.
    pub fn outbound(&self) -> impl Iterator<Item = (SocketAddr, &[u8])> + '_ {
        self.out
            .iter()
            .map(|c| (c.addr, &self.out_bytes[c.start..c.start + c.len]))
    }

    /// Number of captured datagrams.
    pub fn outbound_len(&self) -> usize {
        self.out.len()
    }

    /// Forgets captured output (keeps the storage).
    pub fn clear_outbound(&mut self) {
        self.out.clear();
        self.out_bytes.clear();
    }

    /// Takes the captured output.
    pub fn take_outbound(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let taken = self.outbound().map(|(a, b)| (a, b.to_vec())).collect();
        self.clear_outbound();
        taken
    }
}

impl DatagramIo for MemIo {
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult> {
        let mut received = 0;
        let dropped_before = self.dropped_oversize;
        while !rx.is_full() {
            let Some((addr, bytes)) = self.inbound.front() else {
                break;
            };
            if bytes.len() > BUF_SIZE {
                self.dropped_oversize += 1;
                self.inbound.pop_front();
                continue;
            }
            let Some(buf) = pool.take() else { break };
            let len = bytes.len();
            pool.buf_mut(buf)[..len].copy_from_slice(bytes);
            rx.push(Datagram {
                buf,
                len,
                addr: *addr,
            });
            self.inbound.pop_front();
            received += 1;
        }
        let truncated = (self.dropped_oversize - dropped_before) as usize;
        Ok(RecvResult {
            received,
            would_block: self.inbound.is_empty(),
            truncated,
            unreadable: 0,
        })
    }

    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent {
        let sent = Sent {
            datagrams: tx.len(),
            bytes: tx.iter().map(|d| d.len).sum(),
        };
        for d in tx.iter() {
            let start = self.out_bytes.len();
            self.out_bytes.extend_from_slice(&pool.buf(d.buf)[..d.len]);
            self.out.push(Captured {
                addr: d.addr,
                start,
                len: d.len,
            });
            pool.put(d.buf);
        }
        tx.clear();
        sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_mapped_sources_become_v4() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4000".parse().unwrap();
        assert_eq!(normalize_source(mapped), "192.0.2.7:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(normalize_source(v6), v6);
        let v4: SocketAddr = "192.0.2.7:4000".parse().unwrap();
        assert_eq!(normalize_source(v4), v4);
    }

    #[test]
    fn v4_destinations_are_mapped_on_v6_sockets() {
        let v4: SocketAddr = "192.0.2.7:4000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4000".parse().unwrap();
        assert_eq!(socket_destination(v4, true), mapped);
        assert_eq!(socket_destination(v4, false), v4);
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(socket_destination(v6, true), v6);
        assert_eq!(normalize_source(socket_destination(v4, true)), v4);
    }
}
