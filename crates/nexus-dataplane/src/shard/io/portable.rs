//! `PortableIo`: one `recv_from` / `send_to` per datagram (note §3.5). Correct,
//! not fast: the macOS backend (design §3.12).

use std::io;
use std::net::UdpSocket;

use super::{
    normalize_source, send_buffer_full, socket_destination, Datagram, DatagramIo, RecvBatch,
    RecvResult, SendBatch, Sent,
};
use crate::pool::{BufferPool, BUF_SIZE};

/// Socket I/O with the standard library's calls.
///
/// `recv_from` reports no truncation, so datagrams land in a scratch buffer
/// one byte larger than a pool buffer: a datagram that fills it is too large
/// and dropped, the others are copied into a pool buffer.
pub struct PortableIo {
    socket: UdpSocket,
    socket_is_v6: bool,
    scratch: Box<[u8; BUF_SIZE + 1]>,
}

impl PortableIo {
    /// Takes a non-blocking socket.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let socket_is_v6 = socket.local_addr()?.is_ipv6();
        Ok(Self {
            socket,
            socket_is_v6,
            scratch: Box::new([0; BUF_SIZE + 1]),
        })
    }

    /// The socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl DatagramIo for PortableIo {
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult> {
        let mut result = RecvResult::default();
        // Each round receives, drops or ends the call: bounded by twice the
        // batch (truncated datagrams and interrupts do not fill it).
        for _ in 0..2 * RecvBatch::CAPACITY {
            // Checked before the receive: a datagram taken from the socket
            // always has a buffer.
            if rx.is_full() || pool.available() == 0 {
                break;
            }
            let (len, from) = match self.socket.recv_from(&mut self.scratch[..]) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    result.would_block = true;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if result.received == 0 && result.truncated == 0 => return Err(e),
                Err(_) => break,
            };
            if len > BUF_SIZE {
                result.truncated += 1;
                continue;
            }
            let Some(buf) = pool.take() else { break };
            pool.buf_mut(buf)[..len].copy_from_slice(&self.scratch[..len]);
            let addr = normalize_source(from);
            rx.push(Datagram { buf, len, addr });
            result.received += 1;
        }
        debug_assert!(result.received <= RecvBatch::CAPACITY);
        Ok(result)
    }

    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent {
        let mut sent = Sent::default();
        let mut buffer_full = false;
        for d in tx.iter() {
            if !buffer_full {
                let dest = socket_destination(d.addr, self.socket_is_v6);
                match self.socket.send_to(&pool.buf(d.buf)[..d.len], dest) {
                    Ok(n) => {
                        sent.datagrams += 1;
                        sent.bytes += n;
                    }
                    // The rest would fail the same way: dropped.
                    Err(e) if send_buffer_full(&e) => buffer_full = true,
                    // This destination only (unreachable, wrong family).
                    Err(_) => {}
                }
            }
            pool.put(d.buf);
        }
        debug_assert!(sent.datagrams <= tx.len());
        tx.clear();
        sent
    }
}

#[cfg(test)]
mod tests {
    use super::super::conformance;
    use super::*;

    #[test]
    fn conforms() {
        conformance::run_all(|socket| PortableIo::new(socket).expect("portable io"));
    }
}
