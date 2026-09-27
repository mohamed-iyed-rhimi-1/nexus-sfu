//! Parking a shard thread without losing wake-ups (note §3.3).
//!
//! The shard's socket and a `mio::Waker` are registered with one
//! `mio::Poll` (epoll on Linux, kqueue on macOS). Protocol:
//! - the shard sets `parked`, then checks its command queue once more, and
//!   calls `poll` only if the queue is still empty;
//! - a producer pushes first, then wakes only if it cleared `parked`.
//!
//! A command pushed after the shard's last check finds `parked` set and
//! wakes it; one pushed before is seen by the check. A busy shard costs
//! producers no syscall. mio is edge-triggered, so the shard parks only
//! after a receive call returned `WouldBlock` (the runner's rule).

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

const SOCKET: Token = Token(0);
const WAKER: Token = Token(1);
/// Readiness events per poll: the socket and the waker.
const EVENTS: usize = 8;

/// The shard side: polls the socket and the waker.
pub struct Parker {
    poll: Poll,
    events: Events,
    parked: Arc<AtomicBool>,
    /// Keeps the waker's fd open as long as the poll: on Linux, closing an
    /// eventfd removes its pending readiness from epoll, so a producer
    /// that woke the shard and then dropped the last `Wake` would lose the
    /// wake-up.
    _waker: Arc<Waker>,
}

/// The producer side: wakes a parked shard.
#[derive(Clone)]
pub struct Wake {
    parked: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

impl Parker {
    /// Registers `socket` for readability; returns the parker and the
    /// producers' wake handle.
    pub fn new(socket: RawFd) -> io::Result<(Self, Wake)> {
        assert!(socket >= 0);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut SourceFd(&socket), SOCKET, Interest::READABLE)?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKER)?);
        let parked = Arc::new(AtomicBool::new(false));
        let wake = Wake {
            parked: Arc::clone(&parked),
            waker: Arc::clone(&waker),
        };
        let parker = Self {
            poll,
            events: Events::with_capacity(EVENTS),
            parked,
            _waker: waker,
        };
        Ok((parker, wake))
    }

    /// Parks until the socket is readable, a producer wakes the shard, or
    /// `timeout` passes. Returns without parking when `pending()` says work
    /// arrived after the flag was set. Returns whether it polled.
    pub fn park(&mut self, timeout: Duration, pending: impl Fn() -> bool) -> bool {
        self.parked.store(true, Ordering::SeqCst);
        if pending() {
            self.parked.store(false, Ordering::SeqCst);
            return false;
        }
        // An interrupted or failed poll only ends the park early; the loop
        // runs and parks again.
        let _ = self.poll.poll(&mut self.events, Some(timeout));
        self.parked.store(false, Ordering::SeqCst);
        true
    }
}

impl Wake {
    /// Wakes the shard if it is parked (after the producer pushed).
    pub fn wake(&self) -> io::Result<()> {
        if self.parked.swap(false, Ordering::SeqCst) {
            self.waker.wake()?;
        }
        Ok(())
    }

    /// Wakes the shard whether or not it is parked (shutdown).
    pub fn wake_always(&self) -> io::Result<()> {
        self.parked.store(false, Ordering::SeqCst);
        self.waker.wake()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    fn parker() -> (UdpSocket, Parker, Wake) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let (parker, wake) = Parker::new(socket.as_raw_fd()).unwrap();
        (socket, parker, wake)
    }

    #[test]
    fn pending_work_skips_the_park() {
        let (_socket, mut parker, _wake) = parker();
        let start = Instant::now();
        assert!(!parker.park(Duration::from_secs(5), || true));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn times_out_when_idle() {
        let (_socket, mut parker, _wake) = parker();
        let start = Instant::now();
        assert!(parker.park(Duration::from_millis(20), || false));
        assert!(start.elapsed() >= Duration::from_millis(15));
    }

    #[test]
    fn a_wake_ends_the_park() {
        let (_socket, mut parker, wake) = parker();
        let waker = std::thread::spawn(move || {
            // Wakes only once the shard is parked; retries until then.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !wake.parked.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::yield_now();
            }
            wake.wake().unwrap();
        });
        let start = Instant::now();
        assert!(parker.park(Duration::from_secs(5), || false));
        assert!(start.elapsed() < Duration::from_secs(2));
        waker.join().unwrap();
    }

    #[test]
    fn a_datagram_ends_the_park() {
        let (socket, mut parker, _wake) = parker();
        let to = socket.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.send_to(b"x", to).unwrap();
        });
        let start = Instant::now();
        assert!(parker.park(Duration::from_secs(5), || false));
        assert!(start.elapsed() < Duration::from_secs(2));
        sender.join().unwrap();
    }

    #[test]
    fn wake_without_park_costs_no_syscall() {
        let (_socket, mut parker, wake) = parker();
        wake.wake().unwrap();
        // No stale wake-up: an idle park still times out.
        let start = Instant::now();
        assert!(parker.park(Duration::from_millis(20), || false));
        assert!(start.elapsed() >= Duration::from_millis(15));
    }
}
