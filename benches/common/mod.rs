//! Helpers shared by the benches that send to loopback sockets
//! (`real_path.rs`, `udp_floor.rs`).

// Each bench compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Raise the open-file limit so hundreds of sink sockets can be bound.
pub fn raise_fd_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit only read/write the struct we pass.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur = limit.rlim_max.min(8192);
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

pub const DRAIN_THREADS: usize = 4;

/// Loopback sockets standing in for subscribers, drained by background
/// threads. Undrained sockets fill up and make sends fail (ENOBUFS on
/// macOS), and failed sends are much cheaper than real ones.
pub struct Sinks {
    pub addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    received: Arc<AtomicU64>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Sinks {
    pub fn new(count: usize) -> Self {
        assert!(count > 0, "need at least one sink");
        let sockets: Vec<UdpSocket> = (0..count)
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("bind sink socket"))
            .collect();
        let addrs: Vec<SocketAddr> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicU64::new(0));
        let per_thread = count.div_ceil(DRAIN_THREADS);
        let mut threads = Vec::with_capacity(DRAIN_THREADS);
        let mut sockets = sockets.into_iter();
        for _ in 0..DRAIN_THREADS {
            let chunk: Vec<UdpSocket> = sockets.by_ref().take(per_thread).collect();
            if chunk.is_empty() {
                break;
            }
            let stop = Arc::clone(&stop);
            let received = Arc::clone(&received);
            threads.push(std::thread::spawn(move || drain(chunk, stop, received)));
        }
        assert_eq!(addrs.len(), count);
        Self {
            addrs,
            stop,
            received,
            threads,
        }
    }

    /// Datagrams the drain threads have read so far.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

fn drain(sockets: Vec<UdpSocket>, stop: Arc<AtomicBool>, received: Arc<AtomicU64>) {
    let mut buf = [0u8; 1500];
    for socket in &sockets {
        socket.set_nonblocking(true).expect("nonblocking sink");
    }
    while !stop.load(Ordering::Relaxed) {
        let mut count = 0u64;
        for socket in &sockets {
            // Bounded: at most 64 datagrams per socket per pass.
            for _ in 0..64 {
                if socket.recv(&mut buf).is_err() {
                    break;
                }
                count += 1;
            }
        }
        // One shared-counter update per pass, not per datagram.
        if count > 0 {
            received.fetch_add(count, Ordering::Relaxed);
        }
    }
}

impl Drop for Sinks {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
