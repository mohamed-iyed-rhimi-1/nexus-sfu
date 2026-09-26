//! Kernel UDP floor (Phase 0.4, design §2): the per-datagram cost of the
//! system calls alone, with no SFU code.
//!
//! - `sendmmsg/<dests>`: one `sendmmsg` of 64 distinct 1,200-byte datagrams,
//!   spread round-robin over 1, 10 or 100 loopback destinations (as a
//!   fan-out to that many subscribers). Receivers are drained by background
//!   threads (`common::Sinks`, as in `real_path.rs`).
//! - `recvmmsg`: `recvmmsg` batches of 64 on one socket that sender threads
//!   keep full. Only calls that return datagrams are timed, so waiting for
//!   traffic is not counted.
//!
//! Throughput is per datagram. Loopback only: no NIC, no driver, no
//! GSO/GRO (every subscriber is a different destination anyway).
//!
//! Linux only (`sendmmsg`/`recvmmsg`). Run with: `cargo bench --bench udp_floor`

#[cfg(target_os = "linux")]
mod common;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("udp_floor: linux only (sendmmsg/recvmmsg); skipped");
}

#[cfg(target_os = "linux")]
fn main() {
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::bench_sendmmsg(&mut c);
    linux::bench_recvmmsg(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use criterion::{BenchmarkId, Criterion, Throughput};

    use super::common::{raise_fd_limit, Sinks};

    const BATCH: usize = 64;
    const DATAGRAM: usize = 1200;
    const DESTINATIONS: [usize; 3] = [1, 10, 100];
    const RECV_SENDERS: usize = 2;
    const SOCKET_BUF: libc::c_int = 4 << 20;

    fn sockaddr(addr: SocketAddr) -> libc::sockaddr_in {
        let SocketAddr::V4(v4) = addr else {
            panic!("IPv4 loopback expected");
        };
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            },
            sin_zero: [0; 8],
        }
    }

    fn set_buf(socket: &UdpSocket, option: libc::c_int) {
        let value = SOCKET_BUF;
        // SAFETY: setsockopt reads `value` for the given length only.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt");
    }

    /// 64 distinct datagram buffers and the `mmsghdr` array pointing at them.
    /// Boxed so the self-referential pointers stay valid.
    struct Batch {
        buffers: Box<[[u8; DATAGRAM]; BATCH]>,
        iovecs: Box<[libc::iovec; BATCH]>,
        headers: Box<[libc::mmsghdr; BATCH]>,
    }

    impl Batch {
        fn new() -> Self {
            let mut buffers = Box::new([[0u8; DATAGRAM]; BATCH]);
            for (i, buf) in buffers.iter_mut().enumerate() {
                buf.fill(i as u8);
            }
            // SAFETY: iovec and mmsghdr are plain C structs; all-zero is valid.
            let mut iovecs: Box<[libc::iovec; BATCH]> = Box::new(unsafe { std::mem::zeroed() });
            let mut headers: Box<[libc::mmsghdr; BATCH]> = Box::new(unsafe { std::mem::zeroed() });
            for i in 0..BATCH {
                iovecs[i].iov_base = buffers[i].as_mut_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = DATAGRAM;
                headers[i].msg_hdr.msg_iov = &mut iovecs[i];
                headers[i].msg_hdr.msg_iovlen = 1;
            }
            Self {
                buffers,
                iovecs,
                headers,
            }
        }

        fn len(&self) -> usize {
            assert_eq!(self.buffers.len(), self.iovecs.len());
            self.headers.len()
        }
    }

    // =========================================================================
    // sendmmsg
    // =========================================================================

    struct SendRig {
        socket: UdpSocket,
        dests: Vec<libc::sockaddr_in>,
        batch: Batch,
        next_dest: usize,
        sent: u64,
        short: u64,
    }

    impl SendRig {
        fn new(sinks: &Sinks) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            socket.set_nonblocking(true).expect("nonblocking");
            set_buf(&socket, libc::SO_SNDBUF);
            Self {
                socket,
                dests: sinks.addrs.iter().map(|a| sockaddr(*a)).collect(),
                batch: Batch::new(),
                next_dest: 0,
                sent: 0,
                short: 0,
            }
        }

        /// Timed: point the 64 messages at the next destinations, one call.
        fn send_batch(&mut self) {
            let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            for header in self.batch.headers.iter_mut() {
                let dest = &mut self.dests[self.next_dest];
                header.msg_hdr.msg_name = dest as *mut libc::sockaddr_in as *mut libc::c_void;
                header.msg_hdr.msg_namelen = addr_len;
                self.next_dest += 1;
                if self.next_dest == self.dests.len() {
                    self.next_dest = 0;
                }
            }
            let n = self.batch.len() as libc::c_uint;
            // SAFETY: headers point at live iovecs, buffers and addresses.
            let rc = unsafe {
                libc::sendmmsg(
                    self.socket.as_raw_fd(),
                    self.batch.headers.as_mut_ptr(),
                    n,
                    0,
                )
            };
            let sent = rc.max(0) as u64;
            self.sent += sent;
            if sent < n as u64 {
                self.short += 1;
            }
        }
    }

    pub fn bench_sendmmsg(c: &mut Criterion) {
        raise_fd_limit();
        let mut group = c.benchmark_group("sendmmsg");
        group.throughput(Throughput::Elements(BATCH as u64));
        for dests in DESTINATIONS {
            let sinks = Sinks::new(dests);
            let mut rig = SendRig::new(&sinks);
            group.bench_function(BenchmarkId::from_parameter(dests), |b| {
                b.iter(|| rig.send_batch())
            });
            // Let the drain threads catch up before counting.
            std::thread::sleep(Duration::from_millis(200));
            let received = sinks.received();
            eprintln!(
                "sendmmsg/{dests}: sent={} short_calls={} received={} ({:.1}% delivered)",
                rig.sent,
                rig.short,
                received,
                100.0 * received as f64 / rig.sent.max(1) as f64,
            );
        }
        group.finish();
    }

    // =========================================================================
    // recvmmsg
    // =========================================================================

    /// Threads that keep `target` full with `sendmmsg` batches.
    struct Flood {
        stop: Arc<AtomicBool>,
        threads: Vec<std::thread::JoinHandle<()>>,
    }

    impl Flood {
        fn new(target: SocketAddr) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let threads = (0..RECV_SENDERS)
                .map(|_| {
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || flood(target, stop))
                })
                .collect();
            Self { stop, threads }
        }
    }

    impl Drop for Flood {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    fn flood(target: SocketAddr, stop: Arc<AtomicBool>) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind flood");
        set_buf(&socket, libc::SO_SNDBUF);
        let mut dest = sockaddr(target);
        let mut batch = Batch::new();
        for header in batch.headers.iter_mut() {
            header.msg_hdr.msg_name = &mut dest as *mut libc::sockaddr_in as *mut libc::c_void;
            header.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        }
        while !stop.load(Ordering::Relaxed) {
            // SAFETY: headers point at live iovecs, buffers and `dest`.
            unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    batch.headers.as_mut_ptr(),
                    BATCH as libc::c_uint,
                    0,
                );
            }
        }
    }

    struct RecvRig {
        socket: UdpSocket,
        batch: Batch,
        calls: u64,
        datagrams: u64,
    }

    impl RecvRig {
        /// Receive at least `count` datagrams; return the time spent in
        /// calls that returned data, scaled to exactly `count`.
        fn receive(&mut self, count: u64) -> Duration {
            let fd = self.socket.as_raw_fd();
            let mut got = 0u64;
            let mut busy = Duration::ZERO;
            // Bounded by the wall clock: a stalled flood must not hang the bench.
            let deadline = Instant::now() + Duration::from_secs(60);
            while got < count {
                assert!(Instant::now() < deadline, "recvmmsg: flood stalled");
                let start = Instant::now();
                // SAFETY: headers point at live iovecs and buffers.
                let rc = unsafe {
                    libc::recvmmsg(
                        fd,
                        self.batch.headers.as_mut_ptr(),
                        BATCH as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                };
                if rc > 0 {
                    busy += start.elapsed();
                    got += rc as u64;
                    self.calls += 1;
                    self.datagrams += rc as u64;
                }
            }
            busy.mul_f64(count as f64 / got as f64)
        }
    }

    pub fn bench_recvmmsg(c: &mut Criterion) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        set_buf(&socket, libc::SO_RCVBUF);
        let mut rig = RecvRig {
            socket,
            batch: Batch::new(),
            calls: 0,
            datagrams: 0,
        };
        let _flood = Flood::new(rig.socket.local_addr().unwrap());
        let mut group = c.benchmark_group("recvmmsg");
        group.throughput(Throughput::Elements(1));
        group.bench_function("batch64", |b| b.iter_custom(|n| rig.receive(n)));
        group.finish();
        eprintln!(
            "recvmmsg: {} datagrams in {} productive calls ({:.1} per call, batch {BATCH})",
            rig.datagrams,
            rig.calls,
            rig.datagrams as f64 / rig.calls.max(1) as f64,
        );
    }
}
