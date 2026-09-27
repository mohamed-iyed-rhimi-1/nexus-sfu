//! Checks every socket backend must pass, on real loopback sockets.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::{Datagram, DatagramIo, RecvBatch, SendBatch, Sent};
use crate::ids::ShardId;
use crate::pool::{BufferPool, BUF_SIZE};

const POOL: u32 = 512;

/// Runs every check with backends built by `make` from a bound socket.
pub(crate) fn run_all<I: DatagramIo>(make: impl Fn(UdpSocket) -> I) {
    receives_with_source_and_drops_truncated(&make, "127.0.0.1:0");
    if UdpSocket::bind("[::1]:0").is_ok() {
        receives_with_source_and_drops_truncated(&make, "[::1]:0");
        dual_stack_reports_and_reaches_v4_peers(&make);
    }
    sends_a_full_batch_and_returns_buffers(&make);
    a_bad_destination_drops_only_itself(&make);
}

fn pool() -> BufferPool {
    BufferPool::new(ShardId::new(0), POOL)
}

/// Receives until `want` datagrams arrived (or 2 s passed); returns them
/// and the truncated count. Leaves the pool as it found it.
fn receive<I: DatagramIo>(
    io: &mut I,
    pool: &mut BufferPool,
    want: usize,
) -> (Vec<(SocketAddr, Vec<u8>)>, usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut rx = RecvBatch::new();
    let (mut got, mut truncated) = (Vec::new(), 0);
    while got.len() < want && Instant::now() < deadline {
        let result = io.recv_batch(&mut rx, pool).expect("receive");
        assert_eq!(result.received, rx.len());
        truncated += result.truncated;
        for d in rx.iter() {
            got.push((d.addr, pool.buf(d.buf)[..d.len].to_vec()));
            pool.put(d.buf);
        }
        rx.clear();
        if result.would_block {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(pool.available(), POOL as usize);
    (got, truncated)
}

fn queue(tx: &mut SendBatch, pool: &mut BufferPool, addr: SocketAddr, bytes: &[u8]) {
    let buf = pool.take().expect("buffer");
    pool.buf_mut(buf)[..bytes.len()].copy_from_slice(bytes);
    tx.push(Datagram {
        buf,
        len: bytes.len(),
        addr,
    });
}

fn receives_with_source_and_drops_truncated<I: DatagramIo>(
    make: &impl Fn(UdpSocket) -> I,
    bind: &str,
) {
    let socket = UdpSocket::bind(bind).expect("bind");
    let local = socket.local_addr().unwrap();
    let mut io = make(socket);
    let peer = UdpSocket::bind(bind).expect("bind peer");
    let mut pool = pool();
    peer.send_to(&[7; 1_600], local).unwrap();
    peer.send_to(&[8; 3_000], local).unwrap();
    peer.send_to(&[9; BUF_SIZE], local).unwrap();
    let (got, truncated) = receive(&mut io, &mut pool, 2);
    assert_eq!(truncated, 1, "{bind}: 3,000 bytes do not fit a buffer");
    let lens: Vec<usize> = got.iter().map(|(_, b)| b.len()).collect();
    assert_eq!(lens, [1_600, BUF_SIZE], "{bind}");
    assert!(got.iter().all(|(a, _)| *a == peer.local_addr().unwrap()));
    assert!(got[0].1.iter().all(|&b| b == 7));
}

fn dual_stack_reports_and_reaches_v4_peers<I: DatagramIo>(make: &impl Fn(UdpSocket) -> I) {
    let Ok(socket) = UdpSocket::bind("[::]:0") else {
        return;
    };
    let port = socket.local_addr().unwrap().port();
    let mut io = make(socket);
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut pool = pool();
    peer.send_to(b"ping", ("127.0.0.1", port)).unwrap();
    let (got, _) = receive(&mut io, &mut pool, 1);
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].0,
        peer.local_addr().unwrap(),
        "IPv4 peer reported as V4"
    );

    let mut tx = SendBatch::new();
    queue(&mut tx, &mut pool, got[0].0, b"pong");
    let sent = io.flush(&mut tx, &mut pool);
    assert_eq!(
        sent,
        Sent {
            datagrams: 1,
            bytes: 4
        }
    );
    let mut buf = [0; 16];
    let (len, _) = peer.recv_from(&mut buf).expect("reply reaches the V4 peer");
    assert_eq!(&buf[..len], b"pong");
}

fn sends_a_full_batch_and_returns_buffers<I: DatagramIo>(make: &impl Fn(UdpSocket) -> I) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut io = make(socket);
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let to = peer.local_addr().unwrap();
    let mut pool = pool();
    let mut tx = SendBatch::new();
    for i in 0..SendBatch::CAPACITY {
        queue(&mut tx, &mut pool, to, &[i as u8; 100]);
    }
    let sent = io.flush(&mut tx, &mut pool);
    let expected = Sent {
        datagrams: SendBatch::CAPACITY,
        bytes: SendBatch::CAPACITY * 100,
    };
    assert_eq!(sent, expected);
    assert!(tx.is_empty());
    assert_eq!(pool.available(), POOL as usize);
    let mut buf = [0; 200];
    let (len, _) = peer.recv_from(&mut buf).expect("first datagram arrives");
    assert_eq!(len, 100);
}

fn a_bad_destination_drops_only_itself<I: DatagramIo>(make: &impl Fn(UdpSocket) -> I) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut io = make(socket);
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let to = peer.local_addr().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:9".parse().unwrap();
    let mut pool = pool();
    let mut tx = SendBatch::new();
    for (i, addr) in [to, v6, to, to].into_iter().enumerate() {
        queue(&mut tx, &mut pool, addr, &[i as u8; 10]);
    }
    // Bytes count only what was sent, not the dropped datagram.
    let sent = io.flush(&mut tx, &mut pool);
    let expected = Sent {
        datagrams: 3,
        bytes: 30,
    };
    assert_eq!(sent, expected, "an IPv6 destination on IPv4");
    assert_eq!(pool.available(), POOL as usize);
    let mut seen = Vec::new();
    let mut buf = [0; 16];
    for _ in 0..3 {
        let (len, _) = peer.recv_from(&mut buf).expect("the others arrive");
        seen.push(buf[..len][0]);
    }
    assert_eq!(seen, [0, 2, 3]);
}
