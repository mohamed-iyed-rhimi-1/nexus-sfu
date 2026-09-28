//! Real media path benchmarks, through `nexus-dataplane` (Phase 1).
//!
//! A shard runs on the bench thread (no shard thread, so a result is the
//! work, not a wake-up) on a real loopback socket (`LinuxIo` on Linux,
//! `PortableIo` elsewhere; compare numbers within one platform only):
//!
//! - `ingress`: one publisher packet from the socket buffer to decrypted,
//!   parsed and routed (`recv` + SRTP unprotect + parse + track lookup), on a
//!   track with no subscribers. One datagram per timed `iterate`.
//! - `egress`: one publisher packet in, N rewritten, SRTP-protected packets
//!   out through `sendmmsg`/`send_to` to loopback sinks. The input is handed
//!   to the shard from memory (no receive syscall), but it is still
//!   decrypted: at N = 1 the result includes that, from N = 10 it is noise.
//!   Throughput is per packet leaving the SFU (elements = subscribers).
//! - `srtp`: protect / unprotect alone with the shard's SRTP types.
//!
//! Before each `ingress` and `egress` id, an untimed pass prints the heap
//! allocations per packet inside `Shard::iterate` (expected 0; the check that
//! enforces it is `crates/nexus-dataplane/tests/alloc.rs`).
//!
//! Not comparable with the pre-Phase 1 numbers in architecture.md Part 5:
//! the old ingress started from a byte slice (no `recv`), the old egress from
//! a plaintext packet (no decrypt).
//!
//! Run with: `cargo bench --bench real_path` (`-- --test` runs each once).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use nexus_core::MediaKind;
use nexus_dataplane::{
    bind_shard_socket, BufferPool, Command, Datagram, DatagramIo, DataplaneConfig, Event, ExtIds,
    PlatformIo, RecvBatch, RecvResult, SendBatch, Sent, Shard, ShardConfig, ShardCounters,
    SubscriptionId, TrackId, BUF_SIZE,
};
use nexus_transport::srtp::{ProtectionProfile, SrtpInbound, SrtpOutbound};

mod common;
#[path = "../crates/nexus-dataplane/tests/support/mod.rs"]
mod support;

use common::{raise_fd_limit, Sinks};
use support::{key, rtp_with_ext, sub_spec, track_spec, Peer};

const PUBLISHER_SSRC: u32 = 0x1234_5678;
/// Publisher's extension ids: mid (SSRC learning, stripped) and audio level.
const MID_EXT: u8 = 1;
const AUDIO_LEVEL_EXT: u8 = 2;
/// Opus 20 ms at ~40 kbps.
const AUDIO_PAYLOAD: usize = 100;
/// Typical full video packet; header + extensions + tag stay under 1200.
const VIDEO_PAYLOAD: usize = 1100;
const SUBSCRIBER_COUNTS: [usize; 4] = [1, 10, 100, 500];
/// Packets in the untimed allocation pass before each id.
const ALLOC_PASS_PACKETS: u64 = 200;
/// Longest wait for the sinks to read what was sent, after an egress id.
const DRAIN_WAIT: Duration = Duration::from_millis(500);

// =============================================================================
// Allocation counting (per thread, only while the gate is set)
// =============================================================================

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn note_allocation() {
    // try_with: the allocator can run while thread-locals are torn down.
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: forwards every call to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_allocation();
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Runs `f` with allocation counting on for this thread; returns the count.
fn counted(f: impl FnOnce()) -> u64 {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.with(|c| c.set(true));
    f();
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

fn print_allocations(id: &str, allocations: u64, packets: u64) {
    assert!(packets > 0);
    let marker = if allocations == 0 { "" } else { "!! " };
    eprintln!(
        "{marker}{id}: {:.3} allocations per packet ({allocations} in {packets})",
        allocations as f64 / packets as f64
    );
}

// =============================================================================
// Shared helpers
// =============================================================================

#[derive(Clone, Copy)]
struct Media {
    name: &'static str,
    kind: MediaKind,
    clock_rate: u32,
    payload: usize,
}

const MEDIA: [Media; 2] = [
    Media {
        name: "audio",
        kind: MediaKind::Audio,
        clock_rate: 48_000,
        payload: AUDIO_PAYLOAD,
    },
    Media {
        name: "video",
        kind: MediaKind::Video,
        clock_rate: 90_000,
        payload: VIDEO_PAYLOAD,
    },
];

const PROFILES: [(&str, ProtectionProfile); 2] = [
    ("gcm", ProtectionProfile::AeadAes128Gcm),
    ("cm_sha1_80", ProtectionProfile::Aes128CmHmacSha1_80),
];

/// The shard's socket I/O, plus datagrams handed in from memory first
/// (setup STUN from sink addresses, and the egress input).
struct BenchIo {
    inner: PlatformIo,
    injected: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl BenchIo {
    fn inject(&mut self, from: SocketAddr, bytes: Vec<u8>) {
        assert!(bytes.len() <= BUF_SIZE, "injected datagram too large");
        self.injected.push_back((from, bytes));
    }
}

impl DatagramIo for BenchIo {
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult> {
        let mut received = 0;
        // Bounded by the batch's capacity.
        while !rx.is_full() {
            let Some((addr, bytes)) = self.injected.front() else {
                break;
            };
            let Some(buf) = pool.take() else { break };
            let len = bytes.len();
            pool.buf_mut(buf)[..len].copy_from_slice(bytes);
            rx.push(Datagram {
                buf,
                len,
                addr: *addr,
            });
            self.injected.pop_front();
            received += 1;
        }
        let mut result = self.inner.recv_batch(rx, pool)?;
        result.received += received;
        Ok(result)
    }

    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent {
        self.inner.flush(tx, pool)
    }
}

type BenchShard = Shard<BenchIo, Vec<Event>>;

/// A shard on a fresh loopback socket; returns it, its address, and a clone
/// of its socket (the same socket: `peek_from` on it sees what the shard
/// will receive, without taking it).
fn loopback_shard(now: Instant) -> (BenchShard, SocketAddr, UdpSocket) {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("address");
    let socket = bind_shard_socket(bind, &DataplaneConfig::default()).expect("bind shard socket");
    let addr = socket.local_addr().expect("local address");
    let probe = socket.try_clone().expect("clone shard socket");
    let io = BenchIo {
        inner: PlatformIo::new(socket).expect("shard I/O"),
        injected: VecDeque::with_capacity(1_024),
    };
    let config = ShardConfig {
        // Fan-out holds at most a send batch plus a receive batch.
        pool_buffers: 1_024,
        max_sessions: 1_000,
        ..Default::default()
    };
    let shard = Shard::new(config, io, Vec::with_capacity(4_096), now).expect("shard");
    (shard, addr, probe)
}

/// Iterates until commands and injected datagrams are handled.
fn settle(shard: &mut BenchShard, now: Instant) {
    for _ in 0..1_000 {
        let stats = shard.iterate(now);
        if stats.commands == 0 && stats.received == 0 && shard.io().injected.is_empty() {
            shard.events_mut().clear();
            return;
        }
    }
    panic!("shard did not settle");
}

/// Creates the peer's session, nominates its address and installs SRTP.
fn connect(shard: &mut BenchShard, peer: &Peer, now: Instant) {
    assert!(shard.push_command(peer.create()).is_ok());
    settle(shard, now);
    let stun = peer.binding_request(true);
    shard.io_mut().inject(peer.addr, stun);
    assert!(shard.push_command(peer.install()).is_ok());
    settle(shard, now);
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
}

/// Adds the publisher's track for `media` (mid and audio level extensions).
fn add_track(shard: &mut BenchShard, publisher: &Peer, media: Media, now: Instant) -> TrackId {
    let track = TrackId::new(1);
    let mut spec = track_spec(Some(PUBLISHER_SSRC), b"0");
    spec.kind = media.kind;
    spec.codec.clock_rate = media.clock_rate;
    spec.ext = ExtIds {
        mid: MID_EXT,
        audio_level: AUDIO_LEVEL_EXT,
        video_orientation: 0,
    };
    let command = Command::AddTrack {
        id: publisher.id,
        track,
        spec,
    };
    assert!(shard.push_command(command).is_ok());
    settle(shard, now);
    track
}

/// The publisher's browser: builds and encrypts its next packet (untimed).
struct Publisher {
    peer: Peer,
    seq: u32,
    media: Media,
    payload: Vec<u8>,
}

impl Publisher {
    fn new(peer: Peer, media: Media) -> Self {
        let payload = (0..media.payload).map(|i| i as u8).collect();
        Self {
            peer,
            seq: 0,
            media,
            payload,
        }
    }

    fn next_ciphertext(&mut self) -> Vec<u8> {
        self.seq += 1;
        let seq = self.seq as u16;
        let ts = self.seq.wrapping_mul(self.media.clock_rate / 50);
        let elements: [(u8, &[u8]); 2] = [(MID_EXT, b"0"), (AUDIO_LEVEL_EXT, &[0x85])];
        let plain = rtp_with_ext(PUBLISHER_SSRC, seq, ts, &elements, &self.payload);
        self.peer.protect_rtp(&plain)
    }
}

/// Prints the counters that show a fast result caused by drops.
fn report(id: &str, c: &ShardCounters) {
    eprintln!(
        "{id}: rx={} tx={} send_failed={} srtp_auth={} srtp_protect={} pool_empty={} \
         full_flushes={} rejected={}",
        c.rx_datagrams,
        c.tx_datagrams,
        c.drop_send_failed,
        c.drop_srtp_auth,
        c.drop_srtp_protect,
        c.drop_pool_empty,
        c.tx_full_flushes,
        c.commands_rejected,
    );
    let dropped = c.drop_send_failed + c.drop_srtp_auth + c.drop_srtp_protect + c.drop_pool_empty;
    if dropped > 0 || c.commands_rejected > 0 {
        eprintln!("!! {id}: packets dropped or commands rejected, result not valid");
    }
}

// =============================================================================
// Ingress
// =============================================================================

/// The publisher's side: a real socket sending to the shard.
struct IngressSource {
    shard_addr: SocketAddr,
    client: UdpSocket,
    /// The shard's socket (a clone), to see when a datagram has arrived.
    probe: UdpSocket,
    publisher: Publisher,
}

/// The shard's side.
struct IngressShard {
    shard: BenchShard,
    now: Instant,
    /// Timed iterations that did not receive exactly one datagram.
    irregular: u64,
}

/// How long `send_one` waits for loopback delivery.
const DELIVERY_TIMEOUT: Duration = Duration::from_millis(100);

impl IngressSource {
    /// Untimed: the next packet into the shard's socket buffer. Loopback
    /// delivery can lag `send_to` (macOS: most of the time), so this waits
    /// until the shard's socket has a datagram queued.
    fn send_one(&mut self) {
        let packet = self.publisher.next_ciphertext();
        let sent = self.client.send_to(&packet, self.shard_addr).expect("send");
        assert_eq!(sent, packet.len());
        let start = Instant::now();
        let mut byte = [0u8; 1];
        // Bounded by DELIVERY_TIMEOUT.
        loop {
            match self.probe.peek_from(&mut byte) {
                Ok(_) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("peek on the shard socket: {e}"),
            }
            assert!(
                start.elapsed() < DELIVERY_TIMEOUT,
                "datagram not delivered within {DELIVERY_TIMEOUT:?}"
            );
            std::hint::spin_loop();
        }
    }
}

impl IngressShard {
    /// Timed: receive, decrypt, parse, route.
    fn receive_one(&mut self) {
        let stats = self.shard.iterate(self.now);
        if stats.received != 1 {
            self.irregular += 1;
        }
        black_box(stats);
    }
}

fn ingress_rig(profile: ProtectionProfile, media: Media) -> (IngressSource, IngressShard) {
    let now = Instant::now();
    let (mut shard, shard_addr, probe) = loopback_shard(now);
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let addr = client.local_addr().expect("client address");
    let peer = Peer::new(1, &addr.to_string(), profile);
    connect(&mut shard, &peer, now);
    add_track(&mut shard, &peer, media, now);
    let source = IngressSource {
        shard_addr,
        client,
        probe,
        publisher: Publisher::new(peer, media),
    };
    let shard = IngressShard {
        shard,
        now,
        irregular: 0,
    };
    (source, shard)
}

fn bench_ingress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingress");
    group.throughput(Throughput::Elements(1));
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            let (mut source, mut rig) = ingress_rig(profile, media);
            let id = format!("{profile_name}/{}", media.name);
            let mut allocations = 0;
            for _ in 0..ALLOC_PASS_PACKETS {
                source.send_one();
                allocations += counted(|| rig.receive_one());
            }
            print_allocations(&format!("ingress/{id}"), allocations, ALLOC_PASS_PACKETS);
            // `PerIteration`: one setup, then one timed call, so each timed
            // `iterate` receives exactly one datagram (with larger batches
            // several setups run first and one `iterate` drains them all).
            group.bench_function(id.as_str(), |b| {
                b.iter_batched(
                    || source.send_one(),
                    |()| rig.receive_one(),
                    BatchSize::PerIteration,
                )
            });
            report(&format!("ingress/{id}"), rig.shard.counters());
            let marker = if rig.irregular == 0 { "" } else { "!! " };
            eprintln!(
                "{marker}ingress/{id}: {} iterations (allocation pass and timed) did not \
                 receive exactly one datagram",
                rig.irregular
            );
        }
    }
    group.finish();
}

// =============================================================================
// Egress
// =============================================================================

struct EgressRig {
    shard: BenchShard,
    /// The publisher's (sink 0) address.
    from: SocketAddr,
    now: Instant,
    sinks: Sinks,
}

impl EgressRig {
    fn new(profile: ProtectionProfile, media: Media, subscribers: usize) -> (Self, Publisher) {
        let now = Instant::now();
        let (mut shard, _, _) = loopback_shard(now);
        // Sink 0 stands in for the publisher (it gets STUN answers and PLIs).
        let sinks = Sinks::new(subscribers + 1);
        let peer = Peer::new(1, &sinks.addrs[0].to_string(), profile);
        connect(&mut shard, &peer, now);
        let track = add_track(&mut shard, &peer, media, now);
        for (i, addr) in sinks.addrs[1..].iter().enumerate() {
            let n = i as u64 + 2;
            let mut subscriber = Peer::new(n, &addr.to_string(), profile);
            connect(&mut shard, &subscriber, now);
            // Audio level mapped to 5, the subscriber's mid written as 1:
            // every packet goes through the extension rewrite.
            let mut spec = sub_spec(subscriber.next_out_ssrc(), track);
            spec.ext_map.map[usize::from(AUDIO_LEVEL_EXT)] = 5;
            spec.ext_map.mid = 1;
            let command = Command::Subscribe {
                id: subscriber.id,
                sub: SubscriptionId::new(n),
                track,
                spec,
            };
            assert!(shard.push_command(command).is_ok());
            settle(&mut shard, now);
        }
        assert_eq!(shard.counters().commands_rejected, 0);
        let rig = Self {
            shard,
            from: peer.addr,
            now,
            sinks,
        };
        (rig, Publisher::new(peer, media))
    }

    /// Prints how many of the datagrams the shard sent the sinks read, after
    /// they stop arriving (at most `DRAIN_WAIT`). A send the kernel accepted
    /// can still be dropped at a full sink.
    fn report_delivery(&self, id: &str) {
        let sent = self.shard.counters().tx_datagrams;
        let start = Instant::now();
        let mut received = self.sinks.received();
        // Bounded by DRAIN_WAIT.
        while received < sent && start.elapsed() < DRAIN_WAIT {
            std::thread::sleep(Duration::from_millis(10));
            let now = self.sinks.received();
            if now == received {
                break;
            }
            received = now;
        }
        let share = received as f64 / sent.max(1) as f64;
        let marker = if share < 0.99 { "!! " } else { "" };
        eprintln!(
            "{marker}egress/{id}: sinks read {received} of {sent} datagrams sent ({:.1}%)",
            100.0 * share
        );
    }

    /// Timed: one publisher packet in, one per subscriber out.
    fn forward_one(&mut self, packet: Vec<u8>) {
        self.shard.io_mut().inject(self.from, packet);
        black_box(self.shard.iterate(self.now));
    }
}

fn bench_egress(c: &mut Criterion) {
    raise_fd_limit();
    let mut group = c.benchmark_group("egress");
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            for subscribers in SUBSCRIBER_COUNTS {
                let (mut rig, mut publisher) = EgressRig::new(profile, media, subscribers);
                let name = format!("{profile_name}/{}/{subscribers}", media.name);
                let mut allocations = 0;
                for _ in 0..ALLOC_PASS_PACKETS {
                    let packet = publisher.next_ciphertext();
                    let from = rig.from;
                    rig.shard.io_mut().inject(from, packet);
                    let now = rig.now;
                    allocations += counted(|| {
                        rig.shard.iterate(now);
                    });
                }
                print_allocations(&format!("egress/{name}"), allocations, ALLOC_PASS_PACKETS);
                group.throughput(Throughput::Elements(subscribers as u64));
                let id = BenchmarkId::new(format!("{profile_name}/{}", media.name), subscribers);
                group.bench_function(id, |b| {
                    b.iter_batched(
                        || publisher.next_ciphertext(),
                        |packet| rig.forward_one(packet),
                        BatchSize::PerIteration,
                    )
                });
                report(&format!("egress/{name}"), rig.shard.counters());
                rig.report_delivery(&name);
            }
        }
    }
    group.finish();
}

// =============================================================================
// SRTP alone
// =============================================================================

/// A browser-like RTP packet (mid and audio level extensions) in `buf`.
fn write_rtp(buf: &mut [u8], ssrc: u32, seq: u16, payload: usize) -> usize {
    assert!(buf.len() >= 20 + payload, "buffer too small for packet");
    buf[0] = 0x90; // V=2, X=1
    buf[1] = 111;
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    buf[4..8].copy_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
    buf[12..14].copy_from_slice(&[0xBE, 0xDE]);
    buf[14..16].copy_from_slice(&1u16.to_be_bytes()); // 1 word of extensions
    buf[16..20].copy_from_slice(&[MID_EXT << 4, b'0', AUDIO_LEVEL_EXT << 4, 0x85]);
    for (i, b) in buf[20..20 + payload].iter_mut().enumerate() {
        *b = i as u8;
    }
    20 + payload
}

/// A sender with one registered SSRC; returns it and the SSRC.
fn outbound(profile: ProtectionProfile) -> (SrtpOutbound, u32) {
    let base = 0x5000_0000;
    let mut srtp = SrtpOutbound::new(&key(profile, 7), base).expect("outbound SRTP");
    srtp.register(base + 1).expect("register SSRC");
    (srtp, base + 1)
}

fn bench_srtp(c: &mut Criterion) {
    let mut group = c.benchmark_group("srtp");
    group.throughput(Throughput::Elements(1));
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            let (mut sender, ssrc) = outbound(profile);
            let mut seq = 0u16;
            let id = format!("protect/{profile_name}/{}", media.name);
            group.bench_function(id, |b| {
                let mut buf = [0u8; 1500];
                b.iter(|| {
                    seq = seq.wrapping_add(1);
                    let len = write_rtp(&mut buf, ssrc, seq, media.payload);
                    black_box(sender.protect_rtp(&mut buf, len).expect("protect"))
                })
            });
            // Fresh sender and receiver: indices only move forward.
            let (mut sender, ssrc) = outbound(profile);
            let mut receiver = SrtpInbound::new(&key(profile, 7)).expect("inbound SRTP");
            let mut seq = 0u16;
            let id = format!("unprotect/{profile_name}/{}", media.name);
            group.bench_function(id, |b| {
                b.iter_batched_ref(
                    || {
                        let mut buf = [0u8; 1500];
                        seq = seq.wrapping_add(1);
                        let len = write_rtp(&mut buf, ssrc, seq, media.payload);
                        let len = sender.protect_rtp(&mut buf, len).expect("protect");
                        (buf, len)
                    },
                    |(buf, len)| {
                        black_box(receiver.unprotect_rtp(buf, *len, 0).expect("unprotect"))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_srtp, bench_ingress, bench_egress);
criterion_main!(benches);
