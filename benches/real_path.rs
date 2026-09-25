//! Real media path benchmarks.
//!
//! Unlike `forwarding.rs`, these drive the code that runs in production,
//! including SRTP:
//!
//! - `ingress`: one published packet from SRTP ciphertext to the worker
//!   queue. Mirrors `Sfu::process_packet` → `process_decrypted_rtp` →
//!   `send_publisher_srtcp_if_needed` (src/sfu.rs). Those are private
//!   methods on a fully started `Sfu`, so this bench replays the same calls
//!   through the public APIs. Keep it in sync when that path changes.
//! - `egress`: one plaintext packet through a real `MediaWorker`
//!   (`process_one_iteration`), fanned out to N subscribers with per-
//!   subscriber SRTP and real `sendmmsg`/`sendto` to loopback sockets.
//! - `srtp`: protect / unprotect alone, to show the crypto share.
//!
//! Not covered: kernel receive (`recvmmsg`) and NIC transmit. Loopback
//! sends are cheaper than a real NIC path. Profile the running binary with
//! `perf` on Linux for those.
//!
//! Throughput is reported per packet *leaving* the SFU for `egress`
//! (elements = subscribers) and per packet *entering* for `ingress`.
//!
//! Run with: `cargo bench --bench real_path`

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use criterion::Throughput;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crossbeam::channel::{Receiver, Sender};
use dashmap::DashMap;

use nexus_media::rtp::RtpHeader;
use nexus_sfu::forward::SsrcRouter;
use nexus_sfu::types::MediaKind;
use nexus_sfu::worker::{MediaWorker, WorkerMessage};
use nexus_transport::arena::PacketArena;
use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};
use nexus_webrtc::webrtc::WebRtcTransport;
use nexus_webrtc::webrtc::{DtlsParameters, DtlsRole, IncomingData, TransportConfig};

const PUBLISHER_SSRC: u32 = 0x1234_5678;
const TRACK_ID: u64 = 1;
const TWCC_EXT_ID: u8 = 3;
const MID_EXT_ID: u8 = 4;
/// Opus 20 ms at ~40 kbps.
const AUDIO_PAYLOAD: usize = 100;
/// Typical full video packet; header + extensions + tag stay under 1200.
const VIDEO_PAYLOAD: usize = 1100;
const SUBSCRIBER_COUNTS: [usize; 4] = [1, 10, 100, 500];

// =============================================================================
// Shared helpers
// =============================================================================

#[derive(Clone, Copy)]
struct Media {
    name: &'static str,
    kind: MediaKind,
    payload: usize,
}

const MEDIA: [Media; 2] = [
    Media {
        name: "audio",
        kind: MediaKind::Audio,
        payload: AUDIO_PAYLOAD,
    },
    Media {
        name: "video",
        kind: MediaKind::Video,
        payload: VIDEO_PAYLOAD,
    },
];

const PROFILES: [(&str, ProtectionProfile); 2] = [
    ("gcm", ProtectionProfile::AeadAes128Gcm),
    ("cm_sha1_80", ProtectionProfile::Aes128CmHmacSha1_80),
];

/// Deterministic key material for `profile`, distinct per `seed`.
fn key_material(profile: ProtectionProfile, seed: u8) -> KeyMaterial {
    let len = profile.key_len() + profile.salt_len();
    let material: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8) | 1).collect();
    KeyMaterial::from_dtls_export(&material, profile).expect("valid key material")
}

fn srtp_context(material: &KeyMaterial) -> SrtpContext {
    let policy = SrtpPolicy {
        profile: material.profile,
        ..SrtpPolicy::default()
    };
    SrtpContext::new(material, policy).expect("valid SRTP context")
}

/// Write a browser-like RTP packet (one-byte extension block carrying a
/// transport-wide sequence number) into `buf`. Returns its length.
fn write_rtp(buf: &mut [u8], seq: u16, ts: u32, payload: usize) -> usize {
    assert!(buf.len() >= 20 + payload, "buffer too small for packet");
    buf[0] = 0x90; // V=2, X=1
    buf[1] = 0x60; // PT=96
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    buf[4..8].copy_from_slice(&ts.to_be_bytes());
    buf[8..12].copy_from_slice(&PUBLISHER_SSRC.to_be_bytes());
    buf[12..14].copy_from_slice(&[0xBE, 0xDE]);
    buf[14..16].copy_from_slice(&1u16.to_be_bytes()); // 1 word of extensions
    buf[16] = (TWCC_EXT_ID << 4) | 1; // id, len-1
    buf[17..19].copy_from_slice(&seq.to_be_bytes());
    buf[19] = 0; // padding
    for (i, b) in buf[20..20 + payload].iter_mut().enumerate() {
        *b = i as u8;
    }
    20 + payload
}

/// Raise the open-file limit so hundreds of sink sockets can be bound.
fn raise_fd_limit() {
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

const DRAIN_THREADS: usize = 4;

/// Loopback sockets standing in for subscribers, drained by background
/// threads. Undrained sockets fill up and make sends fail (ENOBUFS on
/// macOS), and failed sends are much cheaper than real ones.
struct Sinks {
    addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Sinks {
    fn new(count: usize) -> Self {
        assert!(count > 0, "need at least one sink");
        let sockets: Vec<UdpSocket> = (0..count)
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("bind sink socket"))
            .collect();
        let addrs = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
        let stop = Arc::new(AtomicBool::new(false));
        let per_thread = count.div_ceil(DRAIN_THREADS);
        let mut threads = Vec::with_capacity(DRAIN_THREADS);
        let mut sockets = sockets.into_iter();
        for _ in 0..DRAIN_THREADS {
            let chunk: Vec<UdpSocket> = sockets.by_ref().take(per_thread).collect();
            if chunk.is_empty() {
                break;
            }
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || drain(chunk, stop)));
        }
        Self {
            addrs,
            stop,
            threads,
        }
    }
}

fn drain(sockets: Vec<UdpSocket>, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 1500];
    for socket in &sockets {
        socket.set_nonblocking(true).expect("nonblocking sink");
    }
    while !stop.load(Ordering::Relaxed) {
        for socket in &sockets {
            // Bounded: at most 64 datagrams per socket per pass.
            for _ in 0..64 {
                if socket.recv(&mut buf).is_err() {
                    break;
                }
            }
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

// =============================================================================
// Ingress
// =============================================================================

struct IngressRig {
    transport: WebRtcTransport,
    router: SsrcRouter,
    arena: PacketArena,
    source: SocketAddr,
    /// Local send keys, as `get_srtp_key_material` re-exports them.
    export: (Vec<u8>, ProtectionProfile),
    srtcp_cache: DashMap<u64, (u64, [u8; 32])>,
    pool_lock: parking_lot::RwLock<()>,
    queue_tx: Sender<WorkerMessage>,
    queue_rx: Receiver<WorkerMessage>,
}

/// The publisher's browser: encrypts with the session's inbound keys.
struct Publisher {
    srtp: SrtpContext,
    seq: u16,
    payload: usize,
}

impl Publisher {
    /// Untimed: build the next packet as the publisher would send it.
    fn next_ciphertext(&mut self) -> ([u8; 1500], usize) {
        let mut buf = [0u8; 1500];
        self.seq = self.seq.wrapping_add(1);
        let len = write_rtp(&mut buf, self.seq, self.seq as u32 * 960, self.payload);
        let len = self.srtp.protect_rtp(&mut buf, len).expect("protect");
        (buf, len)
    }
}

impl IngressRig {
    fn new(profile: ProtectionProfile, payload: usize) -> (Self, Publisher) {
        let transport = WebRtcTransport::new(TransportConfig::default()).expect("transport");
        transport.start().expect("start transport");
        let session = transport
            .create_session(DtlsParameters::new(DtlsRole::Server))
            .expect("create session");
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        transport.associate_address(source, session);

        let inbound = key_material(profile, 0x10);
        let outbound = key_material(profile, 0x40);
        transport
            .with_session_mut(session, |s| s.install_srtp_for_testing(&inbound, &outbound))
            .expect("session exists");

        let router = SsrcRouter::new();
        router
            .register(PUBLISHER_SSRC, TRACK_ID, 0)
            .expect("register SSRC");
        let export_len = profile.key_len() + profile.salt_len();
        let export = (vec![0x40; export_len], profile);
        let (queue_tx, queue_rx) = crossbeam::channel::bounded(4096);

        let rig = Self {
            transport,
            router,
            arena: PacketArena::new(16).expect("arena"),
            source,
            export,
            srtcp_cache: DashMap::with_capacity(256),
            pool_lock: parking_lot::RwLock::new(()),
            queue_tx,
            queue_rx,
        };
        let publisher = Publisher {
            srtp: srtp_context(&inbound),
            seq: 0,
            payload,
        };
        (rig, publisher)
    }

    /// Timed: the ingress path for one packet.
    fn process(&self, data: &[u8]) {
        let mut out = [0u8; 2048];
        let result = self.transport.process_packet(data, self.source, &mut out);
        let len = match result {
            Ok(Some((_, IncomingData::Rtp(len)))) => len,
            other => panic!(
                "expected decrypted RTP, got {:?}",
                other.map(|o| o.is_some())
            ),
        };
        let plain = &out[..len];
        let header = RtpHeader::parse_simd(plain).expect("valid RTP");
        let (track_id, _) = self.router.lookup(header.ssrc).expect("routed SSRC");
        self.srtcp_check(track_id);

        let mut slot = self.arena.alloc().expect("arena slot");
        slot.data_mut()[..len].copy_from_slice(plain);
        slot.set_len(len as u16);

        let _pool = self.pool_lock.read();
        let msg = WorkerMessage::Packet {
            track_id,
            packet: slot,
            source_addr: self.source,
        };
        self.queue_tx.try_send(msg).expect("queue has room");
        black_box(self.queue_rx.try_recv().ok());
    }

    /// Mirrors `Sfu::send_publisher_srtcp_if_needed` on its common path
    /// (cache hit): session lookup, session lock, key re-export into a
    /// fresh Vec, SipHash of the keys, DashMap lookup.
    fn srtcp_check(&self, track_id: u64) {
        let id = self
            .transport
            .find_session_by_addr(&self.source)
            .expect("session");
        let established = self.transport.with_session(id, |s| {
            s.state() == nexus_webrtc::webrtc::SessionState::Established
        });
        assert_eq!(established, Some(true), "session must be established");
        let mut material = Vec::with_capacity(self.export.0.len());
        material.extend_from_slice(&self.export.0);
        let km = KeyMaterial::from_dtls_export(&material, self.export.1).expect("key material");
        let mut hasher = DefaultHasher::new();
        km.master_key.hash(&mut hasher);
        km.master_salt.hash(&mut hasher);
        let mut fingerprint = [0u8; 32];
        fingerprint[..8].copy_from_slice(&hasher.finish().to_le_bytes());
        fingerprint[8..16].copy_from_slice(&id.value().to_le_bytes());
        if self.srtcp_cache.get(&track_id).is_none() {
            self.srtcp_cache.insert(track_id, (id.value(), fingerprint));
        }
    }
}

fn bench_ingress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingress");
    group.throughput(Throughput::Elements(1));
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            let (rig, mut publisher) = IngressRig::new(profile, media.payload);
            let id = format!("{profile_name}/{}", media.name);
            group.bench_function(id, |b| {
                b.iter_batched_ref(
                    || publisher.next_ciphertext(),
                    |(buf, len)| rig.process(&buf[..*len]),
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

// =============================================================================
// Egress
// =============================================================================

struct EgressRig {
    worker: MediaWorker,
    tx: Sender<WorkerMessage>,
    ingress_arena: PacketArena,
    source: SocketAddr,
    seq: u16,
    payload: usize,
    _send_socket: UdpSocket,
    _sinks: Sinks,
}

impl EgressRig {
    fn new(profile: ProtectionProfile, media: Media, subscribers: usize) -> Self {
        let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind send socket");
        send_socket.set_nonblocking(true).expect("nonblocking");
        let (mut worker, tx) =
            MediaWorker::new_standalone(64, send_socket.as_raw_fd()).expect("worker");
        let sinks = Sinks::new(subscribers + 1);
        let source = sinks.addrs[0];

        tx.send(WorkerMessage::SpawnActor {
            track_id: TRACK_ID,
            participant_id: 1,
            ssrc: PUBLISHER_SSRC,
            kind: media.kind,
            content_type: if media.kind == MediaKind::Audio { 2 } else { 0 },
        })
        .unwrap();
        tx.send(WorkerMessage::SetTrackTwccExtId {
            track_id: TRACK_ID,
            twcc_ext_id: TWCC_EXT_ID,
        })
        .unwrap();
        tx.send(WorkerMessage::SetTrackMid {
            track_id: TRACK_ID,
            mid_ext_id: MID_EXT_ID,
            mid_value: *b"0\0\0\0",
            mid_value_len: 1,
        })
        .unwrap();
        worker.process_one_iteration();

        for (i, dest_addr) in sinks.addrs[1..].iter().enumerate() {
            let material = key_material(profile, 0x80u8.wrapping_add(i as u8));
            tx.send(WorkerMessage::AddSubscriber {
                track_id: TRACK_ID,
                subscriber_id: i as u32 + 1,
                participant_id: i as u64 + 2,
                dest_addr: *dest_addr,
                target_layer: 0,
                srtp_context: srtp_context(&material),
            })
            .unwrap();
            // Drain as we go; the channel is bounded.
            if i % 64 == 63 {
                worker.process_one_iteration();
            }
        }
        worker.process_one_iteration();
        assert_eq!(worker.actor_count(), 1, "track actor must exist");

        Self {
            worker,
            tx,
            ingress_arena: PacketArena::new(64).expect("ingress arena"),
            source,
            seq: 0,
            payload: media.payload,
            _send_socket: send_socket,
            _sinks: sinks,
        }
    }

    /// Print how many fan-out packets actually reached the kernel, so a
    /// fast result caused by silent drops is visible.
    fn report(&self, id: &str) {
        let stats = self.worker.stats();
        let (sent, failed) = self.worker.send_stats();
        let dropped_unprotected = self.worker.dropped_unprotected();
        eprintln!(
            "egress/{id}: sent={sent} send_failed={failed} dropped={} \
             arena_failures={} dropped_unprotected={dropped_unprotected}",
            stats.packets_dropped, stats.arena_alloc_failures_fanout,
        );
    }

    /// Timed: hand one decrypted packet to the worker and run one cycle.
    fn forward_one(&mut self) {
        let mut slot = self.ingress_arena.alloc().expect("ingress slot");
        self.seq = self.seq.wrapping_add(1);
        let len = write_rtp(
            slot.data_mut(),
            self.seq,
            self.seq as u32 * 3000,
            self.payload,
        );
        slot.set_len(len as u16);
        let msg = WorkerMessage::Packet {
            track_id: TRACK_ID,
            packet: slot,
            source_addr: self.source,
        };
        self.tx.try_send(msg).expect("worker queue has room");
        black_box(self.worker.process_one_iteration());
    }
}

fn bench_egress(c: &mut Criterion) {
    raise_fd_limit();
    let mut group = c.benchmark_group("egress");
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            for subscribers in SUBSCRIBER_COUNTS {
                let mut rig = EgressRig::new(profile, media, subscribers);
                group.throughput(Throughput::Elements(subscribers as u64));
                let id = BenchmarkId::new(format!("{profile_name}/{}", media.name), subscribers);
                group.bench_function(id, |b| b.iter(|| rig.forward_one()));
                rig.report(&format!("{profile_name}/{}/{subscribers}", media.name));
            }
        }
    }
    group.finish();
}

// =============================================================================
// SRTP alone
// =============================================================================

fn bench_srtp(c: &mut Criterion) {
    let mut group = c.benchmark_group("srtp");
    group.throughput(Throughput::Elements(1));
    for (profile_name, profile) in PROFILES {
        for media in MEDIA {
            let material = key_material(profile, 0x20);
            let mut sender = srtp_context(&material);
            let mut receiver = srtp_context(&material);
            let mut seq = 0u16;
            let id = format!("protect/{profile_name}/{}", media.name);
            group.bench_function(id, |b| {
                let mut buf = [0u8; 1500];
                b.iter(|| {
                    seq = seq.wrapping_add(1);
                    let len = write_rtp(&mut buf, seq, 0, media.payload);
                    black_box(sender.protect_rtp(&mut buf, len).expect("protect"))
                })
            });
            // Fresh sender: the protect loop above wrapped `seq` and advanced
            // its rollover counter past what a new receiver would accept.
            let mut sender = srtp_context(&material);
            let mut seq = 0u16;
            let id = format!("unprotect/{profile_name}/{}", media.name);
            group.bench_function(id, |b| {
                b.iter_batched_ref(
                    || {
                        let mut buf = [0u8; 1500];
                        seq = seq.wrapping_add(1);
                        let len = write_rtp(&mut buf, seq, 0, media.payload);
                        let len = sender.protect_rtp(&mut buf, len).expect("protect");
                        (buf, len)
                    },
                    |(buf, len)| black_box(receiver.unprotect_rtp(buf, *len).expect("unprotect")),
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_srtp, bench_ingress, bench_egress);
criterion_main!(benches);
