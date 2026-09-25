//! Per-participant memory measurement.
//!
//! Counts live heap bytes with a wrapping global allocator while building
//! the real per-participant state: a WebRTC session through a completed
//! DTLS handshake, a published track on a `MediaWorker`, and subscribers.
//! Arena memory held by retransmission rings is reported separately, since
//! it is preallocated rather than heap-allocated per participant.
//!
//! Not covered: signaling connection state (WebSocket / QUIC), orchestrator
//! bookkeeping, and CRDT entries. These are expected to be small next to
//! the items measured here.
//!
//! Run with: `cargo bench --bench memory`
//! Set `NEXUS_MEM_BUDGET_KB` to fail when a publisher exceeds a budget.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicIsize, Ordering};

use nexus_sfu::types::MediaKind;
use nexus_sfu::worker::{MediaWorker, WorkerMessage};
use nexus_transport::arena::PacketArena;
use nexus_transport::dtls::{DtlsRole as EngineRole, OpenSslDtlsEngine};
use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};
use nexus_webrtc::webrtc::{
    DtlsParameters, DtlsRole, IncomingData, SessionState, TransportConfig, WebRtcTransport,
};

// =============================================================================
// Counting allocator
// =============================================================================

struct Counting;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged and only
// updates a counter.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn live() -> isize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

// OpenSSL allocates through its own malloc, not the Rust allocator, so the
// counter misses it. Sample the process allocator too where available.
#[cfg(target_os = "macos")]
fn malloc_in_use() -> Option<isize> {
    #[repr(C)]
    struct MallocStatistics {
        blocks_in_use: u32,
        size_in_use: usize,
        max_size_in_use: usize,
        size_allocated: usize,
    }
    extern "C" {
        fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut MallocStatistics);
    }
    let mut stats = MallocStatistics {
        blocks_in_use: 0,
        size_in_use: 0,
        max_size_in_use: 0,
        size_allocated: 0,
    };
    // SAFETY: a null zone asks for statistics over all zones; the struct
    // layout matches <malloc/malloc.h>.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    Some(stats.size_in_use as isize)
}

#[cfg(target_os = "linux")]
fn malloc_in_use() -> Option<isize> {
    // SAFETY: mallinfo2 has no preconditions and returns a plain struct.
    let info = unsafe { libc::mallinfo2() };
    Some(info.uordblks as isize)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn malloc_in_use() -> Option<isize> {
    None
}

/// Heap delta of `f` per `count` items: (Rust allocator, whole malloc).
fn measure<T>(count: usize, f: impl FnOnce() -> T) -> (T, isize, Option<isize>) {
    assert!(count > 0, "count must be positive");
    let (rust_before, malloc_before) = (live(), malloc_in_use());
    let out = f();
    let rust = (live() - rust_before) / count as isize;
    let malloc = malloc_in_use()
        .zip(malloc_before)
        .map(|(a, b)| (a - b) / count as isize);
    (out, rust, malloc)
}

// =============================================================================
// Sessions
// =============================================================================

const SESSIONS: usize = 50;

fn source_addr(i: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 20_000 + i as u16))
}

/// Run a real DTLS handshake between the session at `addr` and an OpenSSL
/// client engine playing the browser. Returns the client, which must be
/// kept alive so its memory is not freed inside the measurement.
fn handshake(transport: &WebRtcTransport, addr: SocketAddr) -> OpenSslDtlsEngine {
    let id = transport.find_session_by_addr(&addr).expect("session");
    transport.with_session_mut(id, |s| {
        s.force_state_for_testing(SessionState::IceConnecting);
        s.inject_ice_completion_for_testing();
    });
    let mut client = OpenSslDtlsEngine::new(EngineRole::Client).expect("client engine");
    // The SDP answer would carry this; without it the session won't trust DTLS.
    let fingerprint = *client.fingerprint();
    transport
        .with_session_mut(id, |s| s.set_remote_fingerprint(fingerprint))
        .expect("session")
        .expect("fingerprint accepted");
    let mut flight = client.start_handshake().expect("client hello");
    let mut out = [0u8; 2048];
    for _ in 0..16 {
        if flight.is_empty() {
            break;
        }
        let reply = match transport.process_packet(&flight, addr, &mut out) {
            Ok(Some((_, IncomingData::Dtls(reply)))) => reply,
            Ok(_) => Vec::new(),
            Err(e) => panic!("server rejected DTLS flight: {e:?}"),
        };
        flight = if reply.is_empty() {
            Vec::new()
        } else {
            client.process(&reply).expect("client")
        };
    }
    let state = transport.with_session(id, |s| s.state()).expect("session");
    assert_eq!(
        state,
        SessionState::Established,
        "DTLS handshake must complete"
    );
    client
}

fn measure_sessions() -> (isize, Option<isize>, isize, Option<isize>) {
    let transport = WebRtcTransport::new(TransportConfig::default()).expect("transport");
    transport.start().expect("start");
    let (_, created_rust, created_malloc) = measure(SESSIONS, || {
        for i in 0..SESSIONS {
            let id = transport
                .create_session(DtlsParameters::new(DtlsRole::Server))
                .expect("session");
            transport.associate_address(source_addr(i), id);
        }
    });
    // The handshake also builds the client engines. Dropping them afterwards
    // frees exactly the client side, leaving the server session's growth.
    let (clients, hs_rust, hs_malloc) = measure(SESSIONS, || {
        (0..SESSIONS)
            .map(|i| handshake(&transport, source_addr(i)))
            .collect::<Vec<_>>()
    });
    let (_, freed_rust, freed_malloc) = measure(SESSIONS, || drop(clients));
    let hs_malloc = hs_malloc
        .zip(freed_malloc)
        .map(|(total, freed)| total + freed);
    (
        created_rust,
        created_malloc,
        hs_rust + freed_rust,
        hs_malloc,
    )
}

// =============================================================================
// Tracks and subscribers
// =============================================================================

const TRACKS: usize = 20;
/// Mirrors `ACTOR_RING_CAPACITY` in src/worker/pool.rs (not exported).
const ACTOR_RING_CAPACITY: usize = 2048;
const SUBSCRIBERS: usize = 200;

fn srtp_context(seed: u8) -> SrtpContext {
    let profile = ProtectionProfile::AeadAes128Gcm;
    let material: Vec<u8> = (0..profile.key_len() + profile.salt_len())
        .map(|i| seed.wrapping_add(i as u8) | 1)
        .collect();
    let km = KeyMaterial::from_dtls_export(&material, profile).expect("key material");
    SrtpContext::new(
        &km,
        SrtpPolicy {
            profile,
            ..SrtpPolicy::default()
        },
    )
    .expect("context")
}

fn spawn_track(tx: &crossbeam::channel::Sender<WorkerMessage>, track_id: u64, kind: MediaKind) {
    tx.send(WorkerMessage::SpawnActor {
        track_id,
        participant_id: track_id,
        ssrc: 0x1000 + track_id as u32,
        kind,
        content_type: 0,
    })
    .expect("send");
}

fn subscribe(tx: &crossbeam::channel::Sender<WorkerMessage>, track_id: u64, sub: u32) {
    tx.send(WorkerMessage::AddSubscriber {
        track_id,
        subscriber_id: sub,
        participant_id: 10_000 + sub as u64,
        dest_addr: SocketAddr::from(([127, 0, 0, 1], 30_000 + sub as u16)),
        target_layer: 0,
        srtp_context: srtp_context(sub as u8),
    })
    .expect("send");
}

/// Per-track and per-subscriber heap cost on a real worker.
fn measure_tracks() -> (isize, isize, isize) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let (mut worker, tx) = MediaWorker::new_standalone(16, socket.as_raw_fd()).expect("worker");
    let (_, per_track, _) = measure(TRACKS, || {
        for t in 0..TRACKS as u64 {
            spawn_track(&tx, t + 1, MediaKind::Video);
            worker.process_one_iteration();
        }
    });
    // First 100 subscribers fit the per-track reservation; later ones grow it.
    let (_, first_100, _) = measure(100, || {
        for s in 0..100 {
            subscribe(&tx, 1, s);
            worker.process_one_iteration();
        }
    });
    let (_, next_100, _) = measure(SUBSCRIBERS - 100, || {
        for s in 100..SUBSCRIBERS as u32 {
            subscribe(&tx, 1, s);
            worker.process_one_iteration();
        }
    });
    assert_eq!(worker.actor_count() as usize, TRACKS, "all tracks spawned");
    (per_track, first_100, next_100)
}

/// Arena slots a track holds for retransmission after `ACTOR_RING_CAPACITY`
/// packets and after twice that many. With production retention (2048)
/// the two should match; see the ring decay note in the report.
fn measure_ring_slots() -> (u32, u32) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let (mut worker, tx) = MediaWorker::new_standalone(16, socket.as_raw_fd()).expect("worker");
    let ingress = PacketArena::new(16).expect("arena");
    spawn_track(&tx, 1, MediaKind::Video);
    worker.process_one_iteration();
    let source = SocketAddr::from(([127, 0, 0, 1], 40_000));
    let ring = ACTOR_RING_CAPACITY as u16;
    let mut at_full = 0;
    for seq in 0..2 * ring {
        let mut slot = ingress.alloc().expect("slot");
        let data = slot.data_mut();
        data[0] = 0x80;
        data[1] = 0x60;
        data[2..4].copy_from_slice(&seq.to_be_bytes());
        data[8..12].copy_from_slice(&0x1001u32.to_be_bytes());
        slot.set_len(1200);
        tx.send(WorkerMessage::Packet {
            track_id: 1,
            packet: slot,
            source_addr: source,
        })
        .expect("send");
        worker.process_one_iteration();
        if seq + 1 == ring {
            at_full = ingress.allocated_count();
        }
    }
    assert_eq!(
        worker.stats().packets_processed,
        2 * ring as u64,
        "all packets processed"
    );
    (at_full, ingress.allocated_count())
}

// =============================================================================
// Report
// =============================================================================

fn kb(bytes: isize) -> String {
    format!("{:>8.1} KB", bytes as f64 / 1024.0)
}

fn kb_opt(bytes: Option<isize>) -> String {
    bytes.map(kb).unwrap_or_else(|| "     n/a".into())
}

fn main() {
    // Criterion passes `--bench`; nothing to parse.
    let (created_rust, created_malloc, hs_rust, hs_malloc) = measure_sessions();
    let (per_track, sub_first, sub_next) = measure_tracks();
    let (ring_slots, ring_slots_later) = measure_ring_slots();
    let slot_bytes = 1500isize;
    let ring_bytes = ring_slots as isize * slot_bytes;

    println!("\nPer-item heap cost (Rust allocator | all malloc incl. OpenSSL)");
    println!(
        "  session created              {} | {}",
        kb(created_rust),
        kb_opt(created_malloc)
    );
    println!(
        "  + DTLS handshake completed   {} | {}",
        kb(hs_rust),
        kb_opt(hs_malloc)
    );
    println!("  track (worker state)         {}", kb(per_track));
    println!(
        "  subscriber, 1st-100th        {}  (pre-reserved inside the track)",
        kb(sub_first)
    );
    println!("  subscriber, 101st-200th      {}", kb(sub_next));
    println!(
        "  retransmit ring, full        {}  ({ring_slots} arena slots)",
        kb(ring_bytes)
    );
    if ring_slots_later < ring_slots {
        println!(
            "  !! ring decays: {ring_slots_later} slots held after {} packets \
             (push_bounded evicts the newest packet when limit == capacity)",
            2 * ACTOR_RING_CAPACITY
        );
    }

    let session = created_malloc.unwrap_or(created_rust) + hs_malloc.unwrap_or(hs_rust);
    let publisher = session + 2 * per_track;
    println!("\nScenarios (heap; arena slots listed separately)");
    println!(
        "  A+V publisher, 0 subscriptions   {}  + arena {}",
        kb(publisher),
        kb(2 * ring_bytes)
    );
    // Subscriptions live in the *publisher's* track, which pre-reserves 100
    // entries (so 1st-100th measure ~0). Use the real entry size instead.
    let _ = sub_first;
    println!(
        "  + subscribed to 10 A+V others    {}  + arena {}",
        kb(publisher + 20 * sub_next),
        kb(2 * ring_bytes)
    );
    println!("  README target                    {}", kb(100 * 1024));

    if let Ok(budget) = std::env::var("NEXUS_MEM_BUDGET_KB") {
        let budget: isize = budget
            .parse()
            .expect("NEXUS_MEM_BUDGET_KB must be an integer");
        assert!(
            publisher <= budget * 1024,
            "A+V publisher uses {} KB, budget is {budget} KB",
            publisher / 1024
        );
    }
}
