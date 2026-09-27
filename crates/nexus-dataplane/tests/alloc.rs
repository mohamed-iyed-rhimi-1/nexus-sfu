//! Zero heap allocations per packet on the steady-state path (note §17.7,
//! Phase 1 exit criterion 2): RTP with header extensions mapped and the
//! subscriber's mid written, SR translation, PLI and FIR, RR and NACK, and
//! a STUN binding request per round, all inside the measured window.
//!
//! A counting global allocator counts only while `COUNTING` is set on the
//! current thread, which the test sets around `Shard::iterate` alone: the
//! peers' SRTP (`SrtpContext` allocates per new SSRC) and the test's own
//! bookkeeping run outside the measured window.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use nexus_dataplane::{Command, Event, ExtIds, MemIo, Shard, ShardConfig, SubscriptionId, TrackId};
use nexus_transport::srtp::ProtectionProfile;
use support::*;

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

const SUBSCRIBERS: u64 = 10;
const AUDIO_SSRC: u32 = 0xA0A0_0001;
const VIDEO_SSRC: u32 = 0xB0B0_0001;
const ROUNDS: u32 = 100;
const RTP_PER_ROUND: u32 = 100;

type AllocShard = Shard<MemIo, Vec<Event>>;

/// Iterates until drained, counting allocations; returns how many happened.
fn measured_run(shard: &mut AllocShard, now: Instant) -> u64 {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.with(|c| c.set(true));
    for _ in 0..1_000 {
        let stats = shard.iterate(now);
        if stats.received == 0 && stats.commands == 0 && shard.io().inbound_len() == 0 {
            break;
        }
    }
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

struct Scenario {
    shard: AllocShard,
    publisher: Peer,
    subscribers: Vec<Peer>,
    out_ssrcs: Vec<u32>,
    now: Instant,
}

/// 1 publisher (audio + video) and 10 subscribers on both tracks.
fn scenario(profile: ProtectionProfile) -> Scenario {
    let now = Instant::now();
    let config = ShardConfig {
        pool_buffers: 1_024,
        max_sessions: 16,
        ..Default::default()
    };
    // Room for a round's output (≈ 1,000 RTP + SRs + PLIs) without growing.
    let io = MemIo::with_capacity(512, 4_096, 4_096 * 256);
    let mut shard = Shard::new(config, io, Vec::with_capacity(4_096), now).unwrap();
    let publisher = Peer::new(1, "192.0.2.1:1000", profile);
    connect_alloc(&mut shard, &publisher, now);
    let (audio, video) = (TrackId::new(10), TrackId::new(11));
    for (track, ssrc, mid) in [(audio, AUDIO_SSRC, b"0"), (video, VIDEO_SSRC, b"1")] {
        // The publisher's answer accepted mid (1) and audio level (2).
        let mut spec = track_spec(Some(ssrc), mid);
        spec.ext = ExtIds {
            mid: 1,
            audio_level: 2,
            video_orientation: 0,
        };
        assert!(shard
            .push_command(Command::AddTrack {
                id: publisher.id,
                track,
                spec
            })
            .is_ok());
    }
    let mut subscribers = Vec::new();
    let mut out_ssrcs = Vec::new();
    for n in 0..SUBSCRIBERS {
        let mut peer = Peer::new(2 + n, &format!("192.0.2.{}:2000", 2 + n), profile);
        connect_alloc(&mut shard, &peer, now);
        for (k, track) in [audio, video].into_iter().enumerate() {
            let out = peer.next_out_ssrc();
            let sub = SubscriptionId::new(100 + 2 * n + k as u64);
            // Audio level mapped to 5 and the subscriber's mid written as 1:
            // every forwarded packet goes through the extension rewrite.
            let mut spec = sub_spec(out, track);
            spec.ext_map.map[2] = 5;
            spec.ext_map.mid = 1;
            assert!(shard
                .push_command(Command::Subscribe {
                    id: peer.id,
                    sub,
                    track,
                    spec
                })
                .is_ok());
            out_ssrcs.push(out);
        }
        subscribers.push(peer);
    }
    shard.iterate(now);
    Scenario {
        shard,
        publisher,
        subscribers,
        out_ssrcs,
        now,
    }
}

fn connect_alloc(shard: &mut AllocShard, peer: &Peer, now: Instant) {
    assert!(shard.push_command(peer.create()).is_ok());
    shard.iterate(now);
    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    assert!(shard.push_command(peer.install()).is_ok());
    shard.iterate(now);
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
}

/// Queues one round: RTP on both tracks, then one SR, PLI, RR and NACK.
fn queue_round(s: &mut Scenario, round: u32) {
    for i in 0..RTP_PER_ROUND {
        let seq = (round * RTP_PER_ROUND + i) as u16;
        let ssrc = if i % 2 == 0 { AUDIO_SSRC } else { VIDEO_SSRC };
        let mid: &[u8] = if i % 2 == 0 { b"0" } else { b"1" };
        let elements: [(u8, &[u8]); 2] = [(1, mid), (2, &[0x85])];
        let plain = rtp_with_ext(ssrc, seq, u32::from(seq) * 960, &elements, &[0x42; 160]);
        let packet = s.publisher.protect_rtp(&plain);
        s.shard.io_mut().push_inbound(s.publisher.addr, packet);
    }
    // A consent-style binding request on the selected address (fresh id).
    let stun = s.publisher.binding_request(true);
    s.shard.io_mut().push_inbound(s.publisher.addr, stun);
    let sr_ssrc = if round % 2 == 0 {
        AUDIO_SSRC
    } else {
        VIDEO_SSRC
    };
    let sr = s.publisher.rtcp(&sender_report(
        sr_ssrc,
        u64::from(round) << 32,
        round * 960,
        1,
        160,
    ));
    s.shard.io_mut().push_inbound(s.publisher.addr, sr);
    let k = (round as usize) % s.subscribers.len();
    let own = 0x5000_0000 + k as u32;
    let out = s.out_ssrcs[2 * k + 1];
    let peer = &mut s.subscribers[k];
    for plain in [
        pli(own, out),
        fir(own, out),
        receiver_report(own),
        nack(own, out, 1),
    ] {
        let packet = peer.rtcp(&plain);
        s.shard.io_mut().push_inbound(peer.addr, packet);
    }
}

/// Captured output by kind.
#[derive(Default)]
struct Output {
    rtp: u64,
    rtp_with_extensions: u64,
    rtcp: u64,
    stun: u64,
}

/// Counts captured datagrams by kind, then clears the capture.
fn drain_output(s: &mut Scenario) -> Output {
    let mut out = Output::default();
    for (_, bytes) in s.shard.io().outbound() {
        if bytes[0] < 4 {
            out.stun += 1;
        } else if (64..=95).contains(&(bytes[1] & 0x7F)) {
            out.rtcp += 1;
        } else {
            out.rtp += 1;
            // The RTP header is sent in the clear: X is visible.
            out.rtp_with_extensions += u64::from(bytes[0] & 0x10 != 0);
        }
    }
    s.shard.io_mut().clear_outbound();
    out
}

fn run_profile(profile: ProtectionProfile) {
    let mut s = scenario(profile);

    // Warm-up: every SSRC in both directions, RTP and RTCP, so every SRTP
    // slot and map entry exists (round 0 and 1 cover both SR SSRCs; the
    // subscribers' RTCP SSRCs are covered by rounds 0-9).
    for round in 0..SUBSCRIBERS as u32 {
        queue_round(&mut s, round);
        s.shard.iterate(s.now);
        for _ in 0..10 {
            s.shard.iterate(s.now);
        }
        drain_output(&mut s);
    }
    assert!(s
        .shard
        .events()
        .iter()
        .all(|e| !matches!(e, Event::CommandRejected { .. })));

    let (mut rtp_out, mut rtp_ext, mut stun_out, mut allocations) = (0, 0, 0, 0);
    let counters_before = *s.shard.counters();
    for round in SUBSCRIBERS as u32..SUBSCRIBERS as u32 + ROUNDS {
        queue_round(&mut s, round);
        s.now = at(s.now, 20); // 2 s in total: throttle and housekeeping run
        allocations += measured_run(&mut s.shard, s.now);
        let out = drain_output(&mut s);
        rtp_out += out.rtp;
        rtp_ext += out.rtp_with_extensions;
        stun_out += out.stun;
    }
    let counters = s.shard.counters();

    assert_eq!(
        allocations, 0,
        "{profile:?}: allocations on the steady-state path"
    );
    let rtp_in = u64::from(ROUNDS * RTP_PER_ROUND);
    assert_eq!(
        rtp_out,
        SUBSCRIBERS * rtp_in,
        "{profile:?}: output = 10 x RTP input"
    );
    assert_eq!(
        rtp_ext, rtp_out,
        "{profile:?}: every packet went through the extension rewrite"
    );
    assert_eq!(
        stun_out,
        u64::from(ROUNDS),
        "{profile:?}: one binding response per round"
    );
    assert_eq!(
        counters.sr_translated - counters_before.sr_translated,
        SUBSCRIBERS * u64::from(ROUNDS)
    );
    assert!(
        counters.keyframe_requests > counters_before.keyframe_requests,
        "PLIs forwarded"
    );
    assert!(
        counters.keyframe_throttled > counters_before.keyframe_throttled,
        "and throttled"
    );
    // Each round's PLI and FIR both reach the keyframe request.
    let keyframe = |c: &nexus_dataplane::ShardCounters| c.keyframe_requests + c.keyframe_throttled;
    assert_eq!(
        keyframe(counters) - keyframe(&counters_before),
        2 * u64::from(ROUNDS)
    );
    assert_eq!(
        counters.rtcp_ignored - counters_before.rtcp_ignored,
        2 * u64::from(ROUNDS)
    );
    assert_eq!(
        counters.drop_srtp_auth + counters.drop_no_route + counters.drop_pool_empty,
        0
    );
    assert!(counters.iterations > counters_before.iterations);
}

/// One test runs both profiles in turn: counting is per thread, but test
/// threads would still share the peers' warm-up state if split.
#[test]
fn steady_state_path_does_not_allocate() {
    run_profile(ProtectionProfile::AeadAes128Gcm);
    run_profile(ProtectionProfile::Aes128CmHmacSha1_80);
}
