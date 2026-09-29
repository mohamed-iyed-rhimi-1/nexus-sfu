//! Zero heap allocations per packet on the steady-state path (note §17.7,
//! Phase 1 exit criterion 2): RTP with header extensions mapped and the
//! subscriber's mid written, SR translation, PLI and FIR, RR and NACK, and
//! a STUN binding request per round, all inside the measured window.
//! Phase 2 exit criterion 4 adds the cross-shard path: the same scenario on
//! two shards (hand-off, remote fan-out, returns, SRs and keyframe requests
//! between shards), both iterated inside the window on this thread.
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

use nexus_dataplane::{
    Command, Event, ExtIds, MemIo, Shard, ShardConfig, ShardCounters, ShardId, SubscriptionId,
    TrackId, TrackRef, XsMesh,
};
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

/// Iterates every shard until all are drained, counting allocations;
/// returns how many happened.
fn measured_run(shards: &mut [AllocShard], now: Instant) -> u64 {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.with(|c| c.set(true));
    for _ in 0..1_000 {
        let mut busy = false;
        for shard in shards.iter_mut() {
            let stats = shard.iterate(now);
            busy |= stats.received > 0 || stats.commands > 0 || stats.cross_shard > 0;
            busy |= shard.io().inbound_len() > 0 || shard.xs_pending();
        }
        if !busy {
            break;
        }
    }
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

struct Scenario {
    shards: Vec<AllocShard>,
    publisher: Peer,
    subscribers: Vec<Peer>,
    /// Each subscriber's shard.
    placement: Vec<usize>,
    out_ssrcs: Vec<u32>,
    now: Instant,
}

/// `n` shards connected by a mesh (none for one shard).
fn alloc_shards(n: u8, now: Instant) -> Vec<AllocShard> {
    let mut shards: Vec<AllocShard> = (0..n)
        .map(|i| {
            let config = ShardConfig {
                shard: ShardId::new(i),
                pool_buffers: 1_024,
                max_sessions: 16,
                ..Default::default()
            };
            // Room for a round's output (≈ 1,000 RTP + SRs + PLIs) without growing.
            let io = MemIo::with_capacity(512, 4_096, 4_096 * 256);
            Shard::new(config, io, Vec::with_capacity(4_096), now).unwrap()
        })
        .collect();
    if n > 1 {
        let regions: Vec<_> = shards.iter().map(AllocShard::pool_region).collect();
        for (shard, ports) in shards.iter_mut().zip(XsMesh::build(&regions)) {
            shard.attach_xs(ports);
        }
    }
    shards
}

/// 1 publisher (audio + video) on shard 0 and 10 subscribers on both
/// tracks, the first `SUBSCRIBERS / n` on shard 0 and the others spread
/// over the rest.
fn scenario(profile: ProtectionProfile, n: u8) -> Scenario {
    let now = Instant::now();
    let mut shards = alloc_shards(n, now);
    let publisher = Peer::new(1, "192.0.2.1:1000", profile);
    connect_alloc(&mut shards[0], &publisher, now);
    let tracks = [TrackId::new(10), TrackId::new(11)];
    for (track, ssrc, mid) in [(tracks[0], AUDIO_SSRC, b"0"), (tracks[1], VIDEO_SSRC, b"1")] {
        // The publisher's answer accepted mid (1) and audio level (2).
        let mut spec = track_spec(Some(ssrc), mid);
        spec.ext = ExtIds {
            mid: 1,
            audio_level: 2,
            video_orientation: 0,
        };
        let id = publisher.id;
        assert!(shards[0]
            .push_command(Command::AddTrack { id, track, spec })
            .is_ok());
    }
    let placement: Vec<usize> = (0..SUBSCRIBERS as usize)
        .map(|k| k * usize::from(n) / SUBSCRIBERS as usize)
        .collect();
    let mut subscribers = Vec::new();
    let mut out_ssrcs = Vec::new();
    for n in 0..SUBSCRIBERS {
        let mut peer = Peer::new(2 + n, &format!("192.0.2.{}:2000", 2 + n), profile);
        let shard = &mut shards[placement[n as usize]];
        connect_alloc(shard, &peer, now);
        for (k, track) in tracks.into_iter().enumerate() {
            let out = peer.next_out_ssrc();
            let sub = SubscriptionId::new(100 + 2 * n + k as u64);
            // Audio level mapped to 5 and the subscriber's mid written as 1:
            // every forwarded packet goes through the extension rewrite.
            let source = TrackRef {
                shard: ShardId::new(0),
                track,
            };
            let mut spec = sub_spec_from(out, source);
            spec.ext_map.map[2] = 5;
            spec.ext_map.mid = 1;
            spec.pub_mid = 1;
            let id = peer.id;
            assert!(shard
                .push_command(Command::Subscribe {
                    id,
                    sub,
                    track,
                    spec
                })
                .is_ok());
            out_ssrcs.push(out);
        }
        subscribers.push(peer);
    }
    for i in 1..n {
        for track in tracks {
            let shard = ShardId::new(i);
            let add = Command::AddRemoteShard { track, shard };
            assert!(shards[0].push_command(add).is_ok());
        }
    }
    for shard in &mut shards {
        shard.iterate(now);
    }
    Scenario {
        shards,
        publisher,
        subscribers,
        placement,
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
    let from = s.publisher.addr;
    for i in 0..RTP_PER_ROUND {
        let seq = (round * RTP_PER_ROUND + i) as u16;
        let ssrc = if i % 2 == 0 { AUDIO_SSRC } else { VIDEO_SSRC };
        let mid: &[u8] = if i % 2 == 0 { b"0" } else { b"1" };
        let elements: [(u8, &[u8]); 2] = [(1, mid), (2, &[0x85])];
        let plain = rtp_with_ext(ssrc, seq, u32::from(seq) * 960, &elements, &[0x42; 160]);
        let packet = s.publisher.protect_rtp(&plain);
        s.shards[0].io_mut().push_inbound(from, packet);
    }
    // A consent-style binding request on the selected address (fresh id).
    let stun = s.publisher.binding_request(true);
    s.shards[0].io_mut().push_inbound(from, stun);
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
    s.shards[0].io_mut().push_inbound(from, sr);
    // Round k's RTCP comes from subscriber k: every shard's in turn.
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
        s.shards[s.placement[k]]
            .io_mut()
            .push_inbound(peer.addr, packet);
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

/// Counts every shard's captured datagrams by kind, then clears the capture.
fn drain_output(s: &mut Scenario) -> Output {
    let mut out = Output::default();
    for shard in &mut s.shards {
        for (_, bytes) in shard.io().outbound() {
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
        shard.io_mut().clear_outbound();
    }
    out
}

/// The shards' counters added up.
fn total(shards: &[AllocShard]) -> ShardCounters {
    let mut sum = [0u64; ShardCounters::NAMES.len()];
    for shard in shards {
        for (s, v) in sum.iter_mut().zip(shard.counters().values()) {
            *s += v;
        }
    }
    let value = |name: &str| {
        sum[ShardCounters::NAMES
            .iter()
            .position(|n| *n == name)
            .unwrap()]
    };
    ShardCounters {
        iterations: value("iterations"),
        sr_translated: value("sr_translated"),
        keyframe_requests: value("keyframe_requests"),
        keyframe_throttled: value("keyframe_throttled"),
        keyframe_deferred: value("keyframe_deferred"),
        rtcp_ignored: value("rtcp_ignored"),
        drop_srtp_auth: value("drop_srtp_auth"),
        drop_no_route: value("drop_no_route"),
        drop_pool_empty: value("drop_pool_empty"),
        xs_tx: value("xs_tx"),
        xs_rx: value("xs_rx"),
        xs_returned: value("xs_returned"),
        drop_xs_full: value("drop_xs_full"),
        drop_xs_credit: value("drop_xs_credit"),
        drop_xs_no_track: value("drop_xs_no_track"),
        xs_keyframe_ignored: value("xs_keyframe_ignored"),
        ..ShardCounters::default()
    }
}

fn run_profile(profile: ProtectionProfile, n: u8) {
    let mut s = scenario(profile, n);

    // Warm-up: every SSRC in both directions, RTP and RTCP, so every SRTP
    // slot and map entry exists (round 0 and 1 cover both SR SSRCs; the
    // subscribers' RTCP SSRCs are covered by rounds 0-9).
    for round in 0..SUBSCRIBERS as u32 {
        queue_round(&mut s, round);
        for _ in 0..11 {
            for shard in &mut s.shards {
                shard.iterate(s.now);
            }
        }
        drain_output(&mut s);
    }
    for shard in &s.shards {
        assert!(shard
            .events()
            .iter()
            .all(|e| !matches!(e, Event::CommandRejected { .. })));
    }

    let (mut rtp_out, mut rtp_ext, mut stun_out, mut allocations) = (0, 0, 0, 0);
    let before = total(&s.shards);
    for round in SUBSCRIBERS as u32..SUBSCRIBERS as u32 + ROUNDS {
        queue_round(&mut s, round);
        s.now = at(s.now, 20); // 2 s in total: throttle and housekeeping run
        allocations += measured_run(&mut s.shards, s.now);
        let out = drain_output(&mut s);
        rtp_out += out.rtp;
        rtp_ext += out.rtp_with_extensions;
        stun_out += out.stun;
    }
    let after = total(&s.shards);
    let delta = |f: fn(&ShardCounters) -> u64| f(&after) - f(&before);
    let what = format!("{profile:?}, {n} shard(s)");

    assert_eq!(
        allocations, 0,
        "{what}: allocations on the steady-state path"
    );
    let rtp_in = u64::from(ROUNDS * RTP_PER_ROUND);
    assert_eq!(
        rtp_out,
        SUBSCRIBERS * rtp_in,
        "{what}: output = 10 x RTP input"
    );
    assert_eq!(
        rtp_ext, rtp_out,
        "{what}: every packet went through the extension rewrite"
    );
    assert_eq!(
        stun_out,
        u64::from(ROUNDS),
        "{what}: one binding response per round"
    );
    assert_eq!(
        delta(|c| c.sr_translated),
        SUBSCRIBERS * u64::from(ROUNDS),
        "{what}"
    );
    assert!(delta(|c| c.keyframe_requests) > 0, "{what}: PLIs forwarded");
    assert!(delta(|c| c.keyframe_throttled) > 0, "{what}: and throttled");
    assert!(
        delta(|c| c.keyframe_deferred) > 0,
        "{what}: and deferred PLIs sent inside the window"
    );
    // Each round's PLI and FIR both reach the keyframe request, on
    // whichever shard their subscriber is, and are sent or throttled; each
    // deferral adds at most one PLI when its window ends, including one per
    // track still pending from the warm-up.
    let reached = delta(|c| c.keyframe_requests + c.keyframe_throttled);
    let rtcp_requests = 2 * u64::from(ROUNDS);
    let deferred = delta(|c| c.keyframe_deferred) + 2;
    assert!(
        (rtcp_requests..=rtcp_requests + deferred).contains(&reached),
        "{what}: {reached} sent or throttled for {rtcp_requests} requests, {deferred} deferred"
    );
    assert_eq!(delta(|c| c.rtcp_ignored), 2 * u64::from(ROUNDS), "{what}");
    assert_eq!(
        after.drop_srtp_auth + after.drop_no_route + after.drop_pool_empty,
        0,
        "{what}"
    );
    let xs_drops = after.drop_xs_full + after.drop_xs_credit + after.drop_xs_no_track;
    assert_eq!(xs_drops + after.xs_keyframe_ignored, 0, "{what}");
    if n > 1 {
        // One hand-off per packet and remote shard, every one returned.
        assert_eq!(
            delta(|c| c.xs_returned),
            u64::from(n - 1) * rtp_in,
            "{what}"
        );
        assert!(delta(|c| c.xs_rx) >= delta(|c| c.xs_returned), "{what}");
    }
    assert!(after.iterations > before.iterations);
    for (i, shard) in s.shards.iter().enumerate() {
        let snap = shard.snapshot();
        assert_eq!(
            (snap.xs_in_flight, snap.pool_available),
            (0, 1_024),
            "{what}: shard {i}"
        );
    }
}

/// One test runs every case in turn: counting is per thread, but test
/// threads would still share the peers' warm-up state if split.
#[test]
fn steady_state_path_does_not_allocate() {
    for n in [1, 2] {
        run_profile(ProtectionProfile::AeadAes128Gcm, n);
        run_profile(ProtectionProfile::Aes128CmHmacSha1_80, n);
    }
}
