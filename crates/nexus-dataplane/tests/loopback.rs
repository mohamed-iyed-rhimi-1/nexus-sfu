//! The data plane on real sockets and threads (plans 1.3, 2.3): peers on
//! loopback UDP sockets talk to shards started with `Dataplane::start`; the
//! test drives them only through `DataplaneHandle`. With several shards,
//! each shard is its own thread and socket, connected by the mesh.

mod support;

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nexus_dataplane::{
    default_pool_buffers, Command, DataplaneConfig, DataplaneError, DataplaneHandle, Event,
    ShardConfig, ShardId, ShardInfo, ShardStatsSnapshot, SubscriptionId, TrackId, TrackRef,
};
use nexus_transport::srtp::ProtectionProfile;
use support::{pli, sender_report, sub_spec, sub_spec_from, track_spec, Peer, SUB_PT};
use tokio::sync::mpsc::Receiver;

const GCM: ProtectionProfile = ProtectionProfile::AeadAes128Gcm;
const SHARD: fn() -> ShardId = || ShardId::new(0);

/// Tests that measure time or flood a socket run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn config(bind: &str) -> DataplaneConfig {
    DataplaneConfig {
        bind_addr: bind.parse().expect("bind address"),
        recv_buffer_bytes: 1 << 20,
        send_buffer_bytes: 1 << 20,
        rng_seed: Some(1),
        shard: ShardConfig {
            pool_buffers: 1_024,
            max_sessions: 64,
            ..ShardConfig::default()
        },
        ..DataplaneConfig::default()
    }
}

/// `config` with `shards` shards and the default pool for that count.
fn config_n(bind: &str, shards: u16) -> DataplaneConfig {
    let mut config = DataplaneConfig {
        shards,
        ..config(bind)
    };
    config.shard.pool_buffers = default_pool_buffers(shards);
    config
}

struct Plane {
    handle: DataplaneHandle,
    /// Shard 0.
    info: ShardInfo,
    /// Every shard, by index.
    infos: Vec<ShardInfo>,
    events: Receiver<Event>,
}

fn start(config: DataplaneConfig) -> Plane {
    let shards = usize::from(config.shards);
    let (handle, infos) = nexus_dataplane::Dataplane::start(config).expect("start");
    assert_eq!(infos.len(), shards);
    assert_eq!(handle.shard_count(), shards);
    for (i, info) in infos.iter().enumerate() {
        assert_eq!(usize::from(info.id.index()), i);
        assert_ne!(info.local_addr.port(), 0);
        let same = infos.iter().filter(|o| o.local_addr == info.local_addr);
        assert_eq!(same.count(), 1, "a socket per shard");
    }
    let events = handle.take_events().expect("events once");
    assert!(handle.take_events().is_none());
    Plane {
        handle,
        info: infos[0],
        infos,
        events,
    }
}

impl Plane {
    /// Queues a command for shard 0.
    fn send(&self, command: Command) {
        self.send_to(SHARD(), command);
    }

    fn send_to(&self, shard: ShardId, command: Command) {
        self.handle.send(shard, command).expect("queue has room");
    }

    /// Shard `index`'s media address.
    fn addr(&self, index: u8) -> SocketAddr {
        self.infos[usize::from(index)].local_addr
    }

    /// The next event matching `want` within `timeout`; others are skipped.
    fn wait(&mut self, timeout: Duration, want: impl Fn(&Event) -> bool) -> Option<Event> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.events.try_recv() {
                Ok(event) if want(&event) => return Some(event),
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_micros(200)),
            }
        }
        None
    }

    /// Shard 0's stats once published values satisfy `done` (published
    /// every 1 s).
    fn stats_when(&self, done: impl Fn(&ShardStatsSnapshot) -> bool) -> ShardStatsSnapshot {
        self.stats_on(SHARD(), done)
    }

    /// `stats_when` for `shard`.
    fn stats_on(
        &self,
        shard: ShardId,
        done: impl Fn(&ShardStatsSnapshot) -> bool,
    ) -> ShardStatsSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let stats = self.handle.stats(shard);
            if done(&stats) || Instant::now() > deadline {
                return stats;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Time from a rejected command to its `CommandRejected` event.
    fn command_round_trip(&mut self, sub: u64) -> Duration {
        self.command_round_trip_on(SHARD(), sub)
    }

    /// `command_round_trip` through `shard`.
    fn command_round_trip_on(&mut self, shard: ShardId, sub: u64) -> Duration {
        let start = Instant::now();
        let sub = SubscriptionId::new(sub);
        self.send_to(shard, Command::Unsubscribe { sub });
        let rejected = |e: &Event| matches!(e, Event::CommandRejected { .. });
        self.wait(Duration::from_secs(2), rejected)
            .expect("rejected");
        start.elapsed()
    }
}

/// A peer on its own UDP socket.
struct Client {
    socket: UdpSocket,
    peer: Peer,
}

impl Client {
    fn new(n: u64, bind: &str) -> Self {
        let socket = UdpSocket::bind(bind).expect("bind client");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        Self {
            socket,
            peer: Peer::new(n, &addr, GCM),
        }
    }

    /// Time until the shard drained its socket: a binding request every
    /// 10 ms until one is answered. The socket queue is FIFO, so an answer
    /// means everything queued before that request was consumed.
    fn wait_drained(&self, to: SocketAddr) -> Duration {
        let start = Instant::now();
        let probe = self.peer.binding_request(false);
        let short = Some(Duration::from_millis(10));
        self.socket.set_read_timeout(short).unwrap();
        let mut answered = false;
        // Bounded: 5 s of 10 ms probes.
        for _ in 0..500 {
            self.socket.send_to(&probe, to).unwrap();
            // Other traffic (PLIs) may arrive first: skip it.
            while let Some(reply) = self.recv() {
                if reply.len() >= 20 && reply[..2] == [1, 1] {
                    answered = true;
                    break;
                }
            }
            if answered {
                break;
            }
        }
        let normal = Some(Duration::from_millis(100));
        self.socket.set_read_timeout(normal).unwrap();
        assert!(answered, "the shard never drained its socket");
        start.elapsed()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2_048];
        let (len, _) = self.socket.recv_from(&mut buf).ok()?;
        Some(buf[..len].to_vec())
    }

    /// Creates the session on shard 0, nominates this client's address
    /// (retrying until the shard handled `CreateSession`) and installs SRTP.
    fn connect(&self, plane: &mut Plane, to: SocketAddr) -> SocketAddr {
        self.connect_to(plane, SHARD(), to)
    }

    /// `connect` to `shard`, whose socket is `to`.
    fn connect_to(&self, plane: &mut Plane, shard: ShardId, to: SocketAddr) -> SocketAddr {
        plane.send_to(shard, self.peer.create());
        let request = self.peer.binding_request(true);
        let answered = (0..20).any(|_| {
            self.socket.send_to(&request, to).unwrap();
            // A binding success response: type 0x0101.
            self.recv()
                .is_some_and(|r| r.len() >= 20 && r[..2] == [1, 1])
        });
        assert!(answered, "binding request answered");
        let id = self.peer.id;
        let selected = plane.wait(
            Duration::from_secs(2),
            |e| matches!(e, Event::AddressSelected { id: i, .. } if *i == id),
        );
        let Some(Event::AddressSelected { addr, .. }) = selected else {
            panic!("no AddressSelected");
        };
        plane.send_to(shard, self.peer.install());
        addr
    }
}

/// A publisher and `subscribers` subscribers on one track, all connected.
fn call(plane: &mut Plane, to: SocketAddr, bind: &str, subscribers: u64) -> (Client, Vec<Client>) {
    let publisher = Client::new(1, bind);
    let selected = publisher.connect(plane, to);
    assert_eq!(selected, publisher.socket.local_addr().unwrap());
    let track = TrackId::new(1);
    plane.send(Command::AddTrack {
        id: publisher.peer.id,
        track,
        spec: track_spec(Some(0xAAAA), b"a0"),
    });
    let mut subs = Vec::new();
    for n in 0..subscribers {
        let mut sub = Client::new(2 + n, bind);
        sub.connect(plane, to);
        let out = sub.peer.next_out_ssrc();
        plane.send(Command::Subscribe {
            id: sub.peer.id,
            sub: SubscriptionId::new(1 + n),
            track,
            spec: sub_spec(out, track),
        });
        subs.push(sub);
    }
    // Commands are handled in order; a rejected probe proves the ones
    // before it were handled.
    plane.command_round_trip(9_999);
    (publisher, subs)
}

/// Starts a plane on `bind`, connects clients bound to `client_ip` to it at
/// `client_ip:port`, and sends 50 RTP packets from the publisher to one
/// subscriber through the kernel.
fn media_through_the_kernel(bind: &str, client_ip: &str) {
    let mut plane = start(config(bind));
    let port = plane.info.local_addr.port();
    let to: SocketAddr = format!("{client_ip}:{port}").parse().unwrap();
    let client_bind = format!("{client_ip}:0");
    let (mut publisher, mut subs) = call(&mut plane, to, &client_bind, 1);
    let sub = &mut subs[0];
    let mut received = Vec::new();
    for i in 0..50u16 {
        let payload = [i as u8; 120];
        let packet = publisher
            .peer
            .rtp(0xAAAA, 100 + i, 960 * u32::from(i), &payload);
        publisher.socket.send_to(&packet, to).unwrap();
        // One packet out per packet in: nothing queues up in the sockets.
        received.extend(sub.recv());
    }
    received.extend(std::iter::from_fn(|| sub.recv()));
    assert_eq!(received.len(), 50, "{bind}");
    for (i, data) in received.iter().enumerate() {
        let plain = sub.peer.open_rtp(data).expect("decrypts at the subscriber");
        assert_eq!(plain[1] & 0x7F, SUB_PT);
        let ssrc = u32::from_be_bytes([plain[8], plain[9], plain[10], plain[11]]);
        assert_eq!(ssrc, sub.peer.base + 1, "rewritten to the out SSRC");
        assert_eq!(&plain[12..], &[i as u8; 120], "payload intact");
    }
    let stats = plane.stats_when(|s| s.counters.tx_datagrams >= 50);
    assert!(stats.counters.rx_datagrams >= 50);
    plane.handle.shutdown();
}

#[test]
fn media_over_ipv4_loopback() {
    let _serial = serial();
    media_through_the_kernel("127.0.0.1:0", "127.0.0.1");
}

#[test]
fn media_over_ipv6_loopback() {
    let _serial = serial();
    if UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipped: no IPv6 loopback");
        return;
    }
    media_through_the_kernel("[::1]:0", "[::1]");
}

/// A dual-stack shard reports IPv4 peers as V4 (their announced form).
#[test]
fn dual_stack_shard_serves_ipv4_peers() {
    let _serial = serial();
    if UdpSocket::bind("[::]:0").is_err() {
        eprintln!("skipped: no IPv6");
        return;
    }
    media_through_the_kernel("[::]:0", "127.0.0.1");
}

/// Commands reach a parked shard promptly: the waker works.
#[test]
fn commands_wake_a_parked_shard() {
    let _serial = serial();
    let mut plane = start(config("127.0.0.1:0"));
    // Parked by now (busy_poll_rounds = 0); the sweep publishes the count.
    let parked = plane.stats_when(|s| s.counters.parks > 0);
    assert!(parked.counters.parks > 0, "the idle shard parks");
    let mut times: Vec<Duration> = (0..20)
        .map(|i| {
            std::thread::sleep(Duration::from_millis(50));
            plane.command_round_trip(10_000 + i)
        })
        .collect();
    times.sort();
    eprintln!(
        "wake round trips: median {:?}, max {:?}",
        times[10], times[19]
    );
    assert!(times[10] <= Duration::from_millis(10), "{times:?}");
    assert!(times[19] <= Duration::from_millis(100), "{times:?}");
}

/// `shutdown` stops and joins promptly, even from a parked shard, and can
/// be called again.
#[test]
fn shutdown_joins_promptly() {
    let _serial = serial();
    let plane = start(config("127.0.0.1:0"));
    assert!(plane.handle.is_running());
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    plane.handle.shutdown();
    let took = start.elapsed();
    eprintln!("shutdown took {took:?}");
    assert!(took <= Duration::from_millis(100), "{took:?}");
    assert!(!plane.handle.is_running());
    plane.handle.shutdown();
    // Final stats are published on exit.
    assert!(plane.handle.stats(SHARD()).counters.iterations > 0);
}

/// Two concurrent `shutdown` calls both return only once every shard is
/// stopped.
#[test]
fn concurrent_shutdowns_are_safe() {
    let _serial = serial();
    for _ in 0..20 {
        let plane = start(config("127.0.0.1:0"));
        let handle = std::sync::Arc::new(plane.handle);
        let callers: Vec<_> = (0..2)
            .map(|_| {
                let handle = std::sync::Arc::clone(&handle);
                std::thread::spawn(move || {
                    handle.shutdown();
                    assert!(!handle.is_running(), "returned while a shard runs");
                })
            })
            .collect();
        for caller in callers {
            caller.join().expect("no panic in shutdown");
        }
        assert!(!handle.is_running());
    }
}

/// A publisher on shard 0 with track 1 (SSRC 0xAAAA) and one subscriber on
/// each shard of `on`, as the orchestrator will wire it (2.4):
/// `AddRemoteShard` to the publisher's shard, `Subscribe` naming the source
/// to the subscriber's. Returns the publisher and (subscriber, out SSRC).
fn cross_call(plane: &mut Plane, on: &[u8]) -> (Client, Vec<(Client, u32)>) {
    let publisher = Client::new(1, "127.0.0.1:0");
    publisher.connect_to(plane, SHARD(), plane.addr(0));
    let track = TrackId::new(1);
    plane.send(Command::AddTrack {
        id: publisher.peer.id,
        track,
        spec: track_spec(Some(0xAAAA), b"a0"),
    });
    let source = TrackRef {
        shard: SHARD(),
        track,
    };
    let mut subs = Vec::new();
    for (k, &index) in on.iter().enumerate() {
        assert_ne!(index, 0, "subscribers on other shards");
        let shard = ShardId::new(index);
        let mut sub = Client::new(2 + k as u64, "127.0.0.1:0");
        sub.connect_to(plane, shard, plane.addr(index));
        plane.send(Command::AddRemoteShard { track, shard });
        let out = sub.peer.next_out_ssrc();
        plane.send_to(
            shard,
            Command::Subscribe {
                id: sub.peer.id,
                sub: SubscriptionId::new(1 + k as u64),
                track,
                spec: sub_spec_from(out, source),
            },
        );
        plane.command_round_trip_on(shard, 9_000 + k as u64);
        subs.push((sub, out));
    }
    plane.command_round_trip(9_999);
    (publisher, subs)
}

/// Publisher on shard 0, subscriber on shard 1, each shard on its own
/// thread and socket: media, the SR and a PLI cross the mesh, and every
/// loan comes back.
#[test]
fn cross_shard_call_over_real_sockets() {
    let _serial = serial();
    let mut plane = start(config_n("127.0.0.1:0", 2));
    let (mut publisher, mut subs) = cross_call(&mut plane, &[1]);
    let set_up = Instant::now();
    let (sub, out) = &mut subs[0];
    let to = plane.addr(0);
    let mut received = Vec::new();
    for i in 0..50u16 {
        let packet = publisher
            .peer
            .rtp(0xAAAA, 100 + i, 960 * u32::from(i), &[i as u8; 120]);
        publisher.socket.send_to(&packet, to).unwrap();
        received.extend(sub.recv());
    }
    received.extend(std::iter::from_fn(|| sub.recv()));
    assert_eq!(received.len(), 50, "every packet crossed the shards");
    for (i, data) in received.iter().enumerate() {
        let plain = sub.peer.open_rtp(data).expect("decrypts at the subscriber");
        assert_eq!(plain[1] & 0x7F, SUB_PT);
        let ssrc = u32::from_be_bytes([plain[8], plain[9], plain[10], plain[11]]);
        assert_eq!(ssrc, *out, "rewritten on shard 1");
        assert_eq!(&plain[12..], &[i as u8; 120], "payload intact");
    }

    // SR: translated on shard 1 with shard 1's counters (50 packets, 6,000
    // bytes), not the publisher's.
    let ntp = 0xDEAD_BEEF_0000_0001u64;
    let sr = publisher
        .peer
        .rtcp(&sender_report(0xAAAA, ntp, 5_000, 77, 9_999));
    publisher.socket.send_to(&sr, to).unwrap();
    let data = sub.recv().expect("translated SR");
    let plain = sub
        .peer
        .open_rtcp(&data)
        .expect("subscriber decrypts SRTCP");
    let report = nexus_media::rtcp::SenderReport::parse(&plain).expect("an SR");
    assert_eq!(report.ssrc, *out);
    assert_eq!(report.ntp_timestamp, ntp);
    assert_eq!((report.packet_count, report.octet_count), (50, 6_000));
    let sdes = &plain[28..];
    assert_eq!(&sdes[10..10 + sdes[9] as usize], b"publisher-cname");

    // PLI: the setup's keyframe requests (AddRemoteShard's, and shard 1's
    // on subscribe, deferred by the throttle) are out within ≈ 1.5 s; wait
    // until the throttle window after them has ended too.
    std::thread::sleep(Duration::from_millis(2_500).saturating_sub(set_up.elapsed()));
    while publisher.recv().is_some() {}
    let own = 0x5151_5151;
    let request = sub.peer.rtcp(&pli(own, *out));
    let sent = Instant::now();
    sub.socket.send_to(&request, plane.addr(1)).unwrap();
    let data = publisher.recv().expect("PLI at the publisher");
    let took = sent.elapsed();
    let plain = publisher.peer.open_rtcp(&data).expect("publisher decrypts");
    let forwarded = nexus_media::rtcp::PliPacket::parse(&plain).expect("a PLI");
    assert_eq!(
        (forwarded.sender_ssrc, forwarded.media_ssrc),
        (publisher.peer.base, 0xAAAA)
    );
    assert!(took <= Duration::from_millis(100), "PLI took {took:?}");

    // Stats are published once a second: wait for a snapshot taken after
    // the last hand-off.
    let a = plane.stats_on(SHARD(), |s| {
        s.counters.xs_returned >= 50 && s.gauges.xs_in_flight == 0
    });
    let b = plane.stats_on(ShardId::new(1), |s| s.counters.sr_translated > 0);
    // 50 hand-offs and the SR (`xs_tx` counts every message).
    assert_eq!(a.counters.xs_tx, 51);
    assert_eq!(a.counters.xs_returned, 50, "every loan returned");
    assert_eq!(a.gauges.xs_in_flight, 0);
    assert_eq!(b.counters.xs_rx, 51);
    assert_eq!(b.gauges.mirrors, 1);
    assert_eq!(b.counters.sr_translated, 1);
}

/// Parked shards are woken by a peer's hand-off: shards 1-3 have nothing on
/// their sockets, so only shard 0's wake (after it lends them the packet)
/// ends their park, which would otherwise last until housekeeping (≤ 1 s).
/// The first test of `wake_peers` and of the runner's `xs_pending` check.
/// The median shows the wake works; the max only has to stay below the 1 s
/// park timeout (a loaded CI host can deschedule a thread for a while).
#[test]
fn parked_shards_wake_for_a_peer() {
    const WAKE_BOUND: Duration = Duration::from_millis(500);
    let _serial = serial();
    let mut plane = start(config_n("127.0.0.1:0", 4));
    let (mut publisher, mut subs) = cross_call(&mut plane, &[1, 2, 3]);
    for index in 0..4 {
        let parked = plane.stats_on(ShardId::new(index), |s| s.counters.parks > 0);
        assert!(parked.counters.parks > 0, "shard {index} parks when idle");
    }
    for (sub, _) in &subs {
        sub.socket.set_read_timeout(Some(WAKE_BOUND)).unwrap();
    }
    let to = plane.addr(0);
    let mut times: Vec<Duration> = (0..20u16)
        .map(|i| {
            std::thread::sleep(Duration::from_millis(50));
            let packet = publisher
                .peer
                .rtp(0xAAAA, i, 960 * u32::from(i), &[i as u8; 100]);
            let sent = Instant::now();
            publisher.socket.send_to(&packet, to).unwrap();
            // Until the last of the three has it.
            for (sub, _) in &mut subs {
                let data = sub.recv().expect("woken in time");
                let plain = sub.peer.open_rtp(&data).expect("decrypts");
                assert_eq!(&plain[12..], &[i as u8; 100]);
            }
            sent.elapsed()
        })
        .collect();
    times.sort();
    eprintln!(
        "peer wake, 3 parked shards: median {:?}, max {:?}",
        times[10], times[19]
    );
    assert!(times[10] <= Duration::from_millis(10), "{times:?}");
    assert!(times[19] <= WAKE_BOUND, "{times:?}");
    // The loans came back to shard 0 (its wake by the peers).
    // A snapshot taken after the last round (published once a second).
    let a = plane.stats_on(SHARD(), |s| {
        s.counters.xs_returned >= 60 && s.gauges.xs_in_flight == 0
    });
    assert_eq!(
        a.counters.xs_tx, 60,
        "20 packets × 3 shards, no other message"
    );
    assert_eq!(a.counters.xs_returned, 60);
}

/// `shutdown` stops and joins every shard promptly (well under a second;
/// sub-millisecond on an idle host).
#[test]
fn shutdown_joins_every_shard() {
    let _serial = serial();
    let plane = start(config_n("127.0.0.1:0", 4));
    assert!(plane.handle.is_running());
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    plane.handle.shutdown();
    let took = start.elapsed();
    eprintln!("shutdown of 4 shards took {took:?}");
    assert!(took <= Duration::from_secs(1), "{took:?}");
    assert!(!plane.handle.is_running());
    plane.handle.shutdown();
    for index in 0..4 {
        let stats = plane.handle.stats(ShardId::new(index));
        assert!(stats.counters.iterations > 0, "shard {index} ran");
    }
}

/// Shard 1's port is taken: the start fails before any thread runs, and
/// shard 0's socket is released.
#[test]
fn a_failed_bind_starts_no_thread() {
    let _serial = serial();
    let base = {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let Some(next) = base.checked_add(1) else {
        eprintln!("skipped: no port above {base}");
        return;
    };
    let Ok(_taken) = UdpSocket::bind(("127.0.0.1", next)) else {
        eprintln!("skipped: port {next} in use");
        return;
    };
    let config = config_n(&format!("127.0.0.1:{base}"), 2);
    match nexus_dataplane::Dataplane::start(config) {
        Err(DataplaneError::Socket { addr, .. }) => assert_eq!(addr.port(), next),
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("started with shard 1's port taken"),
    }
    UdpSocket::bind(("127.0.0.1", base)).expect("shard 0's socket was released");
}

/// A burst to 5 subscribers: a receive batch of more than 51 packets fans
/// out to more than `SEND_BATCH` datagrams and flushes mid-batch (proved
/// deterministically on `MemIo` in `tests/shard.rs`); nothing is lost or
/// blocked.
#[test]
fn burst_larger_than_the_send_batch() {
    let _serial = serial();
    let mut plane = start(config("127.0.0.1:0"));
    let to = plane.info.local_addr;
    let (mut publisher, mut subs) = call(&mut plane, to, "127.0.0.1:0", 5);
    for sub in &subs {
        sub.socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    // Baseline after a sweep: STUN answers and the PLIs on subscribe also
    // count as sent.
    std::thread::sleep(Duration::from_millis(1_100));
    let before = plane.handle.stats(SHARD()).counters;
    let out = |c: &nexus_dataplane::ShardCounters| c.tx_datagrams + c.drop_send_failed;
    // 150 in, 750 out.
    let packets: Vec<Vec<u8>> = (0..150u16)
        .map(|i| publisher.peer.rtp(0xAAAA, i, 960 * u32::from(i), &[1; 100]))
        .collect();
    for packet in &packets {
        publisher.socket.send_to(packet, to).unwrap();
    }
    let stats = plane.stats_when(|s| out(&s.counters) >= out(&before) + 750);
    assert_eq!(out(&stats.counters) - out(&before), 750);
    let flushes = stats.counters.tx_full_flushes - before.tx_full_flushes;
    eprintln!("mid-batch flushes during the burst: {flushes}");
    assert_eq!(stats.counters.rx_datagrams - before.rx_datagrams, 150);
    for sub in &mut subs {
        let got: Vec<Vec<u8>> = std::iter::from_fn(|| sub.recv()).collect();
        assert!(!got.is_empty());
        assert!(got.iter().all(|d| sub.peer.open_rtp(d).is_some()));
    }
    assert!(plane.handle.is_running());
}

/// Oversized datagrams (dropped as truncated) are work, not idleness: the
/// shard drains a flood of 3,000-byte datagrams well under a second, then
/// media flows. Media is never sent into a still-full socket buffer (the
/// kernel would drop it); the pacing itself is measured deterministically
/// in `runner.rs`.
#[test]
fn media_arrives_after_an_oversized_flood() {
    let _serial = serial();
    let mut plane = start(config("127.0.0.1:0"));
    let to = plane.info.local_addr;
    let (mut publisher, mut subs) = call(&mut plane, to, "127.0.0.1:0", 1);
    let flooder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let oversized = [0x80u8; 3_000];
    for _ in 0..2_000 {
        let _ = flooder.send_to(&oversized, to);
    }
    let drained = publisher.wait_drained(to);
    eprintln!("oversized flood drained in {drained:?}");
    assert!(drained < Duration::from_millis(500), "{drained:?}");

    for i in 0..20u16 {
        let payload = [7; 80];
        let packet = publisher
            .peer
            .rtp(0xAAAA, 500 + i, 960 * u32::from(i), &payload);
        publisher.socket.send_to(&packet, to).unwrap();
    }
    let sub = &mut subs[0];
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| sub.recv()).take(20).collect();
    assert_eq!(got.len(), 20, "every packet after the drain arrives");
    assert!(got.iter().all(|d| sub.peer.open_rtp(d).is_some()));
    let stats = plane.stats_when(|s| s.counters.rx_truncated > 0);
    assert!(
        stats.counters.rx_truncated > 0,
        "the flood reached the shard"
    );
}

/// A flood beyond the socket buffers drops in the kernel and the shard
/// stays responsive.
#[test]
fn flood_beyond_socket_buffers() {
    let _serial = serial();
    let mut plane = start(DataplaneConfig {
        recv_buffer_bytes: 64 << 10,
        ..config("127.0.0.1:0")
    });
    let to = plane.info.local_addr;
    let flooder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let junk = [0x80u8; 1_200];
    let mut sent = 0u64;
    for _ in 0..20_000 {
        if flooder.send_to(&junk, to).is_ok() {
            sent += 1;
        }
    }
    let took = plane.command_round_trip(20_000);
    assert!(
        took <= Duration::from_millis(100),
        "responsive after a flood: {took:?}"
    );
    let stats = plane.stats_when(|s| s.counters.rx_datagrams > 0);
    assert!(stats.counters.rx_datagrams <= sent);
    assert!(stats.counters.rx_datagrams > 0);
    assert!(plane.handle.is_running());
}

/// An idle shard parks instead of spinning. CPU time on shared CI runners
/// is too noisy to gate on: run with `--ignored`.
#[test]
#[ignore]
fn idle_shard_uses_little_cpu() {
    let _serial = serial();
    let plane = start(config("127.0.0.1:0"));
    std::thread::sleep(Duration::from_millis(100));
    let before = cpu_time();
    std::thread::sleep(Duration::from_secs(1));
    let used = cpu_time() - before;
    eprintln!("idle CPU over 1 s: {used:?}");
    assert!(used < Duration::from_millis(50), "{used:?}");
    drop(plane);
}

/// User + system CPU time of the process.
fn cpu_time() -> Duration {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a live, zeroed `rusage` the call fills.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(rc, 0);
    // SAFETY: zeroed is a valid `rusage`, and the call succeeded.
    let usage = unsafe { usage.assume_init() };
    let micros = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    Duration::from_micros(micros(usage.ru_utime) + micros(usage.ru_stime))
}

/// Linux: the shard socket never has UDP_GRO on (it would coalesce reads
/// beyond a pool buffer).
#[cfg(target_os = "linux")]
#[test]
fn shard_socket_has_gro_off() {
    use std::os::fd::AsRawFd;
    let config = config("127.0.0.1:0");
    let socket = nexus_dataplane::bind_shard_socket(config.bind_addr, &config).unwrap();
    assert!(!nexus_dataplane::udp_gro_enabled(socket.as_raw_fd()).unwrap());
}

/// A buffer size the kernel refuses (macOS: `ENOBUFS` above
/// `kern.ipc.maxsockbuf`; Linux caps it silently) still gives a socket: the
/// request is halved until accepted instead of failing the start.
#[test]
fn oversized_socket_buffers_fall_back() {
    let config = DataplaneConfig {
        recv_buffer_bytes: 1 << 30,
        send_buffer_bytes: 1 << 30,
        ..config("127.0.0.1:0")
    };
    let socket = nexus_dataplane::bind_shard_socket(config.bind_addr, &config)
        .expect("socket with smaller buffers");
    assert!(socket.local_addr().is_ok());
}
