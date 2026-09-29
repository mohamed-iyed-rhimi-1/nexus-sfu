//! Fixed memory per participant (design §3.11, note §17.8), on the Phase 1 path.
//! The budget covers session state only (data plane + control plane); signaling is
//! measured and reported apart (`memory/signaling.rs`).
//!
//! Rooms of `ROOM_SIZE` participants; each publishes audio + video and subscribes to
//! the other participants' tracks: "A+V publisher subscribed to 10 tracks" for
//! everyone. All rooms of a run are measured together and divided by the
//! participant count, because the shard's slabs and id maps grow by doubling (one
//! participant's delta would mostly be a resize). Two runs (`ROOM_COUNTS`) bracket a
//! doubling point; the larger result is checked.
//!
//! Both planes run on the bench thread, with no runtime and no threads:
//! - the data plane is a shard on `MemIo`, driven with `iterate`;
//! - the control plane is the real `SessionOrchestrator`, fed signaling messages
//!   (fake clients: answers are rewritten offers) and the shard's events, its
//!   commands going straight into the shard's queue. Each client runs a real DTLS
//!   handshake with an OpenSSL peer, then authenticated SRTCP, so the transport
//!   entry is measured after `free_ssl`, as in a call.
//!
//! Memory is counted by a global allocator that tags each allocation with the plane
//! that made it (the bench sets the tag around its calls into each plane) and
//! counts live bytes per tag. A plane's figure is what it allocated and still holds.
//! The control plane's entries in maps pre-sized before the baseline are invisible
//! to that count and are added to the checked figure from `size_of`. Fixed
//! per-shard, per-orchestrator and per-room state is built before the baseline and
//! reported apart; the signaling channels are warmed up before it.
//!
//! OpenSSL allocates with C `malloc`, which the counter does not see: the `Ssl`
//! figures and the allocator overhead come from the process malloc statistics minus
//! what the Rust counter explains, and are printed, not checked.
//!
//! Run with: `cargo bench --bench memory`. `NEXUS_MEM_BUDGET_KB=<n>` fails the run if
//! the checked figure ("+ subscribed to 10 tracks", both planes, pre-sized entries,
//! larger of the runs) exceeds `n` KB per participant.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use nexus_dataplane::{
    Command, CommandQueueFull, Event, MemIo, Shard, ShardConfig, ShardId, ShardLoad, SingleShard,
};
use nexus_sfu::nexus_api::auth::Claims;
use nexus_sfu::orchestrator::negotiation::NegotiationState;
use nexus_sfu::orchestrator::plane::CommandSink;
use nexus_sfu::orchestrator::subscription::SubscriptionState;
use nexus_sfu::orchestrator::transports::TransportEntry;
use nexus_sfu::orchestrator::{ParticipantHandle, SessionOrchestrator};
use nexus_sfu::signal::{OrchestratorEvent, SignalMessage};
use nexus_state::{DistributedState, DistributedStateConfig};
use nexus_transport::dtls::{DtlsCertificate, DtlsRole, OpenSslDtlsEngine};
use nexus_transport::srtp::{KeyMaterial, SrtpContext, SrtpInbound, SrtpOutbound, SrtpPolicy};
use tokio::sync::mpsc;

#[path = "memory/signaling.rs"]
mod signaling;
#[path = "../crates/nexus-dataplane/tests/support/mod.rs"]
mod support;

/// Participants per room: each subscribes to the other `ROOM_SIZE - 1` A+V pairs.
const ROOM_SIZE: usize = 6;
/// Room counts measured, each in its own run: 10 rooms fill the shard's slabs to
/// just under a power of two (60 sessions in 64 slots), 11 go past it (66 in 128),
/// so the two bracket the doubling. The budget is checked on the larger result.
const ROOM_COUNTS: [usize; 2] = [10, 11];
/// Tracks each participant subscribes to: the §3.11 scenario.
const SUBSCRIBED_TRACKS: usize = 2 * (ROOM_SIZE - 1);
/// The participant that creates the rooms before the baseline (never joins one).
const ADMIN: u64 = 1_000_000;
/// Messages pushed through each signaling channel before the baseline, so its
/// blocks exist already (tokio allocates a block per 32 messages in flight and
/// reuses them once read).
const CHANNEL_WARMUP: usize = 96;

// =============================================================================
// Counting allocator: live bytes per plane
// =============================================================================

/// Who made an allocation. `Other` is the bench and its fake clients; `Signaling`
/// the WebSocket server thread (`signaling.rs`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Other = 0,
    Data = 1,
    Control = 2,
    Signaling = 3,
}

/// Bytes before each allocation, holding its tag (≥ 16 keeps 16-byte alignment).
const HEADER: usize = 16;

static LIVE: [AtomicIsize; 4] = [
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
];
/// Live blocks per tag.
static BLOCKS: [AtomicIsize; 4] = [
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
];
/// Bytes obtained from the system allocator, headers included (every tag).
static TOTAL: AtomicIsize = AtomicIsize::new(0);
/// Highest `LIVE[Control]` since the last `reset_peak`.
static CONTROL_PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static TAG: Cell<Tag> = const { Cell::new(Tag::Other) };
}

fn current_tag() -> Tag {
    // try_with: the allocator can run while thread-locals are torn down.
    TAG.try_with(Cell::get).unwrap_or(Tag::Other)
}

/// Runs `f` with allocations tagged `tag`.
fn tagged<T>(tag: Tag, f: impl FnOnce() -> T) -> T {
    let previous = TAG.with(|t| t.replace(tag));
    let out = f();
    TAG.with(|t| t.set(previous));
    out
}

struct Tagging;

impl Tagging {
    /// The outer layout (header + value) and the header length for `layout`.
    fn outer(layout: Layout) -> Option<(Layout, usize)> {
        let header = HEADER.max(layout.align());
        let outer = Layout::from_size_align(layout.size() + header, header).ok()?;
        Some((outer, header))
    }

    unsafe fn allocate(&self, layout: Layout, zeroed: bool) -> *mut u8 {
        let Some((outer, header)) = Self::outer(layout) else {
            return std::ptr::null_mut();
        };
        let base = if zeroed {
            System.alloc_zeroed(outer)
        } else {
            System.alloc(outer)
        };
        if base.is_null() {
            return base;
        }
        let tag = current_tag();
        let ptr = base.add(header);
        // SAFETY: `header` ≥ 16 bytes precede `ptr` inside the block, and `ptr` is
        // at least 16-aligned, so `ptr - 8` is 8-aligned and in bounds.
        (ptr.sub(8) as *mut u64).write(tag as u64);
        let size = layout.size() as isize;
        BLOCKS[tag as usize].fetch_add(1, Ordering::Relaxed);
        let live = LIVE[tag as usize].fetch_add(size, Ordering::Relaxed) + size;
        if tag == Tag::Control {
            CONTROL_PEAK.fetch_max(live, Ordering::Relaxed);
        }
        TOTAL.fetch_add(outer.size() as isize, Ordering::Relaxed);
        ptr
    }
}

// SAFETY: every block comes from `System` with a header in front; `dealloc` finds
// the block start with the same `outer` computation and frees it with the same
// layout. `realloc` is the trait's default (allocate, copy, free) on these methods.
unsafe impl GlobalAlloc for Tagging {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout, false)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout, true)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let (outer, header) = Self::outer(layout).expect("layout was valid at allocation");
        let tag = (ptr.sub(8) as *const u64).read() as usize;
        LIVE[tag].fetch_sub(layout.size() as isize, Ordering::Relaxed);
        BLOCKS[tag].fetch_sub(1, Ordering::Relaxed);
        TOTAL.fetch_sub(outer.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr.sub(header), outer)
    }
}

#[global_allocator]
static GLOBAL: Tagging = Tagging;

fn reset_peak() {
    CONTROL_PEAK.store(
        LIVE[Tag::Control as usize].load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
}

// =============================================================================
// Samples
// =============================================================================

/// Counters at one point of the run.
#[derive(Clone, Copy)]
struct Sample {
    data: isize,
    control: isize,
    /// Live blocks made by the data and control planes.
    blocks: isize,
    total: isize,
    malloc: Option<isize>,
}

fn sample() -> Sample {
    let live = |tag: Tag| LIVE[tag as usize].load(Ordering::Relaxed);
    let blocks = |tag: Tag| BLOCKS[tag as usize].load(Ordering::Relaxed);
    Sample {
        data: live(Tag::Data),
        control: live(Tag::Control),
        blocks: blocks(Tag::Data) + blocks(Tag::Control),
        total: TOTAL.load(Ordering::Relaxed),
        malloc: malloc_in_use(),
    }
}

impl Sample {
    /// Per-participant (data, control) growth since `base`, over `n` participants.
    fn per_participant(&self, base: &Sample, n: usize) -> (f64, f64) {
        assert!(n > 0);
        (
            (self.data - base.data) as f64 / n as f64,
            (self.control - base.control) as f64 / n as f64,
        )
    }

    /// Per-participant malloc growth since `base` that the Rust counter (requested
    /// bytes plus the bench's headers, every tag) does not explain: allocator
    /// rounding and per-block overhead, plus whatever OpenSSL holds.
    fn residual_per_participant(&self, base: &Sample, n: usize) -> Option<f64> {
        assert!(n > 0);
        let malloc = self.malloc? - base.malloc?;
        Some((malloc - (self.total - base.total)) as f64 / n as f64)
    }
}

/// Bytes the process allocator has handed out, all threads (OpenSSL included).
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
    // SAFETY: a null zone asks for statistics over all zones; the struct layout
    // matches <malloc/malloc.h>.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    Some(stats.size_in_use as isize)
}

#[cfg(target_os = "linux")]
fn malloc_in_use() -> Option<isize> {
    // SAFETY: mallinfo2 has no preconditions and returns a plain struct. It misses
    // mmap'd chunks (large blocks), which OpenSSL's per-session state is not.
    let info = unsafe { libc::mallinfo2() };
    Some(info.uordblks as isize)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn malloc_in_use() -> Option<isize> {
    None
}

// =============================================================================
// Fake clients
// =============================================================================

/// The orchestrator's commands go straight into the shard's queue.
struct QueueSink {
    push: Box<dyn Fn(Command) -> Result<(), Command> + Send + Sync>,
}

impl CommandSink for QueueSink {
    fn send(&self, _shard: ShardId, command: Command) -> Result<(), CommandQueueFull> {
        (self.push)(command).map_err(|_| CommandQueueFull)
    }

    fn loads(&self) -> Vec<ShardLoad> {
        vec![ShardLoad::default()]
    }

    fn shard_count(&self) -> usize {
        1
    }
}

/// A participant's browser, reduced to what the SFU sees of it.
struct Client {
    id: u64,
    room: u64,
    addr: SocketAddr,
    tx: Option<mpsc::Sender<SignalMessage>>,
    rx: mpsc::Receiver<SignalMessage>,
    /// The last offer, not yet answered.
    offer: Option<String>,
    /// Track ids of the other participants in the room.
    others: Vec<u64>,
    /// The DTLS peer (client role), until the handshake is done.
    dtls: Option<OpenSslDtlsEngine>,
    /// The peer's SRTP (it writes with the DTLS client key).
    srtp: Option<SrtpContext>,
}

impl Client {
    fn new(index: usize) -> Self {
        let (tx, mut rx) = mpsc::channel(1_024);
        // Warm the channel up: its blocks are signaling state, allocated here.
        for _ in 0..CHANNEL_WARMUP {
            tx.try_send(SignalMessage::Pong)
                .expect("room in the channel");
            assert!(rx.try_recv().is_ok());
        }
        Self {
            id: index as u64 + 1,
            room: (index / ROOM_SIZE) as u64 + 1,
            addr: SocketAddr::from(([10, 0, (index / 200) as u8, (index % 200) as u8 + 1], 5_000)),
            tx: Some(tx),
            rx,
            offer: None,
            others: Vec::with_capacity(SUBSCRIBED_TRACKS),
            dtls: None,
            srtp: None,
        }
    }

    /// Reads what the SFU sent: offers, the room's tracks. Any error fails the run.
    /// The messages were allocated by the orchestrator (control tag): the client
    /// keeps its own copy and drops them, or the bench's state would count as the
    /// control plane's.
    fn read(&mut self) {
        while let Ok(message) = self.rx.try_recv() {
            match message {
                SignalMessage::Offer { sdp, .. } => self.offer = Some(sdp.as_str().to_owned()),
                SignalMessage::TrackPublished {
                    publisher_id,
                    track_id,
                    ..
                } if publisher_id != self.id => self.others.push(track_id),
                SignalMessage::Error { code, message } => {
                    panic!("participant {}: {code}: {message}", self.id)
                }
                _ => {}
            }
        }
    }

    /// The local ICE credentials in the offer.
    fn ice(&self) -> ([u8; 16], [u8; 32]) {
        let offer = self.offer.as_deref().expect("an offer");
        let find = |key: &str| {
            offer
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .expect("ICE credentials in the offer")
                .as_bytes()
                .to_vec()
        };
        let ufrag: [u8; 16] = find("a=ice-ufrag:").try_into().expect("16-byte ufrag");
        let pwd: [u8; 32] = find("a=ice-pwd:").try_into().expect("32-byte password");
        (ufrag, pwd)
    }
}

/// `AB:CD:…` of a SHA-256 fingerprint.
fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    let hex: Vec<String> = fingerprint.iter().map(|b| format!("{b:02X}")).collect();
    hex.join(":")
}

/// An answer to `offer`, as a browser gives it: directions flipped, `setup:active`
/// (the SFU is the DTLS server), the peer's fingerprint, no ice-lite, and an
/// `a=ssrc` per publish m-line (`ssrc_base + index`).
fn answer_for(offer: &str, ssrc_base: u32, fingerprint: &str) -> String {
    let mut out = String::new();
    let mut sections = offer.split("\r\nm=");
    for line in sections.next().expect("session section").lines() {
        match line {
            "a=ice-lite" => {}
            "a=setup:actpass" => out.push_str("a=setup:active\r\n"),
            l if l.starts_with("a=fingerprint:") => {
                out.push_str(&format!("a=fingerprint:sha-256 {fingerprint}\r\n"))
            }
            l => out.push_str(&format!("{l}\r\n")),
        }
    }
    for (index, section) in sections.enumerate() {
        let publish = section.lines().any(|l| l == "a=recvonly");
        for (n, line) in section.lines().enumerate() {
            let line = match line {
                _ if n == 0 => format!("m={line}"),
                "a=recvonly" => "a=sendonly".to_string(),
                "a=sendonly" => "a=recvonly".to_string(),
                "a=setup:actpass" => "a=setup:active".to_string(),
                l if l.starts_with("a=fingerprint:") => {
                    format!("a=fingerprint:sha-256 {fingerprint}")
                }
                l if l.starts_with("a=ssrc:") || l.starts_with("a=msid:") => continue,
                l => l.to_string(),
            };
            out.push_str(&format!("{line}\r\n"));
        }
        if publish {
            let ssrc = ssrc_base + index as u32;
            out.push_str(&format!("a=ssrc:{ssrc} cname:peer\r\n"));
        }
    }
    out
}

/// Whole DTLS records of `buf`, one per datagram (as browsers send a flight).
fn records(mut buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // Each pass consumes one record header at least.
    while buf.len() >= 13 {
        let len = (13 + u16::from_be_bytes([buf[11], buf[12]]) as usize).min(buf.len());
        out.push(buf[..len].to_vec());
        buf = &buf[len..];
    }
    out
}

// =============================================================================
// The rig: shard, orchestrator, clients
// =============================================================================

struct Rig {
    shard: Shard<MemIo, Vec<Event>>,
    orchestrator: SessionOrchestrator,
    clients: Vec<Client>,
    /// One per room, kept open: a room nobody joined is released with its creator.
    room_admins: Vec<mpsc::Receiver<SignalMessage>>,
    peer_certificate: DtlsCertificate,
    peer_fingerprint: String,
    /// Scratch for the shard's events (pre-sized, bench-owned).
    events: Vec<Event>,
    now: Instant,
}

impl Rig {
    /// Shard, orchestrator and warmed-up clients for `rooms` rooms; the rooms are
    /// created by `create_rooms`. Everything outside the per-participant window.
    fn new(rooms: usize) -> Self {
        let now = Instant::now();
        let config = ShardConfig {
            pool_buffers: 1_024,
            max_sessions: 1_000,
            ..Default::default()
        };
        let shard = tagged(Tag::Data, || {
            let io = MemIo::with_capacity(256, 4_096, 4_096 * 1_500);
            Shard::new(config, io, Vec::with_capacity(4_096), now).expect("shard")
        });
        let queue = shard.command_queue();
        let sink = QueueSink {
            push: Box::new(move |command| queue.push(command)),
        };
        let media: SocketAddr = "192.0.2.1:10000".parse().expect("address");
        let orchestrator = tagged(Tag::Control, || {
            let state = Arc::new(DistributedState::new(DistributedStateConfig::new(1)));
            SessionOrchestrator::new(
                Arc::new(sink),
                vec![vec![media]],
                Box::new(SingleShard),
                DtlsCertificate::generate().expect("certificate"),
                state,
            )
        });
        let peer_certificate = DtlsCertificate::generate().expect("peer certificate");
        let peer_fingerprint = fingerprint_hex(peer_certificate.fingerprint());
        Self {
            shard,
            orchestrator,
            clients: (0..rooms * ROOM_SIZE).map(Client::new).collect(),
            room_admins: Vec::new(),
            peer_certificate,
            peer_fingerprint,
            events: Vec::with_capacity(4_096),
            now,
        }
    }

    /// The rooms, each created by its own admin connection that never joins one
    /// (a connection may create `MAX_ROOMS_PER_CREATOR` rooms). The admins'
    /// connections are scaffolding, untagged; the `Create` is counted as before.
    fn create_rooms(&mut self) {
        let rooms = self.clients.len() / ROOM_SIZE;
        for room in 1..=rooms as u64 {
            let admin = ADMIN + room;
            let (admin_tx, admin_rx) = mpsc::channel(16);
            self.orchestrator
                .handle_signal(OrchestratorEvent::Connected {
                    participant_id: admin,
                    outbound_tx: admin_tx,
                    claims: any_room(),
                });
            let event = OrchestratorEvent::Message {
                participant_id: admin,
                message: SignalMessage::Create { room_name: None },
            };
            tagged(Tag::Control, || self.orchestrator.handle_signal(event));
            let mut admin_rx = admin_rx;
            let created = admin_rx.try_recv();
            self.room_admins.push(admin_rx);
            match created {
                Ok(SignalMessage::Created { room_id, .. }) => assert_eq!(room_id, room),
                other => panic!("room {room} not created: {other:?}"),
            }
        }
    }

    /// Runs the shard and hands its events to the orchestrator until both are idle.
    fn pump(&mut self) {
        for _ in 0..1_000 {
            for _ in 0..1_000 {
                let stats = tagged(Tag::Data, || self.shard.iterate(self.now));
                if stats.commands == 0 && stats.received == 0 && self.shard.io().inbound_len() == 0
                {
                    break;
                }
            }
            self.events.append(self.shard.events_mut());
            if self.events.is_empty() {
                return;
            }
            for event in self.events.drain(..) {
                tagged(Tag::Control, || self.orchestrator.handle_dataplane(event));
            }
        }
        panic!("shard and orchestrator did not settle");
    }

    /// A signaling message from client `index`; then the shard runs and every client
    /// reads what it was sent.
    fn signal(&mut self, index: usize, message: SignalMessage) {
        let participant_id = self.clients[index].id;
        let event = OrchestratorEvent::Message {
            participant_id,
            message,
        };
        tagged(Tag::Control, || self.orchestrator.handle_signal(event));
        self.pump();
        self.shard.io_mut().clear_outbound();
        for client in &mut self.clients {
            client.read();
        }
    }

    /// Client `index` answers its pending offer.
    fn answer(&mut self, index: usize) {
        let client = &mut self.clients[index];
        let offer = client.offer.take().expect("an offer to answer");
        let sdp = answer_for(&offer, 10_000 * client.id as u32, &self.peer_fingerprint);
        client.offer = Some(offer);
        self.signal(index, SignalMessage::Answer { sdp });
    }

    fn connect_and_join(&mut self, index: usize) {
        let client = &mut self.clients[index];
        let event = OrchestratorEvent::Connected {
            participant_id: client.id,
            outbound_tx: client.tx.take().expect("connects once"),
            claims: any_room(),
        };
        let room_id = client.room;
        tagged(Tag::Control, || self.orchestrator.handle_signal(event));
        let participant_name = format!("p{}", self.clients[index].id);
        self.signal(
            index,
            SignalMessage::Join {
                room_id,
                participant_name,
            },
        );
    }

    fn publish(&mut self, index: usize) {
        let message = SignalMessage::Publish {
            kinds: vec!["audio".into(), "video".into()],
            contents: vec!["audio".into(), "camera".into()],
        };
        self.signal(index, message);
        self.answer(index);
    }

    /// The client's nominating binding request reaches the shard.
    fn nominate(&mut self, index: usize) {
        let (ufrag, pwd) = self.clients[index].ice();
        let addr = self.clients[index].addr;
        let request = support::binding_request(&ufrag, &pwd, true);
        self.shard.io_mut().push_inbound(addr, request);
        self.pump();
        self.shard.io_mut().clear_outbound();
    }
}

// =============================================================================
// DTLS and SRTP
// =============================================================================

impl Rig {
    /// A DTLS handshake between client `index` (client role) and the SFU, through the
    /// shard's DTLS datagrams and the orchestrator's `SendDatagram` commands.
    fn handshake(&mut self, index: usize) {
        let addr = self.clients[index].addr;
        let mut peer =
            OpenSslDtlsEngine::with_certificate(DtlsRole::Client, &self.peer_certificate);
        let mut to_sfu = records(&peer.start_handshake().expect("ClientHello"));
        // A DTLS 1.2 handshake is two round trips; bounded well above that.
        for _ in 0..16 {
            for datagram in to_sfu.drain(..) {
                self.shard.io_mut().push_inbound(addr, datagram);
            }
            self.pump();
            let to_peer: Vec<Vec<u8>> = self
                .shard
                .io_mut()
                .take_outbound()
                .into_iter()
                .filter(|(to, bytes)| *to == addr && (20..=63).contains(&bytes[0]))
                .map(|(_, bytes)| bytes)
                .collect();
            if to_peer.is_empty() {
                break;
            }
            for datagram in to_peer {
                let reply = peer.process(&datagram).expect("peer DTLS");
                to_sfu.extend(records(&reply));
            }
        }
        assert!(
            peer.is_established(),
            "participant {index}: DTLS not established"
        );
        let keys = peer.srtp_keys().expect("SRTP keys");
        let material = [keys.client_key(), keys.client_salt()].concat();
        let profile = keys.profile.protection_profile();
        let key = KeyMaterial::from_dtls_export(&material, profile).expect("key material");
        let policy = SrtpPolicy {
            profile,
            ..SrtpPolicy::default()
        };
        let client = &mut self.clients[index];
        client.srtp = Some(SrtpContext::new(&key, policy).expect("peer SRTP"));
        client.dtls = Some(peer);
    }

    /// The client's first SRTCP packet: the SFU frees its DTLS state
    /// (`PeerSrtpVerified`).
    fn first_srtcp(&mut self, index: usize) {
        let client = &mut self.clients[index];
        let plain = support::receiver_report(0x7000_0000 + client.id as u32);
        let mut buf = plain.clone();
        buf.resize(plain.len() + 64, 0);
        let srtp = client.srtp.as_mut().expect("handshake done");
        let len = srtp.protect_rtcp(&mut buf, plain.len()).expect("protect");
        buf.truncate(len);
        let addr = client.addr;
        self.shard.io_mut().push_inbound(addr, buf);
        self.pump();
        self.shard.io_mut().clear_outbound();
    }

    /// Client `index` subscribes to every other track in its room and answers.
    fn subscribe(&mut self, index: usize) {
        let track_ids = self.clients[index].others.clone();
        assert_eq!(track_ids.len(), SUBSCRIBED_TRACKS, "tracks seen by {index}");
        self.signal(index, SignalMessage::Subscribe { track_ids });
        self.answer(index);
    }
}

// =============================================================================
// Run and report
// =============================================================================

fn kb(bytes: f64) -> String {
    format!("{:8.1} KB", bytes / 1024.0)
}

fn kb_opt(bytes: Option<f64>) -> String {
    bytes.map_or_else(|| format!("{:>11}", "n/a"), kb)
}

/// What one run measured, per participant unless stated.
struct Measured {
    rooms: usize,
    participants: usize,
    no_subs: (f64, f64),
    subscribed: (f64, f64),
    /// Live blocks the two planes made, per participant.
    blocks: f64,
    /// Malloc growth the Rust counter does not explain, per participant.
    residual: Option<f64>,
    engine_rust: f64,
    ssl_during: Option<f64>,
    ssl_after: Option<f64>,
    answer_peak: f64,
    /// Shard, orchestrator (with `DistributedState`), one room: bytes.
    fixed_shard: f64,
    fixed_orchestrator: f64,
    fixed_room: f64,
}

impl Measured {
    fn total(&self) -> f64 {
        self.subscribed.0 + self.subscribed.1
    }
}

/// One measurement with `rooms` rooms of `ROOM_SIZE`.
fn run(rooms: usize) -> Measured {
    let n = rooms * ROOM_SIZE;
    let start = sample();
    let mut rig = Rig::new(rooms);
    let built = sample();
    rig.create_rooms();
    let base = sample();
    let (published, handshaken) = connect_publish_handshake(&mut rig);
    let mut answer_peak = 0f64;
    for i in 0..n {
        let before = LIVE[Tag::Control as usize].load(Ordering::Relaxed);
        reset_peak();
        rig.subscribe(i);
        let peak = CONTROL_PEAK.load(Ordering::Relaxed) - before;
        answer_peak = answer_peak.max(peak as f64);
    }
    let subscribed = sample();
    check(&rig);
    // The SFU's engine exists from the publish answer (its role is fixed there) until
    // `free_ssl`: what the first SRTCP step freed is its size.
    let freed = (handshaken.control - published.control) as f64 / n as f64;
    Measured {
        rooms,
        participants: n,
        no_subs: published.per_participant(&base, n),
        subscribed: subscribed.per_participant(&base, n),
        blocks: (subscribed.blocks - base.blocks) as f64 / n as f64,
        residual: subscribed.residual_per_participant(&base, n),
        engine_rust: freed,
        ssl_during: handshaken.residual_per_participant(&base, n),
        ssl_after: published.residual_per_participant(&base, n),
        answer_peak,
        fixed_shard: (built.data - start.data) as f64,
        fixed_orchestrator: (built.control - start.control) as f64,
        fixed_room: (base.control - built.control) as f64 / rooms as f64,
    }
}

/// Every client joins, publishes, nominates, completes DTLS and sends its first
/// SRTCP. Returns the samples after the SRTCP step (DTLS state freed) and before it.
fn connect_publish_handshake(rig: &mut Rig) -> (Sample, Sample) {
    let n = rig.clients.len();
    for i in 0..n {
        rig.connect_and_join(i);
    }
    for i in 0..n {
        rig.publish(i);
    }
    for i in 0..n {
        rig.nominate(i);
    }
    for i in 0..n {
        rig.handshake(i);
    }
    // The SFU's engines are complete but not freed; the peers' engines go now.
    for client in &mut rig.clients {
        client.dtls = None;
    }
    let handshaken = sample();
    for i in 0..n {
        rig.first_srtcp(i);
    }
    (sample(), handshaken)
}

/// The run did what it claims: every session established, every track and
/// subscription on the shard, no command refused.
fn check(rig: &Rig) {
    let n = rig.clients.len();
    let snapshot = rig.shard.snapshot();
    assert_eq!(snapshot.sessions, n, "{snapshot:?}");
    assert_eq!(snapshot.tracks, 2 * n, "{snapshot:?}");
    assert_eq!(
        snapshot.subscriptions,
        SUBSCRIBED_TRACKS * n,
        "{snapshot:?}"
    );
    let counters = rig.shard.counters();
    assert_eq!(counters.commands_rejected, 0, "{counters:?}");
    assert_eq!(counters.consent_lost, 0);
    let established = rig.orchestrator.established_log().snapshot();
    assert_eq!(established.len(), n);
    assert!(established.iter().all(|e| e.role == DtlsRole::Server));
}

/// Bytes of the control plane's per-participant entries in maps pre-sized before
/// the baseline (capacity 1,024): an allocation delta cannot see them.
fn presized_entries() -> usize {
    std::mem::size_of::<(u64, ParticipantHandle)>()
        + std::mem::size_of::<(u64, NegotiationState)>()
        + std::mem::size_of::<(u64, SubscriptionState)>()
}

fn report_run(m: &Measured) {
    println!(
        "\n{} rooms of {ROOM_SIZE} ({} participants), Rust heap per participant",
        m.rooms, m.participants
    );
    println!("                                          data plane  control plane        total");
    let row = |name: &str, (d, c): (f64, f64)| {
        println!("  {name:<38}{}    {}  {}", kb(d), kb(c), kb(d + c));
    };
    row("A+V publisher, no subscriptions", m.no_subs);
    row("+ subscribed to 10 tracks", m.subscribed);
    // OpenSSL holds the same after `free_ssl` as after subscribing: the rest of the
    // residual is the allocator's rounding and per-block overhead.
    let overhead = m.residual.zip(m.ssl_after).map(|(r, ssl)| r - ssl);
    println!(
        "  malloc residual {} = OpenSSL after free_ssl {} + allocator overhead {} ({:.0} live blocks)",
        kb_opt(m.residual).trim(),
        kb_opt(m.ssl_after).trim(),
        kb_opt(overhead).trim(),
        m.blocks
    );
    println!(
        "  DTLS per session: engine Rust heap freed by free_ssl {}; OpenSSL before free {}, after {}",
        kb(m.engine_rust).trim(),
        kb_opt(m.ssl_during).trim(),
        kb_opt(m.ssl_after).trim()
    );
    println!(
        "  transient: control-plane peak while handling a subscribe + answer {}",
        kb(m.answer_peak).trim()
    );
    println!(
        "  fixed: shard {} (incl. the bench's MemIo capture), orchestrator {}, per room {}",
        kb(m.fixed_shard).trim(),
        kb(m.fixed_orchestrator).trim(),
        kb(m.fixed_room).trim()
    );
}

fn report_structure() {
    println!("\nStructural (size_of; printed, not measured)");
    let srtp = std::mem::size_of::<SrtpInbound>() + std::mem::size_of::<SrtpOutbound>();
    let data = nexus_dataplane::sizes::SESSION
        + srtp
        + 2 * nexus_dataplane::sizes::PUBLISHED_TRACK
        + SUBSCRIBED_TRACKS * nexus_dataplane::sizes::SUBSCRIPTION;
    println!(
        "  data plane: session {} + SRTP in/out {} + 2 tracks × {} + 10 subscriptions × {} = {}",
        nexus_dataplane::sizes::SESSION,
        srtp,
        nexus_dataplane::sizes::PUBLISHED_TRACK,
        nexus_dataplane::sizes::SUBSCRIPTION,
        kb(data as f64).trim()
    );
    println!(
        "  control plane: entries of pre-sized maps {} B (added to the checked figure); transport entry {} B",
        presized_entries(),
        std::mem::size_of::<TransportEntry>()
    );
}

fn main() {
    // Criterion passes `--bench`; there is nothing to parse.
    println!("Memory per participant, Phase 1 path: session state (data + control plane)");
    let runs: Vec<Measured> = ROOM_COUNTS.iter().map(|&rooms| run(rooms)).collect();
    for m in &runs {
        report_run(m);
    }
    report_structure();
    signaling::report(&signaling::measure());
    let worst = runs
        .iter()
        .max_by(|a, b| a.total().total_cmp(&b.total()))
        .expect("at least one run");
    let checked = worst.total() + presized_entries() as f64;
    println!(
        "\nChecked figure: {} ({} rooms) + pre-sized entries {} B = {} per participant",
        kb(worst.total()).trim(),
        worst.rooms,
        presized_entries(),
        kb(checked).trim()
    );
    if let Ok(budget) = std::env::var("NEXUS_MEM_BUDGET_KB") {
        let budget: f64 = budget
            .parse()
            .expect("NEXUS_MEM_BUDGET_KB must be a number");
        let (data, control) = worst.subscribed;
        assert!(
            checked <= budget * 1024.0,
            "\"A+V publisher subscribed to 10 tracks\" uses {:.1} KB per participant \
             (data plane {:.1} KB, control plane {:.1} KB, pre-sized entries {} B, {} rooms); \
             budget {budget} KB",
            checked / 1024.0,
            data / 1024.0,
            control / 1024.0,
            presized_entries(),
            worst.rooms
        );
        println!(
            "Budget: {:.1} KB ≤ {budget} KB per participant (session state only)",
            checked / 1024.0
        );
    }
}

/// Claims whose `rooms` claim is `"*"`: the bench's rooms are unnamed. The grant has
/// no heap (`RoomGrant::Any`); a token naming one room would add its name per
/// connection.
fn any_room() -> Claims {
    Claims {
        sub: "bench".to_string(),
        exp: u64::MAX / 2,
        iat: 0,
        rooms: vec!["*".to_string()],
    }
}
