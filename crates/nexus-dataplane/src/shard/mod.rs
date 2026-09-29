//! The shard: state tables and one loop iteration (note §3.2).
//!
//! `iterate` takes an explicit `now`: tests drive it on `MemIo`, and the
//! shard thread (`runner.rs`) calls it in a loop with parking (`park.rs`)
//! on a real socket (`io.rs`).

mod commands;
mod housekeeping;
mod ingress;
pub mod io;
pub mod park;
mod rtcp;
pub(crate) mod runner;
pub mod stats;
mod xs;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use rustc_hash::FxHashMap;

use crate::command::{Command, Event, EventSink, Refused};
use crate::config::{ConfigError, ShardConfig};
use crate::ice::UFRAG_LEN;
use crate::ids::{SessionId, ShardId, SubscriptionId, TrackId};
use crate::pool::{BufRef, BufferPool, PoolRegion};
use crate::rng::Rng;
use crate::session::{MirrorIdx, Session, SessionIdx, SubIdx, TrackIdx};
use crate::slab::Slab;
use crate::subscription::Subscription;
use crate::track::{MirrorTrack, PublishedTrack};
use crate::xs::XsPorts;
use io::{Datagram, DatagramIo, RecvBatch, RecvResult, SendBatch};
use park::Wake;
use stats::{ShardCounters, ShardStats};

/// Capacity of the command queue (note §5.3).
pub const COMMAND_QUEUE_CAPACITY: usize = 4_096;
/// Most commands handled per iteration.
pub const COMMAND_BUDGET: usize = 64;
/// Events kept for retry while the sink is full (note §5.3).
pub const EVENT_RETENTION: usize = 256;
/// Interval of the housekeeping sweep (note §3.4).
pub const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);
/// Least time between two address switches of a session: a peer
/// alternating addresses cannot flip the session (and emit an event) on
/// every request.
pub const MIN_SWITCH_INTERVAL: Duration = Duration::from_millis(100);
/// How long the previous address stays mapped after a switch, so packets
/// already in flight from it still authenticate.
pub const PREV_ADDR_GRACE: Duration = Duration::from_secs(1);
/// Longest park while retained events or deferred nominations wait: both
/// are retried only by `iterate`.
pub const PARK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// What one iteration did (the shard thread uses it to decide when to park).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IterationStats {
    /// Datagrams received and handled.
    pub received: usize,
    /// Datagrams taken from the socket, including those dropped before
    /// handling (truncated, unreadable source): any of them is work.
    pub taken: usize,
    /// The receive source was drained.
    pub would_block: bool,
    /// Commands handled.
    pub commands: usize,
    /// Cross-shard messages handled and lent buffers released.
    pub cross_shard: usize,
}

/// Table sizes, for tests and stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardSnapshot {
    /// Sessions.
    pub sessions: usize,
    /// Published tracks.
    pub tracks: usize,
    /// Subscriptions.
    pub subscriptions: usize,
    /// Address map entries.
    pub addresses: usize,
    /// Ufrag map entries.
    pub ufrags: usize,
    /// Free pool buffers.
    pub pool_available: usize,
    /// Mirror tracks (tracks of other shards with subscriptions here).
    pub mirrors: usize,
    /// Loans outstanding to peer shards, counted per peer (one buffer lent
    /// to 3 peers counts 3).
    pub xs_in_flight: usize,
}

/// One shard: sessions, tracks, subscriptions and the packet path.
pub struct Shard<I: DatagramIo, S: EventSink> {
    config: ShardConfig,
    epoch: Instant,
    io: I,
    events: S,
    commands: Arc<ArrayQueue<Command>>,
    pool: BufferPool,
    rx: RecvBatch,
    tx: SendBatch,
    sessions: Slab<Session>,
    tracks: Slab<PublishedTrack>,
    subs: Slab<Subscription>,
    mirrors: Slab<MirrorTrack>,
    session_ids: FxHashMap<SessionId, SessionIdx>,
    track_ids: FxHashMap<TrackId, TrackIdx>,
    sub_ids: FxHashMap<SubscriptionId, SubIdx>,
    mirror_ids: FxHashMap<TrackId, MirrorIdx>,
    /// Only addresses that passed STUN authentication (note §7.1).
    by_addr: FxHashMap<SocketAddr, SessionIdx>,
    by_ufrag: FxHashMap<[u8; UFRAG_LEN], SessionIdx>,
    rng: Rng,
    counters: ShardCounters,
    stats: Arc<ShardStats>,
    /// Sessions with a pending nomination (capacity `max_sessions`).
    pending_switches: Vec<SessionIdx>,
    /// Events the sink refused, retried every iteration; never grows.
    pending: VecDeque<Event>,
    next_housekeeping: Instant,
    /// DTLS datagrams all sessions may still pass before the next sweep.
    dtls_budget: u32,
    /// `rx_datagrams` and time at the last sweep, for the `rx_pps` gauge.
    last_sweep: (u64, Instant),
    /// Datagrams per second over the last sweep interval.
    rx_pps: u64,
    /// This shard's ends of the cross-shard queues (plan 2.2); `None` until
    /// attached, and while `drain_cross_shard` holds them.
    xs: Option<XsPorts>,
    /// Wakes of the peer shards, by shard index (empty on `MemIo`).
    peer_wakes: Box<[Wake]>,
    /// Peers to wake at the end of the iteration (bit i: shard i): pushed
    /// media, or loans given back to them.
    wake_mask: u64,
}

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// A shard with empty tables; `now` is its clock's epoch.
    pub fn new(config: ShardConfig, io: I, events: S, now: Instant) -> Result<Self, ConfigError> {
        config.validate()?;
        // Selected plus previous address per session: the map never grows
        // on the packet path.
        let addresses = 2 * config.max_sessions as usize;
        Ok(Self {
            epoch: now,
            io,
            events,
            commands: Arc::new(ArrayQueue::new(COMMAND_QUEUE_CAPACITY)),
            pool: BufferPool::new(config.shard, config.pool_buffers),
            rx: RecvBatch::new(),
            tx: SendBatch::new(),
            sessions: Slab::new(),
            tracks: Slab::new(),
            subs: Slab::new(),
            mirrors: Slab::new(),
            session_ids: FxHashMap::default(),
            track_ids: FxHashMap::default(),
            sub_ids: FxHashMap::default(),
            mirror_ids: FxHashMap::default(),
            by_addr: FxHashMap::with_capacity_and_hasher(addresses, Default::default()),
            by_ufrag: FxHashMap::default(),
            rng: Rng::new(config.rng_seed),
            counters: ShardCounters::default(),
            stats: Arc::new(ShardStats::default()),
            pending_switches: Vec::with_capacity(config.max_sessions as usize),
            pending: VecDeque::with_capacity(EVENT_RETENTION),
            next_housekeeping: now + HOUSEKEEPING_INTERVAL,
            dtls_budget: config.dtls_budget_per_sweep,
            last_sweep: (0, now),
            rx_pps: 0,
            xs: None,
            peer_wakes: Box::new([]),
            wake_mask: 0,
            config,
        })
    }

    /// The command queue, for producers.
    pub fn command_queue(&self) -> Arc<ArrayQueue<Command>> {
        Arc::clone(&self.commands)
    }

    /// Queues a command; gives it back when the queue is full.
    pub fn push_command(&self, command: Command) -> Result<(), Command> {
        self.commands.push(command)
    }

    /// The pool region peers read this shard's loans from (startup: the
    /// mesh is built from every shard's region).
    pub fn pool_region(&self) -> Arc<PoolRegion> {
        self.pool.region()
    }

    /// Connects the shard to its peers (startup, once, before `iterate`
    /// hands anything off).
    pub fn attach_xs(&mut self, ports: XsPorts) {
        assert!(ports.shard() == self.config.shard, "ports of another shard");
        assert!(self.xs.is_none(), "cross-shard ports attached twice");
        self.xs = Some(ports);
    }

    /// The peers' wakes, indexed by shard index (this shard's own is never
    /// used). Startup, once, after `attach_xs`.
    pub fn attach_peer_wakes(&mut self, wakes: Vec<Wake>) {
        assert!(self.peer_wakes.is_empty(), "peer wakes attached twice");
        assert!(wakes.len() <= crate::ids::MAX_SHARDS);
        self.peer_wakes = wakes.into_boxed_slice();
    }

    /// The shard's id.
    pub fn id(&self) -> ShardId {
        self.config.shard
    }

    /// Published counters and gauges (updated by housekeeping).
    pub fn stats(&self) -> Arc<ShardStats> {
        Arc::clone(&self.stats)
    }

    /// One loop iteration without parking (note §3.2): receive and handle a
    /// batch, flush sends, handle up to `COMMAND_BUDGET` commands, flush
    /// again, retry retained events, run housekeeping when due.
    pub fn iterate(&mut self, now: Instant) -> IterationStats {
        self.counters.iterations += 1;
        // Returns first: credit peers freed is there for this batch.
        let returned = self.drain_returns();
        // A receive error counts as an empty batch.
        let received = match self.io.recv_batch(&mut self.rx, &mut self.pool) {
            Ok(received) => received,
            Err(_) => {
                self.counters.rx_errors += 1;
                RecvResult::default()
            }
        };
        debug_assert!(received.received == self.rx.len());
        self.counters.rx_truncated += received.truncated as u64;
        self.counters.rx_unreadable += received.unreadable as u64;
        for i in 0..self.rx.len() {
            let datagram = self.rx.get(i);
            self.handle_datagram(datagram, now);
            // Lent to peers: the last return frees it.
            self.pool.put_if_unshared(datagram.buf);
        }
        self.rx.clear();
        if !self.pending_switches.is_empty() {
            self.apply_pending_switches(now);
        }
        self.flush();
        let commands = self.drain_commands(now);
        let messages = self.drain_cross_shard(now);
        // Command and peer output (DTLS records, keyframe requests,
        // forwarded hand-offs) goes out now.
        self.flush();
        self.push_pending();
        if now >= self.next_housekeeping {
            self.housekeeping(now);
            self.next_housekeeping = now + HOUSEKEEPING_INTERVAL;
        }
        self.wake_peers();
        debug_assert!(self.tx.is_empty() && self.wake_mask == 0);
        IterationStats {
            received: received.received,
            taken: received.taken(),
            would_block: received.would_block,
            commands,
            cross_shard: returned + messages,
        }
    }

    /// The I/O backend.
    pub fn io(&self) -> &I {
        &self.io
    }

    /// The I/O backend, writable (tests queue datagrams here).
    pub fn io_mut(&mut self) -> &mut I {
        &mut self.io
    }

    /// The event sink.
    pub fn events(&self) -> &S {
        &self.events
    }

    /// The event sink, writable (tests drain it).
    pub fn events_mut(&mut self) -> &mut S {
        &mut self.events
    }

    /// Counters so far.
    pub fn counters(&self) -> &ShardCounters {
        &self.counters
    }

    /// A command is waiting in the queue (checked before parking).
    pub fn commands_pending(&self) -> bool {
        !self.commands.is_empty()
    }

    /// A peer's message or returned loan is waiting (checked before parking).
    pub fn xs_pending(&self) -> bool {
        self.xs.as_ref().is_some_and(XsPorts::inbound_pending)
    }

    /// Latest time a parked shard must run again: the next housekeeping, or
    /// sooner while retained events or deferred nominations wait for a
    /// retry that only `iterate` makes.
    pub fn park_deadline(&self, now: Instant) -> Instant {
        let retry = !self.pending.is_empty() || !self.pending_switches.is_empty();
        let deadline = if retry {
            self.next_housekeeping.min(now + PARK_RETRY_INTERVAL)
        } else {
            self.next_housekeeping
        };
        debug_assert!(deadline <= now.max(self.next_housekeeping) + PARK_RETRY_INTERVAL);
        deadline
    }

    /// Adds a park to the counters (the runner parks, the shard counts).
    pub fn count_park(&mut self) {
        self.counters.parks += 1;
    }

    /// Publishes the counters now (the runner calls it once on exit, so the
    /// final values are readable after shutdown).
    pub fn publish_stats(&self) {
        self.stats.publish(&self.counters, self.gauges());
    }

    /// Table sizes.
    pub fn snapshot(&self) -> ShardSnapshot {
        ShardSnapshot {
            sessions: self.sessions.len(),
            tracks: self.tracks.len(),
            subscriptions: self.subs.len(),
            addresses: self.by_addr.len(),
            ufrags: self.by_ufrag.len(),
            pool_available: self.pool.available(),
            mirrors: self.mirrors.len(),
            xs_in_flight: self.pool.lent_total() as usize,
        }
    }

    /// The shards a local track is handed to (bit i: shard i); `None` if
    /// the track is not published here. For tests.
    #[doc(hidden)]
    pub fn remote_shards(&self, track: TrackId) -> Option<u64> {
        let tidx = *self.track_ids.get(&track)?;
        Some(self.tracks.get(tidx).remote_shards)
    }

    /// A mirror's source shard and subscription count; `None` if the track
    /// is not mirrored here. For tests.
    #[doc(hidden)]
    pub fn mirror(&self, track: TrackId) -> Option<(ShardId, usize)> {
        let midx = *self.mirror_ids.get(&track)?;
        let mirror = self.mirrors.get(midx);
        Some((mirror.source, mirror.subscribers.len()))
    }

    /// A session's selected address.
    pub fn session_addr(&self, id: SessionId) -> Option<SocketAddr> {
        let idx = *self.session_ids.get(&id)?;
        self.sessions.get(idx).addr
    }

    /// Whole seconds since the shard's epoch (SRTP inbound idle tracking).
    fn now_s(&self, now: Instant) -> u32 {
        let secs = now.saturating_duration_since(self.epoch).as_secs();
        u32::try_from(secs).unwrap_or(u32::MAX)
    }

    /// Queues a datagram in `buf`; flushes first when the batch is full.
    fn send(&mut self, buf: BufRef, len: usize, addr: SocketAddr) {
        self.flush_if_full();
        self.tx.push(Datagram { buf, len, addr });
    }

    /// Flushes in the middle of a fan-out when the send batch is full
    /// (counted: a burst larger than `SEND_BATCH` must not block or drop).
    fn flush_if_full(&mut self) {
        if self.tx.is_full() {
            self.counters.tx_full_flushes += 1;
            self.flush();
        }
    }

    /// Sends the queued datagrams.
    fn flush(&mut self) {
        if self.tx.is_empty() {
            return;
        }
        let queued = self.tx.len();
        let sent = self.io.flush(&mut self.tx, &mut self.pool);
        debug_assert!(sent.datagrams <= queued && self.tx.is_empty());
        self.counters.tx_datagrams += sent.datagrams as u64;
        self.counters.tx_bytes += sent.bytes as u64;
        self.counters.drop_send_failed += (queued - sent.datagrams) as u64;
    }

    /// Hands an event to the sink. When it is full, the event waits in the
    /// retention queue (order kept), except `DtlsDatagram`, which is dropped
    /// (the peer retransmits). A full retention queue drops and counts.
    /// Returns whether the event was delivered or retained; callers whose
    /// state depends on delivery retry later. A closed sink (the control
    /// plane is gone) drops and counts, and reports the event handled: no
    /// one is listening, retries would only repeat the drop.
    fn emit(&mut self, event: Event) -> bool {
        // After ConsentLost the control plane is closing the session: it
        // hears nothing more about it (the event counts as handled, so no
        // caller retries it).
        if self.consent_was_lost(&event) {
            self.counters.drop_after_consent += 1;
            return true;
        }
        // DTLS does not need ordering with the retained events.
        let dtls = matches!(event, Event::DtlsDatagram { .. });
        let event = if self.pending.is_empty() || dtls {
            match self.events.try_send(event) {
                Ok(()) => return true,
                Err(Refused::Full(event)) => event,
                Err(Refused::Closed(_)) => {
                    self.counters.drop_event_closed += 1;
                    return true;
                }
            }
        } else {
            event
        };
        if dtls || self.pending.len() == EVENT_RETENTION {
            self.counters.drop_event_full += 1;
            return false;
        }
        self.pending.push_back(event);
        debug_assert!(self.pending.len() <= EVENT_RETENTION);
        true
    }

    /// The event concerns a session whose `ConsentLost` was delivered.
    fn consent_was_lost(&self, event: &Event) -> bool {
        let id = match event {
            Event::DtlsDatagram { id, .. }
            | Event::AddressSelected { id, .. }
            | Event::PeerSrtpVerified { id }
            | Event::ConsentLost { id } => Some(*id),
            Event::CommandRejected { id, .. } => *id,
        };
        let session = id.and_then(|id| self.session_ids.get(&id));
        session.is_some_and(|&idx| self.sessions.get(idx).consent_lost)
    }

    /// Retries retained events, oldest first, until the sink refuses one.
    /// A closed sink drops them all (counted).
    fn push_pending(&mut self) {
        // Bounded by EVENT_RETENTION.
        while let Some(event) = self.pending.pop_front() {
            match self.events.try_send(event) {
                Ok(()) => {}
                Err(Refused::Full(event)) => {
                    self.pending.push_front(event);
                    return;
                }
                Err(Refused::Closed(_)) => self.counters.drop_event_closed += 1,
            }
        }
    }
}
