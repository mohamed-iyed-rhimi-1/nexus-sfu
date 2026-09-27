//! The shard: state tables and one loop iteration (note §3.2).
//!
//! 1.2 runs `iterate` from tests with an explicit `now`; 1.3 adds the thread,
//! parking and real sockets around it.

mod commands;
mod housekeeping;
mod ingress;
pub mod io;
mod rtcp;
pub mod stats;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use rustc_hash::FxHashMap;

use crate::command::{Command, Event, EventSink};
use crate::config::{ConfigError, ShardConfig};
use crate::ice::UFRAG_LEN;
use crate::ids::{SessionId, SubscriptionId, TrackId};
use crate::pool::{BufRef, BufferPool};
use crate::rng::Rng;
use crate::session::{Session, SessionIdx, SubIdx, TrackIdx};
use crate::slab::Slab;
use crate::subscription::Subscription;
use crate::track::PublishedTrack;
use io::{Datagram, DatagramIo, RecvBatch, SendBatch};
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

/// What one iteration did (1.3 uses it to decide when to park).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IterationStats {
    /// Datagrams received.
    pub received: usize,
    /// The receive source was drained.
    pub would_block: bool,
    /// Commands handled.
    pub commands: usize,
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
    session_ids: FxHashMap<SessionId, SessionIdx>,
    track_ids: FxHashMap<TrackId, TrackIdx>,
    sub_ids: FxHashMap<SubscriptionId, SubIdx>,
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
            session_ids: FxHashMap::default(),
            track_ids: FxHashMap::default(),
            sub_ids: FxHashMap::default(),
            by_addr: FxHashMap::with_capacity_and_hasher(addresses, Default::default()),
            by_ufrag: FxHashMap::default(),
            rng: Rng::new(config.rng_seed),
            counters: ShardCounters::default(),
            stats: Arc::new(ShardStats::default()),
            pending_switches: Vec::with_capacity(config.max_sessions as usize),
            pending: VecDeque::with_capacity(EVENT_RETENTION),
            next_housekeeping: now + HOUSEKEEPING_INTERVAL,
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

    /// Published counters and gauges (updated by housekeeping).
    pub fn stats(&self) -> Arc<ShardStats> {
        Arc::clone(&self.stats)
    }

    /// One loop iteration without parking (note §3.2): receive and handle a
    /// batch, flush sends, handle up to `COMMAND_BUDGET` commands, flush
    /// again, retry retained events, run housekeeping when due.
    pub fn iterate(&mut self, now: Instant) -> IterationStats {
        self.counters.iterations += 1;
        // A receive error counts as an empty batch; 1.3's backends count it.
        let received = self
            .io
            .recv_batch(&mut self.rx, &mut self.pool)
            .unwrap_or_default();
        debug_assert!(received.received == self.rx.len());
        for i in 0..self.rx.len() {
            let datagram = self.rx.get(i);
            self.handle_datagram(datagram, now);
            self.pool.put(datagram.buf);
        }
        self.rx.clear();
        if !self.pending_switches.is_empty() {
            self.apply_pending_switches(now);
        }
        self.flush();
        let commands = self.drain_commands(now);
        // Command output (DTLS records, keyframe requests) goes out now.
        self.flush();
        self.push_pending();
        if now >= self.next_housekeeping {
            self.housekeeping(now);
            self.next_housekeeping = now + HOUSEKEEPING_INTERVAL;
        }
        debug_assert!(self.tx.is_empty());
        IterationStats {
            received: received.received,
            would_block: received.would_block,
            commands,
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

    /// Table sizes.
    pub fn snapshot(&self) -> ShardSnapshot {
        ShardSnapshot {
            sessions: self.sessions.len(),
            tracks: self.tracks.len(),
            subscriptions: self.subs.len(),
            addresses: self.by_addr.len(),
            ufrags: self.by_ufrag.len(),
            pool_available: self.pool.available(),
        }
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
        if self.tx.is_full() {
            self.flush();
        }
        self.tx.push(Datagram { buf, len, addr });
    }

    /// Sends the queued datagrams.
    fn flush(&mut self) {
        if self.tx.is_empty() {
            return;
        }
        let queued = self.tx.len();
        let bytes: usize = self.tx.iter().map(|d| d.len).sum();
        let sent = self.io.flush(&mut self.tx, &mut self.pool);
        debug_assert!(sent <= queued && self.tx.is_empty());
        self.counters.tx_datagrams += sent as u64;
        self.counters.tx_bytes += if sent == queued { bytes as u64 } else { 0 };
        self.counters.drop_send_failed += (queued - sent) as u64;
    }

    /// Hands an event to the sink. When it is full, the event waits in the
    /// retention queue (order kept), except `DtlsDatagram`, which is dropped
    /// (the peer retransmits). A full retention queue drops and counts.
    /// Returns whether the event was delivered or retained; callers whose
    /// state depends on delivery retry later.
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
                Err(event) => event,
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
    fn push_pending(&mut self) {
        // Bounded by EVENT_RETENTION.
        while let Some(event) = self.pending.pop_front() {
            if let Err(event) = self.events.try_send(event) {
                self.pending.push_front(event);
                return;
            }
        }
    }
}
