//! What the orchestrator's managers share to drive the data plane (design note §6.5):
//! the dataplane handle and placement, the process DTLS certificate, the transport
//! and track tables, the id allocator, and the participants to close.
//!
//! Commands are of two kinds (plan 2.4). **Additive** ones (`CreateSession`, `AddTrack`,
//! `Subscribe`, `AddRemoteShard`, ...) go through `push`: a full queue fails the
//! operation and closes the participant (note §5.3), so nothing was added. **Cleanup**
//! ones (`CloseSession`, `Unsubscribe`, `RemoveTrack`, `RemoveRemoteShard`) go through
//! `push_cleanup`: they must arrive, or state leaks on a shard (a subscription, a mirror,
//! a `remote_shards` bit), so on a full queue they wait in a per-shard FIFO retried by
//! the 1 s sweep, and never close anyone. Before any push to a shard, that shard's
//! waiting cleanup is sent first, oldest first; a command is never sent ahead of it.
//!
//! The plane also counts on-shard subscriptions per (track, subscriber shard) and tells
//! the track's shard when another shard gets its first or loses its last
//! (`AddRemoteShard` / `RemoveRemoteShard`).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use nexus_dataplane::{
    Command, CommandQueueFull, DataplaneHandle, Placement, SessionId, ShardId, ShardLoad,
    SubscriptionId, TrackId,
};
use nexus_state::DistributedState;
use nexus_transport::dtls::{DtlsCertificate, DtlsRole};
use nexus_transport::srtp::ProtectionProfile;
use tracing::{error, warn};

use super::events::DisconnectReason;
use super::ids::IdAllocator;
use super::tracks::{TrackInfo, TrackRegistry};
use super::transports::{TransportEntry, Transports, MAX_TRANSPORTS};

/// Most participants waiting to be closed at once (each closes on the next settle).
/// Never reached: entries are distinct connected participants, and signaling accepts at
/// most `transport.max_webrtc_sessions` (≤ 100,000) connections. A close is never
/// dropped (a dropped close could leave a subscription counted with no announcement).
const MAX_CLOSING: usize = MAX_TRANSPORTS;

/// How many cleanup commands may wait for room in their shard's queue, over all shards.
/// `CloseSession` has its own budget, so other cleanup can never crowd one out: a lost
/// `CloseSession` leaks a whole session, a lost `RemoveRemoteShard` only forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleanupBudget {
    /// Waiting `CloseSession` commands.
    pub closes: usize,
    /// Waiting `Unsubscribe`, `RemoveTrack` and `RemoveRemoteShard` commands.
    pub other: usize,
}

impl CleanupBudget {
    /// The default: `MAX_TRANSPORTS` each.
    pub const DEFAULT: Self = Self {
        closes: MAX_TRANSPORTS,
        other: MAX_TRANSPORTS,
    };
}
/// Established sessions remembered for inspection (oldest dropped first).
pub const MAX_ESTABLISHED_LOG: usize = 1_024;

/// A command that removes state from a shard. It is retried until it fits (never
/// dropped for a full queue) and never closes a participant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup {
    /// Remove a session with its tracks and subscriptions.
    CloseSession(SessionId),
    /// Remove one subscription.
    Unsubscribe(SubscriptionId),
    /// Remove a track (or a mirror of it) and every subscription to it.
    RemoveTrack(TrackId),
    /// To the track's shard: `shard` has no subscriptions to it any more.
    RemoveRemoteShard { track: TrackId, shard: ShardId },
}

impl Cleanup {
    /// The command it sends.
    pub fn command(self) -> Command {
        match self {
            Cleanup::CloseSession(id) => Command::CloseSession { id },
            Cleanup::Unsubscribe(sub) => Command::Unsubscribe { sub },
            Cleanup::RemoveTrack(track) => Command::RemoveTrack { track },
            Cleanup::RemoveRemoteShard { track, shard } => {
                Command::RemoveRemoteShard { track, shard }
            }
        }
    }
}

/// A session whose DTLS handshake completed and whose SRTP was installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Established {
    /// The participant.
    pub participant: u64,
    /// The SFU's DTLS role in the handshake.
    pub role: DtlsRole,
    /// The negotiated SRTP protection profile.
    pub profile: ProtectionProfile,
}

/// The last `MAX_ESTABLISHED_LOG` established sessions, shared with the server
/// handle (control path only).
#[derive(Clone, Debug, Default)]
pub struct EstablishedLog(Arc<Mutex<VecDeque<Established>>>);

impl EstablishedLog {
    fn record(&self, entry: Established) {
        let mut log = self.0.lock();
        if log.len() >= MAX_ESTABLISHED_LOG {
            log.pop_front();
        }
        log.push_back(entry);
        debug_assert!(log.len() <= MAX_ESTABLISHED_LOG);
    }

    /// The recorded sessions, oldest first.
    pub fn snapshot(&self) -> Vec<Established> {
        self.0.lock().iter().copied().collect()
    }
}

/// Where commands go: the data plane's shard queues (`DataplaneHandle`), or a test
/// double.
pub trait CommandSink: Send + Sync {
    /// Queue `command` on `shard`; `Err` when the queue is full.
    fn send(&self, shard: ShardId, command: Command) -> Result<(), CommandQueueFull>;
    /// Every shard's load, by shard index.
    fn loads(&self) -> Vec<ShardLoad>;
    /// Number of shards.
    fn shard_count(&self) -> usize;
}

impl CommandSink for DataplaneHandle {
    fn send(&self, shard: ShardId, command: Command) -> Result<(), CommandQueueFull> {
        DataplaneHandle::send(self, shard, command)
    }

    fn loads(&self) -> Vec<ShardLoad> {
        DataplaneHandle::loads(self)
    }

    fn shard_count(&self) -> usize {
        DataplaneHandle::shard_count(self)
    }
}

/// Shared control-plane state for the data plane.
pub struct Plane {
    dataplane: Arc<dyn CommandSink>,
    placement: Box<dyn Placement>,
    /// ICE host candidates of each shard, by shard index.
    shard_candidates: Vec<Arc<[SocketAddr]>>,
    certificate: DtlsCertificate,
    /// Session tables: ICE credentials, DTLS, SSRCs, timeouts.
    pub transports: Transports,
    /// Published tracks.
    pub tracks: TrackRegistry,
    /// Session, track and subscription ids.
    pub ids: IdAllocator,
    /// Cluster-visible rooms, tracks and subscriptions.
    pub state: Arc<DistributedState>,
    /// Participants to close, and why (drained by the orchestrator after each step).
    closing: Vec<(u64, DisconnectReason)>,
    /// Cleanup commands that did not fit, per shard, oldest first.
    pending: Vec<VecDeque<Cleanup>>,
    /// Entries in `pending`, over all shards: (`CloseSession`, other).
    pending_len: (usize, usize),
    /// Bounds on `pending_len`.
    budget: CleanupBudget,
    /// Established sessions (role, SRTP profile), for the server handle.
    established: EstablishedLog,
}

impl Plane {
    /// `shard_candidates[i]` are shard `i`'s ICE candidates; every shard has at least one.
    pub fn new(
        dataplane: Arc<dyn CommandSink>,
        placement: Box<dyn Placement>,
        shard_candidates: Vec<Vec<SocketAddr>>,
        certificate: DtlsCertificate,
        state: Arc<DistributedState>,
    ) -> Self {
        let shards = dataplane.shard_count();
        assert_eq!(shard_candidates.len(), shards);
        assert!(shard_candidates.iter().all(|c| !c.is_empty()));
        assert!(shards <= super::tracks::TRACK_SHARDS);
        Self {
            dataplane,
            placement,
            shard_candidates: shard_candidates.into_iter().map(Into::into).collect(),
            certificate,
            transports: Transports::new(),
            tracks: TrackRegistry::new(),
            ids: IdAllocator::new(),
            state,
            closing: Vec::new(),
            pending: vec![VecDeque::new(); shards],
            pending_len: (0, 0),
            budget: CleanupBudget::DEFAULT,
            established: EstablishedLog::default(),
        }
    }

    /// The log of established sessions (shared).
    pub fn established_log(&self) -> EstablishedLog {
        self.established.clone()
    }

    /// The process DTLS certificate (its fingerprint goes into every offer).
    pub fn certificate(&self) -> &DtlsCertificate {
        &self.certificate
    }

    /// A shard's ICE host candidates.
    pub fn candidates(&self, shard: ShardId) -> Arc<[SocketAddr]> {
        Arc::clone(&self.shard_candidates[usize::from(shard.index())])
    }

    /// Send an additive `command` to `shard` for `participant`, after the shard's
    /// waiting cleanup. On a full queue (or cleanup still waiting) the participant is
    /// closed (`Overloaded`) and `false` is returned: the caller stops the operation.
    pub fn push(&mut self, shard: ShardId, command: Command, participant: u64) -> bool {
        if self.flush(shard) && self.dataplane.send(shard, command).is_ok() {
            return true;
        }
        warn!(participant, shard = shard.index(), "command queue full");
        self.close_participant(participant, DisconnectReason::Overloaded);
        false
    }

    /// Send a cleanup command to `shard`, after the shard's waiting cleanup; if it
    /// does not fit it waits behind them for the sweep. A full retry list leaks it
    /// (logged).
    pub fn push_cleanup(&mut self, shard: ShardId, cleanup: Cleanup) {
        if self.flush(shard) && self.dataplane.send(shard, cleanup.command()).is_ok() {
            return;
        }
        let close = matches!(cleanup, Cleanup::CloseSession(_));
        let (waiting, bound) = if close {
            (self.pending_len.0, self.budget.closes)
        } else {
            (self.pending_len.1, self.budget.other)
        };
        if waiting >= bound {
            error!(
                shard = shard.index(),
                ?cleanup,
                "cleanup retry list full; command dropped, state leaks on the shard"
            );
            return;
        }
        self.pending[usize::from(shard.index())].push_back(cleanup);
        self.count_pending(cleanup, 1);
    }

    /// `pending_len` after `cleanup` joined (`+1`) or left (`-1`) a retry list.
    fn count_pending(&mut self, cleanup: Cleanup, delta: isize) {
        let len = match cleanup {
            Cleanup::CloseSession(_) => &mut self.pending_len.0,
            _ => &mut self.pending_len.1,
        };
        *len = len.checked_add_signed(delta).expect("pending count");
    }

    /// Replace the cleanup budget (tests).
    pub fn set_cleanup_budget(&mut self, budget: CleanupBudget) {
        self.budget = budget;
    }

    /// Send `shard`'s waiting cleanup, oldest first, until one does not fit.
    /// `true` when none is left.
    fn flush(&mut self, shard: ShardId) -> bool {
        let index = usize::from(shard.index());
        // Bounded: each pass sends and removes one entry, or stops.
        while let Some(&cleanup) = self.pending[index].front() {
            if self.dataplane.send(shard, cleanup.command()).is_err() {
                return false;
            }
            self.pending[index].pop_front();
            self.count_pending(cleanup, -1);
        }
        true
    }

    /// Retry every shard's waiting cleanup, in order (the 1 s sweep).
    pub fn retry_pending_cleanup(&mut self) {
        for index in 0..self.pending.len() {
            self.flush(ShardId::new(index as u8));
        }
        debug_assert_eq!(
            self.pending_len.0 + self.pending_len.1,
            self.pending.iter().map(VecDeque::len).sum::<usize>()
        );
    }

    /// Drop a waiting `RemoveRemoteShard { track, shard }` for `track_shard`'s queue;
    /// `true` if there was one.
    fn cancel_pending_remove(
        &mut self,
        track_shard: ShardId,
        track: TrackId,
        shard: ShardId,
    ) -> bool {
        let queue = &mut self.pending[usize::from(track_shard.index())];
        let wanted = Cleanup::RemoveRemoteShard { track, shard };
        let Some(pos) = queue.iter().position(|c| *c == wanted) else {
            return false;
        };
        queue.remove(pos);
        self.count_pending(wanted, -1);
        true
    }

    /// A new session for `participant` on a placed shard: tables and `CreateSession`.
    /// `None` if the table is full or the command did not fit (then being closed); the
    /// placement is released on every failure after `place`.
    pub fn create_session(&mut self, participant: u64, room: Option<u32>) -> Option<SessionId> {
        if self.transports.len() >= MAX_TRANSPORTS {
            return None;
        }
        let loads = self.dataplane.loads();
        let shard = self.placement.place(room, &loads);
        let id = self.ids.session();
        let mut entry = TransportEntry::new(participant, shard, &self.certificate, Instant::now());
        entry.room = room;
        let command = Command::CreateSession {
            id,
            ice: entry.ice,
            out_ssrc_base: entry.ssrcs.base(),
        };
        if !self.transports.insert(id, entry) {
            self.placement.session_closed(room, shard);
            return None;
        }
        if !self.push(shard, command, participant) {
            self.transports.remove(id);
            self.placement.session_closed(room, shard);
            return None;
        }
        assert_eq!(self.transports.session_of(participant), Some(id));
        Some(id)
    }

    /// Remove a session from the tables, the placement and the shard.
    pub fn close_session(&mut self, id: SessionId) {
        let Some(entry) = self.transports.remove(id) else {
            return;
        };
        self.placement.session_closed(entry.room, entry.shard);
        self.push_cleanup(entry.shard, Cleanup::CloseSession(id));
    }

    // ── Subscriptions across shards ──────────────────────────────────

    /// A subscribe m-line of a session on `shard` went onto its shard: count it. A
    /// subscription on a shard other than the track's that is not announced yet
    /// announces the shard (`AddRemoteShard`): the first one, or a later one after an
    /// earlier announcement did not fit (its subscriber is being closed, maybe not in
    /// this step). If a `RemoveRemoteShard` for the pair is still waiting, it is
    /// dropped and nothing is sent (the track's shard never lost the bit, and a late
    /// remove would cut the new subscriber off). `false` if the announcement did not
    /// fit (the participant is being closed; the count stays for its cleanup).
    pub fn count_subscription(&mut self, track: TrackId, shard: ShardId, participant: u64) -> bool {
        if self.tracks.add_subscriber(track, shard).is_none() {
            return true; // removed meanwhile: nothing on its shard to tell
        }
        let info = self.tracks.get(track).expect("counted");
        let (track_shard, bit) = (info.shard, 1u32 << shard.index());
        if shard == track_shard || info.announced & bit != 0 {
            return true;
        }
        let announced = if self.cancel_pending_remove(track_shard, track, shard) {
            true
        } else {
            let command = Command::AddRemoteShard { track, shard };
            self.push(track_shard, command, participant)
        };
        if announced {
            let info = self.tracks.get_mut(track).expect("counted");
            debug_assert!(info.announced & bit == 0);
            info.announced |= bit;
        }
        announced
    }

    /// A subscribe m-line of a session on `shard` left its shard (unsubscribed, or
    /// the subscriber left). The last on an announced shard sends
    /// `RemoveRemoteShard` to the track's shard. Nothing for a removed track.
    pub fn uncount_subscription(&mut self, track: TrackId, shard: ShardId) {
        let Some(last) = self.tracks.remove_subscriber(track, shard) else {
            return;
        };
        let info = self.tracks.get_mut(track).expect("counted");
        let bit = 1u32 << shard.index();
        if !last || info.announced & bit == 0 {
            return;
        }
        info.announced &= !bit;
        let track_shard = info.shard;
        debug_assert!(track_shard != shard);
        self.push_cleanup(track_shard, Cleanup::RemoveRemoteShard { track, shard });
    }

    /// Remove a track from the registry and from every shard with subscriptions to it
    /// (its mirrors there), and from its own shard when `on_track_shard` (unpublish;
    /// a publisher's `CloseSession` removes it there).
    pub fn remove_track(&mut self, track: TrackId, on_track_shard: bool) -> Option<TrackInfo> {
        let info = self.tracks.remove(track)?;
        if on_track_shard {
            self.push_cleanup(info.shard, Cleanup::RemoveTrack(track));
        }
        for shard in info.remote_shards() {
            self.push_cleanup(shard, Cleanup::RemoveTrack(track));
        }
        Some(info)
    }

    /// Close `participant` after the current step (once, whatever the reason count).
    pub fn close_participant(&mut self, participant: u64, reason: DisconnectReason) {
        if self.closing.iter().any(|(p, _)| *p == participant) {
            return;
        }
        assert!(
            self.closing.len() < MAX_CLOSING,
            "more participants closing than can be connected"
        );
        self.closing.push((participant, reason));
    }

    /// The participants to close, in order.
    pub fn take_closing(&mut self) -> Vec<(u64, DisconnectReason)> {
        std::mem::take(&mut self.closing)
    }

    /// Push `datagrams` (DTLS output) to the session's peer, one `SendDatagram` each.
    pub fn send_datagrams(&mut self, id: SessionId, datagrams: Vec<Vec<u8>>) {
        let Some(entry) = self.transports.get(id) else {
            return;
        };
        let (shard, participant) = (entry.shard, entry.participant);
        for bytes in datagrams {
            let command = Command::SendDatagram {
                id,
                bytes: bytes.into_boxed_slice(),
            };
            if !self.push(shard, command, participant) {
                return;
            }
        }
    }

    /// The handshake completed: install the session's SRTP keys on its shard.
    pub fn install_srtp(&mut self, id: SessionId) {
        let Some(entry) = self.transports.get_mut(id) else {
            return;
        };
        let (shard, participant) = (entry.shard, entry.participant);
        assert!(!entry.srtp_installed, "SRTP is installed once");
        match entry.dtls.srtp_install() {
            Ok(keys) => {
                entry.srtp_installed = true;
                let (role, profile) = (entry.dtls.role(), keys.local.profile);
                let command = Command::InstallSrtp {
                    id,
                    keys: Box::new(keys),
                };
                if self.push(shard, command, participant) {
                    if let Some(role) = role {
                        self.established.record(Established {
                            participant,
                            role,
                            profile,
                        });
                    }
                    tracing::info!(
                        participant,
                        session = id.get(),
                        ?role,
                        ?profile,
                        "DTLS established"
                    );
                }
            }
            Err(e) => {
                warn!(participant, "SRTP keys: {e}");
                self.close_participant(participant, DisconnectReason::DtlsFailed);
            }
        }
    }

    /// Cleanup commands waiting to be retried, over all shards (tests).
    pub fn pending_cleanup(&self) -> usize {
        self.pending_len.0 + self.pending_len.1
    }
}
