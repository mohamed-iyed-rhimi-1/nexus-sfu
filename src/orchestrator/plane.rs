//! What the orchestrator's managers share to drive the data plane (design note §6.5):
//! the dataplane handle and placement, the process DTLS certificate, the transport
//! and track tables, the id allocator, and the participants to close.
//!
//! Every command goes through `push`. A full command queue fails the operation and
//! closes the participant's session (note §5.3); a command is never dropped silently.
//! Closing needs the queue too: a `CloseSession` that does not fit waits in
//! `pending_close` and is retried by the 1 s sweep.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use nexus_dataplane::{
    Command, CommandQueueFull, DataplaneHandle, Placement, SessionId, ShardId, ShardLoad,
};
use nexus_state::DistributedState;
use nexus_transport::dtls::{DtlsCertificate, DtlsRole};
use nexus_transport::srtp::ProtectionProfile;
use tracing::{error, warn};

use super::events::DisconnectReason;
use super::ids::IdAllocator;
use super::tracks::TrackRegistry;
use super::transports::{TransportEntry, Transports, MAX_TRANSPORTS};

/// Most participants waiting to be closed at once (each closes on the next settle).
const MAX_CLOSING: usize = 4_096;
/// Established sessions remembered for inspection (oldest dropped first).
pub const MAX_ESTABLISHED_LOG: usize = 1_024;

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
    /// `CloseSession` commands that did not fit their shard's queue.
    pending_close: Vec<(ShardId, SessionId)>,
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
        assert_eq!(shard_candidates.len(), dataplane.shard_count());
        assert!(shard_candidates.iter().all(|c| !c.is_empty()));
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
            pending_close: Vec::new(),
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

    /// Send `command` to `shard` for `participant`. On a full queue the participant is
    /// closed (`Overloaded`) and `false` is returned: the caller stops the operation.
    pub fn push(&mut self, shard: ShardId, command: Command, participant: u64) -> bool {
        match self.dataplane.send(shard, command) {
            Ok(()) => true,
            Err(_) => {
                warn!(participant, shard = shard.index(), "command queue full");
                self.close_participant(participant, DisconnectReason::Overloaded);
                false
            }
        }
    }

    /// A new session for `participant` on a placed shard: tables and `CreateSession`.
    /// `None` if the table is full or the command did not fit (then being closed).
    pub fn create_session(&mut self, participant: u64, room: Option<u32>) -> Option<SessionId> {
        if self.transports.len() >= MAX_TRANSPORTS {
            return None;
        }
        let loads = self.dataplane.loads();
        let shard = self.placement.place(room, &loads);
        let id = self.ids.session();
        let entry = TransportEntry::new(participant, shard, &self.certificate, Instant::now());
        let command = Command::CreateSession {
            id,
            ice: entry.ice,
            out_ssrc_base: entry.ssrcs.base(),
        };
        if !self.transports.insert(id, entry) {
            return None;
        }
        if !self.push(shard, command, participant) {
            self.transports.remove(id);
            return None;
        }
        assert_eq!(self.transports.session_of(participant), Some(id));
        Some(id)
    }

    /// Remove a session from the tables and the shard.
    pub fn close_session(&mut self, id: SessionId, room: Option<u32>) {
        let Some(entry) = self.transports.remove(id) else {
            return;
        };
        self.placement.session_closed(room, entry.shard);
        if self
            .dataplane
            .send(entry.shard, Command::CloseSession { id })
            .is_err()
        {
            if self.pending_close.len() >= MAX_TRANSPORTS {
                error!(
                    session = id.get(),
                    "close queue full; session leaks on the shard"
                );
                return;
            }
            self.pending_close.push((entry.shard, id));
        }
    }

    /// Retry the `CloseSession` commands that did not fit (the 1 s sweep).
    pub fn retry_pending_closes(&mut self) {
        let pending = std::mem::take(&mut self.pending_close);
        for (shard, id) in pending {
            if self
                .dataplane
                .send(shard, Command::CloseSession { id })
                .is_err()
            {
                self.pending_close.push((shard, id));
            }
        }
    }

    /// Close `participant` after the current step (once, whatever the reason count).
    pub fn close_participant(&mut self, participant: u64, reason: DisconnectReason) {
        if self.closing.iter().any(|(p, _)| *p == participant) {
            return;
        }
        if self.closing.len() >= MAX_CLOSING {
            error!(participant, "too many participants waiting to close");
            return;
        }
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

    /// Commands waiting to be retried (tests).
    pub fn pending_closes(&self) -> usize {
        self.pending_close.len()
    }
}
