//! Connection lifecycle on the data plane's events (design note §6.3, §6.4).
//!
//! The shard runs ICE-lite and moves DTLS datagrams; this module runs the DTLS
//! handshake on them, installs SRTP when it completes, frees the OpenSSL state once the
//! peer's SRTP authenticates, and closes sessions on `ConsentLost` and the timeouts.

use std::time::{Duration, Instant};

use nexus_dataplane::{Event, RejectReason, SessionId};
use tokio::time::{interval, Interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use super::dtls::{HandshakeError, Progress};
use super::events::DisconnectReason;
use super::plane::Plane;
use super::transports::Expired;

/// DTLS retransmission timer period.
pub const DTLS_TICK: Duration = Duration::from_millis(200);
/// Timeout sweep period (ICE connect, DTLS handshake, pending closes).
pub const SWEEP_TICK: Duration = Duration::from_secs(1);

/// The orchestrator's timers.
pub struct ConnectionTimers {
    /// Drives `poll_dtls`.
    pub dtls: Interval,
    /// Drives `sweep`.
    pub sweep: Interval,
}

impl ConnectionTimers {
    pub fn new() -> Self {
        let mut dtls = interval(DTLS_TICK);
        let mut sweep = interval(SWEEP_TICK);
        dtls.set_missed_tick_behavior(MissedTickBehavior::Delay);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self { dtls, sweep }
    }
}

impl Default for ConnectionTimers {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle one data-plane event.
pub fn handle_event(event: Event, plane: &mut Plane) {
    match event {
        Event::DtlsDatagram { id, bytes } => on_dtls_datagram(id, &bytes, plane),
        Event::AddressSelected { id, addr, reason } => {
            let Some(entry) = plane.transports.get_mut(id) else {
                return;
            };
            let first = entry.mark_address_selected(Instant::now());
            info!(participant = entry.participant, %addr, ?reason, "address selected");
            if first {
                let result = entry.dtls.on_address_selected();
                apply_progress(id, result, plane);
            }
        }
        Event::PeerSrtpVerified { id } => {
            if let Some(entry) = plane.transports.get_mut(id) {
                let freed = entry.dtls.free_ssl();
                debug!(participant = entry.participant, freed, "peer SRTP verified");
            }
        }
        Event::ConsentLost { id } => {
            if let Some(participant) = plane.transports.participant_of(id) {
                info!(participant, "consent lost");
                plane.close_participant(participant, DisconnectReason::ConsentExpired);
            }
        }
        Event::CommandRejected { id, reason } => on_rejected(id, reason, plane),
    }
}

fn on_dtls_datagram(id: SessionId, bytes: &[u8], plane: &mut Plane) {
    let Some(entry) = plane.transports.get_mut(id) else {
        return;
    };
    match entry.dtls.process(bytes) {
        Err(HandshakeError::InvalidDatagram(len)) => {
            debug!(
                participant = entry.participant,
                len, "DTLS datagram refused"
            );
        }
        result => apply_progress(id, result, plane),
    }
}

/// Send a handshake step's datagrams and install SRTP when it completed; a failed
/// step closes the session.
fn apply_progress(id: SessionId, result: Result<Progress, HandshakeError>, plane: &mut Plane) {
    let Some(participant) = plane.transports.participant_of(id) else {
        return;
    };
    match result {
        Ok(progress) => {
            plane.send_datagrams(id, progress.datagrams);
            if progress.completed {
                plane.install_srtp(id);
            }
        }
        Err(e) => {
            warn!(participant, "DTLS handshake failed: {e}");
            plane.close_participant(participant, DisconnectReason::DtlsFailed);
        }
    }
}

/// A refused command. Unknown ids are expected after removals (a `RemoveTrack` takes
/// the subscriptions to the track with it). Anything else closes the participant: the
/// orchestrator checks the limits and specs before it sends, so a refusal means the
/// shard is full (`Overloaded`) or the two disagree (`Internal`). The event names the
/// session, not the track or subscription, so the registration cannot be undone
/// selectively; a session whose tables disagree with the shard's is not kept.
fn on_rejected(id: Option<SessionId>, reason: RejectReason, plane: &mut Plane) {
    let participant = id.and_then(|id| plane.transports.participant_of(id));
    let close = match reason {
        RejectReason::UnknownSession
        | RejectReason::UnknownTrack
        | RejectReason::UnknownSubscription => {
            debug!(?participant, ?reason, "command for a removed object");
            return;
        }
        RejectReason::SessionLimit | RejectReason::TrackLimit | RejectReason::SubscriptionLimit => {
            warn!(?participant, ?reason, "shard limit reached");
            DisconnectReason::Overloaded
        }
        _ => {
            error!(
                ?participant,
                ?reason,
                "shard refused a command: orchestrator bug"
            );
            DisconnectReason::Internal
        }
    };
    match participant {
        Some(p) => plane.close_participant(p, close),
        None => warn!(?id, ?reason, "refused command for an unknown session"),
    }
}

/// DTLS retransmissions for every running handshake.
pub fn poll_dtls(plane: &mut Plane) {
    for id in plane.transports.handshaking() {
        let Some(entry) = plane.transports.get_mut(id) else {
            continue;
        };
        let result = entry.dtls.handle_timeout().map(|datagrams| Progress {
            datagrams,
            completed: false,
        });
        apply_progress(id, result, plane);
    }
}

/// Close sessions whose ICE-connect or DTLS timeout expired; retry pending closes.
pub fn sweep(plane: &mut Plane, now: Instant) {
    for (id, expired) in plane.transports.sweep(now) {
        let Some(participant) = plane.transports.participant_of(id) else {
            continue;
        };
        let reason = match expired {
            Expired::IceConnect => DisconnectReason::IceFailed,
            Expired::DtlsHandshake => DisconnectReason::DtlsFailed,
        };
        info!(participant, ?expired, "session timed out");
        plane.close_participant(participant, reason);
    }
    plane.retry_pending_closes();
}
