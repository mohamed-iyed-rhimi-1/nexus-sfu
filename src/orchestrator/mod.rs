//! Session Orchestrator — thin dispatcher over specialized managers.
//!
//! Routes signaling events, data-plane events and timer ticks to the managers, and
//! drives the data plane through commands (`plane.rs`). Owns the shared
//! `ParticipantHandle` table.

pub mod candidates;
pub mod connection;
pub mod dtls;
pub mod events;
pub mod ids;
pub mod negotiation;
pub mod plane;
pub mod room;
pub mod sdp_params;
pub mod subscription;
pub mod tracks;
pub mod transports;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_api::RoomGrant;
use nexus_dataplane::{Event, Placement, TrackId as DpTrackId};
use nexus_state::DistributedState;
use nexus_transport::dtls::DtlsCertificate;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::signal::{OrchestratorEvent, SignalMessage};
use crate::types::TrackId;

use connection::ConnectionTimers;
use events::DisconnectReason;
use negotiation::{send_error, send_to, NegotiationManager};
use plane::Plane;
use room::RoomManager;
use subscription::SubscriptionManager;

/// Most participants a room notification reaches.
const MAX_ROOM_NOTIFY: usize = 1_000;
/// Data-plane events handled per wake-up before the other branches get a turn.
const EVENT_BATCH: usize = 256;

/// Shared per-participant state visible to all managers.
pub struct ParticipantHandle {
    pub outbound_tx: mpsc::Sender<SignalMessage>,
    /// The rooms the participant's token grants (`Create`/`Join` check it).
    pub grant: RoomGrant,
    pub room_id: Option<u32>,
    pub published_tracks: Vec<TrackId>,
}

pub struct SessionOrchestrator {
    sessions: HashMap<u64, ParticipantHandle>,
    rooms: RoomManager,
    negotiation: NegotiationManager,
    subscription: SubscriptionManager,
    plane: Plane,
}

impl SessionOrchestrator {
    /// `shard_candidates[i]`: the ICE host candidates of shard `i`.
    pub fn new(
        dataplane: Arc<dyn plane::CommandSink>,
        shard_candidates: Vec<Vec<SocketAddr>>,
        placement: Box<dyn Placement>,
        certificate: DtlsCertificate,
        distributed_state: Arc<DistributedState>,
    ) -> Self {
        Self {
            sessions: HashMap::with_capacity(1024),
            rooms: RoomManager::new(distributed_state.clone()),
            negotiation: NegotiationManager::new(),
            subscription: SubscriptionManager::new(),
            plane: Plane::new(
                dataplane,
                placement,
                shard_candidates,
                certificate,
                distributed_state,
            ),
        }
    }

    /// Sessions whose DTLS completed (role, SRTP profile); stays readable after `run`
    /// takes the orchestrator into its task.
    pub fn established_log(&self) -> plane::EstablishedLog {
        self.plane.established_log()
    }

    /// Main event loop, until `shutdown` is set.
    pub async fn run(
        &mut self,
        mut event_rx: mpsc::Receiver<OrchestratorEvent>,
        mut dataplane_rx: mpsc::Receiver<Event>,
        shutdown: Arc<AtomicBool>,
    ) {
        // The senders outlive the loop, so channel closure never ends it: the
        // shutdown flag does.
        let mut shutdown_check = tokio::time::interval(Duration::from_millis(50));
        let mut timers = ConnectionTimers::new();
        let mut events = Vec::with_capacity(EVENT_BATCH);
        loop {
            tokio::select! {
                _ = shutdown_check.tick() => {
                    if shutdown.load(Ordering::Acquire) {
                        info!("Session orchestrator shutting down");
                        break;
                    }
                }
                Some(event) = event_rx.recv() => self.dispatch_event(event),
                n = dataplane_rx.recv_many(&mut events, EVENT_BATCH) => {
                    if n == 0 {
                        warn!("Data-plane event channel closed");
                        break;
                    }
                    for event in events.drain(..) {
                        connection::handle_event(event, &mut self.plane);
                    }
                }
                _ = timers.dtls.tick() => connection::poll_dtls(&mut self.plane),
                _ = timers.sweep.tick() => connection::sweep(&mut self.plane, Instant::now()),
            }
            self.settle();
        }
    }

    /// One signaling event, then the closes it caused: what `run` does per event.
    /// For benches and tests that drive the orchestrator without a runtime
    /// (`benches/memory.rs`); the server uses `run`.
    #[doc(hidden)]
    pub fn handle_signal(&mut self, event: OrchestratorEvent) {
        self.dispatch_event(event);
        self.settle();
    }

    /// One data-plane event, then the closes it caused (see `handle_signal`).
    #[doc(hidden)]
    pub fn handle_dataplane(&mut self, event: Event) {
        connection::handle_event(event, &mut self.plane);
        self.settle();
    }

    /// Close the participants whose sessions failed during the last step.
    fn settle(&mut self) {
        // Bounded: each round closes the participants recorded in the previous one;
        // a close cannot record more than every remaining participant.
        for _ in 0..=self.sessions.len() {
            let closing = self.plane.take_closing();
            if closing.is_empty() {
                return;
            }
            for (participant_id, reason) in closing {
                self.close_participant(participant_id, reason);
            }
        }
    }

    fn close_participant(&mut self, participant_id: u64, reason: DisconnectReason) {
        if !self.sessions.contains_key(&participant_id) {
            return;
        }
        info!("Closing participant {} ({:?})", participant_id, reason);
        send_error(
            &self.sessions,
            participant_id,
            reason.code(),
            "Session closed",
        );
        self.rooms
            .handle_disconnected(participant_id, &mut self.sessions);
        self.cleanup_participant(participant_id);
    }

    fn dispatch_event(&mut self, event: OrchestratorEvent) {
        match event {
            OrchestratorEvent::Connected {
                participant_id,
                outbound_tx,
                claims,
            } => self.handle_connected(participant_id, outbound_tx, claims.room_grant()),
            OrchestratorEvent::Message {
                participant_id,
                message,
            } => self.handle_message(participant_id, message),
            OrchestratorEvent::Disconnected { participant_id } => {
                self.handle_participant_disconnected(participant_id)
            }
        }
    }

    fn handle_connected(
        &mut self,
        participant_id: u64,
        outbound_tx: mpsc::Sender<SignalMessage>,
        grant: RoomGrant,
    ) {
        if participant_id == 0 {
            return;
        }
        self.sessions.insert(
            participant_id,
            ParticipantHandle {
                outbound_tx,
                grant,
                room_id: None,
                published_tracks: Vec::with_capacity(10),
            },
        );
        self.negotiation.add_participant(participant_id);
        self.subscription.add_participant(participant_id);
        debug!("Participant {} connected", participant_id);
    }

    fn handle_message(&mut self, participant_id: u64, message: SignalMessage) {
        if participant_id == 0 || !self.sessions.contains_key(&participant_id) {
            return;
        }
        match message {
            SignalMessage::Create { room_name } => {
                self.rooms
                    .handle_create(participant_id, room_name, &self.sessions);
            }
            SignalMessage::Join {
                room_id,
                participant_name,
            } => {
                self.rooms.handle_join(
                    participant_id,
                    room_id,
                    &participant_name,
                    &mut self.sessions,
                );
            }
            SignalMessage::Publish { kinds, contents } => {
                self.negotiation.handle_publish(
                    participant_id,
                    &kinds,
                    &contents,
                    &self.sessions,
                    &mut self.plane,
                );
            }
            SignalMessage::Answer { sdp } => self.handle_answer(participant_id, &sdp),
            SignalMessage::IceCandidate { candidate, .. } => {
                self.negotiation
                    .handle_candidate(participant_id, &candidate);
            }
            SignalMessage::Subscribe { track_ids } => {
                self.subscription.handle_subscribe(
                    participant_id,
                    &track_ids,
                    &mut self.negotiation,
                    &self.sessions,
                    &mut self.plane,
                );
            }
            SignalMessage::Unsubscribe { track_ids } => {
                self.subscription.handle_unsubscribe(
                    participant_id,
                    &track_ids,
                    &mut self.negotiation,
                    &self.sessions,
                    &mut self.plane,
                );
            }
            SignalMessage::Viewport { visible, pinned } => {
                self.subscription.handle_viewport(
                    participant_id,
                    &visible,
                    &pinned,
                    &self.sessions,
                );
            }
            SignalMessage::SetContent { track_id, content } => {
                self.subscription.handle_set_content(
                    participant_id,
                    track_id,
                    &content,
                    &self.sessions,
                    &mut self.plane,
                );
            }
            SignalMessage::Leave => {
                self.rooms.handle_leave(participant_id, &mut self.sessions);
                self.cleanup_participant(participant_id);
            }
            SignalMessage::Ping => send_to(&self.sessions, participant_id, SignalMessage::Pong),
            SignalMessage::Unpublish { track_ids } => {
                self.handle_unpublish(participant_id, &track_ids)
            }
            _ => debug!("Unhandled message type from {}", participant_id),
        }
    }

    fn handle_answer(&mut self, participant_id: u64, sdp: &str) {
        if sdp.is_empty() {
            return;
        }
        let outcome =
            self.negotiation
                .handle_answer(participant_id, sdp, &self.sessions, &mut self.plane);
        self.subscription
            .activate(participant_id, &outcome.activated, &self.plane);
        // Tracks registered from the publisher's answer, mirrored on the handle for
        // Joined responses and TrackUnpublished.
        let tracks = self
            .negotiation
            .states
            .get(&participant_id)
            .map(|s| s.published_tracks.clone())
            .unwrap_or_default();
        if let Some(handle) = self.sessions.get_mut(&participant_id) {
            handle.published_tracks = tracks;
        }
    }

    /// Remove the participant's own tracks: `RemoveTrack` to the track's shard and to
    /// every shard subscribed to it (which drops the subscriptions and mirrors there;
    /// retried if a queue is full), the registries, and a renegotiation for
    /// subscribers.
    fn handle_unpublish(&mut self, participant_id: u64, track_ids: &[u64]) {
        let mut removed = Vec::with_capacity(track_ids.len());
        for &track_id in track_ids.iter().take(nexus_webrtc::sdp::MAX_MEDIA_SECTIONS) {
            let track = (track_id != 0).then(|| DpTrackId::new(track_id));
            let owned = track
                .and_then(|t| self.plane.tracks.get(t))
                .map(|i| (i.publisher, i.shard));
            let Some((publisher, shard)) = owned else {
                continue;
            };
            if publisher != participant_id {
                send_error(
                    &self.sessions,
                    participant_id,
                    "NOT_OWNER",
                    "Not your track",
                );
                continue;
            }
            let track = track.expect("checked");
            if let Some(info) = self.plane.remove_track(track, true) {
                debug_assert_eq!(info.shard, shard);
                self.negotiation
                    .release_publish(participant_id, track_id, info.mid().as_bytes());
            }
            self.plane.state.remove_track(track_id);
            removed.push(track_id);
        }
        if let Some(handle) = self.sessions.get_mut(&participant_id) {
            handle.published_tracks.retain(|t| !removed.contains(t));
        }
        self.notify_unpublished(participant_id, &removed);
        self.on_tracks_removed(&removed);
        info!(
            "Participant {} unpublished {} tracks",
            participant_id,
            removed.len()
        );
    }

    /// `TrackUnpublished` to the publisher's room peers.
    fn notify_unpublished(&self, participant_id: u64, tracks: &[TrackId]) {
        let Some(room_id) = self.sessions.get(&participant_id).and_then(|h| h.room_id) else {
            return;
        };
        let participants = self.plane.state.get_participants(room_id);
        for &track_id in tracks {
            for &pid in participants.iter().take(MAX_ROOM_NOTIFY) {
                if pid != participant_id {
                    send_to(
                        &self.sessions,
                        pid,
                        SignalMessage::TrackUnpublished { track_id },
                    );
                }
            }
        }
    }

    /// Tracks gone from the shard: subscribers drop them and are offered without them.
    fn on_tracks_removed(&mut self, tracks: &[TrackId]) {
        if tracks.is_empty() {
            return;
        }
        let mut affected = self.negotiation.forget_tracks(tracks);
        affected.extend(self.subscription.forget_tracks(tracks, &self.plane));
        affected.sort_unstable();
        affected.dedup();
        for participant_id in affected {
            if !self.sessions.contains_key(&participant_id) {
                continue;
            }
            let ids = self.subscription.track_ids(participant_id);
            self.negotiation.request_renegotiation(
                participant_id,
                ids,
                &self.sessions,
                &mut self.plane,
            );
        }
    }

    fn handle_participant_disconnected(&mut self, participant_id: u64) {
        if participant_id == 0 {
            return;
        }
        self.rooms
            .handle_disconnected(participant_id, &mut self.sessions);
        self.cleanup_participant(participant_id);
    }

    fn cleanup_participant(&mut self, participant_id: u64) {
        let published = self
            .sessions
            .get(&participant_id)
            .map(|h| h.published_tracks.clone())
            .unwrap_or_default();
        self.notify_unpublished(participant_id, &published);
        self.subscription
            .cleanup_participant(participant_id, &self.plane);
        let removed = self
            .negotiation
            .cleanup_participant(participant_id, &mut self.plane);
        self.sessions.remove(&participant_id);
        self.on_tracks_removed(&removed);
        info!("Participant {} fully cleaned up", participant_id);
    }
}

#[cfg(test)]
#[path = "orchestrator_tests.rs"]
mod tests;
