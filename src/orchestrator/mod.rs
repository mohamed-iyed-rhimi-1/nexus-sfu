//! Session Orchestrator — thin dispatcher over specialized managers.
//!
//! Routes signaling events, ICE gathering results, cold-path packets,
//! and timer ticks to the appropriate manager. Owns the shared
//! `ParticipantHandle` table.

pub mod candidates;
pub mod connection;
pub mod dtls;
pub mod events;
pub mod ids;
pub mod negotiation;
pub mod room;
pub mod sdp_params;
pub mod subscription;
pub mod tracks;
pub mod transports;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::forward::SsrcRouter;
use crate::signal::{OrchestratorEvent, SignalMessage};
use crate::types::TrackId;
use crate::worker::WorkerPool;
use nexus_state::DistributedState;
use nexus_webrtc::webrtc::WebRtcTransport;

use connection::{ConnectionMonitor, PacketSender};
use events::{ColdPathPacket, SessionEvent};
use negotiation::NegotiationManager;
use room::RoomManager;
use subscription::SubscriptionManager;

/// Shared per-participant state visible to all managers.
pub struct ParticipantHandle {
    pub outbound_tx: mpsc::Sender<SignalMessage>,
    pub room_id: Option<u32>,
    pub published_tracks: Vec<TrackId>,
}

pub struct SessionOrchestrator {
    sessions: HashMap<u64, ParticipantHandle>,
    rooms: RoomManager,
    negotiation: NegotiationManager,
    subscription: SubscriptionManager,
    connection: ConnectionMonitor,
}

impl SessionOrchestrator {
    pub fn new(
        webrtc_transport: Arc<WebRtcTransport>,
        ssrc_router: Arc<SsrcRouter>,
        distributed_state: Arc<DistributedState>,
        worker_pool: Arc<RwLock<WorkerPool>>,
        candidate_addrs: Vec<SocketAddr>,
        packet_sender: PacketSender,
    ) -> Self {
        Self {
            sessions: HashMap::with_capacity(1024),
            rooms: RoomManager::new(distributed_state.clone()),
            negotiation: NegotiationManager::new(
                webrtc_transport.clone(),
                ssrc_router,
                worker_pool.clone(),
                distributed_state.clone(),
                candidate_addrs,
            ),
            subscription: SubscriptionManager::new(worker_pool, distributed_state),
            connection: ConnectionMonitor::new(webrtc_transport, packet_sender),
        }
    }

    /// Main event loop.
    pub async fn run(
        &mut self,
        mut event_rx: mpsc::Receiver<OrchestratorEvent>,
        mut connection_rx: mpsc::Receiver<ColdPathPacket>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) {
        // The event senders outlive the loop (the negotiation manager holds
        // one), so channel closure never ends it: the shutdown flag does.
        let mut shutdown_check = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            tokio::select! {
                _ = shutdown_check.tick() => {
                    if shutdown.load(std::sync::atomic::Ordering::Acquire) {
                        info!("Session orchestrator shutting down");
                        break;
                    }
                }
                Some(event) = event_rx.recv() => {
                    self.dispatch_event(event);
                }
                Some(ice_event) = self.negotiation.ice_gather_rx.recv() => {
                    self.negotiation.dispatch_ice_event(ice_event, &self.sessions);
                }
                Some(packet) = connection_rx.recv() => {
                    let events = self.connection.process_incoming(packet);
                    for ev in events { self.handle_session_event(ev); }
                }
                _ = self.connection.ice_interval.tick() => {
                    let events = self.connection.poll_ice();
                    for ev in events { self.handle_session_event(ev); }
                }
                _ = self.connection.dtls_interval.tick() => {
                    let events = self.connection.poll_dtls();
                    for ev in events { self.handle_session_event(ev); }
                }
                _ = self.connection.consent_interval.tick() => {
                    let events = self.connection.poll_consent();
                    for ev in events { self.handle_session_event(ev); }
                }
                _ = self.connection.cleanup_interval.tick() => {
                    let events = self.connection.cleanup_idle();
                    for ev in events { self.handle_session_event(ev); }
                }
                else => break,
            }
        }
    }

    fn dispatch_event(&mut self, event: OrchestratorEvent) {
        match event {
            OrchestratorEvent::Connected {
                participant_id,
                outbound_tx,
                ..
            } => {
                self.handle_connected(participant_id, outbound_tx);
            }
            OrchestratorEvent::Message {
                participant_id,
                message,
            } => {
                self.handle_message(participant_id, message);
            }
            OrchestratorEvent::Disconnected { participant_id } => {
                self.handle_participant_disconnected(participant_id);
            }
        }
    }

    fn handle_connected(&mut self, participant_id: u64, outbound_tx: mpsc::Sender<SignalMessage>) {
        if participant_id == 0 {
            return;
        }
        self.sessions.insert(
            participant_id,
            ParticipantHandle {
                outbound_tx,
                room_id: None,
                published_tracks: Vec::with_capacity(10),
            },
        );
        self.negotiation.add_participant(participant_id);
        self.subscription.add_participant(participant_id);
        debug!("Participant {} connected", participant_id);
    }

    fn handle_message(&mut self, participant_id: u64, message: SignalMessage) {
        if participant_id == 0 {
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
                self.negotiation
                    .handle_publish(participant_id, &kinds, &contents, &self.sessions);
                // Register transport → participant mapping for SubscriptionManager
                if let Some(tid) = self.negotiation.transport_id(participant_id) {
                    self.subscription
                        .register_transport(tid.value(), participant_id);
                    self.sync_published_tracks(participant_id);
                }
            }
            SignalMessage::Answer { sdp } => {
                self.negotiation
                    .handle_answer(participant_id, &sdp, &self.sessions);
                // Tracks are registered from the publisher's answer; mirror them on
                // the handle so Joined responses and TrackUnpublished see them.
                self.sync_published_tracks(participant_id);
                // Renegotiation on an already-established transport (e.g. a publisher
                // subscribing): no new Established event fires, so activate now.
                if let Some(tid) = self
                    .negotiation
                    .settled_established_transport(participant_id)
                {
                    self.subscription
                        .handle_session_established(tid.value(), &mut self.negotiation);
                }
            }
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
                );
                // Subscribe may have created the transport (subscribe-only participant);
                // map it so SessionEvent::Established activates the subscriptions.
                if let Some(tid) = self.negotiation.transport_id(participant_id) {
                    self.subscription
                        .register_transport(tid.value(), participant_id);
                }
            }
            SignalMessage::Unsubscribe { track_ids } => {
                self.subscription.handle_unsubscribe(
                    participant_id,
                    &track_ids,
                    &mut self.negotiation,
                    &self.sessions,
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
                    &self.negotiation,
                    &self.sessions,
                );
            }
            SignalMessage::Leave => {
                self.rooms.handle_leave(participant_id, &mut self.sessions);
                self.cleanup_participant(participant_id);
            }
            SignalMessage::Ping => {
                if let Some(h) = self.sessions.get(&participant_id) {
                    let _ = h.outbound_tx.try_send(SignalMessage::Pong);
                }
            }
            SignalMessage::Unpublish { track_ids } => {
                // Remove each track from participant's published_tracks, ssrc_router, and notify peers
                let room_id = self.sessions.get(&participant_id).and_then(|h| h.room_id);

                for &track_id in &track_ids {
                    // Remove SSRC mappings via the negotiation manager's ssrc_router
                    self.negotiation.ssrc_router().remove_by_track(track_id);

                    // Remove from negotiation state's published_tracks
                    if let Some(state) = self.negotiation.states.get_mut(&participant_id) {
                        state.published_tracks.retain(|&t| t != track_id);
                    }

                    // Remove from session handle's published_tracks
                    if let Some(handle) = self.sessions.get_mut(&participant_id) {
                        handle.published_tracks.retain(|&t| t != track_id);
                    }

                    // Notify room peers about unpublished track
                    if let Some(rid) = room_id {
                        let participants =
                            self.subscription.distributed_state().get_participants(rid);
                        for &pid in participants.iter().take(1000) {
                            if pid == participant_id {
                                continue;
                            }
                            if let Some(h) = self.sessions.get(&pid) {
                                let _ = h
                                    .outbound_tx
                                    .try_send(SignalMessage::TrackUnpublished { track_id });
                            }
                        }
                    }
                }

                info!(
                    "Participant {} unpublished {} tracks",
                    participant_id,
                    track_ids.len()
                );
            }
            _ => {
                debug!("Unhandled message type from {}", participant_id);
            }
        }
    }

    /// Copy the participant's registered tracks from negotiation state onto its session handle.
    fn sync_published_tracks(&mut self, participant_id: u64) {
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

    fn handle_participant_disconnected(&mut self, participant_id: u64) {
        if participant_id == 0 {
            return;
        }
        self.rooms
            .handle_disconnected(participant_id, &mut self.sessions);
        self.cleanup_participant(participant_id);
    }

    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Established { session_id } => {
                self.subscription
                    .handle_session_established(session_id, &mut self.negotiation);
            }
            SessionEvent::Disconnected { session_id, reason } => {
                // Find participant by transport and clean up
                if let Some(&pid) = self
                    .subscription
                    .transport_to_participant()
                    .get(&session_id)
                {
                    info!(
                        "Transport {} disconnected ({:?}), cleaning up participant {}",
                        session_id, reason, pid
                    );
                    self.rooms.handle_disconnected(pid, &mut self.sessions);
                    self.cleanup_participant(pid);
                }
            }
        }
    }

    fn cleanup_participant(&mut self, participant_id: u64) {
        // Notify room about unpublished tracks
        if let Some(handle) = self.sessions.get(&participant_id) {
            if let Some(room_id) = handle.room_id {
                let participants = self
                    .subscription
                    .distributed_state()
                    .get_participants(room_id);
                for &track_id in &handle.published_tracks {
                    for &pid in participants.iter().take(1000) {
                        if pid == participant_id {
                            continue;
                        }
                        if let Some(h) = self.sessions.get(&pid) {
                            let _ = h
                                .outbound_tx
                                .try_send(SignalMessage::TrackUnpublished { track_id });
                        }
                    }
                }
            }
        }

        self.subscription.cleanup_participant(participant_id);
        self.negotiation.cleanup_participant(participant_id);
        self.sessions.remove(&participant_id);
        info!("Participant {} fully cleaned up", participant_id);
    }
}
