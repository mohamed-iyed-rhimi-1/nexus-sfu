//! Session Orchestrator — thin dispatcher over specialized managers.
//!
//! Routes signaling events, ICE gathering results, cold-path packets,
//! and timer ticks to the appropriate manager. Owns the shared
//! `ParticipantHandle` table.

pub mod connection;
pub mod events;
pub mod negotiation;
pub mod room;
pub mod subscription;

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
    pub outbound_tx: mpsc::UnboundedSender<SignalMessage>,
    pub room_id: Option<u32>,
    pub published_tracks: Vec<TrackId>,
}

impl ParticipantHandle {
    pub fn subscribed_track_ids(&self) -> Vec<TrackId> {
        // Delegated to SubscriptionManager — this is a convenience accessor
        Vec::new()
    }
}

pub struct SessionOrchestrator {
    sessions: HashMap<u64, ParticipantHandle>,
    rooms: RoomManager,
    negotiation: NegotiationManager,
    subscription: SubscriptionManager,
    connection: ConnectionMonitor,
    /// Relay manager for inter-node cascade.
    relay_manager: Option<Arc<parking_lot::RwLock<crate::relay::manager::RelayManager>>>,
    local_node_id: u64,
    relay_event_rx: Option<mpsc::UnboundedReceiver<nexus_state::gossip::RelayEvent>>,
}

impl SessionOrchestrator {
    pub fn new(
        webrtc_transport: Arc<WebRtcTransport>,
        ssrc_router: Arc<SsrcRouter>,
        _actor_manager: Arc<crate::nexus_actor::ActorManager>,
        distributed_state: Arc<DistributedState>,
        worker_pool: Arc<RwLock<WorkerPool>>,
        media_bind_addr: SocketAddr,
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
                media_bind_addr,
            ),
            subscription: SubscriptionManager::new(
                worker_pool,
                distributed_state,
            ),
            connection: ConnectionMonitor::new(
                webrtc_transport,
                packet_sender,
            ),
            relay_manager: None,
            local_node_id: 0,
            relay_event_rx: None,
        }
    }

    pub fn set_relay_manager(
        &mut self,
        relay_manager: Arc<parking_lot::RwLock<crate::relay::manager::RelayManager>>,
        local_node_id: u64,
        relay_event_rx: mpsc::UnboundedReceiver<nexus_state::gossip::RelayEvent>,
    ) {
        self.relay_manager = Some(relay_manager);
        self.local_node_id = local_node_id;
        self.relay_event_rx = Some(relay_event_rx);
    }

    pub fn set_relay_event_rx(&mut self, rx: mpsc::UnboundedReceiver<nexus_state::gossip::RelayEvent>) {
        self.relay_event_rx = Some(rx);
    }

    /// Main event loop.
    pub async fn run(
        &mut self,
        mut event_rx: mpsc::Receiver<OrchestratorEvent>,
        mut connection_rx: mpsc::Receiver<ColdPathPacket>,
    ) {
        loop {
            tokio::select! {
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
                Some(relay_event) = async {
                    match self.relay_event_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.process_relay_events(vec![relay_event]);
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
            OrchestratorEvent::Connected { participant_id, outbound_tx } => {
                self.handle_connected(participant_id, outbound_tx);
            }
            OrchestratorEvent::Message { participant_id, message } => {
                self.handle_message(participant_id, message);
            }
            OrchestratorEvent::Disconnected { participant_id } => {
                self.handle_participant_disconnected(participant_id);
            }
        }
    }

    fn handle_connected(&mut self, participant_id: u64, outbound_tx: mpsc::UnboundedSender<SignalMessage>) {
        assert!(participant_id != 0);
        self.sessions.insert(participant_id, ParticipantHandle {
            outbound_tx,
            room_id: None,
            published_tracks: Vec::with_capacity(10),
        });
        self.negotiation.add_participant(participant_id);
        self.subscription.add_participant(participant_id);
        debug!("Participant {} connected", participant_id);
    }

    fn handle_message(&mut self, participant_id: u64, message: SignalMessage) {
        assert!(participant_id != 0);
        match message {
            SignalMessage::Create { room_name } => {
                self.rooms.handle_create(participant_id, room_name, &self.sessions);
            }
            SignalMessage::Join { room_id, participant_name } => {
                self.rooms.handle_join(participant_id, room_id, &participant_name, &mut self.sessions);
            }
            SignalMessage::Publish { kinds, contents } => {
                self.negotiation.handle_publish(participant_id, &kinds, &contents, &self.sessions);
                // Register transport → participant mapping for SubscriptionManager
                if let Some(tid) = self.negotiation.transport_id(participant_id) {
                    self.subscription.register_transport(tid.value(), participant_id);
                    if let Some(handle) = self.sessions.get_mut(&participant_id) {
                        handle.published_tracks = self.negotiation.states
                            .get(&participant_id)
                            .map(|s| s.published_tracks.clone())
                            .unwrap_or_default();
                    }
                }
            }
            SignalMessage::Answer { sdp } => {
                self.negotiation.handle_answer(participant_id, &sdp, &self.sessions);
            }
            SignalMessage::IceCandidate { candidate, .. } => {
                self.negotiation.handle_candidate(participant_id, &candidate);
            }
            SignalMessage::Subscribe { track_ids } => {
                self.subscription.handle_subscribe(
                    participant_id, &track_ids, &mut self.negotiation, &self.sessions,
                );
            }
            SignalMessage::Unsubscribe { track_ids } => {
                self.subscription.handle_unsubscribe(
                    participant_id, &track_ids, &mut self.negotiation, &self.sessions,
                );
            }
            SignalMessage::Viewport { visible, pinned } => {
                self.subscription.handle_viewport(participant_id, &visible, &pinned, &self.sessions);
            }
            SignalMessage::SetContent { track_id, content } => {
                self.subscription.handle_set_content(
                    participant_id, track_id, &content, &self.negotiation, &self.sessions,
                );
            }
            SignalMessage::Leave => {
                self.rooms.handle_leave(participant_id, &mut self.sessions);
                self.cleanup_participant(participant_id);
            }
            SignalMessage::Ping => {
                if let Some(h) = self.sessions.get(&participant_id) {
                    let _ = h.outbound_tx.send(SignalMessage::Pong);
                }
            }
            _ => {
                debug!("Unhandled message type from {}", participant_id);
            }
        }
    }

    fn handle_participant_disconnected(&mut self, participant_id: u64) {
        assert!(participant_id != 0);
        self.rooms.handle_disconnected(participant_id, &mut self.sessions);
        self.cleanup_participant(participant_id);
    }

    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Established { session_id } => {
                self.subscription.handle_session_established(
                    session_id, &mut self.negotiation,
                );
            }
            SessionEvent::Disconnected { session_id, reason } => {
                // Find participant by transport and clean up
                if let Some(&pid) = self.subscription.transport_to_participant().get(&session_id) {
                    info!("Transport {} disconnected ({:?}), cleaning up participant {}", session_id, reason, pid);
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
                let participants = self.subscription.distributed_state().get_participants(room_id);
                for &track_id in &handle.published_tracks {
                    for &pid in participants.iter().take(1000) {
                        if pid == participant_id { continue; }
                        if let Some(h) = self.sessions.get(&pid) {
                            let _ = h.outbound_tx.send(SignalMessage::TrackUnpublished { track_id });
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

    fn process_relay_events(&mut self, events: Vec<nexus_state::gossip::RelayEvent>) {
        let pool = self.subscription.worker_pool();
        let pool = pool.read();
        for event in events {
            match event {
                nexus_state::gossip::RelayEvent::Subscribe { track_id, requester_node } => {
                    let _ = pool.add_relay_subscriber(track_id, requester_node);
                }
                nexus_state::gossip::RelayEvent::Unsubscribe { track_id, requester_node } => {
                    let sub_id = (requester_node & 0x7FFFFFFF) as u32 | 0x80000000;
                    let _ = pool.remove_subscriber(track_id, sub_id);
                }
            }
        }
    }
}
