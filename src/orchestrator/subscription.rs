//! SubscriptionManager: subscribe/unsubscribe, viewport, content type,
//! and deferred media activation when sessions become Established.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::signal::SignalMessage;
use crate::types::TrackId;
use crate::worker::WorkerPool;
use nexus_state::DistributedState;
use nexus_transport::srtp::SrtpContext;

use super::negotiation::NegotiationManager;
use super::ParticipantHandle;

const MAX_TRACKS_PER_PARTICIPANT: u32 = 10;

/// Subscription negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubState {
    /// Included in SDP offer, waiting for answer.
    Negotiating,
    /// Answer received, media flowing.
    Active,
}

/// Per-participant subscription state.
pub struct SubscriptionState {
    pub subscribed_tracks: Vec<(TrackId, SubState)>,
}

impl SubscriptionState {
    pub fn new() -> Self {
        Self {
            subscribed_tracks: Vec::with_capacity(32),
        }
    }

    pub fn track_ids(&self) -> Vec<TrackId> {
        self.subscribed_tracks.iter().map(|(tid, _)| *tid).collect()
    }
}

pub struct SubscriptionManager {
    pub(crate) states: HashMap<u64, SubscriptionState>,
    worker_pool: Arc<RwLock<WorkerPool>>,
    distributed_state: Arc<DistributedState>,
    /// Reverse map: transport_id → participant_id.
    transport_to_participant: HashMap<u64, u64>,
}

impl SubscriptionManager {
    pub fn new(
        worker_pool: Arc<RwLock<WorkerPool>>,
        distributed_state: Arc<DistributedState>,
    ) -> Self {
        Self {
            states: HashMap::with_capacity(1024),
            worker_pool,
            distributed_state,
            transport_to_participant: HashMap::with_capacity(1024),
        }
    }

    pub fn add_participant(&mut self, participant_id: u64) {
        self.states.insert(participant_id, SubscriptionState::new());
    }

    pub fn remove_participant(&mut self, participant_id: u64) {
        self.states.remove(&participant_id);
        self.transport_to_participant.retain(|_, &mut pid| pid != participant_id);
    }

    /// Register the transport_id → participant_id mapping.
    /// Called by the dispatcher when NegotiationManager creates a transport.
    pub fn register_transport(&mut self, transport_id: u64, participant_id: u64) {
        self.transport_to_participant.insert(transport_id, participant_id);
    }

    // ── Subscribe ────────────────────────────────────────────────────

    pub fn handle_subscribe(
        &mut self,
        participant_id: u64,
        track_ids: &[u64],
        negotiation: &mut NegotiationManager,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let handle = match sessions.get(&participant_id) {
            Some(h) => h,
            None => return,
        };
        if handle.room_id.is_none() {
            send_error(sessions, participant_id, "NOT_IN_ROOM", "Must join a room first");
            return;
        }

        let mut accepted: Vec<u64> = Vec::with_capacity(track_ids.len().min(MAX_TRACKS_PER_PARTICIPANT as usize));
        for &tid in track_ids {
            if tid == 0 { continue; }
            if state.subscribed_tracks.iter().any(|(t, _)| *t == tid) { continue; }
            if accepted.contains(&tid) { continue; }
            if accepted.len() >= MAX_TRACKS_PER_PARTICIPANT as usize { break; }
            accepted.push(tid);
        }
        if accepted.is_empty() { return; }

        for &tid in &accepted {
            state.subscribed_tracks.push((tid, SubState::Negotiating));
        }

        send_to(sessions, participant_id, SignalMessage::Subscribed {
            track_ids: accepted.clone(),
        });

        info!("Participant {} subscribed to {} tracks (negotiating)", participant_id, accepted.len());

        // Trigger renegotiation or queue it
        let neg_state = negotiation.states.get_mut(&participant_id);
        let should_renegotiate = match neg_state {
            Some(ns) if ns.offer_pending => {
                ns.renegotiation_needed = true;
                false
            }
            Some(_) => true,
            None => false,
        };
        if should_renegotiate {
            negotiation.trigger_subscriber_renegotiation(participant_id, sessions);
        }
    }

    // ── Unsubscribe ──────────────────────────────────────────────────

    pub fn handle_unsubscribe(
        &mut self,
        participant_id: u64,
        track_ids: &[u64],
        negotiation: &mut NegotiationManager,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;
        let mut removed: Vec<u64> = Vec::with_capacity(track_ids.len());

        for &tid in track_ids {
            let was_active = state.subscribed_tracks.iter()
                .any(|(t, s)| *t == tid && *s == SubState::Active);
            if was_active {
                let pool = self.worker_pool.read();
                let _ = pool.remove_subscriber(tid, subscriber_id);
                let _ = self.distributed_state.remove_subscription(tid, participant_id);
            }
            let before = state.subscribed_tracks.len();
            state.subscribed_tracks.retain(|(t, _)| *t != tid);
            if state.subscribed_tracks.len() < before {
                removed.push(tid);
            }
        }
        if removed.is_empty() { return; }

        send_to(sessions, participant_id, SignalMessage::Unsubscribed { track_ids: removed });

        let should_renegotiate = match negotiation.states.get_mut(&participant_id) {
            Some(ns) if ns.offer_pending => { ns.renegotiation_needed = true; false }
            Some(_) => true,
            None => false,
        };
        if should_renegotiate {
            negotiation.trigger_subscriber_renegotiation(participant_id, sessions);
        }
    }

    // ── Viewport ─────────────────────────────────────────────────────

    pub fn handle_viewport(
        &self,
        participant_id: u64,
        visible: &[u64],
        pinned: &[u64],
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);

        let state = match self.states.get(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;
        let visible_u32: Vec<u32> = visible.iter().map(|&id| id as u32).collect();
        let pinned_u32: Vec<u32> = pinned.iter().map(|&id| id as u32).collect();
        let pool = self.worker_pool.read();

        for &(track_id, _) in &state.subscribed_tracks {
            let _ = pool.update_viewport(track_id, subscriber_id, visible_u32.clone(), pinned_u32.clone());
        }

        send_to(sessions, participant_id, SignalMessage::ViewportUpdated {
            visible_count: visible.len() as u32,
            pinned_count: pinned.len() as u32,
        });
    }

    // ── Content Type ─────────────────────────────────────────────────

    pub fn handle_set_content(
        &self,
        participant_id: u64,
        track_id: u64,
        content: &str,
        negotiation: &NegotiationManager,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);

        let content_type: u8 = match content {
            "camera" => 0, "screen" => 1, "audio" => 2,
            _ => {
                send_error(sessions, participant_id, "INVALID_CONTENT", &format!("Unknown: {}", content));
                return;
            }
        };

        let owns_track = negotiation.states.get(&participant_id)
            .map(|s| s.published_tracks.contains(&track_id))
            .unwrap_or(false);
        if !owns_track {
            send_error(sessions, participant_id, "NOT_OWNER", "Cannot set content on a track you don't own");
            return;
        }

        let pool = self.worker_pool.read();
        let _ = pool.set_content_type(track_id, content_type);

        send_to(sessions, participant_id, SignalMessage::ContentSet {
            track_id,
            content: content.to_string(),
        });
    }

    // ── Session Established (THE BUG FIX) ────────────────────────────

    /// Called when ConnectionMonitor detects a session reached Established.
    /// Activates all Negotiating subscriptions by creating SRTP contexts
    /// and wiring subscribers in the worker pool.
    pub fn handle_session_established(
        &mut self,
        session_id: u64,
        negotiation: &mut NegotiationManager,
    ) {
        let participant_id = match self.transport_to_participant.get(&session_id) {
            Some(&pid) => pid,
            None => {
                debug!("No participant for transport {}", session_id);
                return;
            }
        };

        let pending_mid_map = negotiation.take_pending_mid_map(participant_id);
        if pending_mid_map.is_empty() { return; }

        let dest_addr = match negotiation.selected_remote_addr(participant_id) {
            Some(addr) => addr,
            None => {
                warn!("No selected pair for participant {} after establishment", participant_id);
                return;
            }
        };

        let srtp_key_material = negotiation.get_srtp_key_material(participant_id);
        let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        for (track_id, _mid_str) in &pending_mid_map {
            let srtp_ctx = match &srtp_key_material {
                Some((km, policy, _epoch)) => match SrtpContext::new(km, *policy) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        warn!("SRTP context failed for track {}: {:?}", track_id, e);
                        continue;
                    }
                },
                None => continue,
            };

            let pool = self.worker_pool.read();
            if let Err(e) = pool.add_subscriber(
                *track_id, subscriber_id, participant_id,
                dest_addr, 0, srtp_ctx,
            ) {
                warn!("Failed to add subscriber for track {}: {:?}", track_id, e);
                continue;
            }

            let _ = self.distributed_state.add_subscription(*track_id, participant_id);

            for (tid, sub_state) in state.subscribed_tracks.iter_mut() {
                if *tid == *track_id && *sub_state == SubState::Negotiating {
                    *sub_state = SubState::Active;
                }
            }
        }

        info!("Media activated for participant {} ({} tracks)", participant_id, pending_mid_map.len());
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    pub fn transport_to_participant(&self) -> &HashMap<u64, u64> {
        &self.transport_to_participant
    }

    pub fn worker_pool(&self) -> &Arc<RwLock<WorkerPool>> {
        &self.worker_pool
    }

    pub fn distributed_state(&self) -> &Arc<DistributedState> {
        &self.distributed_state
    }

    pub fn cleanup_participant(&mut self, participant_id: u64) {
        if let Some(state) = self.states.remove(&participant_id) {
            let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;
            for (track_id, sub_state) in &state.subscribed_tracks {
                if *sub_state == SubState::Active {
                    let pool = self.worker_pool.read();
                    let _ = pool.remove_subscriber(*track_id, subscriber_id);
                    let _ = self.distributed_state.remove_subscription(*track_id, participant_id);
                }
            }
        }
        self.transport_to_participant.retain(|_, &mut pid| pid != participant_id);
    }
}

fn send_to(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, msg: SignalMessage) {
    if let Some(handle) = sessions.get(&participant_id) {
        let _ = handle.outbound_tx.send(msg);
    }
}

fn send_error(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, code: &str, message: &str) {
    send_to(sessions, participant_id, SignalMessage::Error {
        code: code.to_string(),
        message: message.to_string(),
    });
}
