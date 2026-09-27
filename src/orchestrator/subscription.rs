//! SubscriptionManager: what each participant asked to receive (design note §6.5).
//!
//! A subscription is `Negotiating` from `Subscribe` until the answer that puts it on the
//! shard, then `Active`. Viewport and content type are recorded and confirmed; they have
//! no data-plane effect in v1.

use std::collections::HashMap;

use nexus_dataplane::{TrackId as DpTrackId, MAX_SUBS_PER_SESSION};
use tracing::info;

use crate::signal::SignalMessage;
use crate::types::TrackId;

use super::negotiation::{send_error, send_to, NegotiationManager};
use super::plane::Plane;
use super::ParticipantHandle;

/// Most track ids in one `Subscribe` request; more is an error, not a silent cut.
pub const MAX_TRACKS_PER_REQUEST: usize = 10;

/// Subscription negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubState {
    /// Included in an offer, not on the shard yet.
    Negotiating,
    /// The answer put it on the shard: media flows.
    Active,
}

/// Per-participant subscription state.
#[derive(Default)]
pub struct SubscriptionState {
    pub subscribed_tracks: Vec<(TrackId, SubState)>,
}

impl SubscriptionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track_ids(&self) -> Vec<TrackId> {
        self.subscribed_tracks.iter().map(|(tid, _)| *tid).collect()
    }
}

#[derive(Default)]
pub struct SubscriptionManager {
    pub(crate) states: HashMap<u64, SubscriptionState>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            states: HashMap::with_capacity(1024),
        }
    }

    pub fn add_participant(&mut self, participant_id: u64) {
        self.states.insert(participant_id, SubscriptionState::new());
    }

    /// The participant's current subscription set.
    pub fn track_ids(&self, participant_id: u64) -> Vec<TrackId> {
        self.states
            .get(&participant_id)
            .map(SubscriptionState::track_ids)
            .unwrap_or_default()
    }

    // ── Subscribe ────────────────────────────────────────────────────

    pub fn handle_subscribe(
        &mut self,
        participant_id: u64,
        track_ids: &[u64],
        negotiation: &mut NegotiationManager,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let Some(room) = sessions.get(&participant_id).and_then(|h| h.room_id) else {
            send_error(
                sessions,
                participant_id,
                "NOT_IN_ROOM",
                "Must join a room first",
            );
            return;
        };
        if track_ids.len() > MAX_TRACKS_PER_REQUEST {
            let message = format!("At most {MAX_TRACKS_PER_REQUEST} tracks per request");
            send_error(sessions, participant_id, "TOO_MANY_TRACKS", &message);
            return;
        }
        // Only tracks published in the subscriber's own room; unknown and foreign ids
        // are left out of `Subscribed`.
        let mut accepted: Vec<u64> = Vec::with_capacity(track_ids.len());
        for &tid in track_ids {
            let in_room = tid != 0
                && plane
                    .tracks
                    .get(DpTrackId::new(tid))
                    .is_some_and(|info| info.room == room);
            let new = !state.subscribed_tracks.iter().any(|(t, _)| *t == tid);
            if in_room && new && !accepted.contains(&tid) {
                accepted.push(tid);
            }
        }
        if accepted.is_empty() {
            return;
        }
        if state.subscribed_tracks.len() + accepted.len() > MAX_SUBS_PER_SESSION {
            let message = format!("At most {MAX_SUBS_PER_SESSION} subscriptions");
            send_error(sessions, participant_id, "TOO_MANY_TRACKS", &message);
            return;
        }
        for &tid in &accepted {
            state.subscribed_tracks.push((tid, SubState::Negotiating));
        }
        info!(
            "Participant {} subscribed to {} tracks (negotiating)",
            participant_id,
            accepted.len()
        );
        send_to(
            sessions,
            participant_id,
            SignalMessage::Subscribed {
                track_ids: accepted,
            },
        );
        let ids = state.track_ids();
        negotiation.request_renegotiation(participant_id, ids, sessions, plane);
    }

    // ── Unsubscribe ──────────────────────────────────────────────────

    pub fn handle_unsubscribe(
        &mut self,
        participant_id: u64,
        track_ids: &[u64],
        negotiation: &mut NegotiationManager,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let mut removed: Vec<u64> = Vec::with_capacity(track_ids.len());
        for &tid in track_ids {
            let Some(pos) = state.subscribed_tracks.iter().position(|(t, _)| *t == tid) else {
                continue;
            };
            let (_, sub_state) = state.subscribed_tracks.remove(pos);
            if sub_state == SubState::Active {
                let _ = plane.state.remove_subscription(tid, participant_id);
            }
            removed.push(tid);
        }
        if removed.is_empty() {
            return;
        }
        negotiation.drop_subscriptions(participant_id, &removed, plane);
        send_to(
            sessions,
            participant_id,
            SignalMessage::Unsubscribed { track_ids: removed },
        );
        let ids = state.track_ids();
        negotiation.request_renegotiation(participant_id, ids, sessions, plane);
    }

    /// The answer put these subscriptions on the shard.
    pub fn activate(&mut self, participant_id: u64, tracks: &[TrackId], plane: &Plane) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        for (tid, sub_state) in state.subscribed_tracks.iter_mut() {
            if *sub_state == SubState::Negotiating && tracks.contains(tid) {
                *sub_state = SubState::Active;
                let _ = plane.state.add_subscription(*tid, participant_id);
            }
        }
    }

    /// Tracks removed from the shard: they leave every subscription set.
    pub fn forget_tracks(&mut self, tracks: &[TrackId], plane: &Plane) -> Vec<u64> {
        let mut affected = Vec::new();
        for (&participant_id, state) in self.states.iter_mut() {
            let before = state.subscribed_tracks.len();
            state.subscribed_tracks.retain(|(t, sub_state)| {
                let gone = tracks.contains(t);
                if gone && *sub_state == SubState::Active {
                    let _ = plane.state.remove_subscription(*t, participant_id);
                }
                !gone
            });
            if state.subscribed_tracks.len() != before {
                affected.push(participant_id);
            }
        }
        affected.sort_unstable();
        affected
    }

    // ── Viewport, content type ───────────────────────────────────────

    /// Confirmed only: viewport-based forwarding is not in v1.
    pub fn handle_viewport(
        &self,
        participant_id: u64,
        visible: &[u64],
        pinned: &[u64],
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        if !self.states.contains_key(&participant_id) {
            return;
        }
        send_to(
            sessions,
            participant_id,
            SignalMessage::ViewportUpdated {
                visible_count: visible.len() as u32,
                pinned_count: pinned.len() as u32,
            },
        );
    }

    /// Record a track's content type (owner only); no data-plane effect in v1.
    pub fn handle_set_content(
        &self,
        participant_id: u64,
        track_id: u64,
        content: &str,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let content_type: u8 = match content {
            "camera" => 0,
            "screen" => 1,
            "audio" => 2,
            _ => {
                let message = format!("Unknown: {}", content);
                send_error(sessions, participant_id, "INVALID_CONTENT", &message);
                return;
            }
        };
        let info = (track_id != 0)
            .then(|| plane.tracks.get_mut(DpTrackId::new(track_id)))
            .flatten()
            .filter(|info| info.publisher == participant_id);
        let Some(info) = info else {
            let message = "Cannot set content on a track you don't own";
            send_error(sessions, participant_id, "NOT_OWNER", message);
            return;
        };
        info.content_type = content_type;
        send_to(
            sessions,
            participant_id,
            SignalMessage::ContentSet {
                track_id,
                content: content.to_string(),
            },
        );
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    pub fn cleanup_participant(&mut self, participant_id: u64, plane: &Plane) {
        if let Some(state) = self.states.remove(&participant_id) {
            for (track_id, _) in &state.subscribed_tracks {
                let _ = plane.state.remove_subscription(*track_id, participant_id);
            }
        }
    }
}
