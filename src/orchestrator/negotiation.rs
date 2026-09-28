//! NegotiationManager: sessions, SDP offers and answers, and the m-lines of each
//! participant (design note §6.1, §6.2, §6.5).
//!
//! The SFU is always the offerer. A participant's m-lines keep their mid and position
//! in every offer (RFC 3264 §8); publish m-lines become `AddTrack` commands and answered
//! subscribe m-lines `Subscribe` commands when the answer arrives.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_dataplane::{
    Command, SessionId, SubscriptionId, TrackId as DpTrackId, TrackRef, MAX_SUBS_PER_SESSION,
    MAX_TRACKS_PER_SESSION,
};
use nexus_media::rtp::extensions;
use nexus_state::gossip::types::TrackInfo as StateTrackInfo;
use nexus_transport::dtls::DtlsRole;
use nexus_transport::ice::{Candidate, MAX_CANDIDATES};
use nexus_webrtc::sdp::{
    offered_extmaps, Direction, DtlsFingerprint, ExtMap, FingerprintAlgorithm, MediaDescription,
    OfferMline, RecycledMline, RtpCodec, SdpNegotiator, SdpParser, SessionDescription,
    MAX_MEDIA_SECTIONS,
};
use tracing::{debug, info, warn};

use crate::signal::{OfferTrack, SignalMessage};
use crate::types::TrackId;

use super::events::DisconnectReason;
use super::plane::Plane;
use super::sdp_params::{sub_spec, track_spec};
use super::tracks::TrackInfo;
use super::ParticipantHandle;

/// Most participants notified of one published track.
const MAX_PARTICIPANTS_PER_ROOM: usize = 1_000;
/// RTCP feedback on video m-lines, both directions (note §12.4): keyframe requests.
/// No NACK, REMB or transport-cc in v1.
const V1_VIDEO_FBS: &[(&str, &str)] = &[("nack", "pli"), ("ccm", "fir")];
/// Audio m-lines ask for no feedback.
const V1_AUDIO_FBS: &[(&str, &str)] = &[];
/// Offers repeated after invalid answers in a row before the m-lines are released.
const MAX_REOFFERS: u8 = 1;

/// A subscribe m-line: the forwarded track, its subscription id and out SSRC
/// (allocated when the slot is filled), and whether the shard has the subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubSlot {
    /// Signaling track id.
    pub track: TrackId,
    /// Data-plane subscription id.
    pub sub: SubscriptionId,
    /// SSRC the SFU sends the track under on this m-line.
    pub out_ssrc: u32,
    /// `Subscribe` was pushed (the answer accepted the m-line).
    pub on_shard: bool,
}

/// What a negotiated m-line carries. Once offered, an m-line keeps its mid and
/// position in every later offer; only its role changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlineRole {
    /// Participant publishes to the SFU (recvonly from the SFU's side).
    Publish,
    /// SFU forwards a subscribed track (sendonly).
    Subscribe(SubSlot),
    /// No longer used; reusable by a later subscription of the same kind.
    Inactive,
}

impl MlineRole {
    /// The subscribed track, for a subscribe m-line.
    pub fn subscribed_track(&self) -> Option<TrackId> {
        match self {
            MlineRole::Subscribe(slot) => Some(slot.track),
            _ => None,
        }
    }
}

/// One m-line of a participant's session.
#[derive(Debug, Clone)]
pub struct MlineSlot {
    pub mid: String,
    /// 0 = audio, 1 = video.
    pub kind: u8,
    pub role: MlineRole,
}

/// Per-participant negotiation state.
#[derive(Default)]
pub struct NegotiationState {
    /// The participant's data-plane session, from its first offer on.
    pub session: Option<SessionId>,
    /// Tracks registered from this participant's answers.
    pub published_tracks: Vec<TrackId>,
    pub offer_pending: bool,
    pub renegotiation_needed: bool,
    /// Next mid to allocate for a new m-line.
    pub next_mid_index: u32,
    /// The session's m-lines in offer order.
    pub mlines: Vec<MlineSlot>,
    /// Publish mids whose tracks get registered from the next answer.
    pub unregistered_publish_mids: Vec<String>,
    /// Publish request that arrived while an offer was outstanding.
    pub pending_publish: Option<Vec<(String, String)>>,
    /// Subscription set to offer once the outstanding offer is answered.
    pub last_subscribed_track_ids: Vec<TrackId>,
    /// Local candidates were trickled (once per session).
    pub candidates_sent: bool,
    /// Invalid answers in a row (bounds the re-offers after them).
    pub invalid_answers: u8,
    /// SDP session ID (RFC 3264 §8).
    pub session_id: u64,
    /// SDP session version, incremented per offer (RFC 3264 §8).
    pub session_version: u64,
}

impl NegotiationState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Why an answer was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// No offer outstanding (or no such participant): ignored.
    NotExpected,
    /// Unparsable, or not an answer to the offer: the offer is settled.
    Invalid,
}

/// What an answer changed, for the other managers.
#[derive(Debug, Default)]
pub struct AnswerOutcome {
    /// Tracks whose subscriptions went onto the shard.
    pub activated: Vec<TrackId>,
}

pub struct NegotiationManager {
    pub(crate) states: HashMap<u64, NegotiationState>,
}

impl Default for NegotiationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NegotiationManager {
    pub fn new() -> Self {
        Self {
            states: HashMap::with_capacity(1024),
        }
    }

    pub fn add_participant(&mut self, participant_id: u64) {
        self.states.insert(participant_id, NegotiationState::new());
    }

    /// The participant's data-plane session.
    pub fn session(&self, participant_id: u64) -> Option<SessionId> {
        self.states.get(&participant_id).and_then(|s| s.session)
    }

    // ── Sessions ─────────────────────────────────────────────────────

    /// The participant's session, created (with `CreateSession`) on first use.
    fn ensure_session(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) -> Option<SessionId> {
        let state = self.states.get_mut(&participant_id)?;
        if let Some(id) = state.session {
            return Some(id);
        }
        let room = sessions.get(&participant_id).and_then(|h| h.room_id);
        let Some(id) = plane.create_session(participant_id, room) else {
            send_error(sessions, participant_id, "SESSION_FAILED", "No session");
            return None;
        };
        state.session = Some(id);
        state.session_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1);
        state.session_version = 0;
        assert!(state.session.is_some());
        Some(id)
    }

    // ── Publish ──────────────────────────────────────────────────────

    pub fn handle_publish(
        &mut self,
        participant_id: u64,
        kinds: &[String],
        contents: &[String],
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        if participant_id == 0 || kinds.len() != contents.len() {
            return;
        }
        if sessions
            .get(&participant_id)
            .and_then(|h| h.room_id)
            .is_none()
        {
            send_error(
                sessions,
                participant_id,
                "NOT_IN_ROOM",
                "Must join a room first",
            );
            return;
        }
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        // Only audio/video m-lines are offered.
        let published: Vec<(String, String)> = kinds
            .iter()
            .zip(contents)
            .filter(|(k, _)| k.as_str() == "audio" || k.as_str() == "video")
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        if published.is_empty() {
            return;
        }
        // The shard holds at most MAX_TRACKS_PER_SESSION tracks per session: published,
        // in the outstanding offer, and queued.
        let queued = state.pending_publish.as_ref().map_or(0, Vec::len);
        let tracks = state.published_tracks.len() + state.unregistered_publish_mids.len() + queued;
        if tracks + published.len() > MAX_TRACKS_PER_SESSION
            || state.mlines.len() + published.len() > MAX_MEDIA_SECTIONS
        {
            let message = format!("At most {MAX_TRACKS_PER_SESSION} published tracks");
            send_error(sessions, participant_id, "TOO_MANY_TRACKS", &message);
            return;
        }
        // One offer at a time: queue this publish until the pending answer arrives.
        if state.offer_pending {
            state
                .pending_publish
                .get_or_insert_with(Vec::new)
                .extend(published);
            return;
        }
        if self
            .ensure_session(participant_id, sessions, plane)
            .is_none()
        {
            return;
        }
        let state = self.states.get_mut(&participant_id).expect("state exists");
        for (kind, _content) in &published {
            let kind = u8::from(kind.as_str() == "video");
            let mid = Self::claim_mline(state, kind, MlineRole::Publish);
            state.unregistered_publish_mids.push(mid);
        }
        self.send_ordered_offer(participant_id, sessions, plane);
    }

    /// Put `role` on an inactive m-line of `kind`, else on a new one; returns its mid.
    /// The caller checked `MAX_MEDIA_SECTIONS`.
    fn claim_mline(state: &mut NegotiationState, kind: u8, role: MlineRole) -> String {
        if let Some(free) = state
            .mlines
            .iter_mut()
            .find(|s| s.role == MlineRole::Inactive && s.kind == kind)
        {
            free.role = role;
            return free.mid.clone();
        }
        assert!(
            state.mlines.len() < MAX_MEDIA_SECTIONS,
            "m-line count checked"
        );
        let mid = state.next_mid_index.to_string();
        state.next_mid_index += 1;
        state.mlines.push(MlineSlot {
            mid: mid.clone(),
            kind,
            role,
        });
        mid
    }

    // ── Answer ───────────────────────────────────────────────────────

    /// Apply an answer to the outstanding offer: DTLS role and fingerprint, `AddTrack`
    /// per publish m-line, `Subscribe` per accepted subscribe m-line.
    pub fn handle_answer(
        &mut self,
        participant_id: u64,
        sdp: &str,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) -> AnswerOutcome {
        let mut outcome = AnswerOutcome::default();
        let (id, answer) = match self.accept_answer(participant_id, sdp, sessions) {
            Ok(accepted) => accepted,
            Err(Refused::Invalid) => {
                // The offer is settled: what waited for it goes out now, and what it
                // carried is offered again (once) so the client does not stall.
                self.after_answer(participant_id, sessions, plane);
                self.retry_unanswered(participant_id, sessions, plane);
                return outcome;
            }
            Err(Refused::NotExpected) => return outcome,
        };
        if !Self::apply_dtls(participant_id, id, &answer, plane) {
            return outcome;
        }
        let state = self.states.get_mut(&participant_id).expect("accepted");
        state.invalid_answers = 0;
        let publish_mids = std::mem::take(&mut state.unregistered_publish_mids);
        state.offer_pending = false;
        for media in &answer.media {
            let is_publish = media
                .mid
                .as_ref()
                .is_some_and(|m| publish_mids.iter().any(|p| p == m.as_str()));
            if is_publish && !self.register_publish(participant_id, id, media, sessions, plane) {
                // Refused: free the m-line for `claim_mline`, so the next offer does not
                // carry it as a publish m-line nobody will register
                let mid = media.mid.as_ref().map_or("", |m| m.as_str());
                self.release_unregistered_publish(participant_id, mid);
            }
        }
        outcome.activated =
            self.register_subscriptions(participant_id, id, &answer, sessions, plane);
        self.after_answer(participant_id, sessions, plane);
        info!("Answer processed from participant {}", participant_id);
        outcome
    }

    /// The parsed answer, if it answers the outstanding offer (same mids, same order).
    /// An unusable answer settles the offer with an error to the client (`Invalid`).
    fn accept_answer(
        &mut self,
        participant_id: u64,
        sdp: &str,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) -> Result<(SessionId, SessionDescription), Refused> {
        let state = self
            .states
            .get_mut(&participant_id)
            .ok_or(Refused::NotExpected)?;
        let (Some(id), true) = (state.session, state.offer_pending) else {
            debug!(
                "Answer from {} without an outstanding offer",
                participant_id
            );
            return Err(Refused::NotExpected);
        };
        match SdpParser::parse(sdp) {
            Ok(answer) if Self::mids_match(&answer, &state.mlines) => Ok((id, answer)),
            result => {
                warn!("Invalid answer from {}: {:?}", participant_id, result.err());
                state.offer_pending = false;
                send_error(sessions, participant_id, "INVALID_ANSWER", "Answer refused");
                Err(Refused::Invalid)
            }
        }
    }

    /// After an invalid answer with nothing else offered: offer the unanswered publish
    /// and subscribe m-lines again, once in a row. A second invalid answer releases the
    /// publish m-lines (inactive; the client may publish again) instead of looping.
    fn retry_unanswered(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let unanswered_subs = state
            .mlines
            .iter()
            .any(|m| matches!(m.role, MlineRole::Subscribe(s) if !s.on_shard));
        if state.offer_pending || (state.unregistered_publish_mids.is_empty() && !unanswered_subs) {
            return;
        }
        state.invalid_answers = state.invalid_answers.saturating_add(1);
        if state.invalid_answers <= MAX_REOFFERS {
            self.send_ordered_offer(participant_id, sessions, plane);
            return;
        }
        let mids = std::mem::take(&mut state.unregistered_publish_mids);
        for slot in state.mlines.iter_mut().filter(|m| mids.contains(&m.mid)) {
            slot.role = MlineRole::Inactive;
        }
        warn!(
            "Participant {} answered {} offers wrongly; publish m-lines released",
            participant_id, state.invalid_answers
        );
    }

    /// The answer has one m-line per offered m-line, same mids, same order.
    fn mids_match(answer: &SessionDescription, mlines: &[MlineSlot]) -> bool {
        answer.media.len() == mlines.len()
            && answer
                .media
                .iter()
                .zip(mlines)
                .all(|(m, slot)| m.mid.as_ref().is_some_and(|mid| mid.as_str() == slot.mid))
    }

    /// DTLS role and fingerprint from the answer into the handshake. `false` when the
    /// session is being closed.
    fn apply_dtls(
        participant_id: u64,
        id: SessionId,
        answer: &SessionDescription,
        plane: &mut Plane,
    ) -> bool {
        let params = Self::dtls_role_from_answer(answer).and_then(|role| {
            Ok((
                role,
                Self::extract_fingerprint(answer).ok_or("no sha-256 fingerprint")?,
            ))
        });
        let result = match (params, plane.transports.get_mut(id)) {
            (Ok((role, fingerprint)), Some(entry)) => entry
                .dtls
                .on_answer(role, fingerprint)
                .map_err(|e| e.to_string()),
            (Err(reason), _) => Err(reason.to_string()),
            (_, None) => return false,
        };
        match result {
            Ok(progress) => {
                plane.send_datagrams(id, progress.datagrams);
                if progress.completed {
                    plane.install_srtp(id);
                }
                true
            }
            Err(reason) => {
                warn!("Answer from participant {}: {}", participant_id, reason);
                plane.close_participant(participant_id, DisconnectReason::DtlsFailed);
                false
            }
        }
    }

    /// Our DTLS role given the answerer's `a=setup` (RFC 8842 §5.2): the answerer's
    /// `active` (or no attribute) makes us the server, `passive` the client.
    fn dtls_role_from_answer(sdp: &SessionDescription) -> Result<DtlsRole, &'static str> {
        use nexus_webrtc::sdp::DtlsSetup;
        let setup = sdp.setup.or_else(|| sdp.media.iter().find_map(|m| m.setup));
        match setup {
            None | Some(DtlsSetup::Active) => Ok(DtlsRole::Server),
            Some(DtlsSetup::Passive) => Ok(DtlsRole::Client),
            Some(DtlsSetup::Actpass) => Err("a=setup:actpass is not valid in an answer"),
            Some(DtlsSetup::Holdconn) => Err("a=setup:holdconn is not supported"),
        }
    }

    /// The first SHA-256 DTLS fingerprint, session level first, then the m-lines in
    /// order (bundled m-lines share one transport). Other algorithms are skipped, never
    /// truncated into a SHA-256 value.
    fn extract_fingerprint(sdp: &SessionDescription) -> Option<[u8; 32]> {
        let fp = sdp
            .fingerprint
            .iter()
            .chain(sdp.media.iter().filter_map(|m| m.fingerprint.as_ref()))
            .find(|fp| fp.algorithm == FingerprintAlgorithm::Sha256 && fp.value_len == 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&fp.value[..32]);
        Some(out)
    }

    /// Queued renegotiation and publish, once an answer settled the offer.
    fn after_answer(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let renegotiate = std::mem::take(&mut state.renegotiation_needed);
        let pending_publish = state.pending_publish.take();
        if renegotiate {
            let ids = state.last_subscribed_track_ids.clone();
            self.trigger_subscriber_renegotiation(participant_id, &ids, sessions, plane);
        }
        // If the renegotiation above sent an offer, this publish queues again.
        if let Some(published) = pending_publish {
            let (kinds, contents): (Vec<String>, Vec<String>) = published.into_iter().unzip();
            self.handle_publish(participant_id, &kinds, &contents, sessions, plane);
        }
    }

    // ── Tracks ───────────────────────────────────────────────────────

    /// One track per answered publish m-line: `AddTrack`, the registry, the cluster
    /// state, `TrackPublished` to the room and `Published` to the publisher.
    fn register_publish(
        &mut self,
        participant_id: u64,
        id: SessionId,
        media: &MediaDescription,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) -> bool {
        let Some(room) = sessions.get(&participant_id).and_then(|h| h.room_id) else {
            return false; // left the room while the offer was outstanding
        };
        let published = self
            .states
            .get(&participant_id)
            .map_or(0, |s| s.published_tracks.len());
        if published >= MAX_TRACKS_PER_SESSION {
            send_error(sessions, participant_id, "TOO_MANY_TRACKS", "Track limit");
            return false;
        }
        let cname = format!("nexus-{participant_id}");
        let spec = match track_spec(media, cname.as_bytes()) {
            Ok(Some(spec)) => spec,
            Ok(None) => return false,
            Err(e) => {
                send_error(sessions, participant_id, "INVALID_TRACK", &e.to_string());
                return false;
            }
        };
        let Some(entry) = plane.transports.get_mut(id) else {
            return false;
        };
        let shard = entry.shard;
        // The peer's SSRCs must not collide with the session's own (RTCP SSRC, out SSRCs).
        let ssrcs = media.get_ssrc_values();
        if !ssrcs.iter().all(|&s| entry.ssrcs.note_peer_ssrc(s)) {
            send_error(sessions, participant_id, "SSRC_COLLISION", "SSRC in use");
            return false;
        }
        let duplicate = spec.ssrc.is_some()
            && plane.tracks.by_publisher(participant_id).iter().any(|t| {
                plane
                    .tracks
                    .get(*t)
                    .is_some_and(|i| i.spec.ssrc == spec.ssrc)
            });
        if duplicate {
            send_error(
                sessions,
                participant_id,
                "DUPLICATE_SSRC",
                "SSRC published twice",
            );
            return false;
        }
        let track = plane.ids.track();
        let command = Command::AddTrack {
            id,
            track,
            spec: Box::new(spec),
        };
        if !plane.push(shard, command, participant_id) {
            return false;
        }
        let audio = spec.kind == nexus_core::MediaKind::Audio;
        let info = TrackInfo {
            publisher: participant_id,
            session: id,
            shard,
            room,
            spec,
            content_type: if audio { 2 } else { 0 },
        };
        assert!(plane.tracks.insert(track, info), "track ids are fresh");
        let state_info = StateTrackInfo {
            track_type: u8::from(!audio),
            content_type: if audio { 2 } else { 0 },
            codec: 0,
            bitrate_kbps: 0,
            owner_node: 0,
        };
        let _ = plane.state.add_track(track.get(), state_info);
        if let Some(state) = self.states.get_mut(&participant_id) {
            state.published_tracks.push(track.get());
        }
        info!(
            "Track {} registered: participant={}, ssrc={:?}",
            track.get(),
            participant_id,
            spec.ssrc
        );
        notify_track_published(participant_id, track.get(), audio, sessions, plane);
        // The publisher learns its own track id only here (peers get TrackPublished).
        let mid = media.mid.as_ref().map_or("", |m| m.as_str());
        debug_assert!(!mid.is_empty(), "publish m-lines are matched by mid");
        send_to(
            sessions,
            participant_id,
            SignalMessage::Published {
                track_id: track.get(),
                mid: mid.to_string(),
                kind: if audio { "audio" } else { "video" }.to_string(),
            },
        );
        true
    }

    /// `Subscribe` for every accepted subscribe m-line not yet on the shard, in
    /// increasing out-SSRC offset (the shard's monotonic rule). Returns their tracks.
    fn register_subscriptions(
        &mut self,
        participant_id: u64,
        id: SessionId,
        answer: &SessionDescription,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) -> Vec<TrackId> {
        let mut activated = Vec::new();
        let Some(state) = self.states.get_mut(&participant_id) else {
            return activated;
        };
        let Some(entry) = plane.transports.get(id) else {
            return activated;
        };
        let (shard, ssrcs) = (entry.shard, &entry.ssrcs);
        let mut pending: Vec<(u32, usize)> = state
            .mlines
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| match slot.role {
                MlineRole::Subscribe(s) if !s.on_shard && !ssrcs.is_stale(s.out_ssrc) => {
                    Some((ssrcs.offset_of(s.out_ssrc), i))
                }
                _ => None,
            })
            .collect();
        pending.sort_unstable();
        for (_, index) in pending {
            let MlineRole::Subscribe(slot) = state.mlines[index].role else {
                continue;
            };
            let track = DpTrackId::new(slot.track);
            let Some(info) = plane.tracks.get(track) else {
                continue; // unpublished meanwhile: the next offer turns it inactive
            };
            let source = TrackRef {
                shard: info.shard,
                track,
            };
            let spec = match sub_spec(&answer.media[index], &info.spec, slot.out_ssrc, source) {
                Ok(Some(spec)) => spec,
                Ok(None) => continue, // declined: stays off the shard
                Err(e) => {
                    send_error(sessions, participant_id, "SUBSCRIBE_FAILED", &e.to_string());
                    continue;
                }
            };
            let command = Command::Subscribe {
                id,
                sub: slot.sub,
                track,
                spec: Box::new(spec),
            };
            if !plane.push(shard, command, participant_id) {
                break;
            }
            if let Some(entry) = plane.transports.get_mut(id) {
                entry.ssrcs.mark_registered(slot.out_ssrc);
            }
            state.mlines[index].role = MlineRole::Subscribe(SubSlot {
                on_shard: true,
                ..slot
            });
            activated.push(slot.track);
        }
        activated
    }

    // ── Renegotiation ────────────────────────────────────────────────

    /// Offer the current subscription set now, or once the outstanding offer is
    /// answered.
    pub fn request_renegotiation(
        &mut self,
        participant_id: u64,
        track_ids: Vec<TrackId>,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        match self.states.get_mut(&participant_id) {
            Some(state) if state.offer_pending => {
                state.renegotiation_needed = true;
                state.last_subscribed_track_ids = track_ids;
            }
            Some(_) => {
                self.trigger_subscriber_renegotiation(participant_id, &track_ids, sessions, plane)
            }
            None => {}
        }
    }

    /// Offer the participant its current subscription set (`track_ids`).
    ///
    /// New tracks reuse an inactive m-line of the same kind or append one, with a fresh
    /// subscription id and out SSRC; dropped tracks turn inactive (`Unsubscribe` if the
    /// shard had them). Subscribe-only participants get their session here.
    pub fn trigger_subscriber_renegotiation(
        &mut self,
        participant_id: u64,
        track_ids: &[TrackId],
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let has_session = self.session(participant_id).is_some();
        if !has_session && track_ids.is_empty() {
            return; // nothing negotiated and nothing to subscribe
        }
        let Some(id) = self.ensure_session(participant_id, sessions, plane) else {
            return;
        };
        self.drop_subscriptions_except(participant_id, track_ids, plane);
        let kinds: Vec<(TrackId, u8)> = track_ids
            .iter()
            .filter_map(|&t| {
                let info = plane.tracks.get(DpTrackId::new(t))?;
                Some((t, u8::from(info.kind() == nexus_core::MediaKind::Video)))
            })
            .collect();
        let state = self.states.get_mut(&participant_id).expect("state exists");
        state.last_subscribed_track_ids = track_ids.to_vec();
        for (track, kind) in kinds {
            if state
                .mlines
                .iter()
                .any(|s| s.role.subscribed_track() == Some(track))
            {
                continue;
            }
            // The shard holds at most MAX_SUBS_PER_SESSION subscriptions per session.
            let subscribed = state
                .mlines
                .iter()
                .filter(|s| s.role.subscribed_track().is_some());
            let has_mline = state.mlines.len() < MAX_MEDIA_SECTIONS
                || state
                    .mlines
                    .iter()
                    .any(|s| s.role == MlineRole::Inactive && s.kind == kind);
            if subscribed.count() >= MAX_SUBS_PER_SESSION || !has_mline {
                let message = format!("At most {MAX_SUBS_PER_SESSION} subscriptions");
                send_error(sessions, participant_id, "TOO_MANY_TRACKS", &message);
                break;
            }
            let Some(slot) = Self::new_sub_slot(track, id, plane) else {
                send_error(sessions, participant_id, "SSRC_EXHAUSTED", "No SSRC left");
                break;
            };
            Self::claim_mline(state, kind, MlineRole::Subscribe(slot));
        }
        self.send_ordered_offer(participant_id, sessions, plane);
    }

    fn new_sub_slot(track: TrackId, id: SessionId, plane: &mut Plane) -> Option<SubSlot> {
        let out_ssrc = plane.transports.get_mut(id)?.ssrcs.allocate()?;
        Some(SubSlot {
            track,
            sub: plane.ids.subscription(),
            out_ssrc,
            on_shard: false,
        })
    }

    /// Subscribe m-lines whose track is not in `keep` turn inactive; the shard's
    /// subscription is removed (`Unsubscribe`) if it had one.
    fn drop_subscriptions_except(
        &mut self,
        participant_id: u64,
        keep: &[TrackId],
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let Some(id) = state.session else {
            return;
        };
        let Some(shard) = plane.transports.get(id).map(|e| e.shard) else {
            return;
        };
        for slot in state.mlines.iter_mut() {
            let MlineRole::Subscribe(sub) = slot.role else {
                continue;
            };
            if keep.contains(&sub.track) {
                continue;
            }
            slot.role = MlineRole::Inactive;
            if sub.on_shard {
                let _ = plane.push(shard, Command::Unsubscribe { sub: sub.sub }, participant_id);
            }
        }
    }

    /// Unsubscribed tracks: their m-lines turn inactive at once, so an answer to an
    /// outstanding offer does not put them on the shard.
    pub fn drop_subscriptions(
        &mut self,
        participant_id: u64,
        tracks: &[TrackId],
        plane: &mut Plane,
    ) {
        let keep: Vec<TrackId> = self
            .states
            .get(&participant_id)
            .map(|s| {
                s.mlines
                    .iter()
                    .filter_map(|m| m.role.subscribed_track())
                    .filter(|t| !tracks.contains(t))
                    .collect()
            })
            .unwrap_or_default();
        self.drop_subscriptions_except(participant_id, &keep, plane);
    }

    /// The publisher unpublished the track of its m-line `mid`: the m-line turns
    /// inactive and can carry a later publish or subscription of its kind.
    /// A publish m-line of the last answer that registered no track turns inactive.
    fn release_unregistered_publish(&mut self, participant_id: u64, mid: &str) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        if let Some(slot) = state
            .mlines
            .iter_mut()
            .find(|s| s.role == MlineRole::Publish && s.mid == mid)
        {
            slot.role = MlineRole::Inactive;
        }
    }

    pub fn release_publish(&mut self, participant_id: u64, track: TrackId, mid: &[u8]) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        state.published_tracks.retain(|&t| t != track);
        if let Some(slot) = state
            .mlines
            .iter_mut()
            .find(|s| s.role == MlineRole::Publish && s.mid.as_bytes() == mid)
        {
            slot.role = MlineRole::Inactive;
        }
    }

    /// Tracks removed from the shard (unpublished, or their publisher left): every
    /// m-line forwarding them turns inactive. Returns the affected participants.
    pub fn forget_tracks(&mut self, tracks: &[TrackId]) -> Vec<u64> {
        let mut affected = Vec::new();
        for (&participant_id, state) in self.states.iter_mut() {
            for slot in state.mlines.iter_mut() {
                if slot
                    .role
                    .subscribed_track()
                    .is_some_and(|t| tracks.contains(&t))
                {
                    slot.role = MlineRole::Inactive;
                    if !affected.contains(&participant_id) {
                        affected.push(participant_id);
                    }
                }
            }
        }
        affected.sort_unstable();
        affected
    }

    // ── Offers ───────────────────────────────────────────────────────

    /// Build and send an offer from the participant's m-lines, in order: publish
    /// m-lines recvonly, subscriptions sendonly under their out SSRC, inactive ones as
    /// placeholders. The first offer is followed by the session's candidates.
    fn send_ordered_offer(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
        plane: &mut Plane,
    ) {
        let Some(state) = self.states.get_mut(&participant_id) else {
            return;
        };
        let Some(id) = state.session else {
            return;
        };
        if state.mlines.is_empty() {
            return;
        }
        assert!(state.mlines.len() <= MAX_MEDIA_SECTIONS);
        Self::refresh_stale_slots(state, id, plane);
        let version = state.session_version + 1;
        let (sdp, tracks) = match build_offer(state, id, version, plane) {
            Ok(offer) => offer,
            Err(e) => {
                warn!("Offer for participant {} failed: {}", participant_id, e);
                send_error(sessions, participant_id, "OFFER_FAILED", &e);
                return;
            }
        };
        info!(
            "Offer sent to participant {} with {} m-lines ({} subscribed)",
            participant_id,
            state.mlines.len(),
            tracks.len()
        );
        send_to(
            sessions,
            participant_id,
            SignalMessage::Offer { sdp, tracks },
        );
        state.offer_pending = true;
        state.renegotiation_needed = false;
        state.session_version = version;
        if !state.candidates_sent {
            state.candidates_sent = true;
            trickle_candidates(participant_id, id, sessions, plane);
        }
    }

    /// A subscribe m-line whose SSRC was offered but never registered, while a later
    /// one was: the shard would refuse it (`OutSsrcNotMonotonic`), so it gets a fresh
    /// SSRC in this offer.
    fn refresh_stale_slots(state: &mut NegotiationState, id: SessionId, plane: &mut Plane) {
        let Some(entry) = plane.transports.get_mut(id) else {
            return;
        };
        for slot in state.mlines.iter_mut() {
            let MlineRole::Subscribe(sub) = slot.role else {
                continue;
            };
            if sub.on_shard || !entry.ssrcs.is_stale(sub.out_ssrc) {
                continue;
            }
            slot.role = match entry.ssrcs.allocate() {
                Some(out_ssrc) => MlineRole::Subscribe(SubSlot { out_ssrc, ..sub }),
                None => MlineRole::Inactive,
            };
        }
    }

    // ── ICE ──────────────────────────────────────────────────────────

    /// Remote candidates are accepted and ignored: the SFU is ICE-lite and learns the
    /// peer's address from its checks.
    pub fn handle_candidate(&mut self, participant_id: u64, candidate: &str) {
        debug!(
            "Candidate from {} ignored ({} bytes)",
            participant_id,
            candidate.len()
        );
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    /// Close the participant's session and remove its tracks. Returns the removed
    /// tracks (their subscribers renegotiate).
    pub fn cleanup_participant(
        &mut self,
        participant_id: u64,
        room: Option<u32>,
        plane: &mut Plane,
    ) -> Vec<TrackId> {
        let state = self.states.remove(&participant_id);
        let removed: Vec<TrackId> = plane
            .tracks
            .remove_publisher(participant_id)
            .into_iter()
            .map(|t| t.get())
            .collect();
        for &track in &removed {
            plane.state.remove_track(track);
        }
        // CloseSession removes the session's tracks and subscriptions on the shard.
        if let Some(id) = state.and_then(|s| s.session) {
            plane.close_session(id, room);
        }
        removed
    }
}

/// The SDP and `Offer.tracks` of the participant's current m-lines.
fn build_offer(
    state: &NegotiationState,
    id: SessionId,
    version: u64,
    plane: &Plane,
) -> Result<(String, Vec<OfferTrack>), String> {
    let entry = plane.transports.get(id).ok_or("no session")?;
    let ufrag = String::from_utf8_lossy(&entry.ice.local_ufrag).into_owned();
    let pwd = String::from_utf8_lossy(&entry.ice.local_pwd).into_owned();
    let mut value = [0u8; 64];
    value[..32].copy_from_slice(plane.certificate().fingerprint());
    let fingerprint = DtlsFingerprint {
        algorithm: FingerprintAlgorithm::Sha256,
        value,
        value_len: 32,
    };
    let negotiator = SdpNegotiator::with_defaults(ufrag, pwd, fingerprint)
        .map_err(|e| format!("{e:?}"))?
        .with_ice_lite(true);
    let codecs = [publish_codec(true)?, publish_codec(false)?];
    let extmaps = [publish_extmaps(0)?, publish_extmaps(1)?];
    let offered: [Vec<(u8, &str)>; 2] =
        [offered_extmaps(0).collect(), offered_extmaps(1).collect()];
    // Per slot: (stream id = cname) of the forwarded track's publisher.
    let identities: Vec<Option<String>> = state
        .mlines
        .iter()
        .map(|slot| {
            let track = slot.role.subscribed_track()?;
            let info = plane.tracks.get(DpTrackId::new(track))?;
            Some(format!("nexus-{}", info.publisher))
        })
        .collect();
    let mut tracks = Vec::new();
    let mlines: Vec<OfferMline> = state
        .mlines
        .iter()
        .zip(&identities)
        .map(|(slot, identity)| {
            let k = usize::from(slot.kind);
            let fbs = if slot.kind == 0 {
                V1_AUDIO_FBS
            } else {
                V1_VIDEO_FBS
            };
            let recycled = |direction, rtcp_fbs| {
                OfferMline::Recycled(RecycledMline {
                    mid: slot.mid.as_str(),
                    media_kind: slot.kind,
                    codecs: std::slice::from_ref(&codecs[k]),
                    fmtps: &[],
                    offer_pts: &[],
                    extmaps: &extmaps[k],
                    rtcp_fbs,
                    direction,
                })
            };
            match (slot.role, identity) {
                (MlineRole::Publish, _) => recycled(Direction::RecvOnly, fbs),
                (MlineRole::Subscribe(sub), Some(identity)) => {
                    tracks.push(OfferTrack {
                        track_id: sub.track,
                        mid: slot.mid.clone(),
                    });
                    OfferMline::Track {
                        ssrc: sub.out_ssrc,
                        media_kind: slot.kind,
                        mid: slot.mid.as_str(),
                        stream_id: identity.as_str(),
                        cname: identity.as_str(),
                        rtcp_fbs: fbs,
                        // VP8 is 96 and Opus 111 on every m-line: a PT never moves
                        // between offers (the shard keeps the first answer's map).
                        keep_pt: true,
                    }
                }
                // Track gone, or no longer used: keep the position, send nothing.
                _ => recycled(Direction::Inactive, &[]),
            }
        })
        .collect();
    let (sdp, _) = negotiator
        .create_ordered_offer(
            state.session_id,
            version,
            &mlines,
            extensions::MID,
            &offered[1],
            &offered[0],
            Some(&codecs[1]),
            Some(&codecs[0]),
            None,
            None,
        )
        .map_err(|e| format!("{e:?}"))?;
    Ok((sdp, tracks))
}

/// Codec the SFU offers: VP8 96 for video, Opus 111 for audio, on every m-line of the
/// kind, publish and subscribe alike. The PT maps to the same codec across the BUNDLE
/// (the MID extension demuxes) and never changes between offers (`keep_pt`), so the
/// shard's PT map from the first answer stays right.
fn publish_codec(audio: bool) -> Result<RtpCodec, String> {
    let (pt, spec) = if audio {
        (111, "opus/48000/2")
    } else {
        (96, "VP8/90000")
    };
    RtpCodec::parse(pt, spec).map_err(|e| format!("{e:?}"))
}

/// The fixed extension table (note §11.2) as `a=extmap` entries for a kind.
fn publish_extmaps(kind: u8) -> Result<Vec<ExtMap>, String> {
    offered_extmaps(kind)
        .map(|(id, uri)| {
            let bytes = uri.as_bytes();
            let mut buf = [0u8; 128];
            buf.get_mut(..bytes.len())
                .ok_or(format!("extmap URI {uri} too long"))?
                .copy_from_slice(bytes);
            Ok(ExtMap {
                id,
                direction: None,
                uri: buf,
                uri_len: bytes.len() as u8,
            })
        })
        .collect()
}

/// The session's shard candidates as trickled `IceCandidate`s, then end-of-candidates
/// (`a=ice-options:trickle` stays in the offer; the SFU starts no checks).
fn trickle_candidates(
    participant_id: u64,
    id: SessionId,
    sessions: &HashMap<u64, ParticipantHandle>,
    plane: &Plane,
) {
    let Some(entry) = plane.transports.get(id) else {
        return;
    };
    let candidates = plane.candidates(entry.shard);
    for (index, addr) in candidates.iter().take(MAX_CANDIDATES as usize).enumerate() {
        // Distinct interface index: distinct local preference and priority.
        let candidate = Candidate::new_host(*addr, 1, index as u8);
        send_to(
            sessions,
            participant_id,
            SignalMessage::IceCandidate {
                candidate: candidate.to_sdp_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
            },
        );
    }
    send_to(sessions, participant_id, SignalMessage::EndOfCandidates);
}

/// `TrackPublished` to the publisher's room peers.
fn notify_track_published(
    publisher: u64,
    track_id: TrackId,
    audio: bool,
    sessions: &HashMap<u64, ParticipantHandle>,
    plane: &Plane,
) {
    let Some(room) = sessions.get(&publisher).and_then(|h| h.room_id) else {
        return;
    };
    let participants = plane.state.get_participants(room);
    for &pid in participants.iter().take(MAX_PARTICIPANTS_PER_ROOM) {
        if pid == publisher {
            continue;
        }
        send_to(
            sessions,
            pid,
            SignalMessage::TrackPublished {
                publisher_id: publisher,
                track_id,
                kind: if audio { "audio" } else { "video" }.to_string(),
                content: if audio { "audio" } else { "camera" }.to_string(),
            },
        );
    }
}

pub(crate) fn send_to(
    sessions: &HashMap<u64, ParticipantHandle>,
    participant_id: u64,
    msg: SignalMessage,
) {
    if let Some(handle) = sessions.get(&participant_id) {
        let _ = handle.outbound_tx.try_send(msg);
    }
}

pub(crate) fn send_error(
    sessions: &HashMap<u64, ParticipantHandle>,
    participant_id: u64,
    code: &str,
    message: &str,
) {
    send_to(
        sessions,
        participant_id,
        SignalMessage::Error {
            code: code.to_string(),
            message: message.to_string(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(setup_line: &str, media_setup_line: &str) -> SessionDescription {
        let fp = ["AB"; 32].join(":");
        let sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
             a=ice-ufrag:testufrag\r\na=ice-pwd:testpwd12345678901234567890\r\n\
             a=fingerprint:sha-256 {fp}\r\n{setup_line}\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n{media_setup_line}"
        );
        SdpParser::parse(&sdp).unwrap()
    }

    #[test]
    fn dtls_role_from_answer_setup() {
        let role = |s: &str, m: &str| NegotiationManager::dtls_role_from_answer(&answer(s, m));
        assert_eq!(role("a=setup:active\r\n", ""), Ok(DtlsRole::Server));
        assert_eq!(role("a=setup:passive\r\n", ""), Ok(DtlsRole::Client));
        // Browsers put a=setup on the m-line.
        assert_eq!(role("", "a=setup:passive\r\n"), Ok(DtlsRole::Client));
        assert_eq!(role("", ""), Ok(DtlsRole::Server));
        assert!(role("a=setup:actpass\r\n", "").is_err());
        assert!(role("a=setup:holdconn\r\n", "").is_err());
    }

    #[test]
    fn only_a_sha256_fingerprint_is_used() {
        let sdp = answer("", "");
        assert_eq!(
            NegotiationManager::extract_fingerprint(&sdp),
            Some([0xAB; 32])
        );
        let fp = ["CD"; 48].join(":");
        let sdp = SdpParser::parse(&format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
             a=ice-ufrag:testufrag\r\na=ice-pwd:testpwd12345678901234567890\r\n\
             a=fingerprint:sha-384 {fp}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        ))
        .unwrap();
        assert_eq!(
            NegotiationManager::extract_fingerprint(&sdp),
            None,
            "never truncated"
        );
    }

    #[test]
    fn first_sha256_fingerprint_across_levels() {
        // Session level has only sha-384; the m-line has sha-256: that one is used.
        let sha384 = ["CD"; 48].join(":");
        let sha256 = ["EF"; 32].join(":");
        let sdp = SdpParser::parse(&format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
             a=ice-ufrag:testufrag\r\na=ice-pwd:testpwd12345678901234567890\r\n\
             a=fingerprint:sha-384 {sha384}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=fingerprint:sha-256 {sha256}\r\n"
        ))
        .unwrap();
        assert_eq!(
            NegotiationManager::extract_fingerprint(&sdp),
            Some([0xEF; 32])
        );
    }

    #[test]
    fn publish_extmaps_are_the_fixed_table() {
        let audio = publish_extmaps(0).unwrap();
        let video = publish_extmaps(1).unwrap();
        assert!(audio.iter().any(|e| e.id == extensions::MID));
        assert!(audio.iter().any(|e| e.id == extensions::AUDIO_LEVEL));
        assert!(video.iter().any(|e| e.id == extensions::VIDEO_ORIENTATION));
        assert!(!video.iter().any(|e| e.id == extensions::AUDIO_LEVEL));
        assert!(audio
            .iter()
            .chain(&video)
            .all(|e| e.id <= 14 && e.uri_len > 0));
    }
}
