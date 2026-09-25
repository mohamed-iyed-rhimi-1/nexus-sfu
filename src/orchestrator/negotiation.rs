//! NegotiationManager: transport creation, ICE gathering, SDP offer/answer,
//! MID tracking, track registration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::forward::SsrcRouter;
use crate::signal::{OfferTrack, SignalMessage};
use crate::types::{MediaKind, TrackId};
use crate::worker::{WorkerMessage, WorkerPool};
use nexus_state::gossip::types::TrackInfo;
use nexus_state::DistributedState;
use nexus_transport::ice::{Candidate, IceCredentials, MAX_CANDIDATES};
use nexus_webrtc::sdp::{MediaType, OfferMline, SdpNegotiator};
use nexus_webrtc::webrtc::{TransportId, WebRtcTransport};

use super::ParticipantHandle;

const MAX_TRACKS_PER_PARTICIPANT: u32 = 10;
/// Most m-lines one session can carry (publish + subscribe + inactive).
const MAX_MLINES: usize = nexus_webrtc::sdp::MAX_MEDIA_SECTIONS;
const MAX_PARTICIPANTS_PER_ROOM: u32 = 1_000;

/// ICE gathering lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GatheringState {
    #[default]
    Idle,
    InProgress,
    Complete,
    Failed,
}

/// Events from ICE gathering background tasks.
#[derive(Debug)]
pub enum IceGatheringEvent {
    Candidate {
        participant_id: u64,
        transport_id: TransportId,
        candidate: Candidate,
        generation: u32,
    },
    Complete {
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
    },
    Failed {
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
        reason: String,
    },
}

/// What a negotiated m-line carries. Once offered, an m-line keeps its mid and
/// position in every later offer (RFC 3264 §8); only its role changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlineRole {
    /// Participant publishes to the SFU (recvonly from the SFU's side).
    Publish,
    /// SFU forwards this subscribed track (sendonly).
    Subscribe(TrackId),
    /// No longer used; reusable by a later subscription of the same kind.
    Inactive,
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
pub struct NegotiationState {
    pub transport_id: Option<TransportId>,
    pub published_tracks: Vec<TrackId>,
    pub published_kinds: Vec<(String, String)>,
    pub pending_mid_map: Vec<(TrackId, String)>,
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
    pub mid_ext_id: u8,
    pub twcc_ext_id: u8,
    pub gathering_state: GatheringState,
    pub gathering_generation: u32,
    pub candidates_trickled: u8,
    /// Cached subscribed track IDs for deferred renegotiation.
    pub last_subscribed_track_ids: Vec<TrackId>,
    /// SDP session ID (RFC 3264 §8).
    pub session_id: u64,
    /// SDP session version, incremented per offer (RFC 3264 §8).
    pub session_version: u64,
}

impl Default for NegotiationState {
    fn default() -> Self {
        Self::new()
    }
}

impl NegotiationState {
    pub fn new() -> Self {
        Self {
            transport_id: None,
            published_tracks: Vec::with_capacity(MAX_TRACKS_PER_PARTICIPANT as usize),
            published_kinds: Vec::new(),
            pending_mid_map: Vec::new(),
            offer_pending: false,
            renegotiation_needed: false,
            next_mid_index: 0,
            mlines: Vec::new(),
            unregistered_publish_mids: Vec::new(),
            pending_publish: None,
            mid_ext_id: 1,
            twcc_ext_id: 0,
            gathering_state: GatheringState::Idle,
            gathering_generation: 0,
            candidates_trickled: 0,
            last_subscribed_track_ids: Vec::new(),
            session_id: 0,
            session_version: 0,
        }
    }
}

pub struct NegotiationManager {
    pub(crate) states: HashMap<u64, NegotiationState>,
    webrtc_transport: Arc<WebRtcTransport>,
    ssrc_router: Arc<SsrcRouter>,
    worker_pool: Arc<RwLock<WorkerPool>>,
    distributed_state: Arc<DistributedState>,
    pub ice_gather_tx: mpsc::UnboundedSender<IceGatheringEvent>,
    pub ice_gather_rx: mpsc::UnboundedReceiver<IceGatheringEvent>,
    media_bind_addr: SocketAddr,
}

impl NegotiationManager {
    pub fn new(
        webrtc_transport: Arc<WebRtcTransport>,
        ssrc_router: Arc<SsrcRouter>,
        worker_pool: Arc<RwLock<WorkerPool>>,
        distributed_state: Arc<DistributedState>,
        media_bind_addr: SocketAddr,
    ) -> Self {
        let (ice_gather_tx, ice_gather_rx) = mpsc::unbounded_channel();
        Self {
            states: HashMap::with_capacity(1024),
            webrtc_transport,
            ssrc_router,
            worker_pool,
            distributed_state,
            ice_gather_tx,
            ice_gather_rx,
            media_bind_addr,
        }
    }

    pub fn add_participant(&mut self, participant_id: u64) {
        self.states.insert(participant_id, NegotiationState::new());
    }

    pub fn remove_participant(&mut self, participant_id: u64) -> Option<NegotiationState> {
        self.states.remove(&participant_id)
    }

    /// Get the transport_id for a participant (used by other managers).
    /// Transport of a participant whose session is already established and
    /// has no offer outstanding, i.e. a renegotiation just completed on it.
    pub fn settled_established_transport(&self, participant_id: u64) -> Option<TransportId> {
        let state = self.states.get(&participant_id)?;
        let tid = state.transport_id?;
        if state.offer_pending {
            return None;
        }
        let established = self
            .webrtc_transport
            .with_session(tid, |ws| ws.is_established())
            .unwrap_or(false);
        established.then_some(tid)
    }

    pub fn transport_id(&self, participant_id: u64) -> Option<TransportId> {
        self.states
            .get(&participant_id)
            .and_then(|s| s.transport_id)
    }

    /// Get the SRTP key material for a participant's transport.
    pub fn get_srtp_key_material(
        &self,
        participant_id: u64,
    ) -> Option<(
        nexus_transport::srtp::KeyMaterial,
        nexus_transport::srtp::SrtpPolicy,
        u64,
    )> {
        let tid = self.transport_id(participant_id)?;
        self.webrtc_transport
            .with_session(tid, |ws| ws.get_srtp_key_material())
            .flatten()
    }

    /// Take the pending_mid_map for media activation.
    pub fn take_pending_mid_map(&mut self, participant_id: u64) -> Vec<(TrackId, String)> {
        self.states
            .get_mut(&participant_id)
            .map(|s| std::mem::take(&mut s.pending_mid_map))
            .unwrap_or_default()
    }

    /// Get the selected remote address for a participant's transport.
    pub fn selected_remote_addr(&self, participant_id: u64) -> Option<SocketAddr> {
        let tid = self.transport_id(participant_id)?;
        self.webrtc_transport
            .with_session(tid, |ws| ws.selected_pair().map(|(_, remote)| remote))
            .flatten()
    }

    pub fn ssrc_router(&self) -> &Arc<SsrcRouter> {
        &self.ssrc_router
    }

    pub fn webrtc_transport(&self) -> &Arc<WebRtcTransport> {
        &self.webrtc_transport
    }

    // ── Publish ──────────────────────────────────────────────────────

    pub fn handle_publish(
        &mut self,
        participant_id: u64,
        kinds: &[String],
        contents: &[String],
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0
            || kinds.len() != contents.len()
            || kinds.len() > MAX_TRACKS_PER_PARTICIPANT as usize
        {
            return;
        }

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        // Only audio/video m-lines are offered
        let published_kinds: Vec<(String, String)> = kinds
            .iter()
            .zip(contents.iter())
            .filter(|(k, _)| k.as_str() == "audio" || k.as_str() == "video")
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        if published_kinds.is_empty() {
            return;
        }

        // One offer at a time: retry this publish once the pending answer arrives
        if state.offer_pending {
            state.pending_publish = Some(published_kinds);
            return;
        }
        state.published_kinds = published_kinds.clone();

        // Existing transport (from an earlier publish or a subscription): append
        // publish m-lines after the negotiated ones and re-offer the session.
        if let Some(transport_id) = state.transport_id {
            if state.mlines.len() + published_kinds.len() > MAX_MLINES {
                send_error(
                    sessions,
                    participant_id,
                    "TOO_MANY_TRACKS",
                    "Too many m-lines",
                );
                return;
            }
            let mut new_mids = Vec::with_capacity(published_kinds.len());
            for (kind, _content) in &published_kinds {
                let mid = state.next_mid_index.to_string();
                state.next_mid_index += 1;
                state.mlines.push(MlineSlot {
                    mid: mid.clone(),
                    kind: u8::from(kind.as_str() == "video"),
                    role: MlineRole::Publish,
                });
                new_mids.push(mid);
            }
            state.unregistered_publish_mids = new_mids;
            self.send_ordered_offer(participant_id, transport_id, sessions);
            return;
        }

        let (transport_id, ice_creds, dtls_fingerprint) =
            match Self::create_transport(&self.webrtc_transport, participant_id, sessions) {
                Some(t) => t,
                None => return,
            };
        state.transport_id = Some(transport_id);

        // Build SDP offer with RFC 3264 §8 session versioning
        let session_id_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        state.session_id = session_id_ts;
        state.session_version = 1;

        let mut sdp = nexus_webrtc::sdp::SessionDescription::new(session_id_ts);
        sdp.set_session_name("Nexus SFU");
        sdp.set_ice_credentials(&ice_creds.local_ufrag, &ice_creds.local_pwd);
        sdp.set_fingerprint(nexus_webrtc::sdp::DtlsFingerprint {
            algorithm: nexus_webrtc::sdp::FingerprintAlgorithm::Sha256,
            value: {
                let mut v = [0u8; 64];
                v[..32].copy_from_slice(&dtls_fingerprint);
                v
            },
            value_len: 32,
        });
        sdp.set_setup(nexus_webrtc::sdp::DtlsSetup::Actpass);

        for (idx, (kind, _content)) in published_kinds.iter().enumerate() {
            let media_type = match kind.as_str() {
                "audio" => nexus_webrtc::sdp::MediaType::Audio,
                "video" => nexus_webrtc::sdp::MediaType::Video,
                _ => continue,
            };
            let mut media = nexus_webrtc::sdp::MediaDescription::new(
                media_type,
                9,
                nexus_webrtc::sdp::TransportProtocol::UdpTlsRtpSavpf,
            );
            let mid = idx.to_string();
            media.mid = Some(nexus_webrtc::sdp::Mid::new(&mid));
            media.direction = nexus_webrtc::sdp::Direction::RecvOnly;
            state.mlines.push(MlineSlot {
                mid: mid.clone(),
                kind: u8::from(media_type == nexus_webrtc::sdp::MediaType::Video),
                role: MlineRole::Publish,
            });
            state.unregistered_publish_mids.push(mid);
            media.rtcp_mux = true;
            if let Some(c) = publish_codec(media_type == nexus_webrtc::sdp::MediaType::Audio) {
                let _ = media.add_codec(c);
            }
            let _ = sdp.add_media(media);
        }

        state.next_mid_index = state.mlines.len() as u32;

        let offer_sdp = nexus_webrtc::sdp::SdpPrinter::print(&sdp);
        send_to(
            sessions,
            participant_id,
            SignalMessage::Offer {
                sdp: offer_sdp,
                tracks: Vec::new(),
            },
        );

        state.offer_pending = true;
        self.start_ice_gathering(participant_id, transport_id);
    }

    /// Create a WebRTC session for a participant (SFU is the DTLS server).
    /// Reports SESSION_FAILED to the participant on error.
    fn create_transport(
        webrtc_transport: &WebRtcTransport,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) -> Option<(TransportId, IceCredentials, [u8; 32])> {
        let dtls_params =
            nexus_webrtc::webrtc::DtlsParameters::new(nexus_webrtc::webrtc::DtlsRole::Server);
        let transport_id = match webrtc_transport.create_session(dtls_params) {
            Ok(id) => id,
            Err(e) => {
                send_error(
                    sessions,
                    participant_id,
                    "SESSION_FAILED",
                    &format!("{:?}", e),
                );
                return None;
            }
        };
        let created = webrtc_transport.with_session(transport_id, |ws| {
            (ws.local_ice_credentials().clone(), *ws.dtls_fingerprint())
        });
        match created {
            Some((creds, fp)) => Some((transport_id, creds, fp)),
            None => {
                send_error(
                    sessions,
                    participant_id,
                    "SESSION_FAILED",
                    "Session not found after creation",
                );
                None
            }
        }
    }

    // ── Answer ───────────────────────────────────────────────────────

    /// Parse SDP answer, set ICE creds, register tracks.
    /// Does NOT activate media — that happens in SubscriptionManager
    /// when SessionEvent::Established fires.
    pub fn handle_answer(
        &mut self,
        participant_id: u64,
        sdp: &str,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0 || sdp.is_empty() {
            return;
        }

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        let transport_id = match state.transport_id {
            Some(id) => id,
            None => return,
        };

        let answer = match nexus_webrtc::sdp::SdpParser::parse(sdp) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    "Failed to parse answer SDP from {}: {:?}",
                    participant_id, e
                );
                return;
            }
        };

        // Extract remote ICE credentials
        let (remote_ufrag, remote_pwd) = Self::extract_ice_creds(&answer);
        if let (Some(ufrag), Some(pwd)) = (remote_ufrag, remote_pwd) {
            self.webrtc_transport.with_session_mut(transport_id, |ws| {
                ws.set_remote_ice_credentials(IceCredentials {
                    local_ufrag: ufrag,
                    local_pwd: pwd,
                });
            });
        }

        // Pin the peer's DTLS certificate. Until this is set the session
        // will not trust the handshake; on mismatch it fails.
        match Self::extract_fingerprint(&answer) {
            Some(fingerprint) => {
                let result = self
                    .webrtc_transport
                    .with_session_mut(transport_id, |ws| ws.set_remote_fingerprint(fingerprint));
                if let Some(Err(e)) = result {
                    warn!(
                        "DTLS fingerprint check failed for participant {}: {}",
                        participant_id, e
                    );
                    return;
                }
            }
            None => {
                warn!(
                    "Answer from participant {} has no SHA-256 fingerprint",
                    participant_id
                );
                return;
            }
        }

        // Register published tracks from the m-lines this offer added for publishing
        // (subscription m-lines in the same answer are not the participant's media).
        let publish_mids = std::mem::take(&mut state.unregistered_publish_mids);
        state.offer_pending = false;

        if !publish_mids.is_empty() {
            self.register_tracks_from_sdp(participant_id, &answer, &publish_mids, sessions);
        }

        // Update MID mappings and collect renegotiation flag
        let needs_renego = {
            let state = match self.states.get_mut(&participant_id) {
                Some(s) => s,
                None => return,
            };
            let mid_ext_id = state.mid_ext_id;
            let pool = self.worker_pool.read();
            for (track_id, mid_str) in &state.pending_mid_map {
                let mid_bytes = mid_str.as_bytes();
                let mut mid_value = [0u8; 4];
                let mid_len = mid_bytes.len().min(4);
                mid_value[..mid_len].copy_from_slice(&mid_bytes[..mid_len]);
                let _ = pool.send_to_track(
                    *track_id,
                    WorkerMessage::SetTrackMid {
                        track_id: *track_id,
                        mid_ext_id,
                        mid_value,
                        mid_value_len: mid_len as u8,
                    },
                );
            }
            let needed = state.renegotiation_needed;
            state.renegotiation_needed = false;
            needed
        };

        if needs_renego {
            let cached_ids = self
                .states
                .get(&participant_id)
                .map(|s| s.last_subscribed_track_ids.clone())
                .unwrap_or_default();
            self.trigger_subscriber_renegotiation(participant_id, &cached_ids, sessions);
        }

        // Publish that arrived while the previous offer was outstanding. If the
        // subscription renegotiation above sent an offer, it queues again.
        let pending_publish = self
            .states
            .get_mut(&participant_id)
            .and_then(|s| s.pending_publish.take());
        if let Some(published) = pending_publish {
            let (kinds, contents): (Vec<String>, Vec<String>) = published.into_iter().unzip();
            self.handle_publish(participant_id, &kinds, &contents, sessions);
        }

        info!("Answer processed from participant {}", participant_id);
    }

    /// SHA-256 DTLS fingerprint from the session level, else the first
    /// m-line that has one (bundled m-lines share one transport).
    fn extract_fingerprint(sdp: &nexus_webrtc::sdp::SessionDescription) -> Option<[u8; 32]> {
        let session_fp = sdp.fingerprint.as_ref();
        let media_fp = (0..(sdp.media_count as usize).min(8))
            .filter_map(|i| sdp.media[i].as_ref())
            .find_map(|m| m.fingerprint.as_ref());
        let fp = session_fp.or(media_fp)?;
        if fp.algorithm != nexus_webrtc::sdp::FingerprintAlgorithm::Sha256 || fp.value_len != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&fp.value[..32]);
        Some(out)
    }

    fn extract_ice_creds(
        sdp: &nexus_webrtc::sdp::SessionDescription,
    ) -> (Option<String>, Option<String>) {
        if sdp.ice_ufrag.is_some() && sdp.ice_pwd.is_some() {
            return (
                sdp.ice_ufrag.as_ref().map(|u| u.as_str().to_string()),
                sdp.ice_pwd.as_ref().map(|p| p.as_str().to_string()),
            );
        }
        for i in 0..(sdp.media_count as usize).min(8) {
            if let Some(ref media) = sdp.media[i] {
                if media.ice_ufrag.is_some() && media.ice_pwd.is_some() {
                    return (
                        media.ice_ufrag.as_ref().map(|u| u.as_str().to_string()),
                        media.ice_pwd.as_ref().map(|p| p.as_str().to_string()),
                    );
                }
            }
        }
        (None, None)
    }

    // ── ICE Gathering ────────────────────────────────────────────────

    fn start_ice_gathering(&mut self, participant_id: u64, transport_id: TransportId) {
        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        state.gathering_generation = state.gathering_generation.wrapping_add(1);
        state.gathering_state = GatheringState::InProgress;
        state.candidates_trickled = 0;
        let generation = state.gathering_generation;

        let tx = self.ice_gather_tx.clone();
        let media_addr = self.media_bind_addr;
        tokio::spawn(async move {
            let candidate = Candidate::new_host(media_addr, 1, 0);
            let _ = tx.send(IceGatheringEvent::Candidate {
                participant_id,
                transport_id,
                candidate,
                generation,
            });
            let _ = tx.send(IceGatheringEvent::Complete {
                participant_id,
                transport_id,
                generation,
            });
        });
    }

    pub fn dispatch_ice_event(
        &mut self,
        event: IceGatheringEvent,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        match event {
            IceGatheringEvent::Candidate {
                participant_id,
                transport_id,
                candidate,
                generation,
            } => {
                self.handle_ice_candidate_discovered(
                    participant_id,
                    transport_id,
                    candidate,
                    generation,
                    sessions,
                );
            }
            IceGatheringEvent::Complete {
                participant_id,
                transport_id,
                generation,
            } => {
                self.handle_ice_gathering_complete(
                    participant_id,
                    transport_id,
                    generation,
                    sessions,
                );
            }
            IceGatheringEvent::Failed {
                participant_id,
                transport_id: _,
                generation,
                reason: _,
            } => {
                self.handle_ice_gathering_failed(participant_id, generation, sessions);
            }
        }
    }

    fn handle_ice_candidate_discovered(
        &mut self,
        participant_id: u64,
        _transport_id: TransportId,
        candidate: Candidate,
        generation: u32,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        if state.gathering_generation != generation {
            return;
        }
        if state.candidates_trickled >= MAX_CANDIDATES as u8 {
            return;
        }

        let candidate_sdp = candidate.to_sdp_string();
        send_to(
            sessions,
            participant_id,
            SignalMessage::IceCandidate {
                candidate: candidate_sdp,
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
            },
        );
        state.candidates_trickled += 1;

        if let Some(tid) = state.transport_id {
            self.webrtc_transport.with_session_mut(tid, |ws| {
                let _ = ws.add_local_candidate(candidate);
            });
        }
    }

    fn handle_ice_gathering_complete(
        &mut self,
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        if state.gathering_generation != generation {
            return;
        }
        state.gathering_state = GatheringState::Complete;

        send_to(sessions, participant_id, SignalMessage::EndOfCandidates);

        self.webrtc_transport.with_session_mut(transport_id, |ws| {
            let _ = ws.mark_gathering_complete();
            let _ = ws.start_connectivity_checks();
        });
    }

    fn handle_ice_gathering_failed(
        &mut self,
        participant_id: u64,
        generation: u32,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        if state.gathering_generation != generation {
            return;
        }
        state.gathering_state = GatheringState::Failed;
        send_to(sessions, participant_id, SignalMessage::EndOfCandidates);
    }

    // ── Trickle ICE ──────────────────────────────────────────────────

    pub fn handle_candidate(&mut self, participant_id: u64, candidate_str: &str) {
        if participant_id == 0 || candidate_str.is_empty() {
            return;
        }

        let tid = match self
            .states
            .get(&participant_id)
            .and_then(|s| s.transport_id)
        {
            Some(id) => id,
            None => return,
        };

        let candidate = match Candidate::from_sdp(candidate_str) {
            Ok(c) => c,
            Err(e) => {
                debug!("Invalid trickle candidate from {}: {:?}", participant_id, e);
                return;
            }
        };

        self.webrtc_transport.with_session_mut(tid, |ws| {
            let _ = ws.add_remote_candidate(candidate);
            let _ = ws.start_connectivity_checks();
        });
    }

    // ── Track Registration ───────────────────────────────────────────

    /// Register the participant's published tracks from the SSRCs on the
    /// answer's `publish_mids` m-lines.
    fn register_tracks_from_sdp(
        &mut self,
        participant_id: u64,
        sdp: &nexus_webrtc::sdp::SessionDescription,
        publish_mids: &[String],
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        let room_id = sessions.get(&participant_id).and_then(|h| h.room_id);

        let mut notifications: Vec<(u64, SignalMessage)> = Vec::with_capacity(64);
        let media_count = (sdp.media_count as usize).min(16);

        for i in 0..media_count {
            let media = match &sdp.media[i] {
                Some(m) => m,
                None => continue,
            };
            let is_publish_mline = media
                .mid
                .as_ref()
                .is_some_and(|mid| publish_mids.iter().any(|p| p == mid.as_str()));
            if !is_publish_mline {
                continue;
            }
            let ssrc_values = media.get_ssrc_values();
            for &ssrc in ssrc_values.iter().take(8) {
                if ssrc == 0 {
                    continue;
                }
                if state.published_tracks.len() >= MAX_TRACKS_PER_PARTICIPANT as usize {
                    break;
                }

                // Detect duplicate SSRCs — skip if already registered
                if self.ssrc_router.lookup(ssrc).is_some() {
                    warn!(
                        "Duplicate SSRC {} from participant {}, skipping",
                        ssrc, participant_id
                    );
                    continue;
                }

                let kind = if media.media_type == MediaType::Audio {
                    MediaKind::Audio
                } else {
                    MediaKind::Video
                };

                let mut pool = self.worker_pool.write();
                match pool.assign_track(ssrc, kind) {
                    Ok((track_id, worker_id)) => {
                        if let Err(e) = self.ssrc_router.register(ssrc, track_id, worker_id) {
                            warn!("Failed to register SSRC {}: {:?}", ssrc, e);
                            continue;
                        }

                        let content_type = if kind == MediaKind::Audio { 2 } else { 0 };
                        let track_info = TrackInfo {
                            track_type: if kind == MediaKind::Audio { 0 } else { 1 },
                            content_type,
                            codec: 0,
                            bitrate_kbps: 0,
                            owner_node: 0,
                        };
                        let _ = self.distributed_state.add_track(track_id, track_info);
                        state.published_tracks.push(track_id);

                        if state.twcc_ext_id != 0 {
                            let _ = pool.send_to_track(
                                track_id,
                                WorkerMessage::SetTrackTwccExtId {
                                    track_id,
                                    twcc_ext_id: state.twcc_ext_id,
                                },
                            );
                        }

                        if let Some(rid) = room_id {
                            let participants = self.distributed_state.get_participants(rid);
                            for &pid in participants.iter().take(MAX_PARTICIPANTS_PER_ROOM as usize)
                            {
                                if pid == participant_id {
                                    continue;
                                }
                                notifications.push((
                                    pid,
                                    SignalMessage::TrackPublished {
                                        publisher_id: participant_id,
                                        track_id,
                                        kind: if kind == MediaKind::Audio {
                                            "audio".to_string()
                                        } else {
                                            "video".to_string()
                                        },
                                        content: match content_type {
                                            1 => "screen",
                                            2 => "audio",
                                            _ => "camera",
                                        }
                                        .to_string(),
                                    },
                                ));
                            }
                        }
                        info!(
                            "Track {} registered: SSRC={}, worker={}, kind={:?}",
                            track_id, ssrc, worker_id, kind
                        );
                    }
                    Err(e) => warn!("Failed to assign track for SSRC {}: {:?}", ssrc, e),
                }
            }
        }

        for (pid, msg) in notifications {
            send_to(sessions, pid, msg);
        }
    }

    // ── Renegotiation ────────────────────────────────────────────────

    /// Offer the participant its current subscription set (`track_ids`).
    ///
    /// Subscriptions map onto m-lines: new tracks reuse an inactive m-line of
    /// the same kind or append one; dropped tracks turn inactive. Subscribe-only
    /// participants get their transport on the first subscription.
    pub fn trigger_subscriber_renegotiation(
        &mut self,
        participant_id: u64,
        track_ids: &[TrackId],
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let existing_transport = match self.states.get(&participant_id) {
            Some(s) => s.transport_id,
            None => return,
        };
        let transport_id = match existing_transport {
            Some(id) => id,
            // Nothing negotiated and nothing to subscribe: no offer needed
            None if track_ids.is_empty() => return,
            None => {
                match Self::create_transport(&self.webrtc_transport, participant_id, sessions) {
                    Some((id, _, _)) => id,
                    None => return,
                }
            }
        };

        // Resolve kinds before borrowing state mutably
        let kinds: Vec<(TrackId, u8)> = track_ids
            .iter()
            .take(MAX_MLINES)
            .map(|&tid| {
                let kind = self
                    .distributed_state
                    .get_track(tid)
                    .map(|info| info.track_type)
                    .unwrap_or(1);
                (tid, kind)
            })
            .collect();

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };
        if existing_transport.is_none() {
            state.transport_id = Some(transport_id);
            state.session_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.session_version = 0;
        }
        state.last_subscribed_track_ids = track_ids.to_vec();

        // Dropped subscriptions keep their m-line position but go inactive
        for slot in state.mlines.iter_mut() {
            if let MlineRole::Subscribe(tid) = slot.role {
                if !track_ids.contains(&tid) {
                    slot.role = MlineRole::Inactive;
                }
            }
        }
        for (tid, kind) in kinds {
            let already = state
                .mlines
                .iter()
                .any(|s| s.role == MlineRole::Subscribe(tid));
            if already {
                continue;
            }
            if let Some(slot) = state
                .mlines
                .iter_mut()
                .find(|s| s.role == MlineRole::Inactive && s.kind == kind)
            {
                slot.role = MlineRole::Subscribe(tid);
            } else if state.mlines.len() < MAX_MLINES {
                let mid = state.next_mid_index.to_string();
                state.next_mid_index += 1;
                state.mlines.push(MlineSlot {
                    mid,
                    kind,
                    role: MlineRole::Subscribe(tid),
                });
            } else {
                warn!(
                    "Participant {} at {} m-lines, not offering track {}",
                    participant_id, MAX_MLINES, tid
                );
            }
        }

        self.send_ordered_offer(participant_id, transport_id, sessions);
    }

    /// Build and send an offer from the participant's m-lines, in order.
    ///
    /// Publish m-lines are recvonly with the publish codec, subscriptions are
    /// sendonly with the forwarded track's SSRC, inactive ones stay as
    /// placeholders. Starts ICE gathering on a transport's first offer.
    fn send_ordered_offer(
        &mut self,
        participant_id: u64,
        transport_id: TransportId,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get(&participant_id) {
            Some(s) => s,
            None => return,
        };
        if state.mlines.is_empty() {
            return;
        }
        assert!(
            state.mlines.len() <= MAX_MLINES,
            "m-line count must be bounded"
        );

        let (ice_ufrag, ice_pwd, dtls_fp) =
            match self.webrtc_transport.with_session(transport_id, |ws| {
                let creds = ws.local_ice_credentials().clone();
                (creds.local_ufrag, creds.local_pwd, *ws.dtls_fingerprint())
            }) {
                Some(v) => v,
                None => {
                    send_error(
                        sessions,
                        participant_id,
                        "SESSION_NOT_FOUND",
                        "Session gone",
                    );
                    return;
                }
            };
        let negotiator = match SdpNegotiator::with_defaults(
            ice_ufrag,
            ice_pwd,
            nexus_webrtc::sdp::DtlsFingerprint {
                algorithm: nexus_webrtc::sdp::FingerprintAlgorithm::Sha256,
                value: {
                    let mut v = [0u8; 64];
                    v[..32].copy_from_slice(&dtls_fp);
                    v
                },
                value_len: 32,
            },
        ) {
            Ok(n) => n,
            Err(e) => {
                warn!("Negotiator failed: {:?}", e);
                return;
            }
        };

        let audio_codec: Vec<nexus_webrtc::sdp::RtpCodec> =
            publish_codec(true).into_iter().collect();
        let video_codec: Vec<nexus_webrtc::sdp::RtpCodec> =
            publish_codec(false).into_iter().collect();
        let mut mid_map: Vec<(TrackId, String)> = Vec::new();
        let mlines: Vec<OfferMline> = state
            .mlines
            .iter()
            .map(|slot| {
                let codecs: &[nexus_webrtc::sdp::RtpCodec] = if slot.kind == 0 {
                    &audio_codec
                } else {
                    &video_codec
                };
                let recycled = |direction| {
                    OfferMline::Recycled(nexus_webrtc::sdp::RecycledMline {
                        mid: slot.mid.as_str(),
                        media_kind: slot.kind,
                        codecs,
                        fmtps: &[],
                        offer_pts: &[],
                        extmaps: &[],
                        direction,
                    })
                };
                match slot.role {
                    MlineRole::Publish => recycled(nexus_webrtc::sdp::Direction::RecvOnly),
                    MlineRole::Subscribe(tid) => match self.ssrc_router.lookup_ssrc_by_track(tid) {
                        Some(ssrc) => {
                            mid_map.push((tid, slot.mid.clone()));
                            OfferMline::Track {
                                ssrc,
                                media_kind: slot.kind,
                                mid: slot.mid.as_str(),
                            }
                        }
                        // Track gone (publisher left): keep the position, send nothing
                        None => recycled(nexus_webrtc::sdp::Direction::Inactive),
                    },
                    MlineRole::Inactive => recycled(nexus_webrtc::sdp::Direction::Inactive),
                }
            })
            .collect();

        let session_id = state.session_id;
        let session_version = state.session_version + 1;
        let offer_sdp = match negotiator.create_ordered_offer(
            session_id,
            session_version,
            &mlines,
            state.mid_ext_id,
            &[],
            &[],
            None,
            None,
            None,
            None,
        ) {
            Ok((sdp, _)) => sdp,
            Err(e) => {
                warn!("Offer for participant {} failed: {:?}", participant_id, e);
                return;
            }
        };

        send_to(
            sessions,
            participant_id,
            SignalMessage::Offer {
                sdp: offer_sdp,
                tracks: mid_map
                    .iter()
                    .map(|(track_id, mid)| OfferTrack {
                        track_id: *track_id,
                        mid: mid.clone(),
                    })
                    .collect(),
            },
        );

        let needs_gathering = match self.states.get_mut(&participant_id) {
            Some(state) => {
                info!(
                    "Offer sent to participant {} with {} m-lines ({} subscribed)",
                    participant_id,
                    state.mlines.len(),
                    mid_map.len()
                );
                state.pending_mid_map = mid_map;
                state.offer_pending = true;
                state.renegotiation_needed = false;
                state.session_version = session_version;
                state.gathering_state == GatheringState::Idle
            }
            None => return,
        };
        if needs_gathering {
            self.start_ice_gathering(participant_id, transport_id);
        }
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    pub fn cleanup_participant(&mut self, participant_id: u64) {
        if let Some(state) = self.states.remove(&participant_id) {
            // Remove published tracks
            for &track_id in &state.published_tracks {
                self.ssrc_router.remove_by_track(track_id);
                if let Ok(mut pool) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.worker_pool.write()
                })) {
                    let _ = pool.remove_track(track_id);
                }
                self.distributed_state.remove_track(track_id);
            }
            // Remove WebRTC session
            if let Some(tid) = state.transport_id {
                self.webrtc_transport.remove_session(tid);
            }
        }
    }
}

/// Codec the SFU offers on a publisher's upstream m-line.
///
/// Payload types match the negotiator's defaults (opus 111, VP8 96) that
/// subscriber m-lines use, since forwarded packets keep the publisher's PT.
/// Audio and video must not share a PT within one BUNDLE (RFC 8843 §9.2).
fn publish_codec(audio: bool) -> Option<nexus_webrtc::sdp::RtpCodec> {
    let (pt, spec) = if audio {
        (111, "opus/48000/2")
    } else {
        (96, "VP8/90000")
    };
    nexus_webrtc::sdp::RtpCodec::parse(pt, spec).ok()
}

fn send_to(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, msg: SignalMessage) {
    if let Some(handle) = sessions.get(&participant_id) {
        let _ = handle.outbound_tx.try_send(msg);
    }
}

fn send_error(
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
