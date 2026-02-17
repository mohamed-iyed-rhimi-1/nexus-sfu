//! NegotiationManager: transport creation, ICE gathering, SDP offer/answer,
//! MID tracking, track registration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::forward::SsrcRouter;
use crate::signal::SignalMessage;
use crate::types::{MediaKind, TrackId};
use crate::worker::{WorkerMessage, WorkerPool};
use nexus_state::DistributedState;
use nexus_state::gossip::types::TrackInfo;
use nexus_transport::ice::{Candidate, IceCredentials, MAX_CANDIDATES};
use nexus_webrtc::sdp::{MediaType, SdpNegotiator};
use nexus_webrtc::webrtc::{TransportId, WebRtcTransport};

use super::ParticipantHandle;

const MAX_TRACKS_PER_PARTICIPANT: u32 = 10;
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

/// Per-participant negotiation state.
pub struct NegotiationState {
    pub transport_id: Option<TransportId>,
    pub published_tracks: Vec<TrackId>,
    pub published_kinds: Vec<(String, String)>,
    pub pending_mid_map: Vec<(TrackId, String)>,
    pub offer_pending: bool,
    pub renegotiation_needed: bool,
    pub next_mid_index: u32,
    pub initial_mids: Vec<(String, u8)>,
    pub mid_ext_id: u8,
    pub twcc_ext_id: u8,
    pub gathering_state: GatheringState,
    pub gathering_generation: u32,
    pub candidates_trickled: u8,
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
            initial_mids: Vec::new(),
            mid_ext_id: 1,
            twcc_ext_id: 0,
            gathering_state: GatheringState::Idle,
            gathering_generation: 0,
            candidates_trickled: 0,
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
    pub fn transport_id(&self, participant_id: u64) -> Option<TransportId> {
        self.states.get(&participant_id).and_then(|s| s.transport_id)
    }

    /// Get the SRTP key material for a participant's transport.
    pub fn get_srtp_key_material(&self, participant_id: u64) -> Option<(nexus_transport::srtp::KeyMaterial, nexus_transport::srtp::SrtpPolicy, u64)> {
        let tid = self.transport_id(participant_id)?;
        self.webrtc_transport.with_session(tid, |ws| {
            ws.get_srtp_key_material()
        }).flatten()
    }

    /// Take the pending_mid_map for media activation.
    pub fn take_pending_mid_map(&mut self, participant_id: u64) -> Vec<(TrackId, String)> {
        self.states.get_mut(&participant_id)
            .map(|s| std::mem::take(&mut s.pending_mid_map))
            .unwrap_or_default()
    }

    /// Get the selected remote address for a participant's transport.
    pub fn selected_remote_addr(&self, participant_id: u64) -> Option<SocketAddr> {
        let tid = self.transport_id(participant_id)?;
        self.webrtc_transport.with_session(tid, |ws| {
            ws.selected_pair().map(|(_, remote)| remote)
        }).flatten()
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
        assert!(participant_id != 0);
        assert!(kinds.len() == contents.len());
        assert!(kinds.len() <= MAX_TRACKS_PER_PARTICIPANT as usize);

        let state = match self.states.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let published_kinds: Vec<(String, String)> = kinds.iter()
            .zip(contents.iter())
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        state.published_kinds = published_kinds.clone();

        // Create or reuse transport
        let is_renegotiation = state.transport_id.map_or(false, |tid| {
            self.webrtc_transport.with_session(tid, |ws| ws.is_established()).unwrap_or(false)
        });

        let (transport_id, ice_creds, dtls_fingerprint) = if is_renegotiation {
            let tid = state.transport_id.unwrap();
            match self.webrtc_transport.with_session(tid, |ws| {
                (ws.local_ice_credentials().clone(), *ws.dtls_fingerprint())
            }) {
                Some((creds, fp)) => (tid, creds, fp),
                None => {
                    send_error(sessions, participant_id, "SESSION_NOT_FOUND", "Existing session gone");
                    return;
                }
            }
        } else {
            let dtls_params = nexus_webrtc::webrtc::DtlsParameters::new(
                nexus_webrtc::webrtc::DtlsRole::Server,
            );
            let transport_id = match self.webrtc_transport.create_session(dtls_params) {
                Ok(id) => id,
                Err(e) => {
                    send_error(sessions, participant_id, "SESSION_FAILED", &format!("{:?}", e));
                    return;
                }
            };
            match self.webrtc_transport.with_session(transport_id, |ws| {
                (ws.local_ice_credentials().clone(), *ws.dtls_fingerprint())
            }) {
                Some((creds, fp)) => (transport_id, creds, fp),
                None => {
                    send_error(sessions, participant_id, "SESSION_FAILED", "Session not found after creation");
                    return;
                }
            }
        };

        state.transport_id = Some(transport_id);

        // Build SDP offer
        let session_id_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
                media_type, 9,
                nexus_webrtc::sdp::TransportProtocol::UdpTlsRtpSavpf,
            );
            media.mid = Some(nexus_webrtc::sdp::Mid::new(&idx.to_string()));
            media.direction = nexus_webrtc::sdp::Direction::RecvOnly;
            media.rtcp_mux = true;
            let codec = if media_type == nexus_webrtc::sdp::MediaType::Audio {
                nexus_webrtc::sdp::RtpCodec::parse(96, "opus/48000/2")
            } else {
                nexus_webrtc::sdp::RtpCodec::parse(96, "VP8/90000")
            };
            if let Ok(c) = codec { let _ = media.add_codec(c); }
            let _ = sdp.add_media(media);
        }

        // Add sendonly m-lines for existing subscriptions
        if let Some(sub_count) = sessions.get(&participant_id).map(|_| {
            // SubscriptionManager owns this data — we just need the count
            // for now, subscribed tracks are added during renegotiation
            0usize
        }) {
            let _ = sub_count; // placeholder
        }

        let offer_sdp = nexus_webrtc::sdp::SdpPrinter::print(&sdp);
        send_to(sessions, participant_id, SignalMessage::Offer { sdp: offer_sdp });

        state.offer_pending = true;
        self.start_ice_gathering(participant_id, transport_id);
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
        assert!(participant_id != 0);
        assert!(!sdp.is_empty());

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
                warn!("Failed to parse answer SDP from {}: {:?}", participant_id, e);
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

        // First answer: register published tracks from SSRCs
        let is_first_answer = state.published_tracks.is_empty();
        state.offer_pending = false;

        if is_first_answer {
            // Drop the mutable borrow on state before calling register_tracks_from_sdp
            self.register_tracks_from_sdp(participant_id, &answer, sessions);
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
                let _ = pool.send_to_track(*track_id, WorkerMessage::SetTrackMid {
                    track_id: *track_id,
                    mid_ext_id,
                    mid_value,
                    mid_value_len: mid_len as u8,
                });
            }
            let needed = state.renegotiation_needed;
            state.renegotiation_needed = false;
            needed
        };

        if needs_renego {
            self.trigger_subscriber_renegotiation(participant_id, sessions);
        }

        info!("Answer processed from participant {}", participant_id);
    }

    fn extract_ice_creds(sdp: &nexus_webrtc::sdp::SessionDescription) -> (Option<String>, Option<String>) {
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
                participant_id, transport_id, candidate, generation,
            });
            let _ = tx.send(IceGatheringEvent::Complete {
                participant_id, transport_id, generation,
            });
        });
    }

    pub fn dispatch_ice_event(
        &mut self,
        event: IceGatheringEvent,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        match event {
            IceGatheringEvent::Candidate { participant_id, transport_id, candidate, generation } => {
                self.handle_ice_candidate_discovered(participant_id, transport_id, candidate, generation, sessions);
            }
            IceGatheringEvent::Complete { participant_id, transport_id, generation } => {
                self.handle_ice_gathering_complete(participant_id, transport_id, generation, sessions);
            }
            IceGatheringEvent::Failed { participant_id, transport_id: _, generation, reason: _ } => {
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
        if state.gathering_generation != generation { return; }
        if state.candidates_trickled >= MAX_CANDIDATES as u8 { return; }

        let candidate_sdp = candidate.to_sdp_string();
        send_to(sessions, participant_id, SignalMessage::IceCandidate {
            candidate: candidate_sdp,
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
        });
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
        if state.gathering_generation != generation { return; }
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
        if state.gathering_generation != generation { return; }
        state.gathering_state = GatheringState::Failed;
        send_to(sessions, participant_id, SignalMessage::EndOfCandidates);
    }

    // ── Trickle ICE ──────────────────────────────────────────────────

    pub fn handle_candidate(&mut self, participant_id: u64, candidate_str: &str) {
        assert!(participant_id != 0);
        assert!(!candidate_str.is_empty());

        let tid = match self.states.get(&participant_id).and_then(|s| s.transport_id) {
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

    fn register_tracks_from_sdp(
        &mut self,
        participant_id: u64,
        sdp: &nexus_webrtc::sdp::SessionDescription,
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
            let ssrc_values = media.get_ssrc_values();
            for &ssrc in ssrc_values.iter().take(8) {
                if ssrc == 0 { continue; }
                if state.published_tracks.len() >= MAX_TRACKS_PER_PARTICIPANT as usize { break; }

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
                            let _ = pool.send_to_track(track_id, WorkerMessage::SetTrackTwccExtId {
                                track_id,
                                twcc_ext_id: state.twcc_ext_id,
                            });
                        }

                        if let Some(rid) = room_id {
                            let participants = self.distributed_state.get_participants(rid);
                            for &pid in participants.iter().take(MAX_PARTICIPANTS_PER_ROOM as usize) {
                                if pid == participant_id { continue; }
                                notifications.push((pid, SignalMessage::TrackPublished {
                                    publisher_id: participant_id,
                                    track_id,
                                    kind: if kind == MediaKind::Audio { "audio".to_string() } else { "video".to_string() },
                                    content: match content_type { 1 => "screen", 2 => "audio", _ => "camera" }.to_string(),
                                }));
                            }
                        }
                        info!("Track {} registered: SSRC={}, worker={}, kind={:?}", track_id, ssrc, worker_id, kind);
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

    pub fn trigger_subscriber_renegotiation(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let state = match self.states.get(&participant_id) {
            Some(s) => s,
            None => return,
        };
        let transport_id = match state.transport_id {
            Some(id) => id,
            None => return,
        };

        // Collect subscribed track IDs from ParticipantHandle
        let track_ids: Vec<TrackId> = sessions.get(&participant_id)
            .map(|h| h.subscribed_track_ids())
            .unwrap_or_default();
        if track_ids.is_empty() { return; }

        let initial_mid_offset = state.initial_mids.len() as u32;
        let initial_mids = state.initial_mids.clone();
        let mid_ext_id = state.mid_ext_id;

        // Build track info
        let mut track_info: Vec<(u32, u8, String)> = Vec::with_capacity(track_ids.len());
        let mut track_mid_updates: Vec<(TrackId, String)> = Vec::new();

        for (i, &track_id) in track_ids.iter().enumerate().take(MAX_TRACKS_PER_PARTICIPANT as usize) {
            let ssrc = match self.ssrc_router.lookup_ssrc_by_track(track_id) {
                Some(s) => s,
                None => continue,
            };
            let media_kind = self.distributed_state.get_track(track_id)
                .map(|info| info.track_type)
                .unwrap_or(1u8);
            let mid = format!("{}", initial_mid_offset + i as u32);
            track_mid_updates.push((track_id, mid.clone()));
            track_info.push((ssrc as u32, media_kind, mid));
        }

        if track_info.is_empty() { return; }

        // Get credentials
        let (ice_ufrag, ice_pwd, dtls_fp) = match self.webrtc_transport.with_session(transport_id, |ws| {
            let creds = ws.local_ice_credentials().clone();
            let fp = *ws.dtls_fingerprint();
            (creds.local_ufrag, creds.local_pwd, fp)
        }) {
            Some(v) => v,
            None => return,
        };

        let negotiator = match SdpNegotiator::with_defaults(
            ice_ufrag, ice_pwd,
            nexus_webrtc::sdp::DtlsFingerprint {
                algorithm: nexus_webrtc::sdp::FingerprintAlgorithm::Sha256,
                value: { let mut v = [0u8; 64]; v[..32].copy_from_slice(&dtls_fp); v },
                value_len: 32,
            },
        ) {
            Ok(n) => n,
            Err(e) => { warn!("Negotiator failed: {:?}", e); return; }
        };

        let track_refs: Vec<(u32, u8, &str)> = track_info.iter()
            .map(|(ssrc, kind, mid)| (*ssrc, *kind, mid.as_str()))
            .collect();
        let existing_mid_refs: Vec<nexus_webrtc::sdp::RecycledMline> = initial_mids.iter()
            .map(|(mid, kind)| nexus_webrtc::sdp::RecycledMline {
                mid: mid.as_str(), media_kind: *kind,
                codecs: &[], fmtps: &[], offer_pts: &[], extmaps: &[],
                direction: nexus_webrtc::sdp::Direction::SendOnly,
            })
            .collect();

        let (offer_sdp_str, _) = match negotiator.create_renegotiation_offer(
            participant_id, 1u64, &existing_mid_refs, &track_refs,
            mid_ext_id, &[], &[], None, None, None, None,
        ) {
            Ok(sdp) => sdp,
            Err(e) => { warn!("Renegotiation offer failed: {:?}", e); return; }
        };

        send_to(sessions, participant_id, SignalMessage::Offer { sdp: offer_sdp_str });

        if let Some(state) = self.states.get_mut(&participant_id) {
            state.pending_mid_map = track_mid_updates;
            state.offer_pending = true;
            state.renegotiation_needed = false;
            state.next_mid_index = initial_mid_offset + track_info.len() as u32;
        }

        info!("Renegotiation offer sent to participant {} with {} tracks", participant_id, track_info.len());
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    pub fn cleanup_participant(&mut self, participant_id: u64) {
        if let Some(state) = self.states.remove(&participant_id) {
            // Remove published tracks
            for &track_id in &state.published_tracks {
                self.ssrc_router.remove_by_track(track_id);
                if let Ok(mut pool) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.worker_pool.write())) {
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
