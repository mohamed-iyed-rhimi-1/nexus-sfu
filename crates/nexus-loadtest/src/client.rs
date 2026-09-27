//! Headless WebRTC client implementation
//!
//! Lightweight WebRTC client using webrtc-rs for media transport
//! and nexus-signal for signaling protocol compatibility.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_core::{ParticipantId, TrackId};
use nexus_signal::{OfferTrack, SignalMessage};
use tokio::sync::Mutex;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_sender::RTCRtpSender;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::announced::{Announced, AnnouncedSsrcs};
use crate::config::{ClientConfig, ClientRole};
use crate::error::ClientError;
use crate::media::{
    read_marker, stamp_marker, AudioGenerator, AudioPattern, VideoGenerator, VideoPattern,
};
use crate::metrics::ClientMetrics;
use crate::signaling::SignalingConnection;
use crate::track_stats::{TrackRxStats, TrackStatsMap};

/// Client connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// Not connected to SFU
    Disconnected,
    /// Connection in progress
    Connecting,
    /// Connected to SFU
    Connected,
    /// Publishing media
    Publishing,
    /// Subscribing to media
    Subscribing,
    /// Fully active (publishing and/or subscribing based on role)
    Active,
    /// Connection failed
    Failed,
}

impl ClientState {
    /// Returns the state name as a static string
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientState::Disconnected => "Disconnected",
            ClientState::Connecting => "Connecting",
            ClientState::Connected => "Connected",
            ClientState::Publishing => "Publishing",
            ClientState::Subscribing => "Subscribing",
            ClientState::Active => "Active",
            ClientState::Failed => "Failed",
        }
    }
}

/// Lightweight WebRTC client for load testing
pub struct HeadlessClient {
    /// Client configuration
    config: ClientConfig,
    /// Assigned participant ID (set after joining room)
    participant_id: Option<ParticipantId>,
    /// Collected metrics
    metrics: ClientMetrics,
    /// Current connection state
    state: ClientState,
    /// WebRTC peer connection
    peer_connection: Option<Arc<RTCPeerConnection>>,
    /// Signaling connection
    signaling: Option<Arc<Mutex<SignalingConnection>>>,
    /// Connection start time for tracking connection duration
    connection_start: Option<Instant>,
    /// Flag to stop publishing task
    publishing_stop_flag: Option<Arc<AtomicBool>>,
    /// Video track for publishing
    video_track: Option<Arc<TrackLocalStaticSample>>,
    /// Audio track for publishing
    audio_track: Option<Arc<TrackLocalStaticSample>>,
    /// Subscription start time for tracking time to first frame
    subscription_start: Option<Instant>,
    /// Shared counter: total RTP packets received by on_track readers
    rx_packets: Arc<AtomicU64>,
    /// Shared counter: total RTP bytes received by on_track readers
    rx_bytes: Arc<AtomicU64>,
    /// Flag set when the first frame is received (for TTFF measurement)
    first_frame_received: Arc<AtomicBool>,
    /// Timestamp when we started waiting for the first frame
    first_frame_start: Option<Instant>,
    /// Flag to stop background signaling task
    signaling_stop_flag: Option<Arc<AtomicBool>>,
    /// Previous rx_packets count for computing per-interval deltas
    last_rx_count: u64,
    /// Timestamp of last sync_metrics call
    metrics_sync_instant: Option<Instant>,
    /// Previous per-packet arrival interval for jitter computation
    last_per_packet_time: Option<Duration>,
    /// Set once ICE reaches Connected/Completed
    ice_connected: Arc<AtomicBool>,
    /// Remote track IDs announced by the SFU (Joined + TrackPublished), not yet subscribed
    announced_tracks: Vec<TrackId>,
    /// What was received on each remote track, by SSRC
    track_stats: TrackStatsMap,
    /// Senders of the published video and audio tracks
    video_sender: Option<Arc<RTCRtpSender>>,
    audio_sender: Option<Arc<RTCRtpSender>>,
    /// SSRCs the SFU's latest offer announces for the tracks it sends us
    announced: AnnouncedSsrcs,
}

impl HeadlessClient {
    /// Create a new headless client
    pub async fn new(config: ClientConfig) -> Result<Self, ClientError> {
        Ok(Self {
            config,
            participant_id: None,
            metrics: ClientMetrics::default(),
            state: ClientState::Disconnected,
            peer_connection: None,
            signaling: None,
            connection_start: None,
            publishing_stop_flag: None,
            video_track: None,
            audio_track: None,
            subscription_start: None,
            rx_packets: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            first_frame_received: Arc::new(AtomicBool::new(false)),
            first_frame_start: None,
            signaling_stop_flag: None,
            last_rx_count: 0,
            metrics_sync_instant: None,
            last_per_packet_time: None,
            ice_connected: Arc::new(AtomicBool::new(false)),
            announced_tracks: Vec::new(),
            track_stats: TrackStatsMap::default(),
            video_sender: None,
            audio_sender: None,
            announced: AnnouncedSsrcs::default(),
        })
    }

    /// Create WebRTC peer connection with default configuration
    async fn create_peer_connection(&self) -> Result<Arc<RTCPeerConnection>, ClientError> {
        // Create a MediaEngine with default codecs
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;

        // Register RTP header extensions required for track demuxing.
        // Without these, webrtc-rs cannot match incoming RTP packets to
        // transceivers and on_track will never fire.
        use webrtc::rtp_transceiver::rtp_codec::RTCRtpHeaderExtensionCapability;
        for codec_type in [
            webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Audio,
            webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Video,
        ] {
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: "urn:ietf:params:rtp-hdrext:sdes:mid".to_string(),
                    },
                    codec_type,
                    None,
                )
                .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_string(),
                    },
                    codec_type,
                    None,
                )
                .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id".to_string(),
                    },
                    codec_type,
                    None,
                )
                .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;
        }

        // Create an interceptor registry for RTCP reports
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;

        // Create the API with the MediaEngine
        let mut setting_engine = webrtc::api::setting_engine::SettingEngine::default();
        // Increase internal buffers to prevent "buffer: full" drops under load
        setting_engine.set_receive_mtu(8192);
        if let Some(role) = self.config.answering_dtls_role {
            setting_engine
                .set_answering_dtls_role(role)
                .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;
        }
        if let Some(rules) = &self.config.loss {
            let conn = crate::lossy::LossyUdpConn::bind(
                std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                std::sync::Arc::clone(rules),
            )
            .await
            .map_err(|e| ClientError::PeerConnectionFailed(format!("lossy socket: {e}")))?;
            let mux = webrtc::ice::udp_mux::UDPMuxDefault::new(
                webrtc::ice::udp_mux::UDPMuxParams::new(conn),
            );
            setting_engine.set_udp_network(webrtc::ice::udp_network::UDPNetwork::Muxed(mux));
        }
        if self.config.ipv4_only {
            setting_engine.set_network_types(vec![webrtc::ice::network_type::NetworkType::Udp4]);
        }
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();

        // Build ICE server list: use configured servers or fall back to Google public STUN
        let ice_servers = if self.config.ice_servers.is_empty() && !self.config.default_stun {
            Vec::new()
        } else if self.config.ice_servers.is_empty() {
            vec![webrtc::ice_transport::ice_server::RTCIceServer {
                urls: vec![
                    "stun:stun.l.google.com:19302".to_string(),
                    "stun:stun1.l.google.com:19302".to_string(),
                ],
                ..Default::default()
            }]
        } else {
            vec![webrtc::ice_transport::ice_server::RTCIceServer {
                urls: self.config.ice_servers.clone(),
                ..Default::default()
            }]
        };

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        // Create the peer connection
        let peer_connection = api
            .new_peer_connection(config)
            .await
            .map_err(|e| ClientError::PeerConnectionFailed(e.to_string()))?;

        Ok(Arc::new(peer_connection))
    }

    /// Connect to the SFU and join the room
    ///
    /// This method:
    /// 1. Establishes and authenticates the signaling connection with timeout
    /// 2. Joins the specified room
    /// 3. Creates the WebRTC peer connection and its event handlers
    ///
    /// No SDP is exchanged here: the SFU is the sole offerer and sends an Offer
    /// after `start_publishing()` (Publish) or `discover_and_subscribe()` (Subscribe).
    pub async fn connect(&mut self) -> Result<(), ClientError> {
        self.state = ClientState::Connecting;
        self.connection_start = Some(Instant::now());

        let participant_name = format!("loadtest-{:?}-{}", self.config.role, rand_id());

        // Step 1: Establish signaling connection with timeout
        let signaling = SignalingConnection::connect_with_timeout(
            &self.config.sfu_url,
            &self.config.connection,
            &participant_name,
            self.config.connection_timeout,
        )
        .await
        .map_err(|e| {
            ClientError::PeerConnectionFailed(format!("Signaling connection failed: {}", e))
        })?;

        let signaling = Arc::new(Mutex::new(signaling));
        self.signaling = Some(signaling.clone());

        // Step 2: Join the room
        // Use room ID directly if it's numeric, otherwise hash the string
        let mut room_id: u64 = self.config.room.parse().unwrap_or_else(|_| {
            // Simple hash for string room names (fallback for backwards compatibility)
            // Note: For production use, you should use the actual room ID from the API
            let mut hash: u64 = 0;
            for byte in self.config.room.bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            }
            tracing::warn!(
                "Room '{}' is not a numeric ID, using hash {}. For best results, use the numeric room ID from the API.",
                self.config.room,
                hash
            );
            hash
        });

        let join_response = {
            let mut sig = signaling.lock().await;

            // Broadcaster creates the room; viewers just join.
            // If join fails with room_not_found, try creating first then re-join.
            match sig.join_room(room_id, &participant_name).await {
                Ok(resp) => resp,
                Err(e) => {
                    // Room doesn't exist — create it and retry join
                    let create_msg = nexus_signal::protocol::SignalMessage::Create {
                        room_name: Some(self.config.room.clone()),
                    };
                    sig.send(create_msg).await.map_err(|e| {
                        ClientError::PeerConnectionFailed(format!("Failed to create room: {}", e))
                    })?;

                    // Wait for Created response
                    loop {
                        let msg = sig.recv().await.map_err(|e| {
                            ClientError::PeerConnectionFailed(format!(
                                "Failed to recv create response: {}",
                                e
                            ))
                        })?;
                        match msg {
                            nexus_signal::protocol::SignalMessage::Created {
                                room_id: created_id,
                                ..
                            } => {
                                tracing::info!("Created room {}", created_id);
                                room_id = created_id;
                                break;
                            }
                            nexus_signal::protocol::SignalMessage::Error { code, message } => {
                                return Err(ClientError::PeerConnectionFailed(format!(
                                    "Room creation failed: {} - {}",
                                    code, message
                                )));
                            }
                            _ => continue,
                        }
                    }

                    // Now join the created room
                    sig.join_room(room_id, &participant_name)
                        .await
                        .map_err(|e2| {
                            ClientError::PeerConnectionFailed(format!(
                                "Failed to join room after create: {} (original: {})",
                                e2, e
                            ))
                        })?
                }
            }
        };

        self.participant_id = Some(join_response.participant_id);
        // Tracks published before we joined are only listed here, never re-announced
        self.note_announced_tracks(
            join_response
                .tracks
                .iter()
                .map(|t| (t.track_id, t.publisher_id)),
        );

        // Step 3: Create WebRTC peer connection
        let peer_connection = self.create_peer_connection().await?;
        self.peer_connection = Some(peer_connection.clone());

        // Set up ICE candidate handler
        let signaling_for_ice = signaling.clone();
        peer_connection.on_ice_candidate(Box::new(move |candidate| {
            let signaling = signaling_for_ice.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    let candidate_json = match candidate.to_json() {
                        Ok(json) => json,
                        Err(_) => return,
                    };

                    let msg = SignalMessage::IceCandidate {
                        candidate: candidate_json.candidate,
                        sdp_mid: candidate_json.sdp_mid,
                        sdp_mline_index: candidate_json.sdp_mline_index.map(|i| i as u32),
                    };

                    let mut sig = signaling.lock().await;
                    let _ = sig.send(msg).await;
                }
            })
        }));

        let ice_connected = Arc::clone(&self.ice_connected);
        peer_connection.on_ice_connection_state_change(Box::new(move |state| {
            if state == RTCIceConnectionState::Connected
                || state == RTCIceConnectionState::Completed
            {
                ice_connected.store(true, Ordering::SeqCst);
            }
            Box::pin(async {})
        }));

        // Set up on_track handler to consume incoming RTP and track metrics
        let rx_packets = Arc::clone(&self.rx_packets);
        let rx_bytes = Arc::clone(&self.rx_bytes);
        let first_frame_received = Arc::clone(&self.first_frame_received);
        let track_stats = self.track_stats.clone();

        peer_connection.on_track(Box::new(move |track, _receiver, _transceiver| {
            let rx_packets = Arc::clone(&rx_packets);
            let rx_bytes = Arc::clone(&rx_bytes);
            let first_frame_received = Arc::clone(&first_frame_received);
            let track_stats = track_stats.clone();

            Box::pin(async move {
                tracing::info!(
                    "on_track fired: ssrc={}, rid={}, codec={}, kind={}",
                    track.ssrc(),
                    track.rid(),
                    track.codec().capability.mime_type,
                    track.kind(),
                );

                // Mark first frame received
                first_frame_received.store(true, Ordering::SeqCst);

                // Spawn a reader task that drains RTP packets and counts them
                let track_clone = track.clone();
                let kind = track.kind().to_string();
                let mime_type = track.codec().capability.mime_type;
                tokio::spawn(async move {
                    let mut pkt_count: u64 = 0;
                    loop {
                        match track_clone.read_rtp().await {
                            Ok((rtp_packet, _attributes)) => {
                                let payload_len = rtp_packet.payload.len();
                                pkt_count += 1;
                                track_stats.record(
                                    rtp_packet.header.ssrc,
                                    &kind,
                                    &mime_type,
                                    rtp_packet.header.sequence_number,
                                    rtp_packet.header.timestamp,
                                );
                                if let Some((marker_ssrc, frame)) =
                                    read_marker(kind == "video", &rtp_packet.payload)
                                {
                                    track_stats.record_marker(
                                        rtp_packet.header.ssrc,
                                        marker_ssrc,
                                        frame,
                                    );
                                }
                                if pkt_count <= 3 {
                                    tracing::info!(
                                        "RTP pkt #{}: ssrc={} pt={} seq={} ts={} marker={} payload_len={}",
                                        pkt_count,
                                        rtp_packet.header.ssrc,
                                        rtp_packet.header.payload_type,
                                        rtp_packet.header.sequence_number,
                                        rtp_packet.header.timestamp,
                                        rtp_packet.header.marker,
                                        payload_len,
                                    );
                                }
                                if payload_len == 0 {
                                    continue;
                                }
                                rx_packets.fetch_add(1, Ordering::Relaxed);
                                rx_bytes.fetch_add(payload_len as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::warn!("RTP read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            })
        }));

        // Record when we start waiting for first frame (for TTFF)
        self.first_frame_start = Some(Instant::now());

        // Connected = authenticated and joined. ICE comes up with the first
        // SFU offer, in start_publishing() or discover_and_subscribe().
        if let Some(start) = self.connection_start {
            self.metrics.connection_time = Some(start.elapsed());
        }
        self.metrics.connection_successful = true;
        self.state = ClientState::Connected;

        Ok(())
    }

    /// Record announced remote tracks, skipping our own and duplicates
    fn note_announced_tracks(
        &mut self,
        tracks: impl IntoIterator<Item = (TrackId, ParticipantId)>,
    ) {
        for (track_id, publisher_id) in tracks {
            if Some(publisher_id) == self.participant_id
                || self.announced_tracks.contains(&track_id)
            {
                continue;
            }
            self.announced_tracks.push(track_id);
        }
    }

    /// Receive one signaling message (waiting at most `wait`) and handle what
    /// every phase needs: answer SFU offers, add candidates, buffer announced
    /// tracks, and fail on SFU errors. Returns `None` if nothing arrived.
    async fn pump_signaling(&mut self, wait: Duration) -> Result<Option<Pumped>, ClientError> {
        let not_connected = || ClientError::InvalidState {
            expected: "Connected",
            actual: "Disconnected",
        };
        let signaling = Arc::clone(self.signaling.as_ref().ok_or_else(not_connected)?);
        let peer_connection = Arc::clone(self.peer_connection.as_ref().ok_or_else(not_connected)?);

        let msg = {
            let mut sig = signaling.lock().await;
            match tokio::time::timeout(wait, sig.recv()).await {
                Err(_) => return Ok(None),
                Ok(Err(e)) => {
                    return Err(ClientError::PeerConnectionFailed(format!(
                        "Signaling receive error: {}",
                        e
                    )))
                }
                Ok(Ok(msg)) => msg,
            }
        };

        match msg {
            SignalMessage::Offer { sdp, tracks } => {
                answer_offer(&peer_connection, &signaling, sdp, &tracks, &self.announced).await?;
                Ok(Some(Pumped::Offer))
            }
            SignalMessage::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } => {
                add_remote_candidate(&peer_connection, candidate, sdp_mid, sdp_mline_index).await;
                Ok(Some(Pumped::Other))
            }
            SignalMessage::TrackPublished {
                track_id,
                publisher_id,
                ..
            } => {
                self.note_announced_tracks([(track_id, publisher_id)]);
                Ok(Some(Pumped::Other))
            }
            SignalMessage::Subscribed { track_ids } => {
                Ok(Some(Pumped::Subscribed(track_ids.len())))
            }
            SignalMessage::Error { code, message } => Err(ClientError::PeerConnectionFailed(
                format!("Signaling error: {} - {}", code, message),
            )),
            other => {
                tracing::debug!("Ignoring signaling message: {:?}", other);
                Ok(Some(Pumped::Other))
            }
        }
    }

    /// Handle signaling until an SFU offer has been answered
    async fn wait_for_offer(&mut self, timeout: Duration) -> Result<(), ClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if let Some(Pumped::Offer) = self.pump_signaling(Duration::from_millis(100)).await? {
                return Ok(());
            }
        }
        Err(ClientError::OfferFailed(
            "timed out waiting for SFU offer".to_string(),
        ))
    }

    /// Handle signaling (trickled candidates) until ICE connects
    async fn wait_for_ice(&mut self, timeout: Duration) -> Result<(), ClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.is_ice_connected() {
                return Ok(());
            }
            self.pump_signaling(Duration::from_millis(100)).await?;
        }
        if self.is_ice_connected() {
            Ok(())
        } else {
            Err(ClientError::IceConnectionFailed)
        }
    }

    fn is_ice_connected(&self) -> bool {
        self.ice_connected.load(Ordering::SeqCst)
            || self
                .peer_connection
                .as_ref()
                .is_some_and(|pc| pc.connection_state() == RTCPeerConnectionState::Connected)
    }

    /// Start publishing synthetic media (for Broadcaster/Participant roles)
    ///
    /// This method:
    /// 1. Creates VideoGenerator and AudioGenerator for synthetic media
    /// 2. Adds video and audio tracks to the peer connection
    /// 3. Starts a background task to feed synthetic frames/samples
    /// 4. Sends Publish, answers the SFU's offer, and waits for ICE
    pub async fn start_publishing(&mut self) -> Result<(), ClientError> {
        if !self.config.role.can_publish() {
            return Err(ClientError::InvalidState {
                expected: "Broadcaster or Participant",
                actual: "Viewer",
            });
        }

        // Ensure we're connected
        let peer_connection = Arc::clone(self.peer_connection.as_ref().ok_or(
            ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            },
        )?);

        let signaling = Arc::clone(self.signaling.as_ref().ok_or(ClientError::InvalidState {
            expected: "Connected",
            actual: self.state.as_str(),
        })?);

        // Both tracks in one stream, as a browser's camera + microphone.
        let stream_id = format!("loadtest-{}", rand_id());
        let video_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: "video/VP8".to_string(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            format!("video-{}", rand_id()),
            stream_id.clone(),
        ));
        let audio_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: "audio/opus".to_string(),
                clock_rate: 48000,
                channels: 1,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            format!("audio-{}", rand_id()),
            stream_id,
        ));

        let video_sender = peer_connection
            .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to add video track: {}", e)))?;
        let audio_sender = peer_connection
            .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to add audio track: {}", e)))?;
        // RTCP from the SFU (receiver reports, PLI) must be read for the
        // interceptors to process it.
        spawn_rtcp_drain(Arc::clone(&video_sender));
        spawn_rtcp_drain(Arc::clone(&audio_sender));

        self.video_track = Some(Arc::clone(&video_track));
        self.audio_track = Some(Arc::clone(&audio_track));
        self.video_sender = Some(Arc::clone(&video_sender));
        self.audio_sender = Some(Arc::clone(&audio_sender));

        let stop_flag = Arc::new(AtomicBool::new(false));
        self.publishing_stop_flag = Some(Arc::clone(&stop_flag));

        // Declare intent to publish. The SFU replies with an Offer whose recvonly
        // m-lines follow the order of `kinds`, matching the tracks added above.
        signaling
            .lock()
            .await
            .send(SignalMessage::Publish {
                kinds: vec!["video".to_string(), "audio".to_string()],
                contents: vec!["camera".to_string(), "audio".to_string()],
            })
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to send publish: {}", e)))?;

        let timeout = self.config.connection_timeout;
        self.wait_for_offer(timeout).await?;
        self.wait_for_ice(timeout).await?;
        tracing::debug!("Publish negotiation complete");

        // Start media AFTER negotiation so the senders are bound (their SSRCs
        // known, write_sample succeeds).
        let video_ssrc = sender_ssrc(&video_sender).await;
        let audio_ssrc = sender_ssrc(&audio_sender).await;
        spawn_media_loop(
            video_track,
            audio_track,
            [video_ssrc, audio_ssrc],
            stop_flag,
        );

        // Update metrics to track that we're publishing
        self.metrics.packets_received = 0; // Reset for publishing session

        self.state = ClientState::Publishing;
        tracing::debug!(
            "Client {} started publishing",
            self.participant_id.unwrap_or(0)
        );

        Ok(())
    }

    /// Subscribe to a track
    pub async fn subscribe(&mut self, track_id: TrackId) -> Result<(), ClientError> {
        self.subscribe_batch(&[track_id]).await
    }

    /// Subscribe to several tracks with one Subscribe message
    ///
    /// The SFU confirms with Subscribed and renegotiates once for the whole
    /// batch; the resulting Offer is answered by `pump_signaling`.
    /// Also starts the time-to-first-frame clock.
    pub async fn subscribe_batch(&mut self, track_ids: &[TrackId]) -> Result<(), ClientError> {
        if track_ids.is_empty() {
            return Ok(());
        }
        if !self.config.role.can_subscribe() {
            return Err(ClientError::InvalidState {
                expected: "Viewer or Participant",
                actual: "Broadcaster",
            });
        }

        // Ensure we're connected
        let signaling = self.signaling.as_ref().ok_or(ClientError::InvalidState {
            expected: "Connected",
            actual: self.state.as_str(),
        })?;

        let peer_connection = self
            .peer_connection
            .as_ref()
            .ok_or(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            })?;

        // Record subscription start time for time-to-first-frame tracking
        self.subscription_start = Some(Instant::now());
        self.first_frame_start = Some(Instant::now());

        // on_track handler is already registered in connect() — no need to re-register here.
        // The handler from connect() already increments rx_packets, rx_bytes, and
        // sets first_frame_received for all incoming tracks.

        // --- Diagnostic: dump transceiver state BEFORE subscribing ---
        {
            let transceivers = peer_connection.get_transceivers().await;
            tracing::info!(
                "[diag] Before subscribe(track_ids={:?}): {} transceivers, signaling_state={:?}, conn_state={:?}",
                track_ids,
                transceivers.len(),
                peer_connection.signaling_state(),
                peer_connection.connection_state(),
            );
            for (i, t) in transceivers.iter().enumerate() {
                let mid = t.mid();
                let direction = t.direction();
                let current_direction = t.current_direction();
                let kind = t.kind();
                tracing::info!(
                    "[diag]   transceiver[{}]: mid={:?} kind={:?} direction={:?} current_direction={:?}",
                    i, mid, kind, direction, current_direction,
                );
                {
                    let receiver = t.receiver().await;
                    let tracks = receiver.tracks().await;
                    for track in &tracks {
                        tracing::info!(
                            "[diag]     receiver track: ssrc={} rid='{}' codec='{}'",
                            track.ssrc(),
                            track.rid(),
                            track.codec().capability.mime_type,
                        );
                    }
                    if tracks.is_empty() {
                        tracing::info!("[diag]     receiver: no tracks");
                    }
                }
            }
            if let Some(rd) = peer_connection.remote_description().await {
                tracing::info!("[diag]   remote_description type={:?}", rd.sdp_type);
                // Log the m= lines from the remote SDP to see what the SFU sent
                for line in rd.sdp.lines() {
                    if line.starts_with("m=")
                        || line.starts_with("a=ssrc:")
                        || line.starts_with("a=mid:")
                        || line.starts_with("a=msid:")
                    {
                        tracing::info!("[diag]   remote SDP: {}", line);
                    }
                }
            } else {
                // Expected for subscribe-only clients: the first SFU offer follows Subscribe
                tracing::info!("[diag]   no remote description yet");
            }
        }

        // Send subscribe message via signaling
        {
            let mut sig = signaling.lock().await;
            tracing::info!("[diag] Sending Subscribe {{ track_ids: {:?} }}", track_ids);
            sig.send(SignalMessage::Subscribe {
                track_ids: track_ids.to_vec(),
            })
            .await
            .map_err(|_| ClientError::SubscriptionFailed(track_ids[0]))?;
        }

        self.state = ClientState::Subscribing;
        tracing::info!(
            "Client {} subscribed to tracks {:?}",
            self.participant_id.unwrap_or(0),
            track_ids
        );

        Ok(())
    }

    /// Subscribe to all available tracks in the room
    ///
    /// This is a convenience method for Viewer/Participant roles to subscribe
    /// to all tracks that were present when joining the room.
    pub async fn subscribe_to_all(&mut self, track_ids: &[TrackId]) -> Result<(), ClientError> {
        self.subscribe_batch(track_ids).await
    }

    /// Update metrics from track handlers
    ///
    /// Call this periodically to sync metrics from the track handlers
    /// back to the client metrics.
    pub fn sync_metrics(&mut self) {
        // Pull packet/byte counts from the shared atomic counters
        let current_rx = self.rx_packets.load(Ordering::Relaxed);
        self.metrics.packets_received = current_rx;
        self.metrics.bytes_received = self.rx_bytes.load(Ordering::Relaxed);

        // Compute latency and jitter from inter-packet arrival intervals
        let now = Instant::now();
        if let Some(last_instant) = self.metrics_sync_instant {
            let elapsed = now.duration_since(last_instant);
            let packets_in_interval = current_rx.saturating_sub(self.last_rx_count);

            if packets_in_interval > 0 {
                let per_packet_time = elapsed / packets_in_interval as u32;
                self.metrics.latency_samples.push(per_packet_time);

                if let Some(prev) = self.last_per_packet_time {
                    let jitter = if per_packet_time > prev {
                        per_packet_time - prev
                    } else {
                        prev - per_packet_time
                    };
                    self.metrics.jitter_samples.push(jitter);
                }
                self.last_per_packet_time = Some(per_packet_time);
            }
        }
        self.metrics_sync_instant = Some(now);
        self.last_rx_count = current_rx;

        // Track time to first frame
        if self.metrics.time_to_first_frame.is_none()
            && self.first_frame_received.load(Ordering::SeqCst)
        {
            if let Some(start) = self.first_frame_start {
                self.metrics.time_to_first_frame = Some(start.elapsed());
            }
        }
    }

    /// Get current metrics snapshot
    pub fn metrics(&self) -> &ClientMetrics {
        &self.metrics
    }

    /// Get current client state
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Get the client's role
    pub fn role(&self) -> ClientRole {
        self.config.role
    }

    /// Get the participant ID (if assigned)
    /// True once the peer connection (ICE and DTLS) is connected.
    pub fn is_connected(&self) -> bool {
        self.peer_connection
            .as_ref()
            .is_some_and(|pc| pc.connection_state() == RTCPeerConnectionState::Connected)
    }

    /// SSRC of the published `video` (else audio) track, once publishing started.
    pub async fn published_ssrc(&self, video: bool) -> Option<u32> {
        let sender = if video {
            self.video_sender.as_ref()
        } else {
            self.audio_sender.as_ref()
        }?;
        Some(sender_ssrc(sender).await).filter(|&ssrc| ssrc != 0)
    }

    /// SSRCs this client sends on (one per published track).
    pub async fn published_ssrcs(&self) -> Vec<u32> {
        let Some(pc) = self.peer_connection.as_ref() else {
            return Vec::new();
        };
        let mut ssrcs = Vec::new();
        for sender in pc.get_senders().await {
            if sender.track().await.is_some() {
                let params = sender.get_parameters().await;
                ssrcs.extend(params.encodings.iter().map(|e| e.ssrc));
            }
        }
        ssrcs
    }

    /// The m-lines the SFU's latest offer announces for tracks it sends this client
    /// (mid, track id, SSRC).
    pub fn announced_ssrcs(&self) -> Vec<Announced> {
        self.announced.snapshot()
    }

    /// Per-track receive statistics, by SSRC.
    pub fn track_stats(&self) -> Vec<TrackRxStats> {
        self.track_stats.snapshot()
    }

    pub fn participant_id(&self) -> Option<ParticipantId> {
        self.participant_id
    }

    /// Drain pending signaling messages, discover published tracks, and subscribe to them.
    ///
    /// This should be called on viewer/subscriber clients after the broadcaster
    /// has started publishing, to pick up TrackPublished notifications and subscribe.
    pub async fn discover_and_subscribe(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<TrackId>, ClientError> {
        if !self.config.role.can_subscribe() {
            return Ok(Vec::new());
        }

        if self.signaling.is_none() || self.peer_connection.is_none() {
            return Err(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            });
        }

        // Phase 1: Collect TrackPublished notifications (tracks listed in Joined
        // are already buffered). Stop once announcements go quiet.
        tracing::info!(
            "Waiting for TrackPublished notifications (timeout: {:?})",
            timeout
        );
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            let pumped = self.pump_signaling(Duration::from_millis(200)).await?;
            if pumped.is_none() && !self.announced_tracks.is_empty() {
                break;
            }
        }
        let discovered_tracks = std::mem::take(&mut self.announced_tracks);

        // Phase 2: One batched Subscribe, so the SFU renegotiates once
        self.subscribe_batch(&discovered_tracks).await?;

        // Phase 3: Wait for the Subscribed confirmation AND the SFU's renegotiation
        // offer with SSRC information. Both are needed before media can flow.
        let mut got_renegotiation_offer = false;
        if !discovered_tracks.is_empty() {
            tracing::info!(
                "Phase 3: Waiting for Subscribed confirmation and renegotiation offer..."
            );

            let mut confirmed_count = 0usize;
            let expected_count = discovered_tracks.len();
            let renegotiation_deadline = tokio::time::Instant::now() + Duration::from_secs(5);

            while tokio::time::Instant::now() < renegotiation_deadline
                && !(confirmed_count >= expected_count && got_renegotiation_offer)
            {
                match self.pump_signaling(Duration::from_millis(200)).await? {
                    Some(Pumped::Subscribed(count)) => {
                        confirmed_count += count;
                        tracing::info!(
                            "Subscription confirmed ({}/{})",
                            confirmed_count,
                            expected_count
                        );
                    }
                    Some(Pumped::Offer) => got_renegotiation_offer = true,
                    _ => {}
                }
            }

            tracing::info!(
                "Phase 3 done: {}/{} confirmed, got_renegotiation_offer={}",
                confirmed_count,
                expected_count,
                got_renegotiation_offer
            );
            if !got_renegotiation_offer {
                tracing::warn!("Phase 3: timed out waiting for renegotiation offer from SFU");
            }
        }

        tracing::info!(
            "Client {} discovered and subscribed to {} tracks",
            self.participant_id.unwrap_or(0),
            discovered_tracks.len()
        );

        // --- Diagnostic: dump transceiver state AFTER Phase 3 ---
        {
            let peer_connection = self.peer_connection.as_ref().unwrap();
            let transceivers = peer_connection.get_transceivers().await;
            tracing::info!(
                "[diag] After Phase 3: got_renegotiation_offer={}, {} transceivers, signaling_state={:?}, conn_state={:?}",
                got_renegotiation_offer,
                transceivers.len(),
                peer_connection.signaling_state(),
                peer_connection.connection_state(),
            );
            for (i, t) in transceivers.iter().enumerate() {
                let mid = t.mid();
                let direction = t.direction();
                let current_direction = t.current_direction();
                let kind = t.kind();
                tracing::info!(
                    "[diag]   transceiver[{}]: mid={:?} kind={:?} direction={:?} current_direction={:?}",
                    i, mid, kind, direction, current_direction,
                );
                {
                    let receiver = t.receiver().await;
                    let tracks = receiver.tracks().await;
                    for track in &tracks {
                        tracing::info!(
                            "[diag]     receiver track: ssrc={} rid='{}' codec='{}'",
                            track.ssrc(),
                            track.rid(),
                            track.codec().capability.mime_type,
                        );
                    }
                    if tracks.is_empty() {
                        tracing::info!("[diag]     receiver: no tracks");
                    }
                }
            }
            if let Some(rd) = peer_connection.remote_description().await {
                tracing::info!("[diag]   remote_description type={:?}", rd.sdp_type);
                for line in rd.sdp.lines() {
                    if line.starts_with("m=")
                        || line.starts_with("a=ssrc:")
                        || line.starts_with("a=mid:")
                        || line.starts_with("a=msid:")
                        || line.starts_with("a=sendonly")
                        || line.starts_with("a=recvonly")
                        || line.starts_with("a=sendrecv")
                        || line.starts_with("a=inactive")
                    {
                        tracing::info!("[diag]   remote SDP: {}", line);
                    }
                }
            } else {
                tracing::warn!("[diag]   NO remote description set after Phase 3");
            }
            tracing::info!(
                "[diag]   rx_packets={} rx_bytes={} first_frame_received={}",
                self.rx_packets.load(Ordering::Relaxed),
                self.rx_bytes.load(Ordering::Relaxed),
                self.first_frame_received.load(Ordering::Relaxed),
            );
        }

        // Spawn a background signaling handler to process any late-arriving
        // renegotiation offers from the SFU during the metrics collection phase.
        // Without this, offers that arrive after Phase 3 exits would sit unread
        // in the WebSocket buffer and the viewer's new session would never complete.
        {
            let signaling = Arc::clone(self.signaling.as_ref().unwrap());
            let peer_connection = Arc::clone(self.peer_connection.as_ref().unwrap());
            let announced = self.announced.clone();
            let stop_flag = Arc::new(AtomicBool::new(false));
            self.signaling_stop_flag = Some(Arc::clone(&stop_flag));

            tokio::spawn(async move {
                while !stop_flag.load(Ordering::Relaxed) {
                    let recv_result = {
                        let mut sig = signaling.lock().await;
                        tokio::time::timeout(Duration::from_millis(200), sig.recv()).await
                    };

                    match recv_result {
                        Ok(Ok(msg)) => {
                            tracing::info!(
                                "[bg-signaling] Received message: {:?}",
                                std::mem::discriminant(&msg)
                            );
                            match msg {
                                SignalMessage::Offer { sdp, tracks } => {
                                    tracing::info!("[bg-signaling] Received renegotiation offer");
                                    match answer_offer(
                                        &peer_connection,
                                        &signaling,
                                        sdp,
                                        &tracks,
                                        &announced,
                                    )
                                    .await
                                    {
                                        Ok(()) => tracing::info!(
                                            "[bg-signaling] Renegotiation answer sent"
                                        ),
                                        Err(e) => tracing::warn!(
                                            "[bg-signaling] Renegotiation failed: {}",
                                            e
                                        ),
                                    }
                                }
                                SignalMessage::IceCandidate {
                                    candidate,
                                    sdp_mid,
                                    sdp_mline_index,
                                } => {
                                    tracing::info!("[bg-signaling] Received ICE candidate");
                                    add_remote_candidate(
                                        &peer_connection,
                                        candidate,
                                        sdp_mid,
                                        sdp_mline_index,
                                    )
                                    .await;
                                }
                                other => {
                                    tracing::info!("[bg-signaling] Ignoring message: {:?}", other);
                                }
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue, // recv timeout, keep looping
                    }
                }
                tracing::debug!("[bg-signaling] Background signaling handler stopped");
            });
        }

        Ok(discovered_tracks)
    }

    /// Disconnect and cleanup
    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        // Stop background signaling handler
        if let Some(flag) = self.signaling_stop_flag.take() {
            flag.store(true, Ordering::Relaxed);
        }

        // Stop publishing task
        if let Some(flag) = self.publishing_stop_flag.take() {
            flag.store(true, Ordering::Relaxed);
        }

        // Close peer connection
        if let Some(pc) = self.peer_connection.take() {
            let _ = pc.close().await;
        }

        // Leave room and close signaling
        if let Some(signaling) = self.signaling.take() {
            let mut sig = signaling.lock().await;
            let _ = sig.leave_room().await;
            let _ = sig.close().await;
        }

        self.state = ClientState::Disconnected;
        self.participant_id = None;
        Ok(())
    }
}

/// What `HeadlessClient::pump_signaling` received
enum Pumped {
    /// An SFU offer, now answered
    Offer,
    /// Subscribed confirmation for this many tracks
    Subscribed(usize),
    /// Anything else (candidates, notifications)
    Other,
}

/// The first SSRC of a sender (0 if it has none).
async fn sender_ssrc(sender: &RTCRtpSender) -> u32 {
    let params = sender.get_parameters().await;
    params.encodings.first().map_or(0, |e| e.ssrc)
}

/// Read a sender's incoming RTCP until the sender closes.
fn spawn_rtcp_drain(sender: Arc<RTCRtpSender>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while sender.read(&mut buf).await.is_ok() {}
    });
}

/// Feed synthetic video (15 fps) and audio to the published tracks until `stop`.
/// Every frame and audio sample starts with the payload marker (publisher SSRC,
/// frame counter) of `media::stamp_marker`; `ssrcs` is `[video, audio]`.
fn spawn_media_loop(
    video_track: Arc<TrackLocalStaticSample>,
    audio_track: Arc<TrackLocalStaticSample>,
    ssrcs: [u32; 2],
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut video_gen = VideoGenerator::new(320, 240, 15, VideoPattern::ColorBars);
        let mut audio_gen = AudioGenerator::new(48000, 1, AudioPattern::Tone(440));
        let frame_duration = Duration::from_millis(1000 / 15);
        let audio_samples_per_frame = 480; // 10 ms at 48 kHz
        let mut frame: u32 = 0;

        while !stop.load(Ordering::Relaxed) {
            let frame_start = Instant::now();
            frame = frame.wrapping_add(1);

            let mut video = video_gen.next_encoded_frame(VIDEO_BITRATE_BPS).data;
            stamp_marker(&mut video, ssrcs[0], frame);
            let video_sample = Sample {
                data: video.into(),
                duration: frame_duration,
                ..Default::default()
            };
            if video_track.write_sample(&video_sample).await.is_err() {
                break;
            }

            let samples = audio_gen.next_samples(audio_samples_per_frame);
            let mut audio: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
            stamp_marker(&mut audio, ssrcs[1], frame);
            let audio_sample = Sample {
                data: audio.into(),
                duration: frame_duration,
                ..Default::default()
            };
            if audio_track.write_sample(&audio_sample).await.is_err() {
                break;
            }

            let elapsed = frame_start.elapsed();
            if elapsed < frame_duration {
                tokio::time::sleep(frame_duration - elapsed).await;
            }
        }
    });
}

/// Apply an SFU offer and reply with our answer (the SFU is the sole offerer)
async fn answer_offer(
    peer_connection: &RTCPeerConnection,
    signaling: &Mutex<SignalingConnection>,
    sdp: String,
    tracks: &[OfferTrack],
    announced: &AnnouncedSsrcs,
) -> Result<(), ClientError> {
    tracing::debug!("Received SFU offer:\n{}", sdp);
    let offer = RTCSessionDescription::offer(sdp.clone())
        .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
    peer_connection
        .set_remote_description(offer)
        .await
        .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
    announced.update(&sdp, tracks);

    let answer = peer_connection
        .create_answer(None)
        .await
        .map_err(|e| ClientError::OfferFailed(format!("Failed to create answer: {}", e)))?;
    peer_connection
        .set_local_description(answer.clone())
        .await
        .map_err(|e| ClientError::OfferFailed(format!("Failed to set local description: {}", e)))?;

    signaling
        .lock()
        .await
        .send(SignalMessage::Answer { sdp: answer.sdp })
        .await
        .map_err(|e| ClientError::OfferFailed(format!("Failed to send answer: {}", e)))
}

/// Add a trickled ICE candidate from the SFU; invalid ones are logged, not fatal
async fn add_remote_candidate(
    peer_connection: &RTCPeerConnection,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u32>,
) {
    let candidate_init = RTCIceCandidateInit {
        candidate,
        sdp_mid,
        sdp_mline_index: sdp_mline_index.map(|i| i as u16),
        username_fragment: None,
    };
    if let Err(e) = peer_connection.add_ice_candidate(candidate_init).await {
        tracing::debug!("Failed to add ICE candidate: {}", e);
    }
}

/// Synthetic video bitrate: typical for 320x240@15fps VP8 (a raw I420 frame
/// per tick would be ~14 Mbit/s and ~1,400 packets/s per track)
const VIDEO_BITRATE_BPS: u32 = 500_000;

/// Generate a random ID for participant names
fn rand_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_nanos() as u64 ^ (std::process::id() as u64)
}
