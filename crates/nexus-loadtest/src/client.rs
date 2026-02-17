//! Headless WebRTC client implementation
//!
//! Lightweight WebRTC client using webrtc-rs for media transport
//! and nexus-signal for signaling protocol compatibility.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_core::{ParticipantId, TrackId};
use nexus_signal::SignalMessage;
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
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::config::{ClientConfig, ClientRole};
use crate::error::ClientError;
use crate::media::{AudioGenerator, AudioPattern, VideoGenerator, VideoPattern};
use crate::metrics::ClientMetrics;
use crate::signaling::SignalingConnection;

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
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();

        // Build ICE server list: use configured servers or fall back to Google public STUN
        let ice_servers = if self.config.ice_servers.is_empty() {
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
    /// 1. Establishes signaling connection with timeout
    /// 2. Joins the specified room
    /// 3. Creates WebRTC peer connection
    /// 4. Performs SDP offer/answer exchange
    /// 5. Handles ICE candidate exchange
    pub async fn connect(&mut self) -> Result<(), ClientError> {
        self.state = ClientState::Connecting;
        self.connection_start = Some(Instant::now());

        // Step 1: Establish signaling connection with timeout
        let signaling = SignalingConnection::connect_with_timeout(
            &self.config.sfu_url,
            self.config.connection_timeout,
        )
        .await
        .map_err(|e| ClientError::PeerConnectionFailed(format!("Signaling connection failed: {}", e)))?;

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

        let participant_name = format!("loadtest-{:?}-{}", self.config.role, rand_id());

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
                    sig.send(create_msg).await
                        .map_err(|e| ClientError::PeerConnectionFailed(format!("Failed to create room: {}", e)))?;
                    
                    // Wait for Created response
                    loop {
                        let msg = sig.recv().await
                            .map_err(|e| ClientError::PeerConnectionFailed(format!("Failed to recv create response: {}", e)))?;
                        match msg {
                            nexus_signal::protocol::SignalMessage::Created { room_id: created_id, .. } => {
                                tracing::info!("Created room {}", created_id);
                                room_id = created_id;
                                break;
                            }
                            nexus_signal::protocol::SignalMessage::Error { code, message } => {
                                return Err(ClientError::PeerConnectionFailed(
                                    format!("Room creation failed: {} - {}", code, message)
                                ));
                            }
                            _ => continue,
                        }
                    }
                    
                    // Now join the created room
                    sig.join_room(room_id, &participant_name).await
                        .map_err(|e2| ClientError::PeerConnectionFailed(
                            format!("Failed to join room after create: {} (original: {})", e2, e)
                        ))?
                }
            }
        };

        self.participant_id = Some(join_response.participant_id);

        // Step 3: Create WebRTC peer connection
        let peer_connection = self.create_peer_connection().await?;
        self.peer_connection = Some(peer_connection.clone());

        // Add transceivers so the SDP offer has media sections.
        // The SFU requires at least one media section in the offer.
        {
            use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
            use webrtc::rtp_transceiver::RTCRtpTransceiverInit;

            let direction = if self.config.role.can_publish() && !self.config.role.can_subscribe() {
                // Broadcaster: sendonly (will be populated with actual tracks in start_publishing)
                RTCRtpTransceiverDirection::Sendonly
            } else if !self.config.role.can_publish() && self.config.role.can_subscribe() {
                // Viewer: recvonly
                RTCRtpTransceiverDirection::Recvonly
            } else {
                // Participant: sendrecv
                RTCRtpTransceiverDirection::Sendrecv
            };

            // Add video transceiver
            let video_init = RTCRtpTransceiverInit {
                direction,
                send_encodings: vec![],
            };
            peer_connection
                .add_transceiver_from_kind(webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Video, Some(video_init))
                .await
                .map_err(|e| ClientError::PeerConnectionFailed(format!("Failed to add video transceiver: {}", e)))?;

            // Add audio transceiver
            let audio_init = RTCRtpTransceiverInit {
                direction,
                send_encodings: vec![],
            };
            peer_connection
                .add_transceiver_from_kind(webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Audio, Some(audio_init))
                .await
                .map_err(|e| ClientError::PeerConnectionFailed(format!("Failed to add audio transceiver: {}", e)))?;
        }

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

        // Set up on_track handler to consume incoming RTP and track metrics
        let rx_packets = Arc::clone(&self.rx_packets);
        let rx_bytes = Arc::clone(&self.rx_bytes);
        let first_frame_received = Arc::clone(&self.first_frame_received);

        peer_connection.on_track(Box::new(move |track, _receiver, _transceiver| {
            let rx_packets = Arc::clone(&rx_packets);
            let rx_bytes = Arc::clone(&rx_bytes);
            let first_frame_received = Arc::clone(&first_frame_received);

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
                tokio::spawn(async move {
                    let mut pkt_count: u64 = 0;
                    loop {
                        match track_clone.read_rtp().await {
                            Ok((rtp_packet, _attributes)) => {
                                let payload_len = rtp_packet.payload.len();
                                pkt_count += 1;
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

        // Step 4: Create and send SDP offer
        let offer = peer_connection
            .create_offer(None)
            .await
            .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

        // Set local description
        peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| ClientError::OfferFailed(format!("Failed to set local description: {}", e)))?;

        tracing::info!("Sending SDP offer:\n{}", offer.sdp);

        // Send offer via signaling
        {
            let mut sig = signaling.lock().await;
            sig.send(SignalMessage::Offer {
                sdp: offer.sdp,
            })
            .await
            .map_err(|e| ClientError::OfferFailed(format!("Failed to send offer: {}", e)))?;
        }

        // Step 5: Wait for answer and handle ICE candidates
        self.handle_signaling_messages(&peer_connection, &signaling).await?;

        // Record connection time
        if let Some(start) = self.connection_start {
            self.metrics.connection_time = Some(start.elapsed());
        }
        self.metrics.connection_successful = true;
        self.state = ClientState::Connected;

        // --- Diagnostic: dump transceiver state after initial connection ---
        {
            let transceivers = peer_connection.get_transceivers().await;
            tracing::info!(
                "[diag] After connect: {} transceivers, signaling_state={:?}, ice_state={:?}, conn_state={:?}",
                transceivers.len(),
                peer_connection.signaling_state(),
                peer_connection.ice_connection_state(),
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
                }
            }
        }

        Ok(())
    }

    /// Handle incoming signaling messages (answer and ICE candidates)
    async fn handle_signaling_messages(
        &mut self,
        peer_connection: &Arc<RTCPeerConnection>,
        signaling: &Arc<Mutex<SignalingConnection>>,
    ) -> Result<(), ClientError> {
        let mut answer_received = false;
        let mut ice_connected = false;

        // Set up connection state change handler
        let ice_connected_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ice_flag_clone = ice_connected_flag.clone();

        peer_connection.on_ice_connection_state_change(Box::new(move |state| {
            if state == RTCIceConnectionState::Connected || state == RTCIceConnectionState::Completed {
                ice_flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Box::pin(async {})
        }));

        // Process signaling messages until connected
        let timeout = tokio::time::Instant::now() + self.config.connection_timeout;

        while !answer_received || !ice_connected {
            // Check timeout
            if tokio::time::Instant::now() > timeout {
                return Err(ClientError::PeerConnectionFailed(
                    "Connection timeout waiting for SDP answer or ICE connection".to_string(),
                ));
            }

            // Check if ICE connected via callback
            if ice_connected_flag.load(std::sync::atomic::Ordering::SeqCst) {
                ice_connected = true;
            }

            // Also check peer connection state directly
            let pc_state = peer_connection.connection_state();
            if pc_state == RTCPeerConnectionState::Connected {
                ice_connected = true;
            }

            // If we have answer and ICE is connected, we're done
            if answer_received && ice_connected {
                break;
            }

            // Try to receive a signaling message with a short timeout
            let recv_result = {
                let mut sig = signaling.lock().await;
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    sig.recv(),
                )
                .await
            };

            match recv_result {
                Ok(Ok(msg)) => {
                    match msg {
                        SignalMessage::Answer { sdp, .. } | SignalMessage::AnswerReceived { sdp, .. } => {
                            // Log the SDP answer for debugging
                            tracing::info!("Received SDP answer:\n{}", sdp);

                            // Set remote description
                            let answer = RTCSessionDescription::answer(sdp)
                                .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;

                            peer_connection
                                .set_remote_description(answer)
                                .await
                                .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;

                            answer_received = true;
                        }
                        SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index, .. } => {
                            // Add ICE candidate
                            let candidate_init = RTCIceCandidateInit {
                                candidate,
                                sdp_mid,
                                sdp_mline_index: sdp_mline_index.map(|i| i as u16),
                                username_fragment: None,
                            };

                            if let Err(e) = peer_connection.add_ice_candidate(candidate_init).await {
                                // Log but don't fail - some candidates may be invalid
                                tracing::debug!("Failed to add ICE candidate: {}", e);
                            }
                        }
                        SignalMessage::Error { code, message } => {
                            return Err(ClientError::PeerConnectionFailed(format!(
                                "Signaling error: {} - {}",
                                code, message
                            )));
                        }
                        // Ignore other messages during connection
                        _ => {}
                    }
                }
                Ok(Err(e)) => {
                    // Signaling error
                    return Err(ClientError::PeerConnectionFailed(format!(
                        "Signaling receive error: {}",
                        e
                    )));
                }
                Err(_) => {
                    // Timeout on recv, continue loop
                }
            }

            // Small yield to prevent busy loop
            tokio::task::yield_now().await;
        }

        Ok(())
    }

    /// Start publishing synthetic media (for Broadcaster/Participant roles)
    ///
    /// This method:
    /// 1. Creates VideoGenerator and AudioGenerator for synthetic media
    /// 2. Adds video and audio tracks to the peer connection
    /// 3. Starts a background task to feed synthetic frames/samples
    /// 4. Sends Publish message via signaling (TrackPublished notification)
    pub async fn start_publishing(&mut self) -> Result<(), ClientError> {
        if !self.config.role.can_publish() {
            return Err(ClientError::InvalidState {
                expected: "Broadcaster or Participant",
                actual: "Viewer",
            });
        }

        // Ensure we're connected
        let peer_connection = self.peer_connection.as_ref().ok_or(ClientError::InvalidState {
            expected: "Connected",
            actual: self.state.as_str(),
        })?;

        let signaling = self.signaling.as_ref().ok_or(ClientError::InvalidState {
            expected: "Connected",
            actual: self.state.as_str(),
        })?;

        // Create video track with VP8 codec
        let video_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: "video/VP8".to_string(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            format!("video-{}", rand_id()),
            format!("loadtest-video-{}", rand_id()),
        ));

        // Create audio track with Opus codec
        let audio_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: "audio/opus".to_string(),
                clock_rate: 48000,
                channels: 1,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            format!("audio-{}", rand_id()),
            format!("loadtest-audio-{}", rand_id()),
        ));

        // Add tracks to peer connection
        let _video_sender = peer_connection
            .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to add video track: {}", e)))?;

        let _audio_sender = peer_connection
            .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to add audio track: {}", e)))?;

        // Store tracks
        self.video_track = Some(Arc::clone(&video_track));
        self.audio_track = Some(Arc::clone(&audio_track));

        // Create stop flag for background task
        let stop_flag = Arc::new(AtomicBool::new(false));
        self.publishing_stop_flag = Some(Arc::clone(&stop_flag));

        // Send TrackPublished notification via signaling for video
        // Note: In a real implementation, the SFU would assign track IDs
        // For load testing, we use a generated ID
        let video_track_id = rand_id();
        {
            let mut sig = signaling.lock().await;
            // The SFU typically sends TrackPublished as a notification,
            // but we can send an Offer to renegotiate with the new tracks
            let offer = peer_connection
                .create_offer(None)
                .await
                .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

            peer_connection
                .set_local_description(offer.clone())
                .await
                .map_err(|e| ClientError::OfferFailed(format!("Failed to set local description: {}", e)))?;

            sig.send(SignalMessage::Offer {
                sdp: offer.sdp,
            })
            .await
            .map_err(|e| ClientError::MediaError(format!("Failed to send offer: {}", e)))?;

            // Wait for the SFU's answer to complete the renegotiation
            let answer_timeout = tokio::time::Instant::now() + Duration::from_secs(5);
            while tokio::time::Instant::now() < answer_timeout {
                match tokio::time::timeout(Duration::from_millis(200), sig.recv()).await {
                    Ok(Ok(msg)) => {
                        match msg {
                            SignalMessage::Answer { sdp, .. } | SignalMessage::AnswerReceived { sdp, .. } => {
                                let answer = RTCSessionDescription::answer(sdp)
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                peer_connection
                                    .set_remote_description(answer)
                                    .await
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                tracing::debug!("Renegotiation complete after publishing");
                                break;
                            }
                            _ => continue,
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Signaling error waiting for renegotiation answer: {}", e);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        // Start background media generation AFTER renegotiation is complete
        // so the track senders are fully bound and write_sample succeeds.
        let video_track_clone = Arc::clone(&video_track);
        let audio_track_clone = Arc::clone(&audio_track);
        let stop_flag_clone = Arc::clone(&stop_flag);

        tokio::spawn(async move {
            let mut video_gen = VideoGenerator::new(320, 240, 15, VideoPattern::ColorBars);
            let mut audio_gen = AudioGenerator::new(48000, 1, AudioPattern::Tone(440));

            let frame_duration = Duration::from_millis(1000 / 15); // 15 fps
            let audio_samples_per_frame = 480; // 10ms at 48kHz

            while !stop_flag_clone.load(Ordering::Relaxed) {
                let frame_start = Instant::now();

                let video_frame = video_gen.next_frame();
                let video_sample = Sample {
                    data: video_frame.data.into(),
                    duration: frame_duration,
                    ..Default::default()
                };
                if video_track_clone.write_sample(&video_sample).await.is_err() {
                    break;
                }

                let audio_samples = audio_gen.next_samples(audio_samples_per_frame as usize);
                let audio_bytes: Vec<u8> = audio_samples
                    .iter()
                    .flat_map(|s| s.to_le_bytes())
                    .collect();
                let audio_sample = Sample {
                    data: audio_bytes.into(),
                    duration: frame_duration,
                    ..Default::default()
                };
                if audio_track_clone.write_sample(&audio_sample).await.is_err() {
                    break;
                }

                let elapsed = frame_start.elapsed();
                if elapsed < frame_duration {
                    tokio::time::sleep(frame_duration - elapsed).await;
                }
            }
        });

        // Update metrics to track that we're publishing
        self.metrics.packets_received = 0; // Reset for publishing session

        self.state = ClientState::Publishing;
        tracing::debug!(
            "Client {} started publishing video track {}",
            self.participant_id.unwrap_or(0),
            video_track_id
        );

        Ok(())
    }

    /// Subscribe to a track
    ///
    /// This method:
    /// 1. Sends Subscribe message via signaling
    /// 2. Sets up track handler to receive media
    /// 3. Tracks time to first frame in metrics
    pub async fn subscribe(&mut self, track_id: TrackId) -> Result<(), ClientError> {
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

        let peer_connection = self.peer_connection.as_ref().ok_or(ClientError::InvalidState {
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
                "[diag] Before subscribe(track_id={}): {} transceivers, signaling_state={:?}, conn_state={:?}",
                track_id,
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
                    if line.starts_with("m=") || line.starts_with("a=ssrc:") || line.starts_with("a=mid:") || line.starts_with("a=msid:") {
                        tracing::info!("[diag]   remote SDP: {}", line);
                    }
                }
            } else {
                tracing::warn!("[diag]   NO remote description set");
            }
        }

        // Send subscribe message via signaling
        {
            let mut sig = signaling.lock().await;
            tracing::info!("[diag] Sending Subscribe {{ track_id: {} }}", track_id);
            sig.send(SignalMessage::Subscribe { track_id })
                .await
                .map_err(|_| ClientError::SubscriptionFailed(track_id))?;
        }

        self.state = ClientState::Subscribing;
        tracing::info!(
            "Client {} subscribed to track {}",
            self.participant_id.unwrap_or(0),
            track_id
        );

        Ok(())
    }

    /// Subscribe to all available tracks in the room
    ///
    /// This is a convenience method for Viewer/Participant roles to subscribe
    /// to all tracks that were present when joining the room.
    pub async fn subscribe_to_all(&mut self, track_ids: &[TrackId]) -> Result<(), ClientError> {
        for &track_id in track_ids {
            self.subscribe(track_id).await?;
        }
        Ok(())
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
    pub fn participant_id(&self) -> Option<ParticipantId> {
        self.participant_id
    }

    /// Drain pending signaling messages, discover published tracks, and subscribe to them.
    ///
    /// This should be called on viewer/subscriber clients after the broadcaster
    /// has started publishing, to pick up TrackPublished notifications and subscribe.
    pub async fn discover_and_subscribe(&mut self, timeout: Duration) -> Result<Vec<TrackId>, ClientError> {
        if !self.config.role.can_subscribe() {
            return Ok(Vec::new());
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut discovered_tracks: Vec<TrackId> = Vec::new();

        // Phase 1: Drain signaling messages looking for TrackPublished notifications
        {
            let signaling = self.signaling.as_ref().ok_or(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            })?;

            let peer_connection = self.peer_connection.as_ref().ok_or(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            })?;

            tracing::info!("Waiting for TrackPublished notifications (timeout: {:?})", timeout);

            while tokio::time::Instant::now() < deadline {
                let recv_result = {
                    let mut sig = signaling.lock().await;
                    tokio::time::timeout(Duration::from_millis(200), sig.recv()).await
                };

                match recv_result {
                    Ok(Ok(msg)) => {
                        tracing::info!("discover_and_subscribe received signaling message: {:?}", msg);
                        match msg {
                            SignalMessage::TrackPublished { track_id, kind, publisher_id, .. } => {
                                tracing::debug!(
                                    "Discovered track {} ({}) from publisher {}",
                                    track_id, kind, publisher_id
                                );
                                discovered_tracks.push(track_id);
                            }
                            SignalMessage::Answer { sdp, .. } | SignalMessage::AnswerReceived { sdp, .. } => {
                                let answer = RTCSessionDescription::answer(sdp)
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                peer_connection
                                    .set_remote_description(answer)
                                    .await
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                            }
                            SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index, .. } => {
                                let candidate_init = RTCIceCandidateInit {
                                    candidate,
                                    sdp_mid,
                                    sdp_mline_index: sdp_mline_index.map(|i| i as u16),
                                    username_fragment: None,
                                };
                                let _ = peer_connection.add_ice_candidate(candidate_init).await;
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => {
                        if !discovered_tracks.is_empty() {
                            break;
                        }
                        tracing::debug!("No signaling message received (timeout), still waiting...");
                    }
                }
            }
        } // drop borrows of signaling/peer_connection

        // Phase 2: Subscribe to all discovered tracks (needs &mut self)
        for &track_id in &discovered_tracks {
            self.subscribe(track_id).await?;
        }

        let mut got_renegotiation_offer = false;

        // Phase 3: Wait for Subscribed confirmations AND the SFU's renegotiation
        // offer with SSRC information. Both are needed before media can flow.
        {
            let signaling = self.signaling.as_ref().ok_or(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            })?;

            let peer_connection = self.peer_connection.as_ref().ok_or(ClientError::InvalidState {
                expected: "Connected",
                actual: self.state.as_str(),
            })?;

            tracing::info!("Phase 3: Waiting for Subscribed confirmations and renegotiation offer...");

            let mut confirmed_count = 0usize;
            let expected_count = discovered_tracks.len();
            let renegotiation_deadline = tokio::time::Instant::now() + Duration::from_secs(5);

            // Keep looping until we have both confirmations AND the renegotiation offer
            while tokio::time::Instant::now() < renegotiation_deadline {
                // Exit early if we have everything
                if confirmed_count >= expected_count && got_renegotiation_offer {
                    break;
                }

                let recv_result = {
                    let mut sig = signaling.lock().await;
                    tokio::time::timeout(Duration::from_millis(200), sig.recv()).await
                };

                match recv_result {
                    Ok(Ok(msg)) => {
                        tracing::info!("Phase 3 received signaling message: {:?}", msg);
                        match msg {
                            SignalMessage::Subscribed { track_id, .. } => {
                                confirmed_count += 1;
                                tracing::info!(
                                    "Subscription confirmed for track {} ({}/{})",
                                    track_id, confirmed_count, expected_count
                                );
                            }
                            SignalMessage::OfferReceived { sdp, .. } => {
                                got_renegotiation_offer = true;
                                tracing::info!("Received SFU renegotiation offer (OfferReceived), SDP length={}", sdp.len());
                                // Log m= lines and ssrc lines from the offer
                                for line in sdp.lines() {
                                    if line.starts_with("m=") || line.starts_with("a=ssrc:") || line.starts_with("a=mid:") || line.starts_with("a=msid:") || line.starts_with("a=sendonly") || line.starts_with("a=recvonly") || line.starts_with("a=sendrecv") || line.starts_with("a=inactive") {
                                        tracing::info!("[diag] renegotiation offer SDP: {}", line);
                                    }
                                }
                                let offer = RTCSessionDescription::offer(sdp)
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                peer_connection
                                    .set_remote_description(offer)
                                    .await
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;

                                let answer = peer_connection
                                    .create_answer(None)
                                    .await
                                    .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

                                tracing::info!("Sending renegotiation answer:\n{}", answer.sdp);

                                peer_connection
                                    .set_local_description(answer.clone())
                                    .await
                                    .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

                                let mut sig = signaling.lock().await;
                                sig.send(SignalMessage::Answer {
                                    sdp: answer.sdp,
                                })
                                .await
                                .map_err(|e| ClientError::OfferFailed(format!("Failed to send answer: {}", e)))?;
                            }
                            SignalMessage::Answer { sdp, .. } | SignalMessage::AnswerReceived { sdp, .. } => {
                                let answer = RTCSessionDescription::answer(sdp)
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                peer_connection
                                    .set_remote_description(answer)
                                    .await
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                            }
                            SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index, .. } => {
                                let candidate_init = RTCIceCandidateInit {
                                    candidate,
                                    sdp_mid,
                                    sdp_mline_index: sdp_mline_index.map(|i| i as u16),
                                    username_fragment: None,
                                };
                                let _ = peer_connection.add_ice_candidate(candidate_init).await;
                            }
                            SignalMessage::Offer { sdp, .. } => {
                                got_renegotiation_offer = true;
                                tracing::info!("Phase 3 received Offer (not OfferReceived), SDP length={}", sdp.len());
                                for line in sdp.lines() {
                                    if line.starts_with("m=") || line.starts_with("a=ssrc:") || line.starts_with("a=mid:") || line.starts_with("a=msid:") || line.starts_with("a=sendonly") || line.starts_with("a=recvonly") || line.starts_with("a=sendrecv") || line.starts_with("a=inactive") {
                                        tracing::info!("[diag] renegotiation offer SDP: {}", line);
                                    }
                                }
                                let offer = RTCSessionDescription::offer(sdp)
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;
                                peer_connection
                                    .set_remote_description(offer)
                                    .await
                                    .map_err(|e| ClientError::RemoteDescriptionFailed(e.to_string()))?;

                                let answer = peer_connection
                                    .create_answer(None)
                                    .await
                                    .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

                                tracing::info!("Sending renegotiation answer for Offer:\n{}", answer.sdp);

                                peer_connection
                                    .set_local_description(answer.clone())
                                    .await
                                    .map_err(|e| ClientError::OfferFailed(e.to_string()))?;

                                let mut sig = signaling.lock().await;
                                sig.send(SignalMessage::Answer {
                                    sdp: answer.sdp,
                                })
                                .await
                                .map_err(|e| ClientError::OfferFailed(format!("Failed to send answer: {}", e)))?;
                            }
                            other => {
                                tracing::info!("Phase 3 ignoring message: {:?}", other);
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        tracing::warn!("Phase 3: signaling error, breaking");
                        break;
                    }
                    Err(_) => {
                        // recv timeout — keep waiting
                        continue;
                    }
                }
            }

            tracing::info!(
                "Phase 3 done: {}/{} confirmed, got_renegotiation_offer={}",
                confirmed_count, expected_count, got_renegotiation_offer
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
                    if line.starts_with("m=") || line.starts_with("a=ssrc:") || line.starts_with("a=mid:") || line.starts_with("a=msid:") || line.starts_with("a=sendonly") || line.starts_with("a=recvonly") || line.starts_with("a=sendrecv") || line.starts_with("a=inactive") {
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
                            tracing::info!("[bg-signaling] Received message: {:?}", std::mem::discriminant(&msg));
                            match msg {
                                SignalMessage::OfferReceived { sdp, .. } | SignalMessage::Offer { sdp, .. } => {
                                    tracing::info!("[bg-signaling] Received renegotiation offer");
                                    let offer = match RTCSessionDescription::offer(sdp) {
                                        Ok(o) => o,
                                        Err(e) => {
                                            tracing::warn!("[bg-signaling] Failed to parse offer: {}", e);
                                            continue;
                                        }
                                    };
                                    if let Err(e) = peer_connection.set_remote_description(offer).await {
                                        tracing::warn!("[bg-signaling] Failed to set remote description: {}", e);
                                        continue;
                                    }
                                    let answer = match peer_connection.create_answer(None).await {
                                        Ok(a) => a,
                                        Err(e) => {
                                            tracing::warn!("[bg-signaling] Failed to create answer: {}", e);
                                            continue;
                                        }
                                    };
                                    if let Err(e) = peer_connection.set_local_description(answer.clone()).await {
                                        tracing::warn!("[bg-signaling] Failed to set local description: {}", e);
                                        continue;
                                    }
                                    let mut sig = signaling.lock().await;
                                    let _ = sig.send(SignalMessage::Answer {
                                        sdp: answer.sdp,
                                    }).await;
                                    tracing::info!("[bg-signaling] Renegotiation answer sent");
                                }
                                SignalMessage::Answer { sdp, .. } | SignalMessage::AnswerReceived { sdp, .. } => {
                                    let answer = match RTCSessionDescription::answer(sdp) {
                                        Ok(a) => a,
                                        Err(_) => continue,
                                    };
                                    let _ = peer_connection.set_remote_description(answer).await;
                                }
                                SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index, .. } => {
                                    tracing::info!("[bg-signaling] Received ICE candidate");
                                    let candidate_init = RTCIceCandidateInit {
                                        candidate,
                                        sdp_mid,
                                        sdp_mline_index: sdp_mline_index.map(|i| i as u16),
                                        username_fragment: None,
                                    };
                                    let _ = peer_connection.add_ice_candidate(candidate_init).await;
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

/// Generate a random ID for participant names
fn rand_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_nanos() as u64 ^ (std::process::id() as u64)
}
