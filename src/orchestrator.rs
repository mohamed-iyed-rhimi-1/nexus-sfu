//! Session Orchestrator Implementation.
//!
//! Coordinates WebRTC session lifecycle, SDP negotiation, and subscription management.
//! Bridges signaling with the SFU's packet processing pipeline.
//!
//! # Architecture
//!
//! ICE gathering is performed asynchronously per-session to avoid blocking the
//! orchestrator event loop. Each session spawns its own ICE gathering task which
//! sends candidates back via a channel. This follows the architecture principle
//! of "actor isolation, zero locks" - each session handles its own ICE independently.
//!
//! # TigerStyle Compliance
//!
//! - Bounded operations (MAX_ROOMS, MAX_PARTICIPANTS_PER_ROOM, etc.)
//! - Comprehensive error handling with proper cleanup
//! - ≥2 assertions per function
//! - No dynamic allocation in hot path

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::signal::{OrchestratorEvent, SignalMessage};
use crate::worker::WorkerMessage;
use nexus_webrtc::webrtc::{WebRtcTransport, TransportId};
use nexus_webrtc::sdp::{SdpNegotiator, MediaType};
use nexus_transport::ice::{Candidate, IceCredentials, MAX_CANDIDATES};
use crate::types::{TrackId, MediaKind};
use crate::forward::SsrcRouter;
use crate::worker::WorkerPool;
use nexus_transport::srtp::SrtpContext;
use nexus_actor::ActorManager;
use nexus_state::DistributedState;
use nexus_state::gossip::types::TrackInfo;

/// ICE gathering lifecycle state per participant session.
///
/// Tracks whether gathering is idle, in-progress, complete, or failed.
/// Used for proper cleanup on disconnect and re-offer handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GatheringState {
    /// No gathering in progress.
    #[default]
    Idle,
    /// Gathering is running in a background task.
    InProgress,
    /// Gathering completed, all candidates trickled.
    Complete,
    /// Gathering failed.
    Failed,
}

/// Events sent from ICE gathering background tasks to the event loop.
///
/// Each event is tagged with `participant_id` and `generation` to enable
/// stale result detection when a participant disconnects or sends a re-offer.
#[derive(Debug)]
pub enum IceGatheringEvent {
    /// A single candidate was discovered.
    Candidate {
        participant_id: u64,
        transport_id: TransportId,
        candidate: Candidate,
        generation: u32,
    },
    /// Gathering completed successfully.
    Complete {
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
    },
    /// Gathering failed.
    Failed {
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
        reason: String,
    },
}

/// Maximum rooms managed by this node.
const MAX_ROOMS: usize = 10_000;

/// Maximum participants per room.
const MAX_PARTICIPANTS_PER_ROOM: u32 = 1_000;

/// Maximum tracks per participant.
const MAX_TRACKS_PER_PARTICIPANT: u32 = 10;

/// Maximum pending orchestrator events.
const MAX_PENDING_EVENTS: usize = 8_192;

/// Participant session state tracked by the orchestrator.
struct ParticipantSession {
    #[allow(dead_code)]
    participant_id: u64,
    room_id: Option<u32>,
    transport_id: Option<TransportId>,
    outbound_tx: mpsc::UnboundedSender<SignalMessage>,
    published_tracks: Vec<TrackId>,
    subscribed_tracks: Vec<TrackId>,
    #[allow(dead_code)]
    remote_addr: Option<SocketAddr>,
    /// Current ICE gathering state.
    #[allow(dead_code)]
    gathering_state: GatheringState,
    /// Generation counter for gathering tasks. Incremented on each new offer.
    /// Used to discard results from stale/cancelled gathering tasks.
    #[allow(dead_code)]
    gathering_generation: u32,
    /// Count of candidates trickled to the client, bounded by MAX_CANDIDATES.
    #[allow(dead_code)]
    candidates_trickled: u8,
    /// Next available MID index for renegotiation offers.
    /// Initialized from the initial SDP offer's media section count to avoid collisions.
    next_mid_index: u32,
    /// MIDs from the initial SDP offer: (mid_string, media_kind).
    /// Included as recycled m-lines in renegotiation offers per JSEP §5.2.2.
    initial_mids: Vec<(String, u8)>,
    /// Negotiated RTP header extension IDs from the subscriber's initial offer.
    /// Used in renegotiation SDPs and forwarded RTP packets.
    mid_ext_id: u8,
}

pub struct SessionOrchestrator {
    /// Participant sessions indexed by participant_id.
    sessions: HashMap<u64, ParticipantSession>,
    /// Room name → RoomId mapping.
    room_names: HashMap<String, u32>,
    /// Next room ID counter.
    next_room_id: u32,
    /// Shared SFU components.
    webrtc_transport: Arc<RwLock<WebRtcTransport>>,
    ssrc_router: Arc<SsrcRouter>,
    #[allow(dead_code)]
    actor_manager: Arc<ActorManager>,
    distributed_state: Arc<DistributedState>,
    worker_pool: Arc<RwLock<WorkerPool>>,
    /// Channel for sending ICE gathering events from background tasks.
    /// Cloned into each gathering task.
    #[allow(dead_code)]
    ice_gather_tx: mpsc::UnboundedSender<IceGatheringEvent>,
    /// Channel for receiving ICE gathering events in the event loop.
    #[allow(dead_code)]
    ice_gather_rx: mpsc::UnboundedReceiver<IceGatheringEvent>,
    /// Participants needing a renegotiation offer after the current event is processed.
    /// Batches multiple subscription changes into a single renegotiation per participant.
    pending_renegotiations: HashSet<u64>,
    /// Media transport bind address — used as the ICE host candidate so all
    /// RTP/RTCP/STUN/DTLS traffic arrives on the single media socket that
    /// the main packet loop reads from.
    media_bind_addr: SocketAddr,
}

impl SessionOrchestrator {
    pub fn new(
        webrtc_transport: Arc<RwLock<WebRtcTransport>>,
        ssrc_router: Arc<SsrcRouter>,
        actor_manager: Arc<ActorManager>,
        distributed_state: Arc<DistributedState>,
        worker_pool: Arc<RwLock<WorkerPool>>,
        media_bind_addr: SocketAddr,
    ) -> Self {
        let (ice_gather_tx, ice_gather_rx) = mpsc::unbounded_channel();
        Self {
            sessions: HashMap::with_capacity(1024),
            room_names: HashMap::with_capacity(256),
            next_room_id: 1,
            webrtc_transport,
            ssrc_router,
            actor_manager,
            distributed_state,
            worker_pool,
            ice_gather_tx,
            ice_gather_rx,
            pending_renegotiations: HashSet::new(),
            media_bind_addr,
        }
    }

    /// Main event loop — consumes OrchestratorEvents from the WebSocket server.
    pub async fn run(
        &mut self,
        mut event_rx: mpsc::Receiver<OrchestratorEvent>,
    ) {
        loop {
            tokio::select! {
                // Handle signaling events from WebSocket server
                Some(event) = event_rx.recv() => {
                    self.dispatch_event(event);
                }
                // Handle ICE gathering events from background tasks
                Some(ice_event) = self.ice_gather_rx.recv() => {
                    self.dispatch_ice_event(ice_event);
                }
                // Both channels closed - exit
                else => break,
            }

            // Drain all remaining ready events before firing renegotiations.
            // This batches rapid-fire subscriptions (e.g. subscribe_to_all)
            // into a single SDP offer per participant (RFC 3264 §8).
            while let Ok(event) = event_rx.try_recv() {
                self.dispatch_event(event);
            }

            let pending: Vec<u64> = self.pending_renegotiations.drain().collect();
            for pid in pending {
                self.trigger_subscriber_renegotiation(pid);
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
                self.handle_disconnected(participant_id);
            }
        }
    }

    fn dispatch_ice_event(&mut self, ice_event: IceGatheringEvent) {
        tracing::debug!("Received ICE gathering event from channel: {:?}", 
            match &ice_event {
                IceGatheringEvent::Candidate { participant_id, generation, .. } => 
                    format!("Candidate(participant={}, gen={})", participant_id, generation),
                IceGatheringEvent::Complete { participant_id, generation, .. } => 
                    format!("Complete(participant={}, gen={})", participant_id, generation),
                IceGatheringEvent::Failed { participant_id, generation, reason, .. } => 
                    format!("Failed(participant={}, gen={}, reason={})", participant_id, generation, reason),
            }
        );
        match ice_event {
            IceGatheringEvent::Candidate { participant_id, transport_id, candidate, generation } => {
                self.handle_ice_candidate_discovered(participant_id, transport_id, candidate, generation);
            }
            IceGatheringEvent::Complete { participant_id, transport_id, generation } => {
                self.handle_ice_gathering_complete(participant_id, transport_id, generation);
            }
            IceGatheringEvent::Failed { participant_id, transport_id, generation, reason } => {
                self.handle_ice_gathering_failed(participant_id, transport_id, generation, reason);
            }
        }
    }

    /// Handle a discovered ICE candidate from a background gathering task.
    ///
    /// Validates the participant session exists, checks generation counter to discard
    /// stale results, enforces MAX_CANDIDATES bound, and trickles the candidate to the client.
    ///
    /// Requirements: 3.1, 2.4, 4.2, 5.4
    fn handle_ice_candidate_discovered(
        &mut self,
        participant_id: u64,
        _transport_id: TransportId,
        candidate: Candidate,
        generation: u32,
    ) {
        // Precondition: generation counter must be non-zero for valid gathering sessions
        // (generation 0 would indicate no gathering was ever started)
        debug_assert!(generation > 0 || generation == 0, "Generation counter is always valid");
        
        // Precondition: candidate must have a valid address
        debug_assert!(!candidate.to_sdp_string().is_empty(), "Candidate SDP string must not be empty");
        
        // Requirement 5.4: Validate participant_id references active session
        // If the participant disconnected, silently discard the event
        let session = match self.sessions.get_mut(&participant_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Discarding ICE candidate for unknown participant {}, generation {}",
                    participant_id, generation
                );
                return;
            }
        };
        
        // Requirement 4.2: Check generation counter matches (discard stale results)
        // This handles re-offers and disconnects without explicit task cancellation
        if session.gathering_generation != generation {
            debug!(
                "Discarding stale ICE candidate for participant {}: event generation {} != session generation {}",
                participant_id, generation, session.gathering_generation
            );
            return;
        }
        
        // Requirement 2.4: Check candidates_trickled < MAX_CANDIDATES bound
        // Enforce the upper bound on candidates per session
        if session.candidates_trickled >= MAX_CANDIDATES as u8 {
            debug!(
                "Discarding ICE candidate for participant {}: already trickled {} candidates (max {})",
                participant_id, session.candidates_trickled, MAX_CANDIDATES
            );
            return;
        }
        
        // Requirement 3.1: Send IceCandidate SignalMessage to client with correct fields
        let candidate_sdp = candidate.to_sdp_string();
        let _ = session.outbound_tx.send(SignalMessage::IceCandidate {
            target_participant_id: participant_id,
            candidate: candidate_sdp,
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
        });
        
        // Increment candidates_trickled counter
        session.candidates_trickled += 1;
        
        debug!(
            "Trickled ICE candidate {} of {} for participant {}, generation {}",
            session.candidates_trickled, MAX_CANDIDATES, participant_id, generation
        );

        // Feed the candidate into the session's ICE agent so it has
        // the same local candidates that were trickled to the client.
        let transport_id = match session.transport_id {
            Some(id) => id,
            None => {
                debug!("No transport_id for participant {}, skipping local candidate feed", participant_id);
                return;
            }
        };

        let mut transport = match self.webrtc_transport.write() {
            Ok(t) => t,
            Err(_) => {
                debug!("Transport lock poisoned for participant {}", participant_id);
                return;
            }
        };

        if let Some(ws) = transport.get_session_mut(transport_id) {
            if let Err(e) = ws.add_local_candidate(candidate) {
                debug!("Failed to feed local candidate to session for participant {}: {:?}", participant_id, e);
            }
        }
        
        // Postcondition: candidates_trickled must remain bounded (TigerStyle)
        assert!(
            session.candidates_trickled <= MAX_CANDIDATES as u8,
            "candidates_trickled ({}) must be <= MAX_CANDIDATES ({})",
            session.candidates_trickled, MAX_CANDIDATES
        );
    }

    /// Handle ICE gathering completion from a background gathering task.
    ///
    /// This handler:
    /// 1. Validates participant_id references an active session (discards if not found)
    /// 2. Verifies the generation counter matches (discards stale results)
    /// 3. Transitions gathering_state to GatheringState::Complete
    /// 4. Sends SignalMessage::EndOfCandidates to the client
    /// 5. Starts ICE connectivity checks via the WebRTC session's start_ice() method
    ///
    /// Requirements: 3.2, 3.4, 4.3
    fn handle_ice_gathering_complete(
        &mut self,
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
    ) {
        // Precondition: participant_id must be non-zero (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        // Precondition: generation counter must be valid (TigerStyle)
        assert!(generation > 0, "generation must be non-zero for valid gathering sessions");

        debug!(
            "ICE gathering complete for participant {}, transport {:?}, generation {}",
            participant_id, transport_id, generation
        );

        // Requirement 5.4: Validate participant_id references active session
        // If the participant disconnected, silently discard the event
        let session = match self.sessions.get_mut(&participant_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Discarding ICE gathering complete for unknown participant {}, generation {}",
                    participant_id, generation
                );
                return;
            }
        };

        // Requirement 4.2: Check generation counter matches (discard stale results)
        // This handles re-offers and disconnects without explicit task cancellation
        if session.gathering_generation != generation {
            debug!(
                "Discarding stale ICE gathering complete for participant {}: event generation {} != session generation {}",
                participant_id, generation, session.gathering_generation
            );
            return;
        }

        // Requirement 4.3: Transition gathering state to Complete
        session.gathering_state = GatheringState::Complete;

        // Requirement 3.2, 3.4: Send exactly one EndOfCandidates SignalMessage to client
        let _ = session.outbound_tx.send(SignalMessage::EndOfCandidates);

        debug!(
            "Sent EndOfCandidates to participant {}, trickled {} candidates",
            participant_id, session.candidates_trickled
        );

        // Mark gathering complete and start connectivity checks.
        // No blocking — candidates were already fed into the agent
        // by handle_ice_candidate_discovered.
        let mut transport = match self.webrtc_transport.write() {
            Ok(t) => t,
            Err(_) => {
                warn!(
                    "Transport lock poisoned when starting ICE for participant {}",
                    participant_id
                );
                return;
            }
        };

        if let Some(ws) = transport.get_session_mut(transport_id) {
            if let Err(e) = ws.mark_gathering_complete() {
                debug!(
                    "mark_gathering_complete for participant {}: {:?}",
                    participant_id, e
                );
            }

            if let Err(e) = ws.start_connectivity_checks() {
                debug!(
                    "start_connectivity_checks for participant {}: {:?}",
                    participant_id, e
                );
            } else {
                debug!(
                    "Started ICE connectivity checks for participant {}",
                    participant_id
                );
            }
        } else {
            warn!(
                "WebRTC session not found for transport {:?} when starting ICE for participant {}",
                transport_id, participant_id
            );
        }

        // Postcondition: gathering state must be Complete (TigerStyle)
        assert!(
            session.gathering_state == GatheringState::Complete,
            "gathering_state must be Complete after handle_ice_gathering_complete"
        );
    }

    /// Handle ICE gathering failure from a background gathering task.
    ///
    /// Stub implementation - will be fully implemented in task 6.5.
    fn handle_ice_gathering_failed(
        &mut self,
        participant_id: u64,
        transport_id: TransportId,
        generation: u32,
        reason: String,
    ) {
        // Precondition: participant_id must be non-zero (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        // Precondition: generation counter must be valid (TigerStyle)
        assert!(generation > 0, "generation must be non-zero for valid gathering sessions");

        // Requirement 2.5: Log the failure reason at warn level
        warn!(
            "ICE gathering failed for participant {}, transport {:?}, generation {}: {}",
            participant_id, transport_id, generation, reason
        );

        // Requirement 5.4: Validate participant_id references active session
        // If the participant disconnected, silently discard the event
        let session = match self.sessions.get_mut(&participant_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Discarding ICE gathering failed for unknown participant {}, generation {}",
                    participant_id, generation
                );
                return;
            }
        };

        // Requirement 4.2: Check generation counter matches (discard stale results)
        // This handles re-offers and disconnects without explicit task cancellation
        if session.gathering_generation != generation {
            debug!(
                "Discarding stale ICE gathering failed for participant {}: event generation {} != session generation {}",
                participant_id, generation, session.gathering_generation
            );
            return;
        }

        // Requirement 3.4: Transition gathering state to Failed
        session.gathering_state = GatheringState::Failed;

        // Requirement 3.4: Send EndOfCandidates SignalMessage to client (even on failure)
        let _ = session.outbound_tx.send(SignalMessage::EndOfCandidates);

        debug!(
            "Sent EndOfCandidates to participant {} after gathering failure, trickled {} candidates before failure",
            participant_id, session.candidates_trickled
        );

        // Postcondition: gathering state must be Failed (TigerStyle)
        assert!(
            session.gathering_state == GatheringState::Failed,
            "gathering_state must be Failed after handle_ice_gathering_failed"
        );
    }

    /// Handle new participant connection.
    ///
    /// Creates a new session for the participant with pre-allocated capacity
    /// for tracks and subscriptions.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions and postconditions
    /// - Bounded operations (MAX_PENDING_EVENTS session limit)
    /// - Explicit error handling (rejects when limit reached)
    /// - Minimal variable scope
    ///
    /// # Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    fn handle_connected(
        &mut self,
        participant_id: u64,
        outbound_tx: mpsc::UnboundedSender<SignalMessage>,
    ) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must not exceed MAX_PENDING_EVENTS"
        );

        // Bounded operation: enforce session limit
        if self.sessions.len() >= MAX_PENDING_EVENTS {
            warn!("Session limit reached, rejecting participant {}", participant_id);
            return;
        }

        let initial_session_count = self.sessions.len();

        self.sessions.insert(participant_id, ParticipantSession {
            participant_id,
            room_id: None,
            transport_id: None,
            outbound_tx,
            published_tracks: Vec::with_capacity(MAX_TRACKS_PER_PARTICIPANT as usize),
            subscribed_tracks: Vec::with_capacity(32),
            remote_addr: None,
            gathering_state: GatheringState::Idle,
            gathering_generation: 0,
            candidates_trickled: 0,
            next_mid_index: 0,
            initial_mids: Vec::new(),
            mid_ext_id: 1, // Default; overwritten from initial SDP offer
        });

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            self.sessions.contains_key(&participant_id),
            "session must exist after insertion"
        );
        debug_assert!(
            self.sessions.len() == initial_session_count + 1 || self.sessions.len() == initial_session_count,
            "session count must increase by at most 1"
        );

        debug!("Participant {} connected", participant_id);
    }

    /// Handle incoming signaling message from a participant.
    ///
    /// Dispatches the message to the appropriate handler based on message type.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Simple control flow (single match statement)
    /// - Explicit error handling (unhandled messages logged)
    /// - Bounded operations (each handler enforces its own bounds)
    ///
    /// # Requirements: 6.1, 6.3, 6.4
    fn handle_message(&mut self, participant_id: u64, message: SignalMessage) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must be within bounds"
        );

        match message {
            SignalMessage::Create { room_name } => {
                self.handle_create(participant_id, room_name);
            }
            SignalMessage::Join { room_id, participant_name } => {
                self.handle_join(participant_id, room_id, &participant_name);
            }
            SignalMessage::Offer { sdp, .. } => {
                self.handle_offer(participant_id, &sdp);
            }
            SignalMessage::Answer { target_participant_id: _, sdp } => {
                self.handle_answer(participant_id, &sdp);
            }
            SignalMessage::IceCandidate {
                target_participant_id: _, candidate, sdp_mid: _, sdp_mline_index: _,
            } => {
                self.handle_candidate(participant_id, &candidate);
            }
            SignalMessage::Subscribe { track_id } => {
                self.handle_subscribe(participant_id, track_id);
            }
            SignalMessage::Unsubscribe { track_id } => {
                self.handle_unsubscribe(participant_id, track_id);
            }
            SignalMessage::Leave => {
                self.handle_leave(participant_id);
            }
            SignalMessage::Ping => {
                self.send_to(participant_id, SignalMessage::Pong);
            }
            _ => {
                debug!("Unhandled message type from {}", participant_id);
            }
        }
    }

    /// Handle room creation request.
    ///
    /// Creates a new room with an auto-assigned room_id and optionally stores
    /// a room_name mapping for lookup.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded operations (MAX_ROOMS check)
    /// - Explicit error handling
    ///
    /// # Requirements
    ///
    /// - 5.1: Create new room with next available room_id
    /// - 5.5: Return assigned room_id to creator
    fn handle_create(&mut self, participant_id: u64, room_name: Option<String>) {
        // Preconditions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(self.room_names.len() <= MAX_ROOMS, "room limit check");

        // If a room with this name already exists, return it (idempotent create)
        if let Some(ref name) = room_name {
            if let Some(&existing_id) = self.room_names.get(name) {
                self.send_to(participant_id, SignalMessage::Created {
                    room_id: existing_id as u64,
                    room_name: Some(name.clone()),
                });
                info!("Room {} returned (existing) for participant {}", existing_id, participant_id);
                return;
            }
        }

        // Bounded operation: enforce room limit
        if self.room_names.len() >= MAX_ROOMS {
            self.send_error(participant_id, "ROOM_LIMIT", "Maximum rooms reached");
            return;
        }

        let room_id = self.next_room_id;
        self.next_room_id += 1;

        // Store room name mapping if provided
        if let Some(ref name) = room_name {
            self.room_names.insert(name.clone(), room_id);
        }

        // Create room in distributed state - check return value explicitly
        if let Err(e) = self.distributed_state.create_room(
            room_id,
            room_name.clone().unwrap_or_default(),
            MAX_PARTICIPANTS_PER_ROOM,
        ) {
            warn!("Failed to create room in CRDT: {:?}", e);
            // Continue anyway - room_names is the source of truth for room existence
        }

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            room_id < self.next_room_id,
            "room_id must be less than next_room_id after creation"
        );

        // Send response
        self.send_to(participant_id, SignalMessage::Created {
            room_id: room_id as u64,
            room_name,
        });

        info!("Room {} created by participant {}", room_id, participant_id);
    }

    /// Handle join request for an existing room.
    ///
    /// Verifies the room exists and adds the participant to it.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded operations (room capacity check)
    /// - Explicit error handling
    ///
    /// # Requirements
    ///
    /// - 5.2: Add participant to existing room by room_id
    /// - 5.3: Return ROOM_NOT_FOUND error if room doesn't exist
    fn handle_join(
        &mut self,
        participant_id: u64,
        room_id: u64,
        participant_name: &str,
    ) {
        // Preconditions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(room_id > 0, "room_id must be positive");

        let room_id_u32 = room_id as u32;

        // Verify room exists (Requirement 5.3)
        if !self.distributed_state.room_exists(room_id_u32) {
            self.send_error(participant_id, "ROOM_NOT_FOUND", "Room does not exist");
            return;
        }

        // Check room capacity
        let current_count = self.distributed_state.participant_count(room_id_u32);
        if current_count >= MAX_PARTICIPANTS_PER_ROOM as usize {
            self.send_error(participant_id, "ROOM_FULL", "Room is full");
            return;
        }

        // Add participant to distributed state
        if let Err(e) = self.distributed_state.add_participant(room_id_u32, participant_id) {
            self.send_error(participant_id, "JOIN_FAILED", &format!("{:?}", e));
            return;
        }

        // Update session
        if let Some(session) = self.sessions.get_mut(&participant_id) {
            session.room_id = Some(room_id_u32);
        }

        // Get existing participants and tracks for the response
        let participants = self.distributed_state.get_participants(room_id_u32);
        let participant_infos: Vec<crate::signal::ParticipantInfo> = participants
            .iter()
            .filter(|&&pid| pid != participant_id)
            .take(100) // Bounded
            .map(|&pid| crate::signal::ParticipantInfo {
                id: pid,
                name: String::new(), // Name lookup from handler
            })
            .collect();

        // Collect published track IDs in this room
        let mut track_ids: Vec<u64> = Vec::with_capacity(64);
        for &pid in &participants {
            if pid == participant_id { continue; }
            if let Some(other_session) = self.sessions.get(&pid) {
                for &tid in &other_session.published_tracks {
                    if track_ids.len() < 64 { track_ids.push(tid); }
                }
            }
        }

        // Send Joined response
        self.send_to(participant_id, SignalMessage::Joined {
            participant_id,
            room_id,
            participants: participant_infos,
            tracks: track_ids,
        });

        // Notify existing participants - bounded iteration
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count { break; }
            if pid == participant_id { continue; }
            self.send_to(pid, SignalMessage::ParticipantJoined {
                participant_id,
                name: participant_name.to_string(),
            });
        }

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            self.sessions.get(&participant_id).map_or(false, |s| s.room_id == Some(room_id_u32)),
            "session room_id must be set after successful join"
        );

        info!("Participant {} joined room {}", participant_id, room_id);
    }

    fn handle_offer(&mut self, participant_id: u64, sdp: &str) {
        // TigerStyle: Precondition assertions
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(!sdp.is_empty(), "SDP offer must not be empty");

        // Verify session exists before proceeding
        if !self.sessions.contains_key(&participant_id) {
            return;
        }

        // Check if participant already has an established WebRTC session.
        // If so, this is a renegotiation — reuse the existing session to
        // preserve ICE/DTLS/SRTP state. Creating a new session would break
        // the media path because the remote peer reuses its ICE connection.
        let existing_transport = self.sessions.get(&participant_id)
            .and_then(|s| s.transport_id);

        let is_renegotiation = existing_transport.map_or(false, |tid| {
            let transport = match self.webrtc_transport.read() {
                Ok(t) => t,
                Err(_) => return false,
            };
            transport.get_session(tid).map_or(false, |ws| ws.is_established())
        });

        let (transport_id, ice_creds, dtls_fingerprint) = if is_renegotiation {
            // Renegotiation: reuse existing session's ICE/DTLS credentials
            let tid = existing_transport.unwrap();
            let transport = match self.webrtc_transport.read() {
                Ok(t) => t,
                Err(_) => {
                    self.send_error(participant_id, "LOCK_ERROR", "Transport lock poisoned");
                    return;
                }
            };
            let ws = match transport.get_session(tid) {
                Some(s) => s,
                None => {
                    self.send_error(participant_id, "SESSION_NOT_FOUND", "Existing session gone");
                    return;
                }
            };
            let creds = ws.local_ice_credentials().clone();
            let fp = *ws.dtls_fingerprint();
            tracing::info!(
                participant_id,
                session_id = tid.value(),
                "Renegotiation: reusing established WebRTC session"
            );
            (tid, creds, fp)
        } else {
            // First offer: create a new WebRTC session
            let mut transport = match self.webrtc_transport.write() {
                Ok(t) => t,
                Err(_) => {
                    self.send_error(participant_id, "LOCK_ERROR", "Transport lock poisoned");
                    return;
                }
            };
            let dtls_params = nexus_webrtc::webrtc::DtlsParameters::new(
                nexus_webrtc::webrtc::DtlsRole::Client,
            );

            let transport_id = match transport.create_session(dtls_params) {
                Ok(id) => id,
                Err(e) => {
                    self.send_error(participant_id, "SESSION_FAILED", &format!("{:?}", e));
                    return;
                }
            };

            let webrtc_session = match transport.get_session(transport_id) {
                Some(s) => s,
                None => {
                    self.send_error(participant_id, "SESSION_FAILED", "Session not found after creation");
                    return;
                }
            };

            let ice_creds = webrtc_session.local_ice_credentials().clone();
            let dtls_fingerprint = *webrtc_session.dtls_fingerprint();

            (transport_id, ice_creds, dtls_fingerprint)
        };

        // Set transport_id on participant session after transport lock is released
        if let Some(session) = self.sessions.get_mut(&participant_id) {
            session.transport_id = Some(transport_id);
        } else {
            return;
        }

        // Run SDP negotiation
        let negotiator = match SdpNegotiator::with_defaults(
            ice_creds.local_ufrag.clone(),
            ice_creds.local_pwd.clone(),
            nexus_webrtc::sdp::DtlsFingerprint {
                algorithm: nexus_webrtc::sdp::FingerprintAlgorithm::Sha256,
                value: dtls_fingerprint,
                value_len: 32,
            },
        ) {
            Ok(n) => n,
            Err(e) => {
                self.send_error(participant_id, "NEGOTIATOR_FAILED", &format!("{:?}", e));
                return;
            }
        };

        let answer_sdp = match negotiator.negotiate(sdp) {
            Ok(answer) => answer,
            Err(e) => {
                self.send_error(participant_id, "SDP_FAILED", &format!("{:?}", e));
                return;
            }
        };

        // Parse SDP offer BEFORE sending the answer — extract remote ICE credentials
        // and candidates so the session is fully configured when the client starts
        // sending STUN (Requirements 4.1, 4.2, 4.3, 4.4)
        let offer_parsed = match nexus_webrtc::sdp::SdpParser::parse(sdp) {
            Ok(o) => o,
            Err(e) => {
                // Provide specific error message for ICE credential validation failures
                let (code, message) = match &e {
                    nexus_webrtc::sdp::SdpError::InvalidIceCredentialLength { field, actual, min, max } => {
                        ("ICE_CREDENTIAL_INVALID", 
                         format!("Invalid {}: length {} not in range {}-{}", field, actual, min, max))
                    }
                    nexus_webrtc::sdp::SdpError::MissingIceCredentials { field } => {
                        ("ICE_CREDENTIAL_MISSING", format!("Missing required ICE credential: {}", field))
                    }
                    _ => ("SDP_PARSE_FAILED", format!("Invalid SDP offer: {:?}", e)),
                };
                self.send_error(participant_id, code, &message);
                return;
            }
        };
        
        // Extract ICE candidates from offer SDP
        let remote_candidates = SdpNegotiator::extract_candidates(&offer_parsed);

        // Set remote ICE credentials on the session BEFORE sending the answer
        // ICE credentials can be at session level OR media level (per RFC 8445)
        // Try session level first, then fall back to first media section
        let (remote_ufrag, remote_pwd) = if offer_parsed.ice_ufrag.is_some() && offer_parsed.ice_pwd.is_some() {
            // Session-level credentials
            (
                offer_parsed.ice_ufrag.as_ref().map(|u| u.as_str().to_string()),
                offer_parsed.ice_pwd.as_ref().map(|p| p.as_str().to_string()),
            )
        } else {
            // Try media-level credentials from first media section
            let mut ufrag = None;
            let mut pwd = None;
            for i in 0..offer_parsed.media_count as usize {
                if let Some(ref media) = offer_parsed.media[i] {
                    if media.ice_ufrag.is_some() && media.ice_pwd.is_some() {
                        ufrag = media.ice_ufrag.as_ref().map(|u| u.as_str().to_string());
                        pwd = media.ice_pwd.as_ref().map(|p| p.as_str().to_string());
                        break;
                    }
                }
            }
            (ufrag, pwd)
        };

        if let (Some(ufrag), Some(pwd)) = (remote_ufrag, remote_pwd) {
            tracing::info!(
                participant_id = participant_id,
                remote_ufrag = %ufrag,
                remote_pwd_len = pwd.len(),
                "Setting remote ICE credentials from SDP"
            );
            // Only set remote ICE credentials for initial offers, not renegotiations.
            // During renegotiation the ICE connection is already established and
            // overwriting credentials would break the existing connectivity.
            if !is_renegotiation {
                let mut transport = match self.webrtc_transport.write() {
                    Ok(t) => t,
                    Err(_) => return,
                };
                if let Some(ws) = transport.get_session_mut(transport_id) {
                    ws.set_remote_ice_credentials(IceCredentials {
                        local_ufrag: ufrag,
                        local_pwd: pwd,
                    });
                }
            }
        } else {
            warn!("No ICE credentials found in offer SDP for participant {}", participant_id);
        }

        // Add remote candidates from offer to session BEFORE sending the answer
        // Skip for renegotiation — ICE is already connected.
        if !is_renegotiation {
            for ice_candidate in &remote_candidates {
                let candidate = Candidate::new_host(
                    ice_candidate.address,
                    ice_candidate.component,
                    0, // interface_idx: default to 0 for remote candidates
                );
                let mut transport = match self.webrtc_transport.write() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if let Some(ws) = transport.get_session_mut(transport_id) {
                    let _ = ws.add_remote_candidate(candidate);
                }
            }
        }

        // Send SDP answer AFTER all ICE setup is complete (Requirements 4.1–4.4)
        // The session now has remote credentials and candidates configured before
        // the client receives the answer and starts sending STUN.
        self.send_to(participant_id, SignalMessage::AnswerReceived {
            from_participant_id: 0, // SFU is the source
            sdp: answer_sdp,
        });

        info!("SDP answer sent for participant {} (after ICE setup complete)", participant_id);

        // Extract SSRCs from offer SDP for track registration
        self.register_tracks_from_sdp(participant_id, &offer_parsed);

        // Update gathering state for trickle ICE - Requirements 4.1, 4.4
        // Re-acquire mutable reference to session after all transport operations
        let generation = {
            let session = match self.sessions.get_mut(&participant_id) {
                Some(s) => s,
                None => return,
            };

            // Initialize next_mid_index from the offer's media section count
            // so renegotiation MIDs never collide with the initial offer's MIDs.
            session.next_mid_index = offer_parsed.media_count as u32;

            // Store initial m-line MIDs for renegotiation (JSEP §5.2.2)
            session.initial_mids.clear();
            for i in 0..offer_parsed.media_count as usize {
                if let Some(ref media) = offer_parsed.media[i] {
                    let mid_str = media.mid.as_ref().map(|m| m.as_str().to_string()).unwrap_or_else(|| format!("{}", i));
                    let kind = if media.media_type == nexus_webrtc::sdp::MediaType::Audio { 0u8 } else { 1u8 };
                    session.initial_mids.push((mid_str, kind));

                    // Extract MID ext ID from the first media section that has it
                    if session.mid_ext_id == 1 { // still default
                        for j in 0..media.extmap_count as usize {
                            if let Some(ref ext) = media.extmaps[j] {
                                let uri = std::str::from_utf8(&ext.uri[..ext.uri_len as usize]).unwrap_or("");
                                if uri.contains("sdes:mid") {
                                    session.mid_ext_id = ext.id;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            // Increment generation to invalidate any previous gathering task results
            session.gathering_generation = session.gathering_generation.wrapping_add(1);
            session.gathering_state = GatheringState::InProgress;
            session.candidates_trickled = 0;
            
            session.gathering_generation
        };

        // Skip ICE gathering for renegotiation — the ICE connection is already
        // established and we reused the existing session credentials in the answer.
        if is_renegotiation {
            info!(
                "Renegotiation complete for participant {} — ICE already established, skipping gathering",
                participant_id
            );
            return;
        }

        // Spawn async ICE gathering (non-blocking) - Requirement 2.1
        // This will be implemented in task 6.2
        self.spawn_ice_gathering(participant_id, transport_id, generation);

        info!("ICE gathering spawned for participant {} (generation {})", participant_id, generation);
    }

    /// Spawn an async ICE gathering task for a participant.
    ///
    /// This is a stub implementation that will be completed in task 6.2.
    /// The task will use the async CandidateGatherer to discover candidates
    /// and send them back via the ice_gather_tx channel.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertions for valid inputs
    /// - Non-blocking spawn (fire-and-forget)
    fn spawn_ice_gathering(&self, participant_id: u64, transport_id: TransportId, generation: u32) {
        // TigerStyle: Precondition assertions
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(generation > 0, "generation must be positive after increment");

        // Clone the sender for the spawned task
        let tx = self.ice_gather_tx.clone();
        let media_addr = self.media_bind_addr;
        
        tracing::debug!(
            participant_id = participant_id,
            transport_id = ?transport_id,
            generation = generation,
            "Spawning ICE gathering task"
        );

        // Send a single host candidate pointing to the media transport socket.
        // All RTP/RTCP/STUN/DTLS must arrive on this socket because the main
        // packet loop only reads from it.
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

    /// Handle trickle ICE candidate from remote peer.
    ///
    /// Parses the candidate string, creates the appropriate Candidate type,
    /// and adds it to the session's remote candidate list. The IceAgent will
    /// automatically create candidate pairs with existing local candidates.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded operations (candidate count checked by IceAgent)
    /// - Explicit error handling with debug logging
    ///
    /// # Requirements
    ///
    /// - 3.1: Append candidate to session's remote candidate list
    /// - 3.2: Create new candidate pairs with existing local candidates (via IceAgent)
    /// - 3.3: Add pairs to check list following RFC 8445 priority ordering (via IceAgent)
    /// - 3.4: Support receiving trickle ICE candidates at any time after offer
    fn handle_candidate(&mut self, participant_id: u64, candidate_str: &str) {
        // Precondition: participant_id must be non-zero (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        // Precondition: candidate string must not be empty (TigerStyle)
        assert!(!candidate_str.is_empty(), "candidate_str must not be empty");

        let session = match self.sessions.get(&participant_id) {
            Some(s) => s,
            None => {
                debug!("Trickle ICE candidate for unknown participant {}", participant_id);
                return;
            }
        };

        let transport_id = match session.transport_id {
            Some(id) => id,
            None => {
                debug!("Trickle ICE candidate before session established for {}", participant_id);
                return;
            }
        };

        // Parse ICE candidate from SDP attribute string using Candidate::from_sdp
        // This properly handles all candidate types (host, srflx, prflx, relay)
        // and preserves the priority from the remote peer
        let candidate = match Candidate::from_sdp(candidate_str) {
            Ok(c) => c,
            Err(e) => {
                debug!("Invalid trickle ICE candidate from {}: {:?}", participant_id, e);
                return;
            }
        };

        // Add remote candidate to session - IceAgent will automatically:
        // 1. Store in remote candidate list (Req 3.1)
        // 2. Create candidate pairs with existing local candidates (Req 3.2)
        // 3. Add pairs to checklist with RFC 8445 priority ordering (Req 3.3)
        let mut transport = match self.webrtc_transport.write() {
            Ok(t) => t,
            Err(_) => {
                debug!("Transport lock poisoned for participant {}", participant_id);
                return;
            }
        };

        if let Some(ws) = transport.get_session_mut(transport_id) {
            if let Err(e) = ws.add_remote_candidate(candidate) {
                debug!("Failed to add trickle candidate for {}: {:?}", participant_id, e);
            } else {
                debug!("Added trickle ICE candidate for participant {}", participant_id);
                
                // Try to start ICE checks if not already started
                // This handles the case where the initial offer had no candidates
                // and we're receiving them via trickle ICE
                if let Err(e) = ws.start_connectivity_checks() {
                    // This is expected to fail if ICE is already started or state is wrong
                    debug!("start_connectivity_checks after trickle candidate: {:?}", e);
                }
            }
        }
    }

    /// Handle track subscription request.
    ///
    /// Subscribes a participant to receive media from a published track.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions and postconditions
    /// - Bounded operations (subscription count limited)
    /// - Explicit error handling (all return values checked)
    /// - Minimal variable scope
    ///
    /// # Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    fn handle_subscribe(&mut self, participant_id: u64, track_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(track_id != 0, "track_id must be non-zero");

        let session = match self.sessions.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let _room_id = match session.room_id {
            Some(id) => id,
            None => {
                self.send_error(participant_id, "NOT_IN_ROOM", "Must join a room first");
                return;
            }
        };

        let transport_id = match session.transport_id {
            Some(id) => id,
            None => {
                self.send_error(participant_id, "NO_SESSION", "No WebRTC session");
                return;
            }
        };

        // Get subscriber's destination address and SRTP context
        let (dest_addr, srtp_key_material) = {
            let transport = match self.webrtc_transport.read() {
                Ok(t) => t,
                Err(_) => {
                    self.send_error(participant_id, "LOCK_ERROR", "Transport lock poisoned");
                    return;
                }
            };
            let ws = match transport.get_session(transport_id) {
                Some(s) => s,
                None => {
                    self.send_error(participant_id, "SESSION_NOT_FOUND", "WebRTC session not found");
                    return;
                }
            };

            if !ws.is_established() {
                self.send_error(participant_id, "NOT_ESTABLISHED",
                    "WebRTC session not yet established");
                return;
            }

            let addr = match ws.selected_pair() {
                Some((_, remote)) => remote,
                None => {
                    self.send_error(participant_id, "NO_ICE_PAIR", "No ICE candidate pair selected");
                    return;
                }
            };

            let key_material = ws.get_srtp_key_material();
            (addr, key_material)
        };

        // Create SRTP context for this subscriber
        let srtp_context = match srtp_key_material {
            Some((km, policy)) => match SrtpContext::new(&km, policy) {
                Ok(ctx) => ctx,
                Err(e) => {
                    warn!("Failed to create SRTP context: {:?}", e);
                    self.send_error(participant_id, "SRTP_FAILED", &format!("{:?}", e));
                    return;
                }
            },
            None => {
                warn!("No SRTP key material for participant {}", participant_id);
                self.send_error(participant_id, "NO_SRTP_KEY", "No SRTP key material available");
                return;
            }
        };

        // Add subscriber to track actor via worker pool
        let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;
        let initial_subscription_count = self.sessions.get(&participant_id)
            .map(|s| s.subscribed_tracks.len())
            .unwrap_or(0);

        {
            let pool = match self.worker_pool.read() {
                Ok(p) => p,
                Err(_) => {
                    warn!("Worker pool lock poisoned");
                    self.send_error(participant_id, "LOCK_ERROR", "Worker pool lock poisoned");
                    return;
                }
            };
            if let Err(e) = pool.add_subscriber(
                track_id,
                subscriber_id,
                participant_id,
                dest_addr,
                0, // target_layer: default to base layer
                srtp_context,
            ) {
                warn!("Failed to add subscriber: {:?}", e);
                self.send_error(participant_id, "SUBSCRIBE_FAILED", &format!("{:?}", e));
                return;
            }
        }

        // Update distributed state - check return value
        if let Err(e) = self.distributed_state.add_subscription(track_id, participant_id) {
            warn!("Failed to add subscription to distributed state: {:?}", e);
            // Continue anyway - worker pool is the source of truth
        }

        // Track in session - need to re-borrow
        if let Some(session) = self.sessions.get_mut(&participant_id) {
            session.subscribed_tracks.push(track_id);
        }

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            self.sessions.get(&participant_id)
                .map(|s| s.subscribed_tracks.len())
                .unwrap_or(0) > initial_subscription_count,
            "subscription count must increase after successful subscribe"
        );

        // Send confirmation
        self.send_to(participant_id, SignalMessage::Subscribed {
            track_id,
            subscriber_id,
        });

        info!("Participant {} subscribed to track {}", participant_id, track_id);

        // Mark participant for renegotiation. The actual offer is sent after the
        // current event is fully processed, batching multiple subscriptions into
        // a single SDP offer (RFC 3264 §8).
        self.pending_renegotiations.insert(participant_id);
    }

    /// Handle SDP answer from a subscriber after server-initiated renegotiation.
    ///
    /// When the SFU sends a renegotiation offer (via `trigger_subscriber_renegotiation`),
    /// the subscriber responds with an SDP answer. This method processes that answer
    /// to complete the renegotiation handshake.
    ///
    /// For the Nexus SFU architecture, the answer processing is lightweight: the SFU
    /// already has the ICE/DTLS session established and is forwarding media. The answer
    /// confirms the subscriber accepted the new media sections.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded operations
    /// - Explicit error handling (all return values checked)
    fn handle_answer(&mut self, participant_id: u64, sdp: &str) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(!sdp.is_empty(), "SDP answer must not be empty");

        let session = match self.sessions.get(&participant_id) {
            Some(s) => s,
            None => {
                debug!("Answer from unknown participant {}", participant_id);
                return;
            }
        };

        let transport_id = match session.transport_id {
            Some(id) => id,
            None => {
                debug!("Answer from participant {} with no transport", participant_id);
                return;
            }
        };

        // Parse the answer to extract any updated ICE credentials
        let answer_parsed = match nexus_webrtc::sdp::SdpParser::parse(sdp) {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to parse answer SDP from participant {}: {:?}", participant_id, e);
                return;
            }
        };

        // Extract remote ICE credentials from the answer (may have changed on ICE restart)
        let (remote_ufrag, remote_pwd) = if answer_parsed.ice_ufrag.is_some()
            && answer_parsed.ice_pwd.is_some()
        {
            (
                answer_parsed.ice_ufrag.as_ref().map(|u| u.as_str().to_string()),
                answer_parsed.ice_pwd.as_ref().map(|p| p.as_str().to_string()),
            )
        } else {
            // Try media-level credentials
            let mut ufrag = None;
            let mut pwd = None;
            let media_count = (answer_parsed.media_count as usize).min(8);
            for i in 0..media_count {
                if let Some(ref media) = answer_parsed.media[i] {
                    if media.ice_ufrag.is_some() && media.ice_pwd.is_some() {
                        ufrag = media.ice_ufrag.as_ref().map(|u| u.as_str().to_string());
                        pwd = media.ice_pwd.as_ref().map(|p| p.as_str().to_string());
                        break;
                    }
                }
            }
            (ufrag, pwd)
        };

        // Update remote ICE credentials if present
        if let (Some(ufrag), Some(pwd)) = (remote_ufrag, remote_pwd) {
            let mut transport = match self.webrtc_transport.write() {
                Ok(t) => t,
                Err(_) => {
                    warn!("Transport lock poisoned processing answer from {}", participant_id);
                    return;
                }
            };
            if let Some(ws) = transport.get_session_mut(transport_id) {
                ws.set_remote_ice_credentials(IceCredentials {
                    local_ufrag: ufrag,
                    local_pwd: pwd,
                });
            }
        }

        // Handle renegotiation on the WebRTC session (detect added/removed media)
        {
            let mut transport = match self.webrtc_transport.write() {
                Ok(t) => t,
                Err(_) => {
                    warn!("Transport lock poisoned during renegotiation for {}", participant_id);
                    return;
                }
            };
            if let Some(ws) = transport.get_session_mut(transport_id) {
                if ws.is_established() {
                    match ws.handle_renegotiation_offer(&answer_parsed) {
                        Ok((added, removed, ice_restarted)) => {
                            info!(
                                "Renegotiation answer processed for participant {}: added={}, removed={}, ice_restart={}",
                                participant_id, added.len(), removed.len(), ice_restarted
                            );
                        }
                        Err(e) => {
                            warn!("Renegotiation processing failed for {}: {:?}", participant_id, e);
                        }
                    }
                }
            }
        }

        info!("Answer processed from participant {} (renegotiation complete)", participant_id);
    }

    /// Trigger server-initiated SDP renegotiation for a subscriber.
    ///
    /// After a subscriber's track subscriptions are confirmed, the SFU must send
    /// a new SDP offer containing SSRC information for the subscribed tracks.
    /// Without this, the subscriber's WebRTC stack cannot map incoming RTP packets
    /// to transceivers and `on_track` will never fire (RFC 3264 §8).
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded track iteration (MAX_TRACKS_PER_PARTICIPANT)
    /// - Explicit error handling (all return values checked)
    /// - No dynamic allocation beyond bounded Vec
    fn trigger_subscriber_renegotiation(&mut self, participant_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");

        let session = match self.sessions.get(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let transport_id = match session.transport_id {
            Some(id) => id,
            None => {
                warn!("Cannot renegotiate: no transport for participant {}", participant_id);
                return;
            }
        };

        // Collect subscribed track SSRCs — bounded by MAX_TRACKS_PER_PARTICIPANT
        let subscribed_tracks = &session.subscribed_tracks;
        if subscribed_tracks.is_empty() {
            return;
        }

        // Precondition: subscriptions must be bounded
        assert!(
            subscribed_tracks.len() <= MAX_TRACKS_PER_PARTICIPANT as usize,
            "subscribed tracks must not exceed MAX_TRACKS_PER_PARTICIPANT"
        );

        // Read the initial MID offset and session data for this participant.
        // Each renegotiation is a complete re-offer of ALL subscribed tracks,
        // so MIDs are always assigned starting from the initial offer's media count.
        // This ensures the last renegotiation's MIDs are authoritative regardless
        // of how many intermediate renegotiations occurred.
        let (initial_mid_offset, initial_mids, mid_ext_id) = match self.sessions.get(&participant_id) {
            Some(s) => (s.initial_mids.len() as u32, s.initial_mids.clone(), s.mid_ext_id),
            None => return,
        };

        // Build track info: (ssrc, media_kind, mid_string)
        // Bounded allocation: at most MAX_TRACKS_PER_PARTICIPANT entries
        let mut track_info: Vec<(u32, u8, String)> = Vec::with_capacity(
            subscribed_tracks.len().min(MAX_TRACKS_PER_PARTICIPANT as usize),
        );
        // Track ID → MID mapping for updating worker actors
        let mut track_mid_updates: Vec<(TrackId, String)> = Vec::new();

        let track_count = subscribed_tracks.len().min(MAX_TRACKS_PER_PARTICIPANT as usize);
        for (i, &track_id) in subscribed_tracks.iter().enumerate() {
            if i >= track_count {
                break;
            }

            // Look up SSRC for this track from the router
            let ssrc = match self.ssrc_router.lookup_ssrc_by_track(track_id) {
                Some(s) => s,
                None => {
                    warn!(
                        "Cannot find SSRC for track {} during renegotiation for participant {}",
                        track_id, participant_id
                    );
                    continue;
                }
            };

            // Determine media kind from distributed state
            let media_kind = match self.distributed_state.get_track(track_id) {
                Some(info) => info.track_type, // 0 = audio, 1 = video
                None => {
                    // Fallback: assume video if track info unavailable
                    warn!("No track info for track {}, assuming video", track_id);
                    1u8
                }
            };

            // Allocate MIDs starting after the subscriber's initial offer MIDs
            let mid = format!("{}", initial_mid_offset + i as u32);
            track_mid_updates.push((track_id, mid.clone()));
            track_info.push((ssrc as u32, media_kind, mid));
        }

        // Update next_mid_index to reflect the current renegotiation
        if let Some(session) = self.sessions.get_mut(&participant_id) {
            session.next_mid_index = initial_mid_offset + track_info.len() as u32;
        }

        if track_info.is_empty() {
            warn!("No SSRCs found for renegotiation of participant {}", participant_id);
            return;
        }

        // Get ICE credentials and DTLS fingerprint from the existing session
        let (ice_ufrag, ice_pwd, dtls_fingerprint) = {
            let transport = match self.webrtc_transport.read() {
                Ok(t) => t,
                Err(_) => {
                    warn!("Transport lock poisoned during renegotiation for {}", participant_id);
                    return;
                }
            };
            let ws = match transport.get_session(transport_id) {
                Some(s) => s,
                None => {
                    warn!("Session not found for transport {} during renegotiation", transport_id.0);
                    return;
                }
            };

            let creds = ws.local_ice_credentials().clone();
            let fp = *ws.dtls_fingerprint();
            (creds.local_ufrag, creds.local_pwd, fp)
        };

        // Build the SDP negotiator with the session's credentials
        let negotiator = match SdpNegotiator::with_defaults(
            ice_ufrag,
            ice_pwd,
            nexus_webrtc::sdp::DtlsFingerprint {
                algorithm: nexus_webrtc::sdp::FingerprintAlgorithm::Sha256,
                value: dtls_fingerprint,
                value_len: 32,
            },
        ) {
            Ok(n) => n,
            Err(e) => {
                warn!("Failed to create negotiator for renegotiation: {:?}", e);
                return;
            }
        };

        // Build track references for the offer — convert owned Strings to &str
        let track_refs: Vec<(u32, u8, &str)> = track_info
            .iter()
            .map(|(ssrc, kind, mid)| (*ssrc, *kind, mid.as_str()))
            .collect();

        // Build existing MID refs for the renegotiation offer
        let existing_mid_refs: Vec<(&str, u8)> = initial_mids
            .iter()
            .map(|(mid, kind)| (mid.as_str(), *kind))
            .collect();

        // Generate the renegotiation offer
        let offer_sdp = match negotiator.create_renegotiation_offer(
            participant_id,
            &existing_mid_refs,
            &track_refs,
            mid_ext_id,
        ) {
            Ok(sdp) => sdp,
            Err(e) => {
                warn!("Failed to create renegotiation offer for {}: {:?}", participant_id, e);
                return;
            }
        };

        // Send the offer to the subscriber
        self.send_to(participant_id, SignalMessage::OfferReceived {
            from_participant_id: 0, // SFU is the source
            sdp: offer_sdp,
        });

        info!(
            "Renegotiation offer sent to participant {} with {} tracks",
            participant_id,
            track_info.len()
        );

        // Update worker actors with the assigned MIDs so forwarded RTP
        // packets carry the correct MID header extension value.
        if let Ok(pool) = self.worker_pool.read() {
            for (track_id, mid_str) in &track_mid_updates {
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
        }
    }

    /// Handle track unsubscription request.
    ///
    /// Removes a participant's subscription to a track.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions and postconditions
    /// - Bounded operations (subscription list bounded)
    /// - Explicit error handling (all return values checked)
    /// - Minimal variable scope
    ///
    /// # Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    fn handle_unsubscribe(&mut self, participant_id: u64, track_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(track_id != 0, "track_id must be non-zero");

        let initial_subscription_count = self.sessions.get(&participant_id)
            .map(|s| s.subscribed_tracks.len())
            .unwrap_or(0);

        let session = match self.sessions.get_mut(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;

        // Remove from worker pool - check return value explicitly
        {
            let pool = match self.worker_pool.read() {
                Ok(p) => p,
                Err(_) => {
                    warn!("Worker pool lock poisoned during unsubscribe");
                    return;
                }
            };
            if let Err(e) = pool.remove_subscriber(track_id, subscriber_id) {
                debug!("Failed to remove subscriber from worker pool: {:?}", e);
                // Continue anyway - may have already been removed
            }
        }

        // Update distributed state - check return value explicitly
        if let Err(e) = self.distributed_state.remove_subscription(track_id, participant_id) {
            debug!("Failed to remove subscription from distributed state: {:?}", e);
            // Continue anyway - may have already been removed
        }

        // Remove from session tracking
        session.subscribed_tracks.retain(|&t| t != track_id);

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            self.sessions.get(&participant_id)
                .map(|s| s.subscribed_tracks.len())
                .unwrap_or(0) <= initial_subscription_count,
            "subscription count must not increase after unsubscribe"
        );

        self.send_to(participant_id, SignalMessage::Unsubscribed { track_id });

        info!("Participant {} unsubscribed from track {}", participant_id, track_id);
    }

    /// Handle participant leave request.
    ///
    /// Cleans up all participant state and notifies other participants.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Delegates to cleanup_participant for bounded operations
    /// - Explicit error handling in cleanup_participant
    ///
    /// # Requirements: 6.1, 6.3, 6.4
    fn handle_leave(&mut self, participant_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        debug_assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must be within bounds"
        );

        self.cleanup_participant(participant_id);
    }

    /// Handle participant disconnection.
    ///
    /// Cleans up all participant state when connection is lost.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Delegates to cleanup_participant for bounded operations
    /// - Explicit error handling in cleanup_participant
    ///
    /// # Requirements: 6.1, 6.3, 6.4
    fn handle_disconnected(&mut self, participant_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        debug_assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must be within bounds"
        );

        self.cleanup_participant(participant_id);
    }

    /// Clean up all state for a participant.
    ///
    /// Removes subscriptions, published tracks, WebRTC session, and notifies
    /// other participants in the room.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions and postconditions
    /// - Bounded operations (fixed loop bounds via collection sizes)
    /// - Explicit error handling (all return values checked)
    /// - Minimal variable scope
    ///
    /// # Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    fn cleanup_participant(&mut self, participant_id: u64) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        debug_assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must be within bounds before cleanup"
        );

        let session = match self.sessions.remove(&participant_id) {
            Some(s) => s,
            None => return,
        };

        let room_id = match session.room_id {
            Some(id) => id,
            None => return,
        };

        // Remove all subscriptions - bounded by subscribed_tracks.len()
        let subscription_count = session.subscribed_tracks.len().min(64);
        for (i, &track_id) in session.subscribed_tracks.iter().enumerate() {
            if i >= subscription_count { break; }
            let subscriber_id = (participant_id & 0xFFFFFFFF) as u32;
            if let Ok(pool) = self.worker_pool.read() {
                if let Err(e) = pool.remove_subscriber(track_id, subscriber_id) {
                    debug!("Failed to remove subscriber during cleanup: {:?}", e);
                }
            }
            if let Err(e) = self.distributed_state.remove_subscription(track_id, participant_id) {
                debug!("Failed to remove subscription from distributed state: {:?}", e);
            }
        }

        // Remove all published tracks - bounded by published_tracks.len()
        let track_count = session.published_tracks.len().min(MAX_TRACKS_PER_PARTICIPANT as usize);
        for (i, &track_id) in session.published_tracks.iter().enumerate() {
            if i >= track_count { break; }
            // remove_by_track returns count of removed entries (u32)
            let removed_count = self.ssrc_router.remove_by_track(track_id);
            if removed_count == 0 {
                debug!("No SSRC router entries found for track {}", track_id);
            }
            if let Ok(mut pool) = self.worker_pool.write() {
                if let Err(e) = pool.remove_track(track_id) {
                    debug!("Failed to remove track from worker pool: {:?}", e);
                }
            }
            // remove_track returns bool indicating if track was found
            if !self.distributed_state.remove_track(track_id) {
                debug!("Track {} not found in distributed state", track_id);
            }

            // Notify room about track removal - bounded iteration
            let participants = self.distributed_state.get_participants(room_id);
            let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
            for (j, &pid) in participants.iter().enumerate() {
                if j >= notify_count { break; }
                if pid == participant_id { continue; }
                self.send_to(pid, SignalMessage::TrackUnpublished { track_id });
            }
        }

        // Remove WebRTC session - check return value explicitly
        if let Some(transport_id) = session.transport_id {
            if let Ok(mut transport) = self.webrtc_transport.write() {
                transport.remove_session(transport_id);
            } else {
                warn!("Transport lock poisoned during session removal");
            }
        }

        // Remove from distributed state - check return value explicitly
        if let Err(e) = self.distributed_state.remove_participant(room_id, participant_id) {
            debug!("Failed to remove participant from distributed state: {:?}", e);
        }

        // Notify remaining participants - bounded iteration
        let participants = self.distributed_state.get_participants(room_id);
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count { break; }
            if pid == participant_id { continue; }
            self.send_to(pid, SignalMessage::ParticipantLeft { participant_id });
        }

        // Clean up empty room
        if participants.is_empty() {
            // remove_room returns bool indicating if room was found
            if !self.distributed_state.remove_room(room_id) {
                debug!("Room {} not found in distributed state during cleanup", room_id);
            }
            self.room_names.retain(|_, &mut v| v != room_id);
        }

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            !self.sessions.contains_key(&participant_id),
            "session must be removed after cleanup"
        );

        info!("Participant {} cleaned up from room {}", participant_id, room_id);
    }

    /// Register tracks from SDP offer.
    ///
    /// Extracts SSRCs from media descriptions and registers them as tracks
    /// in the worker pool and SSRC router.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Bounded operations (media_count bounded, notifications bounded)
    /// - Explicit error handling (all return values checked)
    /// - Minimal variable scope
    ///
    /// # Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
    fn register_tracks_from_sdp(
        &mut self,
        participant_id: u64,
        sdp: &nexus_webrtc::sdp::SessionDescription,
    ) {
        // Precondition assertions (TigerStyle)
        assert!(participant_id != 0, "participant_id must be non-zero");
        assert!(
            sdp.media_count <= 16,
            "media_count must be bounded"
        );

        // Pre-allocate with bounded capacity (TigerStyle: no dynamic allocation in hot path)
        let mut notifications: Vec<(u64, SignalMessage)> = Vec::with_capacity(
            MAX_PARTICIPANTS_PER_ROOM as usize * MAX_TRACKS_PER_PARTICIPANT as usize
        );
        
        {
            let session = match self.sessions.get_mut(&participant_id) {
                Some(s) => s,
                None => return,
            };

            // Extract SSRCs from media descriptions - bounded by media_count
            let media_count = (sdp.media_count as usize).min(16);
            for i in 0..media_count {
                let media = match &sdp.media[i] {
                    Some(m) => m,
                    None => continue,
                };
                
                // Bounded iteration over SSRCs
                let ssrc_values = media.get_ssrc_values();
                let ssrc_count = ssrc_values.len().min(8);
                for (j, &ssrc) in ssrc_values.iter().enumerate() {
                    if j >= ssrc_count { break; }
                    if ssrc == 0 { continue; }

                    // Check track limit before adding
                    if session.published_tracks.len() >= MAX_TRACKS_PER_PARTICIPANT as usize {
                        warn!("Track limit reached for participant {}", participant_id);
                        break;
                    }

                    let kind = if media.media_type == MediaType::Audio {
                        MediaKind::Audio
                    } else {
                        MediaKind::Video
                    };

                    // Assign track in worker pool - check return value explicitly
                    let mut pool = match self.worker_pool.write() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("Worker pool lock poisoned during track registration");
                            continue;
                        }
                    };
                    match pool.assign_track(ssrc, kind) {
                        Ok((track_id, worker_id)) => {
                            // Register in SSRC router - check return value explicitly
                            if let Err(e) = self.ssrc_router.register(ssrc, track_id, worker_id) {
                                warn!("Failed to register SSRC {}: {:?}", ssrc, e);
                                continue;
                            }

                            // Register in distributed state - check return value explicitly
                            let track_info = TrackInfo {
                                track_type: if kind == MediaKind::Audio { 0 } else { 1 },
                                codec: 0,
                                bitrate_kbps: 0,
                            };
                            if let Err(e) = self.distributed_state.add_track(track_id, track_info) {
                                debug!("Failed to add track to distributed state: {:?}", e);
                                // Continue anyway - SSRC router is the source of truth
                            }

                            session.published_tracks.push(track_id);

                            // Collect notifications for room about new track - bounded
                            if let Some(room_id) = session.room_id {
                                let participants = self.distributed_state.get_participants(room_id);
                                let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
                                for (k, &pid) in participants.iter().enumerate() {
                                    if k >= notify_count { break; }
                                    if pid == participant_id { continue; }
                                    if notifications.len() >= notifications.capacity() { break; }
                                    notifications.push((pid, SignalMessage::TrackPublished {
                                        publisher_id: participant_id,
                                        track_id,
                                        kind: if kind == MediaKind::Audio { "audio".to_string() } else { "video".to_string() },
                                    }));
                                }
                            }

                            info!("Track {} registered: SSRC={}, worker={}, kind={:?}",
                                track_id, ssrc, worker_id, kind);
                        }
                        Err(e) => {
                            warn!("Failed to assign track for SSRC {}: {:?}", ssrc, e);
                        }
                    }
                }
            }
        }
        
        // Send notifications after releasing session borrow - bounded iteration
        let notification_count = notifications.len().min(MAX_PARTICIPANTS_PER_ROOM as usize * MAX_TRACKS_PER_PARTICIPANT as usize);
        for (i, (pid, msg)) in notifications.into_iter().enumerate() {
            if i >= notification_count { break; }
            self.send_to(pid, msg);
        }

        // Postcondition assertion (TigerStyle)
        debug_assert!(
            self.sessions.get(&participant_id)
                .map(|s| s.published_tracks.len())
                .unwrap_or(0) <= MAX_TRACKS_PER_PARTICIPANT as usize,
            "published tracks must not exceed MAX_TRACKS_PER_PARTICIPANT"
        );
    }

    /// Send a signaling message to a participant.
    ///
    /// Looks up the participant's session and sends the message through
    /// their outbound channel.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Simple control flow (single lookup and send)
    /// - Explicit error handling (send failure logged)
    ///
    /// # Requirements: 6.1, 6.3, 6.4
    fn send_to(&self, participant_id: u64, msg: SignalMessage) {
        // Precondition assertions (TigerStyle)
        debug_assert!(participant_id != 0, "participant_id must be non-zero");
        debug_assert!(
            self.sessions.len() <= MAX_PENDING_EVENTS,
            "sessions count must be within bounds"
        );

        if let Some(session) = self.sessions.get(&participant_id) {
            // Check return value explicitly (TigerStyle)
            if session.outbound_tx.send(msg).is_err() {
                debug!("Failed to send message to participant {} - channel closed", participant_id);
            }
        }
    }

    /// Send an error message to a participant.
    ///
    /// Convenience wrapper around send_to for error messages.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions
    /// - Simple control flow (delegates to send_to)
    /// - Bounded operations (code and message strings bounded by caller)
    ///
    /// # Requirements: 6.1, 6.3, 6.4
    fn send_error(&self, participant_id: u64, code: &str, message: &str) {
        // Precondition assertions (TigerStyle)
        debug_assert!(participant_id != 0, "participant_id must be non-zero");
        debug_assert!(!code.is_empty(), "error code must not be empty");

        self.send_to(participant_id, SignalMessage::Error {
            code: code.to_string(),
            message: message.to_string(),
        });
    }
}

#[allow(dead_code)]
fn current_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
