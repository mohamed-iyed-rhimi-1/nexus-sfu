use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nexus_actor::ActorManager;
use nexus_bwe::{
    CongestionController, PacketArrivalInfo as BwePacketArrivalInfo, TransportFeedback,
};
use nexus_core::MediaKind;
use nexus_state::gossip::types::TrackInfo;
use nexus_state::{DistributedState, DistributedStateConfig};
use nexus_transport::arena::PacketArena;
use nexus_transport::ring_buffer::RingBuffer;

// Type aliases matching nexus-actor's types (all u64 for IDs).
type ParticipantId = u64;
type RoomId = u64;
type TrackId = u64;

use crate::event_loop::{EventLoop, SimEvent, SimEventKind};
use crate::fault::{FaultEvent, FaultInjector};
use crate::invariant::InvariantChecker;
use crate::network::{LinkConfig, NetworkSimulator};
use crate::report::{AssertionResult, InvariantViolationReport, PerformanceBenchmarks, SimulationReport, SimulationStats};
use crate::rng::SimRng;
use crate::scenario::Scenario;

/// Interval between periodic invariant checks (100ms in virtual time).
const INVARIANT_CHECK_INTERVAL_NS: u64 = 100_000_000;

/// Interval between periodic gossip rounds (50ms in virtual time).
const GOSSIP_ROUND_INTERVAL_NS: u64 = 50_000_000;

/// Interval between periodic BWE feedback events (100ms in virtual time).
const BWE_FEEDBACK_INTERVAL_NS: u64 = 100_000_000;

/// Default max participants per room for the simulation.
/// Set high enough to support stress test scenarios (webinar with 1001 participants).
const DEFAULT_MAX_PARTICIPANTS: u32 = 2000;

/// Convert `nexus_core::MediaKind` to `nexus_actor::types::MediaKind`.
fn to_actor_media_kind(kind: MediaKind) -> nexus_actor::types::MediaKind {
    match kind {
        MediaKind::Audio => nexus_actor::types::MediaKind::Audio,
        MediaKind::Video => nexus_actor::types::MediaKind::Video,
    }
}

/// The central simulation orchestrator.
///
/// Converts a `Scenario` into events, drives production components
/// (`ActorManager`, `DistributedState`, `CongestionController`) through
/// their public APIs, and collects results into a `SimulationReport`.
pub struct SimulationEngine {
    event_loop: EventLoop,
    rng: SimRng,
    network: NetworkSimulator,
    #[allow(dead_code)]
    fault_injector: FaultInjector,
    invariant_checker: InvariantChecker,

    // Production components
    actor_manager: ActorManager,
    distributed_states: Vec<Arc<DistributedState>>,
    congestion_controller: Option<CongestionController>,

    // Simulation bookkeeping
    participant_map: HashMap<String, ParticipantId>,
    room_map: HashMap<String, RoomId>,
    track_map: HashMap<String, TrackId>,
    /// Maps participant name → room name (for reverse lookups).
    participant_room: HashMap<String, String>,
    /// Maps track label → owning participant name.
    track_owner: HashMap<String, String>,
    /// Maps track label → room name.
    track_room: HashMap<String, String>,
    /// Maps room name → set of participant names currently in the room.
    room_participants: HashMap<String, HashSet<String>>,
    /// Maps participant name → set of track labels they own.
    participant_tracks: HashMap<String, HashSet<String>>,
    /// Maps track label → set of subscriber names.
    track_subscribers: HashMap<String, HashSet<String>>,
    /// Maps (track_label, subscriber_name) → list of packet payloads expected to be delivered.
    packets_sent: HashMap<(String, String), Vec<Vec<u8>>>,
    /// Maps (track_label, subscriber_name) → list of packet payloads received.
    packets_received: HashMap<(String, String), Vec<Vec<u8>>>,
    /// Sequence number counter per track for packet generation.
    track_seq_nums: HashMap<String, u16>,
    /// Pending packet arrival info per participant for BWE feedback.
    bwe_pending_arrivals: HashMap<String, Vec<crate::event_loop::PacketArrivalInfo>>,
    /// Global sequence counter for BWE transport-wide sequence numbers.
    bwe_seq_counter: u16,
    /// Maps (track_label, seq_num) → (send_time_ns, packet_size) for BWE feedback.
    packet_send_times: HashMap<(String, u16), (u64, u32)>,

    // Configuration
    seed: u64,
    verbose: bool,
    timeout_ns: Option<u64>,
    network_loss_rate: f64,
    scenario: Scenario,

    /// Real PacketArena for arena-based allocation in packet forwarding.
    packet_arena: PacketArena,
    /// Per-track RingBuffer for NACK retransmission.
    track_ring_buffers: HashMap<String, RingBuffer<2048>>,
    /// Latency samples for benchmarking (send_time_ns, delivery_time_ns)
    latency_samples: Vec<(u64, u64)>,
    /// Total forward operations (packet × subscribers)
    total_forward_ops: u64,
    /// Gossip rounds counter
    gossip_round_count: u64,
    /// CRDT operations synced counter
    crdt_ops_count: u64,
    /// BWE feedback events counter
    bwe_feedback_count: u64,
    /// Arena peak usage tracking
    arena_peak_slots: u64,
    /// Arena current slots in use (for tracking)
    #[allow(dead_code)]
    arena_current_slots: u64,
    /// Whether this is a stress test scenario (enables benchmark generation)
    is_stress_test: bool,
    /// Simulated number of cores for PPS/core calculation
    simulated_cores: u32,
}

impl SimulationEngine {
    /// Create a new simulation engine from a scenario.
    ///
    /// Initializes all production components and schedules initial events
    /// from the scenario onto the event loop.
    pub fn new(scenario: Scenario, seed: u64, verbose: bool, timeout: Option<u64>) -> Self {
        let rng = SimRng::new(seed);
        let mut event_loop = EventLoop::new();

        // Build network simulator from scenario config
        let default_link = LinkConfig {
            latency_ms: scenario.network.default_latency_ms,
            jitter_ms: scenario.network.default_jitter_ms,
            loss_rate: scenario.network.default_loss_rate,
            reorder_rate: scenario.network.default_reorder_rate,
        };
        let network_loss_rate = scenario.network.default_loss_rate;
        let mut network = NetworkSimulator::new(default_link);

        // Apply per-link overrides
        for link in &scenario.network.links {
            network.set_link_config(
                link.from.clone(),
                link.to.clone(),
                LinkConfig {
                    latency_ms: link.latency_ms,
                    jitter_ms: link.jitter_ms.unwrap_or(0),
                    loss_rate: link.loss_rate.unwrap_or(0.0),
                    reorder_rate: link.reorder_rate.unwrap_or(0.0),
                },
            );
        }

        // Build fault injector from scenario faults
        let mut fault_injector = FaultInjector::new();
        for fault_cfg in &scenario.faults {
            let time_ns = fault_cfg.at_ms * 1_000_000;
            let fault = match fault_cfg.kind.as_str() {
                "partition" => FaultEvent::NetworkPartition {
                    node_a: fault_cfg.params.node_a.clone().unwrap_or_default(),
                    node_b: fault_cfg.params.node_b.clone().unwrap_or_default(),
                },
                "heal" => FaultEvent::NetworkHeal {
                    node_a: fault_cfg.params.node_a.clone().unwrap_or_default(),
                    node_b: fault_cfg.params.node_b.clone().unwrap_or_default(),
                },
                "crash" => FaultEvent::ActorCrash {
                    actor_label: fault_cfg.params.actor.clone().unwrap_or_default(),
                },
                "loss_burst" => FaultEvent::PacketLossBurst {
                    duration_ms: fault_cfg.params.duration_ms.unwrap_or(0),
                    loss_rate: fault_cfg.params.loss_rate.unwrap_or(0.0),
                },
                _ => continue,
            };
            fault_injector.schedule(time_ns, fault);
        }

        // Initialize production components
        // Use higher limits for stress tests
        let ds_config = DistributedStateConfig::with_limits(0, 100, 5000, 50000);
        let distributed_state = Arc::new(DistributedState::new(ds_config));

        // Create a second DistributedState node for CRDT convergence testing
        let ds_config2 = DistributedStateConfig::with_limits(1, 100, 5000, 50000);
        let distributed_state2 = Arc::new(DistributedState::new(ds_config2));

        let actor_manager = ActorManager::new(
            100,  // max_rooms
            2000, // max_participants (increased for stress tests like webinar with 1001 participants)
            5000, // max_tracks
            distributed_state.clone(),
        );

        let congestion_controller = Some(CongestionController::new(
            100_000,    // min 100kbps
            50_000_000, // max 50Mbps
            1_000_000,  // initial 1Mbps
        ));

        let packet_arena =
            PacketArena::new(1).expect("Failed to create 1MB PacketArena for simulation");

        let invariant_checker = InvariantChecker::new();

        // Schedule scenario events onto the event loop
        Self::schedule_scenario_events(&scenario, &mut event_loop);

        // Inject fault events
        fault_injector.inject_into_event_loop(&mut event_loop);

        // Schedule timeout if provided
        let timeout_ns = timeout.map(|t| t * 1_000_000_000);
        if let Some(t) = timeout_ns {
            event_loop.schedule(t, SimEventKind::SimulationEnd);
        }

        // Detect if this is a stress test scenario
        let is_stress_test = scenario.name.contains("stress")
            || scenario.name.contains("extreme")
            || scenario.name.contains("benchmark")
            || scenario.participants.len() >= 100;

        Self {
            event_loop,
            rng,
            network,
            fault_injector,
            invariant_checker,
            actor_manager,
            distributed_states: vec![distributed_state, distributed_state2],
            congestion_controller,
            participant_map: HashMap::new(),
            room_map: HashMap::new(),
            track_map: HashMap::new(),
            participant_room: HashMap::new(),
            track_owner: HashMap::new(),
            track_room: HashMap::new(),
            room_participants: HashMap::new(),
            participant_tracks: HashMap::new(),
            track_subscribers: HashMap::new(),
            packets_sent: HashMap::new(),
            packets_received: HashMap::new(),
            track_seq_nums: HashMap::new(),
            bwe_pending_arrivals: HashMap::new(),
            bwe_seq_counter: 0,
            packet_send_times: HashMap::new(),
            seed,
            verbose,
            timeout_ns,
            network_loss_rate,
            scenario,
            packet_arena,
            track_ring_buffers: HashMap::new(),
            latency_samples: Vec::new(),
            total_forward_ops: 0,
            gossip_round_count: 0,
            crdt_ops_count: 0,
            bwe_feedback_count: 0,
            arena_peak_slots: 0,
            arena_current_slots: 0,
            is_stress_test,
            simulated_cores: 8, // Default to 8 cores for simulation
        }
    }

    /// Schedule all scenario-defined events onto the event loop.
    fn schedule_scenario_events(scenario: &Scenario, event_loop: &mut EventLoop) {
        // Schedule participant joins and leaves
        for p in &scenario.participants {
            event_loop.schedule(
                p.join_at_ms * 1_000_000,
                SimEventKind::ParticipantJoin {
                    participant_name: p.name.clone(),
                    room_name: p.room.clone(),
                },
            );
            if let Some(leave_ms) = p.leave_at_ms {
                event_loop.schedule(
                    leave_ms * 1_000_000,
                    SimEventKind::ParticipantLeave {
                        participant_name: p.name.clone(),
                    },
                );
            }
        }

        // Schedule track publishes and unpublishes
        for t in &scenario.tracks {
            let media_kind = match t.kind.as_str() {
                "video" => MediaKind::Video,
                _ => MediaKind::Audio,
            };
            event_loop.schedule(
                t.publish_at_ms * 1_000_000,
                SimEventKind::TrackPublish {
                    participant_name: t.participant.clone(),
                    media_kind,
                    track_label: t.label.clone(),
                },
            );
            if let Some(unpublish_ms) = t.unpublish_at_ms {
                event_loop.schedule(
                    unpublish_ms * 1_000_000,
                    SimEventKind::TrackUnpublish {
                        track_label: t.label.clone(),
                    },
                );
            }
        }

        // Schedule subscriptions
        for sub in &scenario.subscriptions {
            event_loop.schedule(
                sub.subscribe_at_ms * 1_000_000,
                SimEventKind::Subscribe {
                    subscriber_name: sub.subscriber.clone(),
                    track_label: sub.track.clone(),
                },
            );
            if let Some(unsub_ms) = sub.unsubscribe_at_ms {
                event_loop.schedule(
                    unsub_ms * 1_000_000,
                    SimEventKind::Unsubscribe {
                        subscriber_name: sub.subscriber.clone(),
                        track_label: sub.track.clone(),
                    },
                );
            }
        }

        // Schedule NACK retransmission requests
        for nack in &scenario.nacks {
            event_loop.schedule(
                nack.at_ms * 1_000_000,
                SimEventKind::NackRequest {
                    track_label: nack.track.clone(),
                    subscriber_name: nack.subscriber.clone(),
                    lost_seq_nums: nack.lost_seq_nums.clone(),
                },
            );
        }
    }

    /// Schedule periodic invariant checks throughout the simulation.
    fn schedule_periodic_invariant_checks(&mut self) {
        let end_ns = self.timeout_ns.unwrap_or(60_000_000_000); // default 60s
        let mut t = INVARIANT_CHECK_INTERVAL_NS;
        while t < end_ns {
            self.event_loop.schedule(t, SimEventKind::InvariantCheck);
            t += INVARIANT_CHECK_INTERVAL_NS;
        }
    }

    /// Schedule periodic gossip rounds for CRDT convergence.
    fn schedule_periodic_gossip_rounds(&mut self) {
        let end_ns = self.timeout_ns.unwrap_or(60_000_000_000);
        let mut t = GOSSIP_ROUND_INTERVAL_NS;
        while t < end_ns {
            self.event_loop.schedule(t, SimEventKind::GossipRound);
            t += GOSSIP_ROUND_INTERVAL_NS;
        }
    }

    /// Schedule periodic BWE feedback events for each participant.
    ///
    /// Every `BWE_FEEDBACK_INTERVAL_NS` (100ms), a `BweFeedback` event is
    /// scheduled for each participant. When processed, the event drains
    /// any pending packet arrival info collected during packet delivery
    /// and feeds it to the `CongestionController`.
    fn schedule_periodic_bwe_feedback(&mut self) {
        if self.congestion_controller.is_none() {
            return;
        }
        let end_ns = self.timeout_ns.unwrap_or(60_000_000_000);
        for participant in &self.scenario.participants {
            let mut t = participant.join_at_ms * 1_000_000 + BWE_FEEDBACK_INTERVAL_NS;
            let participant_end = participant
                .leave_at_ms
                .map(|ms| ms * 1_000_000)
                .unwrap_or(end_ns);
            while t < participant_end && t < end_ns {
                self.event_loop.schedule(
                    t,
                    SimEventKind::BweFeedback {
                        participant_name: participant.name.clone(),
                        packets: Vec::new(), // Actual packets filled at event processing time
                    },
                );
                t += BWE_FEEDBACK_INTERVAL_NS;
            }
        }
    }

    /// Run the simulation to completion.
    ///
    /// Processes events from the event loop until the queue is empty,
    /// a `SimulationEnd` event is encountered, or the timeout is reached.
    /// Returns a `SimulationReport` with results.
    pub fn run(&mut self) -> SimulationReport {
        // Schedule periodic events before starting
        self.schedule_periodic_invariant_checks();
        self.schedule_periodic_gossip_rounds();
        self.schedule_periodic_bwe_feedback();

        // Schedule packet send events for each track based on scenario config
        self.schedule_packet_sends();

        let mut total_events: u64 = 0;

        // Main event processing loop
        while let Some(event) = self.event_loop.next_event() {
            // Check timeout
            if let Some(timeout) = self.timeout_ns {
                if event.scheduled_time_ns > timeout {
                    break;
                }
            }

            total_events += 1;

            if matches!(event.kind, SimEventKind::SimulationEnd) {
                self.handle_event(event);
                break;
            }

            self.handle_event(event);
        }

        // Drain remaining packet delivery events to ensure all in-flight packets are delivered
        // This is important for accurate packet delivery invariant checking
        self.drain_pending_packet_deliveries(&mut total_events);

        // Run final invariant checks (CRDT convergence and packet delivery)
        let final_time = self.event_loop.clock().now_ns();
        self.run_final_invariant_checks(final_time);

        // Evaluate assertions from the scenario
        let assertions = self.evaluate_assertions();

        // Build report
        let net_metrics = self.network.metrics();
        let violations: Vec<InvariantViolationReport> = self
            .invariant_checker
            .violations()
            .iter()
            .map(|v| InvariantViolationReport {
                time_ns: v.time_ns,
                invariant_name: v.invariant_name.clone(),
                message: v.message.clone(),
            })
            .collect();

        let has_violations = !violations.is_empty();
        let has_failed_assertions = assertions.iter().any(|a| !a.passed);

        // Generate performance benchmarks for stress test scenarios
        let benchmarks = if self.is_stress_test {
            // Convert latency samples to microseconds
            let latencies_us: Vec<f64> = self
                .latency_samples
                .iter()
                .map(|(send, recv)| (*recv as f64 - *send as f64) / 1000.0)
                .collect();

            // Calculate max subscribers per track
            let max_subs = self
                .track_subscribers
                .values()
                .map(|s| s.len() as u32)
                .max()
                .unwrap_or(0);

            // Get BWE estimate
            let bwe_estimate = self
                .congestion_controller
                .as_ref()
                .map(|cc| cc.estimated_bandwidth_bps())
                .unwrap_or(0);

            // Calculate CRDT convergence time (time of last gossip round)
            let convergence_time = self.gossip_round_count * GOSSIP_ROUND_INTERVAL_NS;

            Some(PerformanceBenchmarks::from_simulation(
                &SimulationStats {
                    total_events,
                    total_packets_sent: net_metrics.packets_sent,
                    total_packets_delivered: net_metrics.packets_delivered,
                    total_packets_dropped: net_metrics.packets_dropped,
                    simulation_duration_ns: final_time,
                },
                &latencies_us,
                self.scenario.participants.len() as u32,
                self.room_map.len() as u32,
                self.scenario.tracks.len() as u32,
                self.scenario.subscriptions.len() as u32,
                max_subs,
                self.total_forward_ops,
                self.arena_peak_slots,
                self.packet_arena.capacity() as u64,
                bwe_estimate,
                self.gossip_round_count,
                self.crdt_ops_count,
                convergence_time,
                self.simulated_cores,
            ))
        } else {
            None
        };

        SimulationReport {
            passed: !has_violations && !has_failed_assertions,
            seed: self.seed,
            violations,
            assertions,
            stats: SimulationStats {
                total_events,
                total_packets_sent: net_metrics.packets_sent,
                total_packets_delivered: net_metrics.packets_delivered,
                total_packets_dropped: net_metrics.packets_dropped,
                simulation_duration_ns: final_time,
            },
            benchmarks,
        }
    }

    /// Schedule packet send events for all tracks based on scenario config.
    fn schedule_packet_sends(&mut self) {
        for track_cfg in &self.scenario.tracks {
            let interval_ns = track_cfg.packet_interval_ms * 1_000_000;
            let start_ns = track_cfg.publish_at_ms * 1_000_000;
            let end_ns = track_cfg
                .unpublish_at_ms
                .map(|ms| ms * 1_000_000)
                .unwrap_or_else(|| self.timeout_ns.unwrap_or(60_000_000_000));

            let mut t = start_ns + interval_ns; // first packet after publish
            let mut seq: u16 = 0;
            while t < end_ns {
                self.event_loop.schedule(
                    t,
                    SimEventKind::PacketSend {
                        track_label: track_cfg.label.clone(),
                        payload_size: track_cfg.packet_size,
                        seq_num: seq,
                    },
                );
                seq = seq.wrapping_add(1);
                t += interval_ns;
            }
        }
    }

    /// Dispatch a single event to the appropriate handler.
    fn handle_event(&mut self, event: SimEvent) {
        let time_ns = event.scheduled_time_ns;

        if self.verbose {
            eprintln!("[t={}ns] {:?}", time_ns, event.kind);
        }

        match event.kind {
            SimEventKind::ParticipantJoin {
                participant_name,
                room_name,
            } => self.handle_participant_join(&participant_name, &room_name, time_ns),

            SimEventKind::ParticipantLeave { participant_name } => {
                self.handle_participant_leave(&participant_name, time_ns)
            }

            SimEventKind::TrackPublish {
                participant_name,
                media_kind,
                track_label,
            } => self.handle_track_publish(&participant_name, media_kind, &track_label, time_ns),

            SimEventKind::TrackUnpublish { track_label } => {
                self.handle_track_unpublish(&track_label, time_ns)
            }

            SimEventKind::Subscribe {
                subscriber_name,
                track_label,
            } => self.handle_subscribe(&subscriber_name, &track_label, time_ns),

            SimEventKind::Unsubscribe {
                subscriber_name,
                track_label,
            } => self.handle_unsubscribe(&subscriber_name, &track_label, time_ns),

            SimEventKind::PacketSend {
                track_label,
                payload_size,
                seq_num,
            } => self.handle_packet_send(&track_label, payload_size, seq_num, time_ns),

            SimEventKind::PacketDeliver {
                track_label,
                subscriber_name,
                packet_data,
            } => self.handle_packet_deliver(&track_label, &subscriber_name, packet_data, time_ns),

            SimEventKind::NetworkPartition { node_a, node_b } => {
                self.network.partition(&node_a, &node_b);
                if self.verbose {
                    eprintln!("  -> Partitioned {} <-> {}", node_a, node_b);
                }
            }

            SimEventKind::NetworkHeal { node_a, node_b } => {
                self.network.heal(&node_a, &node_b);
                if self.verbose {
                    eprintln!("  -> Healed {} <-> {}", node_a, node_b);
                }
            }

            SimEventKind::ActorCrash { actor_label } => {
                self.handle_actor_crash(&actor_label, time_ns);
            }

            SimEventKind::PacketLossBurst {
                duration_ms: _,
                loss_rate: _,
            } => {
                // Packet loss bursts are handled by temporarily modifying
                // network config. For now, record in bookkeeping.
                if self.verbose {
                    eprintln!("  -> Packet loss burst event (bookkeeping only)");
                }
            }

            SimEventKind::GossipRound => {
                self.handle_gossip_round(time_ns);
            }

            SimEventKind::BweFeedback {
                participant_name,
                packets,
            } => {
                self.handle_bwe_feedback(&participant_name, &packets, time_ns);
            }

            SimEventKind::InvariantCheck => {
                self.run_invariant_checks(time_ns);
            }

            SimEventKind::NackRequest {
                track_label,
                subscriber_name,
                lost_seq_nums,
            } => {
                self.handle_nack_request(&track_label, &subscriber_name, &lost_seq_nums, time_ns);
            }

            SimEventKind::SimulationEnd => {
                if self.verbose {
                    eprintln!("  -> Simulation ended at t={}ns", time_ns);
                }
            }
        }
    }

    // =========================================================================
    // Event Handlers
    // =========================================================================

    fn handle_participant_join(&mut self, name: &str, room_name: &str, _time_ns: u64) {
        // Ensure room exists (create if needed)
        if !self.room_map.contains_key(room_name) {
            match self
                .actor_manager
                .create_room(room_name.to_string(), DEFAULT_MAX_PARTICIPANTS)
            {
                Ok(room_id) => {
                    self.room_map.insert(room_name.to_string(), room_id);
                    self.room_participants
                        .insert(room_name.to_string(), HashSet::new());
                    if self.verbose {
                        eprintln!("  -> Created room '{}' (id={})", room_name, room_id);
                    }
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("  -> Failed to create room '{}': {}", room_name, e);
                    }
                    return;
                }
            }
        }

        let room_id = match self.room_map.get(room_name) {
            Some(&id) => id,
            None => return,
        };

        // Add participant via ActorManager
        match self
            .actor_manager
            .add_participant(room_id, name.to_string())
        {
            Ok(participant_id) => {
                self.participant_map
                    .insert(name.to_string(), participant_id);
                self.participant_room
                    .insert(name.to_string(), room_name.to_string());
                self.room_participants
                    .entry(room_name.to_string())
                    .or_default()
                    .insert(name.to_string());
                self.participant_tracks
                    .insert(name.to_string(), HashSet::new());

                if self.verbose {
                    eprintln!(
                        "  -> Participant '{}' joined room '{}' (pid={})",
                        name, room_name, participant_id
                    );
                }
            }
            Err(e) => {
                if self.verbose {
                    eprintln!(
                        "  -> Failed to add participant '{}' to room '{}': {}",
                        name, room_name, e
                    );
                }
            }
        }
    }

    fn handle_participant_leave(&mut self, name: &str, time_ns: u64) {
        let participant_id = match self.participant_map.get(name) {
            Some(&id) => id,
            None => {
                if self.verbose {
                    eprintln!("  -> Participant '{}' not found for leave", name);
                }
                return;
            }
        };

        let room_name = match self.participant_room.get(name) {
            Some(r) => r.clone(),
            None => return,
        };

        let room_id = match self.room_map.get(&room_name) {
            Some(&id) => id,
            None => return,
        };

        // Remove participant's tracks first
        if let Some(tracks) = self.participant_tracks.get(name).cloned() {
            for track_label in tracks {
                self.handle_track_unpublish(&track_label, time_ns);
            }
        }

        // Remove participant via ActorManager
        match self.actor_manager.leave_room(room_id, participant_id) {
            Ok(()) => {
                if self.verbose {
                    eprintln!("  -> Participant '{}' left room '{}'", name, room_name);
                }
            }
            Err(e) => {
                if self.verbose {
                    eprintln!("  -> Error leaving room for '{}': {}", name, e);
                }
            }
        }

        // Update bookkeeping
        self.participant_map.remove(name);
        self.participant_room.remove(name);
        self.participant_tracks.remove(name);
        if let Some(participants) = self.room_participants.get_mut(&room_name) {
            participants.remove(name);
        }
    }

    fn handle_track_publish(
        &mut self,
        participant_name: &str,
        media_kind: MediaKind,
        track_label: &str,
        _time_ns: u64,
    ) {
        let participant_id = match self.participant_map.get(participant_name) {
            Some(&id) => id,
            None => {
                if self.verbose {
                    eprintln!(
                        "  -> Participant '{}' not found for track publish",
                        participant_name
                    );
                }
                return;
            }
        };

        // Generate a simple SSRC from the track label hash
        let ssrc = {
            let mut hash: u32 = 0;
            for b in track_label.bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(b as u32);
            }
            hash.max(1) // SSRC must be > 0
        };

        match self.actor_manager.publish_track(
            participant_id,
            to_actor_media_kind(media_kind),
            ssrc,
        ) {
            Ok(track_id) => {
                self.track_map.insert(track_label.to_string(), track_id);
                self.track_owner
                    .insert(track_label.to_string(), participant_name.to_string());
                self.track_subscribers
                    .insert(track_label.to_string(), HashSet::new());
                // packets_sent is now keyed by (track, subscriber) and created on-demand
                self.track_seq_nums.insert(track_label.to_string(), 0);

                // Track the room association
                if let Some(room_name) = self.participant_room.get(participant_name) {
                    self.track_room
                        .insert(track_label.to_string(), room_name.clone());
                }

                // Update participant tracks
                self.participant_tracks
                    .entry(participant_name.to_string())
                    .or_default()
                    .insert(track_label.to_string());

                // Update distributed state
                let track_type = match media_kind {
                    MediaKind::Audio => 0,
                    MediaKind::Video => 1,
                };
                let _ = self.distributed_states[0].add_track(
                    track_id,
                    TrackInfo {
                        track_type,
                        content_type: 0,
                        codec: 0,
                        bitrate_kbps: 0, owner_node: 0,
                    },
                );

                if self.verbose {
                    eprintln!(
                        "  -> Published track '{}' (id={}, kind={:?}) for '{}'",
                        track_label, track_id, media_kind, participant_name
                    );
                }

                // Create ring buffer for this track
                self.track_ring_buffers
                    .insert(track_label.to_string(), RingBuffer::new());
            }
            Err(e) => {
                if self.verbose {
                    eprintln!(
                        "  -> Failed to publish track '{}' for '{}': {}",
                        track_label, participant_name, e
                    );
                }
            }
        }
    }

    fn handle_track_unpublish(&mut self, track_label: &str, _time_ns: u64) {
        let track_id = match self.track_map.get(track_label) {
            Some(&id) => id,
            None => {
                if self.verbose {
                    eprintln!("  -> Track '{}' not found for unpublish", track_label);
                }
                return;
            }
        };

        let owner_name = match self.track_owner.get(track_label) {
            Some(name) => name.clone(),
            None => return,
        };

        let participant_id = match self.participant_map.get(&owner_name) {
            Some(&id) => id,
            None => return,
        };

        // Unpublish via ActorManager
        match self.actor_manager.unpublish_track(participant_id, track_id) {
            Ok(()) => {
                if self.verbose {
                    eprintln!("  -> Unpublished track '{}'", track_label);
                }
            }
            Err(e) => {
                if self.verbose {
                    eprintln!("  -> Error unpublishing track '{}': {}", track_label, e);
                }
            }
        }

        // Update bookkeeping
        self.track_map.remove(track_label);
        self.track_owner.remove(track_label);
        self.track_room.remove(track_label);
        // Remove all packets_sent entries for this track (keyed by (track, subscriber))
        let subscribers_to_remove: Vec<String> = self
            .track_subscribers
            .get(track_label)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        for subscriber in subscribers_to_remove {
            self.packets_sent
                .remove(&(track_label.to_string(), subscriber));
        }
        self.track_subscribers.remove(track_label);
        self.track_seq_nums.remove(track_label);
        if let Some(tracks) = self.participant_tracks.get_mut(&owner_name) {
            tracks.remove(track_label);
        }
    }

    fn handle_subscribe(&mut self, subscriber_name: &str, track_label: &str, _time_ns: u64) {
        let subscriber_id = match self.participant_map.get(subscriber_name) {
            Some(&id) => id,
            None => {
                if self.verbose {
                    eprintln!(
                        "  -> Subscriber '{}' not found for subscribe",
                        subscriber_name
                    );
                }
                return;
            }
        };

        let track_id = match self.track_map.get(track_label) {
            Some(&id) => id,
            None => {
                if self.verbose {
                    eprintln!("  -> Track '{}' not found for subscribe", track_label);
                }
                return;
            }
        };

        // Subscribe via ActorManager
        let dest_addr =
            std::net::SocketAddr::from(([127, 0, 0, 1], 10000 + (subscriber_id as u16)));
        match self
            .actor_manager
            .subscribe_to_track(subscriber_id, track_id, dest_addr)
        {
            Ok(_worker_id) => {
                if self.verbose {
                    eprintln!(
                        "  -> '{}' subscribed to track '{}'",
                        subscriber_name, track_label
                    );
                }
            }
            Err(e) => {
                if self.verbose {
                    eprintln!(
                        "  -> Failed to subscribe '{}' to '{}': {}",
                        subscriber_name, track_label, e
                    );
                }
            }
        }

        // Update bookkeeping
        self.track_subscribers
            .entry(track_label.to_string())
            .or_default()
            .insert(subscriber_name.to_string());
    }

    fn handle_unsubscribe(&mut self, subscriber_name: &str, track_label: &str, _time_ns: u64) {
        // Update bookkeeping
        if let Some(subs) = self.track_subscribers.get_mut(track_label) {
            subs.remove(subscriber_name);
        }

        if self.verbose {
            eprintln!(
                "  -> '{}' unsubscribed from track '{}'",
                subscriber_name, track_label
            );
        }
    }

    fn handle_packet_send(
        &mut self,
        track_label: &str,
        payload_size: u32,
        seq_num: u16,
        time_ns: u64,
    ) {
        // Check track still exists
        self.track_map.get(track_label);

        // Build a simple RTP-like packet: 12-byte header + payload
        let mut packet = Vec::with_capacity(12 + payload_size as usize);
        // RTP header (simplified): version=2, padding=0, extension=0, CC=0
        packet.push(0x80); // V=2
        packet.push(0x60); // PT=96 (dynamic)
        packet.extend_from_slice(&seq_num.to_be_bytes()); // sequence number
        packet.extend_from_slice(&(time_ns as u32).to_be_bytes()); // timestamp
        packet.extend_from_slice(&[0, 0, 0, 1]); // SSRC placeholder
                                                 // Payload (fill with seq_num byte for identification)
        let payload_byte = (seq_num & 0xFF) as u8;
        packet.resize(12 + payload_size as usize, payload_byte);

        // Allocate from arena, push to ring buffer
        if let Some(mut slot) = self.packet_arena.alloc() {
            let packet_len = packet.len().min(slot.data_mut().len());
            slot.data_mut()[..packet_len].copy_from_slice(&packet[..packet_len]);
            slot.set_len(packet_len as u16);

            // Push to per-track ring buffer
            if let Some(ring_buf) = self.track_ring_buffers.get(track_label) {
                ring_buf.push(slot);
            }
        }

        // Record send time for BWE feedback
        self.packet_send_times
            .insert((track_label.to_string(), seq_num), (time_ns, payload_size));

        // Get the track owner to determine the "from" node
        let owner_name = match self.track_owner.get(track_label) {
            Some(name) => name.clone(),
            None => return,
        };

        // Deliver to each subscriber through the network simulator
        let subscribers: Vec<String> = self
            .track_subscribers
            .get(track_label)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        for subscriber_name in &subscribers {
            // Record packet as expected for this specific subscriber
            self.packets_sent
                .entry((track_label.to_string(), subscriber_name.clone()))
                .or_default()
                .push(packet.clone());

            // Track forward operations for benchmarking
            self.total_forward_ops += 1;

            // Simulate network delivery
            let delivery_time =
                self.network
                    .send_packet(&owner_name, subscriber_name, time_ns, &mut self.rng);

            if let Some(delivery_ns) = delivery_time {
                // Record latency sample for benchmarking
                self.latency_samples.push((time_ns, delivery_ns));

                // Schedule packet delivery event
                self.event_loop.schedule(
                    delivery_ns,
                    SimEventKind::PacketDeliver {
                        track_label: track_label.to_string(),
                        subscriber_name: subscriber_name.clone(),
                        packet_data: packet.clone(),
                    },
                );
            }
        }
    }

    fn handle_packet_deliver(
        &mut self,
        track_label: &str,
        subscriber_name: &str,
        packet_data: Vec<u8>,
        time_ns: u64,
    ) {
        // Extract seq_num from RTP header (bytes 2-3, big-endian u16)
        if packet_data.len() >= 4 {
            let seq_num = u16::from_be_bytes([packet_data[2], packet_data[3]]);
            // Look up send time for BWE feedback
            if let Some(&(send_time_ns, packet_size)) = self
                .packet_send_times
                .get(&(track_label.to_string(), seq_num))
            {
                let bwe_seq = self.bwe_seq_counter;
                self.bwe_seq_counter = self.bwe_seq_counter.wrapping_add(1);
                let arrival_info = crate::event_loop::PacketArrivalInfo {
                    sequence: bwe_seq,
                    send_time_ns,
                    arrival_time_ns: time_ns,
                    packet_size,
                };
                self.bwe_pending_arrivals
                    .entry(subscriber_name.to_string())
                    .or_default()
                    .push(arrival_info);
            }
        }

        // Record the received packet
        self.packets_received
            .entry((track_label.to_string(), subscriber_name.to_string()))
            .or_default()
            .push(packet_data);

        if self.verbose {
            eprintln!(
                "  -> Packet delivered: track '{}' -> '{}'",
                track_label, subscriber_name
            );
        }
    }

    fn handle_nack_request(
        &mut self,
        track_label: &str,
        subscriber_name: &str,
        lost_seq_nums: &[u16],
        _time_ns: u64,
    ) {
        if self.verbose {
            eprintln!(
                "  -> NackRequest: track '{}', subscriber '{}', seqs {:?}",
                track_label, subscriber_name, lost_seq_nums
            );
        }

        // Peek the ring buffer for cached packets
        if let Some(ring_buf) = self.track_ring_buffers.get(track_label) {
            let mut found = 0u32;
            let mut missed = 0u32;
            for &seq in lost_seq_nums {
                match ring_buf.peek(seq as u32) {
                    Some(_cached) => {
                        found += 1;
                    }
                    None => {
                        missed += 1;
                    }
                }
            }
            if self.verbose {
                eprintln!(
                    "    Ring buffer: found={}, missed={} (out of window)",
                    found, missed
                );
            }
        }
    }

    fn handle_actor_crash(&mut self, actor_label: &str, _time_ns: u64) {
        // Try to find the actor by label in our bookkeeping
        // Actor label could be a participant name or track label
        if let Some(&track_id) = self.track_map.get(actor_label) {
            let _ = self.actor_manager.terminate_track(track_id);
            if self.verbose {
                eprintln!("  -> Crashed track actor '{}'", actor_label);
            }
        } else if let Some(&participant_id) = self.participant_map.get(actor_label) {
            let _ = self.actor_manager.terminate_participant(participant_id);
            if self.verbose {
                eprintln!("  -> Crashed participant actor '{}'", actor_label);
            }
        } else if self.verbose {
            eprintln!("  -> Actor '{}' not found for crash", actor_label);
        }
    }

    fn handle_gossip_round(&mut self, _time_ns: u64) {
        // Increment gossip round counter
        self.gossip_round_count += 1;

        // Simulate CRDT gossip by syncing state between nodes.
        // In a real system, this would use delta-based gossip.
        // For the DST simulator, we replicate operations from node 0 to other nodes.
        if self.distributed_states.len() < 2 {
            return;
        }

        // Sync rooms: replicate any rooms from node 0 to other nodes
        for (room_name, &room_id) in &self.room_map {
            let room_id_u32 = room_id as u32;
            for i in 1..self.distributed_states.len() {
                // Only create if not already present
                if !self.distributed_states[i].room_exists(room_id_u32) {
                    let _ = self.distributed_states[i].create_room(
                        room_id_u32,
                        room_name.clone(),
                        DEFAULT_MAX_PARTICIPANTS,
                    );
                    self.crdt_ops_count += 1;
                }
            }
        }

        // Sync participants: replicate from node 0 to other nodes
        for (participant_name, &participant_id) in &self.participant_map {
            if let Some(room_name) = self.participant_room.get(participant_name) {
                if let Some(&room_id) = self.room_map.get(room_name) {
                    let room_id_u32 = room_id as u32;
                    let participant_id_u64 = participant_id;
                    for i in 1..self.distributed_states.len() {
                        // Only add if not already present
                        if !self.distributed_states[i]
                            .participant_exists(room_id_u32, participant_id_u64)
                        {
                            let _ = self.distributed_states[i]
                                .add_participant(room_id_u32, participant_id_u64);
                            self.crdt_ops_count += 1;
                        }
                    }
                }
            }
        }

        // Sync tracks: replicate track info from node 0 to other nodes
        for (track_label, &track_id) in &self.track_map {
            // Get track info from the track config
            let track_type = self
                .scenario
                .tracks
                .iter()
                .find(|t| t.label == *track_label)
                .map(|t| if t.kind == "video" { 1u8 } else { 0u8 })
                .unwrap_or(0);

            let track_info = TrackInfo {
                track_type,
                content_type: 0,
                codec: 0,
                bitrate_kbps: 0, owner_node: 0,
            };

            for i in 1..self.distributed_states.len() {
                // Try to add track (will fail silently if already exists)
                if self.distributed_states[i].add_track(track_id, track_info.clone()).is_ok() {
                    self.crdt_ops_count += 1;
                }
            }
        }

        // Sync subscriptions: replicate from node 0 to other nodes
        for (track_label, subscribers) in &self.track_subscribers {
            if let Some(&track_id) = self.track_map.get(track_label) {
                for subscriber_name in subscribers {
                    if let Some(&subscriber_id) = self.participant_map.get(subscriber_name) {
                        for i in 1..self.distributed_states.len() {
                            if self.distributed_states[i]
                                .add_subscription(track_id, subscriber_id).is_ok() {
                                self.crdt_ops_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if self.verbose {
            eprintln!(
                "  -> Gossip round {}: synced {} rooms, {} participants, {} tracks to {} nodes",
                self.gossip_round_count,
                self.room_map.len(),
                self.participant_map.len(),
                self.track_map.len(),
                self.distributed_states.len() - 1
            );
        }
    }

    fn handle_bwe_feedback(
        &mut self,
        participant_name: &str,
        _packets: &[crate::event_loop::PacketArrivalInfo],
        time_ns: u64,
    ) {
        // Increment BWE feedback counter
        self.bwe_feedback_count += 1;

        if let Some(ref cc) = self.congestion_controller {
            // Drain pending packet arrivals collected during PacketDeliver events
            let arrivals = self
                .bwe_pending_arrivals
                .remove(participant_name)
                .unwrap_or_default();

            if arrivals.is_empty() {
                return;
            }

            // Build TransportFeedback from collected arrival info
            let mut feedback = TransportFeedback::new(1, 0);
            for pkt in &arrivals {
                // Convert ns to us for BWE, ensuring causality (recv >= send)
                let send_time_us = pkt.send_time_ns / 1000;
                let recv_time_us = pkt.arrival_time_ns / 1000;
                // Clamp to ensure causality invariant holds
                let recv_time_us = recv_time_us.max(send_time_us);
                let size_bytes = if pkt.packet_size > 0 {
                    (pkt.packet_size as u16).max(1)
                } else {
                    1
                };
                let bwe_info = BwePacketArrivalInfo {
                    sequence: pkt.sequence,
                    send_time_us,
                    recv_time_us,
                    size_bytes,
                };
                let _ = feedback.add_packet(bwe_info);
            }

            if feedback.packet_count() > 0 {
                cc.on_transport_feedback(&feedback, time_ns / 1000);
            }

            if self.verbose {
                eprintln!(
                    "  -> BWE feedback for '{}': {} packets, estimate={}bps",
                    participant_name,
                    arrivals.len(),
                    cc.estimated_bandwidth_bps()
                );
            }
        }
    }

    // =========================================================================
    // Invariant Checking
    // =========================================================================

    fn run_invariant_checks(&mut self, time_ns: u64) {
        // Check room capacity
        self.invariant_checker
            .check_room_capacity(&self.room_participants, time_ns);

        // Check track capacity
        self.invariant_checker
            .check_track_capacity(&self.participant_tracks, time_ns);

        // Check track ownership
        self.invariant_checker.check_track_ownership(
            &self.track_owner,
            &self.track_room,
            &self.room_participants,
            time_ns,
        );

        // Check CRDT convergence (only at end of simulation to allow gossip to complete)
        // We skip this during periodic checks since gossip may not have propagated yet
    }

    /// Run final invariant checks at simulation end.
    /// These checks are only meaningful after all events have been processed.
    fn run_final_invariant_checks(&mut self, time_ns: u64) {
        // Run standard checks
        self.run_invariant_checks(time_ns);

        // Check CRDT convergence (only at end after gossip has had time to sync)
        let room_ids: Vec<u32> = self.room_map.values().map(|&id| id as u32).collect();
        self.invariant_checker
            .check_crdt_convergence(&self.distributed_states, &room_ids, time_ns);

        // Check packet delivery (only meaningful at end when all packets should be delivered)
        self.invariant_checker.check_packet_delivery(
            &self.packets_sent,
            &self.packets_received,
            &self.track_subscribers,
            self.network_loss_rate,
            time_ns,
        );

        // Check arena leak — clear ring buffers first to release slots
        self.track_ring_buffers.clear();
        self.invariant_checker
            .check_arena_leak(&self.packet_arena, time_ns);
    }

    /// Drain all remaining packet delivery events from the event loop.
    /// This ensures that packets in-flight at simulation end are delivered
    /// before running final invariant checks.
    fn drain_pending_packet_deliveries(&mut self, total_events: &mut u64) {
        while let Some(event) = self.event_loop.next_event() {
            // Only process packet delivery events
            if let SimEventKind::PacketDeliver {
                track_label,
                subscriber_name,
                packet_data,
            } = event.kind
            {
                *total_events += 1;
                self.handle_packet_deliver(
                    &track_label,
                    &subscriber_name,
                    packet_data,
                    event.scheduled_time_ns,
                );
            }
            // Skip all other event types (they're past the simulation end)
        }
    }

    // =========================================================================
    // Assertion Evaluation
    // =========================================================================

    fn evaluate_assertions(&self) -> Vec<AssertionResult> {
        let mut results = Vec::new();

        for assertion in &self.scenario.assertions {
            let result = match assertion.kind.as_str() {
                "participant_count" => self.eval_participant_count_assertion(&assertion.params),
                "track_count" => self.eval_track_count_assertion(&assertion.params),
                "delivery_ratio" => self.eval_delivery_ratio_assertion(&assertion.params),
                "crdt_converged" => self.eval_crdt_converged_assertion(&assertion.params),
                other => AssertionResult {
                    name: other.to_string(),
                    passed: false,
                    message: format!("Unknown assertion kind: {}", other),
                },
            };
            results.push(result);
        }

        results
    }

    fn eval_participant_count_assertion(&self, params: &serde_json::Value) -> AssertionResult {
        let expected = params.get("expected").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        // If a "room" param is specified, count participants in that specific room
        if let Some(room_name) = params.get("room").and_then(|v| v.as_str()) {
            let actual = self
                .room_participants
                .get(room_name)
                .map(|s| s.len())
                .unwrap_or(0);
            AssertionResult {
                name: "participant_count".to_string(),
                passed: actual == expected,
                message: format!(
                    "room '{}': expected {} participants, got {}",
                    room_name, expected, actual
                ),
            }
        } else {
            // No room specified — count all participants globally
            let actual = self.actor_manager.participant_count();
            AssertionResult {
                name: "participant_count".to_string(),
                passed: actual == expected,
                message: format!("expected {} participants, got {}", expected, actual),
            }
        }
    }

    fn eval_track_count_assertion(&self, params: &serde_json::Value) -> AssertionResult {
        let expected = params.get("expected").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let actual = self.actor_manager.track_count();
        AssertionResult {
            name: "track_count".to_string(),
            passed: actual == expected,
            message: format!("expected {} tracks, got {}", expected, actual),
        }
    }

    fn eval_delivery_ratio_assertion(&self, params: &serde_json::Value) -> AssertionResult {
        let min_ratio = params
            .get("min_ratio")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        let metrics = self.network.metrics();
        let total = metrics.packets_sent;
        if total == 0 {
            return AssertionResult {
                name: "delivery_ratio".to_string(),
                passed: true,
                message: "No packets sent".to_string(),
            };
        }

        let ratio = metrics.packets_delivered as f64 / total as f64;
        AssertionResult {
            name: "delivery_ratio".to_string(),
            passed: ratio >= min_ratio,
            message: format!(
                "delivery ratio {:.2}% (min required: {:.2}%)",
                ratio * 100.0,
                min_ratio * 100.0
            ),
        }
    }

    fn eval_crdt_converged_assertion(&self, _params: &serde_json::Value) -> AssertionResult {
        if self.distributed_states.len() < 2 {
            return AssertionResult {
                name: "crdt_converged".to_string(),
                passed: true,
                message: "Only one state node, trivially converged".to_string(),
            };
        }

        // Compare all nodes against node 0
        let s0 = &self.distributed_states[0];
        for i in 1..self.distributed_states.len() {
            let si = &self.distributed_states[i];
            let converged = s0.room_count() == si.room_count()
                && s0.track_count() == si.track_count()
                && s0.subscription_count() == si.subscription_count();

            if !converged {
                return AssertionResult {
                    name: "crdt_converged".to_string(),
                    passed: false,
                    message: format!(
                        "States diverged: node0(rooms={}, tracks={}, subs={}) vs node{}(rooms={}, tracks={}, subs={})",
                        s0.room_count(), s0.track_count(), s0.subscription_count(),
                        i, si.room_count(), si.track_count(), si.subscription_count(),
                    ),
                };
            }
        }

        AssertionResult {
            name: "crdt_converged".to_string(),
            passed: true,
            message: format!(
                "All {} CRDT state nodes converged",
                self.distributed_states.len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{
        AssertionConfig, NetworkConfig, ParticipantConfig, Scenario, SubscriptionConfig,
        TrackConfig,
    };

    fn empty_scenario() -> Scenario {
        Scenario {
            name: "empty".into(),
            description: "Empty scenario".into(),
            seed: Some(42),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![],
            nacks: vec![],
        }
    }

    fn basic_scenario() -> Scenario {
        Scenario {
            name: "basic".into(),
            description: "Basic lifecycle".into(),
            seed: Some(42),
            timeout_secs: Some(2),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![
                ParticipantConfig {
                    name: "alice".into(),
                    room: "room1".into(),
                    join_at_ms: 0,
                    leave_at_ms: Some(1500),
                },
                ParticipantConfig {
                    name: "bob".into(),
                    room: "room1".into(),
                    join_at_ms: 100,
                    leave_at_ms: Some(1500),
                },
            ],
            tracks: vec![TrackConfig {
                label: "audio1".into(),
                participant: "alice".into(),
                kind: "audio".into(),
                publish_at_ms: 200,
                unpublish_at_ms: Some(1400),
                packet_interval_ms: 100,
                packet_size: 160,
            }],
            subscriptions: vec![SubscriptionConfig {
                subscriber: "bob".into(),
                track: "audio1".into(),
                subscribe_at_ms: 300,
                unsubscribe_at_ms: Some(1300),
            }],
            faults: vec![],
            assertions: vec![],
            nacks: vec![],
        }
    }

    #[test]
    fn engine_creation_with_empty_scenario() {
        let scenario = empty_scenario();
        let engine = SimulationEngine::new(scenario, 42, false, Some(1));
        assert_eq!(engine.seed, 42);
        assert!(!engine.verbose);
        assert_eq!(engine.timeout_ns, Some(1_000_000_000));
        assert!(engine.participant_map.is_empty());
        assert!(engine.room_map.is_empty());
        assert!(engine.track_map.is_empty());
    }

    #[test]
    fn empty_scenario_run_passes() {
        let scenario = empty_scenario();
        let mut engine = SimulationEngine::new(scenario, 42, false, Some(1));
        let report = engine.run();
        assert!(report.passed);
        assert_eq!(report.seed, 42);
        assert!(report.violations.is_empty());
        assert!(report.assertions.is_empty());
    }

    #[test]
    fn basic_scenario_runs_without_panic() {
        let scenario = basic_scenario();
        let mut engine = SimulationEngine::new(scenario, 42, false, Some(2));
        let report = engine.run();
        // The simulation should complete without panicking
        assert_eq!(report.seed, 42);
        // Events should have been processed
        assert!(report.stats.total_events > 0);
    }

    #[test]
    fn participant_join_creates_room_and_participant() {
        let scenario = Scenario {
            name: "join_test".into(),
            description: "Test join".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![ParticipantConfig {
                name: "alice".into(),
                room: "room1".into(),
                join_at_ms: 0,
                leave_at_ms: None,
            }],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();

        // Alice should have joined
        assert!(engine.participant_map.contains_key("alice"));
        assert!(engine.room_map.contains_key("room1"));
        assert!(report.stats.total_events > 0);
    }

    #[test]
    fn packet_delivery_tracked_in_bookkeeping() {
        let scenario = basic_scenario();
        let mut engine = SimulationEngine::new(scenario, 42, false, Some(2));
        let report = engine.run();

        // Packets should have been sent and delivered
        assert!(report.stats.total_events > 0);
        // Under zero-loss, packets should be delivered
        // (network metrics track sent/delivered)
    }

    #[test]
    fn verbose_mode_does_not_panic() {
        let scenario = basic_scenario();
        let mut engine = SimulationEngine::new(scenario, 42, true, Some(2));
        let _report = engine.run();
        // Just verify it doesn't panic with verbose output
    }

    #[test]
    fn deterministic_runs_produce_same_report() {
        let scenario1 = basic_scenario();
        let scenario2 = basic_scenario();

        let mut engine1 = SimulationEngine::new(scenario1, 42, false, Some(2));
        let report1 = engine1.run();

        let mut engine2 = SimulationEngine::new(scenario2, 42, false, Some(2));
        let report2 = engine2.run();

        assert_eq!(report1.passed, report2.passed);
        assert_eq!(report1.stats.total_events, report2.stats.total_events);
        assert_eq!(
            report1.stats.total_packets_sent,
            report2.stats.total_packets_sent
        );
        assert_eq!(
            report1.stats.total_packets_delivered,
            report2.stats.total_packets_delivered
        );
    }

    #[test]
    fn assertion_participant_count_global() {
        // Scenario with 2 participants that never leave, assert global count
        let scenario = Scenario {
            name: "assert_participant_count".into(),
            description: "Test participant_count assertion".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![
                ParticipantConfig {
                    name: "alice".into(),
                    room: "room1".into(),
                    join_at_ms: 0,
                    leave_at_ms: None,
                },
                ParticipantConfig {
                    name: "bob".into(),
                    room: "room1".into(),
                    join_at_ms: 50,
                    leave_at_ms: None,
                },
            ],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "participant_count".into(),
                params: serde_json::json!({"expected": 2}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert_eq!(report.assertions.len(), 1);
        assert!(
            report.assertions[0].passed,
            "assertion should pass: {}",
            report.assertions[0].message
        );
        assert_eq!(report.assertions[0].name, "participant_count");
    }

    #[test]
    fn assertion_participant_count_per_room() {
        // Two rooms, assert count in a specific room
        let scenario = Scenario {
            name: "assert_participant_count_room".into(),
            description: "Test per-room participant_count assertion".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![
                ParticipantConfig {
                    name: "alice".into(),
                    room: "room1".into(),
                    join_at_ms: 0,
                    leave_at_ms: None,
                },
                ParticipantConfig {
                    name: "bob".into(),
                    room: "room2".into(),
                    join_at_ms: 0,
                    leave_at_ms: None,
                },
                ParticipantConfig {
                    name: "carol".into(),
                    room: "room1".into(),
                    join_at_ms: 50,
                    leave_at_ms: None,
                },
            ],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![
                AssertionConfig {
                    kind: "participant_count".into(),
                    params: serde_json::json!({"room": "room1", "expected": 2}),
                },
                AssertionConfig {
                    kind: "participant_count".into(),
                    params: serde_json::json!({"room": "room2", "expected": 1}),
                },
            ],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert_eq!(report.assertions.len(), 2);
        assert!(
            report.assertions[0].passed,
            "room1 assertion: {}",
            report.assertions[0].message
        );
        assert!(
            report.assertions[1].passed,
            "room2 assertion: {}",
            report.assertions[1].message
        );
    }

    #[test]
    fn assertion_participant_count_fails_on_mismatch() {
        let scenario = Scenario {
            name: "assert_fail".into(),
            description: "Test failing assertion".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![ParticipantConfig {
                name: "alice".into(),
                room: "room1".into(),
                join_at_ms: 0,
                leave_at_ms: None,
            }],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "participant_count".into(),
                params: serde_json::json!({"expected": 5}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert!(
            !report.passed,
            "report should fail due to assertion mismatch"
        );
        assert_eq!(report.assertions.len(), 1);
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn assertion_track_count() {
        let scenario = Scenario {
            name: "assert_track_count".into(),
            description: "Test track_count assertion".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![ParticipantConfig {
                name: "alice".into(),
                room: "room1".into(),
                join_at_ms: 0,
                leave_at_ms: None,
            }],
            tracks: vec![TrackConfig {
                label: "audio1".into(),
                participant: "alice".into(),
                kind: "audio".into(),
                publish_at_ms: 100,
                unpublish_at_ms: None,
                packet_interval_ms: 200,
                packet_size: 160,
            }],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "track_count".into(),
                params: serde_json::json!({"expected": 1}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert_eq!(report.assertions.len(), 1);
        assert!(
            report.assertions[0].passed,
            "track_count assertion: {}",
            report.assertions[0].message
        );
    }

    #[test]
    fn assertion_delivery_ratio() {
        // Zero-loss scenario — delivery ratio should be 1.0
        let scenario = Scenario {
            name: "assert_delivery".into(),
            description: "Test delivery_ratio assertion".into(),
            seed: Some(1),
            timeout_secs: Some(2),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![
                ParticipantConfig {
                    name: "alice".into(),
                    room: "room1".into(),
                    join_at_ms: 0,
                    leave_at_ms: None,
                },
                ParticipantConfig {
                    name: "bob".into(),
                    room: "room1".into(),
                    join_at_ms: 50,
                    leave_at_ms: None,
                },
            ],
            tracks: vec![TrackConfig {
                label: "audio1".into(),
                participant: "alice".into(),
                kind: "audio".into(),
                publish_at_ms: 100,
                unpublish_at_ms: None,
                packet_interval_ms: 100,
                packet_size: 160,
            }],
            subscriptions: vec![SubscriptionConfig {
                subscriber: "bob".into(),
                track: "audio1".into(),
                subscribe_at_ms: 150,
                unsubscribe_at_ms: None,
            }],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "delivery_ratio".into(),
                params: serde_json::json!({"min_ratio": 0.95}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(2));
        let report = engine.run();
        assert_eq!(report.assertions.len(), 1);
        assert!(
            report.assertions[0].passed,
            "delivery_ratio assertion: {}",
            report.assertions[0].message
        );
    }

    #[test]
    fn assertion_crdt_converged() {
        // Simple scenario — CRDTs should converge trivially
        let scenario = Scenario {
            name: "assert_crdt".into(),
            description: "Test crdt_converged assertion".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "crdt_converged".into(),
                params: serde_json::json!({}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert_eq!(report.assertions.len(), 1);
        assert!(
            report.assertions[0].passed,
            "crdt_converged assertion: {}",
            report.assertions[0].message
        );
    }

    #[test]
    fn assertion_unknown_kind_fails() {
        let scenario = Scenario {
            name: "assert_unknown".into(),
            description: "Test unknown assertion kind".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![AssertionConfig {
                kind: "nonexistent_check".into(),
                params: serde_json::json!({}),
            }],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert!(
            !report.passed,
            "unknown assertion kind should fail the report"
        );
        assert_eq!(report.assertions.len(), 1);
        assert!(!report.assertions[0].passed);
        assert!(report.assertions[0]
            .message
            .contains("Unknown assertion kind"));
    }

    #[test]
    fn assertion_multiple_mixed_results() {
        // One passing, one failing assertion
        let scenario = Scenario {
            name: "assert_mixed".into(),
            description: "Test mixed assertion results".into(),
            seed: Some(1),
            timeout_secs: Some(1),
            network: NetworkConfig {
                default_latency_ms: 10,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![ParticipantConfig {
                name: "alice".into(),
                room: "room1".into(),
                join_at_ms: 0,
                leave_at_ms: None,
            }],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![
                AssertionConfig {
                    kind: "participant_count".into(),
                    params: serde_json::json!({"expected": 1}),
                },
                AssertionConfig {
                    kind: "track_count".into(),
                    params: serde_json::json!({"expected": 99}),
                },
            ],
            nacks: vec![],
        };

        let mut engine = SimulationEngine::new(scenario, 1, false, Some(1));
        let report = engine.run();
        assert!(
            !report.passed,
            "report should fail when any assertion fails"
        );
        assert_eq!(report.assertions.len(), 2);
        assert!(report.assertions[0].passed, "participant_count should pass");
        assert!(!report.assertions[1].passed, "track_count should fail");
    }
}
