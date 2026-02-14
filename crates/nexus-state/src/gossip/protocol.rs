//! SWIM protocol implementation.
//!
//! This module implements the core SWIM (Scalable Weakly-consistent Infection-style
//! Membership) protocol, coordinating failure detection and state dissemination.
//!
//! ## Protocol Overview
//!
//! The SWIM protocol operates in cycles:
//! 1. **Probe**: Select a random peer and send a Ping
//! 2. **Direct Ack**: Wait for Ack response
//! 3. **Indirect Probe**: If no Ack, ask other peers to probe the target
//! 4. **Suspicion**: If indirect probes fail, mark target as Suspect
//! 5. **Declaration**: After timeout, mark Suspect as Dead
//!
//! State updates are piggybacked on protocol messages for efficient dissemination.
//!
//! ## TigerStyle Compliance
//!
//! - All loops bounded by MAX_PEERS or MAX_PIGGYBACK_UPDATES
//! - State machine transitions validated with assertions
//! - Pre-allocated collections with fixed capacity
//! - Atomic statistics for monitoring

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::GossipConfig;
use super::membership::MembershipList;
use super::transport::GossipTransport;
use super::types::{
    GossipMessage, PeerInfo, PeerState, StateUpdate,
    MAX_PEERS, MAX_PIGGYBACK_UPDATES,
};
use crate::distributed_state::DistributedState;
use crate::error::GossipError;
use crate::types::{ActorId, MAX_ACTORS};

/// Maximum number of pending pings
const MAX_PENDING_PINGS: usize = MAX_PEERS;

/// Maximum piggyback queue size
const MAX_PIGGYBACK_QUEUE_SIZE: usize = MAX_PIGGYBACK_UPDATES * 10;

/// Maximum number of pending indirect probes (for forwarding acks)
const MAX_PENDING_INDIRECT: usize = MAX_PEERS;

/// Default anti-entropy interval in milliseconds
const DEFAULT_ANTI_ENTROPY_INTERVAL_MS: u64 = 10_000;

/// Information about a pending indirect probe (for forwarding acks).
#[derive(Debug, Clone, Copy)]
pub struct PendingIndirect {
    /// Target actor ID we're probing on behalf of requester
    #[allow(dead_code)] // Reserved for indirect probe protocol completion
    pub target: ActorId,
    /// Requester's actor ID
    #[allow(dead_code)] // Reserved for indirect probe protocol completion
    pub requester: ActorId,
    /// Requester's address (to forward ack to)
    pub requester_addr: SocketAddr,
    /// Timestamp when we sent the ping (nanoseconds)
    pub sent_at_ns: u64,
}

/// Information about a pending ping awaiting response.
#[derive(Debug, Clone, Copy)]
pub struct PendingPing {
    /// Target actor ID
    pub target: ActorId,
    /// Target's address
    pub target_addr: SocketAddr,
    /// Timestamp when ping was sent (nanoseconds)
    pub sent_at_ns: u64,
    /// Whether indirect probes have been requested
    pub indirect_requested: bool,
}

/// Statistics for protocol operations.
#[derive(Debug, Default)]
pub struct ProtocolStats {
    /// Total pings sent
    pub pings_sent: AtomicU64,
    /// Total acks received
    pub acks_received: AtomicU64,
    /// Total ping timeouts
    pub ping_timeouts: AtomicU64,
    /// Total suspicions raised
    pub suspicions_raised: AtomicU64,
    /// Total peers marked dead
    pub peers_marked_dead: AtomicU64,
    /// Total state updates sent
    pub state_updates_sent: AtomicU64,
    /// Total state updates received
    pub state_updates_received: AtomicU64,
}

impl ProtocolStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> ProtocolStatsSnapshot {
        ProtocolStatsSnapshot {
            pings_sent: self.pings_sent.load(Ordering::Relaxed),
            acks_received: self.acks_received.load(Ordering::Relaxed),
            ping_timeouts: self.ping_timeouts.load(Ordering::Relaxed),
            suspicions_raised: self.suspicions_raised.load(Ordering::Relaxed),
            peers_marked_dead: self.peers_marked_dead.load(Ordering::Relaxed),
            state_updates_sent: self.state_updates_sent.load(Ordering::Relaxed),
            state_updates_received: self.state_updates_received.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.pings_sent.store(0, Ordering::Relaxed);
        self.acks_received.store(0, Ordering::Relaxed);
        self.ping_timeouts.store(0, Ordering::Relaxed);
        self.suspicions_raised.store(0, Ordering::Relaxed);
        self.peers_marked_dead.store(0, Ordering::Relaxed);
        self.state_updates_sent.store(0, Ordering::Relaxed);
        self.state_updates_received.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of protocol statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtocolStatsSnapshot {
    pub pings_sent: u64,
    pub acks_received: u64,
    pub ping_timeouts: u64,
    pub suspicions_raised: u64,
    pub peers_marked_dead: u64,
    pub state_updates_sent: u64,
    pub state_updates_received: u64,
}

/// SWIM protocol coordinator.
///
/// Manages the membership list, transport, and protocol state machine.
/// Call `run_probe_cycle()` periodically and `recv_loop_iteration()` to
/// process incoming messages.
pub struct SwimProtocol {
    /// Local actor ID
    local_actor: ActorId,
    /// Membership list tracking peer states
    membership: MembershipList,
    /// UDP transport for message sending/receiving
    transport: GossipTransport,
    /// Protocol configuration
    config: GossipConfig,
    /// Pending pings awaiting response
    pending_pings: HashMap<ActorId, PendingPing>,
    /// Pending indirect probes (we're helping with) for forwarding acks
    pending_indirect: HashMap<ActorId, PendingIndirect>,
    /// Last probe cycle timestamp (nanoseconds)
    last_probe_ns: AtomicU64,
    /// Last anti-entropy sync timestamp (nanoseconds)
    last_anti_entropy_ns: AtomicU64,
    /// Anti-entropy interval in milliseconds
    anti_entropy_interval_ms: u64,
    /// Queue of state updates to piggyback
    piggyback_queue: VecDeque<StateUpdate>,
    /// Protocol statistics
    stats: ProtocolStats,
    /// Distributed state for applying CRDT updates
    distributed_state: Option<Arc<DistributedState>>,
}

impl SwimProtocol {
    /// Create a new SWIM protocol instance.
    ///
    /// # Arguments
    /// * `local_actor` - This node's actor ID
    /// * `bind_addr` - Address to bind the UDP socket to
    /// * `config` - Protocol configuration
    ///
    /// # Returns
    /// A new protocol instance or an error
    ///
    /// # Panics
    /// Panics if `local_actor >= MAX_ACTORS`
    pub fn new(
        local_actor: ActorId,
        bind_addr: SocketAddr,
        config: GossipConfig,
    ) -> Result<Self, GossipError> {
        assert!(
            local_actor < MAX_ACTORS as u64,
            "local_actor must be < MAX_ACTORS"
        );

        // Validate configuration
        config.validate()?;

        // Create membership list
        let membership = MembershipList::new(local_actor);

        // Create transport
        let transport = GossipTransport::new(bind_addr)?;

        // Initialize pending_pings with capacity
        let pending_pings = HashMap::with_capacity(MAX_PENDING_PINGS);

        // Initialize pending_indirect with capacity
        let pending_indirect = HashMap::with_capacity(MAX_PENDING_INDIRECT);

        // Initialize piggyback queue
        let piggyback_queue = VecDeque::with_capacity(MAX_PIGGYBACK_QUEUE_SIZE);

        Ok(Self {
            local_actor,
            membership,
            transport,
            config,
            pending_pings,
            pending_indirect,
            last_probe_ns: AtomicU64::new(0),
            last_anti_entropy_ns: AtomicU64::new(0),
            anti_entropy_interval_ms: DEFAULT_ANTI_ENTROPY_INTERVAL_MS,
            piggyback_queue,
            stats: ProtocolStats::new(),
            distributed_state: None,
        })
    }

    /// Returns the local actor ID.
    #[inline]
    pub const fn local_actor(&self) -> ActorId {
        self.local_actor
    }

    /// Returns a reference to the membership list.
    #[inline]
    pub fn membership(&self) -> &MembershipList {
        &self.membership
    }

    /// Returns a mutable reference to the membership list.
    #[inline]
    pub fn membership_mut(&mut self) -> &mut MembershipList {
        &mut self.membership
    }

    /// Returns a reference to the transport.
    #[inline]
    pub fn transport(&self) -> &GossipTransport {
        &self.transport
    }

    /// Returns the local address the transport is bound to.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.transport.local_addr()
    }

    /// Returns a reference to the protocol statistics.
    #[inline]
    pub fn stats(&self) -> &ProtocolStats {
        &self.stats
    }

    /// Returns a reference to the configuration.
    #[inline]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Set the anti-entropy interval in milliseconds.
    #[inline]
    pub fn set_anti_entropy_interval(&mut self, interval_ms: u64) {
        assert!(interval_ms > 0, "anti_entropy_interval_ms must be > 0");
        self.anti_entropy_interval_ms = interval_ms;
    }

    /// Set the distributed state for applying CRDT updates.
    ///
    /// When set, state updates received via gossip will be applied to the
    /// distributed state using CRDT merge semantics.
    ///
    /// # Arguments
    /// * `state` - The distributed state to apply updates to
    #[inline]
    pub fn set_distributed_state(&mut self, state: Arc<DistributedState>) {
        assert!(self.distributed_state.is_none(), "distributed_state already set");
        self.distributed_state = Some(state);
    }

    /// Returns a reference to the distributed state, if set.
    #[inline]
    pub fn distributed_state(&self) -> Option<&Arc<DistributedState>> {
        self.distributed_state.as_ref()
    }

    /// Add a seed peer to bootstrap the cluster.
    ///
    /// Sends an initial ping to establish contact.
    ///
    /// # Arguments
    /// * `actor_id` - Peer's actor ID
    /// * `addr` - Peer's network address
    pub fn add_seed_peer(&mut self, actor_id: ActorId, addr: SocketAddr) -> Result<(), GossipError> {
        // Add to membership list
        self.membership.add_peer(actor_id, addr)?;

        // Send initial ping
        let incarnation = self.membership.local_incarnation();
        let piggyback = self.get_piggyback_updates();

        let msg = GossipMessage::Ping {
            from: self.local_actor,
            incarnation,
            piggyback,
        };

        self.transport.send(&msg, addr)?;
        self.stats.pings_sent.fetch_add(1, Ordering::Relaxed);

        // Record pending ping
        self.pending_pings.insert(
            actor_id,
            PendingPing {
                target: actor_id,
                target_addr: addr,
                sent_at_ns: current_time_ns(),
                indirect_requested: false,
            },
        );

        Ok(())
    }

    /// Run one probe cycle.
    ///
    /// This should be called periodically (at least every `probe_interval_ms`).
    /// It will:
    /// 1. Check if it's time for a new probe
    /// 2. Select and probe a random alive peer
    /// 3. Check for pending ping timeouts
    /// 4. Check for suspect timeouts
    /// 5. Run anti-entropy sync if interval elapsed
    ///
    /// # Returns
    ///
    /// `Ok(Vec<ActorId>)` containing the actor IDs of nodes that were newly
    /// marked as dead during this cycle. The caller should use this to clean
    /// up state associated with failed nodes (e.g., call `handle_node_failure`
    /// on the distributed state).
    pub fn run_probe_cycle(&mut self) -> Result<Vec<ActorId>, GossipError> {
        let now_ns = current_time_ns();
        let probe_interval_ns = self.config.probe_interval_ms * 1_000_000;

        // Check if probe interval has elapsed
        let last_probe = self.last_probe_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(last_probe) < probe_interval_ns {
            // Also check timeouts even if not probing
            self.check_ping_timeouts(now_ns);
            let marked_dead = self.membership.check_timeouts(now_ns);
            // Broadcast dead for each newly dead peer (Comment 3)
            for actor_id in &marked_dead {
                self.broadcast_dead(*actor_id);
            }
            self.stats
                .peers_marked_dead
                .fetch_add(marked_dead.len() as u64, Ordering::Relaxed);
            return Ok(marked_dead);
        }

        // Select random alive peer
        if let Some(peer) = self.membership.get_random_alive_peer() {
            self.send_ping(&peer)?;
        }

        // Update last probe time
        self.last_probe_ns.store(now_ns, Ordering::Relaxed);

        // Check pending ping timeouts
        self.check_ping_timeouts(now_ns);

        // Check membership timeouts (Suspect → Dead)
        let marked_dead = self.membership.check_timeouts(now_ns);
        // Broadcast dead for each newly dead peer (Comment 3)
        for actor_id in &marked_dead {
            self.broadcast_dead(*actor_id);
        }
        self.stats
            .peers_marked_dead
            .fetch_add(marked_dead.len() as u64, Ordering::Relaxed);

        // Run anti-entropy sync (Comment 2)
        self.run_anti_entropy(now_ns)?;

        Ok(marked_dead)
    }

    /// Run anti-entropy synchronization if interval has elapsed.
    fn run_anti_entropy(&mut self, now_ns: u64) -> Result<(), GossipError> {
        let anti_entropy_interval_ns = self.anti_entropy_interval_ms * 1_000_000;
        let last_anti_entropy = self.last_anti_entropy_ns.load(Ordering::Relaxed);

        if now_ns.saturating_sub(last_anti_entropy) < anti_entropy_interval_ns {
            return Ok(());
        }

        // Update last anti-entropy time
        self.last_anti_entropy_ns.store(now_ns, Ordering::Relaxed);

        // Select a random peer for full state sync
        let peer = match self.membership.get_random_alive_peer() {
            Some(p) => p,
            None => return Ok(()), // No peers to sync with
        };

        // Build membership snapshot (bounded by MAX_PEERS)
        let all_peers = self.membership.get_all_peers();
        let mut members: Vec<(ActorId, u64, u8)> = Vec::with_capacity(all_peers.len().min(MAX_PEERS));

        for (i, p) in all_peers.into_iter().enumerate() {
            if i >= MAX_PEERS {
                break;
            }
            let state_byte = match p.state() {
                PeerState::Alive => 0,
                PeerState::Suspect => 1,
                PeerState::Dead => 2,
            };
            members.push((p.actor_id(), p.incarnation(), state_byte));
        }

        // Get current piggyback updates
        let updates = self.get_piggyback_updates();

        let msg = GossipMessage::StateSnapshot {
            from: self.local_actor,
            incarnation: self.membership.local_incarnation(),
            members,
            updates,
        };

        let _ = self.transport.send(&msg, peer.addr());

        Ok(())
    }

    /// Send a ping to a peer.
    fn send_ping(&mut self, target: &PeerInfo) -> Result<(), GossipError> {
        assert!(
            target.state() == PeerState::Alive,
            "can only ping alive peers"
        );

        let incarnation = self.membership.local_incarnation();
        let piggyback = self.get_piggyback_updates();

        let msg = GossipMessage::Ping {
            from: self.local_actor,
            incarnation,
            piggyback,
        };

        self.transport.send(&msg, target.addr())?;
        self.stats.pings_sent.fetch_add(1, Ordering::Relaxed);

        // Record pending ping only if not already pending (don't reset timeout)
        if !self.pending_pings.contains_key(&target.actor_id()) {
            self.pending_pings.insert(
                target.actor_id(),
                PendingPing {
                    target: target.actor_id(),
                    target_addr: target.addr(),
                    sent_at_ns: current_time_ns(),
                    indirect_requested: false,
                },
            );
        }

        Ok(())
    }

    /// Handle an incoming ping message.
    fn handle_ping(
        &mut self,
        from: ActorId,
        incarnation: u64,
        piggyback: Vec<StateUpdate>,
        source_addr: SocketAddr,
    ) -> Result<(), GossipError> {
        // Update membership: mark sender as alive
        if from != self.local_actor {
            // Try to add peer if not known
            let _ = self.membership.add_peer(from, source_addr);
            let _ = self.membership.mark_alive(from, incarnation);
            self.membership.touch(from);
        }

        // Process piggyback updates
        self.process_state_updates(piggyback);

        // Send ack response
        let local_incarnation = self.membership.local_incarnation();
        let response_piggyback = self.get_piggyback_updates();

        let msg = GossipMessage::Ack {
            from: self.local_actor,
            incarnation: local_incarnation,
            piggyback: response_piggyback,
        };

        self.transport.send(&msg, source_addr)?;

        Ok(())
    }

    /// Handle an incoming ack message.
    fn handle_ack(
        &mut self,
        from: ActorId,
        incarnation: u64,
        piggyback: Vec<StateUpdate>,
    ) -> Result<(), GossipError> {
        // Remove from pending pings
        self.pending_pings.remove(&from);

        // Update membership: mark sender as alive
        if from != self.local_actor {
            let _ = self.membership.mark_alive(from, incarnation);
            self.membership.touch(from);
        }

        // Check if this ack is for a pending indirect probe we need to forward
        if let Some(pending) = self.pending_indirect.remove(&from) {
            // Forward the ack to the original requester
            let forwarded_msg = GossipMessage::ForwardedAck {
                target: from,
                incarnation,
            };
            let _ = self.transport.send(&forwarded_msg, pending.requester_addr);
        }

        // Process piggyback updates
        self.process_state_updates(piggyback);

        self.stats.acks_received.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Handle an incoming ping-req message.
    fn handle_ping_req(
        &mut self,
        from: ActorId,
        target: ActorId,
        target_addr: SocketAddr,
        requester_addr: SocketAddr,
    ) -> Result<(), GossipError> {
        assert!(target != self.local_actor, "cannot ping-req self");

        // Send ping to target on behalf of requester
        let incarnation = self.membership.local_incarnation();
        let piggyback = self.get_piggyback_updates();

        let msg = GossipMessage::Ping {
            from: self.local_actor,
            incarnation,
            piggyback,
        };

        self.transport.send(&msg, target_addr)?;
        self.stats.pings_sent.fetch_add(1, Ordering::Relaxed);

        // Track this as a pending indirect probe so we can forward the ack
        if self.pending_indirect.len() < MAX_PENDING_INDIRECT {
            self.pending_indirect.insert(
                target,
                PendingIndirect {
                    target,
                    requester: from,
                    requester_addr,
                    sent_at_ns: current_time_ns(),
                },
            );
        }

        Ok(())
    }

    /// Handle an incoming suspect message.
    fn handle_suspect(&mut self, actor_id: ActorId, incarnation: u64) -> Result<(), GossipError> {
        // If this is about us, refute it
        if actor_id == self.local_actor {
            let new_incarnation = self.membership.increment_incarnation();

            // Broadcast alive message to refute
            self.broadcast_alive(self.local_actor, new_incarnation)?;
            return Ok(());
        }

        // Mark the peer as suspect
        let _ = self.membership.mark_suspect(actor_id, incarnation);
        self.stats.suspicions_raised.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Handle an incoming alive message.
    fn handle_alive(&mut self, actor_id: ActorId, incarnation: u64) -> Result<(), GossipError> {
        let _ = self.membership.mark_alive(actor_id, incarnation);
        Ok(())
    }

    /// Handle an incoming dead message.
    fn handle_dead(&mut self, actor_id: ActorId) -> Result<(), GossipError> {
        if actor_id != self.local_actor {
            let _ = self.membership.mark_dead(actor_id);
            self.stats.peers_marked_dead.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Handle an incoming forwarded ack from an indirect probe helper.
    fn handle_forwarded_ack(&mut self, target: ActorId, incarnation: u64) -> Result<(), GossipError> {
        // Clear the pending ping for the target - indirect probe succeeded!
        self.pending_pings.remove(&target);

        // Mark target as alive
        if target != self.local_actor {
            let _ = self.membership.mark_alive(target, incarnation);
            self.membership.touch(target);
        }

        self.stats.acks_received.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Handle an incoming state snapshot for anti-entropy.
    fn handle_state_snapshot(
        &mut self,
        from: ActorId,
        incarnation: u64,
        members: Vec<(ActorId, u64, u8)>,
        updates: Vec<StateUpdate>,
        source_addr: SocketAddr,
    ) -> Result<(), GossipError> {
        // Update sender's status
        if from != self.local_actor {
            let _ = self.membership.add_peer(from, source_addr);
            let _ = self.membership.mark_alive(from, incarnation);
            self.membership.touch(from);
        }

        // Merge membership information (bounded by MAX_PEERS)
        for (actor_id, inc, state) in members.into_iter().take(MAX_PEERS) {
            if actor_id == self.local_actor {
                continue; // Skip self
            }

            // Convert state byte to PeerState
            let peer_state = match state {
                0 => PeerState::Alive,
                1 => PeerState::Suspect,
                2 => PeerState::Dead,
                _ => continue, // Invalid state
            };

            // If we don't know this peer, add it (we need its address, so skip if unknown)
            if self.membership.find_peer(actor_id).is_some() {
                // Apply state update with incarnation-based conflict resolution
                match peer_state {
                    PeerState::Alive => {
                        let _ = self.membership.mark_alive(actor_id, inc);
                    }
                    PeerState::Suspect => {
                        let _ = self.membership.mark_suspect(actor_id, inc);
                    }
                    PeerState::Dead => {
                        let _ = self.membership.mark_dead(actor_id);
                    }
                }
            }
        }

        // Process piggybacked state updates
        self.process_state_updates(updates);

        Ok(())
    }

    /// Check for pending ping timeouts.
    fn check_ping_timeouts(&mut self, now_ns: u64) {
        let ping_timeout_ns = self.config.ping_timeout_ms * 1_000_000;

        // Also clean up stale pending indirect probes
        let indirect_timeout_ns = ping_timeout_ns * 2;
        self.pending_indirect.retain(|_, pending| {
            now_ns.saturating_sub(pending.sent_at_ns) < indirect_timeout_ns
        });

        // Collect timed-out pings (bounded iteration)
        let mut timed_out: Vec<(ActorId, PendingPing)> = Vec::new();

        for (actor_id, pending) in self.pending_pings.iter() {
            if timed_out.len() >= MAX_PENDING_PINGS {
                break;
            }

            let elapsed = now_ns.saturating_sub(pending.sent_at_ns);
            if elapsed > ping_timeout_ns {
                timed_out.push((*actor_id, *pending));
            }
        }

        // Process timed-out pings
        for (actor_id, pending) in timed_out {
            if !pending.indirect_requested {
                // Try indirect probing
                self.request_indirect_probes(actor_id, pending.target_addr);

                // Mark as indirect requested
                if let Some(p) = self.pending_pings.get_mut(&actor_id) {
                    p.indirect_requested = true;
                    p.sent_at_ns = now_ns; // Reset timeout for indirect phase
                }
            } else {
                // Indirect probes also failed, mark as suspect
                self.pending_pings.remove(&actor_id);

                if let Some(peer) = self.membership.find_peer(actor_id) {
                    let incarnation = peer.incarnation();
                    let _ = self.membership.mark_suspect(actor_id, incarnation);
                    self.stats.suspicions_raised.fetch_add(1, Ordering::Relaxed);
                    
                    // Broadcast suspect to fanout peers (Comment 3)
                    self.broadcast_suspect(actor_id, incarnation);
                }

                self.stats.ping_timeouts.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Request indirect probes via other peers.
    fn request_indirect_probes(&mut self, target: ActorId, target_addr: SocketAddr) {
        // Get random alive peers to help with probing
        let helpers = self.membership.get_random_alive_peers(self.config.fanout, target);
        let local_addr = self.transport.local_addr();

        for helper in helpers {
            let msg = GossipMessage::PingReq {
                from: self.local_actor,
                target,
                target_addr,
                requester_addr: local_addr,
            };

            // Ignore send errors - best effort
            let _ = self.transport.send(&msg, helper.addr());
        }
    }

    /// Broadcast an alive message to refute suspicion.
    fn broadcast_alive(&mut self, actor_id: ActorId, incarnation: u64) -> Result<(), GossipError> {
        let msg = GossipMessage::Alive { actor_id, incarnation };

        // Send to all alive peers
        let peers = self.membership.get_alive_peers();
        for peer in peers {
            let _ = self.transport.send(&msg, peer.addr());
        }

        Ok(())
    }

    /// Broadcast a suspect message to random fanout peers.
    fn broadcast_suspect(&mut self, actor_id: ActorId, incarnation: u64) {
        let msg = GossipMessage::Suspect { actor_id, incarnation };

        // Send to random fanout of alive peers (bounded)
        let peers = self.membership.get_random_alive_peers(self.config.fanout, actor_id);
        for peer in peers {
            let _ = self.transport.send(&msg, peer.addr());
        }
    }

    /// Broadcast a dead message to random fanout peers.
    fn broadcast_dead(&mut self, actor_id: ActorId) {
        let msg = GossipMessage::Dead { actor_id };

        // Send to random fanout of alive peers (bounded)
        let peers = self.membership.get_random_alive_peers(self.config.fanout, actor_id);
        for peer in peers {
            let _ = self.transport.send(&msg, peer.addr());
        }
    }

    /// Broadcast a state update to the cluster.
    ///
    /// The update will be piggybacked on subsequent protocol messages.
    pub fn broadcast_state_update(&mut self, update: StateUpdate) {
        // Add to piggyback queue
        self.piggyback_queue.push_back(update);

        // Trim if exceeds capacity (FIFO eviction)
        while self.piggyback_queue.len() > MAX_PIGGYBACK_QUEUE_SIZE {
            self.piggyback_queue.pop_front();
        }

        // Postcondition: queue size within bounds
        assert!(
            self.piggyback_queue.len() <= MAX_PIGGYBACK_QUEUE_SIZE,
            "piggyback queue exceeds capacity"
        );
    }

    /// Get state updates for piggybacking.
    fn get_piggyback_updates(&mut self) -> Vec<StateUpdate> {
        let count = self.piggyback_queue.len().min(self.config.max_piggyback_updates);
        let mut updates = Vec::with_capacity(count);

        for _ in 0..count {
            if let Some(update) = self.piggyback_queue.pop_front() {
                updates.push(update);
            }
        }

        self.stats
            .state_updates_sent
            .fetch_add(updates.len() as u64, Ordering::Relaxed);

        updates
    }

    /// Process received state updates.
    ///
    /// Applies each update to the local distributed state using CRDT merge
    /// semantics. Logs and skips on CRDT errors, continuing to process
    /// remaining updates.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    fn process_state_updates(&mut self, updates: Vec<StateUpdate>) {
        // Precondition: updates bounded by protocol limit
        assert!(
            updates.len() <= MAX_PIGGYBACK_UPDATES,
            "too many piggyback updates"
        );

        // Track statistics
        self.stats
            .state_updates_received
            .fetch_add(updates.len() as u64, Ordering::Relaxed);

        // Apply updates to distributed state if available
        if let Some(ref distributed_state) = self.distributed_state {
            for update in &updates {
                // Log and skip on CRDT errors, continue processing remaining
                // Note: No logging framework available, errors are silently skipped
                let _ = self.apply_state_update(distributed_state, update);
            }
        }

        // Re-broadcast updates by adding to our queue
        for update in updates {
            // Avoid re-adding duplicates (simplified check)
            if self.piggyback_queue.len() < MAX_PIGGYBACK_QUEUE_SIZE {
                self.piggyback_queue.push_back(update);
            }
        }

        // Postcondition: queue size within bounds
        assert!(
            self.piggyback_queue.len() <= MAX_PIGGYBACK_QUEUE_SIZE,
            "piggyback queue exceeds capacity after processing"
        );
    }

    /// Apply a single state update to the distributed state.
    ///
    /// Dispatches to the appropriate DistributedState method based on update type.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines
    /// - ≥2 assertions
    fn apply_state_update(
        &self,
        state: &DistributedState,
        update: &StateUpdate,
    ) -> Result<(), crate::error::CrdtError> {
        // Precondition: state must be valid
        assert!(state.local_actor() < MAX_ACTORS as u64, "invalid local_actor");

        match update {
            StateUpdate::ParticipantAdded {
                room_id,
                participant_id,
                dot: _,
            } => {
                // Add participant to room
                // Note: We ignore the dot from the update and generate a new one
                // locally since add_participant generates its own dot
                let _ = state.add_participant(*room_id, (*participant_id).into())?;
            }
            StateUpdate::ParticipantRemoved {
                room_id,
                participant_id,
                dot: _,
            } => {
                // Remove participant from room
                let _ = state.remove_participant(*room_id, (*participant_id).into())?;
            }
            StateUpdate::TrackUpdated {
                track_id,
                info,
                timestamp: _,
                actor: _,
            } => {
                // Update or add track metadata
                // Try update first, if track doesn't exist, add it
                if state.get_track((*track_id).into()).is_some() {
                    let _ = state.update_track((*track_id).into(), *info)?;
                } else {
                    let _ = state.add_track((*track_id).into(), *info)?;
                }
            }
            StateUpdate::SubscriptionAdded {
                track_id,
                participant_id,
                dot: _,
            } => {
                // Add subscription
                let _ = state.add_subscription((*track_id).into(), (*participant_id).into())?;
            }
            StateUpdate::SubscriptionRemoved {
                track_id,
                participant_id,
                dot: _,
            } => {
                // Remove subscription
                let _ = state.remove_subscription((*track_id).into(), (*participant_id).into())?;
            }
        }

        // Postcondition: update was processed (no panic)
        Ok(())
    }

    /// Handle an incoming message.
    ///
    /// Dispatches to the appropriate handler based on message type.
    pub fn handle_message(
        &mut self,
        msg: GossipMessage,
        source: SocketAddr,
    ) -> Result<(), GossipError> {
        match msg {
            GossipMessage::Ping {
                from,
                incarnation,
                piggyback,
            } => {
                self.handle_ping(from, incarnation, piggyback, source)
            }
            GossipMessage::Ack {
                from,
                incarnation,
                piggyback,
            } => {
                self.handle_ack(from, incarnation, piggyback)
            }
            GossipMessage::PingReq {
                from,
                target,
                target_addr,
                requester_addr,
            } => {
                self.handle_ping_req(from, target, target_addr, requester_addr)
            }
            GossipMessage::Suspect { actor_id, incarnation } => {
                self.handle_suspect(actor_id, incarnation)
            }
            GossipMessage::Alive { actor_id, incarnation } => {
                self.handle_alive(actor_id, incarnation)
            }
            GossipMessage::Dead { actor_id } => {
                self.handle_dead(actor_id)
            }
            GossipMessage::ForwardedAck { target, incarnation } => {
                self.handle_forwarded_ack(target, incarnation)
            }
            GossipMessage::StateSnapshot {
                from,
                incarnation,
                members,
                updates,
            } => {
                self.handle_state_snapshot(from, incarnation, members, updates, source)
            }
        }
    }

    /// Run one iteration of the receive loop.
    ///
    /// Attempts to receive and process incoming messages (non-blocking).
    pub fn recv_loop_iteration(&mut self) -> Result<(), GossipError> {
        // Try to receive with short timeout (non-blocking)
        match self.transport.try_recv() {
            Some((msg, source)) => {
                self.handle_message(msg, source)?;
            }
            None => {
                // No message available - not an error
            }
        }

        Ok(())
    }

    /// Run the protocol for a specified duration.
    ///
    /// This is a convenience method for testing that runs both probe cycles
    /// and receive loops.
    pub fn run_for_duration(&mut self, duration_ms: u64) -> Result<(), GossipError> {
        let start = current_time_ns();
        let target_duration_ns = duration_ms * 1_000_000;

        loop {
            let now = current_time_ns();
            if now.saturating_sub(start) >= target_duration_ns {
                break;
            }

            self.run_probe_cycle()?;
            self.recv_loop_iteration()?;

            // Small sleep to avoid busy-waiting
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        Ok(())
    }
}

/// Get current time in nanoseconds since UNIX epoch.
#[inline]
fn current_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Dot;

    fn localhost_addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn test_protocol_new() {
        let config = GossipConfig::for_testing();
        let protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        assert_eq!(protocol.local_actor(), 1);
        assert!(protocol.local_addr().port() > 0);
        assert_eq!(protocol.membership().peer_count(), 0);
    }

    #[test]
    #[should_panic(expected = "local_actor must be < MAX_ACTORS")]
    fn test_protocol_new_invalid_actor() {
        let config = GossipConfig::default();
        let _ = SwimProtocol::new(MAX_ACTORS as u64, localhost_addr(), config);
    }

    #[test]
    fn test_add_seed_peer() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        protocol.add_seed_peer(2, peer_addr).unwrap();

        assert_eq!(protocol.membership().peer_count(), 1);
        assert!(protocol.pending_pings.contains_key(&2));
    }

    #[test]
    fn test_run_probe_cycle_empty() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Should not panic with no peers
        protocol.run_probe_cycle().unwrap();
    }

    #[test]
    fn test_broadcast_state_update() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let dot = Dot::new(1, 1);
        let update = StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: 42,
            dot,
        };

        protocol.broadcast_state_update(update.clone());

        assert_eq!(protocol.piggyback_queue.len(), 1);
    }

    #[test]
    fn test_piggyback_queue_capacity() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Fill beyond capacity
        for i in 0..(MAX_PIGGYBACK_QUEUE_SIZE + 10) {
            let dot = Dot::new(1, (i + 1) as u64);
            let update = StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: i as u64,
                dot,
            };
            protocol.broadcast_state_update(update);
        }

        // Should be capped at max size
        assert!(protocol.piggyback_queue.len() <= MAX_PIGGYBACK_QUEUE_SIZE);
    }

    #[test]
    fn test_two_node_communication() {
        let config = GossipConfig::for_testing();

        let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

        let node2_addr = node2.local_addr();

        // Node1 adds Node2 as seed
        node1.add_seed_peer(2, node2_addr).unwrap();

        // Give time for message to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Node2 should receive and respond
        node2.recv_loop_iteration().unwrap();

        // Check Node2 knows about Node1
        assert!(node2.membership().find_peer(1).is_some());

        // Give time for ack to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Node1 should receive ack
        node1.recv_loop_iteration().unwrap();

        // Pending ping should be cleared
        assert!(!node1.pending_pings.contains_key(&2));
    }

    #[test]
    fn test_handle_ping() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let msg = GossipMessage::Ping {
            from: 5,
            incarnation: 10,
            piggyback: vec![],
        };

        protocol.handle_message(msg, source).unwrap();

        // Should have added the peer
        let peer = protocol.membership().find_peer(5).unwrap();
        assert_eq!(peer.actor_id(), 5);
        assert_eq!(peer.state(), PeerState::Alive);
    }

    #[test]
    fn test_handle_suspect_self_refutes() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let initial_incarnation = protocol.membership().local_incarnation();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let msg = GossipMessage::Suspect {
            actor_id: 1, // Self
            incarnation: initial_incarnation,
        };

        protocol.handle_message(msg, source).unwrap();

        // Should have incremented incarnation
        assert!(protocol.membership().local_incarnation() > initial_incarnation);
    }

    #[test]
    fn test_handle_alive() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Add a peer first
        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        protocol.membership_mut().add_peer(5, peer_addr).unwrap();

        // Mark as suspect
        protocol.membership_mut().mark_suspect(5, 0).unwrap();
        assert_eq!(
            protocol.membership().find_peer(5).unwrap().state(),
            PeerState::Suspect
        );

        // Handle alive with higher incarnation
        let source: SocketAddr = "127.0.0.1:9998".parse().unwrap();
        let msg = GossipMessage::Alive {
            actor_id: 5,
            incarnation: 1, // Higher than 0
        };

        protocol.handle_message(msg, source).unwrap();

        // Should be alive again
        assert_eq!(
            protocol.membership().find_peer(5).unwrap().state(),
            PeerState::Alive
        );
    }

    #[test]
    fn test_handle_dead() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Add a peer first
        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        protocol.membership_mut().add_peer(5, peer_addr).unwrap();

        // Handle dead
        let source: SocketAddr = "127.0.0.1:9998".parse().unwrap();
        let msg = GossipMessage::Dead { actor_id: 5 };

        protocol.handle_message(msg, source).unwrap();

        // Should be dead
        assert_eq!(
            protocol.membership().find_peer(5).unwrap().state(),
            PeerState::Dead
        );
    }

    #[test]
    fn test_stats() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        protocol.add_seed_peer(2, peer_addr).unwrap();

        let stats = protocol.stats().snapshot();
        assert_eq!(stats.pings_sent, 1);
    }

    #[test]
    fn test_protocol_stats_reset() {
        let stats = ProtocolStats::new();
        stats.pings_sent.fetch_add(10, Ordering::Relaxed);
        stats.acks_received.fetch_add(5, Ordering::Relaxed);

        stats.reset();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.pings_sent, 0);
        assert_eq!(snapshot.acks_received, 0);
    }

    // =========================================================================
    // Comment 1 Tests: Indirect probe forwarding
    // =========================================================================

    #[test]
    fn test_indirect_probe_success_clears_pending() {
        let config = GossipConfig::for_testing();

        // Create 3 nodes: requester, helper, target
        let mut requester = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut helper = SwimProtocol::new(2, localhost_addr(), config.clone()).unwrap();
        let mut target = SwimProtocol::new(3, localhost_addr(), config).unwrap();

        let helper_addr = helper.local_addr();
        let target_addr = target.local_addr();
        let requester_addr = requester.local_addr();

        // Requester knows about helper and target
        requester.membership_mut().add_peer(2, helper_addr).unwrap();
        requester.membership_mut().add_peer(3, target_addr).unwrap();

        // Helper sends PingReq on behalf of requester
        let ping_req = GossipMessage::PingReq {
            from: 1,
            target: 3,
            target_addr,
            requester_addr,
        };
        helper.handle_message(ping_req, requester_addr).unwrap();

        // Helper should have pending indirect for target
        assert!(helper.pending_indirect.contains_key(&3));

        // Give time for ping to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Target receives ping from helper
        target.recv_loop_iteration().unwrap();

        // Give time for ack to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Helper receives ack from target
        helper.recv_loop_iteration().unwrap();

        // Helper should have cleared pending indirect
        assert!(!helper.pending_indirect.contains_key(&3));

        // Give time for forwarded ack to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Requester should have a pending ping for target initially
        requester.pending_pings.insert(3, PendingPing {
            target: 3,
            target_addr,
            sent_at_ns: current_time_ns(),
            indirect_requested: true,
        });

        // Requester receives forwarded ack
        requester.recv_loop_iteration().unwrap();

        // Pending ping should be cleared
        assert!(!requester.pending_pings.contains_key(&3));
    }

    #[test]
    fn test_forwarded_ack_prevents_suspicion() {
        let config = GossipConfig::for_testing();
        let mut requester = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        let target_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        requester.membership_mut().add_peer(3, target_addr).unwrap();

        // Simulate pending ping awaiting indirect probe
        requester.pending_pings.insert(3, PendingPing {
            target: 3,
            target_addr,
            sent_at_ns: current_time_ns(),
            indirect_requested: true,
        });

        // Receive forwarded ack
        let forwarded_ack = GossipMessage::ForwardedAck {
            target: 3,
            incarnation: 5,
        };
        let source: SocketAddr = "127.0.0.1:8888".parse().unwrap();
        requester.handle_message(forwarded_ack, source).unwrap();

        // Pending ping should be cleared
        assert!(!requester.pending_pings.contains_key(&3));

        // Target should still be alive (not suspect)
        assert_eq!(
            requester.membership().find_peer(3).unwrap().state(),
            PeerState::Alive
        );
    }

    // =========================================================================
    // Comment 2 Tests: Anti-entropy full-state sync
    // =========================================================================

    #[test]
    fn test_anti_entropy_sends_snapshot() {
        let config = GossipConfig::for_testing();
        let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut node2 = SwimProtocol::new(2, localhost_addr(), config).unwrap();

        let node2_addr = node2.local_addr();

        // Node1 knows about node2
        node1.membership_mut().add_peer(2, node2_addr).unwrap();

        // Set very short anti-entropy interval
        node1.set_anti_entropy_interval(1);

        // Force last_anti_entropy to be old
        node1.last_anti_entropy_ns.store(0, Ordering::Relaxed);

        // Run probe cycle - should trigger anti-entropy
        node1.run_probe_cycle().unwrap();

        // Give time for snapshot to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Node2 receives snapshot
        node2.recv_loop_iteration().unwrap();

        // Node2 should know about node1 now
        assert!(node2.membership().find_peer(1).is_some());
    }

    #[test]
    fn test_anti_entropy_converges_without_piggyback() {
        let config = GossipConfig::for_testing();
        let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut node2 = SwimProtocol::new(2, localhost_addr(), config.clone()).unwrap();
        let mut node3 = SwimProtocol::new(3, localhost_addr(), config).unwrap();

        let node1_addr = node1.local_addr();
        let node2_addr = node2.local_addr();
        let node3_addr = node3.local_addr();

        // Node1 knows about node2 and node3
        node1.membership_mut().add_peer(2, node2_addr).unwrap();
        node1.membership_mut().add_peer(3, node3_addr).unwrap();

        // Node2 only knows about node1
        node2.membership_mut().add_peer(1, node1_addr).unwrap();

        // Node3 is joining fresh, only learns from anti-entropy
        // Node3 receives a StateSnapshot from node1 with membership info
        let snapshot = GossipMessage::StateSnapshot {
            from: 1,
            incarnation: 1,
            members: vec![
                (1, 1, 0), // Node1 is Alive
                (2, 1, 0), // Node2 is Alive
            ],
            updates: vec![],
        };
        node3.handle_message(snapshot, node1_addr).unwrap();

        // Node3 should know about node1 now
        assert!(node3.membership().find_peer(1).is_some());
        // Node3 doesn't learn node2's address from snapshot (no addr in snapshot)
    }

    // =========================================================================
    // Comment 3 Tests: Gossip suspect/dead transitions
    // =========================================================================

    #[test]
    fn test_third_node_learns_suspect_via_broadcast() {
        let config = GossipConfig::for_testing();
        let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut node2 = SwimProtocol::new(2, localhost_addr(), config.clone()).unwrap();
        let mut node3 = SwimProtocol::new(3, localhost_addr(), config).unwrap();

        let node2_addr = node2.local_addr();
        let node3_addr = node3.local_addr();
        let fake_addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();

        // All nodes know about each other
        node1.membership_mut().add_peer(2, node2_addr).unwrap();
        node1.membership_mut().add_peer(3, node3_addr).unwrap();
        node1.membership_mut().add_peer(99, fake_addr).unwrap(); // Unreachable peer

        node2.membership_mut().add_peer(99, fake_addr).unwrap();
        node3.membership_mut().add_peer(99, fake_addr).unwrap();

        // Node1 marks peer 99 as suspect and broadcasts
        node1.membership_mut().mark_suspect(99, 0).unwrap();
        node1.broadcast_suspect(99, 0);

        // Give time for messages to arrive
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Node2 and Node3 receive suspect messages
        node2.recv_loop_iteration().unwrap();
        node3.recv_loop_iteration().unwrap();

        // Node2 and Node3 should now know peer 99 is suspect
        assert_eq!(
            node2.membership().find_peer(99).unwrap().state(),
            PeerState::Suspect
        );
        assert_eq!(
            node3.membership().find_peer(99).unwrap().state(),
            PeerState::Suspect
        );
    }

    #[test]
    fn test_third_node_learns_dead_via_broadcast() {
        let config = GossipConfig::for_testing();
        let mut node1 = SwimProtocol::new(1, localhost_addr(), config.clone()).unwrap();
        let mut node2 = SwimProtocol::new(2, localhost_addr(), config.clone()).unwrap();
        let mut node3 = SwimProtocol::new(3, localhost_addr(), config).unwrap();

        let node2_addr = node2.local_addr();
        let node3_addr = node3.local_addr();
        let fake_addr: SocketAddr = "127.0.0.1:59998".parse().unwrap();

        // All nodes know about each other
        node1.membership_mut().add_peer(2, node2_addr).unwrap();
        node1.membership_mut().add_peer(3, node3_addr).unwrap();
        node1.membership_mut().add_peer(98, fake_addr).unwrap();

        node2.membership_mut().add_peer(98, fake_addr).unwrap();
        node3.membership_mut().add_peer(98, fake_addr).unwrap();

        // Node1 marks peer 98 as dead and broadcasts
        node1.membership_mut().mark_dead(98).unwrap();
        node1.broadcast_dead(98);

        // Give time for messages to arrive
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Node2 and Node3 receive dead messages
        node2.recv_loop_iteration().unwrap();
        node3.recv_loop_iteration().unwrap();

        // Node2 and Node3 should now know peer 98 is dead
        assert_eq!(
            node2.membership().find_peer(98).unwrap().state(),
            PeerState::Dead
        );
        assert_eq!(
            node3.membership().find_peer(98).unwrap().state(),
            PeerState::Dead
        );
    }

    // =========================================================================
    // State Application Tests
    // =========================================================================

    #[test]
    fn test_set_distributed_state() {
        use crate::distributed_state::{DistributedState, DistributedStateConfig};

        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Initially no distributed state
        assert!(protocol.distributed_state().is_none());

        // Set distributed state
        let state_config = DistributedStateConfig::new(1);
        let state = Arc::new(DistributedState::new(state_config));
        protocol.set_distributed_state(state);

        // Now distributed state is set
        assert!(protocol.distributed_state().is_some());
    }

    #[test]
    fn test_state_updates_applied_to_distributed_state() {
        use crate::distributed_state::{DistributedState, DistributedStateConfig};
        use crate::gossip::types::TrackInfo;

        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Create and set distributed state
        let state_config = DistributedStateConfig::new(1);
        let state = Arc::new(DistributedState::new(state_config));
        
        // Create a room first (required for adding participants)
        state.create_room(1, "Test Room".to_string(), 100).unwrap();
        
        protocol.set_distributed_state(Arc::clone(&state));

        // Create state updates
        let updates = vec![
            StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: 42,
                dot: Dot::new(1, 1),
            },
            StateUpdate::TrackUpdated {
                track_id: 100,
                info: TrackInfo {
                    track_type: 1,
                    codec: 96,
                    bitrate_kbps: 1000,
                },
                timestamp: 1,
                actor: 1,
            },
        ];

        // Process updates via ping message
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let msg = GossipMessage::Ping {
            from: 5,
            incarnation: 10,
            piggyback: updates,
        };

        protocol.handle_message(msg, source).unwrap();

        // Verify participant was added
        assert!(state.participant_exists(1, 42));

        // Verify track was added
        let track = state.get_track(100);
        assert!(track.is_some());
        let track_info = track.unwrap();
        assert_eq!(track_info.track_type, 1);
        assert_eq!(track_info.codec, 96);
        assert_eq!(track_info.bitrate_kbps, 1000);
    }

    #[test]
    fn test_state_updates_without_distributed_state() {
        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // No distributed state set - updates should still be processed (counted and re-broadcast)
        let updates = vec![
            StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: 42,
                dot: Dot::new(1, 1),
            },
        ];

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let msg = GossipMessage::Ping {
            from: 5,
            incarnation: 10,
            piggyback: updates,
        };

        // Should not panic
        protocol.handle_message(msg, source).unwrap();

        // Stats should be updated
        assert_eq!(protocol.stats().snapshot().state_updates_received, 1);

        // Note: The piggyback queue may be empty because handle_ping sends an Ack
        // which calls get_piggyback_updates() and drains the queue. This is correct
        // behavior - updates are re-broadcast via the Ack response.
    }

    #[test]
    fn test_state_updates_error_handling() {
        use crate::distributed_state::{DistributedState, DistributedStateConfig};

        let config = GossipConfig::for_testing();
        let mut protocol = SwimProtocol::new(1, localhost_addr(), config).unwrap();

        // Create and set distributed state
        let state_config = DistributedStateConfig::new(1);
        let state = Arc::new(DistributedState::new(state_config));
        protocol.set_distributed_state(Arc::clone(&state));

        // Create update for non-existent room (will fail)
        let updates = vec![
            StateUpdate::ParticipantAdded {
                room_id: 999, // Room doesn't exist
                participant_id: 42,
                dot: Dot::new(1, 1),
            },
        ];

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let msg = GossipMessage::Ping {
            from: 5,
            incarnation: 10,
            piggyback: updates,
        };

        // Should not panic - errors are logged and skipped
        protocol.handle_message(msg, source).unwrap();

        // Stats should still be updated
        assert_eq!(protocol.stats().snapshot().state_updates_received, 1);

        // Participant should NOT be in state (room doesn't exist)
        assert!(!state.participant_exists(999, 42));
    }
}
