//! SWIM membership list with state machine.
//!
//! This module implements the membership list that tracks all known peers
//! in the cluster. Each peer follows a state machine (Alive → Suspect → Dead)
//! with incarnation-based refutation for false positive prevention.
//!
//! ## State Machine
//!
//! ```text
//! [*] --> Alive: add_peer()
//!
//! Alive --> Suspect: ping_timeout
//! Suspect --> Alive: refutation (higher incarnation)
//! Suspect --> Dead: suspect_timeout
//! Dead --> Alive: resurrection (higher incarnation)
//! ```
//!
//! ## TigerStyle Compliance
//!
//! - All loops bounded by MAX_PEERS
//! - Assertions on all state transitions
//! - Pre-allocated fixed-size array for peers
//! - Atomic operations for thread-safe counters

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::getrandom;

use super::types::{PeerInfo, PeerState, MAX_PEERS, SUSPECT_TIMEOUT_MS};
use crate::error::GossipError;
use crate::types::{ActorId, MAX_ACTORS};

/// Membership list tracking all known peers in the cluster.
///
/// Uses a fixed-size array with `Option<PeerInfo>` for O(1) lookup by slot
/// and O(n) iteration. The peer_count is maintained atomically for
/// lock-free status queries.
///
/// # Invariants
/// - `peer_count <= MAX_PEERS`
/// - No duplicate actor IDs in the list
/// - Local actor is never in the peer list
pub struct MembershipList {
    /// Local actor's ID (self is not in the peer list)
    local_actor: ActorId,
    /// Array of peer slots (None = empty slot)
    peers: [Option<PeerInfo>; MAX_PEERS],
    /// Number of non-empty slots (atomic for lock-free reads)
    peer_count: AtomicU32,
    /// Local incarnation number (atomic for lock-free increments)
    incarnation: AtomicU64,
}

// Compile-time size assertion
const _: () = {
    // Each Option<PeerInfo> is about 56 bytes, total ~14KB
    assert!(MAX_PEERS == 256, "MAX_PEERS must be 256");
};

impl MembershipList {
    /// Create a new membership list for the local actor.
    ///
    /// # Panics
    /// Panics if `local_actor >= MAX_ACTORS`
    #[inline]
    pub fn new(local_actor: ActorId) -> Self {
        assert!(
            local_actor < MAX_ACTORS as u64,
            "local_actor must be < MAX_ACTORS"
        );

        Self {
            local_actor,
            peers: [const { None }; MAX_PEERS],
            peer_count: AtomicU32::new(0),
            incarnation: AtomicU64::new(1),
        }
    }

    /// Returns the local actor ID.
    #[inline]
    pub const fn local_actor(&self) -> ActorId {
        self.local_actor
    }

    /// Returns the current peer count.
    #[inline]
    pub fn peer_count(&self) -> u32 {
        self.peer_count.load(Ordering::Relaxed)
    }

    /// Returns the local incarnation number.
    #[inline]
    pub fn local_incarnation(&self) -> u64 {
        self.incarnation.load(Ordering::Relaxed)
    }

    /// Increment and return the local incarnation number.
    ///
    /// Used when refuting suspicion about self.
    #[inline]
    pub fn increment_incarnation(&self) -> u64 {
        self.incarnation.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Add a new peer to the membership list.
    ///
    /// # Arguments
    /// * `actor_id` - Peer's actor ID (must be < MAX_ACTORS, must not equal local_actor)
    /// * `addr` - Peer's network address
    ///
    /// # Returns
    /// - `Ok(())` if peer was added successfully
    /// - `Err(GossipError::PeerCapacityExhausted)` if list is full
    /// - `Err(GossipError::Config)` if actor_id is invalid
    ///
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS` or `actor_id == local_actor`
    pub fn add_peer(&mut self, actor_id: ActorId, addr: SocketAddr) -> Result<(), GossipError> {
        // Precondition assertions
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );
        assert!(
            actor_id != self.local_actor,
            "cannot add self to peer list"
        );

        // Check if peer already exists (bounded loop)
        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.actor_id() == actor_id {
                    // Peer already exists, update address if different
                    if peer.addr() != addr {
                        // Recreate PeerInfo with updated address
                        self.peers[i] = Some(PeerInfo::new(
                            actor_id,
                            addr,
                            peer.incarnation(),
                            peer.last_seen_ns(),
                        ));
                    }
                    return Ok(());
                }
            }
        }

        // Check capacity
        let current_count = self.peer_count.load(Ordering::Relaxed);
        if current_count >= MAX_PEERS as u32 {
            return Err(GossipError::PeerCapacityExhausted { max: MAX_PEERS });
        }

        // Find first empty slot (bounded loop)
        let now_ns = current_time_ns();
        for i in 0..MAX_PEERS {
            if self.peers[i].is_none() {
                self.peers[i] = Some(PeerInfo::new(actor_id, addr, 0, now_ns));
                self.peer_count.fetch_add(1, Ordering::Relaxed);

                // Postcondition: peer exists in list
                debug_assert!(self.find_peer(actor_id).is_some());

                return Ok(());
            }
        }

        // Should not reach here if count < MAX_PEERS
        Err(GossipError::PeerCapacityExhausted { max: MAX_PEERS })
    }

    /// Remove a peer from the membership list.
    ///
    /// # Returns
    /// - `Ok(())` if peer was removed
    /// - `Err(GossipError::PeerNotFound)` if peer doesn't exist
    pub fn remove_peer(&mut self, actor_id: ActorId) -> Result<(), GossipError> {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.actor_id() == actor_id {
                    self.peers[i] = None;
                    self.peer_count.fetch_sub(1, Ordering::Relaxed);

                    // Postcondition: peer no longer exists
                    debug_assert!(self.find_peer(actor_id).is_none());

                    return Ok(());
                }
            }
        }

        Err(GossipError::PeerNotFound { actor_id })
    }

    /// Find a peer by actor ID.
    ///
    /// # Returns
    /// A copy of the peer info, or None if not found.
    #[inline]
    pub fn find_peer(&self, actor_id: ActorId) -> Option<PeerInfo> {
        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.actor_id() == actor_id {
                    return Some(*peer);
                }
            }
        }
        None
    }

    /// Update a peer's state with incarnation-based rules.
    ///
    /// # State Transition Rules
    /// - Alive → Suspect: Always allowed
    /// - Suspect → Alive: Only if incarnation > current (refutation)
    /// - Suspect → Dead: Always allowed (timeout)
    /// - Dead → Alive: Only if incarnation > current (resurrection)
    /// - Same state: Update if incarnation >= current
    ///
    /// # Returns
    /// - `Ok(())` if state was updated
    /// - `Err(GossipError::PeerNotFound)` if peer doesn't exist
    /// - `Err(GossipError::InvalidStateTransition)` if transition is invalid
    pub fn update_state(
        &mut self,
        actor_id: ActorId,
        new_state: PeerState,
        incarnation: u64,
    ) -> Result<(), GossipError> {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        // First pass: find the peer and validate the transition
        let mut found_idx: Option<usize> = None;
        let mut old_state = PeerState::Alive;
        let mut old_incarnation: u64 = 0;

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.actor_id() == actor_id {
                    old_state = peer.state();
                    old_incarnation = peer.incarnation();
                    found_idx = Some(i);
                    break;
                }
            }
        }

        let idx = match found_idx {
            Some(i) => i,
            None => return Err(GossipError::PeerNotFound { actor_id }),
        };

        // Validate state transition (no borrow conflict now)
        let transition_valid = self.validate_transition(
            old_state,
            new_state,
            old_incarnation,
            incarnation,
        );

        if !transition_valid {
            return Err(GossipError::InvalidStateTransition {
                from: old_state.as_str(),
                to: new_state.as_str(),
            });
        }

        // Second pass: apply the changes
        if let Some(ref mut peer) = self.peers[idx] {
            peer.set_state(new_state);
            peer.set_incarnation(incarnation);
            peer.set_last_seen_ns(current_time_ns());

            // Postcondition: state changed correctly
            debug_assert_eq!(peer.state(), new_state);
        }

        Ok(())
    }

    /// Validate a state transition according to SWIM rules.
    #[inline]
    fn validate_transition(
        &self,
        from: PeerState,
        to: PeerState,
        from_incarnation: u64,
        to_incarnation: u64,
    ) -> bool {
        // Same state: accept if incarnation >= current
        if from == to {
            return to_incarnation >= from_incarnation;
        }

        // Use nested if/else per TigerStyle (no compound conditions)
        if from == PeerState::Alive {
            // Alive → Suspect: always allowed (any incarnation)
            if to == PeerState::Suspect {
                return to_incarnation >= from_incarnation;
            }
            // Alive → Dead: allowed (force)
            if to == PeerState::Dead {
                return true;
            }
            return false;
        }

        if from == PeerState::Suspect {
            // Suspect → Alive: only with higher incarnation (refutation)
            if to == PeerState::Alive {
                return to_incarnation > from_incarnation;
            }
            // Suspect → Dead: always allowed (timeout)
            if to == PeerState::Dead {
                return true;
            }
            return false;
        }

        if from == PeerState::Dead {
            // Dead → Alive: only with higher incarnation (resurrection)
            if to == PeerState::Alive {
                return to_incarnation > from_incarnation;
            }
            // Dead → Suspect: not allowed
            if to == PeerState::Suspect {
                return false;
            }
            return false;
        }

        false
    }

    /// Mark a peer as alive.
    ///
    /// If the actor_id is the local actor, increments local incarnation instead.
    ///
    /// # Panics
    /// Panics if actor_id >= MAX_ACTORS
    pub fn mark_alive(&mut self, actor_id: ActorId, incarnation: u64) -> Result<(), GossipError> {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        // If marking self as alive, increment incarnation to refute
        if actor_id == self.local_actor {
            // Refute by incrementing to at least incarnation + 1
            loop {
                let current = self.incarnation.load(Ordering::Relaxed);
                if current > incarnation {
                    break;
                }
                let new_inc = incarnation + 1;
                if self
                    .incarnation
                    .compare_exchange(current, new_inc, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
            return Ok(());
        }

        self.update_state(actor_id, PeerState::Alive, incarnation)
    }

    /// Mark a peer as suspect.
    ///
    /// # Panics
    /// Panics if actor_id == local_actor (cannot suspect self)
    pub fn mark_suspect(&mut self, actor_id: ActorId, incarnation: u64) -> Result<(), GossipError> {
        assert!(
            actor_id != self.local_actor,
            "cannot suspect self"
        );
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        let result = self.update_state(actor_id, PeerState::Suspect, incarnation);

        // Postcondition: if Ok, peer state is Suspect
        if result.is_ok() {
            if let Some(peer) = self.find_peer(actor_id) {
                debug_assert_eq!(peer.state(), PeerState::Suspect);
            }
        }

        result
    }

    /// Mark a peer as dead.
    ///
    /// # Panics
    /// Panics if actor_id == local_actor
    pub fn mark_dead(&mut self, actor_id: ActorId) -> Result<(), GossipError> {
        assert!(
            actor_id != self.local_actor,
            "cannot mark self as dead"
        );
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        // Find the peer to get current incarnation
        // The Dead transition is always allowed, so we keep the current incarnation
        let current_incarnation = self.find_peer(actor_id)
            .map(|p| p.incarnation())
            .unwrap_or(0);

        let result = self.update_state(actor_id, PeerState::Dead, current_incarnation);

        // Postcondition: if Ok, peer state is Dead
        if result.is_ok() {
            if let Some(peer) = self.find_peer(actor_id) {
                debug_assert_eq!(peer.state(), PeerState::Dead);
            }
        }

        result
    }

    /// Get a random alive peer.
    ///
    /// Uses `getrandom()` for random selection.
    ///
    /// # Returns
    /// A copy of a random alive peer's info, or None if no alive peers.
    pub fn get_random_alive_peer(&self) -> Option<PeerInfo> {
        // Collect alive peers into temporary array (bounded)
        let mut alive_peers = [None; MAX_PEERS];
        let mut alive_count = 0usize;

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.state() == PeerState::Alive && alive_count < MAX_PEERS {
                    alive_peers[alive_count] = Some(*peer);
                    alive_count += 1;
                }
            }
        }

        if alive_count == 0 {
            return None;
        }

        // Select random index using getrandom()
        let mut buf = [0u8; 8];
        getrandom(&mut buf).expect("getrandom failed");
        let random_val = u64::from_le_bytes(buf);
        let index = (random_val % alive_count as u64) as usize;

        alive_peers[index]
    }

    /// Get multiple random alive peers for indirect probing.
    ///
    /// # Arguments
    /// * `count` - Maximum number of peers to return
    /// * `exclude` - Actor ID to exclude (typically the target being probed)
    ///
    /// # Returns
    /// Vector of alive peer infos (may be less than count if not enough peers)
    pub fn get_random_alive_peers(&self, count: usize, exclude: ActorId) -> Vec<PeerInfo> {
        let max_count = count.min(MAX_PEERS);
        let mut alive_peers = Vec::with_capacity(max_count);

        // Collect eligible peers (bounded loop)
        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.state() == PeerState::Alive && peer.actor_id() != exclude {
                    alive_peers.push(*peer);
                }
            }
        }

        // Fisher-Yates shuffle using getrandom() and take first count
        let len = alive_peers.len();
        for i in (1..len).rev() {
            let mut buf = [0u8; 8];
            getrandom(&mut buf).expect("getrandom failed");
            let random_val = u64::from_le_bytes(buf);
            let j = (random_val % (i as u64 + 1)) as usize;
            alive_peers.swap(i, j);
        }
        alive_peers.truncate(max_count);

        alive_peers
    }

    /// Get all alive peers.
    ///
    /// # Returns
    /// Vector of all peers with state == Alive
    pub fn get_alive_peers(&self) -> Vec<PeerInfo> {
        let mut result = Vec::with_capacity(self.peer_count.load(Ordering::Relaxed) as usize);

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.state() == PeerState::Alive {
                    result.push(*peer);
                }
            }
        }

        result
    }

    /// Get all peers regardless of state.
    ///
    /// # Returns
    /// Vector of all peer infos
    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        let mut result = Vec::with_capacity(self.peer_count.load(Ordering::Relaxed) as usize);

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                result.push(*peer);
            }
        }

        result
    }

    /// Check for suspect timeouts and mark dead.
    ///
    /// # Arguments
    /// * `now_ns` - Current time in nanoseconds
    ///
    /// # Returns
    /// Vector of actor IDs that were marked dead
    pub fn check_timeouts(&mut self, now_ns: u64) -> Vec<ActorId> {
        let timeout_ns = SUSPECT_TIMEOUT_MS * 1_000_000;
        let mut marked_dead = Vec::new();

        for i in 0..MAX_PEERS {
            if let Some(ref peer) = self.peers[i] {
                if peer.state() == PeerState::Suspect {
                    let elapsed = now_ns.saturating_sub(peer.last_seen_ns());
                    if elapsed > timeout_ns {
                        let actor_id = peer.actor_id();
                        // Mark dead (modifying in place requires care)
                        if let Some(ref mut p) = self.peers[i] {
                            p.set_state(PeerState::Dead);
                            p.set_last_seen_ns(now_ns);
                            marked_dead.push(actor_id);
                        }
                    }
                }
            }
        }

        // Postcondition: no suspect peers older than timeout remain
        #[cfg(debug_assertions)]
        {
            for i in 0..MAX_PEERS {
                if let Some(ref peer) = self.peers[i] {
                    if peer.state() == PeerState::Suspect {
                        let elapsed = now_ns.saturating_sub(peer.last_seen_ns());
                        debug_assert!(
                            elapsed <= timeout_ns,
                            "suspect peer should have been marked dead"
                        );
                    }
                }
            }
        }

        marked_dead
    }

    /// Update last_seen_ns for a peer.
    pub fn touch(&mut self, actor_id: ActorId) {
        let now_ns = current_time_ns();
        for i in 0..MAX_PEERS {
            if let Some(ref mut peer) = self.peers[i] {
                if peer.actor_id() == actor_id {
                    peer.set_last_seen_ns(now_ns);
                    return;
                }
            }
        }
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

    fn test_addr(port: u16) -> SocketAddr {
        use std::net::{IpAddr, Ipv4Addr};
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, port as u8)), port)
    }

    #[test]
    fn test_new() {
        let list = MembershipList::new(5);

        assert_eq!(list.local_actor(), 5);
        assert_eq!(list.peer_count(), 0);
        assert_eq!(list.local_incarnation(), 1);
    }

    #[test]
    #[should_panic(expected = "local_actor must be < MAX_ACTORS")]
    fn test_new_invalid_actor() {
        let _ = MembershipList::new(MAX_ACTORS as u64);
    }

    #[test]
    fn test_add_peer() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        assert_eq!(list.peer_count(), 1);

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.actor_id(), 2);
        assert_eq!(peer.state(), PeerState::Alive);
        assert_eq!(peer.incarnation(), 0);
    }

    #[test]
    fn test_add_multiple_peers() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(3, test_addr(7947)).unwrap();
        list.add_peer(4, test_addr(7948)).unwrap();

        assert_eq!(list.peer_count(), 3);
        assert!(list.find_peer(2).is_some());
        assert!(list.find_peer(3).is_some());
        assert!(list.find_peer(4).is_some());
    }

    #[test]
    fn test_add_duplicate_peer() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(2, test_addr(7946)).unwrap(); // Duplicate

        assert_eq!(list.peer_count(), 1);
    }

    #[test]
    fn test_add_duplicate_peer_updates_address() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(2, test_addr(8000)).unwrap(); // Different address

        assert_eq!(list.peer_count(), 1);
        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.addr().port(), 8000);
    }

    #[test]
    #[should_panic(expected = "cannot add self to peer list")]
    fn test_add_self() {
        let mut list = MembershipList::new(5);
        let _ = list.add_peer(5, test_addr(7946));
    }

    #[test]
    fn test_remove_peer() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        assert_eq!(list.peer_count(), 1);

        list.remove_peer(2).unwrap();
        assert_eq!(list.peer_count(), 0);
        assert!(list.find_peer(2).is_none());
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let mut list = MembershipList::new(1);

        let result = list.remove_peer(99);
        assert!(matches!(result, Err(GossipError::PeerNotFound { actor_id: 99 })));
    }

    #[test]
    fn test_state_transition_alive_to_suspect() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.update_state(2, PeerState::Suspect, 0).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Suspect);
    }

    #[test]
    fn test_state_transition_suspect_to_dead() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.update_state(2, PeerState::Suspect, 0).unwrap();
        list.update_state(2, PeerState::Dead, 0).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Dead);
    }

    #[test]
    fn test_state_transition_suspect_to_alive_refutation() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.update_state(2, PeerState::Suspect, 5).unwrap();

        // Refutation with higher incarnation
        list.update_state(2, PeerState::Alive, 6).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Alive);
        assert_eq!(peer.incarnation(), 6);
    }

    #[test]
    fn test_state_transition_suspect_to_alive_same_incarnation_fails() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.update_state(2, PeerState::Suspect, 5).unwrap();

        // Cannot refute with same incarnation
        let result = list.update_state(2, PeerState::Alive, 5);
        assert!(matches!(
            result,
            Err(GossipError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn test_state_transition_dead_to_alive_resurrection() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.mark_dead(2).unwrap();

        // Resurrection with higher incarnation
        list.update_state(2, PeerState::Alive, u64::MAX).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Alive);
    }

    #[test]
    fn test_mark_alive_self_increments_incarnation() {
        let mut list = MembershipList::new(5);

        assert_eq!(list.local_incarnation(), 1);
        list.mark_alive(5, 10).unwrap();
        assert!(list.local_incarnation() > 10);
    }

    #[test]
    fn test_mark_suspect() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.mark_suspect(2, 0).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Suspect);
    }

    #[test]
    #[should_panic(expected = "cannot suspect self")]
    fn test_mark_suspect_self() {
        let mut list = MembershipList::new(5);
        let _ = list.mark_suspect(5, 0);
    }

    #[test]
    fn test_mark_dead() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.mark_dead(2).unwrap();

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Dead);
    }

    #[test]
    #[should_panic(expected = "cannot mark self as dead")]
    fn test_mark_dead_self() {
        let mut list = MembershipList::new(5);
        let _ = list.mark_dead(5);
    }

    #[test]
    fn test_get_random_alive_peer_empty() {
        let list = MembershipList::new(1);
        assert!(list.get_random_alive_peer().is_none());
    }

    #[test]
    fn test_get_random_alive_peer() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(3, test_addr(7947)).unwrap();

        let peer = list.get_random_alive_peer().unwrap();
        assert!(peer.actor_id() == 2 || peer.actor_id() == 3);
    }

    #[test]
    fn test_get_random_alive_peer_skips_dead() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(3, test_addr(7947)).unwrap();
        list.mark_dead(2).unwrap();

        // Should only return peer 3
        for _ in 0..10 {
            let peer = list.get_random_alive_peer().unwrap();
            assert_eq!(peer.actor_id(), 3);
        }
    }

    #[test]
    fn test_get_random_alive_peers() {
        let mut list = MembershipList::new(1);

        for i in 2..10u64 {
            list.add_peer(i, test_addr(7946 + i as u16)).unwrap();
        }

        let peers = list.get_random_alive_peers(3, 5);
        assert_eq!(peers.len(), 3);
        for peer in &peers {
            assert_ne!(peer.actor_id(), 5); // Excluded
        }
    }

    #[test]
    fn test_get_alive_peers() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(3, test_addr(7947)).unwrap();
        list.add_peer(4, test_addr(7948)).unwrap();
        list.mark_dead(3).unwrap();

        let alive = list.get_alive_peers();
        assert_eq!(alive.len(), 2);
    }

    #[test]
    fn test_get_all_peers() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.add_peer(3, test_addr(7947)).unwrap();
        list.mark_dead(3).unwrap();

        let all = list.get_all_peers();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_check_timeouts() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.mark_suspect(2, 0).unwrap();

        // Simulate time passing beyond suspect timeout
        let future_ns = current_time_ns() + (SUSPECT_TIMEOUT_MS + 1000) * 1_000_000;
        let marked = list.check_timeouts(future_ns);

        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0], 2);

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Dead);
    }

    #[test]
    fn test_check_timeouts_no_change_if_not_expired() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        list.mark_suspect(2, 0).unwrap();

        // Check immediately (not enough time passed)
        let marked = list.check_timeouts(current_time_ns());
        assert!(marked.is_empty());

        let peer = list.find_peer(2).unwrap();
        assert_eq!(peer.state(), PeerState::Suspect);
    }

    #[test]
    fn test_increment_incarnation() {
        let list = MembershipList::new(1);

        assert_eq!(list.local_incarnation(), 1);
        assert_eq!(list.increment_incarnation(), 2);
        assert_eq!(list.local_incarnation(), 2);
        assert_eq!(list.increment_incarnation(), 3);
    }

    #[test]
    fn test_touch() {
        let mut list = MembershipList::new(1);

        list.add_peer(2, test_addr(7946)).unwrap();
        let before = list.find_peer(2).unwrap().last_seen_ns();

        std::thread::sleep(std::time::Duration::from_millis(10));
        list.touch(2);

        let after = list.find_peer(2).unwrap().last_seen_ns();
        assert!(after > before);
    }
}
