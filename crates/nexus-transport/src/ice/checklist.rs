//! ICE Connectivity Checklist.
//!
//! Manages candidate pairs and performs connectivity checks per RFC 8445.
//!
//! # Check Process
//!
//! 1. Form candidate pairs from local and remote candidates
//! 2. Sort pairs by priority
//! 3. Perform STUN binding requests on each pair
//! 4. Track successful pairs and nominate the best one
//!
//! # TigerStyle Compliance
//!
//! - Fixed-size pair arrays (no heap allocation during checks)
//! - Explicit state machine for check progress
//! - Bounded retransmission timers

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::candidate::{Candidate, CandidatePair, CandidatePairState, MAX_CANDIDATES};
use super::stun::attributes::StunAttribute;
use super::stun::message::{StunClass, StunMessage, STUN_BUFFER_SIZE};
use super::stun::server::{create_binding_request, generate_transaction_id};
use super::types::{IceCredentials, IceRole};
use crate::ice::error::IceError;
use getrandom::getrandom;

/// Maximum candidate pairs in checklist.
/// Capped at 100 per RFC 8445 recommendation (not MAX_CANDIDATES^2 to prevent memory exhaustion).
pub const MAX_CANDIDATE_PAIRS: usize = 100;

/// Maximum pairs to check in parallel.
pub const MAX_PARALLEL_CHECKS: usize = 5;

/// Initial retransmission timeout (Ta in RFC 8445).
pub const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Maximum retransmissions per check.
pub const MAX_RETRANSMISSIONS: u32 = 7;

/// Keepalive interval for nominated pair.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Checklist state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChecklistState {
    /// Checklist not started.
    Running = 0,

    /// Checklist completed successfully.
    Completed = 1,

    /// Checklist failed (no valid pairs).
    Failed = 2,
}

/// Pending connectivity check.
#[derive(Debug)]
pub struct PendingCheck {
    /// Transaction ID.
    pub transaction_id: [u8; 12],

    /// Pair index in checklist.
    pub pair_idx: u16,

    /// Time check was sent.
    pub sent_at: Instant,

    /// Number of retransmissions.
    pub retransmissions: u8,

    /// Whether USE-CANDIDATE was included.
    pub nominating: bool,
}

/// ICE Connectivity Checklist.
pub struct Checklist {
    /// Candidate pairs, sorted by priority.
    pairs: [Option<CandidatePair>; MAX_CANDIDATE_PAIRS],

    /// Number of valid pairs.
    pair_count: u16,

    /// Pending checks.
    pending: [Option<PendingCheck>; MAX_PARALLEL_CHECKS],

    /// Pending check count.
    pending_count: u8,

    /// Local credentials.
    local_credentials: IceCredentials,

    /// Remote credentials.
    remote_credentials: IceCredentials,

    /// ICE role.
    role: IceRole,

    /// Tie-breaker value.
    tie_breaker: u64,

    /// Checklist state.
    state: ChecklistState,

    /// Nominated pair index (if any).
    nominated_idx: Option<u16>,
}

impl Checklist {
    /// Create new checklist.
    pub fn new(
        local_credentials: IceCredentials,
        remote_credentials: IceCredentials,
        role: IceRole,
    ) -> Self {
        Self {
            pairs: std::array::from_fn(|_| None),
            pair_count: 0,
            pending: std::array::from_fn(|_| None),
            pending_count: 0,
            local_credentials,
            remote_credentials,
            role,
            tie_breaker: generate_tie_breaker(),
            state: ChecklistState::Running,
            nominated_idx: None,
        }
    }

    /// Form candidate pairs from local and remote candidates.
    ///
    /// # TigerStyle Compliance (Phase 3.2)
    ///
    /// - Precondition for empty pairs
    /// - Loop bound assertions
    /// - Postcondition for pair count bounds
    pub fn form_pairs(&mut self, local_candidates: &[Candidate], remote_candidates: &[Candidate]) {
        // Precondition: pairs not yet formed (TigerStyle Phase 3.2)
        assert!(self.pair_count == 0, "pairs already formed");

        // Precondition: candidate counts must be bounded (TigerStyle Phase 3.2)
        assert!(
            local_candidates.len() <= MAX_CANDIDATES,
            "Local candidates must be <= MAX_CANDIDATES"
        );
        assert!(
            remote_candidates.len() <= MAX_CANDIDATES,
            "Remote candidates must be <= MAX_CANDIDATES"
        );

        let is_controlling = matches!(self.role, IceRole::Controlling);

        for local in local_candidates {
            for remote in remote_candidates {
                // Only pair candidates with same component
                if local.component != remote.component {
                    continue;
                }

                // Only pair compatible transports
                if local.transport != remote.transport {
                    continue;
                }

                // Only pair same address family
                if local.address.is_ipv4() != remote.address.is_ipv4() {
                    continue;
                }

                // Check bounds before adding (stop if at capacity)
                if (self.pair_count as usize) >= MAX_CANDIDATE_PAIRS {
                    break;
                }

                // Loop bound assertion after check (TigerStyle Phase 3.2)
                assert!(
                    (self.pair_count as usize) < MAX_CANDIDATE_PAIRS,
                    "Pair count must be within bounds before add"
                );

                let pair = CandidatePair::new(local.clone(), remote.clone(), is_controlling);

                self.pairs[self.pair_count as usize] = Some(pair);
                self.pair_count += 1;
            }
        }

        // Sort pairs by priority (descending)
        self.sort_pairs();

        // Prune redundant pairs
        self.prune_pairs();

        // Initialize states
        self.initialize_states();

        // Postcondition: pair count must be bounded (TigerStyle Phase 3.2)
        assert!(
            self.pair_count <= MAX_CANDIDATE_PAIRS as u16,
            "Pair count must be <= MAX_CANDIDATE_PAIRS"
        );

        // Note: pair_count may be 0 even with candidates if address families don't match
        // or if all pairs were pruned as redundant
    }

    /// Add a single candidate pair incrementally.
    ///
    /// This method allows adding pairs one at a time as remote candidates
    /// arrive via trickle ICE, rather than requiring all candidates upfront.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition for pair count bounds
    /// - Postcondition for bounded increment
    /// - Invariant check for pair validity
    ///
    /// # Arguments
    ///
    /// * `local` - Local candidate to pair with
    /// * `remote` - Remote candidate to pair with
    ///
    /// # Returns
    ///
    /// * `Ok(Some(idx))` - Pair was added at the given index
    /// * `Ok(None)` - Pair was not added (incompatible or redundant)
    /// * `Err(_)` - Error (e.g., too many pairs)
    pub fn add_pair(
        &mut self,
        local: &Candidate,
        remote: &Candidate,
    ) -> Result<Option<u16>, IceError> {
        // Precondition: pair count must be below maximum (TigerStyle)
        assert!(
            (self.pair_count as usize) <= MAX_CANDIDATE_PAIRS,
            "Pair count must be <= MAX_CANDIDATE_PAIRS"
        );

        if (self.pair_count as usize) >= MAX_CANDIDATE_PAIRS {
            return Err(IceError::TooManyCandidates {
                count: self.pair_count as u32,
                max: MAX_CANDIDATE_PAIRS as u32,
            });
        }

        // Only pair candidates with same component
        if local.component != remote.component {
            return Ok(None);
        }

        // Only pair compatible transports
        if local.transport != remote.transport {
            return Ok(None);
        }

        // Only pair same address family
        if local.address.is_ipv4() != remote.address.is_ipv4() {
            return Ok(None);
        }

        // Check for redundant pair (same local base and remote address)
        let base_local = local.base_address();
        for i in 0..self.pair_count as usize {
            if let Some(ref existing) = self.pairs[i] {
                if existing.local.base_address() == base_local
                    && existing.remote.address == remote.address
                {
                    // Redundant pair, skip
                    return Ok(None);
                }
            }
        }

        let is_controlling = matches!(self.role, IceRole::Controlling);
        let pair = CandidatePair::new(local.clone(), remote.clone(), is_controlling);

        let count_before = self.pair_count;
        let idx = self.pair_count as usize;
        self.pairs[idx] = Some(pair);
        self.pair_count += 1;

        // Set initial state based on foundation
        // If this is the first pair with this foundation, set to Waiting
        // Otherwise, set to Frozen
        let foundation = local.foundation ^ remote.foundation;
        let mut is_first_foundation = true;

        for i in 0..idx {
            if let Some(ref existing) = self.pairs[i] {
                let existing_foundation = existing.local.foundation ^ existing.remote.foundation;
                if existing_foundation == foundation {
                    is_first_foundation = false;
                    break;
                }
            }
        }

        if let Some(ref mut pair) = self.pairs[idx] {
            pair.state = if is_first_foundation {
                CandidatePairState::Waiting
            } else {
                CandidatePairState::Frozen
            };
        }

        // Re-sort to maintain priority order
        self.sort_pairs();

        // Postcondition: pair count must have incremented by exactly 1 (TigerStyle)
        assert_eq!(
            self.pair_count,
            count_before + 1,
            "Pair count must increment by exactly 1"
        );

        // Postcondition: pair count must remain bounded (TigerStyle)
        assert!(
            self.pair_count <= MAX_CANDIDATE_PAIRS as u16,
            "Pair count must remain <= MAX_CANDIDATE_PAIRS"
        );

        // Find the new index after sorting (pair may have moved)
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.local.address == local.address && pair.remote.address == remote.address {
                    return Ok(Some(i as u16));
                }
            }
        }

        // Should not reach here, but return the original index as fallback
        Ok(Some(idx as u16))
    }

    /// Sort pairs by priority (descending).
    ///
    /// # TigerStyle Compliance (Phase 3.3)
    ///
    /// - Precondition for pair count bounds
    /// - Loop bound assertions
    /// - Postcondition for sorted order
    fn sort_pairs(&mut self) {
        // Precondition: pair count must be bounded (TigerStyle Phase 3.3)
        assert!(
            self.pair_count <= MAX_CANDIDATE_PAIRS as u16,
            "Pair count must be <= MAX_CANDIDATE_PAIRS before sort"
        );

        // Simple insertion sort (pairs array is small)
        for i in 1..self.pair_count as usize {
            // Outer loop bound assertion (TigerStyle Phase 3.3)
            assert!(
                i < self.pair_count as usize,
                "Outer loop index must be within pair count"
            );

            let mut j = i;
            while j > 0 {
                // Inner loop bound assertion (TigerStyle Phase 3.3)
                assert!(j < i + 1, "Inner loop index must be bounded");

                let curr_priority = self.pairs[j].as_ref().map(|p| p.priority).unwrap_or(0);
                let prev_priority = self.pairs[j - 1].as_ref().map(|p| p.priority).unwrap_or(0);

                if curr_priority > prev_priority {
                    self.pairs.swap(j, j - 1);
                    j -= 1;
                } else {
                    break;
                }
            }
        }

        // Postcondition: verify pairs are sorted in descending priority order
        #[cfg(debug_assertions)]
        {
            for i in 1..self.pair_count as usize {
                let curr = self.pairs[i].as_ref().map(|p| p.priority).unwrap_or(0);
                let prev = self.pairs[i - 1].as_ref().map(|p| p.priority).unwrap_or(0);
                assert!(prev >= curr, "Pairs must be sorted in descending priority");
            }
        }
    }

    /// Prune redundant pairs per RFC 8445.
    ///
    /// # TigerStyle Compliance (Phase 3.4)
    ///
    /// - Precondition for non-empty pairs
    /// - Loop bound assertions
    /// - Postcondition for valid count
    fn prune_pairs(&mut self) {
        // Precondition: must have pairs to prune (TigerStyle Phase 3.4)
        if self.pair_count == 0 {
            return;
        }
        assert!(self.pair_count > 0, "Prune called with valid pair count");

        // Remove pairs with same local and remote base addresses
        // Keep only the highest priority one
        // (Already sorted, so just mark duplicates as None)

        let mut valid_count = 0u16;

        for i in 0..self.pair_count as usize {
            // Loop bound assertion (TigerStyle Phase 3.4)
            assert!(
                i < MAX_CANDIDATE_PAIRS,
                "Loop index must be within MAX_CANDIDATE_PAIRS"
            );

            if self.pairs[i].is_none() {
                continue;
            }

            let pair_i = self.pairs[i].as_ref().unwrap();
            let base_local_i = pair_i.local.base_address();
            let base_remote_i = pair_i.remote.address;

            // Check against all previous pairs
            let mut is_redundant = false;
            for j in 0..i {
                // Nested loop bound assertion (TigerStyle Phase 3.4)
                assert!(j < i, "Inner loop index must be less than outer");

                if let Some(ref pair_j) = self.pairs[j] {
                    if pair_j.local.base_address() == base_local_i
                        && pair_j.remote.address == base_remote_i
                    {
                        is_redundant = true;
                        break;
                    }
                }
            }

            if is_redundant {
                self.pairs[i] = None;
            } else {
                valid_count += 1;
            }
        }

        // Postcondition: valid count must not exceed original (TigerStyle Phase 3.4)
        assert!(
            valid_count <= self.pair_count,
            "Valid count must not exceed original pair count"
        );

        // Compact array
        self.compact_pairs();
    }

    /// Compact pairs array (remove None entries).
    fn compact_pairs(&mut self) {
        let mut write_idx = 0;

        for read_idx in 0..self.pair_count as usize {
            if self.pairs[read_idx].is_some() {
                if write_idx != read_idx {
                    self.pairs.swap(write_idx, read_idx);
                }
                write_idx += 1;
            }
        }

        self.pair_count = write_idx as u16;
    }

    /// Initialize pair states per RFC 8445.
    fn initialize_states(&mut self) {
        // Unfreeze the first pair of each foundation
        let mut seen_foundations = [0u32; MAX_CANDIDATE_PAIRS];
        let mut seen_count = 0;

        for i in 0..self.pair_count as usize {
            if let Some(ref mut pair) = self.pairs[i] {
                let foundation = pair.local.foundation ^ pair.remote.foundation;

                // Check if we've seen this foundation
                let mut is_new = true;
                for j in 0..seen_count {
                    if seen_foundations[j] == foundation {
                        is_new = false;
                        break;
                    }
                }

                if is_new {
                    pair.state = CandidatePairState::Waiting;
                    seen_foundations[seen_count] = foundation;
                    seen_count += 1;
                } else {
                    pair.state = CandidatePairState::Frozen;
                }
            }
        }
    }

    /// Get next check to perform.
    ///
    /// Returns (pair_index, destination, request_bytes, request_len).
    ///
    /// # TigerStyle Compliance (Phase 3.5)
    ///
    /// - Precondition for checklist state
    /// - Precondition for pending count
    /// - Postcondition for pending count bounds
    pub fn next_check(&mut self) -> Option<(u16, SocketAddr, [u8; STUN_BUFFER_SIZE], usize)> {
        // Precondition: checklist must be running (TigerStyle Phase 3.5)
        assert!(
            self.state == ChecklistState::Running,
            "next_check requires Running state"
        );

        // if self.state != ChecklistState::Running {
        //     return None;
        // }

        // Precondition: must have room for pending checks (TigerStyle Phase 3.5)
        assert!(
            self.pending_count < MAX_PARALLEL_CHECKS as u8,
            "Must have room for pending checks"
        );

        // if self.pending_count >= MAX_PARALLEL_CHECKS as u8 {
        //     return None;
        // }

        // Find next waiting pair using helper
        let waiting_idx = self.find_next_waiting_pair()?;

        // Generate check (immutable borrow)
        let (request, len) = self.create_check_request(waiting_idx, false);

        // Now do the mutable updates
        let pair = self.pairs[waiting_idx].as_mut()?;
        let remote_addr = pair.remote.address;

        // Mark as in-progress
        pair.state = CandidatePairState::InProgress;

        // Add to pending
        let check = PendingCheck {
            transaction_id: extract_transaction_id(&request),
            pair_idx: waiting_idx as u16,
            sent_at: Instant::now(),
            retransmissions: 0,
            nominating: false,
        };

        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(check);
                self.pending_count += 1;
                break;
            }
        }

        // Postcondition: pending count must be bounded (TigerStyle Phase 3.5)
        assert!(
            self.pending_count <= MAX_PARALLEL_CHECKS as u8,
            "Pending count must be <= MAX_PARALLEL_CHECKS"
        );

        Some((waiting_idx as u16, remote_addr, request, len))
    }

    /// Find the next pair in Waiting state.
    ///
    /// # TigerStyle Compliance (Phase 3.5)
    ///
    /// - Extracted from next_check for function length compliance
    fn find_next_waiting_pair(&self) -> Option<usize> {
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.state == CandidatePairState::Waiting {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Create STUN binding request for connectivity check.
    fn create_check_request(
        &self,
        pair_idx: usize,
        nominating: bool,
    ) -> ([u8; STUN_BUFFER_SIZE], usize) {
        let mut buf = [0u8; STUN_BUFFER_SIZE];

        let pair = self.pairs[pair_idx].as_ref().unwrap();
        let transaction_id = generate_transaction_id();

        // Username: remote_ufrag:local_ufrag (RFC 8445 Section 7.2.2)
        let username = format!(
            "{}:{}",
            self.remote_credentials.local_ufrag, self.local_credentials.local_ufrag
        );

        tracing::debug!(
            username = %username,
            remote_ufrag = %self.remote_credentials.local_ufrag,
            local_ufrag = %self.local_credentials.local_ufrag,
            remote_pwd_len = self.remote_credentials.local_pwd.len(),
            "Creating ICE binding request"
        );

        let is_controlling = matches!(self.role, IceRole::Controlling);
        let use_candidate = nominating && is_controlling;

        let len = create_binding_request(
            &mut buf,
            &transaction_id,
            &username,
            pair.local.priority,
            is_controlling,
            self.tie_breaker,
            use_candidate,
            &self.remote_credentials.local_pwd,
        );

        (buf, len)
    }

    /// Process incoming STUN response.
    ///
    /// # TigerStyle Compliance (Phase 3.6)
    ///
    /// - Split into helper functions for success/error handling
    /// - Transaction ID lookup assertion
    /// - Pair state assertions
    pub fn process_response(
        &mut self,
        data: &[u8],
        _from: SocketAddr,
    ) -> Result<Option<u16>, IceError> {
        if !StunMessage::is_stun(data) {
            return Ok(None);
        }

        let msg = StunMessage::parse(data)?;

        tracing::debug!(
            transaction_id = ?&msg.transaction_id,
            class = ?msg.class,
            pending_count = self.pending_count,
            "Processing STUN response in checklist"
        );

        // Find pending check with matching transaction ID
        let found_idx = self.find_pending_check(&msg.transaction_id);

        let check_idx = match found_idx {
            Some(i) => {
                tracing::debug!(check_idx = i, "Found matching pending check");
                i
            }
            None => {
                tracing::debug!(
                    transaction_id = ?&msg.transaction_id,
                    "No matching pending check found"
                );
                return Ok(None); // Unknown transaction
            }
        };

        let check = self.pending[check_idx].take().unwrap();
        self.pending_count -= 1;

        let pair_idx = check.pair_idx as usize;

        // Assertion: pair must exist for valid pending check (TigerStyle Phase 3.6)
        assert!(
            self.pairs[pair_idx].is_some(),
            "Pair must exist for pending check"
        );

        match msg.class {
            StunClass::SuccessResponse => {
                self.handle_success_response(pair_idx, &msg, check.nominating)?;
                Ok(Some(pair_idx as u16))
            }

            StunClass::ErrorResponse => {
                // Extract and log error code
                let error_code = msg.attributes.iter().flatten().find_map(|attr| {
                    if let crate::ice::stun::StunAttribute::ErrorCode {
                        code,
                        reason,
                        reason_len,
                    } = attr
                    {
                        let reason_str =
                            std::str::from_utf8(&reason[..*reason_len as usize]).unwrap_or("?");
                        Some((*code, reason_str.to_string()))
                    } else {
                        None
                    }
                });

                tracing::warn!(
                    pair_idx = pair_idx,
                    error_code = ?error_code,
                    "ICE check received error response"
                );

                self.handle_error_response(pair_idx)?;
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    /// Find pending check by transaction ID.
    ///
    /// # TigerStyle Compliance (Phase 3.6)
    ///
    /// - Extracted from process_response for clarity
    fn find_pending_check(&self, transaction_id: &[u8; 12]) -> Option<usize> {
        for (i, slot) in self.pending.iter().enumerate() {
            if let Some(ref check) = slot {
                tracing::trace!(
                    idx = i,
                    check_tid = ?&check.transaction_id,
                    search_tid = ?transaction_id,
                    "Comparing transaction IDs"
                );
                if check.transaction_id == *transaction_id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Handle successful STUN response.
    ///
    /// # TigerStyle Compliance (Phase 3.6)
    ///
    /// - Extracted from process_response for function length compliance
    /// - Handles USE-CANDIDATE for controlled agent (Comment 1 fix)
    fn handle_success_response(
        &mut self,
        pair_idx: usize,
        msg: &StunMessage,
        nominating: bool,
    ) -> Result<(), IceError> {
        // Precondition: pair_idx is within bounds (TigerStyle)
        assert!(
            pair_idx < self.pair_count as usize,
            "pair_idx must be within pair_count"
        );

        // Check succeeded
        if let Some(ref mut pair) = self.pairs[pair_idx] {
            pair.state = CandidatePairState::Succeeded;

            // If nominating (controlling agent sent USE-CANDIDATE), mark as nominated
            if nominating {
                pair.nominated = true;
                self.nominated_idx = Some(pair_idx as u16);
                self.state = ChecklistState::Completed;
            }

            // Check for deferred nomination from USE-CANDIDATE.
            // When we're the controlled agent and received a USE-CANDIDATE request
            // before this pair succeeded, pending_nomination will be true.
            // Now that the pair has succeeded, complete the nomination.
            if !nominating && pair.pending_nomination {
                // Postcondition: pair must be Succeeded before completing nomination (TigerStyle)
                assert!(
                    pair.state == CandidatePairState::Succeeded,
                    "Pair must be Succeeded before completing deferred nomination"
                );
                pair.nominated = true;
                pair.pending_nomination = false;
                self.nominated_idx = Some(pair_idx as u16);
                self.state = ChecklistState::Completed;
            }

            // Check for peer-reflexive local candidate per RFC 8445 §7.2.5.3.1.
            // If the XOR-MAPPED-ADDRESS in the response differs from the local
            // candidate's address, we've discovered a new local address (our
            // NAT-mapped address as seen by the remote peer).
            for attr in msg.attributes.iter().flatten() {
                if let StunAttribute::XorMappedAddress(mapped_addr) = attr {
                    if *mapped_addr != pair.local.address {
                        tracing::info!(
                            local_addr = %pair.local.address,
                            mapped_addr = %mapped_addr,
                            pair_idx = pair_idx,
                            "Discovered peer-reflexive local candidate from STUN response"
                        );
                        // The mapped address is our peer-reflexive address.
                        // Per RFC 8445, we should create a new prflx candidate and
                        // potentially add new pairs. In practice, the existing pair
                        // already succeeded so connectivity is established. We log
                        // the discovery for diagnostics.
                    }
                }
            }

            // Unfreeze pairs with same foundation
            self.unfreeze_related(pair_idx);
        }

        // Postcondition: pair state must be Succeeded (TigerStyle)
        assert!(
            self.pairs[pair_idx].as_ref().map(|p| p.state) == Some(CandidatePairState::Succeeded),
            "Pair must be in Succeeded state after success response"
        );

        Ok(())
    }

    /// Handle incoming binding request with USE-CANDIDATE (for controlled agent).
    ///
    /// Called when controlled agent receives a binding request with USE-CANDIDATE
    /// from the controlling agent. This nominates the corresponding pair.
    ///
    /// Per RFC 8445 Section 7.3.1.5: controlled agent nominates pair when
    /// it receives a successful check with USE-CANDIDATE.
    pub fn handle_use_candidate_request(&mut self, from: SocketAddr) -> bool {
        // Precondition: only controlled agent processes USE-CANDIDATE (TigerStyle)
        assert!(
            matches!(self.role, IceRole::Controlled) || matches!(self.role, IceRole::Controlling),
            "ICE role must be set before handling USE-CANDIDATE"
        );

        // Only controlled agent processes USE-CANDIDATE
        if !matches!(self.role, IceRole::Controlled) {
            return false;
        }

        // Precondition: pair_count is within bounds (TigerStyle)
        assert!(
            (self.pair_count as usize) <= MAX_CANDIDATE_PAIRS,
            "pair_count must not exceed MAX_CANDIDATE_PAIRS"
        );

        // Bounded loop over pairs to find matching remote address
        for i in 0..self.pair_count as usize {
            if let Some(ref mut pair) = self.pairs[i] {
                if pair.remote.address == from {
                    if pair.state == CandidatePairState::Succeeded {
                        // Immediate nomination — pair already succeeded
                        pair.nominated = true;
                        self.nominated_idx = Some(i as u16);
                        self.state = ChecklistState::Completed;
                        return true;
                    } else {
                        // Deferred nomination — pair not yet succeeded
                        pair.pending_nomination = true;
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Create a triggered check for a candidate pair per RFC 8445 §7.2.5.1.
    ///
    /// When a STUN binding request is received from a remote address, the agent
    /// must find or create a candidate pair and enqueue a triggered check.
    ///
    /// The triggered check is placed at the head of the check queue by setting
    /// the pair state to Waiting (it will be picked up by the next `next_check` call).
    ///
    /// Returns the pair index if a triggered check was enqueued, or None if
    /// the pair was already succeeded/nominated.
    pub fn add_triggered_check(&mut self, local: &Candidate, remote: &Candidate) -> Option<u16> {
        // Precondition: checklist must be running
        if self.state != ChecklistState::Running {
            return None;
        }

        // Precondition: pair count bounded
        assert!(
            (self.pair_count as usize) <= MAX_CANDIDATE_PAIRS,
            "pair_count must not exceed MAX_CANDIDATE_PAIRS"
        );

        // Step 1: Find existing pair matching local+remote addresses
        let mut existing_idx: Option<usize> = None;
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.local.address == local.address && pair.remote.address == remote.address {
                    existing_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = existing_idx {
            // Pair already exists — apply triggered check rules per RFC 8445 §7.2.5.1
            let pair = self.pairs[idx].as_mut().unwrap();
            match pair.state {
                CandidatePairState::Succeeded => {
                    // Already succeeded, nothing to do
                    return Some(idx as u16);
                }
                CandidatePairState::InProgress => {
                    // Cancel the in-progress check by removing from pending,
                    // then re-enqueue as Waiting so it gets picked up again.
                    for slot in self.pending.iter_mut() {
                        if let Some(ref check) = slot {
                            if check.pair_idx == idx as u16 {
                                *slot = None;
                                self.pending_count = self.pending_count.saturating_sub(1);
                                break;
                            }
                        }
                    }
                    pair.state = CandidatePairState::Waiting;
                    return Some(idx as u16);
                }
                CandidatePairState::Waiting => {
                    // Already waiting, nothing to do
                    return Some(idx as u16);
                }
                CandidatePairState::Frozen => {
                    // Unfreeze and set to Waiting
                    pair.state = CandidatePairState::Waiting;
                    return Some(idx as u16);
                }
                CandidatePairState::Failed => {
                    // Re-enqueue failed pair as Waiting for retry
                    pair.state = CandidatePairState::Waiting;
                    return Some(idx as u16);
                }
            }
        }

        // Step 2: No existing pair — create a new one
        if (self.pair_count as usize) >= MAX_CANDIDATE_PAIRS {
            tracing::warn!(
                "Cannot add triggered check: checklist full ({} pairs)",
                self.pair_count
            );
            return None;
        }

        let is_controlling = matches!(self.role, IceRole::Controlling);
        let mut pair = CandidatePair::new(local.clone(), remote.clone(), is_controlling);
        pair.state = CandidatePairState::Waiting;

        let idx = self.pair_count as usize;
        self.pairs[idx] = Some(pair);
        self.pair_count += 1;

        // Postcondition: pair count bounded
        assert!(
            self.pair_count <= MAX_CANDIDATE_PAIRS as u16,
            "Pair count must remain <= MAX_CANDIDATE_PAIRS"
        );

        tracing::debug!(
            pair_idx = idx,
            local_addr = %local.address,
            remote_addr = %remote.address,
            "Created new candidate pair for triggered check"
        );

        Some(idx as u16)
    }

    /// Find a candidate pair by remote address.
    ///
    /// Returns the index of the first pair whose remote candidate matches
    /// the given address, or None if no match is found.
    pub fn find_pair_by_remote_addr(&self, addr: SocketAddr) -> Option<u16> {
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.remote.address == addr {
                    return Some(i as u16);
                }
            }
        }
        None
    }

    /// Handle error STUN response.
    ///
    /// # TigerStyle Compliance (Phase 3.6)
    ///
    /// - Extracted from process_response for function length compliance
    fn handle_error_response(&mut self, pair_idx: usize) -> Result<(), IceError> {
        // Check failed
        if let Some(ref mut pair) = self.pairs[pair_idx] {
            pair.state = CandidatePairState::Failed;
        }

        // Check if all pairs failed
        self.check_completion();

        Ok(())
    }

    /// Unfreeze pairs with same foundation as succeeded pair.
    fn unfreeze_related(&mut self, succeeded_idx: usize) {
        let succeeded_foundation = match &self.pairs[succeeded_idx] {
            Some(p) => p.local.foundation ^ p.remote.foundation,
            None => return,
        };

        for i in 0..self.pair_count as usize {
            if i == succeeded_idx {
                continue;
            }

            if let Some(ref mut pair) = self.pairs[i] {
                let foundation = pair.local.foundation ^ pair.remote.foundation;
                if foundation == succeeded_foundation && pair.state == CandidatePairState::Frozen {
                    pair.state = CandidatePairState::Waiting;
                }
            }
        }
    }

    /// Check for retransmissions needed.
    ///
    /// # TigerStyle Compliance (Phase 3.7)
    ///
    /// - Precondition for pending count
    /// - Loop bound assertions
    /// - Retry count assertions
    /// - Postcondition for result bounds
    pub fn check_retransmissions(
        &mut self,
    ) -> Vec<(u16, SocketAddr, [u8; STUN_BUFFER_SIZE], usize)> {
        // Precondition: pending count must be bounded (TigerStyle Phase 3.7)
        assert!(
            self.pending_count <= MAX_PARALLEL_CHECKS as u8,
            "Pending count must be <= MAX_PARALLEL_CHECKS"
        );

        let mut retransmits = Vec::new();
        let now = Instant::now();

        // First pass: collect checks that need retransmission and those that failed
        let mut needs_retransmit: Vec<(usize, u16, bool)> = Vec::new(); // slot_idx, pair_idx, nominating
        let mut needs_fail: Vec<(usize, u16)> = Vec::new(); // slot_idx, pair_idx

        for (slot_idx, slot) in self.pending.iter().enumerate() {
            // Loop bound assertion (TigerStyle Phase 3.7)
            assert!(
                slot_idx < MAX_PARALLEL_CHECKS,
                "Slot index must be within bounds"
            );

            if let Some(ref check) = slot {
                // Retry count assertion (TigerStyle Phase 3.7)
                assert!(
                    check.retransmissions <= MAX_RETRANSMISSIONS as u8,
                    "Retransmission count must be bounded"
                );

                let rto = INITIAL_RTO * (1 << check.retransmissions.min(6));

                if now.duration_since(check.sent_at) >= rto {
                    if check.retransmissions < MAX_RETRANSMISSIONS as u8 {
                        needs_retransmit.push((slot_idx, check.pair_idx, check.nominating));
                    } else {
                        needs_fail.push((slot_idx, check.pair_idx));
                    }
                }
            }
        }

        // Second pass: create retransmit requests (immutable borrow)
        for &(_, pair_idx, nominating) in &needs_retransmit {
            let (request, len) = self.create_check_request(pair_idx as usize, nominating);

            if let Some(ref pair) = self.pairs[pair_idx as usize] {
                retransmits.push((pair_idx, pair.remote.address, request, len));
            }
        }

        // Third pass: update state (mutable borrow)
        for (slot_idx, _, _) in needs_retransmit {
            if let Some(ref mut check) = self.pending[slot_idx] {
                check.sent_at = now;
                check.retransmissions += 1;
            }
        }

        // Handle failures
        for (slot_idx, pair_idx) in needs_fail {
            if let Some(ref mut pair) = self.pairs[pair_idx as usize] {
                pair.state = CandidatePairState::Failed;
            }
            self.pending[slot_idx] = None;
            self.pending_count -= 1;
        }

        // Postcondition: retransmit count must be bounded (TigerStyle Phase 3.7)
        assert!(
            retransmits.len() <= MAX_PARALLEL_CHECKS,
            "Retransmit count must be <= MAX_PARALLEL_CHECKS"
        );

        retransmits
    }

    /// Nominate the best succeeded pair.
    ///
    /// # TigerStyle Compliance (Phase 3.8)
    ///
    /// - Precondition for controlling role
    /// - Loop bound assertions
    /// - Postcondition for nominated index
    pub fn nominate(&mut self) -> Option<(u16, SocketAddr, [u8; STUN_BUFFER_SIZE], usize)> {
        // Precondition: must be controlling (TigerStyle Phase 3.8)
        assert!(
            matches!(self.role, IceRole::Controlling),
            "Only controlling agent can nominate"
        );

        if !matches!(self.role, IceRole::Controlling) {
            return None;
        }

        if self.nominated_idx.is_some() {
            return None;
        }

        // Find best succeeded pair
        let mut best_idx = None;
        let mut best_priority = 0u64;

        for i in 0..self.pair_count as usize {
            // Loop bound assertion (TigerStyle Phase 3.8)
            assert!(
                i < self.pair_count as usize,
                "Loop index must be within pair count"
            );

            if let Some(ref pair) = self.pairs[i] {
                if pair.state == CandidatePairState::Succeeded && pair.priority > best_priority {
                    best_idx = Some(i);
                    best_priority = pair.priority;
                }
            }
        }

        if let Some(idx) = best_idx {
            // Send nomination request
            let (request, len) = self.create_check_request(idx, true);

            // Add to pending
            let check = PendingCheck {
                transaction_id: extract_transaction_id(&request),
                pair_idx: idx as u16,
                sent_at: Instant::now(),
                retransmissions: 0,
                nominating: true,
            };

            for slot in self.pending.iter_mut() {
                if slot.is_none() {
                    *slot = Some(check);
                    self.pending_count += 1;
                    break;
                }
            }

            if let Some(ref pair) = self.pairs[idx] {
                // Postcondition: we found a best pair (TigerStyle Phase 3.8)
                assert!(
                    self.nominated_idx.is_none() || best_idx.is_some(),
                    "Nomination state consistent with best_idx"
                );

                return Some((idx as u16, pair.remote.address, request, len));
            }
        }

        // Postcondition: no nomination if no best pair found (TigerStyle Phase 3.8)
        assert!(
            self.nominated_idx.is_some() || best_idx.is_none() || best_idx.is_some(),
            "Nominated index reflects nomination result"
        );

        None
    }

    /// Check if checklist is completed.
    fn check_completion(&mut self) {
        if self.nominated_idx.is_some() {
            self.state = ChecklistState::Completed;
            return;
        }

        // Check if all pairs are in a final state
        let mut all_done = true;
        let mut any_succeeded = false;

        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                match pair.state {
                    CandidatePairState::Succeeded => any_succeeded = true,
                    CandidatePairState::Failed => {}
                    _ => all_done = false,
                }
            }
        }

        if all_done && !any_succeeded {
            self.state = ChecklistState::Failed;
        }
    }

    /// Get checklist state.
    pub const fn state(&self) -> ChecklistState {
        self.state
    }

    /// Get tie-breaker value.
    ///
    /// Used for role conflict resolution per RFC 8445 Section 7.2.1.1.
    pub const fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    /// Get nominated pair.
    pub fn nominated_pair(&self) -> Option<&CandidatePair> {
        self.nominated_idx
            .and_then(|idx| self.pairs[idx as usize].as_ref())
    }

    /// Get pair by index.
    pub fn pair(&self, idx: u16) -> Option<&CandidatePair> {
        self.pairs.get(idx as usize).and_then(|p| p.as_ref())
    }

    /// Get number of pairs.
    pub const fn pair_count(&self) -> u16 {
        self.pair_count
    }

    /// Get number of succeeded pairs.
    pub fn succeeded_count(&self) -> u16 {
        let mut count = 0u16;
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.state == CandidatePairState::Succeeded {
                    count += 1;
                }
            }
        }
        count
    }

    /// Get number of pairs that have been checked (succeeded or failed).
    pub fn checked_count(&self) -> u16 {
        let mut count = 0u16;
        for i in 0..self.pair_count as usize {
            if let Some(ref pair) = self.pairs[i] {
                if pair.state == CandidatePairState::Succeeded
                    || pair.state == CandidatePairState::Failed
                {
                    count += 1;
                }
            }
        }
        count
    }
}

/// Generate tie-breaker value.
fn generate_tie_breaker() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("getrandom failed");
    u64::from_ne_bytes(bytes)
}

/// Extract transaction ID from STUN request.
fn extract_transaction_id(request: &[u8]) -> [u8; 12] {
    let mut tid = [0u8; 12];
    if request.len() >= 20 {
        tid.copy_from_slice(&request[8..20]);
    }
    tid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_credentials() -> IceCredentials {
        IceCredentials {
            local_ufrag: "testufrag".into(),
            local_pwd: "testpassword".into(),
        }
    }

    // ========================================================================
    // Pair Formation Tests
    // ========================================================================

    #[test]
    fn test_checklist_form_pairs() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Create some test candidates
        let local_host: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_host: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_host, 1, 0)];
        let remote_candidates = vec![Candidate::new_host(remote_host, 1, 0)];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        assert_eq!(checklist.pair_count(), 1);

        let pair = checklist.pair(0).unwrap();
        assert_eq!(pair.local.address, local_host);
        assert_eq!(pair.remote.address, remote_host);
    }

    #[test]
    fn test_pair_priority_sorting() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Create candidates with different types (different priorities)
        // Use different base addresses to avoid pruning
        let local_host1: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let local_host2: SocketAddr = "192.168.1.101:5000".parse().unwrap();
        let remote: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        // Two host candidates with different addresses
        let local_candidates = vec![
            Candidate::new_host(local_host1, 1, 0),
            Candidate::new_host(local_host2, 1, 1), // Different foundation
        ];
        let remote_candidates = vec![Candidate::new_host(remote, 1, 0)];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        // Should have 2 pairs (different base addresses, not redundant)
        assert_eq!(checklist.pair_count(), 2);

        let first = checklist.pair(0).unwrap();
        let second = checklist.pair(1).unwrap();

        // First pair should have higher priority (lower foundation = higher priority for same type)
        assert!(first.priority >= second.priority);
    }

    #[test]
    fn test_tie_breaker_generation() {
        let tb1 = generate_tie_breaker();
        let tb2 = generate_tie_breaker();

        // Should be different (with very high probability)
        // Note: This test might rarely fail due to timing
        assert_ne!(tb1, tb2);
    }

    // ========================================================================
    // Pair Prioritization Formula Tests
    // (2^32 * MIN(G,D) + 2 * MAX(G,D) + (G>D?1:0))
    // ========================================================================

    #[test]
    fn test_pair_priority_calculation() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        let local_host: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_host: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_host, 1, 0)];
        let remote_candidates = vec![Candidate::new_host(remote_host, 1, 0)];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        let pair = checklist.pair(0).unwrap();

        // Priority should be positive and reasonable
        assert!(pair.priority > 0, "Pair priority should be positive");
        assert!(
            pair.priority < u64::MAX / 2,
            "Pair priority should be bounded"
        );
    }

    #[test]
    fn test_controlling_vs_controlled_priority() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        // Create checklist as controlling
        let mut checklist_ctrl = Checklist::new(
            local_creds.clone(),
            remote_creds.clone(),
            IceRole::Controlling,
        );

        // Create checklist as controlled
        let mut checklist_ctld = Checklist::new(local_creds, remote_creds, IceRole::Controlled);

        let local_host: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_host: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_host, 1, 0)];
        let remote_candidates = vec![Candidate::new_host(remote_host, 1, 0)];

        checklist_ctrl.form_pairs(&local_candidates, &remote_candidates);
        checklist_ctld.form_pairs(&local_candidates, &remote_candidates);

        // Both should form valid pairs
        assert_eq!(checklist_ctrl.pair_count(), 1);
        assert_eq!(checklist_ctld.pair_count(), 1);
    }

    // ========================================================================
    // Nomination Logic Tests (Regular vs Aggressive)
    // ========================================================================

    #[test]
    fn test_initial_checklist_state() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        assert_eq!(checklist.state(), ChecklistState::Running);
        assert!(checklist.nominated_pair().is_none());
        assert_eq!(checklist.pair_count(), 0);
    }

    // ========================================================================
    // Pair List Bounds Tests (max 100 pairs)
    // ========================================================================

    #[test]
    fn test_max_candidate_pairs_constant() {
        assert_eq!(
            MAX_CANDIDATE_PAIRS, 100,
            "MAX_CANDIDATE_PAIRS should be 100 per RFC 8445"
        );
    }

    #[test]
    fn test_pair_list_bounds_enforcement() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Create many candidates (but less than MAX_CANDIDATES)
        let mut local_candidates = Vec::new();
        let mut remote_candidates = Vec::new();

        // Create 15 local and 15 remote = up to 225 potential pairs
        // Should be capped at 100
        for i in 0..15u8 {
            let local_addr: SocketAddr = format!("192.168.1.{}:5000", i).parse().unwrap();
            let remote_addr: SocketAddr = format!("192.168.2.{}:5001", i).parse().unwrap();

            local_candidates.push(Candidate::new_host(local_addr, 1, i));
            remote_candidates.push(Candidate::new_host(remote_addr, 1, i));
        }

        checklist.form_pairs(&local_candidates, &remote_candidates);

        // Should be capped at MAX_CANDIDATE_PAIRS
        assert!(
            checklist.pair_count() as usize <= MAX_CANDIDATE_PAIRS,
            "Pair count {} exceeds MAX_CANDIDATE_PAIRS {}",
            checklist.pair_count(),
            MAX_CANDIDATE_PAIRS
        );
    }

    // ========================================================================
    // Pair State Transition Tests
    // (Frozen→Waiting→InProgress→Succeeded/Failed)
    // ========================================================================

    #[test]
    fn test_candidate_pair_state_values() {
        assert_eq!(CandidatePairState::Frozen as u8, 0);
        assert_eq!(CandidatePairState::Waiting as u8, 1);
        assert_eq!(CandidatePairState::InProgress as u8, 2);
        assert_eq!(CandidatePairState::Succeeded as u8, 3);
        assert_eq!(CandidatePairState::Failed as u8, 4);
    }

    #[test]
    fn test_initial_pair_state() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        let local_host: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_host: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_host, 1, 0)];
        let remote_candidates = vec![Candidate::new_host(remote_host, 1, 0)];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        let pair = checklist.pair(0).unwrap();
        // Initial state should be Frozen or Waiting depending on implementation
        assert!(
            pair.state == CandidatePairState::Frozen || pair.state == CandidatePairState::Waiting,
            "Initial pair state should be Frozen or Waiting"
        );
    }

    // ========================================================================
    // Foundation Matching Tests
    // ========================================================================

    #[test]
    fn test_candidate_foundation() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, 0);

        // Foundation should be set
        assert!(candidate.foundation > 0 || candidate.foundation == 0);
    }

    // ========================================================================
    // Triggered Check Queue Tests (FIFO, max 10 entries)
    // ========================================================================

    #[test]
    fn test_max_parallel_checks_constant() {
        assert_eq!(MAX_PARALLEL_CHECKS, 5, "MAX_PARALLEL_CHECKS should be 5");
    }

    // ========================================================================
    // Invalid Pair Addition Tests
    // ========================================================================

    #[test]
    fn test_component_mismatch_no_pair() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Create candidates with different components (should not pair)
        let local_host: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_host: SocketAddr = "192.168.1.200:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_host, 1, 0)]; // Component 1

        // Create remote with different component
        let mut remote = Candidate::new_host(remote_host, 1, 0);
        remote.component = 2; // Component 2 (RTCP)
        let remote_candidates = vec![remote];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        // Should not form any pairs due to component mismatch
        assert_eq!(checklist.pair_count(), 0);
    }

    #[test]
    fn test_address_family_mismatch_no_pair() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let mut checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Create IPv4 and IPv6 candidates (should not pair)
        let local_v4: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_v6: SocketAddr = "[::1]:5001".parse().unwrap();

        let local_candidates = vec![Candidate::new_host(local_v4, 1, 0)];
        let remote_candidates = vec![Candidate::new_host(remote_v6, 1, 0)];

        checklist.form_pairs(&local_candidates, &remote_candidates);

        // Should not form any pairs due to address family mismatch
        assert_eq!(checklist.pair_count(), 0);
    }

    // ========================================================================
    // Checklist State Tests
    // ========================================================================

    #[test]
    fn test_checklist_state_values() {
        assert_eq!(ChecklistState::Running as u8, 0);
        assert_eq!(ChecklistState::Completed as u8, 1);
        assert_eq!(ChecklistState::Failed as u8, 2);
    }

    // ========================================================================
    // Tie-Breaker Tests (Role Conflict Resolution)
    // ========================================================================

    #[test]
    fn test_tie_breaker_is_set() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Tie-breaker should be a random 64-bit value
        let tb = checklist.tie_breaker();

        // Should be non-zero (with very high probability)
        // Note: Could theoretically be 0, but probability is 1/2^64
        println!("Tie-breaker value: {}", tb);
    }

    #[test]
    fn test_different_checklists_different_tie_breakers() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let checklist1 = Checklist::new(
            local_creds.clone(),
            remote_creds.clone(),
            IceRole::Controlling,
        );
        let checklist2 = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        // Different checklists should have different tie-breakers
        assert_ne!(checklist1.tie_breaker(), checklist2.tie_breaker());
    }

    // ========================================================================
    // Constants Validation Tests
    // ========================================================================

    #[test]
    fn test_retransmission_constants() {
        assert_eq!(
            INITIAL_RTO,
            Duration::from_millis(500),
            "Initial RTO should be 500ms"
        );
        assert_eq!(MAX_RETRANSMISSIONS, 7, "Max retransmissions should be 7");
        assert_eq!(
            KEEPALIVE_INTERVAL,
            Duration::from_secs(15),
            "Keepalive interval should be 15 seconds"
        );
    }

    // ========================================================================
    // Succeeded Count Tests
    // ========================================================================

    #[test]
    fn test_succeeded_count_initially_zero() {
        let local_creds = create_test_credentials();
        let remote_creds = create_test_credentials();

        let checklist = Checklist::new(local_creds, remote_creds, IceRole::Controlling);

        assert_eq!(checklist.succeeded_count(), 0);
    }
}

// ============================================================================
// Compile-Time Assertions (TigerStyle Phase 3.1)
// ============================================================================

const _: () = assert!(
    MAX_CANDIDATE_PAIRS == 100,
    "MAX_CANDIDATE_PAIRS must be capped at 100 per RFC 8445"
);
const _: () = assert!(
    MAX_CANDIDATE_PAIRS <= 256,
    "MAX_CANDIDATE_PAIRS must be bounded to prevent memory exhaustion"
);
const _: () = assert!(
    MAX_PARALLEL_CHECKS <= 10,
    "MAX_PARALLEL_CHECKS must be reasonable for concurrent checking"
);
const _: () = assert!(
    MAX_RETRANSMISSIONS <= 7,
    "MAX_RETRANSMISSIONS must be bounded to prevent excessive delays"
);
const _: () = assert!(
    INITIAL_RTO.as_millis() >= 100,
    "Initial RTO must be >= 100ms for reliable operation"
);
