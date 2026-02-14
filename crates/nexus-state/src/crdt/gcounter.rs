//! GCounter - Grow-Only Counter CRDT
//!
//! A GCounter is a distributed counter that can only be incremented. Each actor
//! maintains its own counter, and the total value is the sum of all actor counters.
//! Merging two GCounters takes the maximum of each actor's counter.
//!
//! # Properties
//! - **Monotonic**: The counter value can only increase
//! - **Commutative**: `merge(A, B) = merge(B, A)`
//! - **Associative**: `merge(merge(A, B), C) = merge(A, merge(B, C))`
//! - **Idempotent**: `merge(A, A) = A`
//!
//! # Memory Model
//! Pre-allocated array of atomic counters, one per actor. Zero allocation after init.
//!
//! # Concurrency
//! All operations use atomic instructions for lock-free concurrent access.
//!
//! # Example
//! ```
//! use nexus_state::crdt::GCounter;
//!
//! let mut counter = GCounter::new();
//! counter.increment(0, 5);
//! counter.increment(1, 3);
//! assert_eq!(counter.value(), 8);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{CrdtError, CrdtResult};
use crate::types::{ActorId, MAX_ACTORS};

/// A grow-only counter CRDT with pre-allocated storage for MAX_ACTORS
///
/// Each actor has its own counter slot, and the total value is the sum
/// of all actor counters. This provides conflict-free increment operations
/// across distributed nodes.
///
/// # Size
/// `MAX_ACTORS * 8` bytes = 2KB for 256 actors
pub struct GCounter {
    /// Pre-allocated array of counters, one per actor
    /// Index is actor_id (direct mapping, no modulo)
    counters: [AtomicU64; MAX_ACTORS],
}

// Compile-time assertions
const _: () = {
    assert!(MAX_ACTORS > 0, "MAX_ACTORS must be positive");
    assert!(MAX_ACTORS <= 1024, "MAX_ACTORS must not exceed 1024");
};

impl GCounter {
    /// Creates a new GCounter with all counters initialized to zero
    ///
    /// # Postcondition
    /// `self.value() == 0`
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let counter = GCounter::new();
    /// assert_eq!(counter.value(), 0);
    /// ```
    #[inline]
    #[allow(clippy::declare_interior_mutable_const)]
    pub fn new() -> Self {
        // Initialize all counters to zero
        // We use array initialization with const to avoid allocation
        const INIT: AtomicU64 = AtomicU64::new(0);
        let counters = [INIT; MAX_ACTORS];
        
        let result = Self { counters };
        
        // Postcondition: initial value is zero
        debug_assert_eq!(result.value(), 0, "Postcondition: new counter must have value 0");
        
        result
    }

    /// Increments the counter for a specific actor
    ///
    /// # Arguments
    /// * `actor_id` - The actor performing the increment (must be < `MAX_ACTORS`)
    /// * `delta` - The amount to increment (must be > 0)
    ///
    /// # Returns
    /// The new counter value for this actor
    ///
    /// # Panics
    /// - If `actor_id >= MAX_ACTORS`
    /// - If `delta == 0`
    ///
    /// # Complexity
    /// O(1) time, O(0) allocations
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let mut counter = GCounter::new();
    /// let new_val = counter.increment(0, 5);
    /// assert_eq!(new_val, 5);
    /// ```
    #[inline]
    pub fn increment(&self, actor_id: ActorId, delta: u64) -> u64 {
        // Preconditions
        assert!(delta > 0, "Precondition: delta must be positive");
        assert!(
            actor_id < MAX_ACTORS as u64,
            "Precondition: actor_id {actor_id} must be less than MAX_ACTORS {MAX_ACTORS}"
        );

        let index = actor_id as usize;
        
        // Get old value for postcondition check
        let old_value = self.counters[index].load(Ordering::Acquire);
        
        // Atomic increment with Release ordering for visibility
        let new_value = self.counters[index].fetch_add(delta, Ordering::Release) + delta;
        
        // Postcondition: value increased by delta (monotonic increase)
        debug_assert!(
            new_value >= old_value,
            "Postcondition: counter must be monotonically increasing"
        );
        debug_assert!(
            new_value == old_value.wrapping_add(delta),
            "Postcondition: counter must increase by exactly delta"
        );
        
        new_value
    }

    /// Increments the counter, returning an error instead of panicking
    ///
    /// # Arguments
    /// * `actor_id` - The actor performing the increment
    /// * `delta` - The amount to increment
    ///
    /// # Returns
    /// Ok(new_value) on success, Err on invalid input or overflow
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let counter = GCounter::new();
    /// assert!(counter.try_increment(0, 5).is_ok());
    /// assert!(counter.try_increment(1000, 5).is_err()); // Invalid actor
    /// ```
    #[inline]
    pub fn try_increment(&self, actor_id: ActorId, delta: u64) -> CrdtResult<u64> {
        // Validate preconditions
        if actor_id >= MAX_ACTORS as u64 {
            return Err(CrdtError::InvalidActorId { actor_id });
        }
        if delta == 0 {
            return Err(CrdtError::InvalidState {
                reason: "delta must be positive",
            });
        }

        let index = actor_id as usize;
        let old_value = self.counters[index].load(Ordering::Acquire);
        
        // Check for overflow before increment
        if old_value.checked_add(delta).is_none() {
            return Err(CrdtError::Overflow);
        }

        let new_value = self.counters[index].fetch_add(delta, Ordering::Release) + delta;
        Ok(new_value)
    }

    /// Returns the total counter value (sum of all actor counters)
    ///
    /// # Returns
    /// Sum of all actor counters. Returns u64::MAX on overflow.
    ///
    /// # Complexity
    /// O(MAX_ACTORS) time, O(0) allocations
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let counter = GCounter::new();
    /// counter.increment(0, 5);
    /// counter.increment(1, 3);
    /// assert_eq!(counter.value(), 8);
    /// ```
    #[inline]
    pub fn value(&self) -> u64 {
        let mut sum: u64 = 0;
        
        // Bounded loop over all actors
        for i in 0..MAX_ACTORS {
            let counter_value = self.counters[i].load(Ordering::Acquire);
            sum = sum.saturating_add(counter_value);
        }
        
        sum
    }

    /// Returns the counter value for a specific actor
    ///
    /// # Arguments
    /// * `actor_id` - The actor to query
    ///
    /// # Panics
    /// If `actor_id >= MAX_ACTORS`
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let counter = GCounter::new();
    /// counter.increment(5, 42);
    /// assert_eq!(counter.actor_value(5), 42);
    /// ```
    #[inline]
    pub fn actor_value(&self, actor_id: ActorId) -> u64 {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be less than MAX_ACTORS"
        );
        self.counters[actor_id as usize].load(Ordering::Acquire)
    }

    /// Merges another GCounter into this one
    ///
    /// For each actor, takes the maximum of the local and remote counter.
    /// This operation is commutative, associative, and idempotent.
    ///
    /// # Arguments
    /// * `other` - The GCounter to merge from
    ///
    /// # Complexity
    /// O(MAX_ACTORS) time, O(0) allocations
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::GCounter;
    ///
    /// let mut a = GCounter::new();
    /// a.increment(0, 5);
    ///
    /// let mut b = GCounter::new();
    /// b.increment(0, 3);
    /// b.increment(1, 10);
    ///
    /// a.merge(&b);
    /// assert_eq!(a.actor_value(0), 5);  // max(5, 3)
    /// assert_eq!(a.actor_value(1), 10); // max(0, 10)
    /// ```
    #[inline]
    pub fn merge(&self, other: &GCounter) {
        // Bounded loop over all actors
        for i in 0..MAX_ACTORS {
            let other_value = other.counters[i].load(Ordering::Acquire);
            
            if other_value > 0 {
                // Use fetch_max for atomic maximum update
                // This is lock-free and handles concurrent merges correctly
                loop {
                    let current = self.counters[i].load(Ordering::Acquire);
                    if other_value <= current {
                        break;
                    }
                    match self.counters[i].compare_exchange_weak(
                        current,
                        other_value,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    /// Creates a clone of this counter
    ///
    /// Note: This performs atomic loads of all counters.
    #[inline]
    pub fn snapshot(&self) -> GCounterSnapshot {
        let mut values = [0u64; MAX_ACTORS];
        for i in 0..MAX_ACTORS {
            values[i] = self.counters[i].load(Ordering::Acquire);
        }
        GCounterSnapshot { values }
    }

    /// Checks if this counter is empty (all zeros)
    #[inline]
    pub fn is_empty(&self) -> bool {
        for i in 0..MAX_ACTORS {
            if self.counters[i].load(Ordering::Acquire) != 0 {
                return false;
            }
        }
        true
    }
}

impl Default for GCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut non_zero = Vec::new();
        for i in 0..MAX_ACTORS {
            let v = self.counters[i].load(Ordering::Relaxed);
            if v > 0 {
                non_zero.push((i, v));
            }
        }
        f.debug_struct("GCounter")
            .field("value", &self.value())
            .field("non_zero_actors", &non_zero)
            .finish()
    }
}

/// A non-atomic snapshot of a GCounter for comparison and serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GCounterSnapshot {
    values: [u64; MAX_ACTORS],
}

impl GCounterSnapshot {
    /// Returns the total value
    #[inline]
    pub fn value(&self) -> u64 {
        let mut sum: u64 = 0;
        for i in 0..MAX_ACTORS {
            sum = sum.saturating_add(self.values[i]);
        }
        sum
    }

    /// Returns the value for a specific actor
    #[inline]
    pub fn actor_value(&self, actor_id: ActorId) -> u64 {
        assert!(actor_id < MAX_ACTORS as u64);
        self.values[actor_id as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcounter_new() {
        let counter = GCounter::new();
        assert_eq!(counter.value(), 0);
        assert!(counter.is_empty());
        
        for i in 0..MAX_ACTORS as u64 {
            assert_eq!(counter.actor_value(i), 0);
        }
    }

    #[test]
    fn test_gcounter_increment() {
        let counter = GCounter::new();
        
        let new_val = counter.increment(0, 5);
        assert_eq!(new_val, 5);
        assert_eq!(counter.actor_value(0), 5);
        assert_eq!(counter.value(), 5);
        
        let new_val = counter.increment(0, 3);
        assert_eq!(new_val, 8);
        assert_eq!(counter.actor_value(0), 8);
        assert_eq!(counter.value(), 8);
    }

    #[test]
    fn test_gcounter_multi_actor() {
        let counter = GCounter::new();
        
        counter.increment(0, 10);
        counter.increment(1, 20);
        counter.increment(2, 30);
        
        assert_eq!(counter.actor_value(0), 10);
        assert_eq!(counter.actor_value(1), 20);
        assert_eq!(counter.actor_value(2), 30);
        assert_eq!(counter.value(), 60);
    }

    #[test]
    fn test_gcounter_merge_commutative() {
        let a = GCounter::new();
        a.increment(0, 5);
        a.increment(1, 10);
        
        let b = GCounter::new();
        b.increment(0, 3);
        b.increment(2, 15);
        
        // Merge a <- b
        let a1 = GCounter::new();
        a1.increment(0, 5);
        a1.increment(1, 10);
        a1.merge(&b);
        
        // Merge b <- a
        let b1 = GCounter::new();
        b1.increment(0, 3);
        b1.increment(2, 15);
        b1.merge(&a);
        
        // Assert commutativity: merge(a, b) == merge(b, a)
        assert_eq!(a1.snapshot(), b1.snapshot());
        
        // Verify expected values
        assert_eq!(a1.actor_value(0), 5);  // max(5, 3)
        assert_eq!(a1.actor_value(1), 10); // max(10, 0)
        assert_eq!(a1.actor_value(2), 15); // max(0, 15)
    }

    #[test]
    fn test_gcounter_merge_idempotent() {
        let a = GCounter::new();
        a.increment(0, 5);
        a.increment(1, 10);
        
        let before = a.snapshot();
        
        // Merge with self
        a.merge(&a);
        
        let after = a.snapshot();
        
        // Assert idempotence: merge(a, a) == a
        assert_eq!(before, after);
    }

    #[test]
    fn test_gcounter_merge_associative() {
        let a = GCounter::new();
        a.increment(0, 5);
        
        let b = GCounter::new();
        b.increment(1, 10);
        
        let c = GCounter::new();
        c.increment(2, 15);
        
        // (a merge b) merge c
        let ab_c = GCounter::new();
        ab_c.increment(0, 5);
        ab_c.merge(&b);
        ab_c.merge(&c);
        
        // a merge (b merge c)
        let bc = GCounter::new();
        bc.increment(1, 10);
        bc.merge(&c);
        
        let a_bc = GCounter::new();
        a_bc.increment(0, 5);
        a_bc.merge(&bc);
        
        // Assert associativity
        assert_eq!(ab_c.snapshot(), a_bc.snapshot());
    }

    #[test]
    fn test_gcounter_monotonic() {
        let counter = GCounter::new();
        
        let mut prev_value = 0u64;
        for i in 0..100 {
            let actor = (i % MAX_ACTORS) as u64;
            counter.increment(actor, 1);
            
            let current_value = counter.value();
            assert!(
                current_value >= prev_value,
                "Counter must be monotonically increasing"
            );
            prev_value = current_value;
        }
    }

    #[test]
    fn test_gcounter_overflow_detection() {
        let counter = GCounter::new();
        
        // Set a high value
        counter.increment(0, u64::MAX - 10);
        
        // Try to increment beyond max
        let result = counter.try_increment(0, 20);
        assert!(matches!(result, Err(CrdtError::Overflow)));
    }

    #[test]
    #[should_panic(expected = "actor_id")]
    fn test_gcounter_invalid_actor_id() {
        let counter = GCounter::new();
        counter.increment(MAX_ACTORS as u64, 1);
    }

    #[test]
    #[should_panic(expected = "delta must be positive")]
    fn test_gcounter_zero_delta() {
        let counter = GCounter::new();
        counter.increment(0, 0);
    }

    #[test]
    fn test_gcounter_try_increment_invalid_actor() {
        let counter = GCounter::new();
        let result = counter.try_increment(MAX_ACTORS as u64, 1);
        assert!(matches!(result, Err(CrdtError::InvalidActorId { .. })));
    }

    #[test]
    fn test_gcounter_snapshot() {
        let counter = GCounter::new();
        counter.increment(0, 5);
        counter.increment(1, 10);
        
        let snap = counter.snapshot();
        assert_eq!(snap.value(), 15);
        assert_eq!(snap.actor_value(0), 5);
        assert_eq!(snap.actor_value(1), 10);
    }

    #[test]
    fn test_gcounter_is_empty() {
        let counter = GCounter::new();
        assert!(counter.is_empty());
        
        counter.increment(0, 1);
        assert!(!counter.is_empty());
    }

    #[test]
    fn test_gcounter_debug() {
        let counter = GCounter::new();
        counter.increment(0, 5);
        
        let debug_str = format!("{:?}", counter);
        assert!(debug_str.contains("GCounter"));
        assert!(debug_str.contains("5"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_actor_id()(id in 0u64..(MAX_ACTORS as u64)) -> ActorId {
            id
        }
    }

    prop_compose! {
        fn arb_delta()(delta in 1u64..1000u64) -> u64 {
            delta
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn proptest_gcounter_merge_commutative(
            ops_a in prop::collection::vec((arb_actor_id(), arb_delta()), 0..20),
            ops_b in prop::collection::vec((arb_actor_id(), arb_delta()), 0..20)
        ) {
            // Create counter A with ops_a
            let a = GCounter::new();
            for (actor, delta) in &ops_a {
                a.increment(*actor, *delta);
            }
            
            // Create counter B with ops_b
            let b = GCounter::new();
            for (actor, delta) in &ops_b {
                b.increment(*actor, *delta);
            }
            
            // merge(A, B)
            let ab = GCounter::new();
            for (actor, delta) in &ops_a {
                ab.increment(*actor, *delta);
            }
            ab.merge(&b);
            
            // merge(B, A)
            let ba = GCounter::new();
            for (actor, delta) in &ops_b {
                ba.increment(*actor, *delta);
            }
            ba.merge(&a);
            
            // Assert commutativity
            prop_assert_eq!(ab.snapshot(), ba.snapshot());
        }

        #[test]
        fn proptest_gcounter_merge_associative(
            ops_a in prop::collection::vec((arb_actor_id(), arb_delta()), 0..10),
            ops_b in prop::collection::vec((arb_actor_id(), arb_delta()), 0..10),
            ops_c in prop::collection::vec((arb_actor_id(), arb_delta()), 0..10)
        ) {
            let a = GCounter::new();
            for (actor, delta) in &ops_a {
                a.increment(*actor, *delta);
            }
            
            let b = GCounter::new();
            for (actor, delta) in &ops_b {
                b.increment(*actor, *delta);
            }
            
            let c = GCounter::new();
            for (actor, delta) in &ops_c {
                c.increment(*actor, *delta);
            }
            
            // (A merge B) merge C
            let ab_c = GCounter::new();
            for (actor, delta) in &ops_a {
                ab_c.increment(*actor, *delta);
            }
            ab_c.merge(&b);
            ab_c.merge(&c);
            
            // A merge (B merge C)
            let bc = GCounter::new();
            for (actor, delta) in &ops_b {
                bc.increment(*actor, *delta);
            }
            bc.merge(&c);
            
            let a_bc = GCounter::new();
            for (actor, delta) in &ops_a {
                a_bc.increment(*actor, *delta);
            }
            a_bc.merge(&bc);
            
            // Assert associativity
            prop_assert_eq!(ab_c.snapshot(), a_bc.snapshot());
        }

        #[test]
        fn proptest_gcounter_merge_idempotent(
            ops in prop::collection::vec((arb_actor_id(), arb_delta()), 0..20)
        ) {
            let counter = GCounter::new();
            for (actor, delta) in &ops {
                counter.increment(*actor, *delta);
            }
            
            let before = counter.snapshot();
            counter.merge(&counter);
            let after = counter.snapshot();
            
            // Assert idempotence
            prop_assert_eq!(before, after);
        }

        #[test]
        fn proptest_gcounter_monotonic(
            ops in prop::collection::vec((arb_actor_id(), arb_delta()), 0..100)
        ) {
            let counter = GCounter::new();
            let mut prev = 0u64;
            
            for (actor, delta) in ops {
                counter.increment(actor, delta);
                let curr = counter.value();
                
                // Assert monotonicity
                prop_assert!(curr >= prev, "Counter decreased from {} to {}", prev, curr);
                prev = curr;
            }
        }
    }
}
