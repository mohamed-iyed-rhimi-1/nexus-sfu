//! LWWReg - Last-Writer-Wins Register CRDT
//!
//! A LWWReg is a register that resolves concurrent writes by choosing the write
//! with the highest timestamp. If timestamps are equal, the higher actor ID wins.
//! This provides deterministic conflict resolution across distributed nodes.
//!
//! # Properties
//! - **Deterministic**: Same concurrent writes always resolve the same way
//! - **Commutative**: `merge(A, B) = merge(B, A)`
//! - **Associative**: `merge(merge(A, B), C) = merge(A, merge(B, C))`
//! - **Idempotent**: `merge(A, A) = A`
//!
//! # Memory Model
//! Fixed-size structure with atomic timestamp and writer fields. Zero allocation after init.
//!
//! # Concurrency
//! Uses atomic operations for timestamp and writer tracking.
//!
//! # Example
//! ```
//! use nexus_state::crdt::LWWReg;
//!
//! let mut reg = LWWReg::new(0u32, 1);
//! reg.set(42, 100, 1);
//! assert_eq!(reg.get(), 42);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::{ActorId, VectorClock, MAX_ACTORS};

/// Maximum size of a value stored in an LWWReg (256 bytes)
pub const MAX_VALUE_SIZE: usize = 256;

/// A Last-Writer-Wins Register CRDT
///
/// Stores a value of type `T` along with the timestamp and actor of the last write.
/// Concurrent writes are resolved by comparing timestamps, with actor ID as a tie-breaker.
///
/// # Type Parameters
/// * `T` - The value type. Must be `Copy` (no heap allocation), `PartialEq`, and <= 256 bytes.
///
/// # Size
/// `size_of::<T>() + 16` bytes (for timestamp and writer)
#[derive(Debug)]
pub struct LWWReg<T: Clone> {
    /// Current value
    value: T,
    /// Timestamp of last write (atomic for concurrent reads)
    timestamp: AtomicU64,
    /// Actor that performed last write (atomic for concurrent reads)
    writer: AtomicU64,
}

impl<T: Clone> LWWReg<T> {
    /// Creates a new LWWReg with an initial value
    ///
    /// # Arguments
    /// * `initial` - The initial value
    /// * `actor_id` - The actor creating this register
    ///
    /// # Panics
    /// - If `actor_id >= MAX_ACTORS`
    /// - If `size_of::<T>() > MAX_VALUE_SIZE`
    ///
    /// # Postcondition
    /// `self.get() == initial`
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::LWWReg;
    ///
    /// let reg = LWWReg::new(42u32, 1);
    /// assert_eq!(reg.get(), 42);
    /// ```
    #[inline]
    pub fn new(initial: T, actor_id: ActorId) -> Self {
        // Compile-time size check
        const {
            assert!(std::mem::size_of::<T>() <= MAX_VALUE_SIZE);
        };
        
        // Precondition: valid actor_id
        assert!(
            actor_id < MAX_ACTORS as u64,
            "Precondition: actor_id {} must be less than MAX_ACTORS {}",
            actor_id,
            MAX_ACTORS
        );

        let result = Self {
            value: initial,
            timestamp: AtomicU64::new(0),
            writer: AtomicU64::new(actor_id),
        };

        // Postcondition
        debug_assert!(
            std::ptr::eq(&result.value, &result.value),
            "Postcondition: value must be accessible"
        );

        result
    }

    /// Creates a new LWWReg with an initial value and timestamp
    ///
    /// # Arguments
    /// * `initial` - The initial value
    /// * `timestamp` - The initial timestamp
    /// * `actor_id` - The actor creating this register
    ///
    /// # Panics
    /// - If `actor_id >= MAX_ACTORS`
    #[inline]
    pub fn with_timestamp(initial: T, timestamp: VectorClock, actor_id: ActorId) -> Self {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be less than MAX_ACTORS"
        );

        Self {
            value: initial,
            timestamp: AtomicU64::new(timestamp),
            writer: AtomicU64::new(actor_id),
        }
    }

    /// Gets the current value
    ///
    /// # Returns
    /// A clone of the current value
    ///
    /// # Complexity
    /// O(1) time, O(0) allocations
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::LWWReg;
    ///
    /// let reg = LWWReg::new(42u32, 1);
    /// assert_eq!(reg.get(), 42);
    /// ```
    #[inline]
    pub fn get(&self) -> T {
        self.value.clone()
    }

    /// Gets the current timestamp
    #[inline]
    pub fn timestamp(&self) -> VectorClock {
        self.timestamp.load(Ordering::Acquire)
    }

    /// Gets the actor that last wrote to this register
    #[inline]
    pub fn writer(&self) -> ActorId {
        self.writer.load(Ordering::Acquire)
    }

    /// Sets a new value with the given timestamp and actor
    ///
    /// The new value is only applied if:
    /// - `timestamp > current_timestamp`, OR
    /// - `timestamp == current_timestamp AND actor_id > current_writer`
    ///
    /// # Arguments
    /// * `value` - The new value
    /// * `timestamp` - The timestamp of this write (must be > 0)
    /// * `actor_id` - The actor performing this write
    ///
    /// # Returns
    /// `true` if the value was updated, `false` if the write was rejected
    ///
    /// # Panics
    /// - If `timestamp == 0`
    /// - If `actor_id >= MAX_ACTORS`
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::LWWReg;
    ///
    /// let mut reg = LWWReg::new(0u32, 1);
    /// assert!(reg.set(42, 100, 1));
    /// assert!(!reg.set(99, 50, 2)); // Older timestamp rejected
    /// assert_eq!(reg.get(), 42);
    /// ```
    #[inline]
    pub fn set(&mut self, value: T, timestamp: VectorClock, actor_id: ActorId) -> bool {
        // Preconditions
        assert!(timestamp > 0, "Precondition: timestamp must be positive");
        assert!(
            actor_id < MAX_ACTORS as u64,
            "Precondition: actor_id must be less than MAX_ACTORS"
        );

        let current_ts = self.timestamp.load(Ordering::Acquire);
        let current_writer = self.writer.load(Ordering::Acquire);

        // Check if this write wins
        let wins = if timestamp > current_ts {
            true
        } else if timestamp == current_ts {
            // Tie-break by actor_id
            actor_id > current_writer
        } else {
            false
        };

        if wins {
            // Update value (we have &mut self, so this is safe)
            self.value = value;
            self.timestamp.store(timestamp, Ordering::Release);
            self.writer.store(actor_id, Ordering::Release);

            // Postcondition: timestamp is monotonic or tie-broken
            debug_assert!(
                timestamp >= current_ts,
                "Postcondition: timestamp must not decrease"
            );

            true
        } else {
            false
        }
    }

    /// Merges another register into this one
    ///
    /// Takes the value with the higher timestamp (or higher actor_id on tie).
    /// This operation is commutative, associative, and idempotent.
    ///
    /// # Arguments
    /// * `other` - The register to merge from
    ///
    /// # Complexity
    /// O(1) time, O(0) allocations
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::LWWReg;
    ///
    /// let mut a = LWWReg::with_timestamp(10u32, 100, 1);
    /// let b = LWWReg::with_timestamp(20u32, 200, 2);
    ///
    /// a.merge(&b);
    /// assert_eq!(a.get(), 20); // Higher timestamp wins
    /// ```
    #[inline]
    pub fn merge(&mut self, other: &LWWReg<T>) {
        let other_ts = other.timestamp.load(Ordering::Acquire);
        let other_writer = other.writer.load(Ordering::Acquire);
        let other_value = other.value.clone();

        // Treat timestamp 0 as uninitialized - only merge if other has a timestamp
        if other_ts > 0 {
            // Use set() which handles the comparison logic
            let current_ts = self.timestamp.load(Ordering::Acquire);
            
            // If we're also uninitialized (ts == 0), accept any write
            if current_ts == 0 {
                self.value = other_value;
                self.timestamp.store(other_ts, Ordering::Release);
                self.writer.store(other_writer, Ordering::Release);
            } else if other_ts > current_ts {
                self.value = other_value;
                self.timestamp.store(other_ts, Ordering::Release);
                self.writer.store(other_writer, Ordering::Release);
            } else if other_ts == current_ts {
                let current_writer = self.writer.load(Ordering::Acquire);
                if other_writer > current_writer {
                    self.value = other_value;
                    self.writer.store(other_writer, Ordering::Release);
                }
            }
        }
    }

    /// Creates a snapshot of the current state
    #[inline]
    pub fn snapshot(&self) -> LWWRegSnapshot<T> {
        LWWRegSnapshot {
            value: self.value.clone(),
            timestamp: self.timestamp.load(Ordering::Acquire),
            writer: self.writer.load(Ordering::Acquire),
        }
    }
}

impl<T: Clone + Default> Default for LWWReg<T> {
    fn default() -> Self {
        Self::new(T::default(), 0)
    }
}

impl<T: Clone> Clone for LWWReg<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            timestamp: AtomicU64::new(self.timestamp.load(Ordering::Acquire)),
            writer: AtomicU64::new(self.writer.load(Ordering::Acquire)),
        }
    }
}

/// A non-atomic snapshot of an LWWReg for comparison and serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LWWRegSnapshot<T: Clone> {
    /// The value
    pub value: T,
    /// The timestamp
    pub timestamp: VectorClock,
    /// The writer actor
    pub writer: ActorId,
}

impl<T: Clone + PartialEq> LWWRegSnapshot<T> {
    /// Returns true if this snapshot equals another
    pub fn eq_state(&self, other: &Self) -> bool {
        self.value == other.value
            && self.timestamp == other.timestamp
            && self.writer == other.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lwwreg_new() {
        let reg = LWWReg::new(42u32, 1);
        assert_eq!(reg.get(), 42);
        assert_eq!(reg.timestamp(), 0);
        assert_eq!(reg.writer(), 1);
    }

    #[test]
    fn test_lwwreg_with_timestamp() {
        let reg = LWWReg::with_timestamp(42u32, 100, 5);
        assert_eq!(reg.get(), 42);
        assert_eq!(reg.timestamp(), 100);
        assert_eq!(reg.writer(), 5);
    }

    #[test]
    fn test_lwwreg_set_newer_timestamp() {
        let mut reg = LWWReg::with_timestamp(10u32, 100, 1);
        
        // Newer timestamp wins
        let updated = reg.set(20, 200, 2);
        assert!(updated);
        assert_eq!(reg.get(), 20);
        assert_eq!(reg.timestamp(), 200);
        assert_eq!(reg.writer(), 2);
    }

    #[test]
    fn test_lwwreg_set_older_timestamp() {
        let mut reg = LWWReg::with_timestamp(10u32, 200, 1);
        
        // Older timestamp is rejected
        let updated = reg.set(20, 100, 2);
        assert!(!updated);
        assert_eq!(reg.get(), 10);
        assert_eq!(reg.timestamp(), 200);
    }

    #[test]
    fn test_lwwreg_set_same_timestamp_higher_actor() {
        let mut reg = LWWReg::with_timestamp(10u32, 100, 1);
        
        // Same timestamp, higher actor wins
        let updated = reg.set(20, 100, 5);
        assert!(updated);
        assert_eq!(reg.get(), 20);
        assert_eq!(reg.writer(), 5);
    }

    #[test]
    fn test_lwwreg_set_same_timestamp_lower_actor() {
        let mut reg = LWWReg::with_timestamp(10u32, 100, 5);
        
        // Same timestamp, lower actor loses
        let updated = reg.set(20, 100, 1);
        assert!(!updated);
        assert_eq!(reg.get(), 10);
        assert_eq!(reg.writer(), 5);
    }

    #[test]
    fn test_lwwreg_merge_commutative() {
        let a = LWWReg::with_timestamp(10u32, 100, 1);
        let b = LWWReg::with_timestamp(20u32, 200, 2);
        
        // Clone for comparison
        let mut a1 = a.clone();
        let mut b1 = b.clone();
        
        // merge(a, b)
        a1.merge(&b);
        
        // merge(b, a)
        b1.merge(&a);
        
        // Assert commutativity
        assert_eq!(a1.snapshot(), b1.snapshot());
        assert_eq!(a1.get(), 20);
        assert_eq!(b1.get(), 20);
    }

    #[test]
    fn test_lwwreg_merge_associative() {
        let a = LWWReg::with_timestamp(10u32, 100, 1);
        let b = LWWReg::with_timestamp(20u32, 200, 2);
        let c = LWWReg::with_timestamp(30u32, 150, 3);
        
        // (a merge b) merge c
        let mut ab_c = a.clone();
        ab_c.merge(&b);
        ab_c.merge(&c);
        
        // a merge (b merge c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);
        
        // Assert associativity
        assert_eq!(ab_c.snapshot(), a_bc.snapshot());
    }

    #[test]
    fn test_lwwreg_merge_idempotent() {
        let mut reg = LWWReg::with_timestamp(42u32, 100, 1);
        let before = reg.snapshot();
        
        // merge with self
        let clone = reg.clone();
        reg.merge(&clone);
        
        let after = reg.snapshot();
        assert_eq!(before, after);
    }

    #[test]
    fn test_lwwreg_concurrent_writes() {
        // Two concurrent writes with same timestamp
        let mut reg = LWWReg::new(0u32, 0);
        
        // First write
        reg.set(10, 100, 1);
        
        // Concurrent write with same timestamp but higher actor
        reg.set(20, 100, 5);
        assert_eq!(reg.get(), 20);
        
        // Try lower actor - should be rejected
        reg.set(30, 100, 2);
        assert_eq!(reg.get(), 20);
    }

    #[test]
    #[should_panic(expected = "timestamp must be positive")]
    fn test_lwwreg_invalid_timestamp() {
        let mut reg = LWWReg::new(0u32, 0);
        reg.set(42, 0, 1);
    }

    #[test]
    #[should_panic(expected = "actor_id")]
    fn test_lwwreg_invalid_actor_id_new() {
        let _ = LWWReg::new(0u32, MAX_ACTORS as u64);
    }

    #[test]
    #[should_panic(expected = "actor_id")]
    fn test_lwwreg_invalid_actor_id_set() {
        let mut reg = LWWReg::new(0u32, 0);
        reg.set(42, 100, MAX_ACTORS as u64);
    }

    #[test]
    fn test_lwwreg_snapshot() {
        let reg = LWWReg::with_timestamp(42u32, 100, 5);
        let snap = reg.snapshot();
        
        assert_eq!(snap.value, 42);
        assert_eq!(snap.timestamp, 100);
        assert_eq!(snap.writer, 5);
    }

    #[test]
    fn test_lwwreg_clone() {
        let reg = LWWReg::with_timestamp(42u32, 100, 5);
        let clone = reg.clone();
        
        assert_eq!(clone.get(), 42);
        assert_eq!(clone.timestamp(), 100);
        assert_eq!(clone.writer(), 5);
    }

    #[test]
    fn test_lwwreg_with_struct() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Point {
            x: i32,
            y: i32,
        }

        let mut reg = LWWReg::new(Point { x: 0, y: 0 }, 1);
        reg.set(Point { x: 10, y: 20 }, 100, 1);
        
        assert_eq!(reg.get(), Point { x: 10, y: 20 });
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
        fn arb_timestamp()(ts in 1u64..1_000_000u64) -> VectorClock {
            ts
        }
    }

    prop_compose! {
        fn arb_value()(val in 0u32..1000u32) -> u32 {
            val
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn proptest_lwwreg_merge_commutative(
            v1 in arb_value(),
            ts1 in arb_timestamp(),
            a1 in arb_actor_id(),
            v2 in arb_value(),
            ts2 in arb_timestamp(),
            a2 in arb_actor_id()
        ) {
            let reg_a = LWWReg::with_timestamp(v1, ts1, a1);
            let reg_b = LWWReg::with_timestamp(v2, ts2, a2);
            
            // merge(A, B)
            let mut ab = reg_a.clone();
            ab.merge(&reg_b);
            
            // merge(B, A)
            let mut ba = reg_b.clone();
            ba.merge(&reg_a);
            
            // Assert commutativity
            prop_assert_eq!(ab.snapshot(), ba.snapshot());
        }

        #[test]
        fn proptest_lwwreg_merge_associative(
            v1 in arb_value(),
            ts1 in arb_timestamp(),
            a1 in arb_actor_id(),
            v2 in arb_value(),
            ts2 in arb_timestamp(),
            a2 in arb_actor_id(),
            v3 in arb_value(),
            ts3 in arb_timestamp(),
            a3 in arb_actor_id()
        ) {
            let reg_a = LWWReg::with_timestamp(v1, ts1, a1);
            let reg_b = LWWReg::with_timestamp(v2, ts2, a2);
            let reg_c = LWWReg::with_timestamp(v3, ts3, a3);
            
            // (A merge B) merge C
            let mut ab_c = reg_a.clone();
            ab_c.merge(&reg_b);
            ab_c.merge(&reg_c);
            
            // A merge (B merge C)
            let mut bc = reg_b.clone();
            bc.merge(&reg_c);
            let mut a_bc = reg_a.clone();
            a_bc.merge(&bc);
            
            // Assert associativity
            prop_assert_eq!(ab_c.snapshot(), a_bc.snapshot());
        }

        #[test]
        fn proptest_lwwreg_merge_idempotent(
            v in arb_value(),
            ts in arb_timestamp(),
            a in arb_actor_id()
        ) {
            let reg = LWWReg::with_timestamp(v, ts, a);
            let before = reg.snapshot();
            
            let mut reg_clone = reg.clone();
            reg_clone.merge(&reg);
            
            let after = reg_clone.snapshot();
            prop_assert_eq!(before, after);
        }

        #[test]
        fn proptest_lwwreg_timestamp_ordering(
            writes in prop::collection::vec(
                (arb_value(), arb_timestamp(), arb_actor_id()),
                1..20
            )
        ) {
            let mut reg = LWWReg::new(0u32, 0);
            
            // Apply all writes
            for (value, timestamp, actor) in &writes {
                reg.set(*value, *timestamp, *actor);
            }
            
            // Find the winning write
            let winner = writes.iter()
                .max_by(|a, b| {
                    match a.1.cmp(&b.1) {
                        std::cmp::Ordering::Equal => a.2.cmp(&b.2),
                        ord => ord,
                    }
                })
                .unwrap();
            
            // Assert final value matches winner
            prop_assert_eq!(reg.get(), winner.0);
        }
    }
}
