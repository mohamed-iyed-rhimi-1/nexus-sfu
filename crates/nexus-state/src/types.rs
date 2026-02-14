//! Core types for CRDT operations
//!
//! This module defines the fundamental types used across all CRDT implementations:
//! - `ActorId`: Unique identifier for each node in the cluster
//! - `VectorClock`: Lamport timestamp for causality tracking
//! - `Dot`: Unique event identifier combining actor and clock
//!
//! All types use explicit sizing (u64) for predictable memory layout and
//! cross-platform compatibility.

use std::cmp::Ordering;

/// Maximum number of actors (nodes) in the distributed system
/// This is a compile-time constant that bounds all actor-indexed arrays
pub const MAX_ACTORS: usize = 256;

/// Maximum number of elements in an Orswot set
pub const MAX_ELEMENTS: usize = 10_000;

/// Maximum number of tombstones in an Orswot set
pub const MAX_TOMBSTONES: usize = 5_000;

// Compile-time assertions for constants
const _: () = {
    assert!(MAX_ACTORS > 0, "MAX_ACTORS must be positive");
    assert!(MAX_ACTORS <= 1024, "MAX_ACTORS must not exceed 1024");
    assert!(MAX_ELEMENTS > 0, "MAX_ELEMENTS must be positive");
    assert!(MAX_TOMBSTONES > 0, "MAX_TOMBSTONES must be positive");
};

/// Unique identifier for each node in the cluster
/// 
/// Combines node ID and timestamp to ensure global uniqueness.
/// The high 32 bits typically contain the node ID, and the low 32 bits
/// contain a monotonic counter or timestamp.
/// 
/// # Size
/// Always 8 bytes (u64)
/// 
/// # Example
/// ```
/// use nexus_state::types::ActorId;
/// 
/// let actor: ActorId = 42;
/// assert!(actor < nexus_state::types::MAX_ACTORS as u64);
/// ```
pub type ActorId = u64;

/// Lamport timestamp for causality tracking
/// 
/// A monotonically increasing counter used to establish happened-before
/// relationships between events. Each operation increments the local clock.
/// 
/// # Size
/// Always 8 bytes (u64)
/// 
/// # Invariants
/// - Clock values start at 1 (0 is reserved for uninitialized state)
/// - Clock values only increase (monotonic)
/// 
/// # Example
/// ```
/// use nexus_state::types::VectorClock;
/// 
/// let clock: VectorClock = 1;
/// assert!(clock > 0, "Clock must be positive");
/// ```
pub type VectorClock = u64;

/// Unique event identifier in a distributed system
/// 
/// A Dot is a tuple of (ActorId, VectorClock) that uniquely identifies
/// an event in the distributed system. Two dots are equal if and only if
/// they have the same actor ID and clock value.
/// 
/// # Size
/// Always 16 bytes (2 × u64)
/// 
/// # Ordering
/// Dots are ordered first by clock, then by actor_id for tie-breaking.
/// This ensures deterministic merge behavior across all nodes.
/// 
/// # Example
/// ```
/// use nexus_state::types::Dot;
/// 
/// let dot = Dot::new(1, 100);
/// assert_eq!(dot.actor_id(), 1);
/// assert_eq!(dot.clock(), 100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct Dot {
    /// The actor (node) that generated this event
    actor_id: ActorId,
    /// The logical clock value when this event occurred
    clock: VectorClock,
}

// Compile-time size assertions
const _: () = {
    assert!(std::mem::size_of::<ActorId>() == 8, "ActorId must be 8 bytes");
    assert!(std::mem::size_of::<VectorClock>() == 8, "VectorClock must be 8 bytes");
    assert!(std::mem::size_of::<Dot>() == 16, "Dot must be 16 bytes");
};

impl Dot {
    /// Creates a new Dot with the given actor ID and clock value
    /// 
    /// # Arguments
    /// * `actor_id` - The actor that generated this event
    /// * `clock` - The logical clock value
    /// 
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS` or `clock == 0`
    /// 
    /// # Example
    /// ```
    /// use nexus_state::types::Dot;
    /// 
    /// let dot = Dot::new(5, 42);
    /// assert_eq!(dot.actor_id(), 5);
    /// assert_eq!(dot.clock(), 42);
    /// ```
    #[inline]
    pub const fn new(actor_id: ActorId, clock: VectorClock) -> Self {
        assert!(actor_id < MAX_ACTORS as u64, "actor_id must be less than MAX_ACTORS");
        assert!(clock > 0, "clock must be positive (non-zero)");
        Self { actor_id, clock }
    }

    /// Creates a new Dot without validation (unsafe)
    /// 
    /// This is useful for creating dots from trusted sources or during
    /// deserialization where validation is done elsewhere.
    /// 
    /// # Safety
    /// Caller must ensure:
    /// - `actor_id < MAX_ACTORS`
    /// - `clock > 0`
    #[inline]
    pub const fn new_unchecked(actor_id: ActorId, clock: VectorClock) -> Self {
        Self { actor_id, clock }
    }

    /// Returns the actor ID component
    #[inline]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the clock component
    #[inline]
    pub const fn clock(&self) -> VectorClock {
        self.clock
    }

    /// Returns true if this dot happened before the other dot
    /// 
    /// A dot A happened-before dot B if:
    /// - A.clock < B.clock, OR
    /// - A.clock == B.clock AND A.actor_id < B.actor_id
    #[inline]
    pub const fn happened_before(&self, other: &Self) -> bool {
        if self.clock < other.clock {
            true
        } else if self.clock == other.clock {
            self.actor_id < other.actor_id
        } else {
            false
        }
    }

    /// Returns true if this dot is concurrent with the other dot
    /// 
    /// Two dots are concurrent if neither happened-before the other.
    /// In practice, this only occurs when they have the same clock
    /// but different actor IDs.
    #[inline]
    pub const fn is_concurrent_with(&self, other: &Self) -> bool {
        self.clock == other.clock && self.actor_id != other.actor_id
    }

    /// Converts the dot to a tuple (actor_id, clock)
    #[inline]
    pub const fn as_tuple(&self) -> (ActorId, VectorClock) {
        (self.actor_id, self.clock)
    }
}

impl From<(ActorId, VectorClock)> for Dot {
    fn from((actor_id, clock): (ActorId, VectorClock)) -> Self {
        Self::new(actor_id, clock)
    }
}

impl From<Dot> for (ActorId, VectorClock) {
    fn from(dot: Dot) -> Self {
        dot.as_tuple()
    }
}

impl PartialOrd for Dot {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Dot {
    /// Orders dots by clock first, then by actor_id for tie-breaking
    /// 
    /// This provides a total ordering that is consistent across all nodes
    /// and deterministic for merge operations.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.clock.cmp(&other.clock) {
            Ordering::Equal => self.actor_id.cmp(&other.actor_id),
            ord => ord,
        }
    }
}

/// A version vector tracking the latest clock value seen from each actor
/// 
/// Used for causality tracking and conflict detection in CRDTs.
/// Pre-allocated with space for MAX_ACTORS entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionVector {
    /// Clock values indexed by actor_id
    clocks: [VectorClock; MAX_ACTORS],
}

impl Default for VersionVector {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionVector {
    /// Creates a new empty version vector with all clocks at 0
    #[inline]
    pub const fn new() -> Self {
        Self {
            clocks: [0; MAX_ACTORS],
        }
    }

    /// Gets the clock value for an actor
    /// 
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS`
    #[inline]
    pub fn get(&self, actor_id: ActorId) -> VectorClock {
        assert!(actor_id < MAX_ACTORS as u64, "actor_id out of bounds");
        self.clocks[actor_id as usize]
    }

    /// Sets the clock value for an actor
    /// 
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS`
    #[inline]
    pub fn set(&mut self, actor_id: ActorId, clock: VectorClock) {
        assert!(actor_id < MAX_ACTORS as u64, "actor_id out of bounds");
        self.clocks[actor_id as usize] = clock;
    }

    /// Increments the clock value for an actor and returns the new value
    /// 
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS` or on overflow
    #[inline]
    pub fn increment(&mut self, actor_id: ActorId) -> VectorClock {
        assert!(actor_id < MAX_ACTORS as u64, "actor_id out of bounds");
        let idx = actor_id as usize;
        let old = self.clocks[idx];
        let new = old.checked_add(1).expect("clock overflow");
        self.clocks[idx] = new;
        
        // Postcondition: clock increased
        debug_assert!(self.clocks[idx] > old);
        new
    }

    /// Updates this version vector to contain the maximum of each clock
    #[inline]
    pub fn merge(&mut self, other: &Self) {
        for i in 0..MAX_ACTORS {
            if other.clocks[i] > self.clocks[i] {
                self.clocks[i] = other.clocks[i];
            }
        }
    }

    /// Returns true if this version vector dominates the other
    /// 
    /// A version vector V1 dominates V2 if for all actors A:
    /// V1[A] >= V2[A] and there exists at least one actor B where V1[B] > V2[B]
    #[inline]
    pub fn dominates(&self, other: &Self) -> bool {
        let mut dominated = false;
        for i in 0..MAX_ACTORS {
            if self.clocks[i] < other.clocks[i] {
                return false;
            }
            if self.clocks[i] > other.clocks[i] {
                dominated = true;
            }
        }
        dominated
    }

    /// Returns true if the given dot is contained in this version vector
    /// 
    /// A dot (actor, clock) is contained if clocks[actor] >= clock
    #[inline]
    pub fn contains_dot(&self, dot: &Dot) -> bool {
        assert!(dot.actor_id() < MAX_ACTORS as u64, "actor_id out of bounds");
        self.clocks[dot.actor_id() as usize] >= dot.clock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_new() {
        let dot = Dot::new(5, 42);
        assert_eq!(dot.actor_id(), 5);
        assert_eq!(dot.clock(), 42);
    }

    #[test]
    #[should_panic(expected = "actor_id must be less than MAX_ACTORS")]
    fn test_dot_invalid_actor_id() {
        let _ = Dot::new(MAX_ACTORS as u64, 1);
    }

    #[test]
    #[should_panic(expected = "clock must be positive")]
    fn test_dot_invalid_clock() {
        let _ = Dot::new(0, 0);
    }

    #[test]
    fn test_dot_ordering() {
        let d1 = Dot::new(1, 10);
        let d2 = Dot::new(2, 10);
        let d3 = Dot::new(1, 20);

        // Same clock, different actor - actor breaks tie
        assert!(d1 < d2);
        
        // Different clock - clock is primary
        assert!(d1 < d3);
        assert!(d2 < d3);
    }

    #[test]
    fn test_dot_happened_before() {
        let d1 = Dot::new(1, 10);
        let d2 = Dot::new(2, 10);
        let d3 = Dot::new(1, 20);

        assert!(d1.happened_before(&d2)); // Same clock, lower actor
        assert!(d1.happened_before(&d3)); // Lower clock
        assert!(!d3.happened_before(&d1)); // Higher clock
    }

    #[test]
    fn test_dot_concurrent() {
        let d1 = Dot::new(1, 10);
        let d2 = Dot::new(2, 10);
        let d3 = Dot::new(1, 20);

        // Same clock, different actors are concurrent
        assert!(d1.is_concurrent_with(&d2));
        assert!(d2.is_concurrent_with(&d1));
        
        // Different clocks are not concurrent
        assert!(!d1.is_concurrent_with(&d3));
    }

    #[test]
    fn test_dot_from_tuple() {
        let dot: Dot = (5u64, 42u64).into();
        assert_eq!(dot.actor_id(), 5);
        assert_eq!(dot.clock(), 42);

        let tuple: (ActorId, VectorClock) = dot.into();
        assert_eq!(tuple, (5, 42));
    }

    #[test]
    fn test_version_vector_new() {
        let vv = VersionVector::new();
        for i in 0..MAX_ACTORS as u64 {
            assert_eq!(vv.get(i), 0);
        }
    }

    #[test]
    fn test_version_vector_set_get() {
        let mut vv = VersionVector::new();
        vv.set(5, 42);
        assert_eq!(vv.get(5), 42);
        assert_eq!(vv.get(0), 0);
    }

    #[test]
    fn test_version_vector_increment() {
        let mut vv = VersionVector::new();
        
        let c1 = vv.increment(5);
        assert_eq!(c1, 1);
        assert_eq!(vv.get(5), 1);
        
        let c2 = vv.increment(5);
        assert_eq!(c2, 2);
        assert_eq!(vv.get(5), 2);
    }

    #[test]
    fn test_version_vector_merge() {
        let mut vv1 = VersionVector::new();
        vv1.set(0, 10);
        vv1.set(1, 20);
        
        let mut vv2 = VersionVector::new();
        vv2.set(0, 5);
        vv2.set(1, 30);
        vv2.set(2, 15);
        
        vv1.merge(&vv2);
        
        assert_eq!(vv1.get(0), 10); // max(10, 5)
        assert_eq!(vv1.get(1), 30); // max(20, 30)
        assert_eq!(vv1.get(2), 15); // max(0, 15)
    }

    #[test]
    fn test_version_vector_dominates() {
        let mut vv1 = VersionVector::new();
        vv1.set(0, 10);
        vv1.set(1, 20);
        
        let mut vv2 = VersionVector::new();
        vv2.set(0, 5);
        vv2.set(1, 15);
        
        assert!(vv1.dominates(&vv2));
        assert!(!vv2.dominates(&vv1));
        
        // Equal vectors don't dominate
        let vv3 = vv1.clone();
        assert!(!vv1.dominates(&vv3));
    }

    #[test]
    fn test_version_vector_contains_dot() {
        let mut vv = VersionVector::new();
        vv.set(5, 10);
        
        assert!(vv.contains_dot(&Dot::new(5, 5)));
        assert!(vv.contains_dot(&Dot::new(5, 10)));
        assert!(!vv.contains_dot(&Dot::new(5, 11)));
        assert!(!vv.contains_dot(&Dot::new(6, 1)));
    }

    #[test]
    #[should_panic(expected = "actor_id out of bounds")]
    fn test_version_vector_get_out_of_bounds() {
        let vv = VersionVector::new();
        let _ = vv.get(MAX_ACTORS as u64);
    }

    #[test]
    fn test_size_assertions() {
        // Verify compile-time size assertions are correct
        assert_eq!(std::mem::size_of::<ActorId>(), 8);
        assert_eq!(std::mem::size_of::<VectorClock>(), 8);
        assert_eq!(std::mem::size_of::<Dot>(), 16);
    }
}
