//! Orswot - Observed-Remove Set Without Tombstones (with bounded tombstones)
//!
//! An Orswot is a set CRDT that supports both add and remove operations.
//! It uses "dots" (actor, clock pairs) to track causality and prevent
//! removed elements from being accidentally resurrected.
//!
//! # Properties
//! - **Add-wins on concurrent add/remove**: If an add and remove happen concurrently,
//!   the add wins (element stays in set)
//! - **Tombstone-based removal**: Removed elements are tracked to prevent resurrection
//! - **Commutative**: `merge(A, B) = merge(B, A)`
//! - **Associative**: `merge(merge(A, B), C) = merge(A, merge(B, C))`
//! - **Idempotent**: `merge(A, A) = A`
//!
//! # Memory Model
//! Pre-allocated fixed-size arrays for elements and tombstones.
//! Zero allocation after initialization.
//!
//! # Capacity
//! - Maximum elements: `MAX_ELEMENTS` (10,000)
//! - Maximum tombstones: `MAX_TOMBSTONES` (5,000)
//!
//! # Example
//! ```
//! use nexus_state::crdt::Orswot;
//! use nexus_state::types::Dot;
//!
//! let mut set: Orswot<u32> = Orswot::new();
//! set.add(42, Dot::new(1, 1)).unwrap();
//! assert!(set.contains(&42));
//! ```

use std::hash::Hash;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{CrdtError, CrdtResult};
use crate::types::{Dot, MAX_ELEMENTS, MAX_TOMBSTONES, MAX_ACTORS};

/// An entry in the Orswot set
#[derive(Debug, Clone, Copy)]
struct Entry<T: Copy> {
    /// The element value (None if slot is empty)
    element: Option<T>,
    /// The dot that added this element
    dot: Dot,
}

impl<T: Copy> Default for Entry<T> {
    fn default() -> Self {
        Self {
            element: None,
            dot: Dot::new_unchecked(0, 0),
        }
    }
}

/// An Observed-Remove Set Without Tombstones CRDT
///
/// This is a set data structure that supports distributed add and remove operations.
/// Elements are tagged with "dots" (actor_id, clock) pairs to track causality.
/// Tombstones are used to remember removed elements and prevent resurrection.
///
/// # Type Parameters
/// * `T` - Element type. Must be `Copy`, `Eq`, and `Hash`.
///
/// # Capacity
/// - Maximum `MAX_ELEMENTS` elements
/// - Maximum `MAX_TOMBSTONES` tombstones
///
/// # Memory Model
/// Uses Box for initial allocation (one-time at creation), but performs zero
/// heap allocation after initialization. All operations on the hot path
/// (add, remove, contains, merge, iter) are allocation-free. 
/// 
/// Note: The `snapshot()` method uses Vec and is intended for testing/debugging,
/// not for hot path operations. Use `iter()` or `write_elements_to()` for
/// zero-allocation element access.
pub struct Orswot<T: Copy + Eq + Hash> {
    /// Pre-allocated array of elements with their dots (heap-allocated once at init)
    entries: Box<[Entry<T>; MAX_ELEMENTS]>,
    /// Number of active elements
    count: AtomicU32,
    /// Pre-allocated tombstone array (heap-allocated once at init)
    tombstones: Box<[Option<Dot>; MAX_TOMBSTONES]>,
    /// Number of tombstones
    tombstone_count: AtomicU32,
}

// Compile-time assertions
const _: () = {
    assert!(MAX_ELEMENTS > 0, "MAX_ELEMENTS must be positive");
    assert!(MAX_TOMBSTONES > 0, "MAX_TOMBSTONES must be positive");
};

impl<T: Copy + Eq + Hash> Orswot<T> {
    /// Creates a new empty Orswot set
    ///
    /// # Postconditions
    /// - `self.len() == 0`
    /// - `self.is_empty() == true`
    ///
    /// # Complexity
    /// O(MAX_ELEMENTS + MAX_TOMBSTONES) time for initialization
    ///
    /// # Memory
    /// One-time heap allocation at creation. Zero allocation after init.
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::Orswot;
    ///
    /// let set: Orswot<u32> = Orswot::new();
    /// assert!(set.is_empty());
    /// assert_eq!(set.len(), 0);
    /// ```
    pub fn new() -> Self {
        // One-time heap allocation at creation
        let result = Self {
            entries: Box::new([Entry::default(); MAX_ELEMENTS]),
            count: AtomicU32::new(0),
            tombstones: Box::new([None; MAX_TOMBSTONES]),
            tombstone_count: AtomicU32::new(0),
        };

        // Postconditions
        debug_assert_eq!(result.len(), 0, "Postcondition: new set must be empty");
        debug_assert!(result.is_empty(), "Postcondition: new set must be empty");

        result
    }

    /// Adds an element to the set with the given dot
    ///
    /// If the element already exists:
    /// - With the same dot: no-op (idempotent)
    /// - With a different dot: update to newer dot if applicable
    ///
    /// # Arguments
    /// * `element` - The element to add
    /// * `dot` - The dot (actor_id, clock) for this add operation
    ///
    /// # Returns
    /// - `Ok(true)` if element was added
    /// - `Ok(false)` if element already exists (idempotent)
    /// - `Err(CapacityExhausted)` if set is full
    ///
    /// # Complexity
    /// O(MAX_ELEMENTS) time for linear scan
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::Orswot;
    /// use nexus_state::types::Dot;
    ///
    /// let mut set: Orswot<u32> = Orswot::new();
    /// assert!(set.add(42, Dot::new(1, 1)).unwrap());
    /// assert!(!set.add(42, Dot::new(1, 1)).unwrap()); // Idempotent
    /// ```
    pub fn add(&mut self, element: T, dot: Dot) -> CrdtResult<bool> {
        // Preconditions
        if dot.actor_id() >= MAX_ACTORS as u64 {
            return Err(CrdtError::InvalidDot {
                actor_id: dot.actor_id(),
                clock: dot.clock(),
            });
        }
        if dot.clock() == 0 {
            return Err(CrdtError::InvalidDot {
                actor_id: dot.actor_id(),
                clock: 0,
            });
        }

        // Check if element is tombstoned with a newer or equal dot
        if self.is_tombstoned(&dot) {
            return Ok(false);
        }

        // Check if element already exists
        for i in 0..MAX_ELEMENTS {
            if let Some(ref existing) = self.entries[i].element {
                if *existing == element {
                    // Element exists - check if we should update the dot
                    if self.entries[i].dot == dot {
                        // Same dot - idempotent
                        return Ok(false);
                    } else if dot > self.entries[i].dot {
                        // Newer dot - update
                        self.entries[i].dot = dot;
                        return Ok(true);
                    }
                    // Older dot - ignore
                    return Ok(false);
                }
            }
        }

        // Element doesn't exist - find empty slot
        let current_count = self.count.load(Ordering::Acquire);
        if current_count >= MAX_ELEMENTS as u32 {
            return Err(CrdtError::CapacityExhausted {
                capacity: MAX_ELEMENTS as u32,
            });
        }

        // Find first empty slot (bounded loop)
        for i in 0..MAX_ELEMENTS {
            if self.entries[i].element.is_none() {
                self.entries[i] = Entry {
                    element: Some(element),
                    dot,
                };
                self.count.fetch_add(1, Ordering::Release);

                // Postcondition: element is now in set
                debug_assert!(self.contains(&element), "Postcondition: element must be in set after add");
                return Ok(true);
            }
        }

        // Should not reach here if count < MAX_ELEMENTS
        Err(CrdtError::CapacityExhausted {
            capacity: MAX_ELEMENTS as u32,
        })
    }

    /// Removes an element from the set
    ///
    /// The element is removed if it exists and the remove dot is newer than
    /// or equal to the add dot. The dot is added to tombstones to prevent resurrection.
    ///
    /// # Arguments
    /// * `element` - The element to remove
    /// * `dot` - The dot for this remove operation
    ///
    /// # Returns
    /// - `Ok(true)` if element was removed
    /// - `Ok(false)` if element doesn't exist or remove was rejected
    /// - `Err(TombstoneOverflow)` if tombstone array is full
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::Orswot;
    /// use nexus_state::types::Dot;
    ///
    /// let mut set: Orswot<u32> = Orswot::new();
    /// set.add(42, Dot::new(1, 1)).unwrap();
    /// assert!(set.remove(&42, Dot::new(1, 2)).unwrap());
    /// assert!(!set.contains(&42));
    /// ```
    pub fn remove(&mut self, element: &T, dot: Dot) -> CrdtResult<bool> {
        // Preconditions
        if dot.actor_id() >= MAX_ACTORS as u64 {
            return Err(CrdtError::InvalidDot {
                actor_id: dot.actor_id(),
                clock: dot.clock(),
            });
        }

        // Find the element
        for i in 0..MAX_ELEMENTS {
            if let Some(ref existing) = self.entries[i].element {
                if existing == element {
                    let entry_dot = self.entries[i].dot;
                    
                    // Only remove if remove dot is >= add dot
                    if dot >= entry_dot {
                        // Add to tombstones
                        self.add_tombstone(entry_dot)?;
                        
                        // Remove element
                        self.entries[i].element = None;
                        self.count.fetch_sub(1, Ordering::Release);

                        // Postcondition: element not in set
                        debug_assert!(!self.contains(element), "Postcondition: element must not be in set after remove");
                        return Ok(true);
                    }
                    // Remove dot is older - reject
                    return Ok(false);
                }
            }
        }

        // Element not found - no-op
        Ok(false)
    }

    /// Checks if an element is in the set
    ///
    /// # Arguments
    /// * `element` - The element to check
    ///
    /// # Returns
    /// `true` if the element is in the set
    ///
    /// # Complexity
    /// O(MAX_ELEMENTS) time for linear scan
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::Orswot;
    /// use nexus_state::types::Dot;
    ///
    /// let mut set: Orswot<u32> = Orswot::new();
    /// assert!(!set.contains(&42));
    /// set.add(42, Dot::new(1, 1)).unwrap();
    /// assert!(set.contains(&42));
    /// ```
    #[inline]
    pub fn contains(&self, element: &T) -> bool {
        for i in 0..MAX_ELEMENTS {
            if let Some(ref existing) = self.entries[i].element {
                if existing == element {
                    return true;
                }
            }
        }
        false
    }

    /// Returns the number of elements in the set
    ///
    /// # Complexity
    /// O(1) time
    #[inline]
    pub fn len(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }

    /// Returns true if the set is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of tombstones
    #[inline]
    pub fn tombstone_count(&self) -> u32 {
        self.tombstone_count.load(Ordering::Acquire)
    }

    /// Merges another Orswot into this one
    ///
    /// For each element in other:
    /// - If not in self, add it (unless tombstoned)
    /// - If in self, keep the newer dot
    ///
    /// For each tombstone in other:
    /// - Add to self's tombstones
    /// - Remove any elements with matching dots
    ///
    /// # Arguments
    /// * `other` - The Orswot to merge from
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(CapacityExhausted)` if capacity limits are exceeded
    ///
    /// # Example
    /// ```
    /// use nexus_state::crdt::Orswot;
    /// use nexus_state::types::Dot;
    ///
    /// let mut a: Orswot<u32> = Orswot::new();
    /// a.add(1, Dot::new(0, 1)).unwrap();
    ///
    /// let mut b: Orswot<u32> = Orswot::new();
    /// b.add(2, Dot::new(1, 1)).unwrap();
    ///
    /// a.merge(&b).unwrap();
    /// assert!(a.contains(&1));
    /// assert!(a.contains(&2));
    /// ```
    pub fn merge(&mut self, other: &Orswot<T>) -> CrdtResult<()> {
        // First, merge tombstones and remove affected elements
        for i in 0..MAX_TOMBSTONES {
            if let Some(tombstone_dot) = other.tombstones[i] {
                // Add tombstone if not already present
                if !self.has_tombstone(&tombstone_dot) {
                    self.add_tombstone(tombstone_dot)?;
                }
                
                // Remove any element with this dot
                self.remove_by_dot(&tombstone_dot);
            }
        }

        // Then, merge elements - propagate errors immediately
        for i in 0..MAX_ELEMENTS {
            if let Some(element) = other.entries[i].element {
                let dot = other.entries[i].dot;
                
                // Skip if tombstoned
                if self.is_tombstoned(&dot) {
                    continue;
                }

                // Try to add the element - propagate any error
                self.add(element, dot)?;
            }
        }

        Ok(())
    }

    /// Returns an iterator over the elements in the set
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().filter_map(|e| e.element.as_ref())
    }

    /// Returns a snapshot of the set for comparison
    /// 
    /// Note: This method allocates Vec for the snapshot. Use for testing
    /// and debugging, not on the hot path. For zero-allocation element
    /// access, use `iter()` or `write_elements_to()`.
    pub fn snapshot(&self) -> OrswotSnapshot<T> {
        // Collect elements
        let mut elements: Vec<(T, Dot)> = self.entries
            .iter()
            .filter_map(|e| e.element.map(|el| (el, e.dot)))
            .collect();

        // Collect tombstones
        let mut tombstones: Vec<Dot> = self.tombstones
            .iter()
            .filter_map(|opt| *opt)
            .collect();

        // Sort for deterministic comparison
        elements.sort_by_key(|(_, dot)| *dot);
        tombstones.sort();

        OrswotSnapshot {
            elements,
            tombstones,
        }
    }

    /// Writes elements into a caller-provided buffer
    /// 
    /// # Arguments
    /// * `buffer` - A mutable slice to write elements into
    /// 
    /// # Returns
    /// The number of elements written (may be less than set length if buffer is too small)
    pub fn write_elements_to(&self, buffer: &mut [(T, Dot)]) -> u32 {
        let mut written = 0u32;
        let max_write = buffer.len().min(MAX_ELEMENTS);

        for i in 0..MAX_ELEMENTS {
            if written as usize >= max_write {
                break;
            }
            if let Some(element) = self.entries[i].element {
                buffer[written as usize] = (element, self.entries[i].dot);
                written += 1;
            }
        }

        written
    }

    /// Writes tombstones into a caller-provided buffer
    /// 
    /// # Arguments
    /// * `buffer` - A mutable slice to write tombstones into
    /// 
    /// # Returns
    /// The number of tombstones written
    pub fn write_tombstones_to(&self, buffer: &mut [Dot]) -> u32 {
        let mut written = 0u32;
        let max_write = buffer.len().min(MAX_TOMBSTONES);

        for i in 0..MAX_TOMBSTONES {
            if written as usize >= max_write {
                break;
            }
            if let Some(dot) = self.tombstones[i] {
                buffer[written as usize] = dot;
                written += 1;
            }
        }

        written
    }

    // --- Private helper methods ---

    /// Adds a dot to the tombstone array
    fn add_tombstone(&mut self, dot: Dot) -> CrdtResult<()> {
        // Check if already tombstoned
        if self.has_tombstone(&dot) {
            return Ok(());
        }

        let current_count = self.tombstone_count.load(Ordering::Acquire);
        if current_count >= MAX_TOMBSTONES as u32 {
            return Err(CrdtError::TombstoneOverflow {
                count: current_count,
                max: MAX_TOMBSTONES as u32,
            });
        }

        // Find empty slot
        for i in 0..MAX_TOMBSTONES {
            if self.tombstones[i].is_none() {
                self.tombstones[i] = Some(dot);
                self.tombstone_count.fetch_add(1, Ordering::Release);
                return Ok(());
            }
        }

        Err(CrdtError::TombstoneOverflow {
            count: current_count,
            max: MAX_TOMBSTONES as u32,
        })
    }

    /// Checks if a dot is tombstoned
    fn is_tombstoned(&self, dot: &Dot) -> bool {
        for i in 0..MAX_TOMBSTONES {
            if let Some(tombstone) = self.tombstones[i] {
                // A dot is tombstoned if there's a tombstone with:
                // - Same actor and clock >= dot's clock
                if tombstone.actor_id() == dot.actor_id() && tombstone.clock() >= dot.clock() {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a specific dot is in the tombstone array
    fn has_tombstone(&self, dot: &Dot) -> bool {
        for i in 0..MAX_TOMBSTONES {
            if let Some(tombstone) = self.tombstones[i] {
                if tombstone == *dot {
                    return true;
                }
            }
        }
        false
    }

    /// Removes an element by its dot
    fn remove_by_dot(&mut self, dot: &Dot) {
        for i in 0..MAX_ELEMENTS {
            if self.entries[i].element.is_some() && self.entries[i].dot == *dot {
                self.entries[i].element = None;
                self.count.fetch_sub(1, Ordering::Release);
                return;
            }
        }
    }
}

impl<T: Copy + Eq + Hash> Default for Orswot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Eq + Hash + std::fmt::Debug> std::fmt::Debug for Orswot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid heap allocation by using a debug helper that iterates
        struct ElementsDebug<'a, T: Copy + Eq + Hash + std::fmt::Debug>(&'a Orswot<T>);
        
        impl<'a, T: Copy + Eq + Hash + std::fmt::Debug> std::fmt::Debug for ElementsDebug<'a, T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        f.debug_struct("Orswot")
            .field("len", &self.len())
            .field("tombstone_count", &self.tombstone_count())
            .field("elements", &ElementsDebug(self))
            .finish()
    }
}

/// A snapshot of an Orswot for comparison
/// 
/// Uses Vec for storage since snapshots are typically used for testing
/// and debugging, not on the hot path. This avoids stack overflow with
/// large fixed arrays.
#[derive(Debug, Clone)]
pub struct OrswotSnapshot<T: Copy + Eq + Hash> {
    /// Elements with their dots
    pub elements: Vec<(T, Dot)>,
    /// Tombstone dots
    pub tombstones: Vec<Dot>,
}

impl<T: Copy + Eq + Hash> PartialEq for OrswotSnapshot<T> {
    fn eq(&self, other: &Self) -> bool {
        // Compare as sets, not ordered vectors
        // Elements are equal if they contain the same (element, dot) pairs
        if self.elements.len() != other.elements.len() {
            return false;
        }
        if self.tombstones.len() != other.tombstones.len() {
            return false;
        }
        
        // Check all elements in self are in other
        for elem in &self.elements {
            if !other.elements.contains(elem) {
                return false;
            }
        }
        
        // Check all tombstones in self are in other
        for tomb in &self.tombstones {
            if !other.tombstones.contains(tomb) {
                return false;
            }
        }
        
        true
    }
}

impl<T: Copy + Eq + Hash> Eq for OrswotSnapshot<T> {}

impl<T: Copy + Eq + Hash> OrswotSnapshot<T> {
    /// Returns true if this snapshot contains the element
    pub fn contains(&self, element: &T) -> bool {
        self.elements.iter().any(|(e, _)| e == element)
    }

    /// Returns the number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns true if empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns an iterator over elements
    pub fn iter_elements(&self) -> impl Iterator<Item = (T, Dot)> + '_ {
        self.elements.iter().copied()
    }

    /// Returns an iterator over tombstones
    pub fn iter_tombstones(&self) -> impl Iterator<Item = Dot> + '_ {
        self.tombstones.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orswot_new() {
        let set: Orswot<u32> = Orswot::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.tombstone_count(), 0);
    }

    #[test]
    fn test_orswot_add_single() {
        let mut set: Orswot<u32> = Orswot::new();
        
        let added = set.add(42, Dot::new(1, 1)).unwrap();
        assert!(added);
        assert!(set.contains(&42));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_orswot_add_duplicate_idempotent() {
        let mut set: Orswot<u32> = Orswot::new();
        
        let added1 = set.add(42, Dot::new(1, 1)).unwrap();
        let added2 = set.add(42, Dot::new(1, 1)).unwrap();
        
        assert!(added1);
        assert!(!added2); // Idempotent - already exists with same dot
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_orswot_add_same_element_newer_dot() {
        let mut set: Orswot<u32> = Orswot::new();
        
        set.add(42, Dot::new(1, 1)).unwrap();
        let updated = set.add(42, Dot::new(1, 5)).unwrap();
        
        assert!(updated); // Updated with newer dot
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_orswot_remove() {
        let mut set: Orswot<u32> = Orswot::new();
        
        set.add(42, Dot::new(1, 1)).unwrap();
        assert!(set.contains(&42));
        
        let removed = set.remove(&42, Dot::new(1, 2)).unwrap();
        assert!(removed);
        assert!(!set.contains(&42));
        assert_eq!(set.len(), 0);
        assert_eq!(set.tombstone_count(), 1);
    }

    #[test]
    fn test_orswot_remove_nonexistent() {
        let mut set: Orswot<u32> = Orswot::new();
        
        let removed = set.remove(&42, Dot::new(1, 1)).unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_orswot_add_after_remove() {
        let mut set: Orswot<u32> = Orswot::new();
        
        // Add with dot (1, 1)
        set.add(42, Dot::new(1, 1)).unwrap();
        
        // Remove with dot (1, 2)
        set.remove(&42, Dot::new(1, 2)).unwrap();
        assert!(!set.contains(&42));
        
        // Try to re-add with older dot (1, 1) - should be rejected (tombstoned)
        let re_added = set.add(42, Dot::new(1, 1)).unwrap();
        assert!(!re_added);
        assert!(!set.contains(&42));
        
        // Add with newer dot (1, 3) - should succeed
        let re_added = set.add(42, Dot::new(1, 3)).unwrap();
        assert!(re_added);
        assert!(set.contains(&42));
    }

    #[test]
    fn test_orswot_merge_commutative() {
        let mut a: Orswot<u32> = Orswot::new();
        a.add(1, Dot::new(0, 1)).unwrap();
        a.add(2, Dot::new(0, 2)).unwrap();
        
        let mut b: Orswot<u32> = Orswot::new();
        b.add(3, Dot::new(1, 1)).unwrap();
        b.add(4, Dot::new(1, 2)).unwrap();
        
        // merge(a, b)
        let mut ab: Orswot<u32> = Orswot::new();
        ab.add(1, Dot::new(0, 1)).unwrap();
        ab.add(2, Dot::new(0, 2)).unwrap();
        ab.merge(&b).unwrap();
        
        // merge(b, a)
        let mut ba: Orswot<u32> = Orswot::new();
        ba.add(3, Dot::new(1, 1)).unwrap();
        ba.add(4, Dot::new(1, 2)).unwrap();
        ba.merge(&a).unwrap();
        
        // Assert commutativity
        assert_eq!(ab.snapshot(), ba.snapshot());
    }

    #[test]
    fn test_orswot_merge_associative() {
        let mut a: Orswot<u32> = Orswot::new();
        a.add(1, Dot::new(0, 1)).unwrap();
        
        let mut b: Orswot<u32> = Orswot::new();
        b.add(2, Dot::new(1, 1)).unwrap();
        
        let mut c: Orswot<u32> = Orswot::new();
        c.add(3, Dot::new(2, 1)).unwrap();
        
        // (a merge b) merge c
        let mut ab_c: Orswot<u32> = Orswot::new();
        ab_c.add(1, Dot::new(0, 1)).unwrap();
        ab_c.merge(&b).unwrap();
        ab_c.merge(&c).unwrap();
        
        // a merge (b merge c)
        let mut bc: Orswot<u32> = Orswot::new();
        bc.add(2, Dot::new(1, 1)).unwrap();
        bc.merge(&c).unwrap();
        
        let mut a_bc: Orswot<u32> = Orswot::new();
        a_bc.add(1, Dot::new(0, 1)).unwrap();
        a_bc.merge(&bc).unwrap();
        
        // Assert associativity
        assert_eq!(ab_c.snapshot(), a_bc.snapshot());
    }

    #[test]
    fn test_orswot_merge_idempotent() {
        let mut set: Orswot<u32> = Orswot::new();
        set.add(1, Dot::new(0, 1)).unwrap();
        set.add(2, Dot::new(1, 1)).unwrap();
        
        let before = set.snapshot();
        set.merge(&set.clone_for_merge()).unwrap();
        let after = set.snapshot();
        
        // Assert idempotence
        assert_eq!(before, after);
    }

    #[test]
    fn test_orswot_concurrent_add_remove() {
        // Simulate concurrent add and remove
        let mut a: Orswot<u32> = Orswot::new();
        a.add(42, Dot::new(0, 1)).unwrap();
        
        let mut b: Orswot<u32> = Orswot::new();
        b.add(42, Dot::new(0, 1)).unwrap();
        
        // A adds with newer dot
        a.add(42, Dot::new(0, 5)).unwrap();
        
        // B removes
        b.remove(&42, Dot::new(0, 2)).unwrap();
        
        // Merge - the add with newer dot should win
        a.merge(&b).unwrap();
        
        // Element should still be present (add wins due to newer dot)
        assert!(a.contains(&42));
    }

    #[test]
    fn test_orswot_capacity_exhausted() {
        let mut set: Orswot<u32> = Orswot::new();
        
        // Fill to capacity
        for i in 0..MAX_ELEMENTS as u32 {
            let actor = (i % MAX_ACTORS as u32) as u64;
            let clock = (i / MAX_ACTORS as u32 + 1) as u64;
            set.add(i, Dot::new(actor, clock)).unwrap();
        }
        
        // Next add should fail
        let result = set.add(999999, Dot::new(0, 999999));
        assert!(matches!(result, Err(CrdtError::CapacityExhausted { .. })));
    }

    #[test]
    fn test_orswot_invalid_dot() {
        let mut set: Orswot<u32> = Orswot::new();
        
        // Invalid actor ID
        let result = set.add(42, Dot::new_unchecked(MAX_ACTORS as u64, 1));
        assert!(matches!(result, Err(CrdtError::InvalidDot { .. })));
    }

    #[test]
    fn test_orswot_iter() {
        let mut set: Orswot<u32> = Orswot::new();
        set.add(1, Dot::new(0, 1)).unwrap();
        set.add(2, Dot::new(0, 2)).unwrap();
        set.add(3, Dot::new(0, 3)).unwrap();
        
        let elements: Vec<_> = set.iter().copied().collect();
        assert_eq!(elements.len(), 3);
        assert!(elements.contains(&1));
        assert!(elements.contains(&2));
        assert!(elements.contains(&3));
    }

    #[test]
    fn test_orswot_snapshot() {
        let mut set: Orswot<u32> = Orswot::new();
        set.add(1, Dot::new(0, 1)).unwrap();
        set.add(2, Dot::new(1, 1)).unwrap();
        
        let snap = set.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&1));
        assert!(snap.contains(&2));
    }

    impl<T: Copy + Eq + Hash> Orswot<T> {
        /// Creates a clone suitable for merging (for tests only)
        #[cfg(test)]
        fn clone_for_merge(&self) -> Self {
            let mut other = Self::new();
            for i in 0..MAX_ELEMENTS {
                if let Some(element) = self.entries[i].element {
                    let _ = other.add(element, self.entries[i].dot);
                }
            }
            for i in 0..MAX_TOMBSTONES {
                if let Some(dot) = self.tombstones[i] {
                    let _ = other.add_tombstone(dot);
                }
            }
            other
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_actor_id()(id in 0u64..(MAX_ACTORS as u64)) -> u64 {
            id
        }
    }

    prop_compose! {
        fn arb_clock()(clock in 1u64..1000u64) -> u64 {
            clock
        }
    }

    prop_compose! {
        fn arb_element()(elem in 0u32..1000u32) -> u32 {
            elem
        }
    }

    prop_compose! {
        fn arb_dot()(actor in arb_actor_id(), clock in arb_clock()) -> Dot {
            Dot::new(actor, clock)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn proptest_orswot_merge_commutative(
            ops_a in prop::collection::vec((arb_element(), arb_dot()), 0..20),
            ops_b in prop::collection::vec((arb_element(), arb_dot()), 0..20)
        ) {
            let mut a: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_a {
                let _ = a.add(*elem, *dot);
            }
            
            let mut b: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_b {
                let _ = b.add(*elem, *dot);
            }
            
            // merge(A, B)
            let mut ab: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_a {
                let _ = ab.add(*elem, *dot);
            }
            let _ = ab.merge(&b);
            
            // merge(B, A)
            let mut ba: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_b {
                let _ = ba.add(*elem, *dot);
            }
            let _ = ba.merge(&a);
            
            // Assert commutativity
            prop_assert_eq!(ab.snapshot(), ba.snapshot());
        }

        #[test]
        fn proptest_orswot_merge_associative(
            ops_a in prop::collection::vec((arb_element(), arb_dot()), 0..10),
            ops_b in prop::collection::vec((arb_element(), arb_dot()), 0..10),
            ops_c in prop::collection::vec((arb_element(), arb_dot()), 0..10)
        ) {
            let mut a: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_a {
                let _ = a.add(*elem, *dot);
            }
            
            let mut b: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_b {
                let _ = b.add(*elem, *dot);
            }
            
            let mut c: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_c {
                let _ = c.add(*elem, *dot);
            }
            
            // (A merge B) merge C
            let mut ab_c: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_a {
                let _ = ab_c.add(*elem, *dot);
            }
            let _ = ab_c.merge(&b);
            let _ = ab_c.merge(&c);
            
            // A merge (B merge C)
            let mut bc: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_b {
                let _ = bc.add(*elem, *dot);
            }
            let _ = bc.merge(&c);
            
            let mut a_bc: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops_a {
                let _ = a_bc.add(*elem, *dot);
            }
            let _ = a_bc.merge(&bc);
            
            // Assert associativity
            prop_assert_eq!(ab_c.snapshot(), a_bc.snapshot());
        }

        #[test]
        fn proptest_orswot_merge_idempotent(
            ops in prop::collection::vec((arb_element(), arb_dot()), 0..20)
        ) {
            let mut set: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops {
                let _ = set.add(*elem, *dot);
            }
            
            let before = set.snapshot();
            
            // Create a copy for merging
            let mut copy: Orswot<u32> = Orswot::new();
            for (elem, dot) in &ops {
                let _ = copy.add(*elem, *dot);
            }
            
            let _ = set.merge(&copy);
            let after = set.snapshot();
            
            // Assert idempotence
            prop_assert_eq!(before, after);
        }

        #[test]
        fn proptest_orswot_add_remove_convergence(
            adds_a in prop::collection::vec((arb_element(), arb_dot()), 0..10),
            adds_b in prop::collection::vec((arb_element(), arb_dot()), 0..10)
        ) {
            let mut a: Orswot<u32> = Orswot::new();
            for (elem, dot) in &adds_a {
                let _ = a.add(*elem, *dot);
            }
            
            let mut b: Orswot<u32> = Orswot::new();
            for (elem, dot) in &adds_b {
                let _ = b.add(*elem, *dot);
            }
            
            // Merge both ways
            let mut ab: Orswot<u32> = Orswot::new();
            for (elem, dot) in &adds_a {
                let _ = ab.add(*elem, *dot);
            }
            let _ = ab.merge(&b);
            
            let mut ba: Orswot<u32> = Orswot::new();
            for (elem, dot) in &adds_b {
                let _ = ba.add(*elem, *dot);
            }
            let _ = ba.merge(&a);
            
            // Both should converge to same state
            prop_assert_eq!(ab.snapshot(), ba.snapshot());
        }

        #[test]
        fn proptest_orswot_tombstone_prevents_resurrection(
            elem in arb_element(),
            actor in arb_actor_id()
        ) {
            let mut set: Orswot<u32> = Orswot::new();
            
            // Add with dot D1 (clock 1)
            let _ = set.add(elem, Dot::new(actor, 1));
            prop_assert!(set.contains(&elem));
            
            // Remove with dot D2 (clock 2) - newer
            let _ = set.remove(&elem, Dot::new(actor, 2));
            prop_assert!(!set.contains(&elem));
            
            // Try to re-add with D1 (clock 1) - should be rejected (tombstoned)
            let re_added = set.add(elem, Dot::new(actor, 1)).unwrap();
            prop_assert!(!re_added);
            prop_assert!(!set.contains(&elem));
        }
    }
}
