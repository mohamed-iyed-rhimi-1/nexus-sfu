//! Property-based tests for PacketArena refcount invariant.
//!
//! Validates:
//! - Refcount invariant: free_count + allocated_count == capacity
//! - Clone shallow increments refcount
//! - Drop decrements refcount and deallocates on zero
//!
//! Property 6: PacketArena Alloc/Dealloc and Refcount Invariant
//! Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6

use proptest::prelude::*;
use proptest::collection::vec;

use crate::arena::{PacketArena, PacketSlot};

/// Operation on the arena for property testing.
#[derive(Debug, Clone)]
enum ArenaOp {
    /// Allocate a new slot.
    Alloc,
    /// Clone an existing slot (by index in our tracking vec).
    CloneShallow(usize),
    /// Drop a slot (by index in our tracking vec).
    Drop(usize),
}

/// Strategy to generate a sequence of arena operations.
fn arena_ops_strategy() -> impl Strategy<Value = Vec<ArenaOp>> {
    vec(
        prop_oneof![
            // 40% alloc, 30% clone, 30% drop
            4 => Just(ArenaOp::Alloc),
            3 => (0usize..100).prop_map(ArenaOp::CloneShallow),
            3 => (0usize..100).prop_map(ArenaOp::Drop),
        ],
        1..200, // 1 to 200 operations per test
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: free_count + allocated_count == capacity always holds.
    ///
    /// For any sequence of alloc/clone_shallow/drop operations, the
    /// invariant free_count + allocated_count == capacity is maintained.
    #[test]
    fn prop_arena_count_invariant(ops in arena_ops_strategy()) {
        let arena = PacketArena::new(1).expect("arena creation");
        let capacity = arena.capacity();

        // Track allocated slots
        let mut slots: Vec<PacketSlot> = Vec::new();

        for op in ops {
            match op {
                ArenaOp::Alloc => {
                    if let Some(slot) = arena.alloc() {
                        slots.push(slot);
                    }
                }
                ArenaOp::CloneShallow(idx) => {
                    if !slots.is_empty() {
                        let idx = idx % slots.len();
                        let clone = slots[idx].clone_shallow();
                        slots.push(clone);
                    }
                }
                ArenaOp::Drop(idx) => {
                    if !slots.is_empty() {
                        let idx = idx % slots.len();
                        slots.swap_remove(idx);
                    }
                }
            }

            // Property: free_count + allocated_count == capacity
            let free = arena.free_count();
            let allocated = arena.allocated_count();
            prop_assert_eq!(
                free + allocated,
                capacity,
                "invariant violated: free {} + allocated {} != capacity {}",
                free, allocated, capacity
            );
        }

        // Drop all remaining slots
        slots.clear();

        // After all drops, all slots should be free
        prop_assert_eq!(
            arena.free_count(),
            capacity,
            "after dropping all slots, free_count {} != capacity {}",
            arena.free_count(),
            capacity
        );
    }

    /// Property: clone_shallow increments refcount.
    #[test]
    fn prop_clone_shallow_increments_refcount(num_clones in 1usize..=10) {
        let arena = PacketArena::new(1).expect("arena creation");

        let slot = arena.alloc().expect("should allocate");
        prop_assert_eq!(slot.ref_count(), 1, "initial refcount should be 1");

        let mut clones: Vec<PacketSlot> = vec![slot];

        for i in 0..num_clones {
            let clone = clones[0].clone_shallow();
            clones.push(clone);

            // Property: refcount increases with each clone
            let expected_refcount = (i + 2) as u32;
            prop_assert_eq!(
                clones[0].ref_count(),
                expected_refcount,
                "after {} clones, refcount should be {}",
                i + 1,
                expected_refcount
            );
        }

        // All clones share the same refcount
        for clone in &clones {
            prop_assert_eq!(
                clone.ref_count(),
                (num_clones + 1) as u32,
                "all clones should have same refcount"
            );
        }
    }

    /// Property: drop decrements refcount and deallocates on zero.
    #[test]
    fn prop_drop_decrements_refcount(num_clones in 1usize..=10) {
        let arena = PacketArena::new(1).expect("arena creation");
        let initial_free = arena.free_count();

        let slot = arena.alloc().expect("should allocate");
        let mut clones: Vec<PacketSlot> = vec![slot];

        // Create clones
        for _ in 0..num_clones {
            let clone = clones[0].clone_shallow();
            clones.push(clone);
        }

        // Slot is still allocated (refcount > 0)
        prop_assert_eq!(
            arena.free_count(),
            initial_free - 1,
            "slot should still be allocated"
        );

        // Drop all but one
        while clones.len() > 1 {
            let remaining = clones.len();
            clones.pop();

            // Refcount should decrease
            prop_assert_eq!(
                clones[0].ref_count(),
                (remaining - 1) as u32,
                "refcount should decrease after drop"
            );

            // Slot should still be allocated
            prop_assert_eq!(
                arena.free_count(),
                initial_free - 1,
                "slot should still be allocated while refcount > 0"
            );
        }

        // Drop the last one
        clones.clear();

        // Now slot should be deallocated
        prop_assert_eq!(
            arena.free_count(),
            initial_free,
            "slot should be deallocated when refcount reaches 0"
        );
    }

    /// Property: allocated slots have unique indices.
    #[test]
    fn prop_allocated_slots_unique(num_allocs in 1usize..=100) {
        let arena = PacketArena::new(1).expect("arena creation");

        let mut slots: Vec<PacketSlot> = Vec::new();
        let mut indices: Vec<u32> = Vec::new();

        for _ in 0..num_allocs {
            if let Some(slot) = arena.alloc() {
                let idx = slot.slot_index();

                // Property: no duplicate indices
                prop_assert!(
                    !indices.contains(&idx),
                    "duplicate slot index {} allocated",
                    idx
                );

                indices.push(idx);
                slots.push(slot);
            }
        }
    }

    /// Property: deallocated slots can be reallocated.
    #[test]
    fn prop_dealloc_realloc(num_cycles in 1usize..=20) {
        let arena = PacketArena::new(1).expect("arena creation");
        let initial_free = arena.free_count();

        for _ in 0..num_cycles {
            // Allocate
            let slot = arena.alloc().expect("should allocate");
            let idx = slot.slot_index();

            prop_assert_eq!(
                arena.free_count(),
                initial_free - 1,
                "free count should decrease after alloc"
            );

            // Deallocate
            drop(slot);

            prop_assert_eq!(
                arena.free_count(),
                initial_free,
                "free count should restore after dealloc"
            );

            // Reallocate - should get the same slot back (LIFO)
            let slot2 = arena.alloc().expect("should reallocate");
            prop_assert_eq!(
                slot2.slot_index(),
                idx,
                "should reallocate same slot (LIFO)"
            );

            drop(slot2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_refcount_proptest_sanity() {
        let arena = PacketArena::new(1).expect("arena creation");
        let capacity = arena.capacity();

        // Allocate a slot
        let slot = arena.alloc().expect("should allocate");
        assert_eq!(slot.ref_count(), 1);
        assert_eq!(arena.free_count() + arena.allocated_count(), capacity);

        // Clone it
        let clone = slot.clone_shallow();
        assert_eq!(slot.ref_count(), 2);
        assert_eq!(clone.ref_count(), 2);
        assert_eq!(arena.free_count() + arena.allocated_count(), capacity);

        // Drop clone
        drop(clone);
        assert_eq!(slot.ref_count(), 1);
        assert_eq!(arena.free_count() + arena.allocated_count(), capacity);

        // Drop original
        drop(slot);
        assert_eq!(arena.free_count(), capacity);
    }
}
