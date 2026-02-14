//! Property-based tests for ArenaPartition.
//!
//! Validates:
//! - Partition disjointness: partitions cover disjoint slot ranges
//! - Union completeness: union of all partitions equals [0, capacity)
//! - Allocation correctness: slots are allocated within partition bounds
//!
//! Property 3: Arena Partition Disjointness
//! Validates: Requirements 1.6

use proptest::prelude::*;

use crate::arena::{PacketArena, create_partitions};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Partitions cover disjoint ranges whose union equals [0, C).
    ///
    /// For any N workers and capacity C, the partitions:
    /// 1. Have non-overlapping ranges
    /// 2. Together cover all slots from 0 to C-1
    #[test]
    fn prop_partition_disjoint_union(
        num_partitions in 1u32..=32,
        arena_size_mb in 1u32..=4,
    ) {
        let arena = PacketArena::new(arena_size_mb).expect("arena creation");
        let total_capacity = arena.capacity();

        // Skip if we'd have more partitions than slots
        prop_assume!(num_partitions <= total_capacity);

        let partitions = create_partitions(&arena, num_partitions);

        // Property 1: Correct number of partitions
        prop_assert_eq!(
            partitions.len() as u32,
            num_partitions,
            "expected {} partitions, got {}",
            num_partitions,
            partitions.len()
        );

        // Property 2: Partitions are disjoint (no overlap)
        for i in 0..partitions.len() {
            for j in (i + 1)..partitions.len() {
                let p1 = &partitions[i];
                let p2 = &partitions[j];

                // Ranges must not overlap
                let overlaps = p1.start_slot() < p2.end_slot() &&
                               p2.start_slot() < p1.end_slot();

                prop_assert!(
                    !overlaps,
                    "partitions {} [{}, {}) and {} [{}, {}) overlap",
                    i, p1.start_slot(), p1.end_slot(),
                    j, p2.start_slot(), p2.end_slot()
                );
            }
        }

        // Property 3: Union covers all slots [0, capacity)
        let mut covered: Vec<bool> = vec![false; total_capacity as usize];
        for partition in &partitions {
            for slot in partition.start_slot()..partition.end_slot() {
                prop_assert!(
                    !covered[slot as usize],
                    "slot {} covered by multiple partitions",
                    slot
                );
                covered[slot as usize] = true;
            }
        }

        // All slots must be covered
        for (slot, is_covered) in covered.iter().enumerate() {
            prop_assert!(
                *is_covered,
                "slot {} not covered by any partition",
                slot
            );
        }

        // Property 4: Total capacity matches
        let total_partition_capacity: u32 = partitions.iter()
            .map(|p| p.capacity())
            .sum();
        prop_assert_eq!(
            total_partition_capacity,
            total_capacity,
            "partition capacities {} don't sum to arena capacity {}",
            total_partition_capacity,
            total_capacity
        );
    }

    /// Property: Allocated slots are within partition bounds.
    ///
    /// For any allocation from a partition, the slot index is within
    /// that partition's [start, end) range.
    #[test]
    fn prop_partition_alloc_bounds(
        num_partitions in 1u32..=8,
        allocs_per_partition in 1usize..=50,
    ) {
        let arena = PacketArena::new(1).expect("arena creation");
        let total_capacity = arena.capacity();

        prop_assume!(num_partitions <= total_capacity);

        let partitions = create_partitions(&arena, num_partitions);

        // Keep all allocated slots alive to prevent reuse
        let mut all_slots: Vec<crate::arena::PartitionedPacketSlot> = Vec::new();

        for partition in &partitions {
            let mut allocated_slots: Vec<u32> = Vec::new();

            // Allocate multiple slots from this partition
            let max_allocs = allocs_per_partition.min(partition.capacity() as usize);
            for _ in 0..max_allocs {
                if let Some(slot) = partition.alloc() {
                    let slot_idx = slot.slot_index();

                    // Property: slot is within partition range
                    prop_assert!(
                        slot_idx >= partition.start_slot() &&
                        slot_idx < partition.end_slot(),
                        "slot {} not in partition {} range [{}, {})",
                        slot_idx,
                        partition.partition_id(),
                        partition.start_slot(),
                        partition.end_slot()
                    );

                    // Property: slot is unique (no double allocation)
                    prop_assert!(
                        !allocated_slots.contains(&slot_idx),
                        "slot {} allocated twice from partition {}",
                        slot_idx,
                        partition.partition_id()
                    );

                    allocated_slots.push(slot_idx);
                    all_slots.push(slot); // Keep slot alive
                }
            }
        }
    }

    /// Property: Partition owns_slot is consistent with range.
    #[test]
    fn prop_partition_owns_slot_consistent(
        num_partitions in 2u32..=16,
    ) {
        let arena = PacketArena::new(1).expect("arena creation");
        let total_capacity = arena.capacity();

        prop_assume!(num_partitions <= total_capacity);

        let partitions = create_partitions(&arena, num_partitions);

        // For each slot, exactly one partition should own it
        for slot_idx in 0..total_capacity {
            let owners: Vec<u32> = partitions.iter()
                .filter(|p| p.owns_slot(slot_idx))
                .map(|p| p.partition_id())
                .collect();

            prop_assert_eq!(
                owners.len(),
                1,
                "slot {} owned by {} partitions: {:?}",
                slot_idx,
                owners.len(),
                owners
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_proptest_sanity() {
        let arena = PacketArena::new(1).expect("arena creation");
        let partitions = create_partitions(&arena, 4);

        assert_eq!(partitions.len(), 4);

        // Verify each partition can allocate
        for partition in &partitions {
            let slot = partition.alloc().expect("should allocate");
            assert!(partition.owns_slot(slot.slot_index()));
        }
    }
}
