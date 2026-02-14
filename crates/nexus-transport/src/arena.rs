//! PacketArena — pre-allocated memory pool for zero-allocation packet handling.
//!
//! Uses mmap for memory allocation and an atomic free list for O(1)
//! slot allocation and deallocation. Follows TigerStyle with zero
//! dynamic allocation on the hot path.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use memmap2::MmapMut;
use nexus_core::ArenaError;

/// Slot size in bytes — matches typical MTU for RTP packets.
pub const SLOT_SIZE_BYTES: u16 = 1500;

/// Node in the atomic free list stack.
#[repr(C)]
struct StackNode {
    slot_index: u32,
    next: AtomicPtr<StackNode>,
}

/// Lock-free Treiber stack for the free list.
pub struct AtomicStack {
    head: AtomicPtr<StackNode>,
    nodes: NonNull<[StackNode]>,
    capacity: u32,
}

unsafe impl Send for AtomicStack {}
unsafe impl Sync for AtomicStack {}

impl AtomicStack {
    /// Create a new atomic stack with pre-allocated nodes.
    pub fn new(capacity: u32) -> Self {
        assert!(capacity > 0, "AtomicStack capacity must be > 0");

        let mut nodes: Vec<StackNode> =
            Vec::with_capacity(capacity as usize);
        for i in 0..capacity {
            nodes.push(StackNode {
                slot_index: i,
                next: AtomicPtr::new(std::ptr::null_mut()),
            });
        }

        let nodes_box = nodes.into_boxed_slice();
        let nodes_ptr = Box::into_raw(nodes_box);
        let nodes_nn =
            unsafe { NonNull::new_unchecked(nodes_ptr) };

        let stack = Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
            nodes: nodes_nn,
            capacity,
        };

        for i in 0..capacity {
            stack.push(i);
        }

        assert_eq!(
            stack.len(),
            capacity,
            "Stack should contain all slots after init"
        );
        stack
    }

    #[inline]
    pub fn push(&self, slot_index: u32) {
        assert!(
            slot_index < self.capacity,
            "slot_index {} must be < capacity {}",
            slot_index,
            self.capacity
        );

        let node_ptr = self.get_node_ptr(slot_index);
        loop {
            let old_head = self.head.load(Ordering::Acquire);
            unsafe {
                (*node_ptr)
                    .next
                    .store(old_head, Ordering::Release);
            }
            if self
                .head
                .compare_exchange_weak(
                    old_head,
                    node_ptr,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    #[inline]
    pub fn pop(&self) -> Option<u32> {
        loop {
            let old_head = self.head.load(Ordering::Acquire);
            if old_head.is_null() {
                return None;
            }
            let next = unsafe {
                (*old_head).next.load(Ordering::Acquire)
            };
            match self.head.compare_exchange_weak(
                old_head,
                next,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let slot_index =
                        unsafe { (*old_head).slot_index };
                    assert!(
                        slot_index < self.capacity,
                        "popped slot_index {} >= capacity {}",
                        slot_index,
                        self.capacity
                    );
                    return Some(slot_index);
                }
                Err(_) => continue,
            }
        }
    }

    pub fn len(&self) -> u32 {
        let mut count = 0u32;
        let mut current = self.head.load(Ordering::Acquire);
        let max_iterations = self.capacity;
        let mut iterations = 0u32;
        while !current.is_null() && iterations < max_iterations
        {
            count += 1;
            current = unsafe {
                (*current).next.load(Ordering::Acquire)
            };
            iterations += 1;
        }
        count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    #[inline]
    fn get_node_ptr(&self, index: u32) -> *mut StackNode {
        unsafe {
            let nodes_slice = self.nodes.as_ptr();
            (*nodes_slice).as_mut_ptr().add(index as usize)
        }
    }
}

impl Drop for AtomicStack {
    fn drop(&mut self) {
        unsafe {
            let _ = Box::from_raw(self.nodes.as_ptr());
        }
    }
}


/// Pre-allocated memory pool for zero-allocation packet handling.
pub struct PacketArena {
    #[allow(dead_code)] // Backing store for base_ptr
    memory: MmapMut,
    free_list: AtomicStack,
    capacity_slots: u32,
    base_ptr: *mut u8,
}

unsafe impl Send for PacketArena {}
unsafe impl Sync for PacketArena {}

impl PacketArena {
    /// Create arena with specified size in megabytes.
    pub fn new(size_mb: u32) -> Result<Self, ArenaError> {
        assert!(size_mb > 0, "arena size_mb must be > 0");
        assert!(
            size_mb <= 1024,
            "arena size_mb must be <= 1024"
        );

        let size_bytes =
            (size_mb as usize) * 1024 * 1024;
        let capacity_slots =
            (size_bytes / SLOT_SIZE_BYTES as usize) as u32;
        assert!(
            capacity_slots > 0,
            "arena must have at least one slot"
        );

        let memory = MmapMut::map_anon(size_bytes)
            .map_err(|_| ArenaError::MmapFailed)?;
        let base_ptr = memory.as_ptr() as *mut u8;
        let free_list = AtomicStack::new(capacity_slots);

        let arena = Self {
            memory,
            free_list,
            capacity_slots,
            base_ptr,
        };

        assert_eq!(
            arena.free_count(),
            capacity_slots,
            "all slots should be free initially"
        );
        Ok(arena)
    }

    #[inline(always)]
    pub fn alloc(&self) -> Option<PacketSlot> {
        assert!(
            self.capacity_slots > 0,
            "arena capacity must be > 0"
        );
        let slot_index = self.free_list.pop()?;
        assert!(
            slot_index < self.capacity_slots,
            "slot_index {} must be < capacity {}",
            slot_index,
            self.capacity_slots
        );
        let offset =
            slot_index as usize * SLOT_SIZE_BYTES as usize;
        let data_ptr = unsafe { self.base_ptr.add(offset) };
        Some(PacketSlot::new(data_ptr, slot_index, self))
    }

    #[inline(always)]
    pub(crate) fn dealloc(&self, slot_index: u32) {
        assert!(
            slot_index < self.capacity_slots,
            "slot_index {} must be < capacity {}",
            slot_index,
            self.capacity_slots
        );
        self.free_list.push(slot_index);
    }

    pub fn free_count(&self) -> u32 {
        self.free_list.len()
    }

    pub fn capacity(&self) -> u32 {
        self.capacity_slots
    }

    pub fn allocated_count(&self) -> u32 {
        self.capacity_slots - self.free_count()
    }
}

/// Handle to an allocated packet slot with reference counting.
pub struct PacketSlot {
    data_ptr: *mut u8,
    slot_index: u32,
    data_len_bytes: u16,
    ref_count: *const AtomicU32,
    arena: *const PacketArena,
}

impl std::fmt::Debug for PacketSlot {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("PacketSlot")
            .field("slot_index", &self.slot_index)
            .field("data_len_bytes", &self.data_len_bytes)
            .field("ref_count", &self.ref_count())
            .finish()
    }
}

unsafe impl Send for PacketSlot {}
unsafe impl Sync for PacketSlot {}

impl PacketSlot {
    fn new(
        data_ptr: *mut u8,
        slot_index: u32,
        arena: &PacketArena,
    ) -> Self {
        let ref_count =
            Box::into_raw(Box::new(AtomicU32::new(1)));
        Self {
            data_ptr,
            slot_index,
            data_len_bytes: 0,
            ref_count,
            arena: arena as *const PacketArena,
        }
    }

    #[inline(always)]
    pub fn clone_shallow(&self) -> Self {
        let current_count = unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        };
        assert!(
            current_count > 0,
            "cannot clone slot with ref_count 0"
        );
        unsafe {
            (*self.ref_count)
                .fetch_add(1, Ordering::Release);
        }
        Self {
            data_ptr: self.data_ptr,
            slot_index: self.slot_index,
            data_len_bytes: self.data_len_bytes,
            ref_count: self.ref_count,
            arena: self.arena,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        assert!(
            self.data_len_bytes <= SLOT_SIZE_BYTES,
            "data_len_bytes {} > SLOT_SIZE_BYTES {}",
            self.data_len_bytes,
            SLOT_SIZE_BYTES
        );
        unsafe {
            std::slice::from_raw_parts(
                self.data_ptr,
                self.data_len_bytes as usize,
            )
        }
    }

    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let current_count = unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        };
        assert!(
            current_count == 1,
            "data_mut requires exclusive access, got {}",
            current_count
        );
        unsafe {
            std::slice::from_raw_parts_mut(
                self.data_ptr,
                SLOT_SIZE_BYTES as usize,
            )
        }
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: u16) {
        assert!(
            len <= SLOT_SIZE_BYTES,
            "len {} > SLOT_SIZE_BYTES {}",
            len,
            SLOT_SIZE_BYTES
        );
        self.data_len_bytes = len;
    }

    #[inline(always)]
    pub fn len(&self) -> u16 {
        self.data_len_bytes
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data_len_bytes == 0
    }

    #[inline(always)]
    pub fn slot_index(&self) -> u32 {
        self.slot_index
    }

    #[inline(always)]
    pub fn ref_count(&self) -> u32 {
        unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        }
    }
}

impl Drop for PacketSlot {
    fn drop(&mut self) {
        let prev_count = unsafe {
            (*self.ref_count)
                .fetch_sub(1, Ordering::Release)
        };
        assert!(prev_count > 0, "ref_count underflow");
        if prev_count == 1 {
            unsafe {
                (*self.arena).dealloc(self.slot_index);
                let _ = Box::from_raw(
                    self.ref_count as *mut AtomicU32,
                );
            }
        }
    }
}

// ============================================================================
// Arena Partitioning for Per-Worker Allocation
// ============================================================================

/// A partition of a PacketArena for thread-local allocation.
///
/// Each worker owns a disjoint partition of the arena's slot range,
/// enabling contention-free allocation without locks.
///
/// # Design
///
/// - Partitions divide the arena into N disjoint ranges
/// - Each partition has its own AtomicStack free-list
/// - Slots are returned to their owning partition on dealloc
/// - No cross-partition contention
///
/// # TigerStyle
///
/// - ≥2 assertions per function
/// - ≤70 lines per function
/// - Explicit types (u32, not usize for indices)
pub struct ArenaPartition {
    /// Worker/partition ID (0-based).
    partition_id: u32,
    /// Start slot index (inclusive).
    start_slot: u32,
    /// End slot index (exclusive).
    end_slot: u32,
    /// Local free-list for this partition.
    free_list: AtomicStack,
    /// Reference to parent arena for memory access.
    arena: *const PacketArena,
}

unsafe impl Send for ArenaPartition {}
unsafe impl Sync for ArenaPartition {}

impl ArenaPartition {
    /// Create a new partition for the given range.
    ///
    /// # Arguments
    ///
    /// * `partition_id` - Partition/worker ID (0-based)
    /// * `start_slot` - Start slot index (inclusive)
    /// * `end_slot` - End slot index (exclusive)
    /// * `arena` - Parent arena reference
    ///
    /// # Panics
    ///
    /// Panics if range is invalid or empty.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (range validation)
    /// - ≤70 lines
    pub fn new(
        partition_id: u32,
        start_slot: u32,
        end_slot: u32,
        arena: &PacketArena,
    ) -> Self {
        // Precondition: valid range
        assert!(
            start_slot < end_slot,
            "start_slot {} must be < end_slot {}",
            start_slot,
            end_slot
        );
        // Precondition: range within arena capacity
        assert!(
            end_slot <= arena.capacity_slots,
            "end_slot {} must be <= arena capacity {}",
            end_slot,
            arena.capacity_slots
        );

        let capacity = end_slot - start_slot;
        
        // Create local free-list with partition-local indices
        // We use indices relative to start_slot internally
        let free_list = AtomicStack::new(capacity);
        
        // Clear the free list (it was initialized with 0..capacity)
        // and repopulate with actual slot indices
        while free_list.pop().is_some() {}
        
        // Push actual slot indices (in reverse for LIFO order)
        for slot_idx in (start_slot..end_slot).rev() {
            free_list.push(slot_idx - start_slot);
        }

        let partition = Self {
            partition_id,
            start_slot,
            end_slot,
            free_list,
            arena: arena as *const PacketArena,
        };

        // Postcondition: all slots are free
        assert_eq!(
            partition.free_count(),
            capacity,
            "all partition slots should be free initially"
        );

        partition
    }

    /// Allocate a packet slot from this partition.
    ///
    /// Returns `None` if the partition is exhausted.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (bounds checking)
    /// - ≤70 lines
    #[inline(always)]
    pub fn alloc(&self) -> Option<PartitionedPacketSlot> {
        // Precondition: partition is valid
        assert!(
            self.start_slot < self.end_slot,
            "partition must have valid range"
        );
        
        // Pop from local free-list (relative index)
        let relative_idx = self.free_list.pop()?;
        
        // Convert to absolute slot index
        let slot_index = self.start_slot + relative_idx;
        
        // Postcondition: slot is within partition range
        assert!(
            slot_index >= self.start_slot && slot_index < self.end_slot,
            "allocated slot {} must be in range [{}, {})",
            slot_index,
            self.start_slot,
            self.end_slot
        );

        // Calculate data pointer
        let offset = slot_index as usize * SLOT_SIZE_BYTES as usize;
        let data_ptr = unsafe { (*self.arena).base_ptr.add(offset) };

        Some(PartitionedPacketSlot::new(
            data_ptr,
            slot_index,
            self.partition_id,
            self,
        ))
    }

    /// Deallocate a slot back to this partition.
    ///
    /// # Arguments
    ///
    /// * `slot_index` - Absolute slot index to deallocate
    ///
    /// # Panics
    ///
    /// Panics if slot is not within this partition's range.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (ownership validation)
    /// - ≤70 lines
    #[inline(always)]
    pub(crate) fn dealloc(&self, slot_index: u32) {
        // Precondition: slot belongs to this partition
        assert!(
            slot_index >= self.start_slot && slot_index < self.end_slot,
            "slot {} must be in partition range [{}, {})",
            slot_index,
            self.start_slot,
            self.end_slot
        );
        
        // Convert to relative index
        let relative_idx = slot_index - self.start_slot;
        
        // Postcondition: relative index is valid
        assert!(
            relative_idx < self.capacity(),
            "relative index {} must be < capacity {}",
            relative_idx,
            self.capacity()
        );

        self.free_list.push(relative_idx);
    }

    /// Get the number of free slots in this partition.
    #[inline]
    pub fn free_count(&self) -> u32 {
        self.free_list.len()
    }

    /// Get the total capacity of this partition.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.end_slot - self.start_slot
    }

    /// Get the number of allocated slots.
    #[inline]
    pub fn allocated_count(&self) -> u32 {
        self.capacity() - self.free_count()
    }

    /// Get the partition ID.
    #[inline]
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    /// Get the start slot index (inclusive).
    #[inline]
    pub fn start_slot(&self) -> u32 {
        self.start_slot
    }

    /// Get the end slot index (exclusive).
    #[inline]
    pub fn end_slot(&self) -> u32 {
        self.end_slot
    }

    /// Check if a slot index belongs to this partition.
    #[inline]
    pub fn owns_slot(&self, slot_index: u32) -> bool {
        slot_index >= self.start_slot && slot_index < self.end_slot
    }
}

/// Handle to a packet slot allocated from a partition.
///
/// Similar to PacketSlot but tracks partition ownership for
/// correct deallocation back to the owning partition.
pub struct PartitionedPacketSlot {
    data_ptr: *mut u8,
    slot_index: u32,
    data_len_bytes: u16,
    partition_id: u32,
    ref_count: *const AtomicU32,
    partition: *const ArenaPartition,
}

impl std::fmt::Debug for PartitionedPacketSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionedPacketSlot")
            .field("slot_index", &self.slot_index)
            .field("partition_id", &self.partition_id)
            .field("data_len_bytes", &self.data_len_bytes)
            .field("ref_count", &self.ref_count())
            .finish()
    }
}

unsafe impl Send for PartitionedPacketSlot {}
unsafe impl Sync for PartitionedPacketSlot {}

impl PartitionedPacketSlot {
    fn new(
        data_ptr: *mut u8,
        slot_index: u32,
        partition_id: u32,
        partition: &ArenaPartition,
    ) -> Self {
        let ref_count = Box::into_raw(Box::new(AtomicU32::new(1)));
        Self {
            data_ptr,
            slot_index,
            data_len_bytes: 0,
            partition_id,
            ref_count,
            partition: partition as *const ArenaPartition,
        }
    }

    /// Clone with shallow copy (increment refcount).
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions
    /// - ≤70 lines
    #[inline(always)]
    pub fn clone_shallow(&self) -> Self {
        let current_count = unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        };
        // Precondition: refcount is positive
        assert!(
            current_count > 0,
            "cannot clone slot with ref_count 0"
        );
        
        unsafe {
            (*self.ref_count).fetch_add(1, Ordering::Release);
        }
        
        // Postcondition: refcount increased
        let new_count = unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        };
        assert!(
            new_count > current_count,
            "refcount must increase after clone"
        );

        Self {
            data_ptr: self.data_ptr,
            slot_index: self.slot_index,
            data_len_bytes: self.data_len_bytes,
            partition_id: self.partition_id,
            ref_count: self.ref_count,
            partition: self.partition,
        }
    }

    /// Get immutable access to packet data.
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        assert!(
            self.data_len_bytes <= SLOT_SIZE_BYTES,
            "data_len_bytes {} > SLOT_SIZE_BYTES {}",
            self.data_len_bytes,
            SLOT_SIZE_BYTES
        );
        unsafe {
            std::slice::from_raw_parts(
                self.data_ptr,
                self.data_len_bytes as usize,
            )
        }
    }

    /// Get mutable access to packet data (requires exclusive ownership).
    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let current_count = unsafe {
            (*self.ref_count).load(Ordering::Acquire)
        };
        assert!(
            current_count == 1,
            "data_mut requires exclusive access, got {}",
            current_count
        );
        unsafe {
            std::slice::from_raw_parts_mut(
                self.data_ptr,
                SLOT_SIZE_BYTES as usize,
            )
        }
    }

    /// Set the data length.
    #[inline(always)]
    pub fn set_len(&mut self, len: u16) {
        assert!(
            len <= SLOT_SIZE_BYTES,
            "len {} > SLOT_SIZE_BYTES {}",
            len,
            SLOT_SIZE_BYTES
        );
        self.data_len_bytes = len;
    }

    /// Get the data length.
    #[inline(always)]
    pub fn len(&self) -> u16 {
        self.data_len_bytes
    }

    /// Check if data is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data_len_bytes == 0
    }

    /// Get the slot index.
    #[inline(always)]
    pub fn slot_index(&self) -> u32 {
        self.slot_index
    }

    /// Get the partition ID.
    #[inline(always)]
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    /// Get the reference count.
    #[inline(always)]
    pub fn ref_count(&self) -> u32 {
        unsafe { (*self.ref_count).load(Ordering::Acquire) }
    }
}

impl Drop for PartitionedPacketSlot {
    fn drop(&mut self) {
        let prev_count = unsafe {
            (*self.ref_count).fetch_sub(1, Ordering::Release)
        };
        assert!(prev_count > 0, "ref_count underflow");
        if prev_count == 1 {
            unsafe {
                (*self.partition).dealloc(self.slot_index);
                let _ = Box::from_raw(self.ref_count as *mut AtomicU32);
            }
        }
    }
}

/// Create partitions for a PacketArena.
///
/// Divides the arena into `num_partitions` disjoint ranges.
/// Each partition gets approximately equal capacity.
///
/// # Arguments
///
/// * `arena` - The arena to partition
/// * `num_partitions` - Number of partitions to create (typically = num_workers)
///
/// # Returns
///
/// Vector of ArenaPartition, one per worker.
///
/// # Panics
///
/// Panics if num_partitions is 0 or exceeds arena capacity.
///
/// # TigerStyle
///
/// - ≥2 assertions
/// - ≤70 lines
pub fn create_partitions(
    arena: &PacketArena,
    num_partitions: u32,
) -> Vec<ArenaPartition> {
    // Precondition: valid partition count
    assert!(
        num_partitions > 0,
        "num_partitions must be > 0"
    );
    assert!(
        num_partitions <= arena.capacity_slots,
        "num_partitions {} must be <= arena capacity {}",
        num_partitions,
        arena.capacity_slots
    );

    let total_slots = arena.capacity_slots;
    let slots_per_partition = total_slots / num_partitions;
    let remainder = total_slots % num_partitions;

    let mut partitions = Vec::with_capacity(num_partitions as usize);
    let mut current_start = 0u32;

    for partition_id in 0..num_partitions {
        // Distribute remainder slots to first partitions
        let extra = if partition_id < remainder { 1 } else { 0 };
        let partition_size = slots_per_partition + extra;
        let end_slot = current_start + partition_size;

        partitions.push(ArenaPartition::new(
            partition_id,
            current_start,
            end_slot,
            arena,
        ));

        current_start = end_slot;
    }

    // Postcondition: all slots are covered
    assert_eq!(
        current_start,
        total_slots,
        "partitions must cover all {} slots, got {}",
        total_slots,
        current_start
    );
    // Postcondition: correct number of partitions
    assert_eq!(
        partitions.len(),
        num_partitions as usize,
        "must create exactly {} partitions",
        num_partitions
    );

    partitions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_stack_new() {
        let stack = AtomicStack::new(100);
        assert_eq!(stack.capacity(), 100);
        assert_eq!(stack.len(), 100);
        assert!(!stack.is_empty());
    }

    #[test]
    fn test_atomic_stack_push_pop() {
        let stack = AtomicStack::new(10);
        for i in 0..10 {
            let val = stack.pop();
            assert!(val.is_some());
            assert_eq!(val.unwrap(), 9 - i);
        }
        assert!(stack.is_empty());
        assert_eq!(stack.pop(), None);
        stack.push(5);
        stack.push(3);
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(5));
        assert!(stack.is_empty());
    }

    #[test]
    fn test_arena_new() {
        let arena = PacketArena::new(1).unwrap();
        let expected =
            (1024 * 1024) / SLOT_SIZE_BYTES as usize;
        assert_eq!(arena.capacity() as usize, expected);
        assert_eq!(arena.free_count() as usize, expected);
        assert_eq!(arena.allocated_count(), 0);
    }

    #[test]
    fn test_arena_alloc_dealloc() {
        let arena = PacketArena::new(1).unwrap();
        let initial_free = arena.free_count();
        let slot = arena.alloc().expect("should alloc");
        assert_eq!(arena.free_count(), initial_free - 1);
        drop(slot);
        assert_eq!(arena.free_count(), initial_free);
    }

    #[test]
    fn test_slot_data_access() {
        let arena = PacketArena::new(1).unwrap();
        let mut slot = arena.alloc().unwrap();
        slot.data_mut()[0..4]
            .copy_from_slice(&[1, 2, 3, 4]);
        slot.set_len(4);
        assert_eq!(slot.len(), 4);
        assert_eq!(slot.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_slot_clone_shallow() {
        let arena = PacketArena::new(1).unwrap();
        let mut slot = arena.alloc().unwrap();
        slot.data_mut()[0..4]
            .copy_from_slice(&[1, 2, 3, 4]);
        slot.set_len(4);
        assert_eq!(slot.ref_count(), 1);
        let clone1 = slot.clone_shallow();
        assert_eq!(slot.ref_count(), 2);
        assert_eq!(clone1.data(), &[1, 2, 3, 4]);
        drop(clone1);
        assert_eq!(slot.ref_count(), 1);
    }

    #[test]
    fn test_slot_dealloc_on_last_drop() {
        let arena = PacketArena::new(1).unwrap();
        let initial_free = arena.free_count();
        let slot = arena.alloc().unwrap();
        let clone = slot.clone_shallow();
        assert_eq!(arena.free_count(), initial_free - 1);
        drop(slot);
        assert_eq!(arena.free_count(), initial_free - 1);
        drop(clone);
        assert_eq!(arena.free_count(), initial_free);
    }

    // ========================================================================
    // ArenaPartition Tests
    // ========================================================================

    #[test]
    fn test_partition_new() {
        let arena = PacketArena::new(1).unwrap();
        let partition = ArenaPartition::new(0, 0, 100, &arena);
        
        assert_eq!(partition.partition_id(), 0);
        assert_eq!(partition.start_slot(), 0);
        assert_eq!(partition.end_slot(), 100);
        assert_eq!(partition.capacity(), 100);
        assert_eq!(partition.free_count(), 100);
        assert_eq!(partition.allocated_count(), 0);
    }

    #[test]
    fn test_partition_alloc_dealloc() {
        let arena = PacketArena::new(1).unwrap();
        let partition = ArenaPartition::new(0, 0, 100, &arena);
        
        let initial_free = partition.free_count();
        let slot = partition.alloc().expect("should allocate");
        
        assert_eq!(partition.free_count(), initial_free - 1);
        assert!(partition.owns_slot(slot.slot_index()));
        
        drop(slot);
        assert_eq!(partition.free_count(), initial_free);
    }

    #[test]
    fn test_partition_slot_data() {
        let arena = PacketArena::new(1).unwrap();
        let partition = ArenaPartition::new(0, 0, 100, &arena);
        
        let mut slot = partition.alloc().unwrap();
        slot.data_mut()[0..4].copy_from_slice(&[1, 2, 3, 4]);
        slot.set_len(4);
        
        assert_eq!(slot.len(), 4);
        assert_eq!(slot.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_partition_clone_shallow() {
        let arena = PacketArena::new(1).unwrap();
        let partition = ArenaPartition::new(0, 0, 100, &arena);
        
        let mut slot = partition.alloc().unwrap();
        slot.data_mut()[0..4].copy_from_slice(&[5, 6, 7, 8]);
        slot.set_len(4);
        
        assert_eq!(slot.ref_count(), 1);
        let clone = slot.clone_shallow();
        assert_eq!(slot.ref_count(), 2);
        assert_eq!(clone.data(), &[5, 6, 7, 8]);
        
        drop(clone);
        assert_eq!(slot.ref_count(), 1);
    }

    #[test]
    fn test_create_partitions() {
        let arena = PacketArena::new(1).unwrap();
        let total_slots = arena.capacity();
        
        let partitions = create_partitions(&arena, 4);
        
        assert_eq!(partitions.len(), 4);
        
        // Verify disjoint ranges
        let mut covered_slots = 0u32;
        for (i, partition) in partitions.iter().enumerate() {
            assert_eq!(partition.partition_id(), i as u32);
            covered_slots += partition.capacity();
            
            // Check no overlap with other partitions
            for (j, other) in partitions.iter().enumerate() {
                if i != j {
                    assert!(
                        partition.end_slot() <= other.start_slot() ||
                        partition.start_slot() >= other.end_slot(),
                        "partitions {} and {} overlap",
                        i, j
                    );
                }
            }
        }
        
        // Verify all slots are covered
        assert_eq!(covered_slots, total_slots);
    }

    #[test]
    fn test_partition_disjoint_allocation() {
        let arena = PacketArena::new(1).unwrap();
        let partitions = create_partitions(&arena, 4);
        
        // Allocate from each partition
        let mut slots: Vec<PartitionedPacketSlot> = Vec::new();
        for partition in &partitions {
            for _ in 0..10 {
                if let Some(slot) = partition.alloc() {
                    // Verify slot is within partition range
                    assert!(partition.owns_slot(slot.slot_index()));
                    slots.push(slot);
                }
            }
        }
        
        // Verify no duplicate slot indices
        let mut indices: Vec<u32> = slots.iter().map(|s| s.slot_index()).collect();
        indices.sort();
        for i in 1..indices.len() {
            assert_ne!(
                indices[i], indices[i-1],
                "duplicate slot index {}",
                indices[i]
            );
        }
    }

    #[test]
    fn test_partition_owns_slot() {
        let arena = PacketArena::new(1).unwrap();
        let partition = ArenaPartition::new(0, 100, 200, &arena);
        
        assert!(!partition.owns_slot(99));
        assert!(partition.owns_slot(100));
        assert!(partition.owns_slot(150));
        assert!(partition.owns_slot(199));
        assert!(!partition.owns_slot(200));
    }
}
