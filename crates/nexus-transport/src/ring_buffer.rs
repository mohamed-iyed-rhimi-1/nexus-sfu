//! Lock-free SPSC ring buffer for per-track packet storage.
//!
//! Uses atomic head/tail pointers for single-producer
//! single-consumer access without locks.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::arena::PacketSlot;

/// Single-producer single-consumer ring buffer.
pub struct RingBuffer<const N: usize> {
    slots: UnsafeCell<[Option<PacketSlot>; N]>,
    head: AtomicU32,
    tail: AtomicU32,
    head_seq: AtomicU32,
}

unsafe impl<const N: usize> Send for RingBuffer<N> {}
unsafe impl<const N: usize> Sync for RingBuffer<N> {}

const fn assert_power_of_two(n: usize) {
    assert!(n > 0, "RingBuffer size N must be > 0");
    assert!(
        n.is_power_of_two(),
        "RingBuffer size N must be a power of 2"
    );
}

impl<const N: usize> RingBuffer<N> {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        assert_power_of_two(N);
        Self {
            slots: UnsafeCell::new([const { None }; N]),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            head_seq: AtomicU32::new(0),
        }
    }

    #[inline(always)]
    const fn mask() -> u32 {
        (N - 1) as u32
    }

    /// Get the capacity of the buffer.
    #[inline(always)]
    pub const fn capacity(&self) -> u32 {
        N as u32
    }
}

impl<const N: usize> Default for RingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RingBuffer<N> {
    /// Push a packet, returning the assigned sequence number.
    ///
    /// On overflow, silently overwrites the oldest slot. The consumer
    /// will see a gap, which is correct for media — stale frames are
    /// useless. The producer never writes the consumer's tail pointer
    /// (SPSC invariant).
    #[inline(always)]
    pub fn push(&self, packet: PacketSlot) -> u32 {
        assert!(packet.len() > 0, "packet.data_len_bytes must be > 0");
        let head = self.head.load(Ordering::Acquire);
        let seq = self.head_seq.load(Ordering::Acquire);
        let index = (head & Self::mask()) as usize;
        unsafe {
            let slots = &mut *self.slots.get();
            slots[index] = Some(packet);
        }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        self.head_seq.store(seq.wrapping_add(1), Ordering::Release);
        seq
    }

    /// Push a packet, retaining at most `limit` packets (`1..=N`).
    ///
    /// The packet that falls out of the window is released now, returning its
    /// arena slot, instead of lingering until the ring wraps. Use this when
    /// the ring is sized for the largest window but the configured one is
    /// smaller: retention then costs `limit` arena slots, not `N`.
    #[inline(always)]
    pub fn push_bounded(&self, packet: PacketSlot, limit: u32) -> u32 {
        assert!(limit > 0 && limit as usize <= N, "limit must be in 1..=N");
        let seq = self.push(packet);
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        // With limit == N, push() already overwrote the packet leaving the
        // window. Evicting here would hit (head - N - 1) & mask, which is the
        // slot just written, and drop the newest packet on every push.
        if (limit as usize) < N && head.wrapping_sub(tail) > limit {
            let evict = (head.wrapping_sub(limit + 1) & Self::mask()) as usize;
            // Same single-owner access as push(); drops the slot's arena reference
            unsafe {
                let slots = &mut *self.slots.get();
                slots[evict] = None;
            }
        }
        seq
    }

    /// Pop the oldest packet from the buffer.
    ///
    /// If the producer has overwritten the slot (head advanced past
    /// tail + N), the consumer skips forward to the oldest valid slot.
    #[inline(always)]
    pub fn pop(&self) -> Option<PacketSlot> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // If producer lapped us, skip to oldest valid position
        let count = head.wrapping_sub(tail);
        let actual_tail = if count > N as u32 {
            head.wrapping_sub(N as u32)
        } else {
            tail
        };
        let index = (actual_tail & Self::mask()) as usize;
        let packet = unsafe {
            let slots = &mut *self.slots.get();
            slots[index].take()
        };
        self.tail
            .store(actual_tail.wrapping_add(1), Ordering::Release);
        packet
    }

    /// Peek at a packet by sequence number.
    ///
    /// Only the last `N` pushes can still be stored; older sequence numbers
    /// return `None` rather than the newer packet that overwrote their slot.
    pub fn peek(&self, seq: u32) -> Option<&PacketSlot> {
        let head_seq = self.head_seq.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        let count = head.wrapping_sub(tail).min(N as u32);
        let oldest_seq = head_seq.wrapping_sub(count);
        let offset = seq.wrapping_sub(oldest_seq);
        if offset >= count {
            return None;
        }
        let oldest = head.wrapping_sub(count);
        let index = (oldest.wrapping_add(offset) & Self::mask()) as usize;
        debug_assert!(index < N, "index must be within the ring");
        unsafe {
            let slots = &*self.slots.get();
            slots[index].as_ref()
        }
    }

    /// Get the number of packets currently stored.
    #[inline(always)]
    pub fn len(&self) -> u32 {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Check if the buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the buffer is full.
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len() >= N as u32
    }

    /// Skip to the latest packets.
    pub fn skip_to_latest(&self) -> u32 {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let count = head.wrapping_sub(tail);
        if count == 0 {
            return 0;
        }
        let new_tail = if count > 0 {
            head.wrapping_sub(1)
        } else {
            head
        };
        let skipped = new_tail.wrapping_sub(tail);
        unsafe {
            let slots = &mut *self.slots.get();
            let mut current = tail;
            let max_iterations = skipped.min(N as u32);
            for _ in 0..max_iterations {
                let index = (current & Self::mask()) as usize;
                slots[index] = None;
                current = current.wrapping_add(1);
            }
        }
        self.tail.store(new_tail, Ordering::Release);
        skipped
    }

    /// Get the current head sequence number.
    #[inline(always)]
    pub fn head_seq(&self) -> u32 {
        self.head_seq.load(Ordering::Acquire)
    }

    /// Get the sequence number of the oldest packet.
    pub fn tail_seq(&self) -> Option<u32> {
        let head_seq = self.head_seq.load(Ordering::Acquire);
        let count = self.len();
        if count == 0 {
            None
        } else {
            Some(head_seq.wrapping_sub(count))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::PacketArena;

    fn create_test_packet(arena: &PacketArena, value: u8) -> PacketSlot {
        let mut slot = arena.alloc().unwrap();
        slot.data_mut()[0] = value;
        slot.set_len(1);
        slot
    }

    #[test]
    fn test_ring_buffer_new() {
        let buffer: RingBuffer<1024> = RingBuffer::new();
        assert_eq!(buffer.capacity(), 1024);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_push_pop_fifo() {
        let arena = PacketArena::new(1).unwrap();
        let buffer: RingBuffer<8> = RingBuffer::new();
        for i in 0..5 {
            buffer.push(create_test_packet(&arena, i));
        }
        for i in 0..5 {
            let popped = buffer.pop().unwrap();
            assert_eq!(popped.data()[0], i);
        }
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_push_bounded_releases_slots_outside_window() {
        let arena = PacketArena::new(1).unwrap();
        let free_before = arena.free_count();
        let buffer: RingBuffer<8> = RingBuffer::new();

        let mut last_seq = 0;
        for i in 0..6 {
            last_seq = buffer.push_bounded(create_test_packet(&arena, i), 2);
        }

        // Only the 2 newest packets hold arena slots; older ones were released
        assert_eq!(free_before - arena.free_count(), 2);
        assert!(buffer.peek(last_seq).is_some());
        assert!(buffer.peek(last_seq - 1).is_some());
        assert!(buffer.peek(last_seq - 2).is_none());
    }

    #[test]
    fn test_push_bounded_full_window_keeps_newest() {
        // Production uses limit == N. Retention must stay at N after the ring
        // wraps, and the newest packets must be the ones kept.
        let arena = PacketArena::new(1).unwrap();
        let free_before = arena.free_count();
        let buffer: RingBuffer<8> = RingBuffer::new();

        let mut last_seq = 0;
        for i in 0..24u8 {
            last_seq = buffer.push_bounded(create_test_packet(&arena, i), 8);
        }

        assert_eq!(free_before - arena.free_count(), 8);
        for back in 0..8u32 {
            let packet = buffer.peek(last_seq - back).expect("within window");
            assert_eq!(packet.data()[0], 23 - back as u8);
        }
        assert!(buffer.peek(last_seq - 8).is_none());
    }

    #[test]
    fn test_peek_rejects_overwritten_seq() {
        // A lapped sequence number must not return the packet that replaced it.
        let arena = PacketArena::new(1).unwrap();
        let buffer: RingBuffer<4> = RingBuffer::new();
        let seqs: Vec<u32> = (0..6u8)
            .map(|i| buffer.push(create_test_packet(&arena, i)))
            .collect();

        assert!(buffer.peek(seqs[0]).is_none());
        assert!(buffer.peek(seqs[1]).is_none());
        for (i, &seq) in seqs.iter().enumerate().skip(2) {
            assert_eq!(buffer.peek(seq).expect("within window").data()[0], i as u8);
        }
        assert!(buffer.peek(seqs[5] + 1).is_none());
    }

    #[test]
    fn test_push_overflow() {
        let arena = PacketArena::new(1).unwrap();
        let buffer: RingBuffer<4> = RingBuffer::new();
        for i in 0..6 {
            buffer.push(create_test_packet(&arena, i));
        }
        // Producer overwrites oldest slots without advancing tail.
        // pop() detects the lap and skips forward to the oldest valid slot.
        // Slots 0,1 were overwritten by 4,5. Valid slots: indices 2,3,0,1
        // containing values 2,3,4,5.
        let popped = buffer.pop().unwrap();
        assert_eq!(popped.data()[0], 2);
        let popped = buffer.pop().unwrap();
        assert_eq!(popped.data()[0], 3);
        let popped = buffer.pop().unwrap();
        assert_eq!(popped.data()[0], 4);
        let popped = buffer.pop().unwrap();
        assert_eq!(popped.data()[0], 5);
        assert!(buffer.pop().is_none());
    }
}
