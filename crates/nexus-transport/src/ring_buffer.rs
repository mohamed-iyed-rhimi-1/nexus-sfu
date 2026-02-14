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
    #[inline(always)]
    pub fn push(&self, packet: PacketSlot) -> u32 {
        assert!(
            packet.len() > 0,
            "packet.data_len_bytes must be > 0"
        );
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let seq = self.head_seq.load(Ordering::Acquire);
        let index = (head & Self::mask()) as usize;
        let count = head.wrapping_sub(tail);
        if count >= N as u32 {
            self.tail.store(
                tail.wrapping_add(1), Ordering::Release,
            );
        }
        unsafe {
            let slots = &mut *self.slots.get();
            slots[index] = Some(packet);
        }
        self.head.store(
            head.wrapping_add(1), Ordering::Release,
        );
        self.head_seq.store(
            seq.wrapping_add(1), Ordering::Release,
        );
        seq
    }

    /// Pop the oldest packet from the buffer.
    #[inline(always)]
    pub fn pop(&self) -> Option<PacketSlot> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let index = (tail & Self::mask()) as usize;
        let packet = unsafe {
            let slots = &mut *self.slots.get();
            slots[index].take()
        };
        self.tail.store(
            tail.wrapping_add(1), Ordering::Release,
        );
        packet
    }

    /// Peek at a packet by sequence number.
    pub fn peek(&self, seq: u32) -> Option<&PacketSlot> {
        let head_seq = self.head_seq.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        let count = head.wrapping_sub(tail);
        let tail_seq = head_seq.wrapping_sub(count);
        let seq_offset = seq.wrapping_sub(tail_seq);
        let head_offset = head_seq.wrapping_sub(tail_seq);
        if seq_offset >= head_offset {
            return None;
        }
        let slot_offset = seq.wrapping_sub(tail_seq);
        let index = (tail.wrapping_add(slot_offset)
            & Self::mask()) as usize;
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
                let index =
                    (current & Self::mask()) as usize;
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

    fn create_test_packet(
        arena: &PacketArena, value: u8,
    ) -> PacketSlot {
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
    fn test_push_overflow() {
        let arena = PacketArena::new(1).unwrap();
        let buffer: RingBuffer<4> = RingBuffer::new();
        for i in 0..6 {
            buffer.push(create_test_packet(&arena, i));
        }
        assert_eq!(buffer.len(), 4);
        for expected in 2..6 {
            let popped = buffer.pop().unwrap();
            assert_eq!(popped.data()[0], expected);
        }
    }
}
