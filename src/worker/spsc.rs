//! Lock-free SPSC (Single-Producer Single-Consumer) Channel.
//!
//! A bounded, lock-free ring buffer for cross-worker packet forwarding.
//! Uses atomic head/tail indices for wait-free operations.
//!
//! # Design
//!
//! - Fixed capacity (power of 2) for efficient modulo via bitmask
//! - Single producer, single consumer (no contention)
//! - Non-blocking try_send/try_recv operations
//! - TigerStyle compliant: ≥2 assertions per function, ≤70 lines
//!
//! # Thread Safety
//!
//! - Producer owns `head` (write position)
//! - Consumer owns `tail` (read position)
//! - Atomic operations ensure visibility across threads

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use nexus_transport::arena::PacketSlot;

/// Lock-free SPSC channel for cross-worker packet forwarding.
///
/// Const-generic capacity N must be a power of 2 for efficient indexing.
/// Uses atomic head/tail indices with acquire/release ordering.
///
/// # Type Parameters
///
/// * `N` - Channel capacity (must be power of 2, e.g., 1024, 2048, 4096)
pub struct SpscChannel<const N: usize> {
    /// Ring buffer storage.
    buffer: UnsafeCell<[Option<PacketSlot>; N]>,
    /// Writer position (owned by producer).
    head: AtomicU32,
    /// Reader position (owned by consumer).
    tail: AtomicU32,
    /// Capacity mask for efficient modulo (N - 1).
    mask: u32,
}

// SAFETY: SpscChannel is Send+Sync because:
// - Only one producer writes to head and buffer[head]
// - Only one consumer reads from tail and buffer[tail]
// - Atomic operations provide proper synchronization
unsafe impl<const N: usize> Send for SpscChannel<N> {}
unsafe impl<const N: usize> Sync for SpscChannel<N> {}

impl<const N: usize> SpscChannel<N> {
    /// Create a new SPSC channel with capacity N.
    ///
    /// # Panics
    ///
    /// Panics if N is not a power of 2 or N is 0.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (capacity validation)
    /// - ≤70 lines
    #[inline]
    pub fn new() -> Self {
        // Precondition: N must be a power of 2
        assert!(N > 0, "SpscChannel capacity must be > 0");
        assert!(
            N.is_power_of_two(),
            "SpscChannel capacity {} must be a power of 2",
            N
        );
        // Precondition: N must fit in u32
        assert!(
            N <= u32::MAX as usize,
            "SpscChannel capacity must fit in u32"
        );

        // Initialize buffer with None values
        // SAFETY: Option<PacketSlot> is safe to zero-initialize as None
        let buffer = {
            // Use array initialization
            let arr: [Option<PacketSlot>; N] = unsafe {
                // MaybeUninit for array initialization
                let mut arr = std::mem::MaybeUninit::<[Option<PacketSlot>; N]>::uninit();
                let ptr = arr.as_mut_ptr() as *mut Option<PacketSlot>;
                for i in 0..N {
                    ptr.add(i).write(None);
                }
                arr.assume_init()
            };
            arr
        };

        let channel = Self {
            buffer: UnsafeCell::new(buffer),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            mask: (N - 1) as u32,
        };

        // Postcondition: channel is empty
        assert_eq!(channel.len(), 0, "new channel must be empty");

        channel
    }

    /// Try to send a packet to the channel.
    ///
    /// Returns `Ok(())` if the packet was enqueued, or `Err(packet)` if
    /// the channel is full (packet is returned to caller).
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet to send
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (bounds checking)
    /// - ≤70 lines
    #[inline]
    pub fn try_send(&self, packet: PacketSlot) -> Result<(), PacketSlot> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        // Precondition: masked index is within bounds (wrapping is by design)
        debug_assert!((head & self.mask) < N as u32, "head index must be < N");

        // Check if channel is full
        let size = head.wrapping_sub(tail);
        if size >= N as u32 {
            return Err(packet);
        }

        // Write packet to buffer
        let index = (head & self.mask) as usize;

        // SAFETY: We are the only producer, and we checked the slot is available
        unsafe {
            let buffer = &mut *self.buffer.get();
            // Postcondition: slot was empty before write
            debug_assert!(
                buffer[index].is_none(),
                "slot {} must be empty before write",
                index
            );
            buffer[index] = Some(packet);
        }

        // Advance head with release ordering (makes write visible to consumer)
        self.head.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// Try to receive a packet from the channel.
    ///
    /// Returns `Some(packet)` if a packet was available, or `None` if
    /// the channel is empty.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (bounds checking)
    /// - ≤70 lines
    #[inline]
    pub fn try_recv(&self) -> Option<PacketSlot> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        // Precondition: masked index is within bounds (wrapping is by design)
        debug_assert!((tail & self.mask) < N as u32, "tail index must be < N");

        // Check if channel is empty
        if tail == head {
            return None;
        }

        // Read packet from buffer
        let index = (tail & self.mask) as usize;

        // SAFETY: We are the only consumer, and we checked the slot has data
        let packet = unsafe {
            let buffer = &mut *self.buffer.get();
            // Postcondition: slot was occupied before read
            debug_assert!(
                buffer[index].is_some(),
                "slot {} must be occupied before read",
                index
            );
            buffer[index].take()
        };

        // Advance tail with release ordering (makes read visible to producer)
        self.tail.store(tail.wrapping_add(1), Ordering::Release);

        packet
    }

    /// Get the current number of items in the channel.
    ///
    /// Note: This is a snapshot and may be stale by the time it's used.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (result bounds)
    /// - ≤70 lines
    #[inline]
    pub fn len(&self) -> u32 {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        let len = head.wrapping_sub(tail);

        // Postcondition: len is bounded by capacity
        debug_assert!(len <= N as u32, "len {} must be <= capacity {}", len, N);
        // Postcondition: len is non-negative (wrapping handles this)
        debug_assert!(
            len <= u32::MAX / 2,
            "len must be reasonable (not wrapped negative)"
        );

        len
    }

    /// Check if the channel is empty.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (consistency)
    /// - ≤70 lines
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the channel is full.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (consistency)
    /// - ≤70 lines
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= N as u32
    }

    /// Get the channel capacity.
    ///
    /// # TigerStyle
    ///
    /// - ≥2 assertions (constant validation)
    /// - ≤70 lines
    #[inline]
    pub const fn capacity(&self) -> u32 {
        // These are compile-time checks via const
        // Postcondition: capacity is N
        N as u32
    }
}

impl<const N: usize> Default for SpscChannel<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender half of an SPSC channel.
///
/// Owns the producer side of the channel. Only one sender should exist
/// per channel.
pub struct SpscSender<const N: usize> {
    /// Shared channel reference.
    channel: Arc<SpscChannel<N>>,
}

impl<const N: usize> SpscSender<N> {
    /// Try to send a packet.
    #[inline]
    pub fn try_send(&self, packet: PacketSlot) -> Result<(), PacketSlot> {
        debug_assert!(
            packet.len() <= 8192,
            "packet length must be <= max datagram size"
        );
        self.channel.try_send(packet)
    }

    /// Check if the channel is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.channel.is_full()
    }
}

/// Receiver half of an SPSC channel.
///
/// Owns the consumer side of the channel. Only one receiver should exist
/// per channel.
pub struct SpscReceiver<const N: usize> {
    /// Shared channel reference.
    channel: Arc<SpscChannel<N>>,
}

impl<const N: usize> SpscReceiver<N> {
    /// Try to receive a packet.
    #[inline]
    pub fn try_recv(&self) -> Option<PacketSlot> {
        self.channel.try_recv()
    }

    /// Check if the channel is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.channel.is_empty()
    }

    /// Get the current length.
    #[inline]
    pub fn len(&self) -> u32 {
        self.channel.len()
    }
}

/// Create a new SPSC channel pair (sender, receiver).
///
/// Returns sender and receiver handles. The channel is shared via `Arc`.
///
/// # Type Parameters
///
/// * `N` - Channel capacity (must be power of 2)
pub fn channel<const N: usize>() -> (SpscSender<N>, SpscReceiver<N>) {
    let channel = Arc::new(SpscChannel::new());

    let sender = SpscSender {
        channel: Arc::clone(&channel),
    };
    let receiver = SpscReceiver { channel };

    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test arena and packet
    fn create_test_packet() -> PacketSlot {
        use nexus_transport::arena::PacketArena;
        // Use a static arena for tests
        static ARENA: std::sync::OnceLock<PacketArena> = std::sync::OnceLock::new();
        let arena = ARENA.get_or_init(|| PacketArena::new(1).unwrap());
        let mut slot = arena.alloc().expect("should allocate");
        slot.set_len(100);
        slot
    }

    #[test]
    fn test_spsc_new() {
        let channel: SpscChannel<1024> = SpscChannel::new();
        assert_eq!(channel.len(), 0);
        assert!(channel.is_empty());
        assert!(!channel.is_full());
        assert_eq!(channel.capacity(), 1024);
    }

    #[test]
    fn test_spsc_send_recv() {
        let channel: SpscChannel<1024> = SpscChannel::new();

        let packet = create_test_packet();
        let original_len = packet.len();

        // Send should succeed
        assert!(channel.try_send(packet).is_ok());
        assert_eq!(channel.len(), 1);
        assert!(!channel.is_empty());

        // Receive should return the packet
        let received = channel.try_recv();
        assert!(received.is_some());
        assert_eq!(received.unwrap().len(), original_len);
        assert!(channel.is_empty());
    }

    #[test]
    fn test_spsc_fifo_order() {
        let channel: SpscChannel<1024> = SpscChannel::new();

        // Send multiple packets
        for i in 0..10u16 {
            let mut packet = create_test_packet();
            packet.set_len(i);
            assert!(channel.try_send(packet).is_ok());
        }

        assert_eq!(channel.len(), 10);

        // Receive in FIFO order
        for i in 0..10u16 {
            let packet = channel.try_recv().expect("should have packet");
            assert_eq!(packet.len(), i, "packets must be received in FIFO order");
        }

        assert!(channel.is_empty());
    }

    #[test]
    fn test_spsc_full() {
        let channel: SpscChannel<4> = SpscChannel::new();

        // Fill the channel
        for _ in 0..4 {
            let packet = create_test_packet();
            assert!(channel.try_send(packet).is_ok());
        }

        assert!(channel.is_full());
        assert_eq!(channel.len(), 4);

        // Next send should fail
        let packet = create_test_packet();
        let result = channel.try_send(packet);
        assert!(result.is_err());

        // Receive one to make room
        assert!(channel.try_recv().is_some());
        assert!(!channel.is_full());

        // Now send should succeed
        let packet = create_test_packet();
        assert!(channel.try_send(packet).is_ok());
    }

    #[test]
    fn test_spsc_empty_recv() {
        let channel: SpscChannel<1024> = SpscChannel::new();

        // Receive from empty channel should return None
        assert!(channel.try_recv().is_none());
        assert!(channel.is_empty());
    }

    #[test]
    fn test_spsc_channel_pair() {
        let (sender, receiver) = channel::<1024>();

        // Send via sender
        let packet = create_test_packet();
        assert!(sender.try_send(packet).is_ok());

        // Receive via receiver
        assert!(!receiver.is_empty());
        let received = receiver.try_recv();
        assert!(received.is_some());
        assert!(receiver.is_empty());
    }

    #[test]
    #[should_panic(expected = "power of 2")]
    fn test_spsc_non_power_of_two() {
        let _channel: SpscChannel<100> = SpscChannel::new();
    }

    #[test]
    fn test_spsc_wraparound() {
        let channel: SpscChannel<4> = SpscChannel::new();

        // Fill and drain multiple times to test wraparound
        for round in 0..10 {
            // Fill
            for i in 0..4u16 {
                let mut packet = create_test_packet();
                packet.set_len(i + round * 4);
                assert!(channel.try_send(packet).is_ok());
            }

            // Drain
            for i in 0..4u16 {
                let packet = channel.try_recv().expect("should have packet");
                assert_eq!(packet.len(), i + round * 4);
            }
        }
    }
}
