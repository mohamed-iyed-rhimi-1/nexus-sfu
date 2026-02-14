//! Property-based tests for SPSC channel.
//!
//! Validates:
//! - FIFO ordering: items are received in the order they were sent
//! - Length consistency: len() accurately reflects the number of items
//! - Capacity bounds: channel never exceeds capacity
//!
//! Property 2: Cross-Worker SPSC Routing
//! Validates: Requirements 1.4

use proptest::prelude::*;
use proptest::collection::vec;

use nexus_transport::arena::PacketArena;
use crate::worker::spsc::SpscChannel;

/// Operation on the SPSC channel for property testing.
#[derive(Debug, Clone)]
enum SpscOp {
    /// Send a packet with the given sequence number (encoded in length).
    Send(u16),
    /// Receive a packet.
    Recv,
}

/// Strategy to generate a sequence of SPSC operations.
fn spsc_ops_strategy() -> impl Strategy<Value = Vec<SpscOp>> {
    vec(
        prop_oneof![
            // 60% sends, 40% receives for realistic workload
            6 => (0u16..1000).prop_map(SpscOp::Send),
            4 => Just(SpscOp::Recv),
        ],
        1..200, // 1 to 200 operations per test
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: SPSC channel maintains FIFO order.
    ///
    /// For any sequence of send/recv operations, items are received
    /// in the exact order they were sent.
    #[test]
    fn prop_spsc_fifo_order(ops in spsc_ops_strategy()) {
        // Create arena for packet allocation
        let arena = PacketArena::new(1).expect("arena creation");
        let channel: SpscChannel<64> = SpscChannel::new();

        // Track sent and received sequences
        let mut sent_sequence: Vec<u16> = Vec::new();
        let mut recv_sequence: Vec<u16> = Vec::new();

        for op in ops {
            match op {
                SpscOp::Send(seq) => {
                    if let Some(mut slot) = arena.alloc() {
                        // Encode sequence number in packet length
                        slot.set_len(seq);
                        if channel.try_send(slot).is_ok() {
                            sent_sequence.push(seq);
                        }
                    }
                }
                SpscOp::Recv => {
                    if let Some(slot) = channel.try_recv() {
                        recv_sequence.push(slot.len());
                    }
                }
            }
        }

        // Drain remaining items
        while let Some(slot) = channel.try_recv() {
            recv_sequence.push(slot.len());
        }

        // Property: received sequence is a prefix of sent sequence
        // (some items may still be in channel or were dropped due to full)
        prop_assert!(
            recv_sequence.len() <= sent_sequence.len(),
            "received {} items but only sent {}",
            recv_sequence.len(),
            sent_sequence.len()
        );

        // Property: received items match sent items in order
        for (i, (sent, recv)) in sent_sequence.iter()
            .take(recv_sequence.len())
            .zip(recv_sequence.iter())
            .enumerate()
        {
            prop_assert_eq!(
                sent, recv,
                "FIFO violation at index {}: sent {} but received {}",
                i, sent, recv
            );
        }
    }

    /// Property: SPSC channel len() is consistent with operations.
    ///
    /// After any sequence of operations, len() equals the number of
    /// successful sends minus the number of successful receives.
    #[test]
    fn prop_spsc_len_consistent(ops in spsc_ops_strategy()) {
        let arena = PacketArena::new(1).expect("arena creation");
        let channel: SpscChannel<64> = SpscChannel::new();

        let mut expected_len: u32 = 0;

        for op in ops {
            match op {
                SpscOp::Send(seq) => {
                    if let Some(mut slot) = arena.alloc() {
                        slot.set_len(seq);
                        if channel.try_send(slot).is_ok() {
                            expected_len += 1;
                        }
                    }
                }
                SpscOp::Recv => {
                    if channel.try_recv().is_some() {
                        expected_len -= 1;
                    }
                }
            }

            // Property: len() matches expected after each operation
            let actual_len = channel.len();
            prop_assert_eq!(
                actual_len, expected_len,
                "len() mismatch: expected {} but got {}",
                expected_len, actual_len
            );
        }
    }

    /// Property: SPSC channel respects capacity bounds.
    ///
    /// The channel never contains more than N items.
    #[test]
    fn prop_spsc_capacity_bounds(ops in spsc_ops_strategy()) {
        let arena = PacketArena::new(1).expect("arena creation");
        let channel: SpscChannel<32> = SpscChannel::new();
        const CAPACITY: u32 = 32;

        for op in ops {
            match op {
                SpscOp::Send(seq) => {
                    if let Some(mut slot) = arena.alloc() {
                        slot.set_len(seq);
                        let _ = channel.try_send(slot);
                    }
                }
                SpscOp::Recv => {
                    let _ = channel.try_recv();
                }
            }

            // Property: len() never exceeds capacity
            let len = channel.len();
            prop_assert!(
                len <= CAPACITY,
                "capacity violation: len {} > capacity {}",
                len, CAPACITY
            );
        }
    }

    /// Property: SPSC channel is_empty/is_full are consistent with len().
    #[test]
    fn prop_spsc_empty_full_consistent(ops in spsc_ops_strategy()) {
        let arena = PacketArena::new(1).expect("arena creation");
        let channel: SpscChannel<16> = SpscChannel::new();
        const CAPACITY: u32 = 16;

        for op in ops {
            match op {
                SpscOp::Send(seq) => {
                    if let Some(mut slot) = arena.alloc() {
                        slot.set_len(seq);
                        let _ = channel.try_send(slot);
                    }
                }
                SpscOp::Recv => {
                    let _ = channel.try_recv();
                }
            }

            let len = channel.len();
            let is_empty = channel.is_empty();
            let is_full = channel.is_full();

            // Property: is_empty iff len == 0
            prop_assert_eq!(
                is_empty, len == 0,
                "is_empty() = {} but len() = {}",
                is_empty, len
            );

            // Property: is_full iff len >= capacity
            prop_assert_eq!(
                is_full, len >= CAPACITY,
                "is_full() = {} but len() = {} (capacity = {})",
                is_full, len, CAPACITY
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spsc_proptest_sanity() {
        // Quick sanity check that property tests can run
        let arena = PacketArena::new(1).expect("arena creation");
        let channel: SpscChannel<64> = SpscChannel::new();

        // Send a few items
        for i in 0..10u16 {
            let mut slot = arena.alloc().expect("alloc");
            slot.set_len(i);
            assert!(channel.try_send(slot).is_ok());
        }

        // Receive and verify FIFO
        for i in 0..10u16 {
            let slot = channel.try_recv().expect("recv");
            assert_eq!(slot.len(), i);
        }

        assert!(channel.is_empty());
    }
}
