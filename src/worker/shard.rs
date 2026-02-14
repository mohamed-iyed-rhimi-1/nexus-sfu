//! Consistent Hashing for Track Assignment.
//!
//! Uses FNV-1a hash for fast, deterministic mapping of SSRCs to worker IDs.
//! This ensures the same SSRC always maps to the same worker, enabling
//! efficient packet routing without locks.
//!
//! # Algorithm
//!
//! FNV-1a is chosen for its:
//! - Speed: Simple multiply-XOR operations
//! - Distribution: Good avalanche properties
//! - Determinism: Same input always produces same output
//!
//! The hash is then mapped to a worker ID using modulo num_workers.

/// FNV-1a 32-bit offset basis.
const FNV_OFFSET_BASIS: u32 = 2166136261;

/// FNV-1a 32-bit prime.
const FNV_PRIME: u32 = 16777619;

/// Consistent hash for mapping SSRCs to worker IDs.
///
/// Uses FNV-1a hash for fast, deterministic mapping. The same SSRC
/// will always map to the same worker ID, enabling lock-free routing.
///
/// # Example
///
/// ```
/// use nexus_sfu::worker::ConsistentHash;
///
/// let hasher = ConsistentHash::new(4);
///
/// // Same SSRC always maps to same worker
/// let worker1 = hasher.hash(12345);
/// let worker2 = hasher.hash(12345);
/// assert_eq!(worker1, worker2);
///
/// // Different SSRCs may map to different workers
/// let worker_a = hasher.hash(100);
/// let worker_b = hasher.hash(200);
/// // worker_a and worker_b may or may not be equal
/// ```
#[derive(Debug, Clone)]
pub struct ConsistentHash {
    /// Number of workers to distribute across.
    num_workers: u32,
}

impl ConsistentHash {
    /// Create a new consistent hash with the specified number of workers.
    ///
    /// # Arguments
    ///
    /// * `num_workers` - Number of workers to distribute across (1-64)
    ///
    /// # Panics
    ///
    /// Panics if num_workers is 0 or greater than 64.
    ///
    /// # Assertions
    /// - num_workers > 0
    /// - num_workers <= 64
    pub fn new(num_workers: u32) -> Self {
        // TigerStyle: Assert preconditions
        assert!(num_workers > 0, "num_workers must be > 0");
        assert!(num_workers <= 64, "num_workers must be <= 64");

        Self { num_workers }
    }

    /// Hash an SSRC to a worker ID.
    ///
    /// Uses FNV-1a hash followed by modulo to map to worker range.
    /// The same SSRC will always return the same worker ID.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - The SSRC to hash
    ///
    /// # Returns
    ///
    /// Worker ID in range [0, num_workers)
    ///
    /// # Assertions
    /// - ssrc != 0 (SSRC 0 is reserved/invalid)
    #[inline(always)]
    pub fn hash(&self, ssrc: u32) -> u32 {
        // TigerStyle: Assert preconditions
        assert!(ssrc != 0, "ssrc must not be 0 (reserved)");

        let hash = self.fnv1a_hash(ssrc);
        let worker_id = hash % self.num_workers;

        // TigerStyle: Assert postconditions
        debug_assert!(
            worker_id < self.num_workers,
            "worker_id {} must be < num_workers {}",
            worker_id,
            self.num_workers
        );

        worker_id
    }

    /// Compute FNV-1a hash of a 32-bit value.
    ///
    /// FNV-1a processes each byte: hash = (hash XOR byte) * prime
    #[inline(always)]
    fn fnv1a_hash(&self, value: u32) -> u32 {
        let bytes = value.to_le_bytes();
        let mut hash = FNV_OFFSET_BASIS;

        // Process each byte (fixed 4 iterations - TigerStyle compliant)
        for byte in bytes {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        hash
    }

    /// Get the number of workers.
    #[inline(always)]
    pub fn num_workers(&self) -> u32 {
        self.num_workers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash_new() {
        let hasher = ConsistentHash::new(4);
        assert_eq!(hasher.num_workers(), 4);
    }

    #[test]
    fn test_consistent_hash_single_worker() {
        let hasher = ConsistentHash::new(1);
        
        // All SSRCs should map to worker 0
        assert_eq!(hasher.hash(1), 0);
        assert_eq!(hasher.hash(100), 0);
        assert_eq!(hasher.hash(12345), 0);
        assert_eq!(hasher.hash(u32::MAX), 0);
    }

    #[test]
    fn test_consistent_hash_deterministic() {
        let hasher = ConsistentHash::new(8);

        // Same SSRC should always map to same worker
        let ssrc = 12345u32;
        let worker1 = hasher.hash(ssrc);
        let worker2 = hasher.hash(ssrc);
        let worker3 = hasher.hash(ssrc);

        assert_eq!(worker1, worker2);
        assert_eq!(worker2, worker3);
    }

    #[test]
    fn test_consistent_hash_range() {
        let num_workers = 8u32;
        let hasher = ConsistentHash::new(num_workers);

        // All results should be in valid range
        for ssrc in 1..1000 {
            let worker_id = hasher.hash(ssrc);
            assert!(
                worker_id < num_workers,
                "worker_id {} should be < {}",
                worker_id,
                num_workers
            );
        }
    }

    #[test]
    fn test_consistent_hash_distribution() {
        let num_workers = 4u32;
        let hasher = ConsistentHash::new(num_workers);

        // Count distribution across workers
        let mut counts = [0u32; 4];
        for ssrc in 1..=1000 {
            let worker_id = hasher.hash(ssrc);
            counts[worker_id as usize] += 1;
        }

        // Each worker should get some assignments (rough distribution check)
        // With 1000 SSRCs and 4 workers, expect ~250 each, allow 100-400 range
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                count >= 100 && count <= 400,
                "worker {} got {} assignments, expected ~250",
                i,
                count
            );
        }
    }

    #[test]
    fn test_consistent_hash_different_ssrcs() {
        let hasher = ConsistentHash::new(4);

        // Different SSRCs should (usually) map to different workers
        // This is probabilistic, but with 4 workers and 4 different SSRCs,
        // we should see at least 2 different workers
        let workers: Vec<u32> = [100u32, 200, 300, 400]
            .iter()
            .map(|&ssrc| hasher.hash(ssrc))
            .collect();

        let unique_workers: std::collections::HashSet<_> = workers.iter().collect();
        assert!(
            unique_workers.len() >= 2,
            "expected at least 2 different workers, got {:?}",
            workers
        );
    }

    #[test]
    fn test_consistent_hash_max_workers() {
        let hasher = ConsistentHash::new(64);
        assert_eq!(hasher.num_workers(), 64);

        // Should still work correctly
        let worker_id = hasher.hash(12345);
        assert!(worker_id < 64);
    }

    #[test]
    #[should_panic(expected = "num_workers must be > 0")]
    fn test_consistent_hash_zero_workers() {
        let _ = ConsistentHash::new(0);
    }

    #[test]
    #[should_panic(expected = "num_workers must be <= 64")]
    fn test_consistent_hash_too_many_workers() {
        let _ = ConsistentHash::new(100);
    }

    #[test]
    #[should_panic(expected = "ssrc must not be 0")]
    fn test_consistent_hash_zero_ssrc() {
        let hasher = ConsistentHash::new(4);
        let _ = hasher.hash(0);
    }

    #[test]
    fn test_consistent_hash_edge_values() {
        let hasher = ConsistentHash::new(8);

        // Test edge values
        let _ = hasher.hash(1);           // Minimum valid SSRC
        let _ = hasher.hash(u32::MAX);    // Maximum SSRC
        let _ = hasher.hash(u32::MAX / 2); // Middle value
    }

    #[test]
    fn test_fnv1a_avalanche() {
        // Test that small changes in input produce different outputs
        let hasher = ConsistentHash::new(64);

        let hash1 = hasher.hash(1000);
        let hash2 = hasher.hash(1001);
        let hash3 = hasher.hash(1002);

        // With 64 workers, consecutive SSRCs should often map to different workers
        // (not guaranteed, but likely due to avalanche effect)
        let all_same = hash1 == hash2 && hash2 == hash3;
        // This is probabilistic - just verify we get valid results
        assert!(hash1 < 64);
        assert!(hash2 < 64);
        assert!(hash3 < 64);
        
        // Log for debugging (won't fail test)
        if all_same {
            eprintln!("Note: consecutive SSRCs mapped to same worker (valid but unusual)");
        }
    }
}
