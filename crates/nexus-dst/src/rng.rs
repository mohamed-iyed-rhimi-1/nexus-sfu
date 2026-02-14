use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;

/// A deterministic random number generator wrapping `ChaCha8Rng`.
///
/// Produces identical sequences for the same seed across runs and platforms.
/// Implements `RngCore` so it can be used anywhere a standard RNG is expected.
#[derive(Debug, Clone)]
pub struct SimRng {
    rng: ChaCha8Rng,
    seed: u64,
}

impl SimRng {
    /// Create a new `SimRng` from the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            seed,
        }
    }

    /// Return the seed this RNG was created with.
    pub fn seed(&self) -> u64 {
        self.seed
    }
}

impl RngCore for SimRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn seed_is_stored() {
        let rng = SimRng::new(42);
        assert_eq!(rng.seed(), 42);
    }

    #[test]
    fn same_seed_produces_same_sequence() {
        let mut rng1 = SimRng::new(12345);
        let mut rng2 = SimRng::new(12345);

        let vals1: Vec<u64> = (0..100).map(|_| rng1.next_u64()).collect();
        let vals2: Vec<u64> = (0..100).map(|_| rng2.next_u64()).collect();
        assert_eq!(vals1, vals2);
    }

    #[test]
    fn different_seeds_produce_different_sequences() {
        let mut rng1 = SimRng::new(1);
        let mut rng2 = SimRng::new(2);

        let vals1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let vals2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();
        assert_ne!(vals1, vals2);
    }

    #[test]
    fn works_with_rand_rng_trait() {
        let mut rng = SimRng::new(99);
        // gen_range requires Rng, which is auto-implemented for RngCore
        let val: u32 = rng.gen_range(0..100);
        assert!(val < 100);
    }

    #[test]
    fn fill_bytes_is_deterministic() {
        let mut rng1 = SimRng::new(7);
        let mut rng2 = SimRng::new(7);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn zero_seed_works() {
        let mut rng = SimRng::new(0);
        // Should produce values without panicking
        let _ = rng.next_u64();
    }

    #[test]
    fn max_seed_works() {
        let mut rng = SimRng::new(u64::MAX);
        let _ = rng.next_u64();
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mut rng1 = SimRng::new(42);
        // Advance rng1 a bit
        let _ = rng1.next_u64();
        let mut rng2 = rng1.clone();

        // Both should produce the same values from this point
        let vals1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let vals2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();
        assert_eq!(vals1, vals2);
    }
}
