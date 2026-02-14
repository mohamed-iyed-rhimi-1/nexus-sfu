use std::collections::{HashMap, HashSet};

use rand::Rng;

use crate::rng::SimRng;

/// Configuration for a single network link.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Base one-way latency in milliseconds.
    pub latency_ms: u64,
    /// Maximum jitter deviation in milliseconds (added on top of base latency).
    pub jitter_ms: u64,
    /// Packet loss probability in [0.0, 1.0].
    pub loss_rate: f64,
    /// Packet reordering probability in [0.0, 1.0].
    pub reorder_rate: f64,
}

/// Aggregate metrics tracked by the network simulator.
#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    pub packets_sent: u64,
    pub packets_delivered: u64,
    pub packets_dropped: u64,
    pub packets_reordered: u64,
}

/// Simulated network layer with configurable latency, jitter, loss, and partitions.
pub struct NetworkSimulator {
    default_config: LinkConfig,
    per_link_config: HashMap<(String, String), LinkConfig>,
    partitions: HashSet<(String, String)>,
    metrics: NetworkMetrics,
}

impl NetworkSimulator {
    /// Create a new `NetworkSimulator` with the given default link configuration.
    pub fn new(default_config: LinkConfig) -> Self {
        Self {
            default_config,
            per_link_config: HashMap::new(),
            partitions: HashSet::new(),
            metrics: NetworkMetrics::default(),
        }
    }

    /// Set a per-link configuration override for the directed link `from -> to`.
    pub fn set_link_config(&mut self, from: String, to: String, config: LinkConfig) {
        self.per_link_config.insert((from, to), config);
    }

    /// Partition two nodes bidirectionally. All packets between them will be dropped.
    pub fn partition(&mut self, node_a: &str, node_b: &str) {
        self.partitions
            .insert((node_a.to_string(), node_b.to_string()));
        self.partitions
            .insert((node_b.to_string(), node_a.to_string()));
    }

    /// Heal a bidirectional partition between two nodes.
    pub fn heal(&mut self, node_a: &str, node_b: &str) {
        self.partitions
            .remove(&(node_a.to_string(), node_b.to_string()));
        self.partitions
            .remove(&(node_b.to_string(), node_a.to_string()));
    }

    /// Check whether two nodes are partitioned (in either direction).
    pub fn is_partitioned(&self, node_a: &str, node_b: &str) -> bool {
        self.partitions
            .contains(&(node_a.to_string(), node_b.to_string()))
            || self
                .partitions
                .contains(&(node_b.to_string(), node_a.to_string()))
    }

    /// Simulate sending a packet from `from` to `to` at `current_time_ns`.
    ///
    /// Returns `None` if the packet is dropped (partition or loss), or
    /// `Some(delivery_time_ns)` if the packet will be delivered.
    ///
    /// Always increments `packets_sent`. Increments `packets_dropped` on drop,
    /// `packets_delivered` on delivery.
    pub fn send_packet(
        &mut self,
        from: &str,
        to: &str,
        current_time_ns: u64,
        rng: &mut SimRng,
    ) -> Option<u64> {
        self.metrics.packets_sent += 1;

        // Partitioned links always drop.
        if self.is_partitioned(from, to) {
            self.metrics.packets_dropped += 1;
            return None;
        }

        let config = self
            .per_link_config
            .get(&(from.to_string(), to.to_string()))
            .unwrap_or(&self.default_config);

        // Determine loss.
        if config.loss_rate > 0.0 && rng.gen_bool(config.loss_rate) {
            self.metrics.packets_dropped += 1;
            return None;
        }

        // Compute delivery time: base latency + random jitter.
        let jitter: u64 = if config.jitter_ms > 0 {
            rng.gen_range(0..=config.jitter_ms)
        } else {
            0
        };
        let delivery_time_ns =
            current_time_ns + config.latency_ms * 1_000_000 + jitter * 1_000_000;

        self.metrics.packets_delivered += 1;
        Some(delivery_time_ns)
    }

    /// Return a reference to the current network metrics.
    pub fn metrics(&self) -> &NetworkMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LinkConfig {
        LinkConfig {
            latency_ms: 50,
            jitter_ms: 10,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        }
    }

    #[test]
    fn new_simulator_has_zero_metrics() {
        let sim = NetworkSimulator::new(default_config());
        let m = sim.metrics();
        assert_eq!(m.packets_sent, 0);
        assert_eq!(m.packets_delivered, 0);
        assert_eq!(m.packets_dropped, 0);
        assert_eq!(m.packets_reordered, 0);
    }

    #[test]
    fn send_packet_increments_sent_and_delivered() {
        let mut sim = NetworkSimulator::new(default_config());
        let mut rng = SimRng::new(1);
        let result = sim.send_packet("A", "B", 0, &mut rng);
        assert!(result.is_some());
        assert_eq!(sim.metrics().packets_sent, 1);
        assert_eq!(sim.metrics().packets_delivered, 1);
        assert_eq!(sim.metrics().packets_dropped, 0);
    }

    #[test]
    fn delivery_time_within_expected_bounds() {
        let config = LinkConfig {
            latency_ms: 100,
            jitter_ms: 20,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        };
        let mut sim = NetworkSimulator::new(config);
        let mut rng = SimRng::new(42);
        let current = 1_000_000_000; // 1 second in ns

        for _ in 0..100 {
            let delivery = sim.send_packet("A", "B", current, &mut rng).unwrap();
            let min = current + 100 * 1_000_000;
            let max = current + (100 + 20) * 1_000_000;
            assert!(
                delivery >= min && delivery <= max,
                "delivery {delivery} not in [{min}, {max}]"
            );
        }
    }

    #[test]
    fn zero_jitter_gives_exact_latency() {
        let config = LinkConfig {
            latency_ms: 50,
            jitter_ms: 0,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        };
        let mut sim = NetworkSimulator::new(config);
        let mut rng = SimRng::new(7);
        let current = 500_000_000;
        let delivery = sim.send_packet("X", "Y", current, &mut rng).unwrap();
        assert_eq!(delivery, current + 50 * 1_000_000);
    }

    #[test]
    fn full_loss_drops_all_packets() {
        let config = LinkConfig {
            latency_ms: 10,
            jitter_ms: 0,
            loss_rate: 1.0,
            reorder_rate: 0.0,
        };
        let mut sim = NetworkSimulator::new(config);
        let mut rng = SimRng::new(99);

        for _ in 0..50 {
            assert!(sim.send_packet("A", "B", 0, &mut rng).is_none());
        }
        assert_eq!(sim.metrics().packets_sent, 50);
        assert_eq!(sim.metrics().packets_dropped, 50);
        assert_eq!(sim.metrics().packets_delivered, 0);
    }

    #[test]
    fn zero_loss_delivers_all_packets() {
        let config = LinkConfig {
            latency_ms: 10,
            jitter_ms: 0,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        };
        let mut sim = NetworkSimulator::new(config);
        let mut rng = SimRng::new(1);

        for _ in 0..50 {
            assert!(sim.send_packet("A", "B", 0, &mut rng).is_some());
        }
        assert_eq!(sim.metrics().packets_sent, 50);
        assert_eq!(sim.metrics().packets_delivered, 50);
        assert_eq!(sim.metrics().packets_dropped, 0);
    }

    #[test]
    fn partition_drops_packets_bidirectionally() {
        let mut sim = NetworkSimulator::new(default_config());
        let mut rng = SimRng::new(1);

        sim.partition("A", "B");
        assert!(sim.send_packet("A", "B", 0, &mut rng).is_none());
        assert!(sim.send_packet("B", "A", 0, &mut rng).is_none());
        assert_eq!(sim.metrics().packets_dropped, 2);
    }

    #[test]
    fn heal_restores_delivery() {
        let mut sim = NetworkSimulator::new(default_config());
        let mut rng = SimRng::new(1);

        sim.partition("A", "B");
        assert!(sim.send_packet("A", "B", 0, &mut rng).is_none());

        sim.heal("A", "B");
        assert!(sim.send_packet("A", "B", 0, &mut rng).is_some());
        assert!(!sim.is_partitioned("A", "B"));
    }

    #[test]
    fn is_partitioned_checks_both_directions() {
        let mut sim = NetworkSimulator::new(default_config());
        assert!(!sim.is_partitioned("A", "B"));

        sim.partition("A", "B");
        assert!(sim.is_partitioned("A", "B"));
        assert!(sim.is_partitioned("B", "A"));
    }

    #[test]
    fn per_link_config_overrides_default() {
        let mut sim = NetworkSimulator::new(LinkConfig {
            latency_ms: 100,
            jitter_ms: 0,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        });
        sim.set_link_config(
            "A".to_string(),
            "B".to_string(),
            LinkConfig {
                latency_ms: 200,
                jitter_ms: 0,
                loss_rate: 0.0,
                reorder_rate: 0.0,
            },
        );
        let mut rng = SimRng::new(1);

        // A->B uses per-link config (200ms)
        let delivery_ab = sim.send_packet("A", "B", 0, &mut rng).unwrap();
        assert_eq!(delivery_ab, 200 * 1_000_000);

        // B->A uses default config (100ms)
        let delivery_ba = sim.send_packet("B", "A", 0, &mut rng).unwrap();
        assert_eq!(delivery_ba, 100 * 1_000_000);
    }

    #[test]
    fn partition_unrelated_nodes_does_not_affect_others() {
        let mut sim = NetworkSimulator::new(default_config());
        let mut rng = SimRng::new(1);

        sim.partition("A", "B");
        // C->D should still work
        assert!(sim.send_packet("C", "D", 0, &mut rng).is_some());
    }

    #[test]
    fn send_packet_deterministic_with_same_seed() {
        let config = LinkConfig {
            latency_ms: 50,
            jitter_ms: 10,
            loss_rate: 0.3,
            reorder_rate: 0.0,
        };

        let mut sim1 = NetworkSimulator::new(config.clone());
        let mut rng1 = SimRng::new(42);
        let results1: Vec<Option<u64>> = (0..100)
            .map(|_| sim1.send_packet("A", "B", 1_000_000_000, &mut rng1))
            .collect();

        let mut sim2 = NetworkSimulator::new(config);
        let mut rng2 = SimRng::new(42);
        let results2: Vec<Option<u64>> = (0..100)
            .map(|_| sim2.send_packet("A", "B", 1_000_000_000, &mut rng2))
            .collect();

        assert_eq!(results1, results2);
    }

    #[test]
    fn heal_without_partition_is_noop() {
        let mut sim = NetworkSimulator::new(default_config());
        let mut rng = SimRng::new(1);

        // Healing nodes that aren't partitioned should be fine
        sim.heal("A", "B");
        assert!(!sim.is_partitioned("A", "B"));
        assert!(sim.send_packet("A", "B", 0, &mut rng).is_some());
    }

    #[test]
    fn multiple_partitions_independent() {
        let mut sim = NetworkSimulator::new(default_config());

        sim.partition("A", "B");
        sim.partition("C", "D");

        assert!(sim.is_partitioned("A", "B"));
        assert!(sim.is_partitioned("C", "D"));
        assert!(!sim.is_partitioned("A", "C"));

        sim.heal("A", "B");
        assert!(!sim.is_partitioned("A", "B"));
        assert!(sim.is_partitioned("C", "D"));
    }
}
