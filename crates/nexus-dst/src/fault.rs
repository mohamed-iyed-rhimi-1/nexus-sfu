use crate::event_loop::{EventLoop, SimEventKind};

/// A fault event that can be injected into the simulation.
#[derive(Debug, Clone, PartialEq)]
pub enum FaultEvent {
    /// Partition the network between two nodes, preventing packet delivery.
    NetworkPartition { node_a: String, node_b: String },
    /// Heal a network partition, restoring packet delivery between two nodes.
    NetworkHeal { node_a: String, node_b: String },
    /// Crash a specific actor by label.
    ActorCrash { actor_label: String },
    /// Inject a burst of packet loss for a given duration and rate.
    PacketLossBurst { duration_ms: u64, loss_rate: f64 },
}

/// Collects scheduled faults and injects them into the event loop as `SimEventKind` variants.
pub struct FaultInjector {
    scheduled_faults: Vec<(u64, FaultEvent)>, // (time_ns, fault)
}

impl FaultInjector {
    /// Create a new, empty fault injector.
    pub fn new() -> Self {
        Self {
            scheduled_faults: Vec::new(),
        }
    }

    /// Schedule a fault to be injected at the given virtual time (nanoseconds).
    pub fn schedule(&mut self, time_ns: u64, fault: FaultEvent) {
        self.scheduled_faults.push((time_ns, fault));
    }

    /// Convert all scheduled faults into `SimEventKind` variants and schedule
    /// them on the provided event loop.
    pub fn inject_into_event_loop(&self, event_loop: &mut EventLoop) {
        for (time_ns, fault) in &self.scheduled_faults {
            let kind = match fault {
                FaultEvent::NetworkPartition { node_a, node_b } => {
                    SimEventKind::NetworkPartition {
                        node_a: node_a.clone(),
                        node_b: node_b.clone(),
                    }
                }
                FaultEvent::NetworkHeal { node_a, node_b } => SimEventKind::NetworkHeal {
                    node_a: node_a.clone(),
                    node_b: node_b.clone(),
                },
                FaultEvent::ActorCrash { actor_label } => SimEventKind::ActorCrash {
                    actor_label: actor_label.clone(),
                },
                FaultEvent::PacketLossBurst {
                    duration_ms,
                    loss_rate,
                } => SimEventKind::PacketLossBurst {
                    duration_ms: *duration_ms,
                    loss_rate: *loss_rate,
                },
            };
            event_loop.schedule(*time_ns, kind);
        }
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_injector_has_no_faults() {
        let injector = FaultInjector::new();
        assert!(injector.scheduled_faults.is_empty());
    }

    #[test]
    fn default_is_same_as_new() {
        let injector = FaultInjector::default();
        assert!(injector.scheduled_faults.is_empty());
    }

    #[test]
    fn schedule_adds_fault() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            1_000_000,
            FaultEvent::NetworkPartition {
                node_a: "a".into(),
                node_b: "b".into(),
            },
        );
        assert_eq!(injector.scheduled_faults.len(), 1);
        assert_eq!(injector.scheduled_faults[0].0, 1_000_000);
    }

    #[test]
    fn schedule_multiple_faults() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            1_000_000,
            FaultEvent::NetworkPartition {
                node_a: "a".into(),
                node_b: "b".into(),
            },
        );
        injector.schedule(
            5_000_000,
            FaultEvent::NetworkHeal {
                node_a: "a".into(),
                node_b: "b".into(),
            },
        );
        injector.schedule(
            3_000_000,
            FaultEvent::ActorCrash {
                actor_label: "track1".into(),
            },
        );
        injector.schedule(
            7_000_000,
            FaultEvent::PacketLossBurst {
                duration_ms: 500,
                loss_rate: 0.3,
            },
        );
        assert_eq!(injector.scheduled_faults.len(), 4);
    }

    #[test]
    fn inject_network_partition_into_event_loop() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            2_000_000,
            FaultEvent::NetworkPartition {
                node_a: "alice".into(),
                node_b: "bob".into(),
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);

        assert!(!event_loop.is_empty());
        let event = event_loop.next_event().unwrap();
        assert_eq!(event.scheduled_time_ns, 2_000_000);
        assert_eq!(
            event.kind,
            SimEventKind::NetworkPartition {
                node_a: "alice".into(),
                node_b: "bob".into(),
            }
        );
    }

    #[test]
    fn inject_network_heal_into_event_loop() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            4_000_000,
            FaultEvent::NetworkHeal {
                node_a: "alice".into(),
                node_b: "bob".into(),
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);

        let event = event_loop.next_event().unwrap();
        assert_eq!(event.scheduled_time_ns, 4_000_000);
        assert_eq!(
            event.kind,
            SimEventKind::NetworkHeal {
                node_a: "alice".into(),
                node_b: "bob".into(),
            }
        );
    }

    #[test]
    fn inject_actor_crash_into_event_loop() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            3_000_000,
            FaultEvent::ActorCrash {
                actor_label: "room_actor".into(),
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);

        let event = event_loop.next_event().unwrap();
        assert_eq!(event.scheduled_time_ns, 3_000_000);
        assert_eq!(
            event.kind,
            SimEventKind::ActorCrash {
                actor_label: "room_actor".into(),
            }
        );
    }

    #[test]
    fn inject_packet_loss_burst_into_event_loop() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            6_000_000,
            FaultEvent::PacketLossBurst {
                duration_ms: 1000,
                loss_rate: 0.75,
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);

        let event = event_loop.next_event().unwrap();
        assert_eq!(event.scheduled_time_ns, 6_000_000);
        assert_eq!(
            event.kind,
            SimEventKind::PacketLossBurst {
                duration_ms: 1000,
                loss_rate: 0.75,
            }
        );
    }

    #[test]
    fn inject_all_fault_types_preserves_ordering() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            1_000_000,
            FaultEvent::NetworkPartition {
                node_a: "a".into(),
                node_b: "b".into(),
            },
        );
        injector.schedule(
            2_000_000,
            FaultEvent::ActorCrash {
                actor_label: "x".into(),
            },
        );
        injector.schedule(
            3_000_000,
            FaultEvent::PacketLossBurst {
                duration_ms: 200,
                loss_rate: 0.5,
            },
        );
        injector.schedule(
            4_000_000,
            FaultEvent::NetworkHeal {
                node_a: "a".into(),
                node_b: "b".into(),
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);

        let e1 = event_loop.next_event().unwrap();
        let e2 = event_loop.next_event().unwrap();
        let e3 = event_loop.next_event().unwrap();
        let e4 = event_loop.next_event().unwrap();

        assert_eq!(e1.scheduled_time_ns, 1_000_000);
        assert_eq!(e2.scheduled_time_ns, 2_000_000);
        assert_eq!(e3.scheduled_time_ns, 3_000_000);
        assert_eq!(e4.scheduled_time_ns, 4_000_000);

        assert!(matches!(e1.kind, SimEventKind::NetworkPartition { .. }));
        assert!(matches!(e2.kind, SimEventKind::ActorCrash { .. }));
        assert!(matches!(e3.kind, SimEventKind::PacketLossBurst { .. }));
        assert!(matches!(e4.kind, SimEventKind::NetworkHeal { .. }));

        assert!(event_loop.is_empty());
    }

    #[test]
    fn inject_empty_injector_leaves_event_loop_empty() {
        let injector = FaultInjector::new();
        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);
        assert!(event_loop.is_empty());
    }

    #[test]
    fn inject_can_be_called_multiple_times() {
        let mut injector = FaultInjector::new();
        injector.schedule(
            1_000_000,
            FaultEvent::ActorCrash {
                actor_label: "a".into(),
            },
        );

        let mut event_loop = EventLoop::new();
        injector.inject_into_event_loop(&mut event_loop);
        // Calling again should add duplicates (idempotency is not required)
        injector.inject_into_event_loop(&mut event_loop);

        let e1 = event_loop.next_event().unwrap();
        let e2 = event_loop.next_event().unwrap();
        assert_eq!(e1.scheduled_time_ns, 1_000_000);
        assert_eq!(e2.scheduled_time_ns, 1_000_000);
        assert!(event_loop.is_empty());
    }
}
