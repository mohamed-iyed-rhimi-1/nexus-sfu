use std::cmp::Ordering;
use std::collections::BinaryHeap;

use nexus_core::MediaKind;

use crate::clock::VirtualClock;

/// Unique identifier for events (reserved for future use).
pub type EventId = u64;

/// Information about a single packet arrival, used for BWE feedback.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketArrivalInfo {
    pub sequence: u16,
    pub send_time_ns: u64,
    pub arrival_time_ns: u64,
    pub packet_size: u32,
}

/// The kind of simulation event.
#[derive(Debug, Clone, PartialEq)]
pub enum SimEventKind {
    /// A participant joins a room.
    ParticipantJoin {
        participant_name: String,
        room_name: String,
    },
    /// A participant leaves a room.
    ParticipantLeave {
        participant_name: String,
    },
    /// A track is published.
    TrackPublish {
        participant_name: String,
        media_kind: MediaKind,
        track_label: String,
    },
    /// A track is unpublished.
    TrackUnpublish {
        track_label: String,
    },
    /// A subscription is created.
    Subscribe {
        subscriber_name: String,
        track_label: String,
    },
    /// A subscription is removed.
    Unsubscribe {
        subscriber_name: String,
        track_label: String,
    },
    /// A packet is generated and sent on a track.
    PacketSend {
        track_label: String,
        payload_size: u32,
        seq_num: u16,
    },
    /// A packet arrives at a subscriber (after network simulation).
    PacketDeliver {
        track_label: String,
        subscriber_name: String,
        packet_data: Vec<u8>,
    },
    /// Fault injection: network partition.
    NetworkPartition {
        node_a: String,
        node_b: String,
    },
    /// Fault injection: heal partition.
    NetworkHeal {
        node_a: String,
        node_b: String,
    },
    /// Fault injection: actor crash.
    ActorCrash {
        actor_label: String,
    },
    /// Fault injection: packet loss burst.
    PacketLossBurst {
        duration_ms: u64,
        loss_rate: f64,
    },
    /// CRDT gossip round.
    GossipRound,
    /// BWE feedback event.
    BweFeedback {
        participant_name: String,
        packets: Vec<PacketArrivalInfo>,
    },
    /// Run invariant checks.
    InvariantCheck,
    /// NACK retransmission request for testing ring buffer retrieval.
    NackRequest {
        track_label: String,
        subscriber_name: String,
        lost_seq_nums: Vec<u16>,
    },
    /// Simulation complete.
    SimulationEnd,
}

/// A simulation event with scheduling metadata for deterministic ordering.
///
/// Events are ordered by `(scheduled_time_ns, insertion_order)` ascending,
/// ensuring deterministic tie-breaking when multiple events share the same
/// scheduled time.
#[derive(Debug, Clone, PartialEq)]
pub struct SimEvent {
    pub scheduled_time_ns: u64,
    pub insertion_order: u64,
    pub kind: SimEventKind,
}

impl Eq for SimEvent {}

impl Ord for SimEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.scheduled_time_ns
            .cmp(&other.scheduled_time_ns)
            .then_with(|| self.insertion_order.cmp(&other.insertion_order))
    }
}

impl PartialOrd for SimEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A single-threaded, deterministic event loop backed by a min-heap priority queue.
///
/// Events are processed in ascending order of `(scheduled_time_ns, insertion_order)`.
/// The virtual clock is advanced to each event's scheduled time as it is dequeued.
pub struct EventLoop {
    queue: BinaryHeap<std::cmp::Reverse<SimEvent>>,
    clock: VirtualClock,
    next_insertion_order: u64,
}

impl EventLoop {
    /// Create a new event loop with an empty queue and clock at time zero.
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            clock: VirtualClock::new(),
            next_insertion_order: 0,
        }
    }

    /// Schedule a new event at the given virtual time (in nanoseconds).
    ///
    /// Events are automatically assigned a monotonically increasing insertion
    /// order for deterministic tie-breaking.
    pub fn schedule(&mut self, time_ns: u64, kind: SimEventKind) {
        let event = SimEvent {
            scheduled_time_ns: time_ns,
            insertion_order: self.next_insertion_order,
            kind,
        };
        self.next_insertion_order += 1;
        self.queue.push(std::cmp::Reverse(event));
    }

    /// Pop and return the next event in time order, advancing the virtual clock
    /// to that event's scheduled time.
    ///
    /// Returns `None` if the queue is empty.
    pub fn next_event(&mut self) -> Option<SimEvent> {
        let std::cmp::Reverse(event) = self.queue.pop()?;
        self.clock.advance_to(event.scheduled_time_ns);
        Some(event)
    }

    /// Return a reference to the virtual clock.
    pub fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// Return `true` if there are no pending events.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for EventLoop {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_end_event() -> SimEventKind {
        SimEventKind::SimulationEnd
    }

    fn make_join(name: &str, room: &str) -> SimEventKind {
        SimEventKind::ParticipantJoin {
            participant_name: name.to_string(),
            room_name: room.to_string(),
        }
    }

    #[test]
    fn new_event_loop_is_empty() {
        let el = EventLoop::new();
        assert!(el.is_empty());
        assert_eq!(el.clock().now_ns(), 0);
    }

    #[test]
    fn schedule_makes_non_empty() {
        let mut el = EventLoop::new();
        el.schedule(100, make_end_event());
        assert!(!el.is_empty());
    }

    #[test]
    fn next_event_returns_none_when_empty() {
        let mut el = EventLoop::new();
        assert!(el.next_event().is_none());
    }

    #[test]
    fn single_event_round_trip() {
        let mut el = EventLoop::new();
        el.schedule(500, make_end_event());

        let event = el.next_event().unwrap();
        assert_eq!(event.scheduled_time_ns, 500);
        assert_eq!(event.insertion_order, 0);
        assert_eq!(event.kind, SimEventKind::SimulationEnd);
        assert!(el.is_empty());
    }

    #[test]
    fn events_ordered_by_time() {
        let mut el = EventLoop::new();
        el.schedule(300, make_join("c", "room"));
        el.schedule(100, make_join("a", "room"));
        el.schedule(200, make_join("b", "room"));

        let e1 = el.next_event().unwrap();
        let e2 = el.next_event().unwrap();
        let e3 = el.next_event().unwrap();

        assert_eq!(e1.scheduled_time_ns, 100);
        assert_eq!(e2.scheduled_time_ns, 200);
        assert_eq!(e3.scheduled_time_ns, 300);
    }

    #[test]
    fn ties_broken_by_insertion_order() {
        let mut el = EventLoop::new();
        el.schedule(100, make_join("first", "room"));
        el.schedule(100, make_join("second", "room"));
        el.schedule(100, make_join("third", "room"));

        let e1 = el.next_event().unwrap();
        let e2 = el.next_event().unwrap();
        let e3 = el.next_event().unwrap();

        // All at same time, so insertion order determines sequence
        assert_eq!(e1.insertion_order, 0);
        assert_eq!(e2.insertion_order, 1);
        assert_eq!(e3.insertion_order, 2);

        // Verify the kinds match insertion order
        assert_eq!(
            e1.kind,
            make_join("first", "room")
        );
        assert_eq!(
            e2.kind,
            make_join("second", "room")
        );
        assert_eq!(
            e3.kind,
            make_join("third", "room")
        );
    }

    #[test]
    fn clock_advances_to_event_time() {
        let mut el = EventLoop::new();
        el.schedule(1_000_000, make_end_event());

        assert_eq!(el.clock().now_ns(), 0);
        let _ = el.next_event();
        assert_eq!(el.clock().now_ns(), 1_000_000);
    }

    #[test]
    fn clock_advances_monotonically_through_events() {
        let mut el = EventLoop::new();
        el.schedule(100, make_join("a", "room"));
        el.schedule(300, make_join("b", "room"));
        el.schedule(200, make_join("c", "room"));

        let _ = el.next_event(); // time=100
        assert_eq!(el.clock().now_ns(), 100);

        let _ = el.next_event(); // time=200
        assert_eq!(el.clock().now_ns(), 200);

        let _ = el.next_event(); // time=300
        assert_eq!(el.clock().now_ns(), 300);
    }

    #[test]
    fn insertion_order_increments() {
        let mut el = EventLoop::new();
        el.schedule(10, make_end_event());
        el.schedule(20, make_end_event());
        el.schedule(30, make_end_event());

        let e1 = el.next_event().unwrap();
        let e2 = el.next_event().unwrap();
        let e3 = el.next_event().unwrap();

        assert_eq!(e1.insertion_order, 0);
        assert_eq!(e2.insertion_order, 1);
        assert_eq!(e3.insertion_order, 2);
    }

    #[test]
    fn mixed_time_and_insertion_order() {
        let mut el = EventLoop::new();
        // Schedule events with some ties
        el.schedule(200, make_join("d", "room")); // insertion 0
        el.schedule(100, make_join("a", "room")); // insertion 1
        el.schedule(200, make_join("e", "room")); // insertion 2
        el.schedule(100, make_join("b", "room")); // insertion 3

        let e1 = el.next_event().unwrap();
        let e2 = el.next_event().unwrap();
        let e3 = el.next_event().unwrap();
        let e4 = el.next_event().unwrap();

        // time=100 events first, ordered by insertion
        assert_eq!(e1.scheduled_time_ns, 100);
        assert_eq!(e1.insertion_order, 1); // "a"
        assert_eq!(e2.scheduled_time_ns, 100);
        assert_eq!(e2.insertion_order, 3); // "b"

        // time=200 events next, ordered by insertion
        assert_eq!(e3.scheduled_time_ns, 200);
        assert_eq!(e3.insertion_order, 0); // "d"
        assert_eq!(e4.scheduled_time_ns, 200);
        assert_eq!(e4.insertion_order, 2); // "e"
    }

    #[test]
    fn schedule_after_partial_drain() {
        let mut el = EventLoop::new();
        el.schedule(100, make_join("a", "room"));
        el.schedule(300, make_join("c", "room"));

        let _ = el.next_event(); // pop time=100

        // Schedule something between already-popped and remaining
        el.schedule(200, make_join("b", "room"));

        let e2 = el.next_event().unwrap();
        let e3 = el.next_event().unwrap();

        assert_eq!(e2.scheduled_time_ns, 200);
        assert_eq!(e3.scheduled_time_ns, 300);
    }

    #[test]
    fn default_is_same_as_new() {
        let el = EventLoop::default();
        assert!(el.is_empty());
        assert_eq!(el.clock().now_ns(), 0);
    }

    #[test]
    fn all_event_kinds_can_be_scheduled() {
        let mut el = EventLoop::new();

        el.schedule(1, SimEventKind::ParticipantJoin {
            participant_name: "alice".into(),
            room_name: "room1".into(),
        });
        el.schedule(2, SimEventKind::ParticipantLeave {
            participant_name: "alice".into(),
        });
        el.schedule(3, SimEventKind::TrackPublish {
            participant_name: "alice".into(),
            media_kind: MediaKind::Audio,
            track_label: "audio1".into(),
        });
        el.schedule(4, SimEventKind::TrackUnpublish {
            track_label: "audio1".into(),
        });
        el.schedule(5, SimEventKind::Subscribe {
            subscriber_name: "bob".into(),
            track_label: "audio1".into(),
        });
        el.schedule(6, SimEventKind::Unsubscribe {
            subscriber_name: "bob".into(),
            track_label: "audio1".into(),
        });
        el.schedule(7, SimEventKind::PacketSend {
            track_label: "audio1".into(),
            payload_size: 160,
            seq_num: 1,
        });
        el.schedule(8, SimEventKind::PacketDeliver {
            track_label: "audio1".into(),
            subscriber_name: "bob".into(),
            packet_data: vec![1, 2, 3],
        });
        el.schedule(9, SimEventKind::NetworkPartition {
            node_a: "a".into(),
            node_b: "b".into(),
        });
        el.schedule(10, SimEventKind::NetworkHeal {
            node_a: "a".into(),
            node_b: "b".into(),
        });
        el.schedule(11, SimEventKind::ActorCrash {
            actor_label: "track1".into(),
        });
        el.schedule(12, SimEventKind::PacketLossBurst {
            duration_ms: 500,
            loss_rate: 0.5,
        });
        el.schedule(13, SimEventKind::GossipRound);
        el.schedule(14, SimEventKind::BweFeedback {
            participant_name: "alice".into(),
            packets: vec![PacketArrivalInfo {
                sequence: 0,
                send_time_ns: 500,
                arrival_time_ns: 1000,
                packet_size: 100,
            }],
        });
        el.schedule(15, SimEventKind::InvariantCheck);
        el.schedule(16, SimEventKind::SimulationEnd);

        // Drain all 16 events in order
        for expected_time in 1..=16u64 {
            let event = el.next_event().unwrap();
            assert_eq!(event.scheduled_time_ns, expected_time);
        }
        assert!(el.is_empty());
    }
}
