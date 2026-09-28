//! Orchestrator tests on a real one-shard data plane (loopback, port 0).
//!
//! Clients are simulated at the signaling level: offers are turned into answers by
//! rewriting the SDP text (`answer_for`); no media or DTLS flows. What the shard did
//! with the commands is read from its counters and gauges once a barrier command
//! (`CloseSession` of an id never created, answered by a rejection carrying that id)
//! came back. The full-queue test uses a command sink whose queue can be filled and
//! emptied.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use nexus_dataplane::{
    Command, CommandQueueFull, Dataplane, DataplaneConfig, DataplaneHandle, Event, RejectReason,
    SessionId, ShardId, ShardLoad, ShardStatsSnapshot, SingleShard, MAX_TRACKS_PER_SESSION,
};
use nexus_state::DistributedStateConfig;
use parking_lot::Mutex;
use proptest::prelude::*;

use super::plane::CommandSink;
use super::*;

/// A peer fingerprint for answers (the handshake never runs in these tests).
const PEER_FINGERPRINT: &str = "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:\
                                AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB";

struct Harness {
    orchestrator: SessionOrchestrator,
    dataplane: Arc<DataplaneHandle>,
    events: mpsc::Receiver<Event>,
    clients: HashMap<u64, mpsc::Receiver<SignalMessage>>,
    barriers: u64,
}

impl Harness {
    fn new() -> Self {
        let config = DataplaneConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            rng_seed: Some(7),
            ..Default::default()
        };
        let (dataplane, shards) = Dataplane::start(config).unwrap();
        let events = dataplane.take_events().unwrap();
        let dataplane = Arc::new(dataplane);
        let orchestrator = orchestrator_on(
            Arc::clone(&dataplane) as Arc<dyn CommandSink>,
            shards[0].local_addr,
        );
        Self {
            orchestrator,
            dataplane,
            events,
            clients: HashMap::new(),
            barriers: 0,
        }
    }

    fn send(&mut self, participant_id: u64, message: SignalMessage) {
        send(&mut self.orchestrator, participant_id, message);
    }

    /// A connected participant in room 1 (created by participant 1).
    fn join(&mut self, participant_id: u64) {
        let rx = connect(&mut self.orchestrator, participant_id);
        self.clients.insert(participant_id, rx);
        if participant_id == 1 {
            self.send(1, SignalMessage::Create { room_name: None });
        }
        self.join_room(participant_id, 1);
    }

    fn join_room(&mut self, participant_id: u64, room_id: u64) {
        self.send(
            participant_id,
            SignalMessage::Join {
                room_id,
                participant_name: format!("p{participant_id}"),
            },
        );
        self.drain(participant_id);
    }

    /// Every signaling message sent to `participant_id` since the last drain.
    fn drain(&mut self, participant_id: u64) -> Vec<SignalMessage> {
        drain(self.clients.get_mut(&participant_id).unwrap())
    }

    /// Error codes sent to `participant_id` since the last drain.
    fn errors(&mut self, participant_id: u64) -> Vec<String> {
        error_codes(self.drain(participant_id))
    }

    /// The last offer sent to `participant_id` (and its `tracks`).
    fn offer(&mut self, participant_id: u64) -> (String, Vec<crate::signal::OfferTrack>) {
        self.drain(participant_id)
            .into_iter()
            .filter_map(|m| match m {
                SignalMessage::Offer { sdp, tracks } => Some((sdp, tracks)),
                _ => None,
            })
            .last()
            .expect("an offer")
    }

    /// Wait until the shard handled every command pushed so far. The barrier is a
    /// `CloseSession` for a session id no one created: its rejection names that id, so
    /// no other command's outcome can satisfy the wait. Returns the other events.
    async fn barrier(&mut self) -> Vec<Event> {
        self.barriers += 1;
        let id = SessionId::new(u64::MAX / 2 + self.barriers);
        self.dataplane
            .send(ShardId::new(0), Command::CloseSession { id })
            .unwrap();
        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.recv())
                .await
                .expect("barrier within 5 s")
                .expect("event channel open");
            match event {
                Event::CommandRejected { id: Some(got), .. } if got == id => return seen,
                other => seen.push(other),
            }
        }
    }

    /// The shard's stats after a barrier. Stats are published once per second: wait
    /// for a snapshot that counts this barrier's rejection. Every rejection besides
    /// the barriers means the shard refused a command, which fails the test.
    async fn stats(&mut self) -> ShardStatsSnapshot {
        let events = self.barrier().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let stats = self.dataplane.stats(ShardId::new(0));
            if stats.counters.commands_rejected >= self.barriers {
                assert_eq!(
                    stats.counters.commands_rejected, self.barriers,
                    "the shard refused a command: {events:?}"
                );
                return stats;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "stats not published"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn orchestrator_on(sink: Arc<dyn CommandSink>, media: std::net::SocketAddr) -> SessionOrchestrator {
    let state = Arc::new(DistributedState::new(DistributedStateConfig::new(1)));
    SessionOrchestrator::new(
        sink,
        vec![vec![media]],
        Box::new(SingleShard),
        DtlsCertificate::generate().unwrap(),
        state,
    )
}

fn send(orchestrator: &mut SessionOrchestrator, participant_id: u64, message: SignalMessage) {
    orchestrator.dispatch_event(OrchestratorEvent::Message {
        participant_id,
        message,
    });
    orchestrator.settle();
}

fn connect(
    orchestrator: &mut SessionOrchestrator,
    participant_id: u64,
) -> mpsc::Receiver<SignalMessage> {
    let (tx, rx) = mpsc::channel(1024);
    orchestrator.dispatch_event(OrchestratorEvent::Connected {
        participant_id,
        outbound_tx: tx,
        claims: None,
    });
    rx
}

fn drain(rx: &mut mpsc::Receiver<SignalMessage>) -> Vec<SignalMessage> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn error_codes(messages: Vec<SignalMessage>) -> Vec<String> {
    messages
        .into_iter()
        .filter_map(|m| match m {
            SignalMessage::Error { code, .. } => Some(code),
            _ => None,
        })
        .collect()
}

fn publish_msg(kinds: &[&str]) -> SignalMessage {
    SignalMessage::Publish {
        kinds: kinds.iter().map(|k| k.to_string()).collect(),
        contents: kinds
            .iter()
            .map(|k| if *k == "audio" { "audio" } else { "camera" }.to_string())
            .collect(),
    }
}

/// An answer to `offer`: directions flipped, `setup:active`, a peer fingerprint, no
/// ice-lite, an `a=ssrc` per publish m-line (`ssrc_base + index`), and the m-lines of
/// `declined` mids rejected (port 0).
fn answer_for(offer: &str, ssrc_base: u32, declined: &[&str]) -> String {
    let mut out = String::new();
    let mut sections = offer.split("\r\nm=");
    let session = sections.next().unwrap();
    for line in session.lines() {
        match line {
            "a=ice-lite" => {}
            "a=setup:actpass" => out.push_str("a=setup:active\r\n"),
            l if l.starts_with("a=fingerprint:") => {
                out.push_str(&format!("a=fingerprint:sha-256 {PEER_FINGERPRINT}\r\n"))
            }
            l => out.push_str(&format!("{l}\r\n")),
        }
    }
    for (index, section) in sections.enumerate() {
        let mid = section
            .lines()
            .find_map(|l| l.strip_prefix("a=mid:"))
            .unwrap();
        let publish = section.lines().any(|l| l == "a=recvonly");
        for (n, line) in section.lines().enumerate() {
            let line = match line {
                _ if n == 0 && declined.contains(&mid) => {
                    let mut parts: Vec<&str> = line.splitn(3, ' ').collect();
                    parts[1] = "0";
                    parts.join(" ")
                }
                _ if n == 0 => line.to_string(),
                "a=recvonly" => "a=sendonly".to_string(),
                "a=sendonly" => "a=recvonly".to_string(),
                "a=setup:actpass" => "a=setup:active".to_string(),
                l if l.starts_with("a=fingerprint:") => {
                    format!("a=fingerprint:sha-256 {PEER_FINGERPRINT}")
                }
                l if l.starts_with("a=ssrc:") || l.starts_with("a=msid:") => continue,
                l => l.to_string(),
            };
            let prefix = if n == 0 { "m=" } else { "" };
            out.push_str(&format!("{prefix}{line}\r\n"));
        }
        if publish && !declined.contains(&mid) {
            out.push_str(&format!(
                "a=ssrc:{} cname:peer\r\n",
                ssrc_base + index as u32
            ));
        }
    }
    out
}

/// Mids and directions of an SDP, in order.
fn directions(sdp: &str) -> Vec<(String, String)> {
    sdp.split("m=")
        .skip(1)
        .map(|s| {
            let mid = s.lines().find_map(|l| l.strip_prefix("a=mid:")).unwrap();
            let dir = s
                .lines()
                .find(|l| ["a=sendonly", "a=recvonly", "a=inactive", "a=sendrecv"].contains(l))
                .unwrap();
            (mid.to_string(), dir.to_string())
        })
        .collect()
}

/// The SSRC announced on the m-line of `mid`.
fn announced_ssrc(sdp: &str, mid: &str) -> Option<u32> {
    let section = sdp
        .split("m=")
        .skip(1)
        .find(|s| s.lines().any(|l| l == format!("a=mid:{mid}")))?;
    section
        .lines()
        .find_map(|l| l.strip_prefix("a=ssrc:"))
        .and_then(|v| v.split(' ').next())
        .and_then(|v| v.parse().ok())
}

/// Participant `publisher` publishes `kinds` and answers; returns the new track ids.
fn publish_kinds(h: &mut Harness, publisher: u64, kinds: &[&str], ssrc_base: u32) -> Vec<u64> {
    let before = h.orchestrator.negotiation.states[&publisher]
        .published_tracks
        .clone();
    h.send(publisher, publish_msg(kinds));
    let (offer, _) = h.offer(publisher);
    assert!(offer.contains("a=ice-lite\r\n"), "{offer}");
    h.send(
        publisher,
        SignalMessage::Answer {
            sdp: answer_for(&offer, ssrc_base, &[]),
        },
    );
    let after = h.orchestrator.negotiation.states[&publisher]
        .published_tracks
        .clone();
    let new: Vec<u64> = after.into_iter().filter(|t| !before.contains(t)).collect();
    assert_eq!(new.len(), kinds.len());
    new
}

/// Audio and video from `publisher`.
async fn publish(h: &mut Harness, publisher: u64, ssrc_base: u32) -> Vec<u64> {
    publish_kinds(h, publisher, &["audio", "video"], ssrc_base)
}

#[tokio::test]
async fn publish_answer_adds_tracks_on_the_shard() {
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    let stats = h.stats().await;
    assert_eq!(stats.gauges.tracks, 2, "{stats:?}");
    assert_eq!(stats.gauges.sessions, 1, "only the publisher has a session");
    let peer = h.drain(2);
    let published: Vec<u64> = peer
        .iter()
        .filter_map(|m| match m {
            SignalMessage::TrackPublished { track_id, .. } => Some(*track_id),
            _ => None,
        })
        .collect();
    assert_eq!(published, tracks);
    assert!(
        own_tracks(&peer).is_empty(),
        "Published goes to the publisher only"
    );
    // The publisher learns its own ids, with the m-line of each.
    let own = own_tracks(&h.drain(1));
    assert_eq!(
        own,
        [
            (tracks[0], "0".to_string(), "audio".to_string()),
            (tracks[1], "1".to_string(), "video".to_string()),
        ]
    );
}

/// The `Published` messages among `messages`: (track id, mid, kind).
fn own_tracks(messages: &[SignalMessage]) -> Vec<(u64, String, String)> {
    messages
        .iter()
        .filter_map(|m| match m {
            SignalMessage::Published {
                track_id,
                mid,
                kind,
            } => Some((*track_id, mid.clone(), kind.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn publish_needs_a_room_and_subscribe_stays_in_it() {
    let mut h = Harness::new();
    let rx = connect(&mut h.orchestrator, 9);
    h.clients.insert(9, rx);
    h.send(9, publish_msg(&["audio"]));
    assert_eq!(h.errors(9), ["NOT_IN_ROOM"]);
    assert!(h.orchestrator.negotiation.session(9).is_none());

    h.join(1);
    let tracks = publish(&mut h, 1, 5_000).await;
    // Participant 3 is in room 2: room 1's track ids are not its to subscribe to.
    let rx = connect(&mut h.orchestrator, 3);
    h.clients.insert(3, rx);
    h.send(
        3,
        SignalMessage::Create {
            room_name: Some("b".into()),
        },
    );
    h.join_room(3, 2);
    h.send(
        3,
        SignalMessage::Subscribe {
            track_ids: tracks.clone(),
        },
    );
    let messages = h.drain(3);
    assert!(
        !messages.iter().any(|m| matches!(
            m,
            SignalMessage::Subscribed { .. } | SignalMessage::Offer { .. }
        )),
        "{messages:?}"
    );
    assert!(h.orchestrator.subscription.track_ids(3).is_empty());
    assert!(h.orchestrator.negotiation.session(3).is_none());
    // A participant of room 1 may.
    h.join(2);
    h.send(
        2,
        SignalMessage::Subscribe {
            track_ids: tracks.clone(),
        },
    );
    assert_eq!(h.orchestrator.subscription.track_ids(2), tracks);
}

#[tokio::test]
async fn publish_and_subscribe_limits_are_the_shards() {
    let mut h = Harness::new();
    h.join(1);
    // Ten tracks is the most a session publishes, published or in an offer.
    let ten = ["audio"; MAX_TRACKS_PER_SESSION];
    publish_kinds(&mut h, 1, &ten[..6], 1_000);
    h.send(1, publish_msg(&ten[..4]));
    h.send(1, publish_msg(&["video"]));
    assert_eq!(h.errors(1), ["TOO_MANY_TRACKS"]);

    // 31 subscriptions per session: 4 publishers × 8 tracks give 32.
    let mut tracks = Vec::new();
    for publisher in 2..=5 {
        h.join(publisher);
        tracks.extend(publish_kinds(
            &mut h,
            publisher,
            &["audio"; 8],
            publisher as u32 * 1_000,
        ));
    }
    h.join(6);
    for chunk in tracks[..30].chunks(10) {
        h.send(
            6,
            SignalMessage::Subscribe {
                track_ids: chunk.to_vec(),
            },
        );
    }
    assert_eq!(h.orchestrator.subscription.track_ids(6).len(), 30);
    h.drain(6);
    h.send(
        6,
        SignalMessage::Subscribe {
            track_ids: tracks[30..].to_vec(),
        },
    );
    assert_eq!(h.errors(6), ["TOO_MANY_TRACKS"]);
    assert_eq!(h.orchestrator.subscription.track_ids(6).len(), 30);
    assert!(h.stats().await.gauges.tracks == 6 + 32);
}

#[tokio::test]
async fn publish_during_an_open_offer_is_queued_not_lost() {
    let mut h = Harness::new();
    h.join(1);
    h.send(1, publish_msg(&["audio"]));
    let (offer, _) = h.offer(1);
    // Two more publishes while the offer is open: both are kept.
    h.send(1, publish_msg(&["video"]));
    h.send(1, publish_msg(&["audio"]));
    h.send(
        1,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 5_000, &[]),
        },
    );
    let (offer, _) = h.offer(1);
    assert_eq!(directions(&offer).len(), 3, "{offer}");
    h.send(
        1,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 5_000, &[]),
        },
    );
    assert_eq!(
        h.orchestrator.negotiation.states[&1].published_tracks.len(),
        3
    );
    assert_eq!(h.stats().await.gauges.tracks, 3);
}

#[tokio::test]
async fn invalid_answer_releases_the_queued_publish() {
    let mut h = Harness::new();
    h.join(1);
    h.send(1, publish_msg(&["audio"]));
    let (offer, _) = h.offer(1);
    h.send(1, publish_msg(&["video"]));
    let answer = answer_for(&offer, 5_000, &[]).replace("a=mid:0", "a=mid:7");
    h.send(1, SignalMessage::Answer { sdp: answer });
    let messages = h.drain(1);
    assert!(error_codes(messages.clone()).contains(&"INVALID_ANSWER".to_string()));
    let offer = messages.into_iter().find_map(|m| match m {
        SignalMessage::Offer { sdp, .. } => Some(sdp),
        _ => None,
    });
    let offer = offer.expect("the queued publish is offered at once");
    assert_eq!(directions(&offer).len(), 2);
    assert!(h.orchestrator.negotiation.states[&1].offer_pending);
    assert!(h.orchestrator.plane.tracks.is_empty());
}

#[tokio::test]
async fn unpublished_mline_is_reused_by_the_next_publish() {
    let mut h = Harness::new();
    h.join(1);
    let tracks = publish(&mut h, 1, 5_000).await;
    h.send(
        1,
        SignalMessage::Unpublish {
            track_ids: vec![tracks[0]],
        },
    );
    let states = &h.orchestrator.negotiation.states[&1];
    assert_eq!(states.published_tracks, vec![tracks[1]]);
    assert_eq!(states.mlines[0].role, negotiation::MlineRole::Inactive);
    // Chrome reuses the transceiver, and with it the SSRC (m-line 0: 5,000 again).
    let again = publish_kinds(&mut h, 1, &["audio"], 5_000);
    assert_eq!(
        own_tracks(&h.drain(1)),
        [(again[0], "0".to_string(), "audio".to_string())],
        "the publisher learns the new id on the reused m-line"
    );
    let states = &h.orchestrator.negotiation.states[&1];
    assert_eq!(states.mlines.len(), 2, "mid 0 reused");
    assert_eq!(states.mlines[0].role, negotiation::MlineRole::Publish);
    assert_ne!(again[0], tracks[0]);
    let info = h
        .orchestrator
        .plane
        .tracks
        .get(DpTrackId::new(again[0]))
        .unwrap();
    assert_eq!(
        info.spec.ssrc,
        Some(5_000),
        "same SSRC as the unpublished track"
    );
    // The shard accepted it (`stats` fails on any refusal).
    assert_eq!(h.stats().await.gauges.tracks, 2);
}

/// A publish m-line the answer refuses (a duplicate SSRC, or declined) turns inactive,
/// and the next publish of its kind reuses it and registers.
#[tokio::test]
async fn refused_publish_mline_is_released_and_reused() {
    let mut h = Harness::new();
    h.join(1);
    let first = publish_kinds(&mut h, 1, &["audio"], 5_000);
    h.drain(1);

    // Refused at answer time: m-line 1 answers with 5,000, the SSRC of track `first`
    h.send(1, publish_msg(&["audio"]));
    let (offer, _) = h.offer(1);
    let answer = answer_for(&offer, 4_999, &[]);
    h.send(1, SignalMessage::Answer { sdp: answer });
    let replies = h.drain(1);
    assert_eq!(error_codes(replies.clone()), ["DUPLICATE_SSRC"]);
    assert!(own_tracks(&replies).is_empty());
    let states = &h.orchestrator.negotiation.states[&1];
    assert_eq!(states.published_tracks, first);
    assert_eq!(states.mlines[1].role, negotiation::MlineRole::Inactive);

    // Declined (port 0): no track, no error, the m-line is released too
    h.send(1, publish_msg(&["audio"]));
    let (offer, _) = h.offer(1);
    assert_eq!(mline_directions(&offer)[1], ("1".to_string(), "recvonly"));
    h.send(
        1,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 6_000, &["1"]),
        },
    );
    assert!(own_tracks(&h.drain(1)).is_empty());
    let states = &h.orchestrator.negotiation.states[&1];
    assert_eq!(states.mlines[1].role, negotiation::MlineRole::Inactive);

    // The next publish reuses m-line 1 and registers
    let again = publish_kinds(&mut h, 1, &["audio"], 7_000);
    assert_eq!(
        own_tracks(&h.drain(1)),
        [(again[0], "1".to_string(), "audio".to_string())]
    );
    let states = &h.orchestrator.negotiation.states[&1];
    assert_eq!(states.mlines.len(), 2, "mid 1 reused, no new m-line");
    assert_eq!(states.mlines[1].role, negotiation::MlineRole::Publish);
    assert_eq!(h.stats().await.gauges.tracks, 2);
}

/// Each m-line's mid and direction attribute, in offer order.
fn mline_directions(sdp: &str) -> Vec<(String, &'static str)> {
    sdp.split("\r\nm=")
        .skip(1)
        .map(|s| {
            let mid = s.lines().find_map(|l| l.strip_prefix("a=mid:")).unwrap();
            let dir = ["recvonly", "sendonly", "inactive", "sendrecv"]
                .into_iter()
                .find(|d| s.lines().any(|l| l == format!("a={d}")))
                .unwrap();
            (mid.to_string(), dir)
        })
        .collect()
}

/// Room and participant input that reached asserts downstream (exit criterion 6):
/// an over-long room name, the end of the room id space, an over-long participant
/// name, a room id above u32 (it wrapped onto another room).
#[tokio::test]
async fn create_and_join_refuse_input_that_used_to_panic() {
    let mut h = Harness::new();
    let rx = connect(&mut h.orchestrator, 1);
    h.clients.insert(1, rx);
    let long = "a".repeat(nexus_state::MAX_ROOM_NAME_LEN + 1);
    h.send(
        1,
        SignalMessage::Create {
            room_name: Some(long),
        },
    );
    assert_eq!(h.errors(1), ["INVALID_INPUT"]);
    let longest = "é".repeat(nexus_state::MAX_ROOM_NAME_LEN / 2);
    h.send(
        1,
        SignalMessage::Create {
            room_name: Some(longest),
        },
    );
    let created = h.drain(1);
    assert!(matches!(
        created[..],
        [SignalMessage::Created { room_id: 1, .. }]
    ));

    // The last id is never handed out: no wrap to 0
    h.orchestrator.plane.state.set_next_room_id(u32::MAX - 1);
    h.send(1, SignalMessage::Create { room_name: None });
    let created = h.drain(1);
    let max = u64::from(u32::MAX - 1);
    assert!(matches!(created[..], [SignalMessage::Created { room_id, .. }] if room_id == max));
    h.send(1, SignalMessage::Create { room_name: None });
    assert_eq!(h.errors(1), ["ROOM_LIMIT"]);

    let name = "n".repeat(room::MAX_PARTICIPANT_NAME_LEN + 1);
    h.send(
        1,
        SignalMessage::Join {
            room_id: 1,
            participant_name: name,
        },
    );
    assert_eq!(h.errors(1), ["INVALID_INPUT"]);
    h.send(
        1,
        SignalMessage::Join {
            room_id: (1u64 << 32) + 1,
            participant_name: "p1".into(),
        },
    );
    assert_eq!(h.errors(1), ["ROOM_NOT_FOUND"], "not room 1");
    h.send(
        1,
        SignalMessage::Join {
            room_id: 1,
            participant_name: "p1".into(),
        },
    );
    assert!(h.errors(1).is_empty());
}

/// Room creation is bounded per connection, and a room nobody joined is released
/// when its creator leaves or disconnects; a room with members is not.
#[tokio::test]
async fn created_rooms_are_limited_and_released_with_their_creator() {
    let mut h = Harness::new();
    for pid in [1, 2] {
        let rx = connect(&mut h.orchestrator, pid);
        h.clients.insert(pid, rx);
    }
    let state = h.orchestrator.plane.state.clone();
    for _ in 0..room::MAX_ROOMS_PER_CREATOR {
        h.send(1, SignalMessage::Create { room_name: None });
    }
    let created: Vec<u64> = h
        .drain(1)
        .into_iter()
        .filter_map(|m| match m {
            SignalMessage::Created { room_id, .. } => Some(room_id),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), room::MAX_ROOMS_PER_CREATOR);
    h.send(
        1,
        SignalMessage::Create {
            room_name: Some("one more".into()),
        },
    );
    assert_eq!(h.errors(1), ["ROOM_LIMIT"]);
    // A known name is not a new room: allowed
    h.send(
        2,
        SignalMessage::Create {
            room_name: Some("shared".into()),
        },
    );
    h.send(
        1,
        SignalMessage::Create {
            room_name: Some("shared".into()),
        },
    );
    assert!(h.errors(1).is_empty());
    assert_eq!(state.room_count(), room::MAX_ROOMS_PER_CREATOR + 1);

    // Participant 2 joins one of 1's rooms; 1 disconnects: the empty ones go
    let joined = created[0];
    h.send(
        2,
        SignalMessage::Join {
            room_id: joined,
            participant_name: "p2".into(),
        },
    );
    h.drain(2);
    h.orchestrator
        .dispatch_event(OrchestratorEvent::Disconnected { participant_id: 1 });
    h.orchestrator.settle();
    assert!(
        state.room_exists(joined as u32),
        "a room with a member stays"
    );
    for room in &created[1..] {
        assert!(
            !state.room_exists(*room as u32),
            "empty room {room} released"
        );
    }
    assert!(
        state.room_exists(1 + room::MAX_ROOMS_PER_CREATOR as u32),
        "2's room stays"
    );
    // The last member leaving releases the joined room as before
    h.send(2, SignalMessage::Leave);
    assert!(!state.room_exists(joined as u32));
}

/// A room id the REST API created first is skipped, not overwritten.
#[tokio::test]
async fn create_skips_a_room_id_taken_elsewhere() {
    let mut h = Harness::new();
    let rx = connect(&mut h.orchestrator, 1);
    h.clients.insert(1, rx);
    let state = h.orchestrator.plane.state.clone();
    state.create_room(1, "rest".into(), 10).unwrap();
    state.add_participant(1, 99).unwrap();
    h.send(1, SignalMessage::Create { room_name: None });
    let created = h.drain(1);
    assert!(matches!(
        created[..],
        [SignalMessage::Created { room_id: 2, .. }]
    ));
    assert_eq!(state.get_room(1).unwrap().name(), "rest");
    assert_eq!(state.participant_count(1), 1);
}

/// Every room counts against `MAX_ROOMS`, named or not and however created. With
/// participant sets that grow on join, 10,000 empty rooms are cheap to hold.
#[tokio::test]
async fn unnamed_rooms_count_against_the_room_cap() {
    let mut h = Harness::new();
    let rx = connect(&mut h.orchestrator, 1);
    h.clients.insert(1, rx);
    let state = h.orchestrator.plane.state.clone();
    for id in 1..=room::MAX_ROOMS as u32 {
        state.create_room(id, String::new(), 10).unwrap();
    }
    h.send(1, SignalMessage::Create { room_name: None });
    assert_eq!(h.errors(1), ["ROOM_LIMIT"]);
    h.send(
        1,
        SignalMessage::Create {
            room_name: Some("named".into()),
        },
    );
    assert_eq!(h.errors(1), ["ROOM_LIMIT"]);
    assert_eq!(state.room_count(), room::MAX_ROOMS);
}

/// 6,000 participants join and leave one room (more than the participant set's
/// tombstones): every leave takes effect and the room stays usable.
#[tokio::test]
async fn join_leave_churn_keeps_the_room_usable() {
    let mut h = Harness::new();
    h.join(1);
    let state = h.orchestrator.plane.state.clone();
    for pid in 2..6_002u64 {
        let rx = connect(&mut h.orchestrator, pid);
        h.clients.insert(pid, rx);
        h.join_room(pid, 1);
        h.send(pid, SignalMessage::Leave);
        h.orchestrator
            .dispatch_event(OrchestratorEvent::Disconnected {
                participant_id: pid,
            });
        h.orchestrator.settle();
        h.clients.remove(&pid);
        h.drain(1);
    }
    assert_eq!(state.participant_count(1), 1, "only participant 1 is left");
    h.join(6_002);
    assert_eq!(state.participant_count(1), 2);
}

/// One step of the signaling fuzzer.
#[derive(Clone, Debug)]
enum Step {
    /// A message from participant 1, 2 or 3.
    Send(u64, SignalMessage),
    /// A well-formed answer to the participant's latest offer.
    AnswerLatest(u64, u32, bool),
    Disconnect(u64),
    Reconnect(u64),
    /// Join the fuzz room (id 1).
    JoinRoom(u64),
    /// A well-formed Publish of these kinds (true: video).
    PublishKinds(u64, Vec<bool>),
    /// Subscribe to up to this many tracks seen in TrackPublished/Joined.
    SubscribeSeen(u64, usize),
}

fn fuzz_string() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{0,8}",
        ".{0,40}",
        (250..300usize).prop_map(|n| "x".repeat(n)),
        Just("audio".to_string()),
        Just("video".to_string()),
    ]
}

fn fuzz_ids() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(prop_oneof![0..12u64, any::<u64>()], 0..14)
}

fn fuzz_message() -> impl Strategy<Value = SignalMessage> {
    prop_oneof![
        prop::option::of(fuzz_string()).prop_map(|room_name| SignalMessage::Create { room_name }),
        (prop_oneof![0..4u64, any::<u64>()], fuzz_string()).prop_map(
            |(room_id, participant_name)| SignalMessage::Join {
                room_id,
                participant_name
            }
        ),
        Just(SignalMessage::Leave),
        (
            prop::collection::vec(fuzz_string(), 0..4),
            prop::collection::vec(fuzz_string(), 0..4)
        )
            .prop_map(|(kinds, contents)| SignalMessage::Publish { kinds, contents }),
        fuzz_ids().prop_map(|track_ids| SignalMessage::Unpublish { track_ids }),
        fuzz_ids().prop_map(|track_ids| SignalMessage::Subscribe { track_ids }),
        fuzz_ids().prop_map(|track_ids| SignalMessage::Unsubscribe { track_ids }),
        fuzz_string().prop_map(|sdp| SignalMessage::Answer { sdp }),
        (
            fuzz_string(),
            prop::option::of(fuzz_string()),
            prop::option::of(any::<u32>())
        )
            .prop_map(|(candidate, sdp_mid, sdp_mline_index)| {
                SignalMessage::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }
            }),
        (0..12u64, fuzz_string())
            .prop_map(|(track_id, content)| SignalMessage::SetContent { track_id, content }),
        (fuzz_ids(), fuzz_ids())
            .prop_map(|(visible, pinned)| SignalMessage::Viewport { visible, pinned }),
        Just(SignalMessage::Ping),
        Just(SignalMessage::EndOfCandidates),
        fuzz_string().prop_map(|sdp| SignalMessage::Offer {
            sdp,
            tracks: Vec::new()
        }),
    ]
}

fn fuzz_step() -> impl Strategy<Value = Step> {
    let pid = 1..=3u64;
    prop_oneof![
        6 => (pid.clone(), fuzz_message()).prop_map(|(p, m)| Step::Send(p, m)),
        3 => (pid.clone(), 1_000..60_000u32, any::<bool>()).prop_map(|(p, s, d)| Step::AnswerLatest(p, s, d)),
        1 => pid.clone().prop_map(Step::Disconnect),
        1 => pid.clone().prop_map(Step::Reconnect),
        3 => pid.clone().prop_map(Step::JoinRoom),
        3 => (pid.clone(), prop::collection::vec(any::<bool>(), 1..3)).prop_map(|(p, k)| Step::PublishKinds(p, k)),
        3 => (pid, 1..12usize).prop_map(|(p, n)| Step::SubscribeSeen(p, n)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Random signaling from three participants, well-formed and not, in any
    /// order, including well-formed answers (declined m-lines, colliding SSRCs):
    /// the orchestrator never panics (exit criterion 6).
    #[test]
    fn random_signaling_never_panics(steps in prop::collection::vec(fuzz_step(), 1..60)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = rt.enter();
        let mut h = Harness::new();
        let mut offers: HashMap<u64, String> = HashMap::new();
        let mut seen: Vec<u64> = Vec::new();
        for pid in 1..=3u64 {
            let rx = connect(&mut h.orchestrator, pid);
            h.clients.insert(pid, rx);
        }
        h.send(1, SignalMessage::Create { room_name: Some("fuzz".into()) });
        for step in steps {
            match step {
                Step::Send(pid, message) => h.send(pid, message),
                Step::AnswerLatest(pid, ssrc_base, decline) => {
                    if let Some(offer) = offers.get(&pid) {
                        let declined: Vec<&str> = if decline { vec!["0"] } else { Vec::new() };
                        let sdp = answer_for(offer, ssrc_base, &declined);
                        h.send(pid, SignalMessage::Answer { sdp });
                    }
                }
                Step::Disconnect(pid) => {
                    h.orchestrator.dispatch_event(OrchestratorEvent::Disconnected { participant_id: pid });
                    h.orchestrator.settle();
                }
                Step::Reconnect(pid) => {
                    let rx = connect(&mut h.orchestrator, pid);
                    h.clients.insert(pid, rx);
                    offers.remove(&pid);
                }
                Step::JoinRoom(pid) => h.send(pid, SignalMessage::Join { room_id: 1, participant_name: format!("p{pid}") }),
                Step::PublishKinds(pid, video) => {
                    let kinds: Vec<&str> = video.iter().map(|&v| if v { "video" } else { "audio" }).collect();
                    h.send(pid, publish_msg(&kinds));
                }
                Step::SubscribeSeen(pid, n) => {
                    let track_ids: Vec<u64> = seen.iter().rev().take(n).copied().collect();
                    h.send(pid, SignalMessage::Subscribe { track_ids });
                }
            }
            for pid in 1..=3u64 {
                for message in h.drain(pid) {
                    match message {
                        SignalMessage::Offer { sdp, .. } => {
                            offers.insert(pid, sdp);
                        }
                        SignalMessage::TrackPublished { track_id, .. } => seen.push(track_id),
                        SignalMessage::Joined { tracks, .. } => {
                            seen.extend(tracks.iter().map(|t| t.track_id));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// The PT of each m-line's first `a=rtpmap`, by mid.
fn mline_pts(sdp: &str) -> Vec<(String, u8)> {
    sdp.split("\r\nm=")
        .skip(1)
        .map(|s| {
            let mid = s.lines().find_map(|l| l.strip_prefix("a=mid:")).unwrap();
            let pt = s
                .lines()
                .find_map(|l| l.strip_prefix("a=rtpmap:"))
                .and_then(|v| v.split(' ').next())
                .and_then(|v| v.parse().ok())
                .unwrap();
            (mid.to_string(), pt)
        })
        .collect()
}

#[tokio::test]
async fn subscribe_mline_keeps_its_pt_when_a_publish_mline_follows() {
    // Found by the browser check: a participant that subscribes before it publishes
    // got its subscribe m-line's PT moved (96 → 97) by the next offer, while the
    // shard kept sending the first answer's 96: Chrome decoded nothing.
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    h.send(2, SignalMessage::Subscribe { track_ids: tracks });
    let (first, _) = h.offer(2);
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&first, 9_000, &[]),
        },
    );
    h.send(2, publish_msg(&["audio", "video"]));
    let (second, _) = h.offer(2);
    let (before, after) = (mline_pts(&first), mline_pts(&second));
    assert_eq!(after.len(), 4);
    assert_eq!(&after[..2], &before[..], "subscribe m-lines keep their PTs");
    assert_eq!(after[0].1, 111, "Opus is 111 on every m-line");
    assert_eq!(after[1].1, 96, "VP8 is 96 on every m-line");
    assert_eq!((after[2].1, after[3].1), (111, 96));
}

#[tokio::test]
async fn declined_slot_gets_a_fresh_ssrc_after_a_later_one_registers() {
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    let (audio, video) = (tracks[0], tracks[1]);

    // Subscriber 2 declines the audio m-line: the audio slot stays off the shard.
    h.send(
        2,
        SignalMessage::Subscribe {
            track_ids: vec![audio],
        },
    );
    let (offer, _) = h.offer(2);
    let first_ssrc = announced_ssrc(&offer, "0").unwrap();
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 9_000, &["0"]),
        },
    );

    // The video slot, allocated later, registers first.
    h.send(
        2,
        SignalMessage::Subscribe {
            track_ids: vec![video],
        },
    );
    let (offer, _) = h.offer(2);
    assert_eq!(
        announced_ssrc(&offer, "0"),
        Some(first_ssrc),
        "not stale yet"
    );
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 9_000, &["0"]),
        },
    );

    // Now the audio slot's SSRC is below the high-water mark: the next offer
    // replaces it, and accepting it is not refused by the shard.
    h.orchestrator.negotiation.request_renegotiation(
        2,
        vec![audio, video],
        &h.orchestrator.sessions,
        &mut h.orchestrator.plane,
    );
    let (offer, _) = h.offer(2);
    let fresh = announced_ssrc(&offer, "0").unwrap();
    assert_ne!(fresh, first_ssrc, "stale SSRC replaced");
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 9_000, &[]),
        },
    );
    let stats = h.stats().await;
    assert_eq!(stats.gauges.subscriptions, 2, "{stats:?}");
}

#[tokio::test]
async fn unpublish_turns_subscriber_mlines_inactive() {
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    h.send(
        2,
        SignalMessage::Subscribe {
            track_ids: tracks.clone(),
        },
    );
    let (offer, offered) = h.offer(2);
    assert_eq!(offered.len(), 2);
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 9_000, &[]),
        },
    );
    assert_eq!(h.stats().await.gauges.subscriptions, 2);

    // Someone else's track: refused.
    h.send(
        2,
        SignalMessage::Unpublish {
            track_ids: vec![tracks[0]],
        },
    );
    assert_eq!(h.errors(2), ["NOT_OWNER"]);

    h.send(
        1,
        SignalMessage::Unpublish {
            track_ids: vec![tracks[0]],
        },
    );
    let (offer, offered) = h.offer(2);
    let dirs = directions(&offer);
    assert_eq!(dirs[0].1, "a=inactive", "{dirs:?}");
    assert_eq!(dirs[1].1, "a=sendonly", "{dirs:?}");
    assert_eq!(offered.len(), 1);
    assert_eq!(h.orchestrator.subscription.track_ids(2), vec![tracks[1]]);
    // RemoveTrack took the subscription with it (no Unsubscribe was sent for it: the
    // shard would have refused it).
    let stats = h.stats().await;
    assert_eq!((stats.gauges.tracks, stats.gauges.subscriptions), (1, 1));
}

#[tokio::test]
async fn publisher_leaving_closes_its_session_and_renegotiates_subscribers() {
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    h.send(2, SignalMessage::Subscribe { track_ids: tracks });
    let (offer, _) = h.offer(2);
    h.send(
        2,
        SignalMessage::Answer {
            sdp: answer_for(&offer, 9_000, &[]),
        },
    );
    assert_eq!(h.stats().await.gauges.sessions, 2);
    h.orchestrator
        .dispatch_event(OrchestratorEvent::Disconnected { participant_id: 1 });
    h.orchestrator.settle();
    let (offer, offered) = h.offer(2);
    assert!(offered.is_empty());
    assert!(directions(&offer).iter().all(|(_, d)| d == "a=inactive"));
    assert!(h.orchestrator.plane.tracks.is_empty());
    let stats = h.stats().await;
    assert_eq!(stats.gauges.sessions, 1, "CloseSession applied");
    assert_eq!((stats.gauges.tracks, stats.gauges.subscriptions), (0, 0));
}

#[tokio::test]
async fn subscribe_over_ten_ids_is_an_error() {
    let mut h = Harness::new();
    h.join(1);
    h.send(
        1,
        SignalMessage::Subscribe {
            track_ids: (1..=11).collect(),
        },
    );
    assert_eq!(h.errors(1), ["TOO_MANY_TRACKS"]);
}

#[tokio::test]
async fn invalid_answer_is_refused_and_the_offer_repeated_once() {
    let mut h = Harness::new();
    h.join(1);
    h.send(1, publish_msg(&["audio"]));
    let (offer, _) = h.offer(1);
    let wrong = |offer: &str| answer_for(offer, 5_000, &[]).replace("a=mid:0", "a=mid:7");

    // Nothing else queued: the unanswered publish m-line is offered again.
    h.send(1, SignalMessage::Answer { sdp: wrong(&offer) });
    let messages = h.drain(1);
    assert_eq!(error_codes(messages.clone()), ["INVALID_ANSWER"]);
    let again = messages.into_iter().find_map(|m| match m {
        SignalMessage::Offer { sdp, .. } => Some(sdp),
        _ => None,
    });
    let again = again.expect("the client is offered the m-line again");
    assert_eq!(
        directions(&again),
        [("0".to_string(), "a=recvonly".to_string())]
    );
    assert!(h.orchestrator.negotiation.states[&1].offer_pending);

    // A second wrong answer releases the m-line instead of looping.
    h.send(1, SignalMessage::Answer { sdp: wrong(&again) });
    assert_eq!(h.errors(1), ["INVALID_ANSWER"]);
    let state = &h.orchestrator.negotiation.states[&1];
    assert!(!state.offer_pending);
    assert!(state.unregistered_publish_mids.is_empty());
    assert_eq!(state.mlines[0].role, negotiation::MlineRole::Inactive);
    assert!(h.orchestrator.plane.tracks.is_empty());

    // The client can publish again; the released m-line is reused.
    let tracks = publish_kinds(&mut h, 1, &["audio"], 5_000);
    assert_eq!(h.orchestrator.negotiation.states[&1].mlines.len(), 1);
    assert_eq!(tracks.len(), 1);
}

#[tokio::test]
async fn second_join_is_refused_and_leaves_no_ghost() {
    let mut h = Harness::new();
    h.join(1);
    h.join(2);
    let tracks = publish(&mut h, 1, 5_000).await;
    h.send(
        2,
        SignalMessage::Subscribe {
            track_ids: tracks.clone(),
        },
    );
    let rx = connect(&mut h.orchestrator, 5);
    h.clients.insert(5, rx);
    h.send(
        5,
        SignalMessage::Create {
            room_name: Some("other".into()),
        },
    );
    h.join_room(5, 2);

    h.send(
        2,
        SignalMessage::Join {
            room_id: 2,
            participant_name: "p2".into(),
        },
    );
    assert_eq!(h.errors(2), ["ALREADY_IN_ROOM"]);
    let state = &h.orchestrator.plane.state;
    assert_eq!(
        state.get_participants(2),
        vec![5],
        "no ghost member in room 2"
    );
    assert!(state.get_participants(1).contains(&2), "still in room 1");
    assert_eq!(h.orchestrator.sessions[&2].room_id, Some(1));
    // Its subscriptions are room 1's, as before; room 2 sees none of them.
    assert_eq!(h.orchestrator.subscription.track_ids(2), tracks);
}

#[tokio::test]
async fn consent_lost_and_shard_refusals_close_the_participant() {
    let mut h = Harness::new();
    for p in 1..=4 {
        h.join(p);
    }
    publish(&mut h, 1, 5_000).await;
    let id = h.orchestrator.negotiation.session(1).unwrap();
    connection::handle_event(Event::ConsentLost { id }, &mut h.orchestrator.plane);
    h.orchestrator.settle();
    assert_eq!(h.errors(1), ["CONSENT_EXPIRED"]);
    assert!(!h.orchestrator.sessions.contains_key(&1));
    assert!(h.orchestrator.plane.transports.session_of(1).is_none());

    // An orchestrator bug reported by the shard, and a shard limit, after the tracks
    // were registered: the close undoes the registry, the cluster state and tells the
    // room (participant 4 watches).
    for (participant, reason, code) in [
        (2, RejectReason::OutSsrcNotMonotonic, "INTERNAL_ERROR"),
        (3, RejectReason::TrackLimit, "OVERLOADED"),
    ] {
        let tracks = publish(&mut h, participant, participant as u32 * 1_000).await;
        h.drain(participant);
        h.drain(4);
        let id = h.orchestrator.negotiation.session(participant).unwrap();
        let rejected = Event::CommandRejected {
            id: Some(id),
            reason,
        };
        connection::handle_event(rejected, &mut h.orchestrator.plane);
        h.orchestrator.settle();
        assert_eq!(h.errors(participant), [code]);
        assert!(!h.orchestrator.sessions.contains_key(&participant));
        let unpublished: Vec<u64> = h
            .drain(4)
            .into_iter()
            .filter_map(|m| match m {
                SignalMessage::TrackUnpublished { track_id } => Some(track_id),
                _ => None,
            })
            .collect();
        assert_eq!(unpublished, tracks, "the room is told");
        for &t in &tracks {
            assert!(h.orchestrator.plane.tracks.get(DpTrackId::new(t)).is_none());
            assert!(h.orchestrator.plane.state.get_track(t).is_none());
        }
    }
    // Every session was closed on the shard too, with its tracks.
    let stats = h.stats().await;
    assert_eq!((stats.gauges.sessions, stats.gauges.tracks), (0, 0));
}

/// A command sink with a switchable full queue, recording what it accepts.
#[derive(Default)]
struct FakeSink {
    full: AtomicBool,
    accepted: Mutex<Vec<Command>>,
}

impl CommandSink for FakeSink {
    fn send(&self, _shard: ShardId, command: Command) -> Result<(), CommandQueueFull> {
        if self.full.load(Ordering::SeqCst) {
            return Err(CommandQueueFull);
        }
        self.accepted.lock().push(command);
        Ok(())
    }

    fn loads(&self) -> Vec<ShardLoad> {
        vec![ShardLoad::default()]
    }

    fn shard_count(&self) -> usize {
        1
    }
}

#[tokio::test]
async fn full_command_queue_closes_the_participant_and_retries_the_close() {
    let sink = Arc::new(FakeSink::default());
    let media = "127.0.0.1:10000".parse().unwrap();
    let mut o = orchestrator_on(Arc::clone(&sink) as Arc<dyn CommandSink>, media);
    let mut rx1 = connect(&mut o, 1);
    let mut rx2 = connect(&mut o, 2);
    send(&mut o, 1, SignalMessage::Create { room_name: None });
    for p in [1, 2] {
        let join = SignalMessage::Join {
            room_id: 1,
            participant_name: format!("p{p}"),
        };
        send(&mut o, p, join);
    }
    send(&mut o, 1, publish_msg(&["audio"]));
    let session = o.negotiation.session(1).expect("session created");

    // A command that does not fit fails the operation and closes the participant.
    sink.full.store(true, Ordering::SeqCst);
    send(&mut o, 2, publish_msg(&["audio"]));
    assert!(error_codes(drain(&mut rx2)).contains(&"OVERLOADED".to_string()));
    assert!(!o.sessions.contains_key(&2));
    assert!(o.plane.transports.session_of(2).is_none());

    // Closing needs the queue too: the CloseSession waits for the sweep.
    o.dispatch_event(OrchestratorEvent::Disconnected { participant_id: 1 });
    o.settle();
    drain(&mut rx1);
    assert!(o.plane.transports.is_empty());
    assert_eq!(o.plane.pending_closes(), 1);
    connection::sweep(&mut o.plane, std::time::Instant::now());
    assert_eq!(o.plane.pending_closes(), 1, "queue still full");

    // Room in the queue: the next sweep sends it.
    sink.full.store(false, Ordering::SeqCst);
    connection::sweep(&mut o.plane, std::time::Instant::now());
    assert_eq!(o.plane.pending_closes(), 0);
    let accepted = sink.accepted.lock();
    assert!(matches!(accepted.last(), Some(Command::CloseSession { id }) if *id == session));
}
