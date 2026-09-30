//! Plan 2.4 on a recording sink with several shards (no data plane): placement, the
//! per-(track, shard) subscription counts and the `AddRemoteShard` /
//! `RemoveRemoteShard` / `RemoveTrack` they send, cleanup retries on full queues and
//! the per-shard order. Clients answer every offer at once (`World::pump`).

use std::collections::{HashSet, VecDeque};

use nexus_dataplane::{RoomAffine, RoomAffineLimits, TrackId as DpTrackId};

use super::*;

/// Places each new session on the next scripted shard.
struct Scripted(Arc<Mutex<VecDeque<u8>>>);

impl Placement for Scripted {
    fn place(&mut self, _room: Option<u32>, loads: &[ShardLoad]) -> ShardId {
        let shard = self.0.lock().pop_front().expect("a scripted shard");
        assert!(usize::from(shard) < loads.len());
        ShardId::new(shard)
    }

    fn session_closed(&mut self, _room: Option<u32>, _shard: ShardId) {}
}

/// `RoomAffine`, readable by the test.
struct Shared(Arc<Mutex<RoomAffine>>);

impl Placement for Shared {
    fn place(&mut self, room: Option<u32>, loads: &[ShardLoad]) -> ShardId {
        self.0.lock().place(room, loads)
    }

    fn session_closed(&mut self, room: Option<u32>, shard: ShardId) {
        self.0.lock().session_closed(room, shard)
    }
}

/// Participant that creates room 1 and never gets a session.
const HOST: u64 = 1_000;

/// An orchestrator on a `FakeSink`, with clients that answer every offer.
struct World {
    o: SessionOrchestrator,
    sink: Arc<FakeSink>,
    script: Arc<Mutex<VecDeque<u8>>>,
    rx: HashMap<u64, mpsc::Receiver<SignalMessage>>,
    /// Non-offer messages per participant since the last `errors`.
    inbox: HashMap<u64, Vec<SignalMessage>>,
    /// Every recorded command, in order (`take` moves the sink's into it).
    history: Vec<(ShardId, Rec)>,
    answers: u32,
    /// Offers left unanswered by `send_holding`.
    held: HashMap<u64, String>,
}

impl World {
    /// `shards` shards, sessions placed by `script` (`on`).
    fn scripted(shards: usize) -> Self {
        let script = Arc::new(Mutex::new(VecDeque::new()));
        Self::with(shards, Box::new(Scripted(Arc::clone(&script))), script)
    }

    /// `shards` shards and `placement`.
    fn with(
        shards: usize,
        placement: Box<dyn Placement>,
        script: Arc<Mutex<VecDeque<u8>>>,
    ) -> Self {
        let sink = Arc::new(FakeSink::new(shards));
        let o = orchestrator_with(&sink, placement);
        let mut w = Self {
            o,
            sink,
            script,
            rx: HashMap::new(),
            inbox: HashMap::new(),
            history: Vec::new(),
            answers: 0,
            held: HashMap::new(),
        };
        let rx = connect(&mut w.o, HOST);
        w.rx.insert(HOST, rx);
        w.send(HOST, SignalMessage::Create { room_name: None });
        w.join(HOST);
        w
    }

    /// The next sessions go to `shards`, in order.
    fn on(&self, shards: &[u8]) {
        self.script.lock().extend(shards);
    }

    fn send(&mut self, participant: u64, message: SignalMessage) {
        send(&mut self.o, participant, message);
    }

    /// Connect `participant` (if needed) and join room 1.
    fn join(&mut self, participant: u64) {
        if !self.o.sessions.contains_key(&participant) {
            let rx = connect(&mut self.o, participant);
            self.rx.insert(participant, rx);
        }
        let join = SignalMessage::Join {
            room_id: 1,
            participant_name: format!("p{participant}"),
        };
        self.send(participant, join);
        self.pump();
    }

    /// Deliver every client's messages; answer each offer (a new offer may follow
    /// an answer, so a few rounds).
    fn pump(&mut self) {
        for _ in 0..8 {
            let mut offers = Vec::new();
            for (&p, rx) in self.rx.iter_mut() {
                for message in drain(rx) {
                    match message {
                        SignalMessage::Offer { sdp, .. } => offers.push((p, sdp)),
                        other => self.inbox.entry(p).or_default().push(other),
                    }
                }
            }
            if offers.is_empty() {
                return;
            }
            offers.sort_by_key(|(p, _)| *p);
            for (p, offer) in offers {
                self.answers += 1;
                let base = (p as u32) * 100_000 + self.answers * 16;
                let sdp = answer_for(&offer, base, &[]);
                self.send(p, SignalMessage::Answer { sdp });
            }
        }
        panic!("offers did not settle");
    }

    /// Send `message` and keep the offer it causes unanswered (`answer_held`).
    fn send_holding(&mut self, participant: u64, message: SignalMessage) {
        self.send(participant, message);
        let rx = self.rx.get_mut(&participant).expect("connected");
        for message in drain(rx) {
            match message {
                SignalMessage::Offer { sdp, .. } => {
                    self.held.insert(participant, sdp);
                }
                other => self.inbox.entry(participant).or_default().push(other),
            }
        }
        assert!(self.held.contains_key(&participant), "an offer");
    }

    /// Answer `participant`'s held offer without settling: the closes it causes wait
    /// for the next `settle`.
    fn answer_held(&mut self, participant: u64) {
        let offer = self.held.remove(&participant).expect("a held offer");
        self.answers += 1;
        let base = (participant as u32) * 100_000 + self.answers * 16;
        let sdp = answer_for(&offer, base, &[]);
        self.o.dispatch_event(OrchestratorEvent::Message {
            participant_id: participant,
            message: SignalMessage::Answer { sdp },
        });
    }

    /// Error codes sent to `participant` since the last call.
    fn errors(&mut self, participant: u64) -> Vec<String> {
        self.pump();
        error_codes(self.inbox.remove(&participant).unwrap_or_default())
    }

    /// Publish `kinds` and answer; the new track ids.
    fn publish(&mut self, participant: u64, kinds: &[&str]) -> Vec<DpTrackId> {
        let before = self.published(participant);
        self.send(participant, publish_msg(kinds));
        self.pump();
        let after = self.published(participant);
        after.into_iter().filter(|t| !before.contains(t)).collect()
    }

    fn published(&self, participant: u64) -> Vec<DpTrackId> {
        self.o
            .negotiation
            .states
            .get(&participant)
            .map(|s| {
                s.published_tracks
                    .iter()
                    .map(|&t| DpTrackId::new(t))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn subscribe(&mut self, participant: u64, tracks: &[DpTrackId]) {
        let track_ids = tracks.iter().map(|t| t.get()).collect();
        self.send(participant, SignalMessage::Subscribe { track_ids });
        self.pump();
    }

    fn unsubscribe(&mut self, participant: u64, tracks: &[DpTrackId]) {
        let track_ids = tracks.iter().map(|t| t.get()).collect();
        self.send(participant, SignalMessage::Unsubscribe { track_ids });
        self.pump();
    }

    fn unpublish(&mut self, participant: u64, tracks: &[DpTrackId]) {
        let track_ids = tracks.iter().map(|t| t.get()).collect();
        self.send(participant, SignalMessage::Unpublish { track_ids });
        self.pump();
    }

    fn leave(&mut self, participant: u64) {
        self.send(participant, SignalMessage::Leave);
        self.pump();
    }

    fn sweep(&mut self) {
        connection::sweep(&mut self.o.plane, std::time::Instant::now());
        self.o.settle();
        self.pump();
    }

    fn session(&self, participant: u64) -> SessionId {
        self.o.negotiation.session(participant).expect("a session")
    }

    fn shard_of(&self, participant: u64) -> ShardId {
        let id = self.session(participant);
        self.o.plane.transports.get(id).expect("a transport").shard
    }

    /// The commands recorded since the last call, without DTLS and SRTP.
    fn take(&mut self) -> Vec<(ShardId, Rec)> {
        let new = self.sink.take();
        self.history.extend(new.iter().copied());
        new.into_iter().filter(|(_, r)| *r != Rec::Other).collect()
    }

    /// The subscription id of `participant`'s m-line for `track`.
    fn sub_of(&self, participant: u64, track: DpTrackId) -> SubscriptionId {
        self.o.negotiation.states[&participant]
            .mlines
            .iter()
            .find_map(|m| match m.role {
                negotiation::MlineRole::Subscribe(s) if s.track == track.get() => Some(s.sub),
                _ => None,
            })
            .expect("a subscribe m-line")
    }
}

fn shard(i: u8) -> ShardId {
    ShardId::new(i)
}

/// The recorded commands of one kind, in order.
fn only(recs: &[(ShardId, Rec)], keep: fn(&Rec) -> bool) -> Vec<(ShardId, Rec)> {
    recs.iter().copied().filter(|(_, r)| keep(r)).collect()
}

fn is_remote(r: &Rec) -> bool {
    matches!(r, Rec::AddRemote(..) | Rec::RemoveRemote(..))
}

#[tokio::test]
async fn cross_shard_subscribe_announces_the_shard_once() {
    let mut w = World::scripted(3);
    for p in 1..=4 {
        w.join(p);
    }
    w.on(&[0]);
    let tracks = w.publish(1, &["audio", "video"]);
    assert_eq!(tracks.len(), 2);
    w.take();

    // First subscriber on shard 1: Subscribe there with the source on shard 0, and one
    // AddRemoteShard per track to shard 0.
    w.on(&[1]);
    w.subscribe(2, &tracks);
    let recs = w.take();
    let subscribes = only(&recs, |r| matches!(r, Rec::Subscribe { .. }));
    assert_eq!(subscribes.len(), 2, "{recs:?}");
    for (s, r) in &subscribes {
        assert_eq!(*s, shard(1));
        assert!(matches!(r, Rec::Subscribe { source, .. } if *source == shard(0)));
    }
    let mut adds = only(&recs, is_remote);
    adds.sort_by_key(|(_, r)| format!("{r:?}"));
    let mut expected: Vec<_> = tracks
        .iter()
        .map(|&t| (shard(0), Rec::AddRemote(t, shard(1))))
        .collect();
    expected.sort_by_key(|(_, r)| format!("{r:?}"));
    assert_eq!(adds, expected);

    // A second subscriber on shard 1: no second announcement. One on shard 0: none.
    w.on(&[1]);
    w.subscribe(3, &tracks[..1]);
    w.on(&[0]);
    w.subscribe(4, &tracks[..1]);
    let recs = w.take();
    assert_eq!(only(&recs, |r| matches!(r, Rec::Subscribe { .. })).len(), 2);
    assert!(only(&recs, is_remote).is_empty(), "{recs:?}");
    assert_eq!(
        w.o.plane
            .tracks
            .get(tracks[0])
            .unwrap()
            .subscribers_on(shard(1)),
        2
    );

    // Both leave shard 1: one RemoveRemoteShard, after the last.
    let (sub2, sub3) = (w.sub_of(2, tracks[0]), w.sub_of(3, tracks[0]));
    w.unsubscribe(2, &tracks[..1]);
    assert_eq!(w.take(), [(shard(1), Rec::Unsubscribe(sub2))]);
    w.unsubscribe(3, &tracks[..1]);
    assert_eq!(
        w.take(),
        [
            (shard(1), Rec::Unsubscribe(sub3)),
            (shard(0), Rec::RemoveRemote(tracks[0], shard(1))),
        ]
    );
    // The subscriber on the track's own shard: nothing but its Unsubscribe.
    let sub4 = w.sub_of(4, tracks[0]);
    w.unsubscribe(4, &tracks[..1]);
    assert_eq!(w.take(), [(shard(0), Rec::Unsubscribe(sub4))]);
    let info = w.o.plane.tracks.get(tracks[0]).unwrap();
    assert_eq!(info.subscribers, [0; super::tracks::TRACK_SHARDS]);
    assert_eq!(info.announced, 0);
    assert_eq!(w.o.plane.tracks.get(tracks[1]).unwrap().announced, 1 << 1);
}

#[tokio::test]
async fn unpublish_and_publisher_leave_remove_the_track_everywhere() {
    let mut w = World::scripted(3);
    for p in 1..=4 {
        w.join(p);
    }
    w.on(&[0]);
    let tracks = w.publish(1, &["audio", "video"]);
    w.on(&[1, 2, 0]);
    w.subscribe(2, &tracks);
    w.subscribe(3, &tracks[..1]);
    w.subscribe(4, &tracks[..1]);
    w.take();

    // Unpublish: RemoveTrack to the track's shard and to each subscribed shard, and
    // nothing else (RemoveTrack takes the subscriptions and mirrors with it).
    w.unpublish(1, &tracks[..1]);
    let mut recs = w.take();
    recs.sort_by_key(|(s, _)| *s);
    let expected: Vec<_> = (0..3)
        .map(|i| (shard(i), Rec::RemoveTrack(tracks[0])))
        .collect();
    assert_eq!(recs, expected);
    assert!(w.o.plane.tracks.get(tracks[0]).is_none());

    // The publisher leaves: its CloseSession removes the other track on shard 0, and a
    // RemoveTrack goes to shard 1 only (the one subscribed shard besides its own).
    let session = w.session(1);
    w.leave(1);
    let mut recs = w.take();
    recs.sort_by_key(|(s, _)| *s);
    assert_eq!(
        recs,
        [
            (shard(0), Rec::Close(session)),
            (shard(1), Rec::RemoveTrack(tracks[1])),
        ]
    );
    assert!(w.o.plane.tracks.is_empty());
    assert_eq!(w.o.plane.pending_cleanup(), 0);
}

#[tokio::test]
async fn subscriber_leave_removes_the_remote_shard() {
    let mut w = World::scripted(2);
    for p in 1..=3 {
        w.join(p);
    }
    w.on(&[0, 1, 1]);
    let tracks = w.publish(1, &["video"]);
    w.subscribe(2, &tracks);
    w.subscribe(3, &tracks);
    w.take();

    // Not the last on shard 1: its CloseSession only (no Unsubscribe needed).
    let session2 = w.session(2);
    w.leave(2);
    assert_eq!(w.take(), [(shard(1), Rec::Close(session2))]);
    // The last: RemoveRemoteShard as well, also on a disconnect.
    let session3 = w.session(3);
    w.o.dispatch_event(OrchestratorEvent::Disconnected { participant_id: 3 });
    w.o.settle();
    let mut recs = w.take();
    recs.sort_by_key(|(s, _)| *s);
    assert_eq!(
        recs,
        [
            (shard(0), Rec::RemoveRemote(tracks[0], shard(1))),
            (shard(1), Rec::Close(session3)),
        ]
    );
    assert_eq!(w.o.plane.tracks.get(tracks[0]).unwrap().announced, 0);
}

#[tokio::test]
async fn a_full_queue_delays_cleanup_and_closes_on_additive_commands() {
    let mut w = World::scripted(2);
    for p in 1..=3 {
        w.join(p);
    }
    w.on(&[0, 1]);
    let tracks = w.publish(1, &["video"]);
    w.subscribe(2, &tracks);
    w.take();

    // Shard 0 full: the RemoveRemoteShard waits; nobody is closed.
    w.sink.set_full(0, true);
    let sub = w.sub_of(2, tracks[0]);
    w.unsubscribe(2, &tracks);
    assert_eq!(w.take(), [(shard(1), Rec::Unsubscribe(sub))]);
    assert_eq!(w.o.plane.pending_cleanup(), 1);
    assert!(w.o.sessions.contains_key(&1) && w.o.sessions.contains_key(&2));
    assert!(w.errors(1).is_empty() && w.errors(2).is_empty());
    w.sweep();
    assert_eq!(w.o.plane.pending_cleanup(), 1, "still full");

    // An additive command for shard 0 still closes its participant.
    w.on(&[0]);
    w.send(3, publish_msg(&["audio"]));
    assert_eq!(w.errors(3), ["SESSION_FAILED", "OVERLOADED"]);
    assert!(!w.o.sessions.contains_key(&3));

    // Room again: the next cleanup for shard 0 goes out behind the waiting one.
    w.sink.set_full(0, false);
    let session1 = w.session(1);
    w.leave(1);
    assert_eq!(w.o.plane.pending_cleanup(), 0);
    assert_eq!(
        w.take(),
        [
            (shard(0), Rec::RemoveRemote(tracks[0], shard(1))),
            (shard(0), Rec::Close(session1)),
        ]
    );
}

#[tokio::test]
async fn a_pending_remove_is_cancelled_by_a_new_subscriber() {
    let mut w = World::scripted(2);
    for p in 1..=3 {
        w.join(p);
    }
    w.on(&[0, 1]);
    let tracks = w.publish(1, &["video"]);
    w.subscribe(2, &tracks);
    w.take();

    w.sink.set_full(0, true);
    w.unsubscribe(2, &tracks);
    assert_eq!(w.o.plane.pending_cleanup(), 1, "RemoveRemoteShard waits");
    // A new subscriber on shard 1 before the sweep: the waiting remove is dropped and
    // no AddRemoteShard is sent (shard 0 never lost the bit).
    w.on(&[1]);
    w.subscribe(3, &tracks);
    assert_eq!(w.o.plane.pending_cleanup(), 0);
    w.sink.set_full(0, false);
    w.sweep();
    let recs = w.take();
    assert!(only(&recs, is_remote).is_empty(), "{recs:?}");
    assert!(recs.iter().all(|(s, _)| *s == shard(1)));
    assert_eq!(w.o.plane.tracks.get(tracks[0]).unwrap().announced, 1 << 1);
}

#[tokio::test]
async fn queued_cleanup_goes_before_a_new_command() {
    let mut w = World::scripted(2);
    for p in 1..=3 {
        w.join(p);
    }
    w.on(&[0, 1]);
    let tracks = w.publish(1, &["audio", "video"]);
    w.subscribe(2, &tracks[..1]);
    w.take();

    // An Unsubscribe waits for shard 1; the next command to shard 1 (participant 3's
    // CreateSession) goes out after it.
    w.sink.set_full(1, true);
    let sub2 = w.sub_of(2, tracks[0]);
    w.unsubscribe(2, &tracks[..1]);
    assert_eq!(w.o.plane.pending_cleanup(), 1);
    w.sink.set_full(1, false);
    w.on(&[1]);
    w.subscribe(3, &tracks[..1]);
    let recs = w.take();
    let on_1: Vec<_> = recs
        .iter()
        .copied()
        .filter(|(s, _)| *s == shard(1))
        .collect();
    assert_eq!(on_1[0], (shard(1), Rec::Unsubscribe(sub2)), "{recs:?}");
    assert!(matches!(on_1[1], (_, Rec::Create(_))));
    assert_eq!(w.o.plane.pending_cleanup(), 0);

    // Shard 1 full with cleanup waiting: an additive command is not sent ahead of it
    // but closes its participant, whose CloseSession queues behind.
    w.sink.set_full(1, true);
    let sub3 = w.sub_of(3, tracks[0]);
    w.unsubscribe(3, &tracks[..1]);
    w.sink.set_room(1, Some(0));
    let session2 = w.session(2);
    w.subscribe(2, &tracks[1..]);
    assert_eq!(w.errors(2), ["OVERLOADED"]);
    assert_eq!(w.o.plane.pending_cleanup(), 2);
    w.sink.set_full(1, false);
    w.sweep();
    let recs: Vec<_> = w
        .take()
        .into_iter()
        .filter(|(s, _)| *s == shard(1))
        .collect();
    assert_eq!(
        recs,
        [
            (shard(1), Rec::Unsubscribe(sub3)),
            (shard(1), Rec::Close(session2)),
        ]
    );

    // Room for one while two wait: the first goes, the second still blocks the
    // CreateSession, which closes its participant.
    w.subscribe(3, &tracks);
    let subs: Vec<_> = tracks.iter().map(|&t| w.sub_of(3, t)).collect();
    w.sink.set_full(1, true);
    w.unsubscribe(3, &tracks);
    assert_eq!(w.o.plane.pending_cleanup(), 2);
    w.take();
    w.sink.set_room(1, Some(1));
    w.join(4);
    w.on(&[1]);
    w.send(4, publish_msg(&["audio"]));
    assert_eq!(w.errors(4), ["SESSION_FAILED", "OVERLOADED"]);
    assert_eq!(w.take(), [(shard(1), Rec::Unsubscribe(subs[0]))]);
    assert_eq!(w.o.plane.pending_cleanup(), 1);
    w.sink.set_room(1, None);
    w.sweep();
    assert_eq!(w.take(), [(shard(1), Rec::Unsubscribe(subs[1]))]);
}

#[tokio::test]
async fn a_late_rejection_for_a_removed_object_closes_no_one() {
    let mut w = World::scripted(2);
    for p in 1..=2 {
        w.join(p);
    }
    w.on(&[0, 1]);
    let tracks = w.publish(1, &["video"]);
    w.subscribe(2, &tracks);
    let (s1, s2) = (w.session(1), w.session(2));
    for (id, reason) in [
        (Some(s2), RejectReason::UnknownSubscription),
        (None, RejectReason::UnknownSubscription),
        (Some(s1), RejectReason::UnknownTrack),
        (None, RejectReason::UnknownTrack),
    ] {
        w.o.handle_dataplane(Event::CommandRejected { id, reason });
    }
    assert!(w.o.sessions.contains_key(&1) && w.o.sessions.contains_key(&2));
    assert!(w.errors(1).is_empty() && w.errors(2).is_empty());
}

#[tokio::test]
async fn a_failed_announcement_is_retried_by_the_next_subscriber() {
    let mut w = World::scripted(2);
    for p in 1..=3 {
        w.join(p);
    }
    w.on(&[0, 1, 1]);
    let tracks = w.publish(1, &["video"]);
    w.send_holding(
        2,
        SignalMessage::Subscribe {
            track_ids: vec![tracks[0].get()],
        },
    );
    w.send_holding(
        3,
        SignalMessage::Subscribe {
            track_ids: vec![tracks[0].get()],
        },
    );
    w.take();

    // Participant 2's AddRemoteShard does not fit: it is to be closed, but not before
    // participant 3's answer is handled in the same step.
    w.sink.set_full(0, true);
    w.answer_held(2);
    w.sink.set_full(0, false);
    w.answer_held(3);
    assert!(
        w.o.sessions.contains_key(&2),
        "the close waits for the settle"
    );
    // Not the first on shard 1, but the shard is not announced: 3 announces it.
    assert_eq!(
        only(&w.take(), is_remote),
        [(shard(0), Rec::AddRemote(tracks[0], shard(1)))]
    );
    w.o.settle();
    w.pump();
    assert!(!w.o.sessions.contains_key(&2));
    assert!(only(&w.take(), is_remote).is_empty(), "3 still subscribes");
    let info = w.o.plane.tracks.get(tracks[0]).unwrap();
    assert_eq!((info.subscribers_on(shard(1)), info.announced), (1, 1 << 1));
    w.unsubscribe(3, &tracks);
    assert_eq!(
        only(&w.take(), is_remote),
        [(shard(0), Rec::RemoveRemote(tracks[0], shard(1)))]
    );
}

#[tokio::test]
async fn a_rejected_subscribe_removes_the_remote_shard_only_if_announced() {
    let mut w = World::scripted(2);
    for p in 1..=4 {
        w.join(p);
    }
    w.on(&[0, 1, 0]);
    let tracks = w.publish(1, &["video"]);
    w.subscribe(2, &tracks);
    w.subscribe(3, &tracks);
    w.take();
    let reject = |w: &mut World, p: u64| {
        let id = w.session(p);
        let reason = RejectReason::SubscriptionLimit;
        connection::handle_event(
            Event::CommandRejected {
                id: Some(id),
                reason,
            },
            &mut w.o.plane,
        );
        id
    };

    // Announced shard 1: the closed subscriber was its last, so the shard is removed.
    let s2 = reject(&mut w, 2);
    w.o.settle();
    assert_eq!(w.errors(2), ["OVERLOADED"]);
    let mut recs = w.take();
    recs.sort_by_key(|(s, _)| *s);
    assert_eq!(
        recs,
        [
            (shard(0), Rec::RemoveRemote(tracks[0], shard(1))),
            (shard(1), Rec::Close(s2)),
        ]
    );
    // On the track's own shard: nothing to remove.
    let s3 = reject(&mut w, 3);
    w.o.settle();
    assert_eq!(w.take(), [(shard(0), Rec::Close(s3))]);

    // Shard 1 again, but its AddRemoteShard did not fit and the subscriber is also
    // rejected before it is closed: no RemoveRemoteShard for an unannounced shard.
    w.on(&[1]);
    w.send_holding(
        4,
        SignalMessage::Subscribe {
            track_ids: vec![tracks[0].get()],
        },
    );
    w.take();
    w.sink.set_full(0, true);
    w.answer_held(4);
    let s4 = reject(&mut w, 4);
    w.o.settle();
    let recs = w.take();
    assert!(matches!(recs[0], (_, Rec::Subscribe { id, .. }) if id == s4));
    assert_eq!(recs[1..], [(shard(1), Rec::Close(s4))]);
    assert_eq!(w.o.plane.pending_cleanup(), 0);
    let info = w.o.plane.tracks.get(tracks[0]).unwrap();
    assert_eq!((info.subscribers_on(shard(1)), info.announced), (0, 0));
}

#[tokio::test]
async fn close_session_has_its_own_cleanup_budget() {
    let mut w = World::scripted(2);
    for p in 1..=2 {
        w.join(p);
    }
    w.on(&[0, 1]);
    let tracks = w.publish(1, &["audio", "video"]);
    w.subscribe(2, &tracks);
    w.take();
    w.o.plane.set_cleanup_budget(super::plane::CleanupBudget {
        closes: 1,
        other: 1,
    });
    w.sink.set_full(0, true);
    w.sink.set_full(1, true);

    // The Unsubscribe takes the one slot for other cleanup; the RemoveRemoteShard
    // after it is dropped (logged).
    let sub = w.sub_of(2, tracks[0]);
    w.unsubscribe(2, &tracks[..1]);
    assert_eq!(w.o.plane.pending_cleanup(), 1);
    // The CloseSession still waits, in its own budget.
    let s2 = w.session(2);
    w.leave(2);
    assert_eq!(w.o.plane.pending_cleanup(), 2);

    w.sink.set_full(0, false);
    w.sink.set_full(1, false);
    w.sweep();
    assert_eq!(
        w.take(),
        [
            (shard(1), Rec::Unsubscribe(sub)),
            (shard(1), Rec::Close(s2))
        ]
    );
    assert_eq!(w.o.plane.pending_cleanup(), 0);
}

fn room_affine(shards: u16, room_cap: u32) -> Arc<Mutex<RoomAffine>> {
    Arc::new(Mutex::new(RoomAffine::new(RoomAffineLimits {
        shards,
        max_sessions: 100,
        room_shard_max_sessions: room_cap,
        room_shard_max_pps: 0,
    })))
}

#[tokio::test]
async fn a_failed_create_session_releases_its_placement() {
    let affine = room_affine(3, 50);
    let script = Arc::new(Mutex::new(VecDeque::new()));
    let mut w = World::with(3, Box::new(Shared(Arc::clone(&affine))), script);
    w.join(1);
    w.join(2);
    w.sink.set_full(0, true);
    w.send(1, publish_msg(&["audio"]));
    assert_eq!(w.errors(1), ["SESSION_FAILED", "OVERLOADED"]);
    assert_eq!(affine.lock().placed(shard(0)), 0, "released");
    assert_eq!(affine.lock().rooms_tracked(), 0);

    w.sink.set_full(0, false);
    w.publish(2, &["audio"]);
    assert_eq!(w.shard_of(2), shard(0));
    assert_eq!(affine.lock().placed(shard(0)), 1);
    w.leave(2);
    assert_eq!(affine.lock().placed(shard(0)), 0);
    assert_eq!(affine.lock().rooms_tracked(), 0);
}

#[tokio::test]
async fn room_affine_spreads_a_room_through_the_orchestrator() {
    let affine = room_affine(3, 2);
    let script = Arc::new(Mutex::new(VecDeque::new()));
    let mut w = World::with(3, Box::new(Shared(Arc::clone(&affine))), script);
    let mut shards = Vec::new();
    for p in 1..=7 {
        w.join(p);
        w.publish(p, &["audio"]);
        shards.push(w.shard_of(p).index());
    }
    assert_eq!(shards, [0, 0, 1, 1, 2, 2, 0]);
    for p in 1..=7 {
        w.leave(p);
    }
    let affine = affine.lock();
    assert!((0..3).all(|i| affine.placed(shard(i)) == 0));
    assert_eq!(affine.rooms_tracked(), 0);
}

// ── Randomised: balanced streams, shards agree with the counts ────────────────────

/// A shard as the recorded commands leave it (commands on one shard apply in order).
#[derive(Default, Debug)]
struct ShardModel {
    sessions: HashSet<SessionId>,
    /// Local tracks: session and `remote_shards` bits.
    tracks: HashMap<DpTrackId, (SessionId, u32)>,
    /// Subscriptions: session and track (a track of another shard = a mirror).
    subs: HashMap<SubscriptionId, (SessionId, DpTrackId)>,
}

impl ShardModel {
    /// Apply one command. Additive commands must be ones the shard accepts (the
    /// orchestrator never sends one ahead of what it depends on); cleanup of what is
    /// already gone is a no-op, as on the shard.
    fn apply(&mut self, at: ShardId, rec: Rec) {
        match rec {
            Rec::Create(id) => assert!(self.sessions.insert(id), "{id:?} twice"),
            Rec::AddTrack(id, t) => {
                assert!(self.sessions.contains(&id), "AddTrack without session");
                assert!(self.tracks.insert(t, (id, 0)).is_none());
            }
            Rec::Subscribe {
                id,
                sub,
                track,
                source,
            } => {
                assert!(self.sessions.contains(&id), "Subscribe without session");
                assert!(
                    source != at || self.tracks.contains_key(&track),
                    "local track"
                );
                assert!(self.subs.insert(sub, (id, track)).is_none());
            }
            Rec::Unsubscribe(sub) => {
                self.subs.remove(&sub);
            }
            Rec::RemoveTrack(t) => {
                self.tracks.remove(&t);
                self.subs.retain(|_, (_, track)| *track != t);
            }
            Rec::Close(id) => {
                self.sessions.remove(&id);
                let gone: Vec<DpTrackId> = self
                    .tracks
                    .iter()
                    .filter(|(_, (s, _))| *s == id)
                    .map(|(t, _)| *t)
                    .collect();
                self.tracks.retain(|_, (s, _)| *s != id);
                self.subs
                    .retain(|_, (s, track)| *s != id && !gone.contains(track));
            }
            Rec::AddRemote(t, s) => {
                let entry = self
                    .tracks
                    .get_mut(&t)
                    .expect("AddRemoteShard for a live track");
                entry.1 |= 1 << s.index();
            }
            Rec::RemoveRemote(t, s) => {
                if let Some(entry) = self.tracks.get_mut(&t) {
                    entry.1 &= !(1 << s.index());
                }
            }
            Rec::Other => {}
        }
    }
}

#[derive(Clone, Debug)]
enum XsOp {
    Publish(u64, bool),
    Subscribe(u64, usize),
    Unsubscribe(u64, usize),
    Unpublish(u64, usize),
    Leave(u64),
    Join(u64),
    Room(u8, Option<usize>),
    Sweep,
}

fn xs_op() -> impl Strategy<Value = XsOp> {
    let p = 1..=6u64;
    prop_oneof![
        2 => (p.clone(), any::<bool>()).prop_map(|(p, v)| XsOp::Publish(p, v)),
        5 => (p.clone(), 0..16usize).prop_map(|(p, k)| XsOp::Subscribe(p, k)),
        2 => (p.clone(), 0..16usize).prop_map(|(p, k)| XsOp::Unsubscribe(p, k)),
        1 => (p.clone(), 0..4usize).prop_map(|(p, k)| XsOp::Unpublish(p, k)),
        1 => p.clone().prop_map(XsOp::Leave),
        1 => p.prop_map(XsOp::Join),
        2 => (0..3u8, prop::option::of(0..3usize)).prop_map(|(s, r)| XsOp::Room(s, r)),
        1 => Just(XsOp::Sweep),
    ]
}

impl World {
    fn run(&mut self, op: XsOp, seen: &mut Vec<DpTrackId>) {
        let present = |w: &World, p: u64| w.o.sessions.contains_key(&p);
        match op {
            XsOp::Publish(p, video) if present(self, p) => {
                let kind = if video { "video" } else { "audio" };
                let new = self.publish(p, &[kind]);
                seen.extend(new);
            }
            XsOp::Subscribe(p, k) if present(self, p) && !seen.is_empty() => {
                let t = seen[k % seen.len()];
                self.subscribe(p, &[t]);
            }
            XsOp::Unsubscribe(p, k) => {
                let subscribed = self.o.subscription.track_ids(p);
                if !subscribed.is_empty() {
                    let t = DpTrackId::new(subscribed[k % subscribed.len()]);
                    self.unsubscribe(p, &[t]);
                }
            }
            XsOp::Unpublish(p, k) => {
                let own = self.published(p);
                if !own.is_empty() {
                    self.unpublish(p, &[own[k % own.len()]]);
                }
            }
            XsOp::Leave(p) if present(self, p) => self.leave(p),
            XsOp::Join(p) if !present(self, p) => self.join(p),
            XsOp::Room(s, room) => self.sink.set_room(s, room),
            XsOp::Sweep => self.sweep(),
            _ => {}
        }
    }

    /// Free every queue and sweep until no cleanup waits.
    fn quiesce(&mut self) {
        for s in 0..3 {
            self.sink.set_room(s, None);
        }
        self.sweep();
        assert_eq!(self.o.plane.pending_cleanup(), 0);
        self.take();
    }

    /// Replay the recorded stream on three shard models and compare with the
    /// orchestrator's slots, counts and tracks.
    fn check_agreement(&self) {
        let mut shards: Vec<ShardModel> = (0..3).map(|_| ShardModel::default()).collect();
        for &(s, rec) in &self.history {
            shards[usize::from(s.index())].apply(s, rec);
        }
        // Sessions and on-shard slots, per shard.
        let mut sessions: Vec<HashSet<SessionId>> = vec![HashSet::new(); 3];
        let mut slots: Vec<HashMap<SubscriptionId, (SessionId, DpTrackId)>> =
            vec![HashMap::new(); 3];
        for state in self.o.negotiation.states.values() {
            let Some(id) = state.session else { continue };
            let s = usize::from(self.o.plane.transports.get(id).unwrap().shard.index());
            sessions[s].insert(id);
            for m in &state.mlines {
                if let negotiation::MlineRole::Subscribe(sub) = m.role {
                    if sub.on_shard {
                        slots[s].insert(sub.sub, (id, DpTrackId::new(sub.track)));
                    }
                }
            }
        }
        for s in 0..3 {
            assert_eq!(shards[s].sessions, sessions[s], "sessions on shard {s}");
            assert_eq!(shards[s].subs, slots[s], "subscriptions on shard {s}");
        }
        // Tracks: on their shard only while registered, bits = announced = counted.
        let mut live = 0;
        for (t, info) in self.o.plane.tracks.iter() {
            live += 1;
            let a = usize::from(info.shard.index());
            let (_, bits) = shards[a]
                .tracks
                .get(&t)
                .copied()
                .expect("track on its shard");
            let mut counted = 0u32;
            for s in 0..3u8 {
                let n = slots[usize::from(s)]
                    .values()
                    .filter(|(_, tr)| *tr == t)
                    .count();
                assert_eq!(
                    info.subscribers_on(shard(s)) as usize,
                    n,
                    "count {t:?} on {s}"
                );
                let mirror = shards[usize::from(s)].subs.values().any(|(_, tr)| *tr == t);
                if usize::from(s) != a {
                    assert_eq!(mirror, n > 0, "mirror of {t:?} on shard {s}");
                    if n > 0 {
                        counted |= 1 << s;
                    }
                }
            }
            assert_eq!(bits, counted, "remote_shards of {t:?}");
            assert_eq!(info.announced, counted, "announced of {t:?}");
        }
        let on_shards: usize = shards.iter().map(|m| m.tracks.len()).sum();
        assert_eq!(on_shards, live, "no removed track stays on a shard");
        // Every subscription on a shard is to a live track.
        for m in &shards {
            assert!(m
                .subs
                .values()
                .all(|(_, t)| self.o.plane.tracks.get(*t).is_some()));
        }
        self.check_alternation();
    }

    /// Per (track, shard): AddRemoteShard and RemoveRemoteShard alternate, starting
    /// with an add; a live pair with subscribers ends on an add.
    fn check_alternation(&self) {
        let mut last: HashMap<(DpTrackId, ShardId), bool> = HashMap::new();
        for &(_, rec) in &self.history {
            let (key, add) = match rec {
                Rec::AddRemote(t, s) => ((t, s), true),
                Rec::RemoveRemote(t, s) => ((t, s), false),
                _ => continue,
            };
            let before = last.insert(key, add).unwrap_or(false);
            assert!(
                before != add,
                "{key:?}: two {} in a row",
                if add { "adds" } else { "removes" }
            );
        }
        for (t, info) in self.o.plane.tracks.iter() {
            for s in 0..3u8 {
                if shard(s) == info.shard {
                    continue;
                }
                let added = last.get(&(t, shard(s))).copied().unwrap_or(false);
                assert_eq!(added, info.subscribers_on(shard(s)) > 0, "{t:?} on {s}");
            }
        }
    }
}

/// What a random case covered.
#[derive(Default)]
struct Coverage {
    cases: u32,
    /// Cases with an `AddRemoteShard`.
    announced: u32,
    /// Cases where a `RemoveRemoteShard` was sent.
    removed: u32,
    /// Cases where cleanup waited for a full queue.
    waited: u32,
    /// Cases where a participant was closed for a full queue.
    closed: u32,
}

/// Random publish, subscribe, unsubscribe, unpublish, leave and join on three shards,
/// with queues filling and emptying: at quiescence the recorded stream is balanced per
/// (track, shard) and, replayed on shard models, agrees with the orchestrator's slots
/// and counts (exit criterion 6, orchestrator side). A hand-written runner with a
/// fixed seed, so the cases can be checked to cover the cross-shard paths.
#[test]
fn random_cross_shard_streams_stay_balanced() {
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();
    let coverage = std::cell::RefCell::new(Coverage::default());
    // A fixed seed, so the coverage asserts below cannot fail by chance.
    let config = Config {
        cases: 96,
        ..Config::default()
    };
    let rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
    let mut runner = TestRunner::new_with_rng(config, rng);
    let strategy = prop::collection::vec(xs_op(), 1..40);
    let result = runner.run(&strategy, |ops| {
        let mut c = coverage.borrow_mut();
        c.cases += 1;
        let affine = room_affine(3, 1);
        let script = Arc::new(Mutex::new(VecDeque::new()));
        let mut w = World::with(3, Box::new(Shared(Arc::clone(&affine))), script);
        for p in 1..=6 {
            w.join(p);
        }
        let (mut seen, mut waited, mut closed) = (Vec::new(), false, false);
        for op in ops {
            w.run(op, &mut seen);
            w.take();
            waited |= w.o.plane.pending_cleanup() > 0;
            closed |= (1..=6).any(|p| {
                w.inbox
                    .get(&p)
                    .is_some_and(|m| error_codes(m.clone()).iter().any(|c| c == "OVERLOADED"))
            });
        }
        w.quiesce();
        w.check_agreement();
        c.announced += u32::from(
            w.history
                .iter()
                .any(|(_, r)| matches!(r, Rec::AddRemote(..))),
        );
        c.removed += u32::from(
            w.history
                .iter()
                .any(|(_, r)| matches!(r, Rec::RemoveRemote(..))),
        );
        c.waited += u32::from(waited);
        c.closed += u32::from(closed);
        // Everyone leaves: nothing is left anywhere.
        for p in 1..=6 {
            if w.o.sessions.contains_key(&p) {
                w.leave(p);
            }
        }
        w.quiesce();
        w.check_agreement();
        prop_assert!(w.o.plane.tracks.is_empty());
        let affine = affine.lock();
        prop_assert!((0..3).all(|i| affine.placed(shard(i)) == 0));
        prop_assert_eq!(affine.rooms_tracked(), 0);
        Ok(())
    });
    if let Err(e) = result {
        panic!("{e}");
    }
    let c = coverage.into_inner();
    eprintln!(
        "cases {}: announced {}, removed {}, cleanup waited {}, closed {}",
        c.cases, c.announced, c.removed, c.waited, c.closed
    );
    assert!(
        c.announced * 4 >= c.cases,
        "AddRemoteShard in >= 1/4 of cases"
    );
    assert!(c.removed * 8 >= c.cases, "RemoveRemoteShard in >= 1/8");
    assert!(c.waited * 8 >= c.cases, "cleanup waited in >= 1/8");
    assert!(
        c.closed * 8 >= c.cases,
        "a full queue closed someone in >= 1/8"
    );
}
