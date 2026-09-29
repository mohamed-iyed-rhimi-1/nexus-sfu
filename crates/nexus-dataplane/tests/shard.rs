//! The shard driven through `MemIo` with scripted peers (Phase 1.2a).

mod support;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nexus_dataplane::{
    CnameValue, Command, Event, ExtIds, RejectReason, SelectReason, ShardId, SubSpec,
    SubscriptionId, TrackId, TrackRef, XsMesh, XsMsg, XS_CREDIT, XS_RING,
};
use nexus_transport::ice::stun::StunMessage;
use nexus_transport::srtp::ProtectionProfile;
use proptest::prelude::*;
use support::*;

const GCM: ProtectionProfile = ProtectionProfile::AeadAes128Gcm;
const CM: ProtectionProfile = ProtectionProfile::Aes128CmHmacSha1_80;

// ---------------------------------------------------------------------------
// STUN
// ---------------------------------------------------------------------------

#[test]
fn binding_request_answered_with_mapped_address_ipv4_and_ipv6() {
    let now = Instant::now();
    let mut shard = shard(now);
    for (n, addr) in [(1, "192.0.2.10:4000"), (2, "[2001:db8::7]:4001")] {
        let peer = Peer::new(n, addr, GCM);
        command(&mut shard, peer.create());
        run(&mut shard, now);
        shard
            .io_mut()
            .push_inbound(peer.addr, peer.binding_request(false));
        run(&mut shard, now);
        let answers = sent_to(&mut shard, peer.addr);
        assert_eq!(answers.len(), 1);
        let msg = StunMessage::parse(&answers[0]).expect("response parses");
        assert_eq!(msg.get_xor_mapped_address(), Some(peer.addr));
    }
    assert_eq!(shard.counters().stun_answered, 2);
}

#[test]
fn bad_binding_requests_get_no_answer_and_change_nothing() {
    let now = Instant::now();
    let mut shard = shard(now);
    let peer = Peer::new(1, "192.0.2.10:4000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, now);
    let before = shard.snapshot();

    let good = peer.binding_request(true);
    let mut bad_fingerprint = good.clone();
    *bad_fingerprint.last_mut().unwrap() ^= 0x01;
    let mut user = peer.ice.local_ufrag.to_vec();
    user.extend_from_slice(b":remote");
    let mut invalid_utf8 = user.clone();
    invalid_utf8[3] = 0xFF;
    let other_ufrag = *b"ufrag99999999999";

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "wrong password",
            binding_request(&peer.ice.local_ufrag, &[b'x'; 32], true),
        ),
        (
            "wrong ufrag",
            binding_request(&other_ufrag, &peer.ice.local_pwd, true),
        ),
        ("bad fingerprint", bad_fingerprint),
        ("truncated", good[..good.len() - 8].to_vec()),
        (
            "invalid UTF-8 username",
            raw_binding_request(&invalid_utf8, &peer.ice.local_pwd, 0),
        ),
        (
            "40 unknown attributes",
            raw_binding_request(&user, &peer.ice.local_pwd, 40),
        ),
    ];
    for (name, request) in cases {
        shard.io_mut().push_inbound(peer.addr, request);
        run(&mut shard, now);
        assert!(
            sent_to(&mut shard, peer.addr).is_empty(),
            "{name}: answered"
        );
        assert_eq!(shard.snapshot(), before, "{name}: state changed");
        assert_eq!(
            shard.session_addr(peer.id),
            None,
            "{name}: address selected"
        );
    }
    assert!(events(&mut shard).is_empty());

    // The same raw builder with a valid username is answered.
    shard.io_mut().push_inbound(
        peer.addr,
        raw_binding_request(&user, &peer.ice.local_pwd, 3),
    );
    run(&mut shard, now);
    assert_eq!(sent_to(&mut shard, peer.addr).len(), 1);
}

#[test]
fn nomination_selects_and_request_without_use_candidate_does_not() {
    let now = Instant::now();
    let mut shard = shard(now);
    let peer = Peer::new(1, "192.0.2.10:4000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, now);

    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(false));
    run(&mut shard, now);
    assert_eq!(shard.session_addr(peer.id), None);
    assert!(events(&mut shard).is_empty());

    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    run(&mut shard, now);
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
    assert_eq!(
        events(&mut shard),
        vec![Event::AddressSelected {
            id: peer.id,
            addr: peer.addr,
            reason: SelectReason::Nominated
        }]
    );
}

#[test]
fn rebinding_waits_for_silence_and_nomination_switches_at_once() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.10:4000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    run(&mut shard, t0);
    events(&mut shard);

    let b: SocketAddr = "192.0.2.10:5000".parse().unwrap();
    let c: SocketAddr = "192.0.2.10:6000".parse().unwrap();

    // 1 s after the selected address was last heard: answer only.
    shard.io_mut().push_inbound(b, peer.binding_request(false));
    run(&mut shard, at(t0, 1_000));
    assert_eq!(sent_to(&mut shard, b).len(), 1, "answered");
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));

    // 1.9 s: still within rebind_silence (2 s).
    shard.io_mut().push_inbound(b, peer.binding_request(false));
    run(&mut shard, at(t0, 1_900));
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));

    // 2.1 s of silence: rebound.
    shard.io_mut().push_inbound(b, peer.binding_request(false));
    run(&mut shard, at(t0, 2_100));
    assert_eq!(shard.session_addr(peer.id), Some(b));

    // USE-CANDIDATE from c switches immediately.
    shard.io_mut().push_inbound(c, peer.binding_request(true));
    run(&mut shard, at(t0, 2_200));
    assert_eq!(shard.session_addr(peer.id), Some(c));
    let reasons: Vec<_> = events(&mut shard)
        .into_iter()
        .map(|e| match e {
            Event::AddressSelected { addr, reason, .. } => (addr, reason),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        reasons,
        vec![(b, SelectReason::Rebound), (c, SelectReason::Nominated)]
    );
    assert_eq!(shard.counters().rebinds, 1);
    // Selected + previous address only.
    assert_eq!(shard.snapshot().addresses, 2);
}

// ---------------------------------------------------------------------------
// Forwarding
// ---------------------------------------------------------------------------

struct Call {
    shard: TestShard,
    publisher: Peer,
    subscribers: Vec<Peer>,
    out_ssrcs: Vec<u32>,
    track: TrackId,
    now: Instant,
}

const PUB_SSRC: u32 = 0xAAAA_0001;

fn call(profile: ProtectionProfile, subscribers: u64) -> Call {
    call_with(profile, subscribers, false)
}

/// A call; with `extensions`, the publisher's answer accepted mid (1) and
/// audio level (2), and subscribers map audio level to 5 and write mid as 1.
fn call_with(profile: ProtectionProfile, subscribers: u64, extensions: bool) -> Call {
    let now = Instant::now();
    let mut shard = shard(now);
    let publisher = Peer::new(1, "192.0.2.1:1000", profile);
    connect(&mut shard, &publisher, now);
    let track = TrackId::new(10);
    let mut spec = track_spec(Some(PUB_SSRC), b"0");
    if extensions {
        spec.ext = ExtIds {
            mid: 1,
            audio_level: 2,
            video_orientation: 0,
        };
    }
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track,
            spec,
        },
    );
    let mut subs = Vec::new();
    let mut out_ssrcs = Vec::new();
    for n in 0..subscribers {
        let mut peer = Peer::new(2 + n, &format!("192.0.2.{}:2000", 2 + n), profile);
        connect(&mut shard, &peer, now);
        let out = peer.next_out_ssrc();
        let mut spec = sub_spec(out, track);
        if extensions {
            spec.ext_map.map[2] = 5;
            spec.ext_map.mid = 1;
            spec.pub_mid = 1;
        }
        let sub = SubscriptionId::new(100 + n);
        command(
            &mut shard,
            Command::Subscribe {
                id: peer.id,
                sub,
                track,
                spec,
            },
        );
        run(&mut shard, now);
        out_ssrcs.push(out);
        subs.push(peer);
    }
    events(&mut shard);
    // The first Subscribe asked the publisher for a keyframe.
    assert_eq!(
        shard.counters().keyframe_requests,
        u64::from(subscribers > 0)
    );
    shard.io_mut().clear_outbound();
    Call {
        shard,
        publisher,
        subscribers: subs,
        out_ssrcs,
        track,
        now,
    }
}

impl Call {
    fn publish(&mut self, seq: u16, ts: u32, payload: &[u8]) {
        let packet = self.publisher.rtp(PUB_SSRC, seq, ts, payload);
        self.shard
            .io_mut()
            .push_inbound(self.publisher.addr, packet);
        run(&mut self.shard, self.now);
    }

    /// Decrypted packets each subscriber received since the last call.
    fn received(&mut self) -> Vec<Vec<Vec<u8>>> {
        let out = self.shard.io_mut().take_outbound();
        self.subscribers
            .iter_mut()
            .map(|peer| {
                let addr = peer.addr;
                out.iter()
                    .filter(|(a, _)| *a == addr)
                    .map(|(_, b)| peer.open_rtp(b).expect("subscriber decrypts"))
                    .collect()
            })
            .collect()
    }
}

fn seq(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[2], p[3]])
}
fn ts(p: &[u8]) -> u32 {
    u32::from_be_bytes(p[4..8].try_into().unwrap())
}
fn ssrc(p: &[u8]) -> u32 {
    u32::from_be_bytes(p[8..12].try_into().unwrap())
}

/// One receive batch of 64 packets to 5 subscribers is 320 datagrams, more
/// than `SEND_BATCH` (256): the fan-out flushes in the middle of the batch
/// and nothing is lost.
#[test]
fn fan_out_beyond_the_send_batch_flushes_mid_batch() {
    let mut call = call(GCM, 5);
    let flushes = call.shard.counters().tx_full_flushes;
    for i in 0..nexus_dataplane::RECV_BATCH as u16 {
        let packet = call
            .publisher
            .rtp(PUB_SSRC, 100 + i, 960 * u32::from(i), &[1; 50]);
        let from = call.publisher.addr;
        call.shard.io_mut().push_inbound(from, packet);
    }
    // One iteration receives the whole batch.
    let stats = call.shard.iterate(call.now);
    assert_eq!(stats.received, nexus_dataplane::RECV_BATCH);
    assert!(
        call.shard.counters().tx_full_flushes > flushes,
        "flushed mid-batch"
    );
    let received = call.received();
    for packets in &received {
        assert_eq!(packets.len(), nexus_dataplane::RECV_BATCH);
    }
}

#[test]
fn publisher_to_three_subscribers_rewritten_per_subscriber() {
    for profile in [GCM, CM] {
        let mut call = call(profile, 3);
        for i in 0..5u16 {
            call.publish(1000 + i, 90_000 + 960 * i as u32, &[i as u8; 100]);
        }
        let received = call.received();
        let mut starts = HashSet::new();
        for (k, packets) in received.iter().enumerate() {
            assert_eq!(packets.len(), 5, "{profile:?}: subscriber {k}");
            for (i, p) in packets.iter().enumerate() {
                assert_eq!(ssrc(p), call.out_ssrcs[k]);
                assert_eq!(p[1] & 0x7F, SUB_PT);
                assert_eq!(
                    seq(p),
                    seq(&packets[0]).wrapping_add(i as u16),
                    "contiguous seq"
                );
                assert_eq!(ts(p), ts(&packets[0]).wrapping_add(960 * i as u32));
                assert_eq!(&p[12..], &[i as u8; 100], "payload intact");
            }
            starts.insert(seq(&packets[0]));
        }
        assert_eq!(
            starts.len(),
            3,
            "each subscriber starts at its own random seq"
        );
    }
}

#[test]
fn reordering_in_is_reordering_out() {
    let mut call = call(GCM, 1);
    for s in [5u16, 7, 6] {
        call.publish(s, s as u32 * 10, &[s as u8]);
    }
    let packets = &call.received()[0];
    let base = seq(&packets[0]);
    let order: Vec<u16> = packets.iter().map(|p| seq(p).wrapping_sub(base)).collect();
    assert_eq!(order, vec![0, 2, 1]);
    assert_eq!(packets[2][12], 6);
}

#[test]
fn subscriber_without_srtp_or_address_is_skipped() {
    let mut call = call(GCM, 1);
    // A second subscriber with a session and subscription but no SRTP.
    let mut late = Peer::new(9, "192.0.2.9:9000", GCM);
    command(&mut call.shard, late.create());
    run(&mut call.shard, call.now);
    call.shard
        .io_mut()
        .push_inbound(late.addr, late.binding_request(true));
    subscribe(&mut call.shard, &mut late, 900, call.track, call.now);
    // A third with SRTP but no address.
    let mut hidden = Peer::new(8, "192.0.2.8:8000", GCM);
    command(&mut call.shard, hidden.create());
    command(&mut call.shard, hidden.install());
    run(&mut call.shard, call.now);
    subscribe(&mut call.shard, &mut hidden, 800, call.track, call.now);
    call.shard.io_mut().clear_outbound();

    call.publish(1, 1, b"x");
    let out = call.shard.io_mut().take_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, call.subscribers[0].addr);
}

#[test]
fn srtp_from_unknown_address_is_dropped_and_does_not_move_session() {
    let mut call = call(GCM, 1);
    let stranger: SocketAddr = "198.51.100.1:1000".parse().unwrap();
    let packet = call.publisher.rtp(PUB_SSRC, 1, 1, b"x");
    call.shard.io_mut().push_inbound(stranger, packet);
    run(&mut call.shard, call.now);
    assert_eq!(call.shard.io().outbound_len(), 0);
    assert_eq!(call.shard.counters().drop_unknown_addr, 1);
    assert_eq!(
        call.shard.session_addr(call.publisher.id),
        Some(call.publisher.addr)
    );
}

/// RFC 3711 §3.3.1 index estimate per SSRC, as a receiver keeps it.
#[derive(Default)]
struct IndexTracker {
    state: std::collections::HashMap<u32, (u32, u16)>,
    seen: HashSet<(u32, u64)>,
}

impl IndexTracker {
    /// Records the packet's (SSRC, index); `false` if it was seen before.
    fn record(&mut self, ssrc: u32, seq: u16) -> bool {
        let (roc, high) = *self.state.entry(ssrc).or_insert((0, seq));
        let v = if high < 32_768 {
            if i32::from(seq) - i32::from(high) > 32_768 {
                roc.wrapping_sub(1)
            } else {
                roc
            }
        } else if i32::from(high) - 32_768 > i32::from(seq) {
            roc + 1
        } else {
            roc
        };
        let index = (u64::from(v) << 16) | u64::from(seq);
        let highest = (u64::from(roc) << 16) | u64::from(high);
        if index > highest {
            self.state.insert(ssrc, (v, seq));
        }
        self.seen.insert((ssrc, index))
    }
}

#[test]
fn resubscribe_never_repeats_ssrc_and_packet_index() {
    let mut call = call(GCM, 1);
    let first = call.out_ssrcs[0];
    let id = call.subscribers[0].id;
    let subscribe_as = |call: &mut Call, n: u64, out: u32| {
        let spec = sub_spec(out, call.track);
        let command = Command::Subscribe {
            id,
            sub: SubscriptionId::new(n),
            track: call.track,
            spec,
        };
        support::command(&mut call.shard, command);
        run(&mut call.shard, call.now);
    };

    // Smaller than the last out SSRC: rejected.
    subscribe_as(&mut call, 200, first - 1);
    let rejected = Event::CommandRejected {
        id: Some(id),
        reason: RejectReason::OutSsrcNotMonotonic,
    };
    assert_eq!(events(&mut call.shard), vec![rejected.clone()]);

    // First subscription, then unsubscribe.
    let mut wire = Vec::new();
    for i in 0..40u16 {
        call.publish(i, u32::from(i) * 960, b"a");
    }
    wire.extend(sent_to(&mut call.shard, call.subscribers[0].addr));
    command(
        &mut call.shard,
        Command::Unsubscribe {
            sub: SubscriptionId::new(100),
        },
    );
    run(&mut call.shard, call.now);
    let after_unsubscribe = wire.len();

    // An orchestrator that re-uses the retired SSRC (the architecture.md 2.2
    // bug) is refused; a fresh SSRC works.
    subscribe_as(&mut call, 101, first);
    let rejections: Vec<Event> = events(&mut call.shard)
        .into_iter()
        .filter(|e| matches!(e, Event::CommandRejected { .. }))
        .collect();
    assert_eq!(rejections, vec![rejected]);
    let second = call.subscribers[0].next_out_ssrc();
    subscribe_as(&mut call, 102, second);
    for i in 40..80u16 {
        call.publish(i, u32::from(i) * 960, b"b");
    }
    wire.extend(sent_to(&mut call.shard, call.subscribers[0].addr));

    // One subscriber SRTP context sees both subscriptions: every packet
    // decrypts (a repeated index would be refused as a replay), and no
    // (SSRC, packet index) repeats.
    let mut tracker = IndexTracker::default();
    assert_eq!(wire.len(), 80);
    for (k, bytes) in wire.iter().enumerate() {
        let packet = call.subscribers[0]
            .open_rtp(bytes)
            .expect("subscriber context accepts it");
        assert!(
            tracker.record(ssrc(&packet), seq(&packet)),
            "repeated (SSRC, index) at {k}"
        );
        let expected = if k < after_unsubscribe { first } else { second };
        assert_eq!(ssrc(&packet), expected, "packet {k}");
    }
}

#[test]
fn close_session_removes_everything() {
    let mut call = call(GCM, 2);
    let empty = {
        let mut s = shard(call.now);
        run(&mut s, call.now);
        s.snapshot()
    };
    command(
        &mut call.shard,
        Command::CloseSession {
            id: call.subscribers[1].id,
        },
    );
    run(&mut call.shard, call.now);
    let snap = call.shard.snapshot();
    assert_eq!((snap.sessions, snap.tracks, snap.subscriptions), (2, 1, 1));

    // The closed subscriber gets nothing; the other still does.
    call.publish(1, 1, b"x");
    let out = call.shard.io_mut().take_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, call.subscribers[0].addr);

    // Closing the publisher removes its track and the subscription to it.
    command(
        &mut call.shard,
        Command::CloseSession {
            id: call.publisher.id,
        },
    );
    run(&mut call.shard, call.now);
    let packet = call.publisher.rtp(PUB_SSRC, 2, 2, b"x");
    call.shard
        .io_mut()
        .push_inbound(call.publisher.addr, packet);
    run(&mut call.shard, call.now);
    assert_eq!(call.shard.io().outbound_len(), 0);
    assert_eq!(call.shard.counters().drop_unknown_addr, 1);

    command(
        &mut call.shard,
        Command::CloseSession {
            id: call.subscribers[0].id,
        },
    );
    run(&mut call.shard, call.now);
    assert_eq!(call.shard.snapshot(), empty);
    let evs = events(&mut call.shard);
    assert_eq!(
        evs,
        vec![Event::PeerSrtpVerified {
            id: call.publisher.id
        }],
        "no rejections"
    );
}

#[test]
fn dtls_events_until_first_authenticated_srtp() {
    let now = Instant::now();
    let mut shard = shard(now);
    let mut peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, now);
    let dtls = vec![22u8, 0xFE, 0xFD, 0, 0, 1, 2, 3];

    // Unknown address: no event.
    shard.io_mut().push_inbound(peer.addr, dtls.clone());
    run(&mut shard, now);
    assert!(events(&mut shard).is_empty());

    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    shard.io_mut().push_inbound(peer.addr, dtls.clone());
    command(&mut shard, peer.install());
    run(&mut shard, now);
    let evs = events(&mut shard);
    assert!(evs.contains(&Event::DtlsDatagram {
        id: peer.id,
        bytes: dtls.clone().into()
    }));
    shard.io_mut().clear_outbound(); // the STUN answer

    // SendDatagram goes to the selected address.
    command(
        &mut shard,
        Command::SendDatagram {
            id: peer.id,
            bytes: vec![22u8, 1, 2].into(),
        },
    );
    run(&mut shard, now);
    assert_eq!(sent_to(&mut shard, peer.addr), vec![vec![22u8, 1, 2]]);

    // First authenticated SRTCP → PeerSrtpVerified, then DTLS is dropped.
    let rr = [0x80, 201, 0, 1, 0, 0, 0, 9];
    let srtcp = peer.rtcp(&rr);
    shard.io_mut().push_inbound(peer.addr, srtcp);
    shard.io_mut().push_inbound(peer.addr, dtls);
    run(&mut shard, now);
    assert_eq!(
        events(&mut shard),
        vec![Event::PeerSrtpVerified { id: peer.id }]
    );
    assert_eq!(shard.counters().drop_dtls_verified, 1);
}

#[test]
fn dtls_only_from_the_selected_address() {
    // After a switch the previous address stays in the address map for its grace
    // period; DTLS from it must not reach the handshake (replies go to the new one).
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    let (a, b): (SocketAddr, SocketAddr) = (
        "192.0.2.1:1000".parse().unwrap(),
        "192.0.2.1:1001".parse().unwrap(),
    );
    shard.io_mut().push_inbound(a, peer.binding_request(true));
    run(&mut shard, t0);
    shard.io_mut().push_inbound(b, peer.binding_request(true));
    run(&mut shard, at(t0, 200));
    assert_eq!(
        shard.snapshot().addresses,
        2,
        "previous address still mapped"
    );
    events(&mut shard);

    let dtls = vec![22u8, 0xFE, 0xFD, 0, 0, 1, 2, 3];
    shard.io_mut().push_inbound(a, dtls.clone());
    run(&mut shard, at(t0, 210));
    assert!(events(&mut shard).is_empty());
    assert_eq!(shard.counters().drop_dtls_unselected, 1);

    shard.io_mut().push_inbound(b, dtls.clone());
    run(&mut shard, at(t0, 220));
    assert_eq!(
        events(&mut shard),
        vec![Event::DtlsDatagram {
            id: peer.id,
            bytes: dtls.into()
        }]
    );
    assert_eq!(shard.counters().drop_dtls_unselected, 1);
}

#[test]
fn unknown_ids_are_rejected() {
    let now = Instant::now();
    let mut shard = shard(now);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.install());
    command(
        &mut shard,
        Command::RemoveTrack {
            track: TrackId::new(5),
        },
    );
    command(
        &mut shard,
        Command::Unsubscribe {
            sub: SubscriptionId::new(5),
        },
    );
    command(&mut shard, peer.create());
    command(&mut shard, peer.create());
    command(&mut shard, peer.install());
    command(&mut shard, peer.install());
    run(&mut shard, now);
    let reasons: Vec<_> = events(&mut shard)
        .into_iter()
        .map(|e| match e {
            Event::CommandRejected { reason, .. } => reason,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            RejectReason::UnknownSession,
            RejectReason::UnknownTrack,
            RejectReason::UnknownSubscription,
            RejectReason::DuplicateId,
            RejectReason::SrtpAlreadyInstalled,
        ]
    );
}

#[test]
fn subscribe_before_install_srtp_registers_at_install() {
    let now = Instant::now();
    let mut shard = shard(now);
    let mut publisher = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &publisher, now);
    let track = TrackId::new(10);
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track,
            spec: track_spec(Some(PUB_SSRC), b"0"),
        },
    );
    let mut sub = Peer::new(2, "192.0.2.2:2000", GCM);
    command(&mut shard, sub.create());
    run(&mut shard, now);
    let first = subscribe(&mut shard, &mut sub, 1, track, now);
    let second = subscribe(&mut shard, &mut sub, 2, track, now);
    shard
        .io_mut()
        .push_inbound(sub.addr, sub.binding_request(true));
    command(&mut shard, sub.install());
    run(&mut shard, now);
    assert!(events(&mut shard)
        .iter()
        .all(|e| !matches!(e, Event::CommandRejected { .. })));
    shard.io_mut().clear_outbound(); // the STUN answer

    let packet = publisher.rtp(PUB_SSRC, 1, 1, b"x");
    shard.io_mut().push_inbound(publisher.addr, packet);
    run(&mut shard, now);
    let ssrcs: HashSet<u32> = sent_to(&mut shard, sub.addr)
        .iter()
        .map(|b| ssrc(&sub.open_rtp(b).unwrap()))
        .collect();
    assert_eq!(ssrcs, HashSet::from([first, second]));
}

// ---------------------------------------------------------------------------
// 1.2b: extensions, SSRC learning, RTCP, housekeeping
// ---------------------------------------------------------------------------

#[test]
fn unknown_ssrc_is_learned_from_the_mid_extension() {
    let now = Instant::now();
    let mut shard = shard(now);
    let mut publisher = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &publisher, now);
    let track = TrackId::new(10);
    let mut spec = track_spec(None, b"a0");
    spec.ext.mid = 1;
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track,
            spec,
        },
    );
    let mut sub = Peer::new(2, "192.0.2.2:2000", GCM);
    connect(&mut shard, &sub, now);
    let out = sub.next_out_ssrc();
    let mut sub_spec = sub_spec(out, track);
    sub_spec.ext_map.mid = 1;
    sub_spec.pub_mid = 1;
    command(
        &mut shard,
        Command::Subscribe {
            id: sub.id,
            sub: SubscriptionId::new(1),
            track,
            spec: sub_spec,
        },
    );
    run(&mut shard, now);
    shard.io_mut().clear_outbound();

    // Wrong mid: dropped. Right mid: bound and forwarded, publisher mid
    // replaced by the subscriber's.
    let wrong = publisher.protect_rtp(&rtp_with_ext(0x77, 1, 1, &[(1, b"zz")], b"x"));
    let right = publisher.protect_rtp(&rtp_with_ext(0x99, 1, 1, &[(1, b"a0")], b"y"));
    shard.io_mut().push_inbound(publisher.addr, wrong);
    shard.io_mut().push_inbound(publisher.addr, right);
    run(&mut shard, now);
    assert_eq!(shard.counters().drop_no_route, 1);
    assert_eq!(shard.counters().ssrcs_learned, 1);
    let packets: Vec<Vec<u8>> = sent_to(&mut shard, sub.addr)
        .iter()
        .map(|b| sub.open_rtp(b).unwrap())
        .collect();
    assert_eq!(packets.len(), 1);
    let p = &packets[0];
    assert_eq!(ssrc(p), out);
    assert_eq!(
        &p[12..20],
        &[0xBE, 0xDE, 0, 1, 0x11, b's', b'0', 0],
        "subscriber mid"
    );
    assert_eq!(&p[20..], b"y");

    // Later packets of the learned SSRC need no mid.
    let plain = publisher.protect_rtp(&rtp_packet(0x99, 2, 2, PUB_PT, b"z"));
    shard.io_mut().push_inbound(publisher.addr, plain);
    run(&mut shard, now);
    assert_eq!(sent_to(&mut shard, sub.addr).len(), 1);
}

#[test]
fn sender_report_is_translated_with_sdes_cname() {
    let mut call = call(GCM, 1);
    for i in 0..3u16 {
        call.publish(i, 1000 + 960 * i as u32, &[0u8; 50]);
    }
    let rtp_out = call.received().remove(0);
    let ts_offset = ts(&rtp_out[0]).wrapping_sub(1000);

    let ntp = 0xDEAD_BEEF_0000_0001u64;
    let mut indices = Vec::new();
    for round in 0..2u32 {
        let sr = call
            .publisher
            .rtcp(&sender_report(PUB_SSRC, ntp + round as u64, 5000, 3, 150));
        call.shard.io_mut().push_inbound(call.publisher.addr, sr);
        run(&mut call.shard, call.now);
        let sent = sent_to(&mut call.shard, call.subscribers[0].addr);
        assert_eq!(sent.len(), 1);
        // GCM SRTCP: E+index is the last word (after the tag).
        let wire = &sent[0];
        indices.push(u32::from_be_bytes(wire[wire.len() - 4..].try_into().unwrap()) & 0x7FFF_FFFF);
        let plain = call.subscribers[0]
            .open_rtcp(wire)
            .expect("subscriber decrypts SRTCP");
        let sr = nexus_media::rtcp::SenderReport::parse(&plain).unwrap();
        assert_eq!(sr.ssrc, call.out_ssrcs[0]);
        assert_eq!(sr.ntp_timestamp, ntp + round as u64);
        assert_eq!(sr.rtp_timestamp, 5000u32.wrapping_add(ts_offset));
        assert_eq!((sr.packet_count, sr.octet_count), (3, 150), "sent so far");
        let sdes = &plain[28..];
        assert_eq!(sdes[1], 202);
        assert_eq!(
            u32::from_be_bytes(sdes[4..8].try_into().unwrap()),
            call.out_ssrcs[0]
        );
        assert_eq!(&sdes[10..10 + sdes[9] as usize], b"publisher-cname");
    }
    assert!(
        indices[1] > indices[0],
        "SRTCP index of the out SSRC increases"
    );
}

/// PLIs the publisher received (decrypted), as (sender, media).
fn plis_to_publisher(call: &mut Call) -> Vec<(u32, u32)> {
    let addr = call.publisher.addr;
    let sent = sent_to(&mut call.shard, addr);
    sent.iter()
        .map(|b| {
            let p = call.publisher.open_rtcp(b).expect("publisher decrypts");
            let pli = nexus_media::rtcp::PliPacket::parse(&p).expect("a PLI");
            (pli.sender_ssrc, pli.media_ssrc)
        })
        .collect()
}

#[test]
fn keyframe_requests_are_forwarded_and_throttled() {
    let mut call = call(GCM, 1);
    call.publish(1, 1, b"x");
    call.shard.io_mut().clear_outbound();
    let start = call.now;
    let own = 0x5151_5151; // the subscriber's own RTCP SSRC
    let out = call.out_ssrcs[0];
    let send = |call: &mut Call, plain: &[u8], ms: u64| {
        let request = call.subscribers[0].rtcp(plain);
        let addr = call.subscribers[0].addr;
        call.shard.io_mut().push_inbound(addr, request);
        run(&mut call.shard, at(start, ms));
    };

    // 600 ms after the Subscribe-time PLI: forwarded, from the publisher
    // session's RTCP SSRC, for the publisher's media SSRC.
    send(&mut call, &pli(own, out), 600);
    assert_eq!(
        plis_to_publisher(&mut call),
        vec![(call.publisher.base, PUB_SSRC)]
    );

    // 5 PLIs within 100 ms: one now, the other four throttled into one
    // pending request.
    for i in 0..5 {
        send(&mut call, &pli(own, out), 1_200 + 20 * i);
    }
    assert_eq!(plis_to_publisher(&mut call).len(), 1);
    let c = call.shard.counters();
    assert_eq!((c.keyframe_throttled, c.keyframe_deferred), (4, 1));
    // The pending request goes out with the track's first packet after the
    // window (1,200 + 500 ms), not before.
    call.now = at(start, 1_650);
    call.publish(2, 2, b"x");
    assert!(plis_to_publisher(&mut call).is_empty(), "inside the window");
    call.now = at(start, 1_700);
    call.publish(3, 3, b"x");
    assert_eq!(plis_to_publisher(&mut call).len(), 1, "the deferred PLI");
    call.now = at(start, 2_100);
    call.publish(4, 4, b"x");
    assert!(plis_to_publisher(&mut call).is_empty(), "sent once");

    // A FIR after the throttle: one PLI. A PLI for an SSRC the subscriber
    // does not receive: nothing.
    send(&mut call, &fir(own, out), 2_400);
    send(&mut call, &pli(own, 0x1234), 2_400);
    assert_eq!(plis_to_publisher(&mut call).len(), 1);
    // Subscribe, the forwarded PLI, the burst's first, the deferred one, the FIR.
    let c = call.shard.counters();
    assert_eq!(
        (
            c.keyframe_requests,
            c.keyframe_throttled,
            c.keyframe_deferred
        ),
        (5, 4, 1)
    );
}

#[test]
fn install_srtp_requests_one_keyframe_per_track() {
    let now = Instant::now();
    let mut shard = shard(now);
    let mut publisher = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &publisher, now);
    let (audio, video) = (TrackId::new(10), TrackId::new(11));
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track: audio,
            spec: track_spec(Some(0xA0), b"0"),
        },
    );
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track: video,
            spec: track_spec(Some(0xB0), b"1"),
        },
    );
    let mut sub = Peer::new(2, "192.0.2.2:2000", GCM);
    command(&mut shard, sub.create());
    run(&mut shard, now);
    subscribe(&mut shard, &mut sub, 1, audio, now);
    subscribe(&mut shard, &mut sub, 2, video, now);
    assert_eq!(shard.counters().keyframe_requests, 0, "no SRTP yet");

    command(&mut shard, sub.install());
    run(&mut shard, now);
    let mut media: Vec<u32> = sent_to(&mut shard, publisher.addr)
        .iter()
        .map(|b| {
            let p = publisher.open_rtcp(b).unwrap();
            nexus_media::rtcp::PliPacket::parse(&p).unwrap().media_ssrc
        })
        .collect();
    media.sort();
    assert_eq!(media, vec![0xA0, 0xB0]);
}

#[test]
fn malformed_rtcp_compounds_are_counted_and_dropped() {
    let mut call = call(GCM, 1);
    let own = 0x5151_5151;
    let mut trailing = receiver_report(own);
    trailing.extend_from_slice(&[0x80, 201, 0, 9, 0, 0, 0, 1]); // claims 40 bytes
    let seventeen: Vec<u8> = (0..17).flat_map(|_| receiver_report(own)).collect();
    for plain in [trailing, seventeen] {
        let packet = call.subscribers[0].rtcp(&plain);
        call.shard
            .io_mut()
            .push_inbound(call.subscribers[0].addr, packet);
    }
    let fine =
        call.subscribers[0].rtcp(&[receiver_report(own), nack(own, call.out_ssrcs[0], 3)].concat());
    call.shard
        .io_mut()
        .push_inbound(call.subscribers[0].addr, fine);
    run(&mut call.shard, call.now);
    assert_eq!(call.shard.counters().drop_rtcp_malformed, 2);
    assert_eq!(
        call.shard.counters().rtcp_ignored,
        2,
        "RR and NACK counted, ignored"
    );
    assert_eq!(call.shard.io().outbound_len(), 0);
}

#[test]
fn consent_lost_once_after_thirty_seconds_of_silence() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let mut peer = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &peer, t0);
    events(&mut shard);

    // Traffic at 20 s keeps it alive past 30 s.
    let rr = peer.rtcp(&receiver_report(7));
    shard.io_mut().push_inbound(peer.addr, rr);
    run(&mut shard, at(t0, 20_000));
    for s in [21, 30, 49] {
        run(&mut shard, at(t0, s * 1_000));
    }
    assert!(events(&mut shard)
        .iter()
        .all(|e| !matches!(e, Event::ConsentLost { .. })));
    for s in [51, 52, 80] {
        run(&mut shard, at(t0, s * 1_000));
    }
    let lost: Vec<_> = events(&mut shard)
        .into_iter()
        .filter(|e| matches!(e, Event::ConsentLost { .. }))
        .collect();
    assert_eq!(lost, vec![Event::ConsentLost { id: peer.id }]);
}

#[test]
fn housekeeping_publishes_stats_and_forgets_the_previous_address() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &peer, t0);
    let other: SocketAddr = "192.0.2.1:1001".parse().unwrap();
    shard
        .io_mut()
        .push_inbound(other, peer.binding_request(true));
    run(&mut shard, at(t0, 100));
    assert_eq!(shard.snapshot().addresses, 2);
    run(&mut shard, at(t0, 1_100));
    assert_eq!(shard.snapshot().addresses, 1);
    let published = shard.stats().load();
    assert_eq!(published.counters.nominations, 2);
    assert_eq!(published.gauges.sessions, 1);
}

/// A sink that refuses events beyond `room`.
struct Bounded {
    room: usize,
    events: Vec<Event>,
}

impl nexus_dataplane::EventSink for Bounded {
    fn try_send(&mut self, event: Event) -> Result<(), nexus_dataplane::Refused> {
        if self.events.len() >= self.room {
            return Err(nexus_dataplane::Refused::Full(event));
        }
        self.events.push(event);
        Ok(())
    }
}

#[test]
fn events_wait_while_the_sink_is_full_and_dtls_is_dropped() {
    let now = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 8,
        ..Default::default()
    };
    let sink = Bounded {
        room: 0,
        events: Vec::new(),
    };
    let mut shard =
        nexus_dataplane::Shard::new(config, nexus_dataplane::MemIo::new(), sink, now).unwrap();
    let peers: Vec<Peer> = (1..=3)
        .map(|n| Peer::new(n, &format!("192.0.2.{n}:1000"), GCM))
        .collect();
    for p in &peers {
        assert!(shard.push_command(p.create()).is_ok());
    }
    shard.iterate(now);
    for p in &peers {
        shard.io_mut().push_inbound(p.addr, p.binding_request(true));
        shard.io_mut().push_inbound(p.addr, vec![22, 0xFE, 0xFD, 1]);
    }
    shard.iterate(now);
    assert!(shard.events().events.is_empty());
    assert_eq!(
        shard.counters().drop_event_full,
        3,
        "DTLS dropped, not retained"
    );

    shard.events_mut().room = 10;
    shard.iterate(now);
    let ids: Vec<_> = shard
        .events()
        .events
        .iter()
        .map(|e| match e {
            Event::AddressSelected { id, .. } => *id,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        ids,
        peers.iter().map(|p| p.id).collect::<Vec<_>>(),
        "in order"
    );
}

// ---------------------------------------------------------------------------
// Review fixes: floods, lost events, switching, replays, gaps
// ---------------------------------------------------------------------------

#[test]
fn dtls_flood_is_capped_per_session_and_second() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    for _ in 0..100 {
        shard
            .io_mut()
            .push_inbound(peer.addr, vec![22, 0xFE, 0xFD, 0]);
    }
    run(&mut shard, t0);
    let dtls = |events: Vec<Event>| {
        events
            .iter()
            .filter(|e| matches!(e, Event::DtlsDatagram { .. }))
            .count()
    };
    assert_eq!(dtls(events(&mut shard)), 32);
    assert_eq!(shard.counters().drop_dtls_budget, 68);

    // The sweep refills the budget.
    run(&mut shard, at(t0, 1_000));
    shard
        .io_mut()
        .push_inbound(peer.addr, vec![22, 0xFE, 0xFD, 0]);
    run(&mut shard, at(t0, 1_000));
    assert_eq!(dtls(events(&mut shard)), 1);
}

#[test]
fn dtls_flood_is_capped_per_shard_and_second() {
    let t0 = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 64,
        dtls_budget_per_sweep: 1_000,
        ..Default::default()
    };
    let io = nexus_dataplane::MemIo::new();
    let mut shard = nexus_dataplane::Shard::new(config, io, Vec::new(), t0).expect("valid config");
    let peers: Vec<Peer> = (1..=40)
        .map(|n| Peer::new(n, &format!("192.0.2.{n}:1000"), GCM))
        .collect();
    for peer in &peers {
        command(&mut shard, peer.create());
        run(&mut shard, t0);
        let request = peer.binding_request(true);
        shard.io_mut().push_inbound(peer.addr, request);
        run(&mut shard, t0);
    }
    events(&mut shard);
    // Each session stays within its own budget of 32; together they send
    // 1,280, over the shard's 1,000.
    for peer in &peers {
        for _ in 0..32 {
            let record = vec![22, 0xFE, 0xFD, 0];
            shard.io_mut().push_inbound(peer.addr, record);
        }
    }
    run(&mut shard, t0);
    let dtls = |events: Vec<Event>| {
        events
            .iter()
            .filter(|e| matches!(e, Event::DtlsDatagram { .. }))
            .count()
    };
    assert_eq!(dtls(events(&mut shard)), 1_000);
    assert_eq!(shard.counters().drop_dtls_shard_budget, 280);
    assert_eq!(shard.counters().drop_dtls_budget, 0);

    // The sweep refills the shard's budget.
    run(&mut shard, at(t0, 1_000));
    let record = vec![22, 0xFE, 0xFD, 0];
    shard.io_mut().push_inbound(peers[39].addr, record);
    run(&mut shard, at(t0, 1_000));
    assert_eq!(dtls(events(&mut shard)), 1);
}

/// A sink whose receiver is gone.
struct Closed;

impl nexus_dataplane::EventSink for Closed {
    fn try_send(&mut self, event: Event) -> Result<(), nexus_dataplane::Refused> {
        Err(nexus_dataplane::Refused::Closed(event))
    }
}

/// A closed event channel (control plane gone) is counted apart from a full
/// one, and nothing waits in the retention queue for it.
#[test]
fn closed_event_channel_is_counted_and_not_retained() {
    let t0 = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 8,
        ..Default::default()
    };
    let io = nexus_dataplane::MemIo::new();
    let mut shard = nexus_dataplane::Shard::new(config, io, Closed, t0).unwrap();
    for n in 0..300 {
        let rejected = Command::Unsubscribe {
            sub: SubscriptionId::new(n + 1),
        };
        assert!(shard.push_command(rejected).is_ok());
    }
    for _ in 0..10 {
        shard.iterate(t0);
    }
    let counters = shard.counters();
    assert_eq!(counters.drop_event_closed, 300);
    assert_eq!(counters.drop_event_full, 0);
    assert_eq!(
        shard.park_deadline(t0),
        t0 + nexus_dataplane::shard::HOUSEKEEPING_INTERVAL
    );
}

/// Fills the shard's 256-event retention while the sink takes nothing more.
fn fill_retention(
    shard: &mut nexus_dataplane::Shard<nexus_dataplane::MemIo, Bounded>,
    now: Instant,
) {
    shard.events_mut().room = shard.events().events.len();
    for _ in 0..300 {
        let rejected = Command::Unsubscribe {
            sub: SubscriptionId::new(9),
        };
        assert!(shard.push_command(rejected).is_ok());
    }
    for _ in 0..5 {
        shard.iterate(now);
    }
}

/// Events other than the filler rejections.
fn session_events(shard: &nexus_dataplane::Shard<nexus_dataplane::MemIo, Bounded>) -> Vec<Event> {
    let events = &shard.events().events;
    events
        .iter()
        .filter(|e| !matches!(e, Event::CommandRejected { .. }))
        .cloned()
        .collect()
}

/// A parked shard wakes for retries: while events wait in the retention
/// queue it parks at most `PARK_RETRY_INTERVAL`, else until housekeeping.
#[test]
fn park_deadline_is_short_while_events_wait() {
    use nexus_dataplane::shard::{HOUSEKEEPING_INTERVAL, PARK_RETRY_INTERVAL};
    let t0 = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 8,
        ..Default::default()
    };
    let sink = Bounded {
        room: 0,
        events: Vec::new(),
    };
    let mut shard =
        nexus_dataplane::Shard::new(config, nexus_dataplane::MemIo::new(), sink, t0).unwrap();
    shard.iterate(t0);
    assert_eq!(shard.park_deadline(t0), t0 + HOUSEKEEPING_INTERVAL);
    fill_retention(&mut shard, t0);
    assert_eq!(shard.park_deadline(t0), t0 + PARK_RETRY_INTERVAL);
    // Never later than the housekeeping.
    let late = t0 + HOUSEKEEPING_INTERVAL - Duration::from_millis(1);
    assert_eq!(shard.park_deadline(late), t0 + HOUSEKEEPING_INTERVAL);
    // Drained: back to the housekeeping deadline.
    shard.events_mut().room = usize::MAX;
    shard.iterate(t0);
    assert_eq!(shard.park_deadline(t0), t0 + HOUSEKEEPING_INTERVAL);
}

#[test]
fn events_refused_by_a_full_sink_are_sent_later() {
    let t0 = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 8,
        ..Default::default()
    };
    let sink = Bounded {
        room: 0,
        events: Vec::new(),
    };
    let mut shard =
        nexus_dataplane::Shard::new(config, nexus_dataplane::MemIo::new(), sink, t0).unwrap();
    let mut peer = Peer::new(1, "192.0.2.1:1000", GCM);

    // AddressSelected and PeerSrtpVerified refused while the retention is full.
    fill_retention(&mut shard, t0);
    assert!(shard.push_command(peer.create()).is_ok());
    assert!(shard.push_command(peer.install()).is_ok());
    shard.iterate(t0); // commands run after the datagrams of an iteration
    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    shard.iterate(t0);
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
    let srtcp = peer.rtcp(&receiver_report(7));
    shard.io_mut().push_inbound(peer.addr, srtcp);
    shard.iterate(t0);
    assert!(session_events(&shard).is_empty());

    // Room again: the next authenticated packet re-sends PeerSrtpVerified,
    // the sweep re-sends AddressSelected.
    shard.events_mut().room = usize::MAX;
    shard.iterate(at(t0, 400)); // the retained backlog drains
    let srtcp = peer.rtcp(&receiver_report(7));
    shard.io_mut().push_inbound(peer.addr, srtcp);
    shard.iterate(at(t0, 500));
    shard.iterate(at(t0, 1_000));
    let verified = Event::PeerSrtpVerified { id: peer.id };
    let selected = Event::AddressSelected {
        id: peer.id,
        addr: peer.addr,
        reason: SelectReason::Nominated,
    };
    assert_eq!(
        session_events(&shard),
        vec![verified.clone(), selected.clone()]
    );

    // ConsentLost refused at 31 s, re-sent by the sweep once there is room.
    fill_retention(&mut shard, at(t0, 1_000));
    shard.iterate(at(t0, 31_000));
    assert_eq!(shard.counters().consent_lost, 0);
    shard.events_mut().room = usize::MAX;
    shard.iterate(at(t0, 31_500));
    shard.iterate(at(t0, 32_000));
    assert_eq!(shard.counters().consent_lost, 1);

    // After ConsentLost: nothing more about this session.
    let other: SocketAddr = "192.0.2.1:1001".parse().unwrap();
    shard
        .io_mut()
        .push_inbound(other, peer.binding_request(true));
    shard.iterate(at(t0, 33_000));
    shard.iterate(at(t0, 40_000));
    let lost = Event::ConsentLost { id: peer.id };
    assert_eq!(session_events(&shard), vec![verified, selected, lost]);
    assert!(shard.counters().drop_after_consent >= 1);
}

#[test]
fn address_switches_are_rate_limited() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    let (a, b): (SocketAddr, SocketAddr) = (
        "192.0.2.1:1000".parse().unwrap(),
        "192.0.2.1:1001".parse().unwrap(),
    );
    // Alternating nominations every 10 ms for 300 ms.
    for i in 0..30u64 {
        let from = if i % 2 == 0 { a } else { b };
        shard
            .io_mut()
            .push_inbound(from, peer.binding_request(true));
        run(&mut shard, at(t0, 10 * i));
    }
    let switches = events(&mut shard).len();
    assert!(switches <= 4, "{switches} switches in 300 ms");
    assert!(shard.counters().switch_throttled > 0);
}

#[test]
fn throttled_nomination_is_applied_when_the_interval_passes() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    let addr = |port: u16| -> SocketAddr { format!("192.0.2.1:{port}").parse().unwrap() };
    let nominate = |shard: &mut TestShard, from: SocketAddr, ms: u64| {
        shard
            .io_mut()
            .push_inbound(from, peer.binding_request(true));
        run(shard, at(t0, ms));
    };
    nominate(&mut shard, addr(1000), 0);
    nominate(&mut shard, addr(1001), 50);
    nominate(&mut shard, addr(1002), 70); // the latest nomination wins
    run(&mut shard, at(t0, 99));
    assert_eq!(shard.session_addr(peer.id), Some(addr(1000)));
    run(&mut shard, at(t0, 100));
    assert_eq!(shard.session_addr(peer.id), Some(addr(1002)));
    let selected: Vec<SocketAddr> = events(&mut shard)
        .into_iter()
        .map(|e| match e {
            Event::AddressSelected { addr, .. } => addr,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(selected, vec![addr(1000), addr(1002)]);

    // A later nomination of the current address cancels a pending one.
    nominate(&mut shard, addr(1003), 150);
    nominate(&mut shard, addr(1002), 160);
    run(&mut shard, at(t0, 300));
    assert_eq!(shard.session_addr(peer.id), Some(addr(1002)));
    assert!(events(&mut shard).is_empty());

    // Closing a session with a pending nomination leaves nothing behind.
    nominate(&mut shard, addr(1004), 310);
    command(&mut shard, Command::CloseSession { id: peer.id });
    run(&mut shard, at(t0, 320));
    run(&mut shard, at(t0, 500));
    assert_eq!(shard.snapshot().sessions, 0);
}

/// Nominations alternating between a new address and the current one inside the
/// switch interval list the session once. Each cancel used to leave its entry, and
/// the next throttled nomination added another, until the list's capacity assert
/// aborted the process (exit criterion 6).
#[test]
fn alternating_throttled_nominations_list_the_session_once() {
    let t0 = Instant::now();
    let config = nexus_dataplane::ShardConfig {
        pool_buffers: 512,
        max_sessions: 2,
        ..Default::default()
    };
    let io = nexus_dataplane::MemIo::new();
    let mut shard: TestShard = nexus_dataplane::Shard::new(config, io, Vec::new(), t0).unwrap();
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, t0);
    let current: SocketAddr = "192.0.2.1:1000".parse().unwrap();
    let other: SocketAddr = "192.0.2.1:2000".parse().unwrap();
    shard
        .io_mut()
        .push_inbound(current, peer.binding_request(true));
    run(&mut shard, t0);
    assert_eq!(shard.session_addr(peer.id), Some(current));

    // Pairs within the interval, ending each batch on `other` so the nomination
    // stays pending across batches (the case that piled up entries)
    for round in 0..100u64 {
        for _ in 0..2 {
            shard
                .io_mut()
                .push_inbound(current, peer.binding_request(true));
            shard
                .io_mut()
                .push_inbound(other, peer.binding_request(true));
        }
        run(&mut shard, at(t0, round * 9 / 10)); // 0..89 ms
    }
    assert_eq!(shard.session_addr(peer.id), Some(current));
    assert_eq!(shard.counters().switch_throttled, 200);

    // The pending nomination of `other` is applied once due, once
    run(&mut shard, at(t0, 100));
    run(&mut shard, at(t0, 150));
    assert_eq!(shard.session_addr(peer.id), Some(other));
    let selected = events(&mut shard)
        .into_iter()
        .filter(|e| matches!(e, Event::AddressSelected { .. }))
        .count();
    assert_eq!(
        selected, 2,
        "the first selection and the one pending switch"
    );
}

#[test]
fn replayed_nomination_does_not_move_the_session() {
    let now = Instant::now();
    let mut shard = shard(now);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    command(&mut shard, peer.create());
    run(&mut shard, now);
    let captured = peer.binding_request(true);
    shard.io_mut().push_inbound(peer.addr, captured.clone());
    run(&mut shard, now);
    events(&mut shard);

    let attacker: SocketAddr = "198.51.100.66:4000".parse().unwrap();
    shard.io_mut().push_inbound(attacker, captured);
    run(&mut shard, at(now, 5_000));
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
    assert_eq!(shard.counters().stun_repeated, 1);
    assert!(events(&mut shard).is_empty());
    assert_eq!(shard.snapshot().addresses, 1, "attacker address not mapped");
}

#[test]
fn subscription_survives_a_forwarding_gap_beyond_two_to_the_fifteen() {
    let mut call = call(GCM, 1);
    call.publish(1, 100, b"a");
    // 20,000 later, an unmapped PT: accepted inbound, not forwarded.
    let skipped = call
        .publisher
        .protect_rtp(&rtp_packet(PUB_SSRC, 20_001, 200, 96, b"b"));
    call.shard
        .io_mut()
        .push_inbound(call.publisher.addr, skipped);
    run(&mut call.shard, call.now);
    // 40,000 after the last forwarded packet: without the rebase the
    // outbound index estimate refuses this and every later packet.
    call.publish(40_001, 300, b"c");
    call.publish(40_002, 400, b"d");
    let packets = call.received().remove(0);
    assert_eq!(packets.len(), 3);
    assert_eq!(seq(&packets[1]), seq(&packets[0]).wrapping_add(1));
    assert_eq!(seq(&packets[2]), seq(&packets[0]).wrapping_add(2));
    assert_eq!(&packets[2][12..], b"d");
    assert_eq!(call.shard.counters().rebased, 1);
}

#[test]
fn previous_address_is_kept_for_the_grace_period() {
    let t0 = Instant::now();
    let mut shard = shard(t0);
    let peer = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &peer, t0);
    let other: SocketAddr = "192.0.2.1:1001".parse().unwrap();
    shard
        .io_mut()
        .push_inbound(other, peer.binding_request(true));
    run(&mut shard, at(t0, 900));
    run(&mut shard, at(t0, 1_000)); // sweep, 100 ms after the switch
    assert_eq!(shard.snapshot().addresses, 2);
    run(&mut shard, at(t0, 2_000)); // sweep, 1.1 s after
    assert_eq!(shard.snapshot().addresses, 1);
}

#[test]
fn several_srs_for_one_ssrc_in_a_compound_send_one() {
    let mut call = call(GCM, 1);
    call.publish(1, 100, b"a");
    call.shard.io_mut().clear_outbound();
    let compound: Vec<u8> = (0..5)
        .flat_map(|i| sender_report(PUB_SSRC, i, 100, 1, 1))
        .collect();
    let packet = call.publisher.rtcp(&compound);
    call.shard
        .io_mut()
        .push_inbound(call.publisher.addr, packet);
    run(&mut call.shard, call.now);
    let sent = sent_to(&mut call.shard, call.subscribers[0].addr);
    assert_eq!(sent.len(), 1);
    let sr = call.subscribers[0].open_rtcp(&sent[0]).unwrap();
    assert_eq!(
        nexus_media::rtcp::SenderReport::parse(&sr)
            .unwrap()
            .ntp_timestamp,
        4,
        "the last"
    );
}

#[test]
fn subscribe_with_colliding_extension_ids_is_rejected() {
    let mut call = call(GCM, 1);
    let out = call.subscribers[0].next_out_ssrc();
    let mut spec = sub_spec(out, call.track);
    spec.ext_map.map[2] = 1;
    spec.ext_map.mid = 1;
    let id = call.subscribers[0].id;
    command(
        &mut call.shard,
        Command::Subscribe {
            id,
            sub: SubscriptionId::new(500),
            track: call.track,
            spec,
        },
    );
    run(&mut call.shard, call.now);
    assert_eq!(
        events(&mut call.shard),
        vec![Event::CommandRejected {
            id: Some(id),
            reason: RejectReason::InvalidSpec
        }]
    );
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

fn datagram() -> impl Strategy<Value = (bool, Vec<u8>)> {
    let first = prop_oneof![0u8..=3, 20u8..=63, 128u8..=191, any::<u8>()];
    (
        any::<bool>(),
        first,
        prop::collection::vec(any::<u8>(), 0..2_048),
    )
        .prop_map(|(known, first, mut body)| {
            if !body.is_empty() {
                body[0] = first;
            }
            (known, body)
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn random_datagrams_never_panic_or_change_state(inputs in prop::collection::vec(datagram(), 1..16)) {
        let mut call = call(GCM, 2);
        let before = call.shard.snapshot();
        let addrs = [call.publisher.addr, call.subscribers[0].addr];
        let stranger: SocketAddr = "203.0.113.5:7".parse().unwrap();
        for (i, (known, bytes)) in inputs.into_iter().enumerate() {
            let from = if known { addrs[i % 2] } else { stranger };
            call.shard.io_mut().push_inbound(from, bytes);
        }
        run(&mut call.shard, call.now);
        prop_assert_eq!(call.shard.snapshot(), before);
        prop_assert_eq!(call.shard.session_addr(call.publisher.id), Some(call.publisher.addr));
        let only_dtls = events(&mut call.shard)
            .iter()
            .all(|e| matches!(e, Event::DtlsDatagram { .. }));
        prop_assert!(only_dtls);
    }
}

/// One step of the STUN fuzzer: which peer sends, from which of four addresses
/// (index 3 is shared by both peers), nominated or not, a replay of that peer's
/// previous request or a fresh one, and how many ms pass before the shard runs
/// (none: the request joins the next batch).
fn stun_step() -> impl Strategy<Value = (usize, usize, bool, bool, Option<u64>)> {
    (
        0..2usize,
        0..4usize,
        any::<bool>(),
        any::<bool>(),
        prop::option::of(0..60u64),
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Authenticated binding requests in random order, sources, nominations,
    /// replays and timing (switch throttle, rebind silence, address stealing):
    /// no panic, each session keeps an address one of its requests came from,
    /// and only `AddressSelected` events come out (exit criterion 6).
    #[test]
    fn authenticated_stun_sequences_never_panic(steps in prop::collection::vec(stun_step(), 1..200)) {
        let t0 = Instant::now();
        let config = nexus_dataplane::ShardConfig {
            pool_buffers: 512,
            max_sessions: 2,
            ..Default::default()
        };
        let io = nexus_dataplane::MemIo::new();
        let mut shard: TestShard = nexus_dataplane::Shard::new(config, io, Vec::new(), t0).unwrap();
        let peers = [
            Peer::new(1, "192.0.2.1:1000", GCM),
            Peer::new(2, "192.0.2.2:1000", GCM),
        ];
        for peer in &peers {
            command(&mut shard, peer.create());
        }
        run(&mut shard, t0);
        let addr = |peer: usize, i: usize| -> SocketAddr {
            if i == 3 {
                "198.51.100.9:4000".parse().unwrap()
            } else {
                format!("192.0.2.{}:{}", peer + 1, 1000 + i).parse().unwrap()
            }
        };
        let mut last: [Option<Vec<u8>>; 2] = [None, None];
        let mut ms = 0;
        for (peer, source, nominated, replay, dt) in steps {
            let bytes = match (&last[peer], replay) {
                (Some(previous), true) => previous.clone(),
                _ => peers[peer].binding_request(nominated),
            };
            last[peer] = Some(bytes.clone());
            shard.io_mut().push_inbound(addr(peer, source), bytes);
            if let Some(dt) = dt {
                ms += dt;
                run(&mut shard, at(t0, ms));
            }
        }
        run(&mut shard, at(t0, ms + 1_000));
        prop_assert_eq!(shard.snapshot().sessions, 2);
        for (n, peer) in peers.iter().enumerate() {
            if let Some(selected) = shard.session_addr(peer.id) {
                prop_assert!((0..4).any(|i| addr(n, i) == selected), "{selected}");
            }
        }
        let only_selected = events(&mut shard)
            .iter()
            .all(|e| matches!(e, Event::AddressSelected { .. }));
        prop_assert!(only_selected);
    }
}

/// A plaintext for the authenticated fuzzer.
#[derive(Clone, Debug)]
enum Plain {
    Rtp {
        known_ssrc: bool,
        ssrc: u32,
        pt: u8,
        marker: bool,
        step: u16,
        ts: u32,
        csrcs: Vec<u32>,
        ext: Option<(bool, Vec<u8>)>,
        padding: Option<(Vec<u8>, u8)>,
        payload: Vec<u8>,
    },
    Rtcp {
        from_publisher: bool,
        blocks: Vec<(u8, u8, Vec<u8>, bool)>,
    },
}

fn plain() -> impl Strategy<Value = Plain> {
    let pt = prop_oneof![Just(PUB_PT), Just(96u8), 0u8..128];
    let step = prop_oneof![8 => 0u16..40, 1 => any::<u16>()];
    let ext = prop::option::of((any::<bool>(), prop::collection::vec(any::<u8>(), 0..64)));
    let padding = prop::option::of((prop::collection::vec(any::<u8>(), 0..8), any::<u8>()));
    let rtp = (
        (
            prop::bool::weighted(0.8),
            any::<u32>(),
            pt,
            any::<bool>(),
            step,
            any::<u32>(),
        ),
        prop::collection::vec(any::<u32>(), 0..4),
        ext,
        padding,
        prop::collection::vec(any::<u8>(), 0..300),
    )
        .prop_map(
            |((known_ssrc, ssrc, pt, marker, step, ts), csrcs, ext, padding, payload)| Plain::Rtp {
                known_ssrc,
                ssrc,
                pt,
                marker,
                step,
                ts,
                csrcs,
                ext,
                padding,
                payload,
            },
        );
    let block_pt = prop_oneof![
        Just(200u8),
        Just(201),
        Just(202),
        Just(203),
        Just(205),
        Just(206),
        Just(207),
        any::<u8>()
    ];
    // PSFB formats 1 (PLI) and 4 (FIR) likely; lengths usually right, so
    // many compounds are well-formed and reach SR/PLI/FIR handling.
    let count = prop_oneof![Just(1u8), Just(4), 0u8..32];
    let block = (
        block_pt,
        count,
        prop::collection::vec(any::<u8>(), 4..40),
        prop::bool::weighted(0.95),
    );
    let rtcp = (any::<bool>(), prop::collection::vec(block, 1..18)).prop_map(
        |(from_publisher, blocks)| Plain::Rtcp {
            from_publisher,
            blocks,
        },
    );
    prop_oneof![3 => rtp, 1 => rtcp]
}

/// Builds the plaintext bytes. RTCP blocks get a correct length field when
/// their flag is set; every other block carries meaningful SSRCs.
fn build(plain: &Plain, seq: &mut u16, out_ssrc: u32) -> Vec<u8> {
    match plain {
        Plain::Rtp {
            known_ssrc,
            ssrc,
            pt,
            marker,
            step,
            ts,
            csrcs,
            ext,
            padding,
            payload,
        } => {
            *seq = seq.wrapping_add(*step);
            let ssrc = if *known_ssrc { PUB_SSRC } else { *ssrc };
            let mut p = rtp_packet(ssrc, *seq, *ts, *pt, &[]);
            p[0] |= csrcs.len() as u8;
            p[1] |= u8::from(*marker) << 7;
            p.extend(csrcs.iter().flat_map(|c| c.to_be_bytes()));
            if let Some((two_byte, block)) = ext {
                let mut block = block.clone();
                block.resize(block.len().div_ceil(4) * 4, 0);
                p[0] |= 0x10;
                let profile: u16 = if *two_byte { 0x1000 } else { 0xBEDE };
                p.extend_from_slice(&profile.to_be_bytes());
                p.extend_from_slice(&((block.len() / 4) as u16).to_be_bytes());
                p.extend_from_slice(&block);
            }
            p.extend_from_slice(payload);
            if let Some((bytes, count)) = padding {
                p[0] |= 0x20;
                p.extend_from_slice(bytes);
                p.push(*count);
            }
            p
        }
        Plain::Rtcp { blocks, .. } => {
            let mut p = Vec::new();
            for (i, (pt, count, body, good_len)) in blocks.iter().enumerate() {
                let mut body = body.clone();
                body.resize(body.len().div_ceil(4) * 4, 0);
                // Every other block: the publisher's SSRC as sender (an SR
                // that translates) and the subscriber's out SSRC as media
                // (PLI) and first FIR entry.
                if i % 2 == 0 && body.len() >= 12 {
                    body[0..4].copy_from_slice(&PUB_SSRC.to_be_bytes());
                    body[4..8].copy_from_slice(&out_ssrc.to_be_bytes());
                    body[8..12].copy_from_slice(&out_ssrc.to_be_bytes());
                }
                let words = if *good_len {
                    body.len() / 4
                } else {
                    usize::from(body[0])
                };
                p.extend_from_slice(&[0x80 | count, *pt]);
                p.extend_from_slice(&(words as u16).to_be_bytes());
                p.extend_from_slice(&body);
            }
            p
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Random plaintexts protected with the peers' keys: they pass SRTP and
    /// reach the RTP parser, rewrite, extension iterator and RTCP handling.
    #[test]
    fn authenticated_random_packets_never_panic_and_output_stays_valid(inputs in prop::collection::vec(plain(), 1..24)) {
        let mut call = call_with(GCM, 2, true);
        let before = call.shard.snapshot();
        let out_ssrc = call.out_ssrcs[0];
        // Past the throttle of the Subscribe-time PLI, so fuzzed PLI/FIR can
        // be forwarded; one well-formed packet first, so every case forwards.
        call.now = at(call.now, 600);
        call.publish(0, 0, b"first");
        let mut seq = 0u16;
        for input in &inputs {
            let bytes = build(input, &mut seq, out_ssrc);
            let (peer_addr, protected) = match input {
                Plain::Rtp { .. } => (call.publisher.addr, call.publisher.try_protect_rtp(&bytes)),
                Plain::Rtcp { from_publisher: true, .. } => (call.publisher.addr, call.publisher.try_protect_rtcp(&bytes)),
                Plain::Rtcp { .. } => (call.subscribers[0].addr, call.subscribers[0].try_protect_rtcp(&bytes)),
            };
            // The peer's own SRTP refuses some malformed plaintexts; send raw.
            call.shard.io_mut().push_inbound(peer_addr, protected.unwrap_or(bytes));
        }
        run(&mut call.shard, call.now);
        prop_assert_eq!(call.shard.snapshot(), before);
        prop_assert_eq!(call.shard.session_addr(call.publisher.id), Some(call.publisher.addr));
        let unexpected = events(&mut call.shard)
            .into_iter()
            .find(|e| !matches!(e, Event::DtlsDatagram { .. } | Event::PeerSrtpVerified { .. }));
        prop_assert_eq!(unexpected, None);

        // Every datagram the shard sent decrypts and parses at its receiver.
        let mut forwarded = 0;
        for (addr, bytes) in call.shard.io_mut().take_outbound() {
            let rtcp = (64..=95).contains(&(bytes[1] & 0x7F));
            let peer = if addr == call.publisher.addr {
                &mut call.publisher
            } else {
                call.subscribers.iter_mut().find(|p| p.addr == addr).expect("known peer")
            };
            if rtcp {
                let plain = peer.open_rtcp(&bytes);
                prop_assert!(plain.is_some(), "RTCP to {} does not decrypt", addr);
                prop_assert!(nexus_media::rtcp::demux_compound(&plain.unwrap()).is_ok());
            } else {
                let plain = peer.open_rtp(&bytes);
                prop_assert!(plain.is_some(), "RTP to {} does not decrypt", addr);
                let plain = plain.unwrap();
                let header = nexus_media::rtp::RtpHeader::parse(&plain);
                prop_assert!(header.is_ok(), "rewritten RTP does not parse");
                prop_assert_eq!(header.unwrap().payload_type, SUB_PT);
                forwarded += 1;
            }
        }
        prop_assert!(forwarded >= 2, "the first packet reached both subscribers");
    }
}

// ---------------------------------------------------------------------------
// Several shards on one thread (Phase 2.2): remote fan-out, mirror tracks,
// SRs and keyframe requests across shards, lending and returns
// ---------------------------------------------------------------------------

const XS_POOL: u32 = 512;

/// A track published on shard 0 with subscribers on the given shards.
struct Cross {
    shards: Vec<TestShard>,
    publisher: Peer,
    /// (shard, peer, out SSRC, subscription id).
    subs: Vec<(usize, Peer, u32, SubscriptionId)>,
    track: TrackId,
    now: Instant,
}

fn source(track: TrackId) -> TrackRef {
    TrackRef {
        shard: ShardId::new(0),
        track,
    }
}

/// `n` shards, the publisher on shard 0, one subscriber per entry of
/// `placement` (its shard). Every shard with subscribers other than 0 gets
/// one `AddRemoteShard`, as the orchestrator sends it (2.4).
fn cross(n: u8, placement: &[usize]) -> Cross {
    let now = Instant::now();
    let mut shards = mesh(n, XS_POOL, now);
    let publisher = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shards[0], &publisher, now);
    let track = TrackId::new(10);
    let spec = track_spec(Some(PUB_SSRC), b"0");
    let add = Command::AddTrack {
        id: publisher.id,
        track,
        spec,
    };
    command(&mut shards[0], add);
    run_all(&mut shards, now);
    let mut subs = Vec::new();
    for (k, &s) in placement.iter().enumerate() {
        let n = 2 + k as u64;
        let mut peer = Peer::new(n, &format!("192.0.2.{n}:2000"), GCM);
        connect(&mut shards[s], &peer, now);
        let out = peer.next_out_ssrc();
        let sub = SubscriptionId::new(100 + k as u64);
        let spec = sub_spec_from(out, source(track));
        let id = peer.id;
        command(
            &mut shards[s],
            Command::Subscribe {
                id,
                sub,
                track,
                spec,
            },
        );
        subs.push((s, peer, out, sub));
    }
    let remote: HashSet<usize> = placement.iter().copied().filter(|&s| s != 0).collect();
    for s in remote {
        let shard = ShardId::new(s as u8);
        command(&mut shards[0], Command::AddRemoteShard { track, shard });
    }
    run_all(&mut shards, now);
    for shard in &mut shards {
        shard.io_mut().clear_outbound();
        let rejected: Vec<Event> = events(shard)
            .into_iter()
            .filter(|e| matches!(e, Event::CommandRejected { .. }))
            .collect();
        assert!(rejected.is_empty(), "{rejected:?}");
    }
    Cross {
        shards,
        publisher,
        subs,
        track,
        now,
    }
}

impl Cross {
    fn publish(&mut self, seq: u16, ts: u32, payload: &[u8]) {
        let packet = self.publisher.rtp(PUB_SSRC, seq, ts, payload);
        let addr = self.publisher.addr;
        self.shards[0].io_mut().push_inbound(addr, packet);
        run_all(&mut self.shards, self.now);
    }

    /// Datagrams each shard sent since the last call.
    fn outbound(&mut self) -> Vec<Vec<(SocketAddr, Vec<u8>)>> {
        self.shards
            .iter_mut()
            .map(|s| s.io_mut().take_outbound())
            .collect()
    }

    /// Decrypted RTP each subscriber received since the last call (from its
    /// own shard only).
    fn received(&mut self) -> Vec<Vec<Vec<u8>>> {
        let out = self.outbound();
        self.subs
            .iter_mut()
            .map(|(s, peer, _, _)| {
                let addr = peer.addr;
                out[*s]
                    .iter()
                    .filter(|(a, _)| *a == addr)
                    .map(|(_, b)| peer.open_rtp(b).expect("subscriber decrypts"))
                    .collect()
            })
            .collect()
    }

    /// Sends the subscriber's RTCP compound to its shard.
    fn rtcp_from(&mut self, k: usize, plain: &[u8]) {
        let (s, peer, _, _) = &mut self.subs[k];
        let packet = peer.rtcp(plain);
        let addr = peer.addr;
        self.shards[*s].io_mut().push_inbound(addr, packet);
    }

    /// PLIs the publisher received, as (sender, media).
    fn plis_to_publisher(&mut self) -> Vec<(u32, u32)> {
        let addr = self.publisher.addr;
        let sent = sent_to(&mut self.shards[0], addr);
        sent.iter()
            .map(|b| {
                let p = self.publisher.open_rtcp(b).expect("publisher decrypts");
                let pli = nexus_media::rtcp::PliPacket::parse(&p).expect("a PLI");
                (pli.sender_ssrc, pli.media_ssrc)
            })
            .collect()
    }

    fn assert_quiet(&self) {
        for (i, shard) in self.shards.iter().enumerate() {
            let snap = shard.snapshot();
            assert_eq!(snap.pool_available, XS_POOL as usize, "shard {i} pool");
            assert_eq!(snap.xs_in_flight, 0, "shard {i} loans");
            assert!(!shard.xs_pending(), "shard {i} queues");
        }
    }
}

fn rejections(shard: &mut TestShard) -> Vec<RejectReason> {
    events(shard)
        .into_iter()
        .filter_map(|e| match e {
            Event::CommandRejected { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

#[test]
fn cross_shard_subscriber_gets_what_a_local_one_gets() {
    let mut x = cross(2, &[0, 1]);
    assert_eq!(x.shards[1].mirror(x.track), Some((ShardId::new(0), 1)));
    assert_eq!(x.shards[0].remote_shards(x.track), Some(0b10));
    let before = (*x.shards[0].counters(), *x.shards[1].counters());
    for i in 0..3u16 {
        x.publish(i, 1000 + 960 * u32::from(i), &[i as u8; 40]);
    }
    let got = x.received();
    for (k, packets) in got.iter().enumerate() {
        assert_eq!(packets.len(), 3, "subscriber {k}");
        for (i, p) in packets.iter().enumerate() {
            assert_eq!(ssrc(p), x.subs[k].2);
            assert_eq!(p[1] & 0x7F, SUB_PT);
            assert_eq!(&p[12..], &[i as u8; 40]);
        }
        assert_eq!(seq(&packets[2]).wrapping_sub(seq(&packets[0])), 2);
    }
    let (a, b) = (x.shards[0].counters(), x.shards[1].counters());
    assert_eq!(a.xs_tx - before.0.xs_tx, 3);
    assert_eq!(b.xs_rx - before.1.xs_rx, 3);
    assert_eq!(a.xs_returned - before.0.xs_returned, 3);
    x.assert_quiet();
}

#[test]
fn one_hand_off_per_shard_not_per_subscriber() {
    let mut x = cross(3, &[1, 1, 1, 2, 2]);
    let before = *x.shards[0].counters();
    for i in 0..4u16 {
        x.publish(i, 960 * u32::from(i), b"media");
    }
    assert!(x.received().iter().all(|p| p.len() == 4));
    let after = x.shards[0].counters();
    assert_eq!(after.xs_tx - before.xs_tx, 8, "4 packets × 2 shards");
    assert_eq!(
        after.tx_datagrams, before.tx_datagrams,
        "no local subscriber"
    );
    x.assert_quiet();
}

#[test]
fn sender_report_is_translated_on_the_subscribers_shard() {
    let mut x = cross(2, &[1]);
    for i in 0..3u16 {
        x.publish(i, 1000 + 960 * u32::from(i), &[0u8; 50]);
    }
    let rtp = x.received().remove(0);
    let ts_offset = ts(&rtp[0]).wrapping_sub(1000);
    let ntp = 0xDEAD_BEEF_0000_0001u64;
    let sr = x
        .publisher
        // The publisher's own counters differ from B's, so B's are checked.
        .rtcp(&sender_report(PUB_SSRC, ntp, 5000, 77, 9_999));
    let addr = x.publisher.addr;
    x.shards[0].io_mut().push_inbound(addr, sr);
    run_all(&mut x.shards, x.now);
    let (_, peer, out, _) = &mut x.subs[0];
    let sent = sent_to(&mut x.shards[1], peer.addr);
    assert_eq!(sent.len(), 1);
    let plain = peer.open_rtcp(&sent[0]).expect("subscriber decrypts SRTCP");
    let sr = nexus_media::rtcp::SenderReport::parse(&plain).unwrap();
    assert_eq!(sr.ssrc, *out);
    assert_eq!(sr.ntp_timestamp, ntp);
    assert_eq!(sr.rtp_timestamp, 5000u32.wrapping_add(ts_offset));
    assert_eq!((sr.packet_count, sr.octet_count), (3, 150), "B's counters");
    let sdes = &plain[28..];
    assert_eq!(&sdes[10..10 + sdes[9] as usize], b"publisher-cname");
    assert_eq!(x.shards[1].counters().sr_translated, 1);
    assert_eq!(x.shards[0].counters().sr_translated, 0);
}

#[test]
fn keyframe_requests_cross_shards_and_are_throttled_on_the_publisher() {
    let mut x = cross(3, &[1, 2]);
    x.publish(1, 1, b"x");
    x.outbound();
    let own = 0x5151_5151;
    x.now = at(x.now, 600);
    let out = x.subs[0].2;
    x.rtcp_from(0, &pli(own, out));
    run_all(&mut x.shards, x.now);
    let base = x.publisher.base;
    assert_eq!(x.plis_to_publisher(), vec![(base, PUB_SSRC)]);

    // Five PLIs from B and C within 100 ms after the throttle: one now, and
    // one when the window ends (with the track's next packet).
    x.now = at(x.now, 600);
    let before = *x.shards[0].counters();
    for i in 0..5 {
        let k = i % 2;
        let out = x.subs[k].2;
        x.rtcp_from(k, &pli(own, out));
        run_all(&mut x.shards, at(x.now, 20 * i as u64));
    }
    assert_eq!(x.plis_to_publisher().len(), 1);
    x.now = at(x.now, 500);
    x.publish(2, 2, b"y");
    assert_eq!(x.plis_to_publisher().len(), 1, "the deferred PLI");
    let c = x.shards[0].counters();
    assert_eq!(c.keyframe_requests - before.keyframe_requests, 2);
    assert_eq!(c.keyframe_throttled - before.keyframe_throttled, 4);
    assert_eq!(c.keyframe_deferred - before.keyframe_deferred, 1);
    assert_eq!(c.xs_keyframe_ignored, 0);
}

/// Review race: `AddRemoteShard` reaches A before B's `Subscribe`, so A's
/// keyframe arrives at B before the mirror exists (dropped), and B's own
/// request then falls inside A's throttle window. It is deferred, not
/// dropped: exactly one PLI when the window ends, even with no media (the
/// sweep sends it).
#[test]
fn a_throttled_request_from_a_new_shard_gets_a_keyframe_after_the_window() {
    let mut x = cross(2, &[]);
    let t0 = x.now;
    let (track, shard) = (x.track, ShardId::new(1));
    command(&mut x.shards[0], Command::AddRemoteShard { track, shard });
    run_all(&mut x.shards, t0);
    assert_eq!(x.plis_to_publisher().len(), 1, "AddRemoteShard's PLI");
    x.publish(1, 1, b"keyframe");
    assert_eq!(
        x.shards[1].counters().drop_xs_no_track,
        1,
        "before the mirror"
    );

    let t1 = at(t0, 100);
    let mut peer = Peer::new(2, "192.0.2.2:2000", GCM);
    connect(&mut x.shards[1], &peer, t1);
    let out = peer.next_out_ssrc();
    let sub = SubscriptionId::new(100);
    let spec = sub_spec_from(out, source(track));
    command(
        &mut x.shards[1],
        Command::Subscribe {
            id: peer.id,
            sub,
            track,
            spec,
        },
    );
    run_all(&mut x.shards, t1);
    assert!(x.plis_to_publisher().is_empty(), "inside the window");
    let c = *x.shards[0].counters();
    assert_eq!((c.keyframe_throttled, c.keyframe_deferred), (1, 1));

    // Still inside the window: nothing. Past it (the sweep runs at 1 s, no
    // packet needed): exactly one.
    run_all(&mut x.shards, at(t0, 450));
    assert!(x.plis_to_publisher().is_empty());
    run_all(&mut x.shards, at(t0, 1_100));
    assert_eq!(x.plis_to_publisher(), vec![(x.publisher.base, PUB_SSRC)]);
    run_all(&mut x.shards, at(t0, 2_200));
    assert!(x.plis_to_publisher().is_empty(), "sent once");
    let c = x.shards[0].counters();
    assert_eq!(c.keyframe_requests, 2);
    assert_eq!((c.keyframe_throttled, c.keyframe_deferred), (1, 1));
}

/// Shard 0 as a `Shard` publishing one track; shard 1's ports held by the
/// test (a scripted peer), with `AddRemoteShard` for it applied.
struct Scripted {
    shard: TestShard,
    peer: nexus_dataplane::XsPorts,
    publisher: Peer,
    now: Instant,
    seq: u16,
}

fn scripted(pool: u32) -> Scripted {
    let now = Instant::now();
    let mut shard = shard_on(ShardId::new(0), pool, now);
    let other = nexus_dataplane::BufferPool::new(ShardId::new(1), 4);
    let mut ports = XsMesh::build(&[shard.pool_region(), other.region()]);
    let peer = ports.pop().unwrap();
    shard.attach_xs(ports.pop().unwrap());
    let publisher = Peer::new(1, "192.0.2.1:1000", GCM);
    connect(&mut shard, &publisher, now);
    let track = TrackId::new(10);
    let spec = track_spec(Some(PUB_SSRC), b"0");
    command(
        &mut shard,
        Command::AddTrack {
            id: publisher.id,
            track,
            spec,
        },
    );
    let shard_1 = ShardId::new(1);
    command(
        &mut shard,
        Command::AddRemoteShard {
            track,
            shard: shard_1,
        },
    );
    run(&mut shard, now);
    assert!(rejections(&mut shard).is_empty());
    shard.io_mut().clear_outbound();
    Scripted {
        shard,
        peer,
        publisher,
        now,
        seq: 0,
    }
}

impl Scripted {
    fn publish(&mut self, count: usize) {
        for _ in 0..count {
            self.seq = self.seq.wrapping_add(1);
            let packet = self.publisher.rtp(PUB_SSRC, self.seq, 0, b"payload");
            let addr = self.publisher.addr;
            self.shard.io_mut().push_inbound(addr, packet);
        }
        run(&mut self.shard, self.now);
    }

    /// Takes every RTP hand-off in the queue, checking it reads as the
    /// publisher's packet; other messages are discarded.
    fn take(&mut self) -> Vec<nexus_dataplane::Loan> {
        let mut loans = Vec::new();
        while let Some(msg) = self.peer.recv(ShardId::new(0)) {
            if let XsMsg::Rtp { loan, len, .. } = msg {
                let bytes = self.peer.region(ShardId::new(0)).read(&loan, len.into());
                assert_eq!(ssrc(bytes), PUB_SSRC);
                loans.push(loan);
            }
        }
        loans
    }
}

#[test]
fn full_peer_queue_drops_with_credit_left_and_recovers() {
    let mut s = scripted(XS_POOL);
    // Fill the queue with SRs (no loans): the credit stays untouched.
    for i in 0..XS_RING as u64 {
        let sr = s.publisher.rtcp(&sender_report(PUB_SSRC, i, 0, 0, 0));
        let addr = s.publisher.addr;
        s.shard.io_mut().push_inbound(addr, sr);
    }
    run(&mut s.shard, s.now);
    assert_eq!(
        s.shard.counters().xs_tx,
        XS_RING as u64,
        "the queue is full"
    );
    let before = *s.shard.counters();
    s.publish(3);
    let c = s.shard.counters();
    assert_eq!(c.drop_xs_full - before.drop_xs_full, 3);
    assert_eq!(c.drop_xs_credit, 0);
    let snap = s.shard.snapshot();
    assert_eq!(
        (snap.xs_in_flight, snap.pool_available),
        (0, XS_POOL as usize)
    );

    // The peer drains: hand-offs resume without drops.
    assert!(s.take().is_empty(), "only SRs were queued");
    s.publish(2);
    let loans = s.take();
    assert_eq!(loans.len(), 2);
    assert_eq!(s.shard.counters().drop_xs_full - before.drop_xs_full, 3);
    for loan in loans {
        s.peer.give_back(loan);
    }
    s.shard.iterate(s.now);
    assert_eq!(s.shard.snapshot().pool_available, XS_POOL as usize);
}

#[test]
fn exhausted_credit_drops_and_returns_at_the_top_of_iterate_restore_it() {
    let pool = 2 * XS_CREDIT + 256;
    let mut s = scripted(pool);
    let mut held = Vec::new();
    // Hand off the whole credit while the peer keeps every loan (its queue
    // stays empty, so only the credit can refuse).
    while held.len() < XS_CREDIT as usize {
        s.publish(64.min(XS_CREDIT as usize - held.len()));
        held.extend(s.take());
    }
    assert_eq!(s.shard.snapshot().xs_in_flight, XS_CREDIT as usize);
    assert_eq!(s.shard.counters().drop_xs_credit, 0);
    s.publish(5);
    assert_eq!(s.shard.counters().drop_xs_credit, 5);
    assert_eq!(
        s.shard.snapshot().xs_in_flight,
        XS_CREDIT as usize,
        "unchanged"
    );
    assert!(s.take().is_empty());

    // Every loan back: the next iteration releases them before its batch,
    // so a burst the size of the credit goes out with no credit drop.
    for loan in held.drain(..) {
        s.peer.give_back(loan);
    }
    s.publish(64);
    assert_eq!(s.shard.counters().drop_xs_credit, 5, "no new drop");
    assert_eq!(s.shard.snapshot().xs_in_flight, 64);
    for loan in s.take() {
        s.peer.give_back(loan);
    }
    s.shard.iterate(s.now);
    let snap = s.shard.snapshot();
    assert_eq!((snap.xs_in_flight, snap.pool_available), (0, pool as usize));
}

#[test]
fn subscribe_before_add_remote_shard_gets_media_and_a_keyframe_after_it() {
    let now = Instant::now();
    let mut x = cross(2, &[]);
    x.now = now;
    let mut peer = Peer::new(2, "192.0.2.2:2000", GCM);
    connect(&mut x.shards[1], &peer, now);
    let out = peer.next_out_ssrc();
    let (track, sub) = (x.track, SubscriptionId::new(100));
    let spec = sub_spec_from(out, source(track));
    command(
        &mut x.shards[1],
        Command::Subscribe {
            id: peer.id,
            sub,
            track,
            spec,
        },
    );
    x.subs.push((1, peer, out, sub));
    run_all(&mut x.shards, now);
    // B's keyframe request arrived before B was a remote shard: ignored.
    assert_eq!(x.shards[0].counters().xs_keyframe_ignored, 1);
    assert!(x.plis_to_publisher().is_empty());
    x.publish(1, 1, b"early");
    assert!(x.received()[0].is_empty(), "not handed off yet");
    assert_eq!(x.shards[0].counters().xs_tx, 0);

    let shard = ShardId::new(1);
    command(&mut x.shards[0], Command::AddRemoteShard { track, shard });
    run_all(&mut x.shards, now);
    assert_eq!(
        x.plis_to_publisher().len(),
        1,
        "AddRemoteShard asks for a keyframe"
    );
    x.publish(2, 2, b"late");
    assert_eq!(x.received()[0].len(), 1);
    x.assert_quiet();
}

#[test]
fn hand_off_before_the_mirror_exists_is_dropped_and_returned() {
    let mut x = cross(2, &[]);
    let (track, shard) = (x.track, ShardId::new(1));
    command(&mut x.shards[0], Command::AddRemoteShard { track, shard });
    run_all(&mut x.shards, x.now);
    x.publish(1, 1, b"nobody");
    assert_eq!(x.shards[1].counters().drop_xs_no_track, 1);
    x.assert_quiet();

    // The subscription comes later (after the throttle): keyframe, media.
    x.now = at(x.now, 600);
    x.plis_to_publisher();
    let mut peer = Peer::new(2, "192.0.2.2:2000", GCM);
    connect(&mut x.shards[1], &peer, x.now);
    let out = peer.next_out_ssrc();
    let sub = SubscriptionId::new(100);
    let spec = sub_spec_from(out, source(track));
    command(
        &mut x.shards[1],
        Command::Subscribe {
            id: peer.id,
            sub,
            track,
            spec,
        },
    );
    x.subs.push((1, peer, out, sub));
    run_all(&mut x.shards, x.now);
    assert_eq!(x.plis_to_publisher().len(), 1);
    x.publish(2, 2, b"now");
    assert_eq!(x.received()[0].len(), 1);
}

#[test]
fn remove_track_on_the_publishers_shard_then_on_the_mirrors() {
    let mut x = cross(2, &[0, 1]);
    let track = x.track;
    command(&mut x.shards[0], Command::RemoveTrack { track });
    run_all(&mut x.shards, x.now);
    assert_eq!(x.shards[0].snapshot().tracks, 0);
    assert_eq!(x.shards[0].snapshot().subscriptions, 0);
    x.publish(1, 1, b"gone");
    assert_eq!(x.shards[0].counters().drop_no_route, 1);
    assert_eq!(x.shards[0].counters().xs_tx, 0);
    // The mirror stays until its own RemoveTrack (the orchestrator sends it).
    assert_eq!(x.shards[1].mirror(track), Some((ShardId::new(0), 1)));
    command(&mut x.shards[1], Command::RemoveTrack { track });
    run_all(&mut x.shards, x.now);
    let snap = x.shards[1].snapshot();
    assert_eq!((snap.mirrors, snap.subscriptions), (0, 0));
    command(&mut x.shards[1], Command::RemoveTrack { track });
    run_all(&mut x.shards, x.now);
    assert_eq!(
        rejections(&mut x.shards[1]),
        vec![RejectReason::UnknownTrack]
    );
    x.assert_quiet();
}

#[test]
fn publisher_close_session_leaves_the_mirror_to_remove_track() {
    let mut x = cross(2, &[1]);
    let track = x.track;
    command(
        &mut x.shards[0],
        Command::CloseSession { id: x.publisher.id },
    );
    run_all(&mut x.shards, x.now);
    assert_eq!(x.shards[0].snapshot().tracks, 0);
    assert_eq!(x.shards[0].remote_shards(track), None);
    command(&mut x.shards[1], Command::RemoveTrack { track });
    run_all(&mut x.shards, x.now);
    assert_eq!(x.shards[1].snapshot().mirrors, 0);
    x.assert_quiet();
}

#[test]
fn subscriber_leaves_while_hand_offs_are_in_flight() {
    let mut x = cross(2, &[1]);
    for i in 0..5u16 {
        let packet = x.publisher.rtp(PUB_SSRC, i, 0, b"in flight");
        let addr = x.publisher.addr;
        x.shards[0].io_mut().push_inbound(addr, packet);
    }
    run(&mut x.shards[0], x.now);
    assert_eq!(x.shards[0].snapshot().xs_in_flight, 5);
    let id = x.subs[0].1.id;
    command(&mut x.shards[1], Command::CloseSession { id });
    run_all(&mut x.shards, x.now);
    // Commands run before the peers' messages in an iteration.
    assert_eq!(x.shards[1].counters().drop_xs_no_track, 5);
    assert_eq!(x.shards[1].snapshot().mirrors, 0);
    x.assert_quiet();
}

#[test]
fn mirror_is_freed_with_its_last_subscription() {
    let mut x = cross(2, &[1, 1]);
    let track = x.track;
    command(&mut x.shards[1], Command::Unsubscribe { sub: x.subs[0].3 });
    run_all(&mut x.shards, x.now);
    assert_eq!(x.shards[1].mirror(track), Some((ShardId::new(0), 1)));
    command(&mut x.shards[1], Command::Unsubscribe { sub: x.subs[1].3 });
    run_all(&mut x.shards, x.now);
    assert_eq!(x.shards[1].mirror(track), None);
    assert_eq!(x.shards[1].snapshot().mirrors, 0);
}

#[test]
fn wrong_shard_and_mismatched_descriptions_are_rejected() {
    let mut x = cross(2, &[1]);
    let track = x.track;
    let mut peer = Peer::new(9, "192.0.2.9:2000", GCM);
    connect(&mut x.shards[1], &peer, x.now);
    let id = peer.id;
    let try_subscribe = |x: &mut Cross, s: usize, spec: Box<SubSpec>, n: u64| {
        let sub = SubscriptionId::new(900 + n);
        command(
            &mut x.shards[s],
            Command::Subscribe {
                id,
                sub,
                track,
                spec,
            },
        );
        run_all(&mut x.shards, x.now);
        rejections(&mut x.shards[s])
    };
    let not_a_peer = TrackRef {
        shard: ShardId::new(5),
        track,
    };
    let spec = sub_spec_from(peer.next_out_ssrc(), not_a_peer);
    assert_eq!(
        try_subscribe(&mut x, 1, spec, 1),
        vec![RejectReason::WrongShard]
    );
    let other = source(TrackId::new(11));
    let spec = sub_spec_from(peer.next_out_ssrc(), other);
    assert_eq!(
        try_subscribe(&mut x, 1, spec, 2),
        vec![RejectReason::WrongShard]
    );
    let mut spec = sub_spec_from(peer.next_out_ssrc(), source(track));
    spec.clock_rate = 90_000;
    assert_eq!(
        try_subscribe(&mut x, 1, spec, 3),
        vec![RejectReason::InvalidSpec]
    );
    assert_eq!(
        x.shards[1].mirror(track),
        Some((ShardId::new(0), 1)),
        "unchanged"
    );

    for (shard, reason) in [
        (ShardId::new(0), RejectReason::WrongShard),
        (ShardId::new(3), RejectReason::WrongShard),
    ] {
        command(&mut x.shards[0], Command::AddRemoteShard { track, shard });
        run_all(&mut x.shards, x.now);
        assert_eq!(rejections(&mut x.shards[0]), vec![reason]);
    }
    let unknown = TrackId::new(99);
    let shard = ShardId::new(1);
    command(
        &mut x.shards[0],
        Command::AddRemoteShard {
            track: unknown,
            shard,
        },
    );
    command(
        &mut x.shards[0],
        Command::RemoveRemoteShard {
            track: unknown,
            shard,
        },
    );
    run_all(&mut x.shards, x.now);
    assert_eq!(
        rejections(&mut x.shards[0]),
        vec![RejectReason::UnknownTrack, RejectReason::UnknownTrack]
    );
    assert_eq!(x.shards[0].remote_shards(track), Some(0b10), "unchanged");
}

#[test]
fn local_subscription_must_describe_the_track_as_it_was_published() {
    let mut call = call(GCM, 0);
    let mut peer = Peer::new(2, "192.0.2.2:2000", GCM);
    connect(&mut call.shard, &peer, call.now);
    let mut spec = sub_spec(peer.next_out_ssrc(), call.track);
    spec.cname = CnameValue::new(b"someone-else").unwrap();
    let (id, sub, track) = (peer.id, SubscriptionId::new(1), call.track);
    command(
        &mut call.shard,
        Command::Subscribe {
            id,
            sub,
            track,
            spec,
        },
    );
    run(&mut call.shard, call.now);
    assert_eq!(rejections(&mut call.shard), vec![RejectReason::InvalidSpec]);
    // Without a mesh, a track of another shard cannot be subscribed to.
    let remote = TrackRef {
        shard: ShardId::new(1),
        track,
    };
    let spec = sub_spec_from(peer.next_out_ssrc(), remote);
    command(
        &mut call.shard,
        Command::Subscribe {
            id,
            sub,
            track,
            spec,
        },
    );
    run(&mut call.shard, call.now);
    assert_eq!(rejections(&mut call.shard), vec![RejectReason::WrongShard]);
}

// ---------------------------------------------------------------------------
// Three shards, random operations (Phase 2 exit criterion 6)
// ---------------------------------------------------------------------------

/// A participant or control-plane operation; indices pick among what exists
/// (modulo), so every sequence is meaningful.
#[derive(Clone, Debug)]
enum XsOp {
    Publish(u8),
    Subscribe(u8, u8),
    Unsubscribe(u8),
    Unpublish(u8),
    Leave(u8),
    Rtp(u8),
    Sr(u8),
    Pli(u8),
    /// Hand up to n queued commands to a shard.
    Deliver(u8, u8),
    /// One iteration of a shard.
    Iterate(u8),
}

fn xs_op() -> impl Strategy<Value = XsOp> {
    prop_oneof![
        2 => any::<u8>().prop_map(XsOp::Publish),
        4 => (any::<u8>(), any::<u8>()).prop_map(|(s, t)| XsOp::Subscribe(s, t)),
        1 => any::<u8>().prop_map(XsOp::Unsubscribe),
        1 => any::<u8>().prop_map(XsOp::Unpublish),
        1 => any::<u8>().prop_map(XsOp::Leave),
        4 => any::<u8>().prop_map(XsOp::Rtp),
        1 => any::<u8>().prop_map(XsOp::Sr),
        1 => any::<u8>().prop_map(XsOp::Pli),
        4 => (any::<u8>(), 1..16u8).prop_map(|(s, n)| XsOp::Deliver(s, n)),
        4 => any::<u8>().prop_map(XsOp::Iterate),
    ]
}

const XS_SHARDS: usize = 3;
const XS_PEOPLE: usize = 6;

struct ModelTrack {
    id: TrackId,
    owner: usize,
    ssrc: u32,
    seq: u16,
    live: bool,
}

struct ModelSub {
    id: SubscriptionId,
    who: usize,
    track: usize,
    out: u32,
    live: bool,
}

/// The shards and a small model of the orchestrator's counting rule (plan
/// 2.4): per (track, shard other than the track's), the live subscriptions;
/// `AddRemoteShard` on 0 → 1, `RemoveRemoteShard` on 1 → 0, `RemoveTrack` to
/// every counted shard on unpublish. Commands wait in one FIFO per shard and
/// are delivered in a random interleaving.
struct Model {
    shards: Vec<TestShard>,
    people: Vec<(Peer, usize, bool)>,
    subs_ever: Vec<usize>,
    tracks: Vec<ModelTrack>,
    subs: Vec<ModelSub>,
    counts: std::collections::HashMap<(usize, usize), u32>,
    queues: Vec<std::collections::VecDeque<Command>>,
    now: Instant,
}

impl Model {
    fn new() -> Self {
        let now = Instant::now();
        let mut shards = mesh(XS_SHARDS as u8, XS_POOL, now);
        let people = (0..XS_PEOPLE)
            .map(|i| {
                let n = 1 + i as u64;
                let peer = Peer::new(n, &format!("192.0.2.{n}:1000"), GCM);
                let shard = i % XS_SHARDS;
                connect(&mut shards[shard], &peer, now);
                (peer, shard, true)
            })
            .collect();
        Self {
            shards,
            people,
            subs_ever: vec![0; XS_PEOPLE],
            tracks: Vec::new(),
            subs: Vec::new(),
            counts: Default::default(),
            queues: (0..XS_SHARDS).map(|_| Default::default()).collect(),
            now,
        }
    }

    fn live_tracks(&self) -> Vec<usize> {
        (0..self.tracks.len())
            .filter(|&t| self.tracks[t].live)
            .collect()
    }

    fn live_subs(&self) -> Vec<usize> {
        (0..self.subs.len())
            .filter(|&k| self.subs[k].live)
            .collect()
    }

    fn pick<T: Copy>(items: &[T], i: u8) -> Option<T> {
        (!items.is_empty()).then(|| items[usize::from(i) % items.len()])
    }

    fn apply(&mut self, op: XsOp) {
        match op {
            XsOp::Publish(p) => self.publish(usize::from(p) % XS_PEOPLE),
            XsOp::Subscribe(s, t) => {
                if let Some(t) = Self::pick(&self.live_tracks(), t) {
                    self.subscribe(usize::from(s) % XS_PEOPLE, t);
                }
            }
            XsOp::Unsubscribe(k) => {
                if let Some(k) = Self::pick(&self.live_subs(), k) {
                    let (who, id) = (self.subs[k].who, self.subs[k].id);
                    self.queues[self.people[who].1].push_back(Command::Unsubscribe { sub: id });
                    self.sub_ended(k);
                }
            }
            XsOp::Unpublish(t) => {
                if let Some(t) = Self::pick(&self.live_tracks(), t) {
                    let owner = self.people[self.tracks[t].owner].1;
                    let track = self.tracks[t].id;
                    self.queues[owner].push_back(Command::RemoveTrack { track });
                    self.track_ended(t);
                }
            }
            XsOp::Leave(p) => self.leave(usize::from(p) % XS_PEOPLE),
            XsOp::Rtp(t) => self.media(t, false),
            XsOp::Sr(t) => self.media(t, true),
            XsOp::Pli(k) => {
                if let Some(k) = Self::pick(&self.live_subs(), k) {
                    let (who, out) = (self.subs[k].who, self.subs[k].out);
                    let (peer, shard, _) = &mut self.people[who];
                    let packet = peer.rtcp(&pli(0x5151_5151, out));
                    let addr = peer.addr;
                    self.shards[*shard].io_mut().push_inbound(addr, packet);
                }
            }
            XsOp::Deliver(s, n) => {
                let s = usize::from(s) % XS_SHARDS;
                for _ in 0..n {
                    let Some(c) = self.queues[s].pop_front() else {
                        break;
                    };
                    command(&mut self.shards[s], c);
                }
            }
            XsOp::Iterate(s) => {
                self.now = at(self.now, 7);
                self.shards[usize::from(s) % XS_SHARDS].iterate(self.now);
            }
        }
    }

    fn publish(&mut self, p: usize) {
        let mine = self
            .tracks
            .iter()
            .filter(|t| t.live && t.owner == p)
            .count();
        if !self.people[p].2 || mine >= 3 {
            return;
        }
        let n = self.tracks.len() as u64 + 1;
        let (id, ssrc) = (TrackId::new(n), 0xC000_0000 + n as u32);
        let spec = track_spec(Some(ssrc), format!("{n}").as_bytes());
        let (peer, shard, _) = &self.people[p];
        let add = Command::AddTrack {
            id: peer.id,
            track: id,
            spec,
        };
        self.queues[*shard].push_back(add);
        self.tracks.push(ModelTrack {
            id,
            owner: p,
            ssrc,
            seq: 0,
            live: true,
        });
    }

    fn subscribe(&mut self, who: usize, t: usize) {
        let owner = self.tracks[t].owner;
        let taken = self
            .subs
            .iter()
            .any(|s| s.live && s.who == who && s.track == t);
        if who == owner || !self.people[who].2 || taken || self.subs_ever[who] >= 20 {
            return;
        }
        self.subs_ever[who] += 1;
        let (from, track) = (self.people[owner].1, self.tracks[t].id);
        let id = SubscriptionId::new(1_000 + self.subs.len() as u64);
        let (peer, shard, _) = &mut self.people[who];
        let (shard, out) = (*shard, peer.next_out_ssrc());
        let source = TrackRef {
            shard: ShardId::new(from as u8),
            track,
        };
        let spec = sub_spec_from(out, source);
        let sub = Command::Subscribe {
            id: peer.id,
            sub: id,
            track,
            spec,
        };
        self.queues[shard].push_back(sub);
        self.subs.push(ModelSub {
            id,
            who,
            track: t,
            out,
            live: true,
        });
        if shard != from {
            let count = self.counts.entry((t, shard)).or_insert(0);
            *count += 1;
            if *count == 1 {
                let shard = ShardId::new(shard as u8);
                self.queues[from].push_back(Command::AddRemoteShard { track, shard });
            }
        }
    }

    /// A subscription ends (Unsubscribe or its subscriber left).
    fn sub_ended(&mut self, k: usize) {
        self.subs[k].live = false;
        let (t, shard) = (self.subs[k].track, self.people[self.subs[k].who].1);
        let from = self.people[self.tracks[t].owner].1;
        if shard == from {
            return;
        }
        let count = self.counts.get_mut(&(t, shard)).expect("counted");
        *count -= 1;
        if *count == 0 {
            self.counts.remove(&(t, shard));
            let (track, shard) = (self.tracks[t].id, ShardId::new(shard as u8));
            self.queues[from].push_back(Command::RemoveRemoteShard { track, shard });
        }
    }

    /// A track ends: `RemoveTrack` to every counted shard; its subscriptions
    /// end without `Unsubscribe` (the orchestrator's `forget_tracks`).
    fn track_ended(&mut self, t: usize) {
        self.tracks[t].live = false;
        for s in 0..XS_SHARDS {
            if self.counts.remove(&(t, s)).is_some() {
                let track = self.tracks[t].id;
                self.queues[s].push_back(Command::RemoveTrack { track });
            }
        }
        for sub in self.subs.iter_mut().filter(|s| s.track == t) {
            sub.live = false;
        }
    }

    /// At most two participants leave, so the others keep the case busy.
    fn leave(&mut self, p: usize) {
        let left = self.people.iter().filter(|(_, _, alive)| !alive).count();
        if !self.people[p].2 || left >= 2 {
            return;
        }
        for k in self.live_subs() {
            if self.subs[k].who == p {
                self.sub_ended(k);
            }
        }
        for t in self.live_tracks() {
            if self.tracks[t].owner == p {
                self.track_ended(t);
            }
        }
        self.people[p].2 = false;
        let (peer, shard, _) = &self.people[p];
        self.queues[*shard].push_back(Command::CloseSession { id: peer.id });
    }

    fn media(&mut self, t: u8, sr: bool) {
        let Some(t) = Self::pick(&self.live_tracks(), t) else {
            return;
        };
        let track = &mut self.tracks[t];
        track.seq = track.seq.wrapping_add(1);
        let (ssrc, seq) = (track.ssrc, track.seq);
        let (peer, shard, _) = &mut self.people[track.owner];
        let packet = match sr {
            true => peer.rtcp(&sender_report(
                ssrc,
                u64::from(seq),
                960 * u32::from(seq),
                1,
                5,
            )),
            false => peer.rtp(ssrc, seq, 960 * u32::from(seq), b"media"),
        };
        let addr = peer.addr;
        self.shards[*shard].io_mut().push_inbound(addr, packet);
    }

    /// Delivers what is left, drains every shard, then checks: no leaked
    /// buffer or loan, and every shard agrees with the model.
    fn check_quiescent(&mut self) -> Result<(), TestCaseError> {
        for s in 0..XS_SHARDS {
            // Far below the queue's capacity (< 200 operations).
            while let Some(c) = self.queues[s].pop_front() {
                command(&mut self.shards[s], c);
            }
        }
        run_all(&mut self.shards, self.now);
        for (s, shard) in self.shards.iter_mut().enumerate() {
            let snap = shard.snapshot();
            prop_assert_eq!(snap.pool_available, XS_POOL as usize, "shard {} pool", s);
            prop_assert_eq!(snap.xs_in_flight, 0, "shard {} loans", s);
            // The model sends commands in the orchestrator's order per shard:
            // an add before the track's removal on its shard, `RemoveTrack`
            // only to shards with subscriptions (so with a mirror), cleanup
            // only for live ids. Nothing is ever rejected.
            let rejected = rejections(shard);
            prop_assert!(rejected.is_empty(), "shard {}: {:?}", s, rejected);
        }
        for (t, track) in self.tracks.iter().enumerate() {
            let owner = self.people[track.owner].1;
            let mask: u64 = (0..XS_SHARDS)
                .filter(|&s| self.counts.contains_key(&(t, s)))
                .map(|s| 1 << s)
                .sum();
            let expected = track.live.then_some(mask);
            prop_assert_eq!(
                self.shards[owner].remote_shards(track.id),
                expected,
                "track {}",
                t
            );
            for s in (0..XS_SHARDS).filter(|&s| s != owner) {
                let subs = self
                    .subs
                    .iter()
                    .filter(|k| k.live && k.track == t && self.people[k.who].1 == s)
                    .count();
                let expected = (subs > 0).then_some((ShardId::new(owner as u8), subs));
                prop_assert_eq!(
                    self.shards[s].mirror(track.id),
                    expected,
                    "track {} on {}",
                    t,
                    s
                );
            }
        }
        for s in 0..XS_SHARDS {
            let subs = self
                .subs
                .iter()
                .filter(|k| k.live && self.people[k.who].1 == s);
            prop_assert_eq!(
                self.shards[s].snapshot().subscriptions,
                subs.count(),
                "shard {}",
                s
            );
        }
        self.check_final_media()
    }

    /// Every live track sends one packet marked with its id: each live
    /// subscription gets exactly its track's, with its own SSRC, whichever
    /// shard it is on; afterwards nothing is lent or leaked.
    fn check_final_media(&mut self) -> Result<(), TestCaseError> {
        for shard in &mut self.shards {
            shard.io_mut().clear_outbound();
        }
        for t in self.live_tracks() {
            let track = &mut self.tracks[t];
            track.seq = track.seq.wrapping_add(1);
            let marker = track.id.get().to_be_bytes();
            let (peer, shard, _) = &mut self.people[track.owner];
            let packet = peer.rtp(track.ssrc, track.seq, 0, &marker);
            let addr = peer.addr;
            self.shards[*shard].io_mut().push_inbound(addr, packet);
        }
        run_all(&mut self.shards, self.now);
        let out: Vec<_> = self
            .shards
            .iter_mut()
            .map(|s| s.io_mut().take_outbound())
            .collect();
        for who in 0..XS_PEOPLE {
            let mut expected: Vec<(u32, u64)> = self
                .subs
                .iter()
                .filter(|k| k.live && k.who == who)
                .map(|k| (k.out, self.tracks[k.track].id.get()))
                .collect();
            let (peer, shard, _) = &mut self.people[who];
            let (addr, mut got) = (peer.addr, Vec::new());
            for (_, bytes) in out[*shard].iter().filter(|(a, _)| *a == addr) {
                if (64..=95).contains(&(bytes[1] & 0x7F)) {
                    continue; // RTCP (SRs, PLIs)
                }
                let p = peer.open_rtp(bytes).expect("subscriber decrypts");
                let marker = u64::from_be_bytes(p[12..20].try_into().unwrap());
                got.push((ssrc(&p), marker));
            }
            expected.sort_unstable();
            got.sort_unstable();
            prop_assert_eq!(got, expected, "participant {}", who);
        }
        for (s, shard) in self.shards.iter().enumerate() {
            let snap = shard.snapshot();
            prop_assert_eq!(snap.pool_available, XS_POOL as usize, "shard {} pool", s);
            prop_assert_eq!(snap.xs_in_flight, 0, "shard {} loans", s);
        }
        Ok(())
    }
}

/// Cases the proptest runs.
const XS_CASES: u32 = 128;

/// The runner is written out (not `proptest!`) so the test can also check,
/// after all cases, that enough of them handed packets across shards and
/// ended with mirrors: the checks above would pass vacuously otherwise.
#[test]
fn three_shards_agree_with_the_orchestrator_model_and_leak_nothing() {
    use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
    let (handed_off, mirrored) = (AtomicU32::new(0), AtomicU32::new(0));
    let config = ProptestConfig {
        cases: XS_CASES,
        ..ProptestConfig::default()
    };
    let mut runner = proptest::test_runner::TestRunner::new(config);
    let ops = prop::collection::vec(xs_op(), 1..200);
    let result = runner.run(&ops, |ops| {
        let mut model = Model::new();
        for op in ops {
            model.apply(op);
        }
        let xs_tx: u64 = model.shards.iter().map(|s| s.counters().xs_tx).sum();
        model.check_quiescent()?;
        // At quiescence, where the model check applies.
        let mirrors: usize = model.shards.iter().map(|s| s.snapshot().mirrors).sum();
        handed_off.fetch_add(u32::from(xs_tx > 0), Relaxed);
        mirrored.fetch_add(u32::from(mirrors > 0), Relaxed);
        Ok(())
    });
    if let Err(error) = result {
        panic!("{error}");
    }
    // Measured ≈ 75% and ≈ 50-60% (random seeds); an eighth is far below.
    let (handed_off, mirrored) = (handed_off.into_inner(), mirrored.into_inner());
    eprintln!("{handed_off} of {XS_CASES} cases handed off, {mirrored} ended with mirrors");
    assert!(
        handed_off >= XS_CASES / 8,
        "{handed_off} cases with hand-offs"
    );
    assert!(mirrored >= XS_CASES / 8, "{mirrored} cases with mirrors");
}
