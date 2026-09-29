//! End-to-end tests: the SFU started in-process (`nexus_sfu::server::start`)
//! on ephemeral ports, driven by real WebRTC clients (webrtc-rs, from
//! `nexus-loadtest`) over WebSocket signaling. Assertions are made on what
//! the clients receive.
//!
//! ```bash
//! cargo test --test e2e
//! RUST_LOG=nexus_sfu=debug cargo test --test e2e -- --nocapture
//! ```
//!
//! Every later phase adds its exit checks here. Loss is injected on a
//! client's own socket (`nexus_loadtest::lossy`), so every packet between
//! that client and the SFU passes through it.

#[path = "e2e/harness.rs"]
mod harness;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use harness::*;
use nexus_loadtest::client::HeadlessClient;
use nexus_loadtest::config::ConnectionOptions;
use nexus_loadtest::error::SignalingError;
use nexus_loadtest::lossy::{Direction, LossRule, LossRules, PacketClass, SrtcpLayout, TapEntry};
use nexus_loadtest::rtcp_log::ntp_to_system_time;
use nexus_loadtest::signaling::{mint_token, SignalingConnection};
use nexus_loadtest::{Announced, RemoteTrack, TrackRxStats};
use nexus_sfu::nexus_transport::dtls::DtlsRole;
use nexus_sfu::nexus_transport::srtp::ProtectionProfile;
use nexus_sfu::signal::SignalMessage;
use webrtc::dtls_transport::dtls_role::DTLSRole;

/// How long media is measured in `two_party_audio_video`.
const MEDIA_WINDOW: Duration = Duration::from_secs(5);

/// A and B each publish audio + video and receive the other's two tracks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_party_audio_video() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    // A answers a=setup:active (the SFU is the DTLS server, as with browsers); B
    // keeps webrtc-rs's default against an ICE-lite offer, passive (the SFU is the
    // DTLS client).
    let a_config = nexus_loadtest::ClientConfig {
        answering_dtls_role: Some(DTLSRole::Client),
        ..client_config(&server, "two-party")
    };
    let mut a = HeadlessClient::new(a_config).await.unwrap();
    let mut b = HeadlessClient::new(client_config(&server, "two-party"))
        .await
        .unwrap();
    a.connect().await.expect("A connects");
    a.start_publishing().await.expect("A publishes");
    b.connect().await.expect("B connects");
    b.start_publishing().await.expect("B publishes");

    let a_tracks = a.discover_and_subscribe(STEP_TIMEOUT).await.unwrap();
    let b_tracks = b.discover_and_subscribe(STEP_TIMEOUT).await.unwrap();
    assert_eq!(a_tracks.len(), 2, "A sees B's audio and video");
    assert_eq!(b_tracks.len(), 2, "B sees A's audio and video");

    // Let media start, then measure a fixed window.
    wait_for_tracks(&a, &b, 2, STEP_TIMEOUT).await;
    let (a_before, b_before) = (a.track_stats(), b.track_stats());
    tokio::time::sleep(MEDIA_WINDOW).await;
    let (a_after, b_after) = (a.track_stats(), b.track_stats());

    // Each side receives exactly the other's streams: not its own echoed back,
    // not a mix. The SFU rewrites SSRCs (note §9.3): what arrives is what its
    // offer announced, never the publisher's own SSRC, and each announced SSRC
    // carries the payload of one publisher track of the same kind (its marker).
    let (a_sent, b_sent) = (a.published_ssrcs().await, b.published_ssrcs().await);
    assert_eq!(a_sent.len(), 2, "A publishes audio and video: {a_sent:?}");
    assert_eq!(b_sent.len(), 2, "B publishes audio and video: {b_sent:?}");
    let a_expected = expected_streams(&a, &b).await;
    let b_expected = expected_streams(&b, &a).await;
    for ssrc in a_expected.keys() {
        assert!(!b_sent.contains(ssrc), "SSRC {ssrc:#x} is not rewritten");
    }
    for ssrc in b_expected.keys() {
        assert!(!a_sent.contains(ssrc), "SSRC {ssrc:#x} is not rewritten");
    }
    check_received("A", &a_before, &a_after, &a_expected);
    check_received("B", &b_before, &b_after, &b_expected);

    // Both DTLS roles, AES-GCM negotiated (note §9: GCM first).
    let established = server.established();
    let role_of = |client: &HeadlessClient| {
        let id = client.participant_id().expect("joined");
        let session = established.iter().find(|e| e.participant == id);
        session.unwrap_or_else(|| panic!("no DTLS session for {id}: {established:?}"))
    };
    let (a_dtls, b_dtls) = (role_of(&a), role_of(&b));
    assert_eq!(a_dtls.role, DtlsRole::Server, "A answered active");
    assert_eq!(
        b_dtls.role,
        DtlsRole::Client,
        "B answered passive (ICE-lite default)"
    );
    assert_eq!(
        a_dtls.profile,
        ProtectionProfile::AeadAes128Gcm,
        "{a_dtls:?}"
    );
    assert_eq!(
        b_dtls.profile,
        ProtectionProfile::AeadAes128Gcm,
        "{b_dtls:?}"
    );

    // The media went through the shard (stats are published every second).
    let shard = server.dataplane().stats(nexus_dataplane::ShardId::new(0));
    assert!(shard.counters.tx_datagrams > 0, "{shard:?}");
    assert_eq!(shard.counters.drop_dtls_unselected, 0, "{shard:?}");
    assert_eq!(shard.counters.commands_rejected, 0, "{shard:?}");

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}

/// For each SSRC the SFU's latest offer to `receiver` announces: the m-line's kind
/// and the SSRC `publisher` publishes that kind under (what the payload marker names).
async fn expected_streams(
    receiver: &HeadlessClient,
    publisher: &HeadlessClient,
) -> BTreeMap<u32, (String, u32)> {
    let announced = receiver.announced_ssrcs();
    assert_eq!(
        announced.len(),
        2,
        "offered the peer's two tracks: {announced:?}"
    );
    let mut expected = BTreeMap::new();
    for a in announced {
        assert!(a.track_id.is_some(), "m-line {} not in Offer.tracks", a.mid);
        let published = publisher
            .published_ssrc(a.kind == "video")
            .await
            .expect("publisher SSRC");
        expected.insert(a.ssrc, (a.kind, published));
    }
    expected
}

async fn wait_for_tracks(a: &HeadlessClient, b: &HeadlessClient, n: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if a.track_stats().len() >= n && b.track_stats().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "media did not start: A has {:?}, B has {:?}",
        a.track_stats(),
        b.track_stats()
    );
}

/// Per received track over the window: packets arrive at a plausible rate,
/// sequence numbers are continuous, timestamps advance, and the SSRC stays
/// the same (exactly one stream per announced SSRC, no new SSRCs). The arriving
/// SSRCs are the keys of `expected`; each carries the kind and the publisher SSRC
/// its payload markers must name, unchanged.
fn check_received(
    who: &str,
    before: &[nexus_loadtest::TrackRxStats],
    after: &[nexus_loadtest::TrackRxStats],
    expected: &BTreeMap<u32, (String, u32)>,
) {
    let received: BTreeSet<u32> = after.iter().map(|t| t.ssrc).collect();
    let wanted: BTreeSet<u32> = expected.keys().copied().collect();
    assert_eq!(
        received, wanted,
        "{who}: must receive exactly the peer's streams"
    );
    assert_eq!(
        after.len(),
        expected.len(),
        "{who}: exactly the announced SSRCs received: {after:?}"
    );

    let window = MEDIA_WINDOW.as_secs();
    for track in after {
        let received = delta(before, track);
        // The loadtest sender paces both tracks at 15 frames/s: at least one
        // video packet per frame and one audio packet per frame. Accept 2/3.
        let min = 10 * window;
        assert!(
            received >= min,
            "{who}: {} track {:#x}: {received} packets in {window}s, want >= {min}",
            track.kind,
            track.ssrc
        );
        let span = track.expected_packets();
        assert!(
            track.missing_packets() * 100 <= span,
            "{who}: {} track lost {} of {span} packets on loopback",
            track.kind,
            track.missing_packets()
        );
        assert_eq!(track.timestamp_regressions, 0, "{who}: {track:?}");
        assert!(track.markers > 0, "{who}: no payload marker: {track:?}");
        assert_eq!(track.marker_mismatches, 0, "{who}: {track:?}");
        assert_eq!(track.marker_regressions, 0, "{who}: {track:?}");
        let (kind, publisher) = &expected[&track.ssrc];
        assert_eq!(&track.kind, kind, "{who}: {track:?}");
        assert_eq!(
            track.marker_ssrc,
            Some(*publisher),
            "{who}: SSRC {:#x} must carry publisher SSRC {publisher:#x}",
            track.ssrc
        );
        assert_ne!(
            track.last_timestamp, track.first_timestamp,
            "{who}: {track:?}"
        );
    }
}

/// The SFU's ICE candidates carry the announced IP and the bound media
/// port, never an unspecified address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn candidate_is_announced_address() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;
    let expected = std::net::SocketAddr::new(announced_ip(), server.media_addrs()[0].port());
    assert_eq!(server.candidate_addrs(), &[expected]);

    let options = client_config(&server, "candidates").connection;
    let mut sig = SignalingConnection::connect_with_timeout(
        &ws_url(&server),
        &options,
        "cand",
        "candidates",
        STEP_TIMEOUT,
    )
    .await
    .expect("signaling connects");
    sig.send(SignalMessage::Create {
        room_name: Some("candidates".to_string()),
    })
    .await
    .unwrap();
    let room_id = tokio::time::timeout(STEP_TIMEOUT, async {
        loop {
            if let SignalMessage::Created { room_id, .. } = sig.recv().await.unwrap() {
                break room_id;
            }
        }
    })
    .await
    .expect("SFU answers Create");
    sig.join_room(room_id, "cand").await.expect("joins");
    sig.send(SignalMessage::Publish {
        kinds: vec!["audio".to_string()],
        contents: vec!["audio".to_string()],
    })
    .await
    .unwrap();

    let mut candidates = Vec::new();
    let deadline = Instant::now() + STEP_TIMEOUT;
    while candidates.is_empty() && Instant::now() < deadline {
        let msg = tokio::time::timeout(STEP_TIMEOUT, sig.recv())
            .await
            .expect("SFU sends candidates")
            .unwrap();
        if let SignalMessage::IceCandidate { candidate, .. } = msg {
            candidates.push(parse_candidate(&candidate).expect("parsable candidate"));
        }
    }
    assert!(!candidates.is_empty(), "no candidate trickled");
    for (addr, typ) in &candidates {
        assert!(!addr.ip().is_unspecified(), "unspecified candidate {addr}");
        assert_eq!(*addr, expected);
        assert_eq!(typ, "host");
    }

    drop(sig);
    server.shutdown().await.expect("clean shutdown");
}

/// `step`'s result, or a panic naming it after `STEP_TIMEOUT`.
async fn within<T>(what: &str, step: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(STEP_TIMEOUT, step)
        .await
        .unwrap_or_else(|_| panic!("{what}: no reply within {STEP_TIMEOUT:?}"))
}

/// Phase 1.9a, the owner's reproduction: a token for room "alpha" cannot reach room
/// "beta" by id or by name, a token without a `rooms` claim reaches no room, and a
/// `"*"` token reaches every room. Signaling only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn room_claim_confines_create_and_join() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;
    let connect = |subject: &'static str, rooms: &'static [&'static str]| {
        let url = ws_url(&server);
        async move {
            let token = mint_token(JWT_SECRET, subject, rooms, 600).expect("mints");
            let options = ConnectionOptions {
                auth_token: Some(token),
                ..Default::default()
            };
            SignalingConnection::connect_with_timeout(&url, &options, subject, "", STEP_TIMEOUT)
                .await
                .expect("authenticates: the rooms claim does not gate the handshake")
        }
    };
    let mut a = connect("alice", &["alpha"]).await;
    let alpha = within("Create", a.create_room("alpha"))
        .await
        .expect("alpha");
    within("Join", a.join_room(alpha, "alice"))
        .await
        .expect("joins alpha");

    let mut b = connect("bob", &["beta"]).await;
    let by_name = within("Create", b.create_room("alpha")).await;
    assert!(
        matches!(by_name, Err(SignalingError::Forbidden(_))),
        "{by_name:?}"
    );
    let by_id = within("Join", b.join_room(alpha, "bob")).await;
    assert!(
        matches!(by_id, Err(SignalingError::Forbidden(_))),
        "{by_id:?}"
    );
    let beta = within("Create", b.create_room("beta")).await.expect("beta");
    assert_ne!(beta, alpha, "a new room, not alpha under another name");
    within("Join", b.join_room(beta, "bob"))
        .await
        .expect("joins beta");

    let mut c = connect("carol", &[]).await;
    let create = within("Create", c.create_room("gamma")).await;
    assert!(
        matches!(create, Err(SignalingError::Forbidden(_))),
        "{create:?}"
    );
    let join = within("Join", c.join_room(alpha, "carol")).await;
    assert!(
        matches!(join, Err(SignalingError::Forbidden(_))),
        "{join:?}"
    );

    let mut d = connect("dave", &["*"]).await;
    let joined = within("Join", d.join_room(alpha, "dave"))
        .await
        .expect("any room");
    assert_eq!(joined.room_id, alpha);
    assert_eq!(
        joined.participants.len(),
        1,
        "alice only: no ghost from bob or carol"
    );
}

/// The client takes the DTLS server role (answer `a=setup:passive`), so the
/// SFU is the DTLS client, and the SFU's first flight (ClientHello) is lost.
/// The call connects only if the SFU retransmits (OpenSSL's timer, 1 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dtls_survives_lost_first_flight() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    let rules = LossRules::new();
    rules.add(LossRule::first(Direction::Inbound, PacketClass::Dtls, 1));
    let config = nexus_loadtest::ClientConfig {
        answering_dtls_role: Some(DTLSRole::Server),
        ..lossy_client_config(&server, "dtls-loss", &rules)
    };
    let mut client = HeadlessClient::new(config).await.unwrap();
    client.connect().await.expect("connects");
    let start = Instant::now();
    client.start_publishing().await.expect("ICE connects");

    // ICE is up; DTLS completes once the SFU resends its ClientHello
    // (OpenSSL's first timeout is 1 s, polled every 200 ms).
    let deadline = start + Duration::from_secs(3);
    while !client.is_connected() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let elapsed = start.elapsed();
    assert!(
        client.is_connected(),
        "DTLS did not complete in {elapsed:?}"
    );
    assert_eq!(
        rules.dropped_by_rule(),
        vec![1],
        "the first flight was dropped"
    );
    // Prove the SFU was the DTLS client: what was dropped is its ClientHello
    // (record type 22 = handshake; handshake type at byte 13, 1 = ClientHello).
    let dropped = rules.first_dropped(0).expect("a datagram was dropped");
    assert_eq!(
        dropped[0], 22,
        "dropped a DTLS handshake record: {dropped:02x?}"
    );
    assert_eq!(
        dropped[13], 1,
        "dropped the SFU's ClientHello: {dropped:02x?}"
    );
    let established = server.established();
    assert_eq!(established.len(), 1, "{established:?}");
    assert_eq!(established[0].role, DtlsRole::Client);
    assert_eq!(established[0].profile, ProtectionProfile::AeadAes128Gcm);

    let _ = client.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Clients in `ten_clients_audio_video`.
const TEN: usize = 10;

/// Ten participants in one room, each publishing audio + video and subscribed
/// to the other nine's 18 tracks (20 m-lines per session, note §17.2). Each
/// receives exactly its 18 announced streams, each from the right publisher.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_clients_audio_video() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let started = Instant::now();
    let server = start_server().await;

    let mut clients = Vec::with_capacity(TEN);
    for _ in 0..TEN {
        clients.push(publishing_client(client_config(&server, "ten")).await);
    }
    // Publisher id -> (video SSRC, audio SSRC), what the payload markers name.
    let mut published = BTreeMap::new();
    for client in &clients {
        let id = client.participant_id().expect("joined");
        let video = client.published_ssrc(true).await.expect("video SSRC");
        let audio = client.published_ssrc(false).await.expect("audio SSRC");
        published.insert(id, (video, audio));
    }
    let others = 2 * (TEN - 1);
    for client in &mut clients {
        let known = client
            .wait_for_known_tracks(others, STEP_TIMEOUT)
            .await
            .expect("every other track announced");
        assert_eq!(known.len(), others, "{known:?}");
        let ids: Vec<u64> = known.iter().map(|t| t.track_id).collect();
        // 18 ids: the client sends two requests (the SFU takes 10 per request).
        let offered = client
            .subscribe_confirmed(&ids, STEP_TIMEOUT)
            .await
            .expect("subscribed to all");
        assert_eq!(offered.len(), others, "{offered:?}");
    }
    let setup = started.elapsed();

    let expected: Vec<BTreeMap<u32, (String, u32)>> = clients
        .iter()
        .map(|c| streams_from(&c.announced_ssrcs(), &c.known_tracks(), &published))
        .collect();
    for (client, streams) in clients.iter().zip(&expected) {
        let ssrcs: Vec<u32> = streams.keys().copied().collect();
        wait_for_media(client, &ssrcs, 1, STEP_TIMEOUT).await;
    }
    let before: Vec<_> = clients.iter().map(HeadlessClient::track_stats).collect();
    tokio::time::sleep(MEDIA_WINDOW).await;
    for (i, client) in clients.iter().enumerate() {
        let who = format!("client {i}");
        check_received(&who, &before[i], &client.track_stats(), &expected[i]);
        assert_eq!(client.signal_events_dropped(), 0, "{who}");
    }
    let shard = settled_shard_stats(&server).await;
    let c = &shard.counters;
    assert_eq!(c.commands_rejected, 0, "{shard:?}");
    assert_eq!(c.drop_srtp_protect, 0, "{shard:?}");
    assert_eq!(c.drop_pool_empty, 0, "{shard:?}");
    assert_eq!(c.drop_send_failed, 0, "{shard:?}");
    assert_eq!(c.drop_too_large, 0, "{shard:?}");
    assert_eq!(shard.gauges.sessions, TEN as u64, "{shard:?}");
    assert_eq!(
        shard.gauges.subscriptions,
        (TEN * others) as u64,
        "{shard:?}"
    );
    eprintln!(
        "ten_clients_audio_video: setup {setup:?}, total {:?}",
        started.elapsed()
    );

    for client in &mut clients {
        let _ = client.disconnect().await;
    }
    server.shutdown().await.expect("clean shutdown");
}

/// For each announced m-line: its SSRC -> (kind, the publisher's SSRC of that
/// kind), through the announced track id and the track's publisher.
fn streams_from(
    announced: &[Announced],
    known: &[RemoteTrack],
    published: &BTreeMap<u64, (u32, u32)>,
) -> BTreeMap<u32, (String, u32)> {
    let mut streams = BTreeMap::new();
    for a in announced {
        let track_id = a.track_id.expect("announced m-line is in Offer.tracks");
        let track = known.iter().find(|t| t.track_id == track_id);
        let track = track.unwrap_or_else(|| panic!("track {track_id} not announced"));
        assert_eq!(track.kind, a.kind, "{a:?}");
        let (video, audio) = published[&track.publisher_id];
        let publisher_ssrc = if a.kind == "video" { video } else { audio };
        assert!(streams
            .insert(a.ssrc, (a.kind.clone(), publisher_ssrc))
            .is_none());
    }
    streams
}

/// Unsubscribe/resubscribe rounds in `resubscribe_no_srtp_index_reuse`.
const RESUBSCRIBE_ROUNDS: usize = 3;

/// Inbound datagrams B's tap can hold (≈ 150 packets/s for a few seconds).
const TAP_CAPACITY: usize = 50_000;

/// B subscribes to A's two tracks, receives for 1 s and unsubscribes, three
/// times (note §17.4). Each subscription arrives on new SSRCs, and on the wire
/// no (SSRC, sequence number) or (SSRC, SRTCP index) pair repeats: the SFU never
/// encrypts two packets under the same key, SSRC and index.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resubscribe_no_srtp_index_reuse() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    let mut a = publishing_client(client_config(&server, "resubscribe")).await;
    let rules = LossRules::new();
    rules.enable_tap(TAP_CAPACITY);
    let mut b = HeadlessClient::new(lossy_client_config(&server, "resubscribe", &rules))
        .await
        .unwrap();
    b.connect().await.expect("B connects");
    b.start_signaling_task().expect("signaling task starts");
    let known = b
        .wait_for_known_tracks(2, STEP_TIMEOUT)
        .await
        .expect("A's tracks announced");
    let ids: Vec<u64> = known.iter().map(|t| t.track_id).collect();

    let mut used = BTreeSet::new();
    let mut round_ssrcs = Vec::with_capacity(RESUBSCRIBE_ROUNDS);
    let mut first_mids = BTreeSet::new();
    for round in 0..RESUBSCRIBE_ROUNDS {
        rules.mark_tap();
        let offered = b
            .subscribe_confirmed(&ids, STEP_TIMEOUT)
            .await
            .expect("subscribed");
        let ssrcs: Vec<u32> = offered.iter().map(|m| m.ssrc).collect();
        assert_eq!(ssrcs.len(), 2, "round {round}: {offered:?}");
        for ssrc in &ssrcs {
            assert!(used.insert(*ssrc), "round {round}: SSRC {ssrc:#x} reused");
        }
        // The SFU reuses the inactive m-lines: same mids, new SSRCs.
        let mids: BTreeSet<String> = offered.iter().map(|m| m.mid.clone()).collect();
        if round == 0 {
            first_mids = mids;
        } else {
            assert_eq!(mids, first_mids, "round {round} reuses round 0's mids");
        }
        round_ssrcs.push(ssrcs.clone());
        wait_for_media(&b, &ssrcs, 10, STEP_TIMEOUT).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // The offer that follows Unsubscribe no longer announces the SSRCs (the
        // m-lines go inactive), so webrtc-rs replaces the receivers before the
        // next subscription brings new ones.
        let after = b
            .unsubscribe(&ids, STEP_TIMEOUT)
            .await
            .expect("unsubscribed");
        assert!(
            after.iter().all(|m| !ssrcs.contains(&m.ssrc)),
            "round {round}: still announced after Unsubscribe: {after:?}"
        );
    }
    let (history, overflow) = b.announced_history();
    assert_eq!(overflow, 0);
    assert_eq!(history.len(), 2 * RESUBSCRIBE_ROUNDS, "{history:?}");

    let layout = srtcp_layout(&server, &b);
    let (entries, overflow) = rules.tap();
    assert_eq!(overflow, 0, "tap too small");
    check_no_index_reuse(&entries, layout, &used);
    check_rounds(&rules.tap_rounds(), &round_ssrcs);

    let shard = settled_shard_stats(&server).await;
    assert_eq!(shard.counters.commands_rejected, 0, "{shard:?}");
    assert_eq!(shard.counters.drop_srtp_protect, 0, "{shard:?}");

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Every SRTP and SRTCP SSRC on the wire in round r is one announced in round r
/// (so none of an earlier round's SSRCs shows up later). `rounds[0]` is what
/// arrived before the first subscription: nothing.
fn check_rounds(rounds: &[Vec<TapEntry>], round_ssrcs: &[Vec<u32>]) {
    assert_eq!(
        rounds.len(),
        round_ssrcs.len() + 1,
        "one tap mark per round"
    );
    assert!(
        rounds[0].is_empty(),
        "media before subscribing: {:?}",
        rounds[0]
    );
    for (round, (entries, ssrcs)) in rounds[1..].iter().zip(round_ssrcs).enumerate() {
        let earlier: Vec<u32> = round_ssrcs[..round].iter().flatten().copied().collect();
        for entry in entries {
            let ssrc = match entry {
                TapEntry::Srtp { ssrc, .. } => *ssrc,
                TapEntry::Srtcp { sender_ssrc, .. } => *sender_ssrc,
            };
            assert!(
                !earlier.contains(&ssrc),
                "round {round}: SSRC {ssrc:#x} of an earlier round on the wire"
            );
            assert!(
                ssrcs.contains(&ssrc),
                "round {round}: SSRC {ssrc:#x} not announced in this round ({ssrcs:x?})"
            );
        }
        assert!(!entries.is_empty(), "round {round}: nothing on the wire");
    }
}

/// Shard stats after the next once-a-second publish, so counters include
/// everything that happened before the call.
async fn settled_shard_stats(
    server: &nexus_sfu::server::ServerHandle,
) -> nexus_dataplane::ShardStatsSnapshot {
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    shard_stats(server)
}

/// The SRTCP layout of the profile `client`'s DTLS session negotiated.
fn srtcp_layout(server: &nexus_sfu::server::ServerHandle, client: &HeadlessClient) -> SrtcpLayout {
    let id = client.participant_id().expect("joined");
    let established = server.established();
    let session = established.iter().find(|e| e.participant == id);
    match session.expect("DTLS established").profile {
        ProtectionProfile::AeadAes128Gcm => SrtcpLayout::Gcm,
        ProtectionProfile::Aes128CmHmacSha1_80 => SrtcpLayout::AesCm80,
        other => panic!("unexpected profile {other:?}"),
    }
}

/// No (SSRC, seq) and no (SSRC, SRTCP index) repeats on the wire; SRTP arrived
/// on every SSRC in `ssrcs`; every SRTCP packet is encrypted (E set).
fn check_no_index_reuse(entries: &[TapEntry], layout: SrtcpLayout, ssrcs: &BTreeSet<u32>) {
    let mut rtp = BTreeSet::new();
    let mut rtcp = BTreeSet::new();
    for entry in entries {
        match entry {
            TapEntry::Srtp { ssrc, seq } => {
                assert!(
                    rtp.insert((*ssrc, *seq)),
                    "SRTP ({ssrc:#x}, {seq}) sent twice"
                );
            }
            TapEntry::Srtcp { sender_ssrc, .. } => {
                let word = entry.srtcp_e_index(layout).expect("SRTCP entry");
                assert_ne!(word >> 31, 0, "SRTCP from {sender_ssrc:#x} not encrypted");
                let index = word & 0x7FFF_FFFF;
                assert!(
                    rtcp.insert((*sender_ssrc, index)),
                    "SRTCP ({sender_ssrc:#x}, {index}) sent twice"
                );
            }
        }
    }
    for ssrc in ssrcs {
        assert!(
            rtp.iter().any(|(s, _)| s == ssrc),
            "no SRTP on the wire for {ssrc:#x}"
        );
    }
    eprintln!(
        "resubscribe: {} SRTP and {} SRTCP datagrams checked on {} SSRCs",
        rtp.len(),
        rtcp.len(),
        ssrcs.len()
    );
}

/// Subscribe `client` to the first `count` tracks announced to it; returns the
/// announced m-lines of those tracks.
async fn subscribe_all(client: &mut HeadlessClient, count: usize) -> Vec<Announced> {
    let known = client
        .wait_for_known_tracks(count, STEP_TIMEOUT)
        .await
        .expect("tracks announced");
    let ids: Vec<u64> = known.iter().map(|t| t.track_id).take(count).collect();
    let offered = client
        .subscribe_confirmed(&ids, STEP_TIMEOUT)
        .await
        .expect("subscribed");
    assert_eq!(offered.len(), count, "{offered:?}");
    offered
}

fn ssrcs_of(announced: &[Announced]) -> Vec<u32> {
    announced.iter().map(|a| a.ssrc).collect()
}

fn shard_stats(server: &nexus_sfu::server::ServerHandle) -> nexus_dataplane::ShardStatsSnapshot {
    server.dataplane().stats(nexus_dataplane::ShardId::new(0))
}

/// Media window after the rebind in `address_change_mid_call`.
const AFTER_REBIND_WINDOW: Duration = Duration::from_secs(3);

/// Latest resume accepted in `address_change_mid_call` (measured ≈ 2.1-2.3 s; the
/// margin is for emulated and loaded CI runners).
const REBIND_RESUME_MAX: Duration = Duration::from_millis(4_500);

/// A and B in a call; A's socket moves to a new local port (a NAT rebinding;
/// A's ICE agent keeps its candidate, note §17.3). Media resumes both ways
/// within 3.5 s (not before the silence rule allows), runs with ≤ 1 % loss
/// afterwards, nothing more reaches A's old port, and the shard counted the
/// rebinding. Expected resume ≈ 2.0-2.6 s: webrtc-ice sends a binding request
/// once it has received nothing for 2 s, and the SFU accepts it once A's old
/// address has been silent for `rebind_silence` (2 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn address_change_mid_call() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    let a_rules = LossRules::new();
    let mut a = publishing_client(lossy_client_config(&server, "rebind", &a_rules)).await;
    let mut b = publishing_client(client_config(&server, "rebind")).await;
    let a_streams = ssrcs_of(&subscribe_all(&mut a, 2).await);
    let b_streams = ssrcs_of(&subscribe_all(&mut b, 2).await);
    wait_for_media(&a, &a_streams, 1, STEP_TIMEOUT).await;
    wait_for_media(&b, &b_streams, 1, STEP_TIMEOUT).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let rebinds = shard_stats(&server).counters.rebinds;
    let rebound_at = Instant::now();
    let new_addr = a_rules.rebind().await.expect("rebinds");
    let ((a_first, a_resumed), (b_first, b_resumed)) = tokio::join!(
        wait_for_resume(&a, &a_streams, rebound_at),
        wait_for_resume(&b, &b_streams, rebound_at)
    );
    eprintln!(
        "address_change_mid_call: A moved to port {}; media to A resumed after {a_resumed:?}, \
         A's media to B after {b_resumed:?}",
        new_addr.port()
    );
    assert!(
        a_resumed < REBIND_RESUME_MAX,
        "B -> A resumed after {a_resumed:?}"
    );
    assert!(
        b_resumed < REBIND_RESUME_MAX,
        "A -> B resumed after {b_resumed:?}"
    );
    // A's media from the new port is dropped until the old address has been
    // silent for rebind_silence: any stream resuming earlier means the rule was
    // skipped. Checked on the earliest stream of each direction.
    let silence = Duration::from_millis(test_config().dataplane.rebind_silence_ms.into());
    let earliest = silence.saturating_sub(Duration::from_millis(200));
    assert!(
        b_first >= earliest,
        "A -> B: a stream resumed after {b_first:?}, before {earliest:?}"
    );
    assert!(
        a_first >= earliest,
        "B -> A: a stream resumed after {a_first:?}, before {earliest:?}"
    );

    let (a_before, b_before) = (a.track_stats(), b.track_stats());
    tokio::time::sleep(AFTER_REBIND_WINDOW).await;
    check_window("A", &a_before, &a.track_stats(), &a_streams);
    check_window("B", &b_before, &b.track_stats(), &b_streams);

    // The SFU sends to A's new port only: the old one got nothing from 1 s
    // after media to A resumed.
    let (retired_rx, last) = a_rules.retired_received();
    let quiet_from = rebound_at + a_resumed + Duration::from_secs(1);
    if let Some(last) = last {
        assert!(
            last < quiet_from,
            "A's old port received {:?} after media resumed",
            last.duration_since(rebound_at + a_resumed)
        );
    }
    eprintln!("address_change_mid_call: {retired_rx} datagrams reached A's old port");

    // Stats are published once a second.
    let deadline = Instant::now() + Duration::from_secs(3);
    while shard_stats(&server).counters.rebinds == rebinds && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let shard = shard_stats(&server);
    assert_eq!(shard.counters.rebinds, rebinds + 1, "{shard:?}");

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}

/// How long after `since` packets on each of `ssrcs` started arriving again,
/// each after having stopped for at least 500 ms: (earliest, latest) stream.
/// The earliest is the one the silence rule bounds from below; the latest ends
/// the outage (a window measured from an earlier stream would count a later
/// stream's outage gap as loss).
async fn wait_for_resume(
    client: &HeadlessClient,
    ssrcs: &[u32],
    since: Instant,
) -> (Duration, Duration) {
    const GAP: Duration = Duration::from_millis(500);
    assert!(!ssrcs.is_empty() && ssrcs.len() <= 8);
    let count = |ssrc: u32| -> u64 {
        let stats = client.track_stats();
        stats
            .iter()
            .find(|t| t.ssrc == ssrc)
            .map_or(0, |t| t.packets)
    };
    // Per stream: packets last seen, when they last changed, stalled, resumed at
    let mut streams: Vec<(u32, u64, Instant, bool, Option<Duration>)> = ssrcs
        .iter()
        .map(|&s| (s, count(s), since, false, None))
        .collect();
    let deadline = since + Duration::from_secs(10);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        for (ssrc, last, changed_at, stalled, resumed) in streams.iter_mut() {
            let now = count(*ssrc);
            if resumed.is_some() {
                continue;
            }
            if now == *last {
                *stalled |= changed_at.elapsed() >= GAP;
                continue;
            }
            if *stalled {
                *resumed = Some(since.elapsed());
            }
            (*last, *changed_at) = (now, Instant::now());
        }
        if streams.iter().all(|s| s.4.is_some()) {
            let resumed = || streams.iter().filter_map(|s| s.4);
            let (first, last) = (resumed().min().unwrap(), resumed().max().unwrap());
            assert!(first <= last);
            return (first, last);
        }
    }
    panic!("media on {ssrcs:x?} did not stop and resume within 10 s: {streams:?}");
}

/// Over one window: each of `ssrcs` received ≥ 10 packets/s with ≤ 1 % of its
/// sequence numbers missing.
fn check_window(who: &str, before: &[TrackRxStats], after: &[TrackRxStats], ssrcs: &[u32]) {
    let window = AFTER_REBIND_WINDOW.as_secs();
    for ssrc in ssrcs {
        let find = |all: &[TrackRxStats]| all.iter().find(|t| t.ssrc == *ssrc).cloned();
        let (b, a) = (find(before).expect("before"), find(after).expect("after"));
        let received = a.packets - b.packets;
        let expected = a.highest_ext_seq - b.highest_ext_seq;
        let missing = expected.saturating_sub(received);
        assert!(
            received >= 10 * window,
            "{who}: {ssrc:#x}: {received} packets"
        );
        assert!(
            missing * 100 <= expected,
            "{who}: {ssrc:#x}: {missing} of {expected} missing"
        );
    }
}

/// Error between a sender report's RTP timestamp and the media's, extrapolated
/// from the last packet received when the report arrived to the report's NTP
/// time (note §17.5): the median over a track's reports, and the most for any
/// one. The single-report bound absorbs scheduling delay on loaded runners; a
/// translation bug is off by far more (a wrong clock or offset: seconds).
const SR_MEDIAN_TOLERANCE_MS: f64 = 50.0;
const SR_MAX_TOLERANCE_MS: f64 = 200.0;

/// A publishes audio + video (webrtc-rs sends SRs every second), B subscribes.
/// B receives translated SRs on the SSRCs it receives the media on, with RTP
/// timestamps consistent with that media, and the same CNAME (the one its offer
/// announced) for both tracks (note §17.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sender_report_translation() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    let mut a = publishing_client(client_config(&server, "sender-reports")).await;
    let mut b = HeadlessClient::new(client_config(&server, "sender-reports"))
        .await
        .unwrap();
    b.connect().await.expect("B connects");
    b.start_signaling_task().expect("signaling task starts");
    let offered = subscribe_all(&mut b, 2).await;
    let ssrcs = ssrcs_of(&offered);
    wait_for_media(&b, &ssrcs, 1, STEP_TIMEOUT).await;

    let deadline = Instant::now() + Duration::from_secs(8);
    let log = b.rtcp_log();
    let reports_on = |ssrc: u32| {
        log.sender_reports()
            .iter()
            .filter(|r| r.ssrc == ssrc && r.last_packet.is_some())
            .count()
    };
    while ssrcs.iter().any(|s| reports_on(*s) < 3) {
        assert!(
            Instant::now() < deadline,
            "fewer than 3 SRs after media per track in 8 s: {:?}",
            log.sender_reports()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for report in log.sender_reports() {
        assert!(
            ssrcs.contains(&report.ssrc),
            "SR on an unknown SSRC: {report:?}"
        );
    }
    // The SFU's packet count per subscription only grows.
    for ssrc in &ssrcs {
        let reports = log.sender_reports();
        let counts: Vec<u32> = reports
            .iter()
            .filter(|r| r.ssrc == *ssrc)
            .map(|r| r.packet_count)
            .collect();
        assert!(
            counts.windows(2).all(|w| w[0] <= w[1]),
            "{ssrc:#x}: packet count went down: {counts:?}"
        );
    }

    for m in &offered {
        let clock = if m.kind == "video" {
            90_000.0
        } else {
            48_000.0
        };
        let reports = log.sender_reports();
        let mut errors: Vec<f64> = reports
            .iter()
            .filter(|r| r.ssrc == m.ssrc)
            .filter_map(|sr| Some(sr_error_ms(sr, &sr.last_packet?, clock)))
            .collect();
        assert!(
            errors.len() >= 2,
            "{}: {} SRs after media",
            m.kind,
            errors.len()
        );
        errors.sort_by(|a, b| a.abs().total_cmp(&b.abs()));
        let median = errors[errors.len() / 2].abs();
        let worst = errors.last().unwrap().abs();
        eprintln!(
            "sender_report_translation: {} SR error over {} reports: median {median:.1} ms, \
             worst {worst:.1} ms",
            m.kind,
            errors.len()
        );
        assert!(
            median <= SR_MEDIAN_TOLERANCE_MS,
            "{}: median {median} ms: {errors:?}",
            m.kind
        );
        assert!(
            worst <= SR_MAX_TOLERANCE_MS,
            "{}: worst {worst} ms: {errors:?}",
            m.kind
        );
    }

    let cnames = log.cnames();
    for m in &offered {
        let announced = m.cname.as_deref().expect("offer announces a CNAME");
        let received: Vec<&str> = cnames
            .iter()
            .filter(|(ssrc, _)| *ssrc == m.ssrc)
            .map(|(_, c)| c.as_str())
            .collect();
        assert_eq!(received, vec![announced], "{} SDES: {cnames:?}", m.kind);
    }
    assert_eq!(
        offered[0].cname, offered[1].cname,
        "one CNAME per publisher"
    );
    assert_eq!(log.overflow(), 0);
    assert!(shard_stats(&server).counters.sr_translated > 0);

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}

/// The SR's RTP timestamp minus the latest received packet's, extrapolated at
/// `clock` Hz from that packet's arrival to the SR's NTP time, in ms.
fn sr_error_ms(
    sr: &nexus_loadtest::rtcp_log::SenderReportRx,
    last: &nexus_loadtest::LastPacket,
    clock: f64,
) -> f64 {
    let sr_time = ntp_to_system_time(sr.ntp_time);
    let elapsed = match sr_time.duration_since(last.arrival) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    };
    let ticks = sr.rtp_time.wrapping_sub(last.rtp_timestamp) as i32 as f64;
    (ticks - elapsed * clock) / clock * 1000.0
}

/// A's keyframe requests for `ssrc` that arrived at or after `since`.
fn plis_since(a: &HeadlessClient, ssrc: u32, since: Instant) -> Vec<Instant> {
    let requests = a.rtcp_log().keyframe_requests();
    let wanted = |r: &&nexus_loadtest::rtcp_log::KeyframeRequest| {
        r.media_ssrc == ssrc && r.at >= since && !r.fir
    };
    requests.iter().filter(wanted).map(|r| r.at).collect()
}

/// Wait up to `within` after `since` for A's first PLI on `ssrc`; returns its delay.
async fn wait_for_pli(a: &HeadlessClient, ssrc: u32, since: Instant, within: Duration) -> Duration {
    loop {
        if let Some(at) = plis_since(a, ssrc, since).first() {
            return at.duration_since(since);
        }
        assert!(
            since.elapsed() < within,
            "no PLI for {ssrc:#x} within {within:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Keyframe requests (R1, note §17.6): the SFU asks A for a keyframe when B
/// subscribes, forwards B's PLI, and forwards one of a burst (500 ms throttle).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyframe_requests() {
    let _serial = SERIAL.lock().await;
    init_logging();
    let server = start_server().await;

    // A records RTCP from start_publishing on, before any subscriber.
    let mut a = publishing_client(client_config(&server, "keyframes")).await;
    let video = a.published_ssrc(true).await.expect("video SSRC");
    let mut b = HeadlessClient::new(client_config(&server, "keyframes"))
        .await
        .unwrap();
    b.connect().await.expect("B connects");
    b.start_signaling_task().expect("signaling task starts");

    // 1. B subscribes: A gets a PLI for its video within 3 s (B's ICE and
    // DTLS come up in that time: B has no transport before this offer;
    // 0.2-0.4 s natively, the margin is for emulated CI runners).
    let subscribed = Instant::now();
    let offered = subscribe_all(&mut b, 2).await;
    let on_subscribe = wait_for_pli(&a, video, subscribed, Duration::from_secs(3)).await;
    let b_video = offered
        .iter()
        .find(|m| m.kind == "video")
        .expect("video")
        .ssrc;
    wait_for_media(&b, &[b_video], 1, STEP_TIMEOUT).await;

    // 2. Past the throttle, B's PLI reaches A within 500 ms. Nothing asks A
    // for a keyframe in between.
    let quiet = Instant::now();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        plis_since(&a, video, quiet),
        Vec::<Instant>::new(),
        "PLI while quiet"
    );
    let sent = Instant::now();
    b.send_pli(b_video).await.expect("PLI sent");
    let forwarded = wait_for_pli(&a, video, sent, Duration::from_millis(500)).await;

    // 3. Past the throttle again (the settled stats take 1.1 s), 5 PLIs within
    // 100 ms: exactly one reaches A in the following 400 ms, and the shard
    // throttled the other four.
    let quiet = Instant::now();
    let throttled = settled_shard_stats(&server)
        .await
        .counters
        .keyframe_throttled;
    assert_eq!(
        plis_since(&a, video, quiet),
        Vec::<Instant>::new(),
        "PLI while quiet"
    );
    let burst = Instant::now();
    for i in 0..5 {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        b.send_pli(b_video).await.expect("PLI sent");
    }
    assert!(
        burst.elapsed() < Duration::from_millis(100),
        "burst took {:?}",
        burst.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(500).saturating_sub(burst.elapsed())).await;
    let arrived = plis_since(&a, video, burst);
    eprintln!(
        "keyframe_requests: on subscribe {on_subscribe:?}, forwarded {forwarded:?}, \
         burst -> {} at {:?}",
        arrived.len(),
        arrived
            .iter()
            .map(|t| t.duration_since(burst))
            .collect::<Vec<_>>()
    );
    assert_eq!(arrived.len(), 1, "one PLI of the burst reaches A");

    let shard = settled_shard_stats(&server).await;
    assert_eq!(
        shard.counters.keyframe_throttled,
        throttled + 4,
        "{shard:?}"
    );
    assert_eq!(a.rtcp_log().overflow(), 0);

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
}
