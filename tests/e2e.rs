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
use nexus_loadtest::lossy::{Direction, LossRule, LossRules, PacketClass, SrtcpLayout, TapEntry};
use nexus_loadtest::signaling::SignalingConnection;
use nexus_loadtest::{Announced, RemoteTrack};
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
    let mut sig =
        SignalingConnection::connect_with_timeout(&ws_url(&server), &options, "cand", STEP_TIMEOUT)
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
    let shard = server.dataplane().stats(nexus_dataplane::ShardId::new(0));
    assert_eq!(shard.counters.commands_rejected, 0, "{shard:?}");
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
    for round in 0..RESUBSCRIBE_ROUNDS {
        let offered = b
            .subscribe_confirmed(&ids, STEP_TIMEOUT)
            .await
            .expect("subscribed");
        let ssrcs: Vec<u32> = offered.iter().map(|m| m.ssrc).collect();
        assert_eq!(ssrcs.len(), 2, "round {round}: {offered:?}");
        for ssrc in &ssrcs {
            assert!(used.insert(*ssrc), "round {round}: SSRC {ssrc:#x} reused");
        }
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

    let _ = a.disconnect().await;
    let _ = b.disconnect().await;
    server.shutdown().await.expect("clean shutdown");
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
