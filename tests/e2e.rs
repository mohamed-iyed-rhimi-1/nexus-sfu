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
use nexus_loadtest::lossy::{Direction, LossRule, LossRules, PacketClass};
use nexus_loadtest::signaling::SignalingConnection;
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
/// the same (exactly one audio and one video stream, no new SSRCs). The arriving
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
        2,
        "{who}: exactly two SSRCs received: {after:?}"
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
