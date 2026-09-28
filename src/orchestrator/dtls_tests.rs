//! Tests for `DtlsHandshake`: a plain OpenSSL engine (its own certificate) plays the
//! peer; datagrams go one at a time, as over UDP. The peer's flights reach the SFU one
//! record per datagram (browsers send a flight as several datagrams), so reassembly
//! across datagrams is exercised.

use super::*;
use proptest::prelude::*;

fn certificate() -> DtlsCertificate {
    DtlsCertificate::generate().unwrap()
}

/// A peer engine in `role` (the SFU takes the other one), on its own certificate.
fn peer(role: DtlsRole) -> OpenSslDtlsEngine {
    OpenSslDtlsEngine::with_certificate(role, &certificate())
}

/// A buffer of whole DTLS records, one record per datagram.
fn one_record_per_datagram(mut buf: &[u8]) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    while !buf.is_empty() {
        assert!(buf.len() >= RECORD_HEADER_LEN);
        let len = RECORD_HEADER_LEN + u16::from_be_bytes([buf[11], buf[12]]) as usize;
        datagrams.push(buf[..len].to_vec());
        buf = &buf[len..];
    }
    datagrams
}

/// Exchanges datagrams until nothing is left to send; returns whether the SFU side
/// reported completion. Bounded: a DTLS 1.2 handshake is two round trips. What goes to
/// the SFU is cut into one record per datagram first.
fn pump(
    sfu: &mut DtlsHandshake,
    peer: &mut OpenSslDtlsEngine,
    mut to_sfu: Vec<Vec<u8>>,
    mut to_peer: Vec<Vec<u8>>,
) -> Result<bool, HandshakeError> {
    let mut completed = false;
    for _ in 0..16 {
        for datagram in std::mem::take(&mut to_peer) {
            assert!(
                datagram.len() <= DTLS_MTU as usize,
                "{} bytes",
                datagram.len()
            );
            let reply = peer.process(&datagram).unwrap();
            if !reply.is_empty() {
                to_sfu.push(reply);
            }
        }
        let flights = std::mem::take(&mut to_sfu);
        for datagram in flights.iter().flat_map(|f| one_record_per_datagram(f)) {
            let progress = sfu.process(&datagram)?;
            assert!(!(completed && progress.completed), "completed twice");
            completed |= progress.completed;
            to_peer.extend(progress.datagrams);
        }
        if to_peer.is_empty() && to_sfu.is_empty() {
            break;
        }
    }
    Ok(completed)
}

fn assert_keys(install: &SrtpInstall, peer: &OpenSslDtlsEngine, sfu_role: DtlsRole) {
    let keys = peer.srtp_keys().unwrap();
    let (ours, theirs) = match sfu_role {
        DtlsRole::Server => (
            (keys.server_key(), keys.server_salt()),
            (keys.client_key(), keys.client_salt()),
        ),
        DtlsRole::Client => (
            (keys.client_key(), keys.client_salt()),
            (keys.server_key(), keys.server_salt()),
        ),
    };
    assert_eq!((install.local.key(), install.local.salt()), ours);
    assert_eq!((install.remote.key(), install.remote.salt()), theirs);
}

/// Browser case: the answer says `active`, the SFU is the server.
#[test]
fn server_after_answer() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    let progress = sfu
        .on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    assert!(progress.datagrams.is_empty() && !progress.completed);
    assert!(sfu.holds_ssl());
    let hello = client.start_handshake().unwrap();
    assert!(pump(&mut sfu, &mut client, vec![hello], vec![]).unwrap());
    assert!(sfu.is_complete());
    assert_keys(&sfu.srtp_install().unwrap(), &client, DtlsRole::Server);
}

/// The ClientHello arrives before the answer: the SFU becomes the server; completion
/// waits for the fingerprint, then the answer completes it.
#[test]
fn client_hello_before_answer() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    let hello = client.start_handshake().unwrap();
    assert!(!pump(&mut sfu, &mut client, vec![hello], vec![]).unwrap());
    assert_eq!(sfu.role(), Some(DtlsRole::Server));
    assert!(client.is_established(), "the peer finished");
    assert!(!sfu.is_complete(), "pending until the fingerprint is known");
    assert!(sfu.srtp_install().is_err());
    let progress = sfu
        .on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    assert!(progress.completed);
    assert_keys(&sfu.srtp_install().unwrap(), &client, DtlsRole::Server);
}

#[test]
fn passive_answer_after_client_hello_fails() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    let hello = client.start_handshake().unwrap();
    sfu.process(&hello).unwrap();
    let err = sfu
        .on_answer(DtlsRole::Client, *client.fingerprint())
        .unwrap_err();
    assert!(matches!(err, HandshakeError::RoleConflict { .. }), "{err}");
    assert!(sfu.is_failed() && !sfu.holds_ssl());
    assert!(matches!(sfu.process(&hello), Err(HandshakeError::Failed)));
}

/// webrtc-rs case: the answer says `passive`, the SFU is the client and sends its
/// ClientHello once an address is selected, in either order.
#[test]
fn client_starts_on_answer_and_address() {
    for address_first in [false, true] {
        let mut sfu = DtlsHandshake::new(&certificate());
        let mut server = peer(DtlsRole::Server);
        assert!(server.start_handshake().unwrap().is_empty());
        let hello = if address_first {
            assert!(sfu.on_address_selected().unwrap().datagrams.is_empty());
            sfu.on_answer(DtlsRole::Client, *server.fingerprint())
                .unwrap()
                .datagrams
        } else {
            let progress = sfu
                .on_answer(DtlsRole::Client, *server.fingerprint())
                .unwrap();
            assert!(progress.datagrams.is_empty() && !sfu.holds_ssl());
            sfu.on_address_selected().unwrap().datagrams
        };
        assert!(is_client_hello(&hello[0]));
        assert!(
            sfu.on_address_selected().unwrap().datagrams.is_empty(),
            "once"
        );
        assert!(pump(&mut sfu, &mut server, vec![], hello).unwrap());
        assert_keys(&sfu.srtp_install().unwrap(), &server, DtlsRole::Client);
    }
}

#[test]
fn fingerprint_mismatch_fails() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    let mut wrong = *client.fingerprint();
    wrong[0] ^= 1;
    sfu.on_answer(DtlsRole::Server, wrong).unwrap();
    let hello = client.start_handshake().unwrap();
    let err = pump(&mut sfu, &mut client, vec![hello], vec![]).unwrap_err();
    assert!(matches!(err, HandshakeError::FingerprintMismatch));
    assert!(sfu.is_failed() && sfu.srtp_install().is_err());
}

/// The ClientHello came first and DTLS completed (pending); the answer then pins a
/// fingerprint the peer's certificate does not have.
#[test]
fn fingerprint_mismatch_when_the_answer_comes_after_completion() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    let hello = client.start_handshake().unwrap();
    assert!(!pump(&mut sfu, &mut client, vec![hello], vec![]).unwrap());
    assert!(client.is_established() && !sfu.is_complete());
    let mut wrong = *client.fingerprint();
    wrong[7] ^= 0x40;
    assert!(matches!(
        sfu.on_answer(DtlsRole::Server, wrong),
        Err(HandshakeError::FingerprintMismatch)
    ));
    assert!(sfu.is_failed() && !sfu.holds_ssl() && sfu.srtp_install().is_err());
}

/// The SFU is server and its flight is lost: the peer's retransmitted ClientHello
/// (OpenSSL's 1 s timer on the peer) makes the SFU resend it, and the handshake
/// completes without calling the SFU's `handle_timeout` (OpenSSL may still run its own
/// expired timer while reading the retransmission).
#[test]
fn lost_server_flight_is_recovered_by_the_client_retransmission() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    let hello = client.start_handshake().unwrap();
    let mut lost = Vec::new();
    for datagram in one_record_per_datagram(&hello) {
        lost.extend(sfu.process(&datagram).unwrap().datagrams);
    }
    assert!(!lost.is_empty(), "the server flight, dropped");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let resent_hello = client.handle_timeout().unwrap();
    assert!(is_client_hello(&resent_hello));
    assert!(pump(&mut sfu, &mut client, vec![resent_hello], vec![]).unwrap());
    assert!(client.is_established());
    assert_keys(&sfu.srtp_install().unwrap(), &client, DtlsRole::Server);
}

/// `free_ssl` before completion (a stray or early event) changes nothing: the engine
/// stays, and a later ClientHello cannot start a second one or complete twice.
#[test]
fn free_ssl_before_completion_is_a_no_op() {
    let mut sfu = DtlsHandshake::new(&certificate());
    assert!(!sfu.free_ssl(), "nothing to free before the handshake");
    let mut client = peer(DtlsRole::Client);
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    let hello = client.start_handshake().unwrap();
    let mut flight = Vec::new();
    for datagram in one_record_per_datagram(&hello) {
        flight.extend(sfu.process(&datagram).unwrap().datagrams);
    }
    assert!(!sfu.free_ssl() && sfu.holds_ssl(), "mid-handshake: kept");
    assert!(pump(&mut sfu, &mut client, vec![], flight).unwrap());
    assert!(sfu.free_ssl() && !sfu.holds_ssl());
    assert!(!sfu.free_ssl(), "once");
    // A new ClientHello (another peer, same address) after the free starts nothing.
    let mut other = peer(DtlsRole::Client);
    let progress = sfu.process(&other.start_handshake().unwrap()).unwrap();
    assert!(progress.datagrams.is_empty() && !progress.completed && !sfu.holds_ssl());
}

#[test]
fn answers_must_repeat_fingerprint_and_role() {
    let client = peer(DtlsRole::Client);
    let mut sfu = DtlsHandshake::new(&certificate());
    assert!(matches!(
        sfu.on_answer(DtlsRole::Server, [0; 32]),
        Err(HandshakeError::ZeroFingerprint)
    ));
    let mut sfu = DtlsHandshake::new(&certificate());
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    let mut other = *client.fingerprint();
    other[31] ^= 0xFF;
    assert!(matches!(
        sfu.on_answer(DtlsRole::Server, other),
        Err(HandshakeError::FingerprintMismatch)
    ));
    let mut sfu = DtlsHandshake::new(&certificate());
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    assert!(matches!(
        sfu.on_answer(DtlsRole::Client, *client.fingerprint()),
        Err(HandshakeError::RoleConflict { .. })
    ));
}

#[test]
fn free_ssl_keeps_the_entry_usable() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut client = peer(DtlsRole::Client);
    sfu.on_answer(DtlsRole::Server, *client.fingerprint())
        .unwrap();
    let hello = client.start_handshake().unwrap();
    assert!(pump(&mut sfu, &mut client, vec![hello.clone()], vec![]).unwrap());
    assert!(sfu.free_ssl());
    assert!(!sfu.holds_ssl() && sfu.is_complete());
    let late = sfu.process(&hello).unwrap();
    assert!(late.datagrams.is_empty() && !late.completed);
    assert!(sfu.handle_timeout().unwrap().is_empty());
    assert!(sfu.on_address_selected().unwrap().datagrams.is_empty());
}

/// SFU as client, its ClientHello lost: OpenSSL's timer (1 s) resends it through
/// `handle_timeout`, and the handshake completes. Wall-clock sleep: OpenSSL reads the
/// real clock.
#[test]
fn lost_client_hello_is_retransmitted() {
    let mut sfu = DtlsHandshake::new(&certificate());
    let mut server = peer(DtlsRole::Server);
    server.start_handshake().unwrap();
    sfu.on_answer(DtlsRole::Client, *server.fingerprint())
        .unwrap();
    let lost = sfu.on_address_selected().unwrap().datagrams;
    assert!(!lost.is_empty());
    assert!(
        sfu.handle_timeout().unwrap().is_empty(),
        "timer not expired yet"
    );
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let resent = sfu.handle_timeout().unwrap();
    assert!(!resent.is_empty() && is_client_hello(&resent[0]));
    assert!(pump(&mut sfu, &mut server, vec![], resent).unwrap());
}

#[test]
fn split_records_packs_whole_records_up_to_the_mtu() {
    let record = |len: usize| {
        let mut r = vec![22u8; RECORD_HEADER_LEN + len];
        r[11..13].copy_from_slice(&(len as u16).to_be_bytes());
        r
    };
    let lens = [100usize, 900, 500, 1_500, 20, 0];
    let input: Vec<u8> = lens.iter().flat_map(|&n| record(n)).collect();
    let datagrams = split_records(&input).unwrap();
    // 113 + 913 fit; 513 starts a new one; 1,513 goes alone; 33 + 13 follow.
    let sizes: Vec<usize> = datagrams.iter().map(Vec::len).collect();
    assert_eq!(sizes, vec![1_026, 513, 1_513, 46]);
    assert_eq!(datagrams.concat(), input);
    assert!(split_records(&[]).unwrap().is_empty());
    assert!(split_records(&input[..input.len() - 1]).is_err());
    assert!(split_records(&[22, 254, 253]).is_err());
}

#[test]
fn client_hello_detection() {
    let mut client = peer(DtlsRole::Client);
    let hello = client.start_handshake().unwrap();
    assert!(is_client_hello(&hello));
    let mut not_hello = hello.clone();
    not_hello[RECORD_HEADER_LEN] = 2;
    assert!(!is_client_hello(&not_hello));
    assert!(!is_client_hello(&hello[..RECORD_HEADER_LEN]));
    assert!(!is_client_hello(&[]));
}

/// Handshakes in each state network input can reach: role unknown, server waiting,
/// client mid-handshake, complete, freed.
fn handshakes_in_every_state() -> Vec<DtlsHandshake> {
    let cert = certificate();
    let fresh = DtlsHandshake::new(&cert);
    let mut waiting = DtlsHandshake::new(&cert);
    waiting
        .on_answer(DtlsRole::Server, *peer(DtlsRole::Client).fingerprint())
        .unwrap();
    let mut client = DtlsHandshake::new(&cert);
    client
        .on_answer(DtlsRole::Client, *peer(DtlsRole::Server).fingerprint())
        .unwrap();
    client.on_address_selected().unwrap();
    let mut complete = DtlsHandshake::new(&cert);
    let mut peer_client = peer(DtlsRole::Client);
    complete
        .on_answer(DtlsRole::Server, *peer_client.fingerprint())
        .unwrap();
    let hello = peer_client.start_handshake().unwrap();
    assert!(pump(&mut complete, &mut peer_client, vec![hello], vec![]).unwrap());
    let mut freed = DtlsHandshake::new(&cert);
    let mut peer_client = peer(DtlsRole::Client);
    freed
        .on_answer(DtlsRole::Server, *peer_client.fingerprint())
        .unwrap();
    let hello = peer_client.start_handshake().unwrap();
    assert!(pump(&mut freed, &mut peer_client, vec![hello], vec![]).unwrap());
    assert!(freed.free_ssl());
    vec![fresh, waiting, client, complete, freed]
}

#[test]
fn empty_and_oversized_datagrams_are_refused_without_state_change() {
    for mut sfu in handshakes_in_every_state() {
        let before = format!("{sfu:?}");
        for len in [0usize, MAX_BIO_READ + 1] {
            let datagram = vec![22u8; len];
            assert!(matches!(
                sfu.process(&datagram),
                Err(HandshakeError::InvalidDatagram(n)) if n == len
            ));
        }
        assert_eq!(format!("{sfu:?}"), before);
        // One byte, and a maximal datagram: OpenSSL may refuse them, never a panic.
        let _ = sfu.process(&[22]);
        let _ = sfu.process(&vec![22u8; MAX_BIO_READ]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random datagrams (every first byte, lengths 1-2,048) into every state: an
    /// error or output, never a panic; a freed handshake stays silent.
    #[test]
    fn random_datagrams_never_panic(
        datagrams in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..2_048), 1..8),
        hello_prefix in any::<bool>(),
    ) {
        for mut sfu in handshakes_in_every_state() {
            let freed = sfu.is_complete() && !sfu.holds_ssl();
            for mut datagram in datagrams.clone() {
                if hello_prefix && datagram.len() > RECORD_HEADER_LEN {
                    datagram[0] = CONTENT_TYPE_HANDSHAKE;
                    datagram[3] = 0;
                    datagram[4] = 0;
                    datagram[RECORD_HEADER_LEN] = HANDSHAKE_CLIENT_HELLO;
                }
                if let Ok(progress) = sfu.process(&datagram) {
                    prop_assert!(!freed || progress.datagrams.is_empty());
                    for out in &progress.datagrams {
                        prop_assert!(out.len() <= DTLS_MTU as usize);
                    }
                }
                let _ = sfu.handle_timeout();
            }
        }
    }

    #[test]
    fn split_records_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4_096)) {
        if let Ok(datagrams) = split_records(&bytes) {
            prop_assert_eq!(datagrams.concat(), bytes);
        }
    }
}
