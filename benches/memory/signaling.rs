//! One signaling connection's memory on the server: reported next to the session
//! state, not in the budget (note §15: the WebSocket connection is signaling, not
//! session state; design §3.11: the 25 KB budget is session state only).
//!
//! The real `SignalingServer` runs on its own thread (a current-thread runtime), with
//! every allocation on that thread tagged `Signaling`; real clients
//! (`nexus_loadtest::signaling::SignalingConnection`) run on the bench thread. The
//! bench stands in for the orchestrator: it keeps each connection's outbound sender
//! (as `ParticipantHandle` does) and drops the rest of each event. Each connection
//! authenticates, receives a ~15 KB offer and sends a ~15 KB answer, then stays open;
//! what the server thread still holds, divided by the connections, is the figure.
//! Measured over plain WebSocket and over TLS.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nexus_loadtest::config::ConnectionOptions;
use nexus_loadtest::signaling::SignalingConnection;
use nexus_sfu::signal::{OrchestratorEvent, SignalMessage, SignalingConfig, SignalingServer};
use tokio::sync::mpsc;

use super::{kb, tagged, Tag, LIVE};

/// Connections measured together.
const CONNECTIONS: usize = 50;
/// SDP size of the offer and the answer exchanged on each connection.
const SDP_BYTES: usize = 15 * 1024;
/// HS256 secret for the server and the clients' minted tokens (≥ 32 bytes).
const JWT_SECRET: &str = "memory-bench-jwt-secret-0123456789abcdef";

/// Server-side bytes per connection.
pub struct Measured {
    plain: f64,
    tls: f64,
}

/// Measures plain WebSocket, then TLS.
pub fn measure() -> Measured {
    let plain = connection_cost(None);
    let (cert, key) = self_signed_pem();
    let tls = connection_cost(Some((cert.clone(), key.clone())));
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    Measured { plain, tls }
}

pub fn report(m: &Measured) {
    println!("\nSignaling per participant (server side; not session state, not in the budget)");
    println!(
        "  one WebSocket connection after a {} KB offer/answer exchange: ws {}, wss {}",
        SDP_BYTES / 1024,
        kb(m.plain).trim(),
        kb(m.tls).trim()
    );
    println!("  (connection task, outbound channel, tungstenite buffers, TLS session state)");
}

fn signaling_live() -> isize {
    LIVE[Tag::Signaling as usize].load(Ordering::Relaxed)
}

/// Server bytes per connection; `tls` = (certificate, key) PEM paths.
fn connection_cost(tls: Option<(PathBuf, PathBuf)>) -> f64 {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (orchestrator_tx, mut orchestrator_rx) = mpsc::channel(4 * CONNECTIONS);
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
    let (cert, key) = tls.clone().unwrap_or_default();
    let config = SignalingConfig {
        ws_addr: "127.0.0.1:0".parse().expect("address"),
        tls_cert_path: cert.to_string_lossy().into_owned(),
        tls_key_path: key.to_string_lossy().into_owned(),
        jwt_secret: JWT_SECRET.to_string(),
        ..SignalingConfig::default()
    };
    let server_shutdown = Arc::clone(&shutdown);
    let server = std::thread::spawn(move || {
        tagged(Tag::Signaling, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server runtime");
            runtime.block_on(async move {
                let server = SignalingServer::new(config, server_shutdown, orchestrator_tx)
                    .expect("signaling server");
                addr_tx.send(server.local_addr()).expect("bench waits");
                server.run().await.expect("signaling server run");
            });
        })
    });
    let addr = addr_rx.recv().expect("server address");
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    let url = format!("{scheme}://{addr}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("client runtime");
    let per_connection = runtime.block_on(exchange(&url, &mut orchestrator_rx));
    shutdown.store(true, Ordering::Release);
    server.join().expect("server thread");
    per_connection
}

/// Opens `CONNECTIONS` connections, each with one offer/answer exchange, and returns
/// the server thread's growth per connection while they are all open.
async fn exchange(url: &str, orchestrator_rx: &mut mpsc::Receiver<OrchestratorEvent>) -> f64 {
    let options = ConnectionOptions {
        auth_token: None,
        jwt_secret: Some(JWT_SECRET.to_string()),
        insecure_tls: true,
    };
    // Let the server reach its accept loop before the baseline.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = signaling_live();
    let mut clients = Vec::with_capacity(CONNECTIONS);
    let mut outbound = Vec::with_capacity(CONNECTIONS);
    for i in 0..CONNECTIONS {
        let mut client = SignalingConnection::connect(url, &options, &format!("p{i}"))
            .await
            .expect("client connects");
        let Some(OrchestratorEvent::Connected { outbound_tx, .. }) = orchestrator_rx.recv().await
        else {
            panic!("connection {i}: no Connected event");
        };
        let offer = SignalMessage::Offer {
            sdp: "o".repeat(SDP_BYTES),
            tracks: Vec::new(),
        };
        outbound_tx
            .send(offer)
            .await
            .expect("server connection open");
        match client.recv().await.expect("offer") {
            SignalMessage::Offer { sdp, .. } => assert_eq!(sdp.len(), SDP_BYTES),
            other => panic!("expected the offer, got {other:?}"),
        }
        let answer = SignalMessage::Answer {
            sdp: "a".repeat(SDP_BYTES),
        };
        client.send(answer).await.expect("answer sent");
        match orchestrator_rx.recv().await {
            Some(OrchestratorEvent::Message {
                message: SignalMessage::Answer { sdp },
                ..
            }) => assert_eq!(sdp.len(), SDP_BYTES),
            _ => panic!("connection {i}: expected the answer"),
        }
        clients.push(client);
        outbound.push(outbound_tx);
    }
    // Let the server tasks finish their writes.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let grown = signaling_live() - before;
    for mut client in clients {
        let _ = client.close().await;
    }
    drop(outbound);
    grown as f64 / CONNECTIONS as f64
}

/// A self-signed certificate and PKCS#8 key for `localhost`, written as PEM files in
/// the temporary directory.
fn self_signed_pem() -> (PathBuf, PathBuf) {
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509NameBuilder, X509};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
    let key = PKey::from_ec_key(EcKey::generate(&group).expect("EC key")).expect("key");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", "localhost").expect("CN");
    let name = name.build();
    let mut builder = X509::builder().expect("certificate");
    builder.set_version(2).expect("version");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("public key");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("time"))
        .expect("not before");
    builder
        .set_not_after(&Asn1Time::days_from_now(1).expect("time"))
        .expect("not after");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let certificate = builder.build();
    let dir = std::env::temp_dir();
    let id = std::process::id();
    let cert_path = dir.join(format!("nexus-memory-bench-{id}-cert.pem"));
    let key_path = dir.join(format!("nexus-memory-bench-{id}-key.pem"));
    let write = |path: &PathBuf, bytes: &[u8]| {
        let mut file = std::fs::File::create(path).expect("create PEM file");
        file.write_all(bytes).expect("write PEM file");
    };
    write(&cert_path, &certificate.to_pem().expect("certificate PEM"));
    write(&key_path, &key.private_key_to_pem_pkcs8().expect("key PEM"));
    (cert_path, key_path)
}
