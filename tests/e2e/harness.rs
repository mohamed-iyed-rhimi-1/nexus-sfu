//! Shared setup for the end-to-end tests: an in-process SFU on ephemeral
//! ports and webrtc-rs clients from `nexus-loadtest`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nexus_loadtest::lossy::LossRules;
use nexus_loadtest::{ClientConfig, ClientRole, ConnectionOptions, TrackRxStats};
use nexus_sfu::config::NexusConfig;
use nexus_sfu::server::{self, ServerHandle};

/// JWT secret shared by the server and the clients (>= 32 characters).
pub const JWT_SECRET: &str = "e2e-test-secret-at-least-32-characters";

/// Signaling and ICE deadline for one client step.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Servers are started one test at a time: each runs a spinning ingress
/// thread and worker, and CI runners have few cores.
pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Log to stderr when `RUST_LOG` is set (`cargo test -- --nocapture`).
pub fn init_logging() {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    }
}

/// The address the SFU announces. webrtc-rs never offers loopback
/// candidates, so a client can only pair with a candidate on a real
/// interface; the SFU and clients share this host.
pub fn announced_ip() -> IpAddr {
    let ips = nexus_sfu::nexus_transport::ice::gather::host_interface_ips(IpAddr::is_ipv4);
    ips.iter()
        .flatten()
        .copied()
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
        .expect("e2e tests need a non-loopback IPv4 interface")
}

/// Server config: every port ephemeral, plain WebSocket, one worker.
pub fn test_config() -> NexusConfig {
    let mut config = NexusConfig::default();
    config.transport.media_bind_addr = "0.0.0.0:0".parse().unwrap();
    config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.transport.announced_ips = vec![announced_ip()];
    config.transport.tls_cert_path.clear();
    config.transport.tls_key_path.clear();
    config.security.jwt_secret = JWT_SECRET.to_string();
    config.api.jwt_secret = JWT_SECRET.to_string();
    config.api.enabled = false;
    config.worker.num_workers = 1;
    config.worker.cpu_affinity = false;
    config.memory.arena_size_mb = 16;
    config.drain_timeout_ms = 50;
    config.cluster.node_id = 1;
    config
}

pub async fn start_server() -> ServerHandle {
    let server = server::start(test_config()).await.expect("server starts");
    assert_ne!(server.media_addr().port(), 0);
    assert_ne!(server.signaling_addr().port(), 0);
    server
}

pub fn ws_url(server: &ServerHandle) -> String {
    format!("ws://{}", server.signaling_addr())
}

/// A publishing and subscribing client for `room`, offline (no STUN).
pub fn client_config(server: &ServerHandle, room: &str) -> ClientConfig {
    ClientConfig {
        sfu_url: ws_url(server),
        room: room.to_string(),
        role: ClientRole::Participant,
        connection_timeout: STEP_TIMEOUT,
        connection: ConnectionOptions {
            jwt_secret: Some(JWT_SECRET.to_string()),
            ..Default::default()
        },
        default_stun: false,
        ipv4_only: true,
        ..Default::default()
    }
}

/// A client whose socket drops datagrams by `rules`.
pub fn lossy_client_config(
    server: &ServerHandle,
    room: &str,
    rules: &Arc<LossRules>,
) -> ClientConfig {
    ClientConfig {
        loss: Some(Arc::clone(rules)),
        ..client_config(server, room)
    }
}

/// Packets received per track between two snapshots, by SSRC.
pub fn delta(before: &[TrackRxStats], after: &TrackRxStats) -> u64 {
    let start = before
        .iter()
        .find(|t| t.ssrc == after.ssrc)
        .map_or(0, |t| t.packets);
    after.packets - start
}

/// Parse `candidate:<foundation> <component> <transport> <priority> <ip>
/// <port> typ <type> ...` into its address and type.
pub fn parse_candidate(candidate: &str) -> Option<(SocketAddr, String)> {
    let fields: Vec<&str> = candidate
        .trim_start_matches("a=")
        .trim_start_matches("candidate:")
        .split_whitespace()
        .collect();
    let ip: IpAddr = fields.get(4)?.parse().ok()?;
    let port: u16 = fields.get(5)?.parse().ok()?;
    let typ = fields.get(7)?.to_string();
    Some((SocketAddr::new(ip, port), typ))
}
