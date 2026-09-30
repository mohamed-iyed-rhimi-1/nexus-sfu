//! Shared setup for the end-to-end tests: an in-process SFU on ephemeral
//! ports and webrtc-rs clients from `nexus-loadtest`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_dataplane::{ShardId, ShardStatsSnapshot};
use nexus_loadtest::client::HeadlessClient;
use nexus_loadtest::lossy::LossRules;
use nexus_loadtest::{ClientConfig, ClientRole, ConnectionOptions};
use nexus_sfu::config::NexusConfig;
use nexus_sfu::server::{self, ServerHandle};

/// JWT secret shared by the server and the clients (>= 32 characters).
pub const JWT_SECRET: &str = "e2e-test-secret-at-least-32-characters";

/// Signaling and ICE deadline for one client step.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Media tests run one at a time: each server runs one thread per shard beside
/// webrtc-rs clients, and CI runners have few cores. Signaling-only tests
/// (no ICE, no media) do not take it.
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

/// How long a test waits for shard gauges to reach a state: more than two
/// stats publishes (once a second).
pub const STATS_TIMEOUT: Duration = Duration::from_secs(5);

/// Server config: every port ephemeral, plain WebSocket, one shard.
pub fn test_config() -> NexusConfig {
    test_config_shards(1)
}

/// Server config with `shards` shards (each on its own ephemeral port). A
/// room's next session goes to another shard once it has one on the current
/// one (`room_shard_max_sessions = 1`), so real placement spreads a room.
pub fn test_config_shards(shards: u16) -> NexusConfig {
    assert!((1..=4).contains(&shards));
    let mut config = NexusConfig::default();
    config.transport.media_bind_addr = "0.0.0.0:0".parse().unwrap();
    config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.transport.announced_ips = vec![announced_ip()];
    config.transport.tls_cert_path.clear();
    config.transport.tls_key_path.clear();
    config.security.jwt_secret = JWT_SECRET.to_string();
    config.api.jwt_secret = JWT_SECRET.to_string();
    config.api.enabled = false;
    config.drain_timeout_ms = 50;
    config.cluster.node_id = 1;
    config.dataplane.shards = shards;
    config.dataplane.room_shard_max_sessions = 1;
    config
}

/// A server on `test_config()` (one shard).
pub async fn start_server() -> ServerHandle {
    start_server_with(test_config()).await
}

/// A server on `test_config_shards(shards)`.
pub async fn start_server_shards(shards: u16) -> ServerHandle {
    start_server_with(test_config_shards(shards)).await
}

pub async fn start_server_with(config: NexusConfig) -> ServerHandle {
    let shards = usize::from(config.dataplane.shards);
    let server = server::start(config).await.expect("server starts");
    let ports: Vec<u16> = server.media_addrs().iter().map(|a| a.port()).collect();
    assert_eq!(ports.len(), shards, "one media socket per shard");
    assert_eq!(server.dataplane().shard_count(), shards);
    assert!(ports.iter().all(|&p| p != 0), "{ports:?}");
    let distinct: std::collections::BTreeSet<u16> = ports.iter().copied().collect();
    assert_eq!(distinct.len(), shards, "a port per shard: {ports:?}");
    assert_ne!(server.signaling_addr().port(), 0);
    server
}

/// Each shard's last published stats, by shard index.
pub fn shard_stats(server: &ServerHandle) -> Vec<ShardStatsSnapshot> {
    let shards = u8::try_from(server.dataplane().shard_count()).expect("≤ 16 shards");
    assert!(shards >= 1);
    (0..shards)
        .map(|i| server.dataplane().stats(ShardId::new(i)))
        .collect()
}

/// The shards' stats summed: the process's counters and table sizes.
pub fn total_stats(server: &ServerHandle) -> ShardStatsSnapshot {
    sum_stats(&shard_stats(server))
}

/// `stats` summed over shards.
pub fn sum_stats(stats: &[ShardStatsSnapshot]) -> ShardStatsSnapshot {
    let mut total = ShardStatsSnapshot::default();
    for shard in stats {
        total.add(shard);
    }
    total
}

/// Every shard's first stats published after the call, so counters include
/// everything the shards did before it. A publish runs inside an iteration,
/// so a newer one has a larger `iterations`; a parked shard still wakes for
/// its once-a-second publish.
pub async fn next_stats(server: &ServerHandle) -> Vec<ShardStatsSnapshot> {
    let start: Vec<u64> = shard_stats(server)
        .iter()
        .map(|s| s.counters.iterations)
        .collect();
    let deadline = Instant::now() + STATS_TIMEOUT;
    loop {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let stats = shard_stats(server);
        if stats
            .iter()
            .zip(&start)
            .all(|(s, i)| s.counters.iterations != *i)
        {
            return stats;
        }
        let stale: Vec<usize> = (0..start.len())
            .filter(|&i| stats[i].counters.iterations == start[i])
            .collect();
        assert!(
            Instant::now() < deadline,
            "shards {stale:?} published no stats within {STATS_TIMEOUT:?}"
        );
    }
}

/// `total_stats` from the next publish (`next_stats`).
pub async fn settled_total_stats(server: &ServerHandle) -> ShardStatsSnapshot {
    sum_stats(&next_stats(server).await)
}

/// Per shard, every counter of `after` that grew since `before` and is a
/// drop (`drop_*`), plus the datagrams received, sent and handed off, for a
/// failure report.
pub fn drop_report(before: &[ShardStatsSnapshot], after: &[ShardStatsSnapshot]) -> String {
    assert_eq!(before.len(), after.len());
    let names = nexus_dataplane::ShardCounters::NAMES;
    let mut report = String::new();
    for (i, (b, a)) in before.iter().zip(after).enumerate() {
        let (b, a) = (b.counters.values(), a.counters.values());
        let grew = |name: &'static str| {
            let k = names.iter().position(|n| *n == name).expect("counter");
            (name, a[k].saturating_sub(b[k]))
        };
        let context = ["rx_datagrams", "tx_datagrams", "xs_tx", "xs_rx"];
        let drops = names.iter().copied().filter(|n| n.starts_with("drop_"));
        let lines: Vec<String> = context
            .into_iter()
            .map(grew)
            .chain(drops.map(grew).filter(|(_, d)| *d > 0))
            .map(|(name, d)| format!("{name} +{d}"))
            .collect();
        report.push_str(&format!("  shard {i}: {}\n", lines.join(", ")));
    }
    report
}

/// The table sizes a test compares per shard (`xs_in_flight` and `rx_pps`
/// move while media flows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardView {
    pub sessions: u64,
    pub tracks: u64,
    pub subscriptions: u64,
    pub mirrors: u64,
}

impl ShardView {
    pub const fn new(sessions: u64, tracks: u64, subscriptions: u64, mirrors: u64) -> Self {
        Self {
            sessions,
            tracks,
            subscriptions,
            mirrors,
        }
    }

    pub fn of(stats: &ShardStatsSnapshot) -> Self {
        let g = &stats.gauges;
        Self::new(g.sessions, g.tracks, g.subscriptions, g.mirrors)
    }
}

/// Per-shard views of `stats`.
pub fn views(stats: &[ShardStatsSnapshot]) -> Vec<ShardView> {
    stats.iter().map(ShardView::of).collect()
}

/// Poll the shards' stats until `done` holds; panics after `STATS_TIMEOUT`
/// naming `what` with the last per-shard gauges. Returns the stats that
/// satisfied it.
pub async fn wait_for_shards(
    server: &ServerHandle,
    what: &str,
    done: impl Fn(&[ShardStatsSnapshot]) -> bool,
) -> Vec<ShardStatsSnapshot> {
    let deadline = Instant::now() + STATS_TIMEOUT;
    loop {
        let stats = shard_stats(server);
        if done(&stats) {
            return stats;
        }
        let gauges: Vec<_> = stats.iter().map(|s| s.gauges).collect();
        assert!(
            Instant::now() < deadline,
            "{what}: not reached within {STATS_TIMEOUT:?}: {gauges:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until the per-shard `sessions` gauges are exactly `sessions`: which
/// shard each participant's session is on, as placement put it.
pub async fn wait_for_sessions(server: &ServerHandle, sessions: &[u64]) -> Vec<ShardStatsSnapshot> {
    let what = format!("sessions per shard {sessions:?}");
    wait_for_shards(server, &what, |stats| {
        stats.len() == sessions.len()
            && stats
                .iter()
                .zip(sessions)
                .all(|(s, n)| s.gauges.sessions == *n)
    })
    .await
}

/// Wait until every shard's table sizes are exactly `expected`.
pub async fn wait_for_views(server: &ServerHandle, what: &str, expected: &[ShardView]) {
    wait_for_shards(server, what, |stats| views(stats) == expected).await;
}

/// Index of the only shard for which `pick(index, stats)` holds.
pub fn only_shard(
    stats: &[ShardStatsSnapshot],
    pick: impl Fn(usize, &ShardStatsSnapshot) -> bool,
) -> usize {
    let found: Vec<usize> = (0..stats.len()).filter(|&i| pick(i, &stats[i])).collect();
    assert_eq!(found.len(), 1, "one shard expected: {:#?}", views(stats));
    found[0]
}

/// No cross-shard message was dropped for want of room or credit, and none
/// was malformed. `drop_xs_no_track` is not checked: a hand-off can race with
/// `Subscribe` or `RemoveTrack` on the receiving shard (its documented race).
pub fn assert_no_xs_drops(stats: &[ShardStatsSnapshot]) {
    for (i, s) in stats.iter().enumerate() {
        let c = &s.counters;
        assert_eq!(c.drop_xs_full, 0, "shard {i}: {s:?}");
        assert_eq!(c.drop_xs_credit, 0, "shard {i}: {s:?}");
        assert_eq!(c.drop_xs_malformed, 0, "shard {i}: {s:?}");
    }
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

/// A client that joined, publishes audio + video with ICE up, and has its
/// signaling task running.
pub async fn publishing_client(config: ClientConfig) -> HeadlessClient {
    let mut client = HeadlessClient::new(config).await.unwrap();
    client.connect().await.expect("connects");
    client.start_publishing().await.expect("publishes");
    client
        .start_signaling_task()
        .expect("signaling task starts");
    client
}

/// Wait until `client` has received at least `min` packets on each of `ssrcs`.
pub async fn wait_for_media(client: &HeadlessClient, ssrcs: &[u32], min: u64, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let stats = client.track_stats();
        let has = |ssrc: &u32| stats.iter().any(|t| t.ssrc == *ssrc && t.packets >= min);
        if ssrcs.iter().all(has) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no media on {ssrcs:x?}: {stats:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
