//! Node identity, distributed state and gossip.
//!
//! What a running SFU node owns besides its data plane: the CRDT actor id,
//! the `DistributedState` the orchestrator and the REST API read, the SWIM
//! gossip thread that keeps it in sync with other nodes, and the shutdown
//! notice sent to signaling clients.
//!
//! `Sfu::new` starts a `Node` until the old path is deleted; after the switch
//! to the new data plane `server::start` does.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_state::{DistributedState, GossipConfig, StateUpdate, SwimProtocol, MAX_ACTORS};
use tracing::{debug, info, warn};

use crate::config::{ClusterConfig, NexusConfig};
use crate::signal::{SignalMessage, SignalingConnections};

/// Upper bound on shutdown notices sent in one pass.
pub const MAX_SHUTDOWN_NOTICES: u32 = 10_000;

/// State updates forwarded to gossip per iteration (the channel is unbounded).
const MAX_UPDATES_PER_ITERATION: u32 = 4_096;

/// Why a node could not start.
#[derive(Debug)]
pub enum NodeError {
    /// `cluster.node_id` is outside the CRDT actor range.
    InvalidNodeId { node_id: u64, max: u64 },
    /// The SWIM protocol could not be created (socket bind).
    Gossip(String),
    /// The gossip thread could not be spawned.
    Thread(std::io::Error),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::InvalidNodeId { node_id, max } => write!(
                f,
                "cluster.node_id ({}) must be < MAX_ACTORS ({})",
                node_id, max
            ),
            NodeError::Gossip(message) => write!(f, "failed to create SwimProtocol: {}", message),
            NodeError::Thread(e) => write!(f, "failed to spawn gossip thread: {}", e),
        }
    }
}

impl std::error::Error for NodeError {}

/// The CRDT actor id of this node: `cluster.node_id` when set, else derived
/// from the host name (or random bytes), the process id and the wall clock.
pub fn actor_id(cluster: &ClusterConfig) -> Result<u64, NodeError> {
    let max = MAX_ACTORS as u64;
    assert!(max > 1, "actor range must hold at least one non-zero id");
    let id = if cluster.node_id > 0 {
        if cluster.node_id >= max {
            return Err(NodeError::InvalidNodeId {
                node_id: cluster.node_id,
                max,
            });
        }
        cluster.node_id
    } else {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        match std::env::var("HOSTNAME") {
            Ok(hostname) => hostname.hash(&mut hasher),
            Err(_) => rand::random::<[u8; 8]>().hash(&mut hasher),
        }
        std::process::id().hash(&mut hasher);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.hash(&mut hasher);
        // Map into 1..MAX_ACTORS: actor 0 is reserved.
        (hasher.finish() % (max - 1)) + 1
    };
    assert!(id > 0 && id < max, "actor id in 1..MAX_ACTORS");
    Ok(id)
}

/// A running node: distributed state plus, in a configured cluster, its gossip
/// thread.
pub struct Node {
    actor_id: u64,
    state: Arc<DistributedState>,
    /// `None` on a single node (`cluster.gossip_enabled` off, the default).
    gossip_addr: Option<SocketAddr>,
    stop_tx: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Node {
    /// Create the distributed state and, when `cluster.gossip_enabled`, start
    /// gossip. The gossip thread also stops when `shutdown` is set.
    ///
    /// Without a cluster no gossip socket is opened: gossip is unauthenticated,
    /// and v1 is single-node.
    pub fn start(config: &NexusConfig, shutdown: Arc<AtomicBool>) -> Result<Self, NodeError> {
        let actor_id = actor_id(&config.cluster)?;
        info!("Node actor ID: {}", actor_id);

        let state_config = nexus_state::DistributedStateConfig::new(actor_id);
        let state = Arc::new(DistributedState::new(state_config));
        if !config.cluster.gossip_enabled {
            info!("Gossip off (single node): cluster.gossip_enabled is false");
            assert_eq!(state.local_actor(), actor_id);
            return Ok(Self {
                actor_id,
                state,
                gossip_addr: None,
                stop_tx: None,
                thread: None,
            });
        }
        let (updates_tx, updates_rx) = mpsc::channel::<StateUpdate>();
        state.set_broadcast_sender(updates_tx);

        let swim = build_swim(config, actor_id, &state)?;
        let gossip_addr = swim.local_addr();
        info!("Gossip protocol bound to {}", gossip_addr);

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let gossip = GossipLoop {
            swim,
            state: state.clone(),
            shutdown,
            stop_rx,
            updates_rx,
            probe_interval: Duration::from_millis(config.gossip.probe_interval_ms),
        };
        let thread = std::thread::Builder::new()
            .name("nexus-gossip".into())
            .spawn(move || gossip.run())
            .map_err(NodeError::Thread)?;

        assert_eq!(state.local_actor(), actor_id);
        Ok(Self {
            actor_id,
            state,
            gossip_addr: Some(gossip_addr),
            stop_tx: Some(stop_tx),
            thread: Some(thread),
        })
    }

    /// This node's CRDT actor id.
    pub fn actor_id(&self) -> u64 {
        self.actor_id
    }

    /// The distributed state shared with the orchestrator and the API.
    pub fn distributed_state(&self) -> &Arc<DistributedState> {
        &self.state
    }

    /// The address the gossip socket bound; `None` without a cluster.
    pub fn gossip_addr(&self) -> Option<SocketAddr> {
        self.gossip_addr
    }

    /// Stop the gossip thread and wait for it (at most one probe interval).
    /// Idempotent. Blocks: call it from `spawn_blocking` in async code.
    pub fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread.take() {
            match handle.join() {
                Ok(()) => info!("Gossip thread shutdown complete"),
                Err(_) => warn!("Gossip thread panicked during shutdown"),
            }
        }
        assert!(self.stop_tx.is_none() && self.thread.is_none());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Signal only: joining could block an async caller for a probe interval.
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn build_swim(
    config: &NexusConfig,
    actor_id: u64,
    state: &Arc<DistributedState>,
) -> Result<SwimProtocol, NodeError> {
    let gossip_config = GossipConfig {
        probe_interval_ms: config.gossip.probe_interval_ms,
        ping_timeout_ms: config.gossip.ping_timeout_ms,
        suspect_timeout_ms: config.gossip.suspect_timeout_ms,
        fanout: config.gossip.fanout,
        max_piggyback_updates: config.gossip.max_piggyback_updates,
        seed_peers: config.gossip.seed_peers.clone(),
    };
    // Validated: a specific interface address (port 0: the OS assigns it).
    let Some(bind_addr) = config.cluster.gossip_bind_addr else {
        return Err(NodeError::Gossip(
            "cluster.gossip_bind_addr is not set".into(),
        ));
    };
    assert!(
        !bind_addr.ip().is_unspecified(),
        "validated by ClusterConfig"
    );
    let mut swim = SwimProtocol::new(actor_id, bind_addr, gossip_config)
        .map_err(|e| NodeError::Gossip(format!("{:?}", e)))?;
    swim.set_distributed_state(state.clone());

    for seed in &config.gossip.seed_peers {
        match swim.add_seed_peer(seed.actor_id, seed.addr) {
            Ok(_) => info!(
                "Added seed peer: actor_id={}, addr={}",
                seed.actor_id, seed.addr
            ),
            Err(e) => warn!("Failed to add seed peer {}: {:?}", seed.addr, e),
        }
    }
    Ok(swim)
}

/// The gossip thread's state.
struct GossipLoop {
    swim: SwimProtocol,
    state: Arc<DistributedState>,
    shutdown: Arc<AtomicBool>,
    stop_rx: mpsc::Receiver<()>,
    updates_rx: mpsc::Receiver<StateUpdate>,
    probe_interval: Duration,
}

impl GossipLoop {
    fn run(mut self) {
        info!("Gossip thread started");
        while self.iteration() {
            std::thread::sleep(self.probe_interval);
        }
        info!("Gossip thread stopped");
    }

    /// One probe cycle; `false` when the thread should stop.
    fn iteration(&mut self) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            info!("Gossip thread detected shared shutdown signal");
            return false;
        }
        // A disconnected channel means the `Node` is gone.
        match self.stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return false,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let mut forwarded = 0;
        while forwarded < MAX_UPDATES_PER_ITERATION {
            let Ok(update) = self.updates_rx.try_recv() else {
                break;
            };
            self.swim.broadcast_state_update(update);
            forwarded += 1;
        }

        match self.swim.run_probe_cycle() {
            Ok(dead_nodes) => {
                for dead in dead_nodes {
                    let (tracks, subs) = self.state.handle_node_failure(dead);
                    if tracks > 0 || subs > 0 {
                        info!(
                            "Handled node failure for actor {}: removed {} tracks, {} subscriptions",
                            dead, tracks, subs
                        );
                    }
                }
            }
            Err(e) => warn!("Gossip probe cycle error: {:?}", e),
        }
        if let Err(e) = self.swim.recv_loop_iteration() {
            warn!("Gossip recv error: {:?}", e);
        }
        true
    }
}

/// Tell every signaling client the server is shutting down. Returns the number
/// of clients notified (bounded by `MAX_SHUTDOWN_NOTICES`).
pub fn notify_shutdown(connections: &SignalingConnections, drain_seconds: u32) -> u32 {
    let message = SignalMessage::ServerShutdown {
        reason: "Server shutting down for maintenance".to_string(),
        drain_seconds,
    };
    let mut notified: u32 = 0;
    for (visited, entry) in connections.iter().enumerate() {
        if visited as u32 >= MAX_SHUTDOWN_NOTICES {
            warn!(
                "Notification limit reached ({}), some participants not notified",
                MAX_SHUTDOWN_NOTICES
            );
            break;
        }
        let participant_id = *entry.key();
        match entry.value().sender.try_send(message.clone()) {
            Ok(()) => {
                notified += 1;
                debug!(participant_id, "Shutdown notification sent");
            }
            Err(e) => warn!(participant_id, error = %e, "Failed to send shutdown notification"),
        }
    }
    assert!(notified <= MAX_SHUTDOWN_NOTICES);
    info!(
        notified,
        total_connections = connections.len(),
        drain_seconds,
        "Shutdown notifications sent"
    );
    notified
}

/// Notify the clients (if the signaling server is up), then wait `drain`.
pub async fn notify_and_drain(connections: Option<&SignalingConnections>, drain: Duration) {
    if let Some(connections) = connections {
        let drain_seconds = u32::try_from(drain.as_secs()).unwrap_or(u32::MAX);
        notify_shutdown(connections, drain_seconds);
    }
    if !drain.is_zero() {
        info!("Draining for {:?}", drain);
        tokio::time::sleep(drain).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_signal::websocket::{new_signaling_connections, SignalingConnectionHandle};

    fn cluster(node_id: u64) -> ClusterConfig {
        ClusterConfig {
            node_id,
            ..ClusterConfig::default()
        }
    }

    /// A config with gossip on, bound to loopback.
    fn clustered(node_id: u64) -> NexusConfig {
        let mut config = NexusConfig::default();
        config.cluster.node_id = node_id;
        config.cluster.gossip_enabled = true;
        config.cluster.gossip_bind_addr = Some("127.0.0.1:0".parse().unwrap());
        config.gossip.probe_interval_ms = 10;
        config
    }

    #[test]
    fn single_node_opens_no_gossip_socket() {
        let mut config = NexusConfig::default();
        config.cluster.node_id = 42;
        assert!(!config.cluster.gossip_enabled, "off by default");
        let mut node = Node::start(&config, Arc::new(AtomicBool::new(false))).unwrap();
        assert_eq!(node.gossip_addr(), None);
        assert!(node.thread.is_none());
        assert_eq!(node.distributed_state().local_actor(), 42);
        node.stop();
    }

    #[test]
    fn gossip_config_is_validated() {
        let mut config = clustered(1);
        assert!(config.cluster.validate().is_ok());
        config.cluster.gossip_bind_addr = None;
        assert!(config.cluster.validate().is_err());
        config.cluster.gossip_bind_addr = Some("0.0.0.0:7946".parse().unwrap());
        assert!(config.cluster.validate().is_err(), "wildcard refused");
        config.cluster.gossip_bind_addr = Some("[::]:7946".parse().unwrap());
        assert!(config.cluster.validate().is_err(), "wildcard refused");

        let mut single = NexusConfig::default();
        single.gossip.seed_peers = vec![nexus_state::SeedPeer::new(
            2,
            "192.0.2.2:7946".parse().unwrap(),
        )];
        assert!(single.validate().is_err(), "seed peers without a cluster");
    }

    #[test]
    fn explicit_node_id_is_used() {
        assert_eq!(actor_id(&cluster(42)).unwrap(), 42);
    }

    #[test]
    fn generated_node_id_is_in_range() {
        for _ in 0..100 {
            let id = actor_id(&cluster(0)).unwrap();
            assert!(id > 0 && id < MAX_ACTORS as u64);
        }
    }

    #[test]
    fn node_id_out_of_range_is_refused() {
        let err = actor_id(&cluster(1000)).unwrap_err();
        assert!(matches!(
            err,
            NodeError::InvalidNodeId { node_id: 1000, .. }
        ));
        assert!(err.to_string().contains("MAX_ACTORS"));
        assert!(actor_id(&cluster(MAX_ACTORS as u64)).is_err());
    }

    #[test]
    fn node_starts_and_stops() {
        let config = clustered(42);
        let mut node = Node::start(&config, Arc::new(AtomicBool::new(false))).unwrap();
        assert_eq!(node.actor_id(), 42);
        assert_eq!(node.distributed_state().local_actor(), 42);
        let addr = node.gossip_addr().expect("gossip on");
        assert!(addr.ip().is_loopback(), "bound where configured: {addr}");
        assert_ne!(addr.port(), 0);
        node.stop();
        node.stop(); // idempotent
    }

    #[test]
    fn gossip_stops_on_shared_shutdown() {
        let config = clustered(7);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut node = Node::start(&config, shutdown.clone()).unwrap();
        shutdown.store(true, Ordering::SeqCst);
        let handle = node.thread.take().unwrap();
        handle.join().unwrap();
        node.stop();
    }

    #[tokio::test]
    async fn shutdown_notice_reaches_every_client() {
        let connections = new_signaling_connections();
        let mut receivers = Vec::new();
        for id in 1..=3u64 {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            connections.insert(id, SignalingConnectionHandle { sender: tx });
            receivers.push(rx);
        }
        assert_eq!(notify_shutdown(&connections, 5), 3);
        for rx in &mut receivers {
            match rx.try_recv().unwrap() {
                SignalMessage::ServerShutdown { drain_seconds, .. } => {
                    assert_eq!(drain_seconds, 5)
                }
                other => panic!("unexpected {:?}", other),
            }
        }
        notify_and_drain(Some(&connections), Duration::ZERO).await;
        assert!(receivers[0].try_recv().is_ok());
    }
}
