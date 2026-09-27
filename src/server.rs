//! Server startup: everything `main.rs` used to wire by hand, as a library
//! function, so the end-to-end tests run the same startup in-process.
//!
//! ```text
//! start(config)
//!  ├─ Node                node id, distributed state, gossip thread
//!  ├─ Dataplane           one socket and one thread per shard (nexus-dataplane)
//!  ├─ SignalingServer     WebSocket listener (bound before anything runs)
//!  ├─ SessionOrchestrator tokio task: signaling + data-plane events → commands
//!  └─ ApiServer           tokio task (if api.enabled)
//! ```
//!
//! `start` does not initialise tracing and does not install signal handlers;
//! `main.rs` does both. Ports may be 0: the bound addresses are in the
//! returned handle, and ICE candidates carry the bound media ports.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nexus_dataplane::{Dataplane, DataplaneHandle, SingleShard};
use nexus_metrics::MetricsCollector;
use nexus_state::DistributedState;
use nexus_transport::dtls::DtlsCertificate;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::NexusConfig;
use crate::node::{self, Node};
use crate::orchestrator::candidates;
use crate::orchestrator::plane::{Established, EstablishedLog};
use crate::orchestrator::SessionOrchestrator;
use crate::signal::{OrchestratorEvent, SignalingConfig, SignalingConnections, SignalingServer};

/// Bound on waiting for the control-plane tasks at shutdown.
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Queue depth between signaling and the orchestrator.
const ORCHESTRATOR_QUEUE: usize = 4096;

/// A running server. Dropping it without `shutdown` stops it abruptly.
pub struct ServerHandle {
    media_addrs: Vec<SocketAddr>,
    signaling_addr: SocketAddr,
    candidate_addrs: Vec<SocketAddr>,
    shared_shutdown: Arc<AtomicBool>,
    /// Set when the shutdown drain starts: `/ready` answers 503 from then on.
    draining: Arc<AtomicBool>,
    dataplane: Arc<DataplaneHandle>,
    node: Option<Node>,
    connections: SignalingConnections,
    established: EstablishedLog,
    drain: Duration,
    tasks: Vec<JoinHandle<()>>,
}

impl ServerHandle {
    /// Addresses the media UDP sockets are bound to, one per shard.
    pub fn media_addrs(&self) -> &[SocketAddr] {
        &self.media_addrs
    }

    /// Address the WebSocket signaling listener is bound to.
    pub fn signaling_addr(&self) -> SocketAddr {
        self.signaling_addr
    }

    /// Addresses advertised as ICE host candidates (shard 0's).
    pub fn candidate_addrs(&self) -> &[SocketAddr] {
        &self.candidate_addrs
    }

    /// The data plane (stats, for tests and metrics).
    pub fn dataplane(&self) -> &DataplaneHandle {
        &self.dataplane
    }

    /// Sessions whose DTLS handshake completed, with the SFU's role and the negotiated
    /// SRTP profile (the last `MAX_ESTABLISHED_LOG`).
    pub fn established(&self) -> Vec<Established> {
        self.established.snapshot()
    }

    /// True once the data plane stopped (a shard thread ended, or after shutdown).
    pub fn is_finished(&self) -> bool {
        !self.dataplane.is_running()
    }

    /// Graceful shutdown: notify clients, drain for `drain_timeout_ms`, then stop the
    /// control-plane tasks, the shards and gossip. `Err` if the data plane had
    /// already stopped by itself.
    pub async fn shutdown(mut self) -> Result<(), String> {
        let stopped_early = self.is_finished();
        // Load balancers see 503 during the drain; /health keeps answering until the
        // API task stops with the others below.
        self.draining.store(true, Ordering::Release);
        node::notify_and_drain(Some(&self.connections), self.drain).await;
        self.shared_shutdown.store(true, Ordering::Release);
        let tasks = std::mem::take(&mut self.tasks);
        let joined = tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, async {
            for task in tasks {
                let _ = task.await;
            }
        })
        .await;
        if joined.is_err() {
            error!(
                "Control-plane tasks did not stop within {:?}",
                TASK_SHUTDOWN_TIMEOUT
            );
        }
        let dataplane = Arc::clone(&self.dataplane);
        let node = self.node.take();
        tokio::task::spawn_blocking(move || {
            dataplane.shutdown();
            if let Some(mut node) = node {
                node.stop();
            }
        })
        .await
        .map_err(|e| format!("shutdown join: {e}"))?;
        assert!(self.tasks.is_empty() && !self.dataplane.is_running());
        if stopped_early {
            return Err("the data plane stopped before shutdown".to_string());
        }
        Ok(())
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shared_shutdown.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
        // Idempotent; bounded (the shards check their stop flag every iteration).
        self.dataplane.shutdown();
    }
}

/// Start the SFU. Must be called inside a multi-threaded tokio runtime.
pub async fn start(config: NexusConfig) -> Result<ServerHandle, String> {
    config
        .validate()
        .map_err(|e| format!("invalid config: {e}"))?;
    let shared_shutdown = Arc::new(AtomicBool::new(false));
    let node = Node::start(&config, shared_shutdown.clone())
        .map_err(|e| format!("failed to start node: {e}"))?;
    let metrics = metrics_collector(config.dataplane.shards);

    let dataplane_config = config
        .to_dataplane_config()
        .map_err(|e| format!("invalid config: {e}"))?;
    let (dataplane, shards) =
        Dataplane::start(dataplane_config).map_err(|e| format!("data plane: {e}"))?;
    let dataplane = Arc::new(dataplane);
    let media_addrs: Vec<SocketAddr> = shards.iter().map(|s| s.local_addr).collect();
    let shard_candidates = shards
        .iter()
        .map(|s| candidates::resolve(&config.transport.announced_ips, s.local_addr))
        .collect::<Result<Vec<_>, _>>()?;
    let events = dataplane
        .take_events()
        .ok_or("data-plane events already taken")?;
    let certificate =
        DtlsCertificate::generate().map_err(|e| format!("DTLS certificate: {e:?}"))?;
    info!(media = ?media_addrs, "Data plane started");

    let (orchestrator_tx, orchestrator_rx) =
        tokio::sync::mpsc::channel::<OrchestratorEvent>(ORCHESTRATOR_QUEUE);
    let signaling = SignalingServer::new(
        signaling_config(&config),
        shared_shutdown.clone(),
        orchestrator_tx,
    )
    .map_err(|e| format!("failed to set up signaling: {e}"))?;
    let signaling_addr = signaling.local_addr();
    let connections = signaling.connections();

    let mut tasks = Vec::with_capacity(3);
    tasks.push(tokio::spawn(async move {
        if let Err(e) = signaling.run().await {
            error!("Signaling server error: {}", e);
        }
    }));
    info!("WebSocket signaling listening on {}", signaling_addr);

    let mut orchestrator = SessionOrchestrator::new(
        Arc::clone(&dataplane) as Arc<dyn crate::orchestrator::plane::CommandSink>,
        shard_candidates.clone(),
        Box::new(SingleShard),
        certificate,
        node.distributed_state().clone(),
    );
    let established = orchestrator.established_log();
    let orchestrator_shutdown = shared_shutdown.clone();
    tasks.push(tokio::spawn(async move {
        orchestrator
            .run(orchestrator_rx, events, orchestrator_shutdown)
            .await;
    }));

    let state = node.distributed_state().clone();
    let draining = Arc::new(AtomicBool::new(false));
    let readiness = ReadinessInputs {
        dataplane: Arc::clone(&dataplane),
        draining: Arc::clone(&draining),
        shutdown: shared_shutdown.clone(),
    };
    let api = start_api(&config, metrics, state, readiness)?;
    if let Some(api_task) = api {
        tasks.push(api_task);
    }

    let candidate_addrs = shard_candidates[0].clone();
    assert!(!candidate_addrs.is_empty() && media_addrs.len() == shard_candidates.len());
    Ok(ServerHandle {
        media_addrs,
        signaling_addr,
        candidate_addrs,
        shared_shutdown,
        draining,
        dataplane,
        node: Some(node),
        connections,
        established,
        drain: Duration::from_millis(u64::from(config.drain_timeout_ms)),
        tasks,
    })
}

/// The metrics collector; a failure disables metrics, it does not stop the server.
fn metrics_collector(shards: u16) -> Option<Arc<MetricsCollector>> {
    match MetricsCollector::new(u32::from(shards.max(1))) {
        Ok(m) => Some(Arc::new(m)),
        Err(e) => {
            warn!(
                "Failed to create metrics collector: {}, metrics disabled",
                e
            );
            None
        }
    }
}

fn signaling_config(config: &NexusConfig) -> SignalingConfig {
    SignalingConfig {
        ws_addr: config.transport.signaling_bind_addr,
        tls_cert_path: config.transport.tls_cert_path.clone(),
        tls_key_path: config.transport.tls_key_path.clone(),
        jwt_secret: config.security.jwt_secret.clone(),
        max_connections: config.transport.max_webrtc_sessions,
    }
}

/// The REST API, started last: when it reports ready, everything else runs. `/ready`
/// turns false if the data plane stops.
fn start_api(
    config: &NexusConfig,
    metrics: Option<Arc<MetricsCollector>>,
    state: Arc<DistributedState>,
    inputs: ReadinessInputs,
) -> Result<Option<JoinHandle<()>>, String> {
    if !config.api.enabled {
        info!("API server disabled");
        return Ok(None);
    }
    let api_addr: SocketAddr = config
        .api
        .bind_addr
        .parse()
        .map_err(|e| format!("invalid API bind address: {e}"))?;
    let api_server = crate::nexus_api::ApiServer::with_distributed_state(
        api_addr,
        &config.security.jwt_secret,
        metrics,
        state,
    );
    api_server.set_ready();
    let readiness = api_server.readiness();
    Ok(Some(tokio::spawn(async move {
        tokio::select! {
            result = api_server.run() => {
                if let Err(e) = result {
                    error!("API server error: {}", e);
                }
            }
            _ = track_readiness(readiness, inputs) => {
                info!("API server shutting down")
            }
        }
    })))
}

/// What `/ready` depends on.
struct ReadinessInputs {
    dataplane: Arc<DataplaneHandle>,
    /// The shutdown drain started.
    draining: Arc<AtomicBool>,
    /// The API task ends.
    shutdown: Arc<AtomicBool>,
}

/// Keep `/ready` in step (checked every 100 ms) until `shutdown`: ready while the
/// data plane runs and no drain started.
async fn track_readiness(readiness: crate::nexus_api::Readiness, inputs: ReadinessInputs) {
    while !inputs.shutdown.load(Ordering::Acquire) {
        let running = inputs.dataplane.is_running();
        let draining = inputs.draining.load(Ordering::Acquire);
        if readiness.get() && !running {
            warn!("Data plane stopped: /ready reports 503");
        }
        readiness.set(running && !draining);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_turns_false_while_draining_and_when_the_data_plane_stops() {
        let config = nexus_dataplane::DataplaneConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let (dataplane, _) = Dataplane::start(config).unwrap();
        let dataplane = Arc::new(dataplane);
        let api = crate::nexus_api::ApiServer::new(
            "127.0.0.1:1".parse().unwrap(),
            "0123456789abcdef0123456789abcdef",
            None,
        );
        api.set_ready();
        let readiness = api.readiness();
        let shutdown = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let inputs = ReadinessInputs {
            dataplane: Arc::clone(&dataplane),
            draining: Arc::clone(&draining),
            shutdown: Arc::clone(&shutdown),
        };
        let task = tokio::spawn(track_readiness(readiness.clone(), inputs));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(readiness.get());
        // The drain: not ready, while the data plane still runs.
        draining.store(true, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!readiness.get(), "/ready reports the drain");
        draining.store(false, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(readiness.get());
        dataplane.shutdown();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!readiness.get(), "/ready reports the stopped data plane");
        shutdown.store(true, Ordering::Release);
        task.await.unwrap();
    }
}
