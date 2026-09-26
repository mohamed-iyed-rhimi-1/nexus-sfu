//! Server startup: everything `main.rs` used to wire by hand, as a library
//! function, so the end-to-end tests run the same startup in-process.
//!
//! ```text
//! start(config)
//!  ├─ Sfu::new            media socket, worker pool, gossip thread
//!  ├─ SignalingServer     WebSocket listener (bound before anything runs)
//!  ├─ SessionOrchestrator tokio task
//!  ├─ ApiServer           tokio task (if api.enabled)
//!  └─ packet loop         dedicated OS thread (it busy-polls and sleeps)
//! ```
//!
//! `start` does not initialise tracing and does not install signal handlers;
//! `main.rs` does both. Ports may be 0: the bound addresses are in the
//! returned handle, and ICE candidates carry the bound media port.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::config::NexusConfig;
use crate::orchestrator::candidates;
use crate::orchestrator::connection::PacketSender;
use crate::orchestrator::events::ColdPathPacket;
use crate::orchestrator::SessionOrchestrator;
use crate::sfu::Sfu;
use crate::signal::{OrchestratorEvent, SignalingConfig, SignalingServer};

/// Bound on waiting for the control-plane tasks after the packet loop stops.
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Queue depth between signaling / packet loop and the orchestrator.
const ORCHESTRATOR_QUEUE: usize = 4096;

/// A running server. Dropping it without `shutdown` stops it abruptly.
pub struct ServerHandle {
    media_addr: SocketAddr,
    signaling_addr: SocketAddr,
    candidate_addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    shared_shutdown: Arc<AtomicBool>,
    packet_loop: Option<std::thread::JoinHandle<Result<(), String>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl ServerHandle {
    /// Address the media UDP socket is bound to.
    pub fn media_addr(&self) -> SocketAddr {
        self.media_addr
    }

    /// Address the WebSocket signaling listener is bound to.
    pub fn signaling_addr(&self) -> SocketAddr {
        self.signaling_addr
    }

    /// Addresses advertised as ICE host candidates.
    pub fn candidate_addrs(&self) -> &[SocketAddr] {
        &self.candidate_addrs
    }

    /// True once the packet loop has stopped (on error or after shutdown).
    pub fn is_finished(&self) -> bool {
        self.packet_loop.as_ref().map_or(true, |t| t.is_finished())
    }

    /// Graceful shutdown: stop the packet loop, notify clients, drain for
    /// `drain_timeout_ms`, then stop every task and thread.
    pub async fn shutdown(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        let result = self.join_packet_loop().await;
        // Sfu::shutdown sets this; set it anyway in case the loop failed early.
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
        assert!(self.tasks.is_empty());
        result
    }

    /// Wait until the packet loop stops by itself (e.g. `main.rs` waiting
    /// for a signal runs `shutdown` instead).
    async fn join_packet_loop(&mut self) -> Result<(), String> {
        let Some(thread) = self.packet_loop.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|e| format!("packet loop join: {e}"))?
            .map_err(|_| "packet loop thread panicked".to_string())?
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if self.packet_loop.is_some() {
            self.stop.store(true, Ordering::Release);
            self.shared_shutdown.store(true, Ordering::Release);
            for task in &self.tasks {
                task.abort();
            }
        }
    }
}

/// Start the SFU. Must be called inside a multi-threaded tokio runtime.
pub async fn start(config: NexusConfig) -> Result<ServerHandle, String> {
    config
        .validate()
        .map_err(|e| format!("invalid config: {e}"))?;

    let mut sfu = Sfu::new(config.clone())
        .await
        .map_err(|e| format!("failed to initialize SFU: {e}"))?;
    let media_addr = sfu.media_local_addr();
    let candidate_addrs = candidates::resolve(&config.transport.announced_ips, media_addr)?;

    let (orchestrator_tx, orchestrator_rx) =
        tokio::sync::mpsc::channel::<OrchestratorEvent>(ORCHESTRATOR_QUEUE);
    let signaling = SignalingServer::new(
        signaling_config(&config),
        sfu.shared_shutdown().clone(),
        orchestrator_tx,
    )
    .map_err(|e| format!("failed to set up signaling: {e}"))?;
    let signaling_addr = signaling.local_addr();
    sfu.set_signaling_connections(signaling.connections());

    let mut tasks = Vec::with_capacity(3);
    tasks.push(tokio::spawn(async move {
        if let Err(e) = signaling.run().await {
            error!("Signaling server error: {}", e);
        }
    }));
    info!("WebSocket signaling listening on {}", signaling_addr);

    let (connection_tx, connection_rx) =
        tokio::sync::mpsc::channel::<ColdPathPacket>(ORCHESTRATOR_QUEUE);
    let media_socket = sfu
        .media_socket_for_sender()
        .ok_or("media socket unavailable for the orchestrator")?;
    let mut orchestrator = SessionOrchestrator::new(
        sfu.webrtc_transport().clone(),
        sfu.ssrc_router().clone(),
        sfu.distributed_state().clone(),
        sfu.worker_pool_arc().ok_or("worker pool not initialized")?,
        candidate_addrs.clone(),
        PacketSender::new(media_socket),
    );
    let orchestrator_shutdown = sfu.shared_shutdown().clone();
    tasks.push(tokio::spawn(async move {
        orchestrator
            .run(orchestrator_rx, connection_rx, orchestrator_shutdown)
            .await;
    }));

    if let Some(api_task) = start_api(&config, &sfu)? {
        tasks.push(api_task);
    }

    sfu.set_connection_tx(connection_tx);
    let stop = sfu.stop_handle();
    let shared_shutdown = sfu.shared_shutdown().clone();
    let packet_loop = spawn_packet_loop(sfu)?;

    assert!(!candidate_addrs.is_empty());
    Ok(ServerHandle {
        media_addr,
        signaling_addr,
        candidate_addrs,
        stop,
        shared_shutdown,
        packet_loop: Some(packet_loop),
        tasks,
    })
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

/// The REST API, started last: when it reports ready, everything else runs.
fn start_api(config: &NexusConfig, sfu: &Sfu) -> Result<Option<JoinHandle<()>>, String> {
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
        sfu.metrics().cloned(),
        sfu.distributed_state().clone(),
    );
    api_server.set_ready();
    let api_shutdown = sfu.shared_shutdown().clone();
    Ok(Some(tokio::spawn(async move {
        tokio::select! {
            result = api_server.run() => {
                if let Err(e) = result {
                    error!("API server error: {}", e);
                }
            }
            _ = async {
                while !api_shutdown.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => info!("API server shutting down"),
        }
    })))
}

/// Run the ingress loop on its own OS thread. The loop busy-polls and
/// sleeps between empty polls (`SpinLoop`), which would stall a tokio
/// worker; its own current-thread runtime also runs `Sfu::shutdown`.
fn spawn_packet_loop(mut sfu: Sfu) -> Result<std::thread::JoinHandle<Result<(), String>>, String> {
    std::thread::Builder::new()
        .name("nexus-ingress".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("packet loop runtime: {e}"))?;
            runtime.block_on(async move {
                let run_result = sfu.run().await;
                let shutdown_result = sfu.shutdown().await;
                run_result.map_err(|e| format!("packet loop: {e}"))?;
                shutdown_result.map_err(|e| format!("shutdown: {e}"))
            })
        })
        .map_err(|e| format!("spawn packet loop thread: {e}"))
}
