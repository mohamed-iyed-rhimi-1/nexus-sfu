//! Starting the data plane and talking to it (note §3.1, §3.6, §5.3).
//!
//! `Dataplane::start` binds one socket per shard and spawns one thread per
//! shard. The control plane then uses only `DataplaneHandle`: commands in
//! (one `ArrayQueue` per shard, waking a parked shard), events out (one
//! tokio channel all shards share, filled with `try_send`), stats, and
//! shutdown.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use crossbeam_queue::ArrayQueue;
use tokio::sync::mpsc;

use crate::command::{Command, Event, EventSink, Refused};
use crate::config::{ConfigError, DataplaneConfig};
use crate::ids::ShardId;
use crate::placement::ShardLoad;
use crate::shard::io::PlatformIo;
use crate::shard::park::{Parker, Wake};
use crate::shard::runner::ShardThread;
use crate::shard::stats::{ShardStats, ShardStatsSnapshot};
use crate::shard::Shard;

/// Capacity of the event channel all shards share (note §5.3).
pub const EVENT_CHANNEL_CAPACITY: usize = 8_192;
/// Stack of a shard thread: the shard never recurses; the largest frames
/// are STUN and SRTP buffers of a few KB.
pub const SHARD_STACK_SIZE: usize = 1 << 20;

impl EventSink for mpsc::Sender<Event> {
    fn try_send(&mut self, event: Event) -> Result<(), Refused> {
        mpsc::Sender::try_send(self, event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(event) => Refused::Full(event),
            mpsc::error::TrySendError::Closed(event) => Refused::Closed(event),
        })
    }
}

/// A shard as `Dataplane::start` bound it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardInfo {
    /// The shard.
    pub id: ShardId,
    /// Its socket's local address (the port candidates announce).
    pub local_addr: SocketAddr,
}

/// A shard's command queue is full; the command was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandQueueFull;

impl std::fmt::Display for CommandQueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("shard command queue full")
    }
}

impl std::error::Error for CommandQueueFull {}

/// Why the data plane did not start.
#[derive(Debug)]
pub enum DataplaneError {
    /// An invalid setting.
    Config(ConfigError),
    /// A shard's socket could not be bound or set up.
    Socket {
        /// The address.
        addr: SocketAddr,
        /// The error.
        source: io::Error,
    },
    /// The poller or a shard thread could not be created.
    Thread(io::Error),
}

impl std::fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "invalid data plane config: {e}"),
            Self::Socket { addr, source } => write!(f, "media socket {addr}: {source}"),
            Self::Thread(e) => write!(f, "shard thread: {e}"),
        }
    }
}

impl std::error::Error for DataplaneError {}

/// Binds and sets up a shard socket: non-blocking, buffer sizes from the
/// config. Deliberately not `configure_high_performance_socket`: it enables
/// UDP_GRO, which coalesces datagrams into reads larger than a pool buffer.
#[doc(hidden)]
pub fn bind_shard_socket(addr: SocketAddr, config: &DataplaneConfig) -> io::Result<UdpSocket> {
    // `configure_socket_buffers` asserts positive sizes: checked here too,
    // since this helper is public.
    let size = |bytes: u32| {
        i32::try_from(bytes)
            .ok()
            .filter(|&b| b > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket buffer size"))
    };
    let recv = size(config.recv_buffer_bytes)?;
    let send = size(config.send_buffer_bytes)?;
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    nexus_transport::socket_config::configure_socket_buffers(
        socket.as_raw_fd(),
        Some(recv),
        Some(send),
    )?;
    Ok(socket)
}

/// Entry point of the data plane.
pub struct Dataplane;

impl Dataplane {
    /// Binds a socket and spawns a thread per shard. On any failure the
    /// shards already started are stopped and joined.
    pub fn start(
        config: DataplaneConfig,
    ) -> Result<(DataplaneHandle, Vec<ShardInfo>), DataplaneError> {
        config.validate().map_err(DataplaneError::Config)?;
        let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let mut handle = DataplaneHandle {
            shards: Vec::with_capacity(usize::from(config.shards)),
            events: Mutex::new(Some(events_rx)),
            threads: Mutex::new(Vec::with_capacity(usize::from(config.shards))),
        };
        let seed = process_seed();
        let mut infos = Vec::with_capacity(usize::from(config.shards));
        for index in 0..config.shards {
            // shards ≤ MAX_SHARDS_PHASE_1, validated.
            let index = u8::try_from(index).expect("validated shard count");
            let info = handle.spawn_shard(&config, index, seed, events_tx.clone())?;
            infos.push(info);
        }
        assert!(infos.len() == usize::from(config.shards));
        assert!(handle.shards.len() == infos.len());
        Ok((handle, infos))
    }
}

/// A random seed per process for the shards' rewrite offsets (no clock,
/// no extra dependency: the standard library's per-process hash keys).
fn process_seed() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(0x6E65_7875_735F_7366);
    hasher.finish()
}

struct ShardHandle {
    commands: Arc<ArrayQueue<Command>>,
    wake: Wake,
    stats: Arc<ShardStats>,
    running: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

/// The control plane's side of the data plane.
pub struct DataplaneHandle {
    shards: Vec<ShardHandle>,
    events: Mutex<Option<mpsc::Receiver<Event>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl DataplaneHandle {
    /// Binds shard `index`, builds it on this thread (so setup errors
    /// surface before any spawn) and starts its thread.
    fn spawn_shard(
        &mut self,
        config: &DataplaneConfig,
        index: u8,
        seed: u64,
        events: mpsc::Sender<Event>,
    ) -> Result<ShardInfo, DataplaneError> {
        let mut addr = config.bind_addr;
        if addr.port() != 0 {
            addr.set_port(addr.port() + u16::from(index));
        }
        let socket_error = |source| DataplaneError::Socket { addr, source };
        let socket = bind_shard_socket(addr, config).map_err(socket_error)?;
        let local_addr = socket.local_addr().map_err(socket_error)?;
        let (parker, wake) = Parker::new(socket.as_raw_fd()).map_err(DataplaneError::Thread)?;
        let io = PlatformIo::new(socket).map_err(socket_error)?;
        let shard_config = config.shard_config(index, seed);
        let shard =
            Shard::new(shard_config, io, events, Instant::now()).map_err(DataplaneError::Config)?;
        let handle = ShardHandle {
            commands: shard.command_queue(),
            wake,
            stats: shard.stats(),
            running: Arc::new(AtomicBool::new(true)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let thread = ShardThread {
            shard,
            parker,
            stop: Arc::clone(&handle.stop),
            running: Arc::clone(&handle.running),
            busy_poll_rounds: config.busy_poll_rounds,
            cpu_affinity: config.cpu_affinity,
            realtime_priority: config.realtime_priority,
        };
        let id = ShardId::new(index);
        let join = std::thread::Builder::new()
            .name(format!("nexus-shard-{index}"))
            .stack_size(SHARD_STACK_SIZE)
            .spawn(move || thread.run(id))
            .map_err(DataplaneError::Thread)?;
        self.shards.push(handle);
        self.threads.lock().expect("threads lock").push(join);
        Ok(ShardInfo { id, local_addr })
    }

    /// Number of shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn shard(&self, shard: ShardId) -> &ShardHandle {
        let index = usize::from(shard.index());
        assert!(index < self.shards.len(), "unknown shard {index}");
        &self.shards[index]
    }

    /// Queues a command for `shard` and wakes it if parked. A full queue is
    /// an error, never a silent drop (note §5.3).
    pub fn send(&self, shard: ShardId, command: Command) -> Result<(), CommandQueueFull> {
        let target = self.shard(shard);
        target
            .commands
            .push(command)
            .map_err(|_| CommandQueueFull)?;
        if let Err(e) = target.wake.wake() {
            tracing::warn!(shard = shard.index(), error = %e, "shard wake-up failed");
        }
        Ok(())
    }

    /// The event receiver; `Some` once, for the one consumer.
    pub fn take_events(&self) -> Option<mpsc::Receiver<Event>> {
        self.events.lock().expect("events lock").take()
    }

    /// The last published stats of `shard` (updated once per second, and
    /// when the shard stops).
    pub fn stats(&self, shard: ShardId) -> ShardStatsSnapshot {
        self.shard(shard).stats.load()
    }

    /// Load of every shard, for placement.
    pub fn loads(&self) -> Vec<ShardLoad> {
        let loads: Vec<ShardLoad> = self
            .shards
            .iter()
            .map(|s| ShardLoad::from(&s.stats.load()))
            .collect();
        debug_assert!(loads.len() == self.shards.len());
        loads
    }

    /// Every shard thread is running (backs `ServerHandle::is_finished`).
    pub fn is_running(&self) -> bool {
        !self.shards.is_empty() && self.shards.iter().all(|s| s.running.load(Ordering::SeqCst))
    }

    /// Stops every shard (after its current iteration and a final flush)
    /// and joins the threads. Idempotent.
    pub fn shutdown(&self) {
        // Held across the joins: a concurrent caller waits here until every
        // thread is joined, so no caller returns while a shard still runs.
        let mut threads = self.threads.lock().unwrap_or_else(|e| e.into_inner());
        for shard in &self.shards {
            shard.stop.store(true, Ordering::SeqCst);
            if let Err(e) = shard.wake.wake_always() {
                tracing::warn!(error = %e, "shard wake-up at shutdown failed");
            }
        }
        // Bounded by the shard count.
        for thread in threads.drain(..) {
            if thread.join().is_err() {
                tracing::error!("a shard thread panicked");
            }
        }
        debug_assert!(threads.is_empty());
        debug_assert!(!self.is_running());
    }
}

impl Drop for DataplaneHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}
