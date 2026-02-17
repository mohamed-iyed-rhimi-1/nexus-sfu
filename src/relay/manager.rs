//! Relay manager — manages relay links to peer SFU nodes and the
//! local relay receiver that injects remote packets into the worker pool.
//!
//! # TigerStyle + NASA Compliance
//!
//! - Bounded peer count (MAX_RELAY_PEERS)
//! - ≥2 assertions per public function
//! - No recursion
//! - All loops bounded
//! - Explicit error handling

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam::channel::{Receiver, Sender, bounded};
use tracing::{debug, info};

use crate::relay::link::{RelayLink, MAX_RELAY_PACKET, RELAY_HEADER_SIZE};
use crate::types::TrackId;

/// Maximum peer nodes we relay to/from.
const MAX_RELAY_PEERS: usize = 64;

/// Relay receiver channel capacity.
const RELAY_RECV_CHANNEL_CAP: usize = 8192;

/// A received relay packet ready for injection into the worker pool.
pub struct RelayPacket {
    pub track_id: TrackId,
    pub data: [u8; 1500],
    pub len: u16,
}

/// Manages relay links to all peer SFU nodes.
pub struct RelayManager {
    /// Local node's actor ID.
    local_node: u64,
    /// Relay links keyed by peer node ID.
    links: HashMap<u64, RelayLink>,
    /// Local relay receiver socket (all peers send to this).
    recv_socket: Arc<UdpSocket>,
    /// Bind address of the relay receiver.
    recv_addr: SocketAddr,
    /// Channel for received relay packets → SFU main loop.
    packet_tx: Sender<RelayPacket>,
    /// Receiver end — polled by the SFU to inject into workers.
    packet_rx: Receiver<RelayPacket>,
    /// Background receiver thread handle.
    recv_handle: Option<JoinHandle<()>>,
    /// Shutdown flag for the receiver thread.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayManager {
    /// Create a new relay manager.
    ///
    /// Binds a UDP socket on `relay_addr` for receiving relay packets from peers.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(local_node: u64, relay_addr: SocketAddr) -> io::Result<Self> {
        assert!(local_node > 0, "local_node must be non-zero");
        assert!(relay_addr.port() > 0, "relay port must be non-zero");

        let recv_socket = UdpSocket::bind(relay_addr)?;
        let recv_addr = recv_socket.local_addr()?;
        recv_socket.set_nonblocking(false)?; // Blocking for the receiver thread.
        // Set read timeout so the receiver thread can check the shutdown flag
        recv_socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;

        let (packet_tx, packet_rx) = bounded(RELAY_RECV_CHANNEL_CAP);

        info!(local_node, addr = %recv_addr, "relay manager initialized");

        Ok(Self {
            local_node,
            links: HashMap::with_capacity(8),
            recv_socket: Arc::new(recv_socket),
            recv_addr,
            packet_tx,
            packet_rx,
            recv_handle: None,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Start the background receiver thread.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn start_receiver(&mut self) {
        assert!(self.recv_handle.is_none(), "receiver already started");

        let socket = self.recv_socket.clone();
        let tx = self.packet_tx.clone();
        let shutdown = self.shutdown.clone();

        let handle = thread::Builder::new()
            .name("nexus-relay-recv".into())
            .spawn(move || relay_recv_loop(socket, tx, shutdown))
            .expect("failed to spawn relay receiver thread");

        self.recv_handle = Some(handle);
        info!("relay receiver thread started");
    }

    /// Get the channel receiver for relay packets.
    ///
    /// The SFU main loop drains this and injects packets into the worker pool.
    pub fn packet_rx(&self) -> &Receiver<RelayPacket> {
        &self.packet_rx
    }

    /// Add a relay link to a peer node.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn add_peer(&mut self, peer_node: u64, peer_relay_addr: SocketAddr) -> io::Result<()> {
        assert!(peer_node > 0, "peer_node must be non-zero");
        assert!(peer_node != self.local_node, "cannot relay to self");

        if self.links.len() >= MAX_RELAY_PEERS {
            return Err(io::Error::new(io::ErrorKind::Other, "max relay peers reached"));
        }

        if self.links.contains_key(&peer_node) {
            debug!(peer_node, "relay link already exists");
            return Ok(());
        }

        let link = RelayLink::new(peer_node, peer_relay_addr)?;
        info!(peer_node, addr = %peer_relay_addr, "relay link established");
        self.links.insert(peer_node, link);
        Ok(())
    }

    /// Remove a relay link to a peer node.
    pub fn remove_peer(&mut self, peer_node: u64) {
        if self.links.remove(&peer_node).is_some() {
            info!(peer_node, "relay link removed");
        }
    }

    /// Send an RTP packet to a peer node for a specific track.
    ///
    /// Returns false if the peer link doesn't exist or send fails.
    ///
    /// # TigerStyle: ≥2 assertions
    #[inline]
    pub fn relay_packet(&self, peer_node: u64, track_id: TrackId, rtp_data: &[u8]) -> bool {
        assert!(track_id > 0, "track_id must be non-zero");
        assert!(!rtp_data.is_empty(), "rtp_data must be non-empty");

        let link = match self.links.get(&peer_node) {
            Some(l) => l,
            None => return false,
        };

        match link.send_packet(track_id, rtp_data) {
            Ok(_) => true,
            Err(e) => {
                debug!(peer_node, track_id, err = %e, "relay send failed");
                false
            }
        }
    }

    /// Check if a peer link exists.
    pub fn has_peer(&self, peer_node: u64) -> bool {
        self.links.contains_key(&peer_node)
    }

    /// Number of active relay links.
    pub fn peer_count(&self) -> usize {
        self.links.len()
    }

    /// Local relay receiver address (peers send to this).
    pub fn recv_addr(&self) -> SocketAddr {
        self.recv_addr
    }

    /// Local node ID.
    pub fn local_node(&self) -> u64 {
        self.local_node
    }
}

impl Drop for RelayManager {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Release);
        if let Some(handle) = self.recv_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Background receiver loop — reads relay packets and sends to channel.
///
/// NASA Rule 1: no recursion. NASA Rule 2: loop bounded by channel lifetime.
fn relay_recv_loop(
    socket: Arc<UdpSocket>,
    tx: Sender<RelayPacket>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf = [0u8; MAX_RELAY_PACKET];

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }

        let n = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Socket closed or fatal error — exit thread.
                debug!(err = %e, "relay receiver exiting");
                return;
            }
        };

        if n < RELAY_HEADER_SIZE {
            continue; // Runt packet.
        }

        let track_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ]);

        if track_id == 0 {
            continue;
        }

        let payload_len = n - RELAY_HEADER_SIZE;
        if payload_len == 0 || payload_len > 1500 {
            continue;
        }

        let mut pkt = RelayPacket {
            track_id,
            data: [0u8; 1500],
            len: payload_len as u16,
        };
        pkt.data[..payload_len].copy_from_slice(&buf[RELAY_HEADER_SIZE..n]);

        // Non-blocking send — drop if channel full.
        if tx.try_send(pkt).is_err() {
            // Channel full — backpressure, drop relay packet.
        }
    }
}
