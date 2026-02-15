//! UDP relay link to a peer SFU node.
//!
//! A `RelayLink` wraps a connected UDP socket to a specific peer node.
//! Packets are prefixed with an 8-byte header (track_id) so the receiver
//! can route them to the correct local worker.
//!
//! # Wire format
//!
//! ```text
//! [track_id: u64 BE][rtp_payload: N bytes]
//! ```
//!
//! # TigerStyle Compliance
//!
//! - ≥2 assertions per public function
//! - No heap allocation on send path
//! - Bounded recv buffer

use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::types::TrackId;

/// Relay packet header size (track_id: u64).
pub const RELAY_HEADER_SIZE: usize = 8;

/// Maximum relay packet size (header + MTU).
pub const MAX_RELAY_PACKET: usize = RELAY_HEADER_SIZE + 1500;

/// A UDP link to a peer SFU node for RTP relay.
pub struct RelayLink {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    peer_node: u64,
}

impl RelayLink {
    /// Create a new relay link to a peer node.
    ///
    /// Binds to an ephemeral port and connects to the peer's relay address.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn new(peer_node: u64, peer_addr: SocketAddr) -> io::Result<Self> {
        assert!(peer_node > 0, "peer_node must be non-zero");
        assert!(peer_addr.port() > 0, "peer port must be non-zero");

        let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(peer_addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            socket,
            peer_addr,
            peer_node,
        })
    }

    /// Send an RTP packet for a track to the peer node.
    ///
    /// Prepends the track_id header. No heap allocation.
    ///
    /// # TigerStyle: ≥2 assertions
    #[inline]
    pub fn send_packet(&self, track_id: TrackId, rtp_data: &[u8]) -> io::Result<usize> {
        assert!(track_id > 0, "track_id must be non-zero");
        assert!(!rtp_data.is_empty(), "rtp_data must be non-empty");

        let mut buf = [0u8; MAX_RELAY_PACKET];
        let total_len = RELAY_HEADER_SIZE + rtp_data.len();
        if total_len > MAX_RELAY_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet too large"));
        }

        buf[..RELAY_HEADER_SIZE].copy_from_slice(&track_id.to_be_bytes());
        buf[RELAY_HEADER_SIZE..total_len].copy_from_slice(rtp_data);

        self.socket.send(&buf[..total_len])
    }

    /// Receive a relay packet. Returns (track_id, payload_len).
    ///
    /// `buf` must be at least `MAX_RELAY_PACKET` bytes.
    ///
    /// # TigerStyle: ≥2 assertions
    pub fn recv_packet<'a>(&self, buf: &'a mut [u8; MAX_RELAY_PACKET]) -> io::Result<(TrackId, &'a [u8])> {
        assert!(buf.len() >= MAX_RELAY_PACKET, "buffer too small");

        let n = self.socket.recv(buf)?;
        if n < RELAY_HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "relay packet too short"));
        }

        let track_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ]);

        assert!(track_id > 0, "received relay packet with zero track_id");

        Ok((track_id, &buf[RELAY_HEADER_SIZE..n]))
    }

    pub fn peer_node(&self) -> u64 {
        self.peer_node
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}
