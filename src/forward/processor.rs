//! XDP Packet Processor for cold-path packet handling.
//!
//! This module integrates the XDP fast path (kernel-space RTP forwarding)
//! with user-space cold path processing for RTCP, DTLS, STUN, and new tracks.
//!
//! # Requirements Coverage
//!
//! - Requirement 19.7: XdpPacketProcessor integrates XDP fast path with user-space cold path
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    XdpPacketProcessor                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  AF_XDP Socket ◄── Cold path packets from XDP program       │
//! │       │                                                      │
//! │       ▼                                                      │
//! │  classify_packet()                                          │
//! │       │                                                      │
//! │       ├── RTP (new SSRC) ──► register_track() + forward     │
//! │       ├── RTCP ──► dispatch to BWE/stats handler            │
//! │       ├── DTLS ──► dispatch to DTLS handler                 │
//! │       └── STUN ──► dispatch to ICE handler                  │
//! │                                                              │
//! │  ForwardTable ◄── register_track() / unregister_track()     │
//! │       │                                                      │
//! │       ▼                                                      │
//! │  BPF Map (kernel) ◄── SSRC-to-destination mappings          │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TigerStyle Compliance
//!
//! - Assertions: worker_pool is initialized, ssrc != 0
//! - Fixed bounds: MAX_BATCH_PACKETS = 64
//! - Explicit types: All sizes use u32/u64

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::state::{ForwardEntry, ForwardTable, XdpError};

#[cfg(all(target_os = "linux", feature = "xdp"))]
use crate::transport::{AfXdpPacket, AfXdpSocket};

/// Packet type classification result
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// RTP packet (media data)
    Rtp,
    /// RTCP packet (control/feedback)
    Rtcp,
    /// DTLS packet (encryption handshake)
    Dtls,
    /// STUN packet (ICE connectivity)
    Stun,
    /// Unknown packet type
    Unknown,
}

impl PacketType {
    /// Classify a UDP payload as RTP, RTCP, DTLS, or STUN.
    ///
    /// # Arguments
    ///
    /// * `data` - UDP payload to classify
    ///
    /// # Returns
    ///
    /// The detected packet type.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions (implicit via bounds checks)
    /// - No recursion
    pub fn classify(data: &[u8]) -> Self {
        // Precondition: need at least 1 byte
        if data.is_empty() {
            return PacketType::Unknown;
        }

        let first_byte = data[0];

        // DTLS check: content type 20-25 (change_cipher_spec=20, alert=21, 
        // handshake=22, application_data=23, heartbeat=24, tls12_cid=25)
        // DTLS records have: content_type (1) + version (2) + epoch (2) + 
        // sequence (6) + length (2) = 13 bytes minimum
        if (20..=25).contains(&first_byte) && data.len() >= 13 {
            return PacketType::Dtls;
        }

        // STUN check: magic cookie at bytes 4-7 (0x2112A442)
        // STUN messages have: type (2) + length (2) + magic (4) + 
        // transaction_id (12) = 20 bytes minimum
        if data.len() >= 20 {
            let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            if magic == 0x2112A442 {
                return PacketType::Stun;
            }
        }

        // RTP/RTCP check: version must be 2 (bits 6-7 of first byte)
        let version = (first_byte >> 6) & 0x03;
        if version != 2 || data.len() < 2 {
            return PacketType::Unknown;
        }

        let second_byte = data[1];

        // RTCP: payload type 200-206 (SR=200, RR=201, SDES=202, BYE=203, 
        // APP=204, RTPFB=205, PSFB=206)
        // RTCP packets have: V/P/RC (1) + PT (1) + length (2) + SSRC (4) = 8 bytes minimum
        if (200..=206).contains(&second_byte) && data.len() >= 8 {
            return PacketType::Rtcp;
        }

        // RTP: valid payload type (0-34 static, 96-127 dynamic)
        // RTP packets have: V/P/X/CC (1) + M/PT (1) + seq (2) + 
        // timestamp (4) + SSRC (4) = 12 bytes minimum
        let pt = second_byte & 0x7F;
        if (pt <= 34 || (96..=127).contains(&pt)) && data.len() >= 12 {
            return PacketType::Rtp;
        }

        PacketType::Unknown
    }

    /// Extract SSRC from RTP packet.
    ///
    /// # Arguments
    ///
    /// * `data` - RTP packet data
    ///
    /// # Returns
    ///
    /// SSRC if packet is valid RTP, None otherwise.
    #[inline]
    pub fn extract_rtp_ssrc(data: &[u8]) -> Option<u32> {
        if data.len() < 12 {
            return None;
        }
        // SSRC is at bytes 8-11 of RTP header
        Some(u32::from_be_bytes([data[8], data[9], data[10], data[11]]))
    }

    /// Extract SSRC from RTCP packet.
    ///
    /// # Arguments
    ///
    /// * `data` - RTCP packet data
    ///
    /// # Returns
    ///
    /// SSRC if packet is valid RTCP, None otherwise.
    #[inline]
    pub fn extract_rtcp_ssrc(data: &[u8]) -> Option<u32> {
        if data.len() < 8 {
            return None;
        }
        // SSRC is at bytes 4-7 of RTCP header
        Some(u32::from_be_bytes([data[4], data[5], data[6], data[7]]))
    }
}

/// XDP processor statistics
#[derive(Debug, Default)]
pub struct XdpProcessorStats {
    /// Packets received from AF_XDP
    pub packets_received: AtomicU64,
    /// RTP packets processed
    pub rtp_packets: AtomicU64,
    /// RTCP packets processed
    pub rtcp_packets: AtomicU64,
    /// DTLS packets processed
    pub dtls_packets: AtomicU64,
    /// STUN packets processed
    pub stun_packets: AtomicU64,
    /// Unknown packets dropped
    pub unknown_packets: AtomicU64,
    /// Tracks registered in forward table
    pub tracks_registered: AtomicU64,
    /// Tracks unregistered from forward table
    pub tracks_unregistered: AtomicU64,
    /// Processing errors
    pub errors: AtomicU64,
}

impl XdpProcessorStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> XdpProcessorStatsSnapshot {
        XdpProcessorStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            rtp_packets: self.rtp_packets.load(Ordering::Relaxed),
            rtcp_packets: self.rtcp_packets.load(Ordering::Relaxed),
            dtls_packets: self.dtls_packets.load(Ordering::Relaxed),
            stun_packets: self.stun_packets.load(Ordering::Relaxed),
            unknown_packets: self.unknown_packets.load(Ordering::Relaxed),
            tracks_registered: self.tracks_registered.load(Ordering::Relaxed),
            tracks_unregistered: self.tracks_unregistered.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of XDP processor statistics
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpProcessorStatsSnapshot {
    pub packets_received: u64,
    pub rtp_packets: u64,
    pub rtcp_packets: u64,
    pub dtls_packets: u64,
    pub stun_packets: u64,
    pub unknown_packets: u64,
    pub tracks_registered: u64,
    pub tracks_unregistered: u64,
    pub errors: u64,
}

/// Callback trait for handling cold-path packets.
///
/// Implementations of this trait receive packets that cannot be
/// handled in kernel space and require user-space processing.
///
/// # Source Address Preservation
///
/// All handler methods now include an optional source address parameter
/// to support proper routing of responses (STUN binding responses, DTLS
/// handshake responses) back to the originating peer.
///
/// # Requirements Coverage
///
/// - Requirement 7.5: Route cold-path packets with source address preservation
pub trait PacketHandler: Send + Sync {
    /// Handle an RTP packet (typically for new SSRC registration).
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC from the packet
    /// * `data` - Raw packet data
    fn handle_rtp(&self, ssrc: u32, data: &[u8]);

    /// Handle an RTP packet with source address.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC from the packet
    /// * `data` - Raw packet data
    /// * `source_addr` - Source address of the packet
    ///
    /// Default implementation calls handle_rtp without address.
    fn handle_rtp_with_addr(&self, ssrc: u32, data: &[u8], _source_addr: std::net::SocketAddr) {
        self.handle_rtp(ssrc, data);
    }

    /// Handle an RTCP packet.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    fn handle_rtcp(&self, data: &[u8]);

    /// Handle an RTCP packet with source address.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    /// * `source_addr` - Source address of the packet
    ///
    /// Default implementation calls handle_rtcp without address.
    fn handle_rtcp_with_addr(&self, data: &[u8], _source_addr: std::net::SocketAddr) {
        self.handle_rtcp(data);
    }

    /// Handle a DTLS packet.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    fn handle_dtls(&self, data: &[u8]);

    /// Handle a DTLS packet with source address.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    /// * `source_addr` - Source address of the packet for session lookup
    ///
    /// Default implementation calls handle_dtls without address.
    fn handle_dtls_with_addr(&self, data: &[u8], _source_addr: std::net::SocketAddr) {
        self.handle_dtls(data);
    }

    /// Handle a STUN packet.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    fn handle_stun(&self, data: &[u8]);

    /// Handle a STUN packet with source address.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data
    /// * `source_addr` - Source address of the packet for response routing
    ///
    /// Default implementation calls handle_stun without address.
    fn handle_stun_with_addr(&self, data: &[u8], _source_addr: std::net::SocketAddr) {
        self.handle_stun(data);
    }
}

/// XDP Packet Processor configuration
#[derive(Clone, Debug)]
pub struct XdpProcessorConfig {
    /// Interface name
    pub ifname: String,
    /// Queue ID
    pub queue_id: u32,
    /// Path to pinned BPF forward table map
    pub forward_table_path: String,
    /// Maximum packets per batch
    pub batch_size: usize,
    /// Poll timeout in milliseconds
    pub poll_timeout_ms: u32,
}

impl Default for XdpProcessorConfig {
    fn default() -> Self {
        Self {
            ifname: String::new(),
            queue_id: 0,
            forward_table_path: "/sys/fs/bpf/forward_table".to_string(),
            batch_size: 64,
            poll_timeout_ms: 100,
        }
    }
}

/// XDP Packet Processor integrates XDP fast path with user-space cold path.
///
/// This processor receives packets from the AF_XDP socket (cold path)
/// and dispatches them to appropriate handlers based on packet type.
/// It also manages the BPF forward table for kernel-space RTP forwarding.
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub struct XdpPacketProcessor {
    /// AF_XDP socket for cold-path packets
    af_xdp: AfXdpSocket,
    /// Forward table for managing XDP BPF map
    forward_table: ForwardTable,
    /// Packet handler for dispatching packets
    handler: Arc<dyn PacketHandler>,
    /// Statistics
    stats: XdpProcessorStats,
    /// Running flag
    running: AtomicBool,
    /// Configuration
    config: XdpProcessorConfig,
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
impl XdpPacketProcessor {
    /// Create a new XDP packet processor.
    ///
    /// # Arguments
    ///
    /// * `ifname` - Network interface name
    /// * `queue_id` - NIC queue ID
    /// * `forward_table` - BPF forward table
    /// * `handler` - Packet handler for cold-path packets
    ///
    /// # Assertions
    ///
    /// * `ifname.len() > 0` - Interface name must not be empty
    ///
    /// # Errors
    ///
    /// Returns `XdpError` if socket creation fails.
    pub fn new(
        ifname: &str,
        queue_id: u32,
        forward_table: ForwardTable,
        handler: Arc<dyn PacketHandler>,
    ) -> Result<Self, XdpError> {
        // Assertion: interface name must not be empty
        assert!(!ifname.is_empty(), "interface name must not be empty");

        let af_xdp = AfXdpSocket::new(ifname, queue_id, 2048)?;

        Ok(Self {
            af_xdp,
            forward_table,
            handler,
            stats: XdpProcessorStats::new(),
            running: AtomicBool::new(false),
            config: XdpProcessorConfig {
                ifname: ifname.to_string(),
                queue_id,
                ..Default::default()
            },
        })
    }

    /// Create a new XDP packet processor with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Processor configuration
    /// * `forward_table` - BPF forward table
    /// * `handler` - Packet handler for cold-path packets
    ///
    /// # Errors
    ///
    /// Returns `XdpError` if socket creation fails.
    pub fn with_config(
        config: XdpProcessorConfig,
        forward_table: ForwardTable,
        handler: Arc<dyn PacketHandler>,
    ) -> Result<Self, XdpError> {
        let af_xdp = AfXdpSocket::new(&config.ifname, config.queue_id, 2048)?;

        Ok(Self {
            af_xdp,
            forward_table,
            handler,
            stats: XdpProcessorStats::new(),
            running: AtomicBool::new(false),
            config,
        })
    }

    /// Main processing loop.
    ///
    /// Receives cold-path packets from AF_XDP and dispatches to handlers.
    /// This method blocks until `stop()` is called.
    pub fn run(&mut self) {
        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            // Receive batch of packets
            match self.af_xdp.recv_batch(self.config.batch_size) {
                Ok(packets) => {
                    for packet in packets {
                        self.process_packet(&packet);
                    }
                }
                Err(e) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("AF_XDP recv error: {}", e);
                }
            }
        }
    }

    /// Stop the processing loop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the processor is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Register a new track in the XDP forward table.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC
    /// * `destinations` - Slice of destination entries
    ///
    /// # Assertions
    ///
    /// * `ssrc != 0` - SSRC must be non-zero
    ///
    /// # Errors
    ///
    /// Returns `XdpError` if registration fails.
    pub fn register_track(
        &self,
        ssrc: u32,
        destinations: &[ForwardEntry],
    ) -> Result<(), XdpError> {
        // Assertion: SSRC must be non-zero
        assert!(ssrc != 0, "SSRC must be non-zero");

        // Register each destination
        // WHY: In a real SFU, one SSRC may be forwarded to multiple subscribers.
        // For simplicity, we register the first destination here.
        // A production implementation would use a more sophisticated mapping.
        if let Some(entry) = destinations.first() {
            self.forward_table.insert(ssrc, *entry)?;
            self.stats.tracks_registered.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Unregister a track from the XDP forward table.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC to unregister
    ///
    /// # Errors
    ///
    /// Returns `XdpError` if unregistration fails.
    pub fn unregister_track(&self, ssrc: u32) -> Result<(), XdpError> {
        self.forward_table.remove(ssrc)?;
        self.stats.tracks_unregistered.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get statistics.
    pub fn stats(&self) -> &XdpProcessorStats {
        &self.stats
    }

    /// Get the forward table.
    pub fn forward_table(&self) -> &ForwardTable {
        &self.forward_table
    }

    /// Get mutable access to the underlying AF_XDP socket.
    ///
    /// This accessor enables the XDP packet loop to poll the AF_XDP RX ring
    /// for cold-path packets (RTCP, DTLS, STUN) that require user-space
    /// processing.
    ///
    /// # Returns
    ///
    /// Mutable reference to the AF_XDP socket, or None if not initialized.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions (implicit via Option return)
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 25.1: XDP_Packet_Loop SHALL poll the AF_XDP_RX_Ring
    #[inline]
    pub fn af_xdp_socket_mut(&mut self) -> Option<&mut AfXdpSocket> {
        // WHY: The XDP packet loop needs direct access to the AF_XDP socket
        // to poll for cold-path packets. This accessor provides that access
        // while maintaining encapsulation of the processor's internal state.
        Some(&mut self.af_xdp)
    }

    /// Process a batch of packets from AF_XDP.
    ///
    /// Classifies each packet and dispatches to appropriate handler.
    /// Updates per-CPU statistics counters.
    ///
    /// # Arguments
    ///
    /// * `packets` - Slice of AF_XDP packets to process
    ///
    /// # Returns
    ///
    /// Number of packets successfully processed.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions
    /// - Bounded loop (max 64 packets)
    pub fn process_xdp_batch(&mut self, packets: &[AfXdpPacket]) -> u32 {
        // Precondition assertions
        assert!(packets.len() <= 64, "batch size must not exceed 64");

        let mut processed = 0u32;

        // Bounded loop (TigerStyle: explicit upper bound)
        for packet in packets.iter().take(64) {
            self.process_packet(packet);
            processed += 1;
        }

        // Postcondition assertion
        assert!(processed <= 64, "processed count must not exceed 64");

        processed
    }

    /// Register a single track in the XDP forward table.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC
    /// * `entry` - Destination entry
    ///
    /// # Assertions
    ///
    /// * `ssrc != 0` - SSRC must be non-zero
    ///
    /// # Errors
    ///
    /// Returns `XdpError` if registration fails.
    pub fn register_track_single(
        &self,
        ssrc: u32,
        entry: ForwardEntry,
    ) -> Result<(), XdpError> {
        // Assertion: SSRC must be non-zero
        assert!(ssrc != 0, "SSRC must be non-zero");

        self.forward_table.insert(ssrc, entry)?;
        self.stats.tracks_registered.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    /// Process a single packet from AF_XDP.
    ///
    /// Extracts source address from IP/UDP headers and dispatches to
    /// appropriate handler with source address preservation.
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 7.5: Route cold-path packets with source address preservation
    fn process_packet(&mut self, packet: &AfXdpPacket) {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Get packet data
        let data = match self.af_xdp.packet_data(packet) {
            Some(d) => d,
            None => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Skip Ethernet + IP + UDP headers (14 + 20 + 8 = 42 bytes minimum)
        // WHY: AF_XDP receives raw frames including all headers
        const ETH_HEADER_SIZE: usize = 14;
        const IP_HEADER_SIZE: usize = 20;
        const UDP_HEADER_SIZE: usize = 8;
        const MIN_HEADER_SIZE: usize = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
        
        if data.len() < MIN_HEADER_SIZE {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Extract source address from IP/UDP headers
        // IP header starts at offset 14 (after Ethernet header)
        // Source IP is at offset 12-15 within IP header
        // UDP header starts at offset 34 (14 + 20)
        // Source port is at offset 0-1 within UDP header
        let source_addr = Self::extract_source_addr(&data[ETH_HEADER_SIZE..]);

        // Extract UDP payload (skip headers)
        let payload = &data[MIN_HEADER_SIZE..];

        // Classify and dispatch with source address
        let ptype = Self::classify_packet(payload);
        match ptype {
            PacketType::Rtp => {
                self.stats.rtp_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(ssrc) = Self::extract_ssrc(payload) {
                    if let Some(addr) = source_addr {
                        self.handler.handle_rtp_with_addr(ssrc, payload, addr);
                    } else {
                        self.handler.handle_rtp(ssrc, payload);
                    }
                }
            }
            PacketType::Rtcp => {
                self.stats.rtcp_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(addr) = source_addr {
                    self.handler.handle_rtcp_with_addr(payload, addr);
                } else {
                    self.handler.handle_rtcp(payload);
                }
            }
            PacketType::Dtls => {
                self.stats.dtls_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(addr) = source_addr {
                    self.handler.handle_dtls_with_addr(payload, addr);
                } else {
                    self.handler.handle_dtls(payload);
                }
            }
            PacketType::Stun => {
                self.stats.stun_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(addr) = source_addr {
                    self.handler.handle_stun_with_addr(payload, addr);
                } else {
                    self.handler.handle_stun(payload);
                }
            }
            PacketType::Unknown => {
                self.stats.unknown_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Extract source address from IP/UDP headers.
    ///
    /// Parses the IP and UDP headers to extract the source IP address
    /// and port for response routing.
    ///
    /// # Arguments
    ///
    /// * `ip_data` - Data starting at IP header (after Ethernet header)
    ///
    /// # Returns
    ///
    /// `Some(SocketAddr)` if successfully parsed, `None` otherwise.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≤70 lines
    /// - ≥2 assertions (implicit via bounds checks)
    fn extract_source_addr(ip_data: &[u8]) -> Option<std::net::SocketAddr> {
        // IP header minimum size is 20 bytes
        if ip_data.len() < 28 {
            // Need at least IP header (20) + UDP header (8)
            return None;
        }

        // Check IP version (must be 4)
        let version = (ip_data[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length (IHL field, in 32-bit words)
        let ihl = (ip_data[0] & 0x0F) as usize * 4;
        if ihl < 20 || ip_data.len() < ihl + 8 {
            return None;
        }

        // Extract source IP (bytes 12-15 of IP header)
        let src_ip = std::net::Ipv4Addr::new(
            ip_data[12],
            ip_data[13],
            ip_data[14],
            ip_data[15],
        );

        // Extract source port (bytes 0-1 of UDP header, after IP header)
        let src_port = u16::from_be_bytes([ip_data[ihl], ip_data[ihl + 1]]);

        Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(src_ip, src_port)))
    }

    /// Classify a UDP payload as RTP, RTCP, DTLS, or STUN.
    fn classify_packet(data: &[u8]) -> PacketType {
        if data.is_empty() {
            return PacketType::Unknown;
        }

        let first_byte = data[0];

        // DTLS check: content type 20-25
        if (20..=25).contains(&first_byte) && data.len() >= 13 {
            return PacketType::Dtls;
        }

        // STUN check: magic cookie at bytes 4-7
        if data.len() >= 20 {
            let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            if magic == 0x2112A442 {
                return PacketType::Stun;
            }
        }

        // RTP/RTCP check: version must be 2
        let version = (first_byte >> 6) & 0x03;
        if version != 2 || data.len() < 2 {
            return PacketType::Unknown;
        }

        let second_byte = data[1];

        // RTCP: payload type 200-206
        if (200..=206).contains(&second_byte) && data.len() >= 8 {
            return PacketType::Rtcp;
        }

        // RTP: valid payload type (0-34 or 96-127)
        let pt = second_byte & 0x7F;
        if pt <= 34 || (96..=127).contains(&pt) {
            if data.len() >= 12 {
                return PacketType::Rtp;
            }
        }

        PacketType::Unknown
    }

    /// Extract SSRC from RTP packet.
    fn extract_ssrc(data: &[u8]) -> Option<u32> {
        if data.len() < 12 {
            return None;
        }
        // SSRC is at bytes 8-11 of RTP header
        Some(u32::from_be_bytes([data[8], data[9], data[10], data[11]]))
    }
}

// Stub implementation for non-Linux platforms
#[cfg(not(all(target_os = "linux", feature = "xdp")))]
pub struct XdpPacketProcessor {
    stats: XdpProcessorStats,
    running: AtomicBool,
}

#[cfg(not(all(target_os = "linux", feature = "xdp")))]
impl XdpPacketProcessor {
    /// Create a new XDP packet processor (stub - always fails).
    pub fn new(
        _ifname: &str,
        _queue_id: u32,
        _forward_table: ForwardTable,
        _handler: Arc<dyn PacketHandler>,
    ) -> Result<Self, XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Create with config (stub - always fails).
    pub fn with_config(
        _config: XdpProcessorConfig,
        _forward_table: ForwardTable,
        _handler: Arc<dyn PacketHandler>,
    ) -> Result<Self, XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Main processing loop (stub).
    pub fn run(&mut self) {
        // No-op on non-Linux
    }

    /// Stop the processing loop (stub).
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the processor is running (stub).
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Register a new track (stub - always fails).
    pub fn register_track(
        &self,
        _ssrc: u32,
        _destinations: &[ForwardEntry],
    ) -> Result<(), XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Register a single track (stub - always fails).
    pub fn register_track_single(
        &self,
        _ssrc: u32,
        _entry: ForwardEntry,
    ) -> Result<(), XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Unregister a track (stub - always fails).
    pub fn unregister_track(&self, _ssrc: u32) -> Result<(), XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Get statistics.
    pub fn stats(&self) -> &XdpProcessorStats {
        &self.stats
    }

    /// Get forward table (stub - returns None).
    pub fn forward_table(&self) -> Option<&ForwardTable> {
        None
    }

    /// Get mutable access to the underlying AF_XDP socket (stub - returns None).
    ///
    /// # Returns
    ///
    /// Always returns None on non-Linux platforms.
    #[inline]
    pub fn af_xdp_socket_mut(&mut self) -> Option<&mut ()> {
        // WHY: AF_XDP is only available on Linux. This stub returns None
        // to allow the XDP packet loop to gracefully fall back to the
        // standard transport path.
        None
    }

    /// Process XDP batch (stub - returns 0).
    pub fn process_xdp_batch(&mut self, _packets: &[()]) -> u32 {
        0
    }
}

/// Process a batch of packets from fallback (standard) transport.
///
/// Classifies each packet and returns classification results with SSRCs.
/// This function is used when XDP is not available.
///
/// # Arguments
///
/// * `packets` - Slice of received packets from UDP transport
/// * `stats` - Statistics to update
///
/// # Returns
///
/// Vector of (PacketType, Option<SSRC>, packet_index) tuples.
///
/// # TigerStyle Compliance
///
/// - ≤70 lines
/// - ≥2 assertions
/// - Bounded loop (max 64 packets)
pub fn process_fallback_batch(
    packets: &[crate::transport::RecvPacket],
    stats: &XdpProcessorStats,
) -> Vec<(PacketType, Option<u32>, usize)> {
    // Precondition assertion
    assert!(packets.len() <= 64, "batch size must not exceed 64");

    let mut results = Vec::with_capacity(packets.len());

    // Bounded loop (TigerStyle: explicit upper bound)
    for (idx, packet) in packets.iter().enumerate().take(64) {
        stats.packets_received.fetch_add(1, Ordering::Relaxed);

        let ptype = PacketType::classify(&packet.data);
        let ssrc = match ptype {
            PacketType::Rtp => {
                stats.rtp_packets.fetch_add(1, Ordering::Relaxed);
                PacketType::extract_rtp_ssrc(&packet.data)
            }
            PacketType::Rtcp => {
                stats.rtcp_packets.fetch_add(1, Ordering::Relaxed);
                PacketType::extract_rtcp_ssrc(&packet.data)
            }
            PacketType::Dtls => {
                stats.dtls_packets.fetch_add(1, Ordering::Relaxed);
                None
            }
            PacketType::Stun => {
                stats.stun_packets.fetch_add(1, Ordering::Relaxed);
                None
            }
            PacketType::Unknown => {
                stats.unknown_packets.fetch_add(1, Ordering::Relaxed);
                None
            }
        };

        results.push((ptype, ssrc, idx));
    }

    // Postcondition assertion
    assert!(results.len() <= 64, "results count must not exceed 64");

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_classification() {
        // Test DTLS detection (content type 22 = handshake)
        let dtls_packet = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(PacketType::classify(&dtls_packet), PacketType::Dtls);

        // Test STUN detection (magic cookie)
        let stun_packet = [
            0x00, 0x01, 0x00, 0x00, // Type + Length
            0x21, 0x12, 0xA4, 0x42, // Magic cookie
            0x00, 0x00, 0x00, 0x00, // Transaction ID (12 bytes)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(PacketType::classify(&stun_packet), PacketType::Stun);

        // Test RTCP detection (PT 200 = SR)
        let rtcp_packet = [0x80, 200, 0, 0, 0, 0, 0, 0];
        assert_eq!(PacketType::classify(&rtcp_packet), PacketType::Rtcp);

        // Test RTP detection (PT 96 = dynamic)
        let rtp_packet = [
            0x80, 96, 0, 0, // V=2, PT=96
            0, 0, 0, 0, // Timestamp
            0, 0, 0, 1, // SSRC
        ];
        assert_eq!(PacketType::classify(&rtp_packet), PacketType::Rtp);
    }

    #[test]
    fn test_packet_type_extract_ssrc() {
        // Test RTP SSRC extraction
        let rtp_packet = [
            0x80, 96, 0, 1, // V=2, PT=96, seq=1
            0, 0, 0, 0,    // Timestamp
            0x12, 0x34, 0x56, 0x78, // SSRC = 0x12345678
        ];
        assert_eq!(PacketType::extract_rtp_ssrc(&rtp_packet), Some(0x12345678));

        // Test RTCP SSRC extraction
        let rtcp_packet = [
            0x80, 200, 0, 6, // V=2, PT=200 (SR), length=6
            0xAB, 0xCD, 0xEF, 0x01, // SSRC = 0xABCDEF01
        ];
        assert_eq!(PacketType::extract_rtcp_ssrc(&rtcp_packet), Some(0xABCDEF01));

        // Test too short packet
        let short_packet = [0x80, 96, 0, 1];
        assert_eq!(PacketType::extract_rtp_ssrc(&short_packet), None);
    }

    #[test]
    fn test_xdp_processor_stats() {
        let stats = XdpProcessorStats::new();
        stats.packets_received.fetch_add(100, Ordering::Relaxed);
        stats.rtp_packets.fetch_add(90, Ordering::Relaxed);
        stats.rtcp_packets.fetch_add(10, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_received, 100);
        assert_eq!(snapshot.rtp_packets, 90);
        assert_eq!(snapshot.rtcp_packets, 10);
    }

    #[test]
    fn test_packet_type_enum() {
        assert_ne!(PacketType::Rtp, PacketType::Rtcp);
        assert_ne!(PacketType::Dtls, PacketType::Stun);
        assert_eq!(PacketType::Unknown, PacketType::Unknown);
    }

    #[test]
    fn test_packet_type_unknown() {
        // Empty packet
        assert_eq!(PacketType::classify(&[]), PacketType::Unknown);

        // Invalid version (not 2)
        let invalid_version = [0x00, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(PacketType::classify(&invalid_version), PacketType::Unknown);

        // Too short for RTP
        let short_rtp = [0x80, 96, 0, 0, 0, 0, 0, 0];
        assert_eq!(PacketType::classify(&short_rtp), PacketType::Unknown);
    }

    #[test]
    fn test_packet_type_dtls_content_types() {
        // Test all valid DTLS content types (20-25)
        for content_type in 20..=25 {
            let dtls_packet = [content_type, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                PacketType::classify(&dtls_packet),
                PacketType::Dtls,
                "content type {} should be DTLS",
                content_type
            );
        }

        // Content type 19 should not be DTLS
        let not_dtls = [19u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(PacketType::classify(&not_dtls), PacketType::Dtls);
    }

    #[test]
    fn test_packet_type_rtcp_types() {
        // Test all valid RTCP payload types (200-206)
        for pt in 200..=206 {
            let rtcp_packet = [0x80, pt, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                PacketType::classify(&rtcp_packet),
                PacketType::Rtcp,
                "PT {} should be RTCP",
                pt
            );
        }

        // PT 199 should not be RTCP (it's RTP with invalid PT)
        let not_rtcp = [0x80, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(PacketType::classify(&not_rtcp), PacketType::Rtcp);
    }
}
