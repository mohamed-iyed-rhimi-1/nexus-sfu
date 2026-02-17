//! ConnectionMonitor: owns the WebRTC connection lifecycle.
//!
//! Processes STUN/DTLS packets forwarded from the packet loop,
//! runs timer-driven polls (ICE pacing, DTLS retransmit, consent, cleanup),
//! and emits `SessionEvent`s when sessions transition state.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::time::{Interval, interval, Duration};
use tracing::{debug, info};

use nexus_webrtc::webrtc::{SessionState, TransportId, WebRtcTransport};

use super::events::{ColdPathPacket, DisconnectReason, SessionEvent};

/// Idle timeout before session cleanup.
const SESSION_IDLE_TIMEOUT_SECS: u64 = 30;

/// Shared UDP send capability.
///
/// Uses a raw UdpSocket for sending STUN/DTLS responses.
/// The packet loop keeps its own MediaTransport for recv + send.
#[derive(Clone)]
pub struct PacketSender {
    socket: Arc<std::net::UdpSocket>,
}

impl PacketSender {
    pub fn new(socket: Arc<std::net::UdpSocket>) -> Self {
        Self { socket }
    }

    #[inline]
    pub fn send(&self, data: &[u8], dest: SocketAddr) {
        if let Err(e) = self.socket.send_to(data, dest) {
            debug!("PacketSender: failed to send to {}: {:?}", dest, e);
        }
    }
}

/// Monitors WebRTC connection lifecycle via timers and cold-path packets.
pub struct ConnectionMonitor {
    webrtc_transport: Arc<WebRtcTransport>,
    packet_sender: PacketSender,
    /// Sessions already known to be Established — avoids duplicate events.
    established: HashSet<u64>,
    /// Timer intervals (public so orchestrator can use them in select!).
    pub ice_interval: Interval,
    pub dtls_interval: Interval,
    pub consent_interval: Interval,
    pub cleanup_interval: Interval,
}

impl ConnectionMonitor {
    pub fn new(
        webrtc_transport: Arc<WebRtcTransport>,
        packet_sender: PacketSender,
    ) -> Self {
        Self {
            webrtc_transport,
            packet_sender,
            established: HashSet::with_capacity(256),
            ice_interval: interval(Duration::from_millis(50)),
            dtls_interval: interval(Duration::from_millis(200)),
            consent_interval: interval(Duration::from_secs(5)),
            cleanup_interval: interval(Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)),
        }
    }

    /// Process a STUN or DTLS packet forwarded from the packet loop.
    /// Returns any session lifecycle events triggered by the packet.
    pub fn process_incoming(&mut self, packet: ColdPathPacket) -> Vec<SessionEvent> {
        let mut out_buf = [0u8; 2048];
        let result = self.webrtc_transport.process_packet(
            &packet.data,
            packet.source_addr,
            &mut out_buf,
        );

        match result {
            Ok(Some((session_id, incoming_data))) => {
                use nexus_webrtc::webrtc::IncomingData;
                match incoming_data {
                    IncomingData::Stun(response) => {
                        self.packet_sender.send(&response, packet.source_addr);
                    }
                    IncomingData::Dtls(response) => {
                        self.packet_sender.send(&response, packet.source_addr);
                    }
                    IncomingData::StunAndDtls(stun_response, dtls_flight) => {
                        self.packet_sender.send(&stun_response, packet.source_addr);
                        self.packet_sender.send(&dtls_flight, packet.source_addr);
                    }
                    // RTP/RTCP should not arrive here — packet loop handles them inline.
                    IncomingData::Rtp(_) | IncomingData::Rtcp(_) | IncomingData::None => {}
                }
                self.check_established(session_id)
            }
            Ok(None) => Vec::new(),
            Err(e) => {
                debug!("Cold-path packet error from {}: {:?}", packet.source_addr, e);
                Vec::new()
            }
        }
    }

    /// Poll ICE connectivity checks and retransmissions for all sessions.
    pub fn poll_ice(&mut self) -> Vec<SessionEvent> {
        let session_ids = self.webrtc_transport.session_ids();
        let mut events = Vec::new();

        for session_id in session_ids {
            let poll_result = self.webrtc_transport.with_session_mut(session_id, |session| {
                let (packets, dtls_flight) = session.poll_ice_outbound();
                let remote = session.remote_addr();
                if !packets.is_empty() || dtls_flight.is_some() {
                    Some((packets, dtls_flight, remote))
                } else {
                    None
                }
            });

            if let Some(Some((packets, dtls_flight, remote))) = poll_result {
                for (dest_addr, stun_request) in &packets {
                    self.packet_sender.send(stun_request, *dest_addr);
                }
                if let Some(ref dtls_data) = dtls_flight {
                    if let Some(addr) = remote {
                        self.packet_sender.send(dtls_data, addr);
                    }
                }
                events.extend(self.check_established(session_id));
            }
        }
        events
    }

    /// Poll DTLS retransmissions for sessions in DtlsHandshaking state.
    pub fn poll_dtls(&mut self) -> Vec<SessionEvent> {
        let session_ids = self.webrtc_transport.session_ids();
        let mut events = Vec::new();

        for session_id in session_ids {
            let dtls_result = self.webrtc_transport.with_session_mut(session_id, |session| {
                session.poll_dtls_retransmit()
            });

            if let Some(Some((dest_addr, data))) = dtls_result {
                self.packet_sender.send(&data, dest_addr);
                events.extend(self.check_established(session_id));
            }
        }
        events
    }

    /// Send consent keepalives to all established sessions (RFC 7675).
    pub fn poll_consent(&mut self) -> Vec<SessionEvent> {
        let failed = self.webrtc_transport.check_consent_freshness();
        let mut events = Vec::new();

        // Emit Disconnected for sessions that failed consent
        for session_id in &failed {
            let sid = session_id.value();
            self.established.remove(&sid);
            events.push(SessionEvent::Disconnected {
                session_id: sid,
                reason: DisconnectReason::ConsentExpired,
            });
        }

        // Send STUN binding indications to healthy established sessions
        let session_ids = self.webrtc_transport.session_ids();
        for sid in session_ids {
            let remote_addr = self.webrtc_transport.with_session(sid, |session| {
                if session.state() == SessionState::Established {
                    session.remote_addr()
                } else {
                    None
                }
            });

            if let Some(Some(remote)) = remote_addr {
                let mut buf = [0u8; 20];
                let txn: [u8; 12] = rand::random();
                let len = nexus_transport::ice::stun::create_binding_indication(&mut buf, &txn);
                self.packet_sender.send(&buf[..len], remote);
            }
        }
        events
    }

    /// Remove idle sessions and emit Disconnected events.
    pub fn cleanup_idle(&mut self) -> Vec<SessionEvent> {
        let removed = self.webrtc_transport.cleanup_idle_sessions(SESSION_IDLE_TIMEOUT_SECS);
        let mut events = Vec::with_capacity(removed.len());

        for session_id in removed {
            let sid = session_id.value();
            self.established.remove(&sid);
            events.push(SessionEvent::Disconnected {
                session_id: sid,
                reason: DisconnectReason::IdleTimeout,
            });
            info!("Cleaned up idle session {}", sid);
        }
        events
    }

    /// Check if a session just transitioned to Established.
    /// Returns a one-shot event if this is the first time we see it.
    fn check_established(&mut self, transport_id: TransportId) -> Vec<SessionEvent> {
        let sid = transport_id.value();
        if self.established.contains(&sid) {
            return Vec::new();
        }

        let is_established = self.webrtc_transport.with_session(transport_id, |session| {
            session.state() == SessionState::Established
        });

        if is_established == Some(true) {
            self.established.insert(sid);
            info!("Session {} established", sid);
            vec![SessionEvent::Established { session_id: sid }]
        } else {
            Vec::new()
        }
    }
}
