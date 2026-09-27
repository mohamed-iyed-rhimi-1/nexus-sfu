//! The packet path (note §10): classify, STUN, DTLS, SRTP in, fan-out.
//!
//! Everything here runs on network input: no allocation (except the
//! `DtlsDatagram` copy until SRTP is verified), no panic, every loop bounded.

use std::net::SocketAddr;
use std::time::Instant;

use nexus_media::rtp::RtpHeader;

use super::Shard;
use crate::command::{Event, EventSink, SelectReason};
use crate::ext;
use crate::ice;
use crate::pool::{BufRef, BUF_SIZE};
use crate::rewrite::{commit, rewrite, RewriteError};
use crate::session::{SessionIdx, SubIdx, TrackIdx};
use crate::shard::io::{Datagram, DatagramIo};

/// Datagram classes by first byte (RFC 7983) and second byte (RFC 5761).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
    Other,
}

/// Classifies a datagram.
pub(crate) fn classify(data: &[u8]) -> Class {
    match data.first() {
        Some(0..=3) => Class::Stun,
        Some(20..=63) => Class::Dtls,
        Some(128..=191) => match data.get(1) {
            Some(b) if (64..=95).contains(&(b & 0x7F)) => Class::Rtcp,
            Some(_) => Class::Rtp,
            None => Class::Other,
        },
        _ => Class::Other,
    }
}

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// Handles one received datagram. The caller returns its buffer.
    pub(super) fn handle_datagram(&mut self, d: Datagram, now: Instant) {
        self.counters.rx_datagrams += 1;
        self.counters.rx_bytes += d.len as u64;
        match classify(&self.pool.buf(d.buf)[..d.len]) {
            Class::Stun => self.handle_stun(d, now),
            Class::Dtls => self.handle_dtls(d),
            Class::Rtp => self.handle_rtp(d, now),
            Class::Rtcp => self.handle_rtcp(d, now),
            Class::Other => self.counters.drop_unclassified += 1,
        }
    }

    /// Answers an authenticated binding request and applies nomination and
    /// rebinding (note §8.2-§8.4).
    fn handle_stun(&mut self, d: Datagram, now: Instant) {
        let data = &self.pool.buf(d.buf)[..d.len];
        let Some(request) = ice::scan(data) else {
            self.counters.drop_stun += 1;
            return;
        };
        let Some(&idx) = self.by_ufrag.get(&request.local_ufrag) else {
            self.counters.drop_stun += 1;
            return;
        };
        let password = self.sessions.get(idx).ice.local_pwd;
        if !ice::verify(data, &request, &password) {
            self.counters.drop_stun_auth += 1;
            return;
        }
        let Some(out) = self.pool.take() else {
            self.counters.drop_pool_empty += 1;
            return;
        };
        let (_, dst) = self.pool.pair_mut(d.buf, out);
        match ice::write_success(dst, &request, d.addr, &password) {
            Some(len) => {
                self.counters.stun_answered += 1;
                self.send(out, len, d.addr);
            }
            None => self.pool.put(out),
        }
        let replayed = self
            .sessions
            .get_mut(idx)
            .note_transaction(request.transaction_id);
        if replayed {
            // A retransmission (answered above) or a replay from another
            // address: never a reason to move the session.
            self.counters.stun_repeated += 1;
            return;
        }
        self.select_address(idx, d.addr, request.use_candidate, now);
    }

    /// Nomination (USE-CANDIDATE) selects at once; without it, a new address
    /// is selected only after the selected one was silent for
    /// `rebind_silence`. At most one switch per `MIN_SWITCH_INTERVAL`.
    fn select_address(&mut self, idx: SessionIdx, from: SocketAddr, nominated: bool, now: Instant) {
        let session = self.sessions.get_mut(idx);
        if session.addr == Some(from) {
            session.last_rx_selected = now;
            if nominated {
                session.pending_nomination = None; // the latest nomination wins
            }
            return;
        }
        let silent = now.saturating_duration_since(session.last_rx_selected);
        let reason = if nominated {
            SelectReason::Nominated
        } else if session.addr.is_some() && silent >= self.config.rebind_silence {
            SelectReason::Rebound
        } else {
            return; // another candidate pair being checked: answer only
        };
        if session
            .last_switch
            .is_some_and(|at| now.saturating_duration_since(at) < super::MIN_SWITCH_INTERVAL)
        {
            self.counters.switch_throttled += 1;
            // A refused nomination is applied once the interval passed (a
            // rebind is simply retried by the peer's next request).
            if nominated && session.pending_nomination.replace(from).is_none() {
                assert!(self.pending_switches.len() < self.pending_switches.capacity());
                self.pending_switches.push(idx);
            }
            return;
        }
        session.pending_nomination = None;
        self.switch_to(idx, from, reason, now);
    }

    /// Applies nominations refused by the switch interval once it passed.
    /// Bounded by `max_sessions` (each session is listed at most once).
    pub(super) fn apply_pending_switches(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.pending_switches.len() {
            let idx = self.pending_switches[i];
            let session = self.sessions.get_mut(idx);
            let due = session
                .last_switch
                .is_none_or(|at| now.saturating_duration_since(at) >= super::MIN_SWITCH_INTERVAL);
            if session.pending_nomination.is_some() && !due {
                i += 1;
                continue;
            }
            self.pending_switches.swap_remove(i);
            if let Some(addr) = self.sessions.get_mut(idx).pending_nomination.take() {
                self.switch_to(idx, addr, SelectReason::Nominated, now);
            }
        }
    }

    /// Makes `from` the session's selected address.
    fn switch_to(&mut self, idx: SessionIdx, from: SocketAddr, reason: SelectReason, now: Instant) {
        let session = self.sessions.get_mut(idx);
        debug_assert!(session.addr != Some(from));
        // The old address stays mapped for PREV_ADDR_GRACE (in-flight
        // packets); a switch within the grace evicts the one before it, so
        // the map holds ≤ 2 entries per session.
        if let Some(stale) = session.prev_addr.take() {
            if self.by_addr.get(&stale) == Some(&idx) {
                self.by_addr.remove(&stale);
            }
        }
        session.prev_addr = session.addr;
        session.addr = Some(from);
        session.last_rx_selected = now;
        session.last_switch = Some(now);
        if let Some(other) = self.by_addr.insert(from, idx) {
            if other != idx {
                self.forget_address(other, from);
            }
        }
        match reason {
            SelectReason::Nominated => self.counters.nominations += 1,
            SelectReason::Rebound => self.counters.rebinds += 1,
        }
        self.report_switch(idx, reason);
    }

    /// Emits `AddressSelected` for the session's current address; if the
    /// sink refuses it, the sweep retries.
    pub(super) fn report_switch(&mut self, idx: SessionIdx, reason: SelectReason) {
        let session = self.sessions.get(idx);
        let (id, Some(addr)) = (session.id, session.addr) else {
            return;
        };
        let delivered = self.emit(Event::AddressSelected { id, addr, reason });
        self.sessions.get_mut(idx).unreported_switch = (!delivered).then_some(reason);
    }

    /// Another session authenticated from `addr`: the old owner loses it.
    fn forget_address(&mut self, idx: SessionIdx, addr: SocketAddr) {
        let session = self.sessions.get_mut(idx);
        if session.addr == Some(addr) {
            session.addr = None;
        }
        if session.prev_addr == Some(addr) {
            session.prev_addr = None;
        }
    }

    /// DTLS goes to the control plane until the peer's SRTP is verified.
    fn handle_dtls(&mut self, d: Datagram) {
        let Some(&idx) = self.by_addr.get(&d.addr) else {
            self.counters.drop_unknown_addr += 1;
            return;
        };
        let session = self.sessions.get_mut(idx);
        if session.srtp_verified {
            self.counters.drop_dtls_verified += 1;
            return;
        }
        // Checked before the copy: a flood costs no allocation.
        if session.dtls_budget == 0 {
            self.counters.drop_dtls_budget += 1;
            return;
        }
        session.dtls_budget -= 1;
        let id = session.id;
        let bytes: Box<[u8]> = self.pool.buf(d.buf)[..d.len].into();
        self.emit(Event::DtlsDatagram { id, bytes });
    }

    /// Session by address and SRTP of the session, else counted.
    fn srtp_session(&mut self, d: &Datagram) -> Option<SessionIdx> {
        let Some(&idx) = self.by_addr.get(&d.addr) else {
            self.counters.drop_unknown_addr += 1;
            return None;
        };
        if self.sessions.get(idx).srtp_in.is_none() {
            self.counters.drop_no_srtp += 1;
            return None;
        }
        Some(idx)
    }

    /// An authenticated SRTP/SRTCP packet arrived: liveness, and the first
    /// one tells the control plane DTLS state can go (note §6.3).
    fn authenticated(&mut self, idx: SessionIdx, from: SocketAddr, now: Instant) {
        let session = self.sessions.get_mut(idx);
        if session.addr == Some(from) {
            session.last_rx_selected = now;
        }
        if !session.srtp_verified {
            // Set only once delivered; otherwise the next packet retries.
            let id = session.id;
            if self.emit(Event::PeerSrtpVerified { id }) {
                self.sessions.get_mut(idx).srtp_verified = true;
            }
        }
    }

    fn handle_rtp(&mut self, d: Datagram, now: Instant) {
        let Some(idx) = self.srtp_session(&d) else {
            return;
        };
        let now_s = self.now_s(now);
        let buf = &mut self.pool.buf_mut(d.buf)[..BUF_SIZE];
        let inbound = self
            .sessions
            .get_mut(idx)
            .srtp_in
            .as_mut()
            .expect("checked");
        let Some(len) = inbound.unprotect_rtp(buf, d.len, now_s) else {
            self.counters.drop_srtp_auth += 1;
            return;
        };
        self.authenticated(idx, d.addr, now);
        // Parsed only after unprotect: padding is read from the last byte.
        let Ok(header) = RtpHeader::parse(&self.pool.buf(d.buf)[..len]) else {
            self.counters.drop_malformed += 1;
            return;
        };
        let known = self.sessions.get(idx).track_of_ssrc(header.ssrc);
        let Some(track) = known.or_else(|| self.learn_ssrc(idx, d.buf, len, &header)) else {
            self.counters.drop_no_route += 1;
            return;
        };
        self.fan_out(track, d.buf, len, &header, now);
    }

    /// Note §7.2: an unknown SSRC whose `mid` element names one of the
    /// session's unbound tracks is bound to it (≤ 10 tracks checked).
    fn learn_ssrc(
        &mut self,
        idx: SessionIdx,
        buf: BufRef,
        len: usize,
        header: &RtpHeader,
    ) -> Option<TrackIdx> {
        let session = self.sessions.get(idx);
        let packet = &self.pool.buf(buf)[..len];
        let tidx = session.unbound.as_slice().iter().copied().find(|&t| {
            let spec = &self.tracks.get(t).spec;
            ext::find(packet, header, spec.ext.mid) == Some(spec.mid.as_bytes())
        })?;
        let ssrc = header.ssrc;
        let session = self.sessions.get_mut(idx);
        let removed = session.unbound.swap_remove_where(|t| *t == tidx);
        let added = session.published.push((ssrc, tidx));
        debug_assert!(removed.is_some() && added);
        if let Some(inbound) = session.srtp_in.as_mut() {
            // ≤ 10 tracks, so a pin slot is always free.
            let pinned = inbound.pin(ssrc);
            debug_assert!(pinned.is_ok());
        }
        self.tracks.get_mut(tidx).layers[0].ssrc = Some(ssrc);
        self.counters.ssrcs_learned += 1;
        Some(tidx)
    }

    fn handle_rtcp(&mut self, d: Datagram, now: Instant) {
        let Some(idx) = self.srtp_session(&d) else {
            return;
        };
        let now_s = self.now_s(now);
        let buf = &mut self.pool.buf_mut(d.buf)[..BUF_SIZE];
        let inbound = self
            .sessions
            .get_mut(idx)
            .srtp_in
            .as_mut()
            .expect("checked");
        let Some(len) = inbound.unprotect_rtcp(buf, d.len, now_s) else {
            self.counters.drop_srtp_auth += 1;
            return;
        };
        self.authenticated(idx, d.addr, now);
        self.counters.rtcp_received += 1;
        self.handle_rtcp_compound(idx, d.buf, len, now);
    }

    /// Rewrites and sends the packet to every subscriber with outbound SRTP
    /// and an address (note §10.2).
    fn fan_out(
        &mut self,
        tidx: TrackIdx,
        src: BufRef,
        len: usize,
        header: &RtpHeader,
        now: Instant,
    ) {
        let count = self.tracks.get(tidx).subscribers.len();
        for i in 0..count {
            if self.tx.is_full() {
                self.flush();
            }
            let sidx = self.tracks.get(tidx).subscribers[i];
            self.forward(sidx, src, len, header, now);
        }
    }

    /// Rewrite, protect and queue for one subscription; the rewrite state
    /// advances only when the packet is queued. `tx` has room.
    fn forward(&mut self, sidx: SubIdx, src: BufRef, len: usize, header: &RtpHeader, now: Instant) {
        debug_assert!(!self.tx.is_full());
        let sub = self.subs.get_mut(sidx);
        let session = self.sessions.get_mut(sub.session);
        let (Some(outbound), Some(addr)) = (session.srtp_out.as_mut(), session.addr) else {
            return;
        };
        let Some(out) = self.pool.take() else {
            self.counters.drop_pool_empty += 1;
            return;
        };
        let (input, dst) = self.pool.pair_mut(src, out);
        let room = BUF_SIZE - outbound.tag_len() - 4;
        let written = rewrite(
            &input[..len],
            header,
            sub,
            &mut self.rng,
            now,
            &mut dst[..room],
        );
        let (rtp_len, advance) = match written {
            Ok(done) => done,
            Err(error) => {
                match error {
                    RewriteError::UnmappedPt => self.counters.drop_unmapped_pt += 1,
                    RewriteError::TooLarge => self.counters.drop_too_large += 1,
                }
                self.pool.put(out);
                return;
            }
        };
        let Some(n) = outbound.protect_rtp(dst, rtp_len) else {
            self.counters.drop_srtp_protect += 1;
            self.pool.put(out);
            return;
        };
        commit(&mut sub.rewrite, advance, now);
        self.counters.rebased += u64::from(advance.rebased);
        sub.sent_packets = sub.sent_packets.wrapping_add(1);
        sub.sent_octets = sub.sent_octets.wrapping_add(header.payload_len(len) as u32);
        self.tx.push(Datagram {
            buf: out,
            len: n,
            addr,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_follows_rfc_7983_and_5761() {
        assert_eq!(classify(&[0, 1]), Class::Stun);
        assert_eq!(classify(&[3]), Class::Stun);
        assert_eq!(classify(&[20]), Class::Dtls);
        assert_eq!(classify(&[63]), Class::Dtls);
        assert_eq!(classify(&[0x80, 111]), Class::Rtp);
        assert_eq!(classify(&[0x80, 0x80 | 111]), Class::Rtp);
        assert_eq!(classify(&[0x80, 200]), Class::Rtcp);
        assert_eq!(classify(&[0x81, 201]), Class::Rtcp);
        assert_eq!(classify(&[0x80, 64]), Class::Rtcp);
        assert_eq!(classify(&[0x80, 95]), Class::Rtcp);
        assert_eq!(classify(&[0x80]), Class::Other);
        assert_eq!(classify(&[]), Class::Other);
        assert_eq!(classify(&[4]), Class::Other);
        assert_eq!(classify(&[64]), Class::Other);
        assert_eq!(classify(&[192]), Class::Other);
    }
}
