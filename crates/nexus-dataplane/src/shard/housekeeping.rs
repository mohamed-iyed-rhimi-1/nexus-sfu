//! The 1 s sweep (note §3.4): consent, inbound SSRC eviction, stale
//! addresses, published stats. Bounded by the session slab's slots, which
//! never exceed `max_sessions`.

use std::time::Instant;

use nexus_transport::srtp::INBOUND_IDLE_EVICT_S;

use super::stats::Gauges;
use super::{Shard, PREV_ADDR_GRACE};
use crate::command::{Event, EventSink};
use crate::session::{SessionIdx, DTLS_BUDGET_PER_SWEEP};
use crate::shard::io::DatagramIo;

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// Runs the sweep over every session, then publishes the counters.
    pub(super) fn housekeeping(&mut self, now: Instant) {
        self.dtls_budget = self.config.dtls_budget_per_sweep;
        let slots = self.sessions.slot_count();
        assert!(slots <= self.config.max_sessions as usize);
        for index in 0..slots {
            if let Some(idx) = self.sessions.key_at(index) {
                self.sweep_session(idx, now);
            }
        }
        // Bounded by the track slab's slots (≤ 10 per session). Sent before
        // the stats are published, so they count what went out.
        for index in 0..self.tracks.slot_count() {
            if let Some(tidx) = self.tracks.key_at(index) {
                self.deferred_keyframe(tidx, now);
            }
        }
        self.flush();
        let (last_rx, last_at) = self.last_sweep;
        let elapsed_ms = now.saturating_duration_since(last_at).as_millis() as u64;
        let received = self.counters.rx_datagrams - last_rx;
        if elapsed_ms > 0 {
            self.rx_pps = received.saturating_mul(1_000) / elapsed_ms;
        }
        self.last_sweep = (self.counters.rx_datagrams, now);
        self.stats.publish(&self.counters, self.gauges());
    }

    /// Table sizes and rates for `ShardStats`.
    pub(super) fn gauges(&self) -> Gauges {
        Gauges {
            sessions: self.sessions.len() as u64,
            tracks: self.tracks.len() as u64,
            subscriptions: self.subs.len() as u64,
            rx_pps: self.rx_pps,
            mirrors: self.mirrors.len() as u64,
            xs_in_flight: u64::from(self.pool.lent_total()),
        }
    }

    fn sweep_session(&mut self, idx: SessionIdx, now: Instant) {
        let now_s = self.now_s(now);
        let session = self.sessions.get_mut(idx);
        session.dtls_budget = DTLS_BUDGET_PER_SWEEP;
        if let Some(inbound) = session.srtp_in.as_mut() {
            inbound.evict_idle(now_s, INBOUND_IDLE_EVICT_S);
        }
        // In-flight packets from before the last switch have arrived by now.
        let grace_over = session
            .last_switch
            .is_none_or(|at| now.saturating_duration_since(at) >= PREV_ADDR_GRACE);
        if grace_over {
            if let Some(stale) = session.prev_addr.take() {
                if self.by_addr.get(&stale) == Some(&idx) {
                    self.by_addr.remove(&stale);
                }
            }
        }
        if let Some(reason) = session.unreported_switch {
            self.report_switch(idx, reason);
        }
        self.check_consent(idx, now);
    }

    /// Note §8.5: `ConsentLost` once no authenticated traffic came from the
    /// selected address for `consent_timeout`. The flag is set only when the
    /// event was accepted, so a full sink means a retry next sweep.
    fn check_consent(&mut self, idx: SessionIdx, now: Instant) {
        let session = self.sessions.get(idx);
        let silent = now.saturating_duration_since(session.last_rx_selected);
        if session.consent_lost || silent < self.config.consent_timeout {
            return;
        }
        let id = session.id;
        if self.emit(Event::ConsentLost { id }) {
            self.sessions.get_mut(idx).consent_lost = true;
            self.counters.consent_lost += 1;
        }
    }
}
