//! Shard counters (note §5.4). The hot path increments plain `u64`s in
//! `ShardCounters`; housekeeping copies them into the `ShardStats` atomics
//! once per second, which anything may read.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        /// Shard-local counters (plain integers, hot path).
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct ShardCounters {
            $($(#[$doc])* pub $name: u64,)*
        }

        /// Published counters and gauges, written once per second.
        #[derive(Debug, Default)]
        pub struct ShardStats {
            $($name: AtomicU64,)*
            sessions: AtomicU64,
            tracks: AtomicU64,
            subscriptions: AtomicU64,
            rx_pps: AtomicU64,
        }

        impl ShardStats {
            /// Stores the shard's current counters and table sizes.
            pub fn publish(&self, counters: &ShardCounters, gauges: Gauges) {
                $(self.$name.store(counters.$name, Ordering::Relaxed);)*
                self.sessions.store(gauges.sessions, Ordering::Relaxed);
                self.tracks.store(gauges.tracks, Ordering::Relaxed);
                self.subscriptions.store(gauges.subscriptions, Ordering::Relaxed);
                self.rx_pps.store(gauges.rx_pps, Ordering::Relaxed);
            }

            /// The last published values.
            pub fn load(&self) -> ShardStatsSnapshot {
                ShardStatsSnapshot {
                    counters: ShardCounters {
                        $($name: self.$name.load(Ordering::Relaxed),)*
                    },
                    gauges: Gauges {
                        sessions: self.sessions.load(Ordering::Relaxed),
                        tracks: self.tracks.load(Ordering::Relaxed),
                        subscriptions: self.subscriptions.load(Ordering::Relaxed),
                        rx_pps: self.rx_pps.load(Ordering::Relaxed),
                    },
                }
            }
        }
    };
}

/// Table sizes published with the counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gauges {
    /// Sessions.
    pub sessions: u64,
    /// Published tracks.
    pub tracks: u64,
    /// Subscriptions.
    pub subscriptions: u64,
    /// Datagrams received per second over the last sweep interval.
    pub rx_pps: u64,
}

/// A read of `ShardStats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardStatsSnapshot {
    /// Counters.
    pub counters: ShardCounters,
    /// Gauges.
    pub gauges: Gauges,
}

counters! {
    /// Loop iterations.
    iterations,
    /// Times the shard thread parked (note §3.3).
    parks,
    /// Datagrams received.
    rx_datagrams,
    /// Bytes received.
    rx_bytes,
    /// Received datagrams larger than a pool buffer, dropped.
    rx_truncated,
    /// Receive calls that failed with an error other than `WouldBlock`.
    rx_errors,
    /// Datagrams dropped because their source address was unreadable.
    rx_unreadable,
    /// Datagrams handed to the I/O backend and sent.
    tx_datagrams,
    /// Bytes sent.
    tx_bytes,
    /// Datagrams the backend could not send.
    drop_send_failed,
    /// Flushes forced by a full send batch in the middle of a fan-out.
    tx_full_flushes,
    /// First byte in no RFC 7983 range.
    drop_unclassified,
    /// STUN that is not a valid binding request for a known ufrag.
    drop_stun,
    /// Binding request that failed FINGERPRINT or MESSAGE-INTEGRITY.
    drop_stun_auth,
    /// DTLS or SRTP from an address no session selected.
    drop_unknown_addr,
    /// DTLS from a session's address that is not the selected one (the previous
    /// address during its grace period after a switch).
    drop_dtls_unselected,
    /// DTLS after `PeerSrtpVerified`.
    drop_dtls_verified,
    /// DTLS beyond the session's per-second budget.
    drop_dtls_budget,
    /// DTLS beyond the shard's per-second budget (all sessions together).
    drop_dtls_shard_budget,
    /// SRTP/SRTCP for a session without SRTP.
    drop_no_srtp,
    /// SRTP/SRTCP that failed authentication, replay or length checks.
    drop_srtp_auth,
    /// Decrypted RTP whose header does not parse.
    drop_malformed,
    /// RTP for an SSRC no track has (and no unbound mid matches).
    drop_no_route,
    /// RTP whose PT the subscription does not map.
    drop_unmapped_pt,
    /// Rewritten packet does not fit a buffer.
    drop_too_large,
    /// Outbound SRTP refused the packet (e.g. an index already sent).
    drop_srtp_protect,
    /// No free pool buffer.
    drop_pool_empty,
    /// Event sink and retention queue full.
    drop_event_full,
    /// Events dropped because the event channel is closed (control plane
    /// gone).
    drop_event_closed,
    /// Events for a session after its `ConsentLost` (not sent).
    drop_after_consent,
    /// `SendDatagram` for a session without an address, or too large.
    drop_send_datagram,
    /// Malformed RTCP compound (a bad block or more than 16).
    drop_rtcp_malformed,
    /// Binding requests answered.
    stun_answered,
    /// Addresses selected by nomination.
    nominations,
    /// Addresses selected by NAT rebinding.
    rebinds,
    /// Address switches refused by `MIN_SWITCH_INTERVAL`.
    switch_throttled,
    /// Binding requests with a recently seen transaction id (answered, never
    /// moving the session).
    stun_repeated,
    /// Subscriptions whose offsets were rebased after a forwarding gap.
    rebased,
    /// SSRCs bound to a track through the `mid` extension.
    ssrcs_learned,
    /// Authenticated RTCP compounds received.
    rtcp_received,
    /// RTCP blocks ignored in Phase 1 (RR, NACK, REMB, TWCC, SDES, BYE, XR, APP).
    rtcp_ignored,
    /// Translated SRs sent to subscribers.
    sr_translated,
    /// PLIs sent to publishers.
    keyframe_requests,
    /// Keyframe requests suppressed by the 500 ms throttle.
    keyframe_throttled,
    /// `ConsentLost` events.
    consent_lost,
    /// Commands handled.
    commands,
    /// Commands rejected.
    commands_rejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_then_load_round_trips() {
        let stats = ShardStats::default();
        let counters = ShardCounters {
            rx_datagrams: 3,
            rebinds: 1,
            ..Default::default()
        };
        let gauges = Gauges {
            sessions: 2,
            tracks: 1,
            subscriptions: 4,
            rx_pps: 250,
        };
        stats.publish(&counters, gauges);
        assert_eq!(stats.load(), ShardStatsSnapshot { counters, gauges });
    }
}
