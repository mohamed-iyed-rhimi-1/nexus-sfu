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

        impl ShardCounters {
            /// The counters' names, in declaration order (for exporters).
            pub const NAMES: &'static [&'static str] = &[$(stringify!($name),)*];

            /// The counters' values, in the order of `NAMES`.
            pub fn values(&self) -> [u64; Self::NAMES.len()] {
                [$(self.$name,)*]
            }

            /// Adds `other` field by field (saturating), e.g. to total the shards.
            pub fn add(&mut self, other: &Self) {
                $(self.$name = self.$name.saturating_add(other.$name);)*
            }
        }

        /// Published counters and gauges, written once per second.
        #[derive(Debug, Default)]
        pub struct ShardStats {
            $($name: AtomicU64,)*
            sessions: AtomicU64,
            tracks: AtomicU64,
            subscriptions: AtomicU64,
            rx_pps: AtomicU64,
            mirrors: AtomicU64,
            xs_in_flight: AtomicU64,
        }

        impl ShardStats {
            /// Stores the shard's current counters and table sizes.
            pub fn publish(&self, counters: &ShardCounters, gauges: Gauges) {
                $(self.$name.store(counters.$name, Ordering::Relaxed);)*
                self.sessions.store(gauges.sessions, Ordering::Relaxed);
                self.tracks.store(gauges.tracks, Ordering::Relaxed);
                self.subscriptions.store(gauges.subscriptions, Ordering::Relaxed);
                self.rx_pps.store(gauges.rx_pps, Ordering::Relaxed);
                self.mirrors.store(gauges.mirrors, Ordering::Relaxed);
                self.xs_in_flight.store(gauges.xs_in_flight, Ordering::Relaxed);
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
                        mirrors: self.mirrors.load(Ordering::Relaxed),
                        xs_in_flight: self.xs_in_flight.load(Ordering::Relaxed),
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
    /// Mirror tracks (tracks published on another shard with subscribers
    /// here).
    pub mirrors: u64,
    /// Loans outstanding: this shard's buffers lent to peers and not
    /// returned yet, counted per peer (one buffer lent to 3 peers counts 3;
    /// the per-peer credit bounds each peer's share).
    pub xs_in_flight: u64,
}

impl Gauges {
    /// Adds `other` field by field (saturating), e.g. to total the shards.
    pub fn add(&mut self, other: &Self) {
        // Destructured: a new gauge does not compile until it is added here.
        let Self {
            sessions,
            tracks,
            subscriptions,
            rx_pps,
            mirrors,
            xs_in_flight,
        } = *other;
        self.sessions = self.sessions.saturating_add(sessions);
        self.tracks = self.tracks.saturating_add(tracks);
        self.subscriptions = self.subscriptions.saturating_add(subscriptions);
        self.rx_pps = self.rx_pps.saturating_add(rx_pps);
        self.mirrors = self.mirrors.saturating_add(mirrors);
        self.xs_in_flight = self.xs_in_flight.saturating_add(xs_in_flight);
    }
}

/// A read of `ShardStats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardStatsSnapshot {
    /// Counters.
    pub counters: ShardCounters,
    /// Gauges.
    pub gauges: Gauges,
}

impl ShardStatsSnapshot {
    /// Adds `other`'s counters and gauges (the process total over shards).
    pub fn add(&mut self, other: &Self) {
        self.counters.add(&other.counters);
        self.gauges.add(&other.gauges);
    }
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
    /// Throttle windows that ended with a request waiting: one PLI is sent
    /// when the window ends (counted in `keyframe_requests` once sent).
    keyframe_deferred,
    /// `ConsentLost` events.
    consent_lost,
    /// Commands handled.
    commands,
    /// Commands rejected.
    commands_rejected,
    /// Messages sent to peer shards (RTP hand-offs, SRs, keyframe requests).
    xs_tx,
    /// Messages received from peer shards.
    xs_rx,
    /// Lent buffers given back by peer shards.
    xs_returned,
    /// Cross-shard messages dropped because the peer's queue was full.
    drop_xs_full,
    /// RTP hand-offs dropped because the peer held its whole credit.
    drop_xs_credit,
    /// Cross-shard messages for a track this shard neither publishes nor
    /// mirrors (a race with removal or with `AddRemoteShard`), or a hand-off
    /// from a shard that is not the mirror's source (a bug there).
    drop_xs_no_track,
    /// Handed-off RTP whose header does not parse (a bug on the sender).
    drop_xs_malformed,
    /// Keyframe requests from a shard not (yet) in the track's remote shards.
    xs_keyframe_ignored,
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
            mirrors: 3,
            xs_in_flight: 5,
        };
        stats.publish(&counters, gauges);
        assert_eq!(stats.load(), ShardStatsSnapshot { counters, gauges });
    }

    #[test]
    fn snapshots_add_field_by_field() {
        let one = |n: u64| ShardStatsSnapshot {
            counters: ShardCounters {
                rx_datagrams: n,
                xs_keyframe_ignored: 2 * n,
                ..Default::default()
            },
            gauges: Gauges {
                sessions: n,
                tracks: n + 1,
                subscriptions: n + 2,
                rx_pps: n + 3,
                mirrors: n + 4,
                xs_in_flight: n + 5,
            },
        };
        let mut total = one(1);
        total.add(&one(10));
        assert_eq!(total.counters.rx_datagrams, 11);
        assert_eq!(total.counters.xs_keyframe_ignored, 22);
        assert_eq!(total.counters.tx_datagrams, 0);
        let expected = Gauges {
            sessions: 11,
            tracks: 13,
            subscriptions: 15,
            rx_pps: 17,
            mirrors: 19,
            xs_in_flight: 21,
        };
        assert_eq!(total.gauges, expected);
        let mut max = ShardCounters {
            iterations: u64::MAX,
            ..Default::default()
        };
        max.add(&ShardCounters {
            iterations: 1,
            ..Default::default()
        });
        assert_eq!(max.iterations, u64::MAX, "saturates");
    }

    #[test]
    fn names_and_values_line_up() {
        let counters = ShardCounters {
            rx_datagrams: 3,
            rebinds: 7,
            ..Default::default()
        };
        let values = counters.values();
        assert_eq!(values.len(), ShardCounters::NAMES.len());
        let value = |name: &str| {
            let i = ShardCounters::NAMES
                .iter()
                .position(|n| *n == name)
                .unwrap();
            values[i]
        };
        assert_eq!(value("rx_datagrams"), 3);
        assert_eq!(value("rebinds"), 7);
        assert_eq!(value("tx_datagrams"), 0);
        // Prometheus names: lowercase ASCII and underscores only, all distinct.
        let mut names = ShardCounters::NAMES.to_vec();
        assert!(names
            .iter()
            .all(|n| n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ShardCounters::NAMES.len());
    }
}
