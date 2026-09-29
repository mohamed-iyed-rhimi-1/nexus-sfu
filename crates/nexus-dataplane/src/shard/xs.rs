//! The cross-shard path (note §13.4, plan 2.2): hand-off of decrypted RTP
//! to the shards with subscribers, SRs and keyframe requests between shards,
//! and the buffers coming back.
//!
//! A packet is lent only after the local fan-out, so its buffer is final
//! (nothing writes a lent buffer). Every push is checked first (credit,
//! then room) and never waits: a refused hand-off is dropped and counted.
//! Everything here runs on the packet path: no allocation, every loop
//! bounded.

use std::time::Instant;

use nexus_media::rtp::RtpHeader;

use super::ingress::Src;
use super::Shard;
use crate::command::EventSink;
use crate::ids::{ShardId, TrackId};
use crate::pool::{BufRef, BUF_SIZE};
use crate::rtcp::SrInfo;
use crate::session::TrackIdx;
use crate::shard::io::DatagramIo;
use crate::track::MAX_LAYERS;
use crate::xs::{XsMsg, XS_BUDGET, XS_CREDIT};

/// The shards of a mask, lowest first (≤ 64).
fn shards_of(mut mask: u64) -> impl Iterator<Item = ShardId> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let index = mask.trailing_zeros() as u8;
        mask &= mask - 1;
        Some(ShardId::new(index))
    })
}

/// A shard's bit in a `ShardMask`.
pub(super) fn bit(shard: ShardId) -> u64 {
    1 << shard.index()
}

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// Releases the loans peers gave back; returns how many. Runs at the top
    /// of `iterate`, so their credit is there for this iteration's batch.
    pub(super) fn drain_returns(&mut self) -> usize {
        let Some(xs) = self.xs.as_ref() else {
            return 0;
        };
        let mut released = 0;
        for peer in xs.peer_ids() {
            // The credit bounds what can be outstanding to a peer.
            for _ in 0..XS_CREDIT {
                let Some(loan) = xs.take_return(peer) else {
                    break;
                };
                self.pool.release(loan, peer);
                released += 1;
            }
        }
        self.counters.xs_returned += released as u64;
        released
    }

    /// Lends the decrypted packet in `buf` to every remote shard of the track,
    /// after the local fan-out. Credit is checked first, then room (this shard
    /// is the queue's only producer, so the room is still there at the push).
    pub(super) fn lend_to_remotes(&mut self, tidx: TrackIdx, buf: BufRef, len: usize) {
        let track = self.tracks.get(tidx);
        let (id, mask) = (track.id, track.remote_shards);
        if mask == 0 {
            return;
        }
        let Some(xs) = self.xs.as_ref() else {
            debug_assert!(false, "remote shards without ports");
            return;
        };
        debug_assert!(len <= BUF_SIZE && mask & bit(self.config.shard) == 0);
        for peer in shards_of(mask) {
            if !self.pool.can_lend(peer) {
                self.counters.drop_xs_credit += 1;
                continue;
            }
            if !xs.has_room(peer) {
                self.counters.drop_xs_full += 1;
                continue;
            }
            let loan = self.pool.lend(buf, peer);
            let msg = XsMsg::Rtp {
                loan,
                len: len as u16,
                track: id,
                layer: 0,
            };
            match xs.send(peer, msg) {
                Ok(()) => {
                    self.counters.xs_tx += 1;
                    self.wake_mask |= bit(peer);
                }
                Err(msg) => {
                    debug_assert!(false, "room seen, then the push failed");
                    if let XsMsg::Rtp { loan, .. } = msg {
                        self.pool.unlend(loan);
                    }
                    self.counters.drop_xs_full += 1;
                }
            }
        }
    }

    /// Sends a message without a loan (SR, keyframe request); a full queue
    /// drops it (counted).
    pub(super) fn send_xs(&mut self, peer: ShardId, msg: XsMsg) {
        debug_assert!(!matches!(msg, XsMsg::Rtp { .. }));
        let Some(xs) = self.xs.as_ref() else {
            debug_assert!(false, "cross-shard message without ports");
            return;
        };
        match xs.send(peer, msg) {
            Ok(()) => {
                self.counters.xs_tx += 1;
                self.wake_mask |= bit(peer);
            }
            Err(_) => self.counters.drop_xs_full += 1,
        }
    }

    /// Sends a publisher's SR to every remote shard of the track.
    pub(super) fn sr_to_remotes(&mut self, track: TrackId, mask: u64, sr: SrInfo) {
        for peer in shards_of(mask) {
            let msg = XsMsg::SenderReport {
                track,
                layer: 0,
                ntp: sr.ntp,
                rtp: sr.rtp,
            };
            self.send_xs(peer, msg);
        }
    }

    /// Handles up to `XS_BUDGET` messages from each peer; returns how many.
    /// The ports are moved out for the drain (no allocation), so a peer's
    /// buffer can be read while the shard forwards from it.
    ///
    /// Nothing called from here may send to a peer (`send_xs`,
    /// `lend_to_remotes`, `keyframe_for` on a mirror): the ports are out, so
    /// the message would be lost (a `debug_assert!` in `send_xs`). Today the
    /// drain only forwards, translates SRs and asks the local publisher.
    pub(super) fn drain_cross_shard(&mut self, now: Instant) -> usize {
        let Some(xs) = self.xs.take() else {
            return 0;
        };
        let mut handled = 0;
        for peer in xs.peer_ids() {
            let mut returned = false;
            for _ in 0..XS_BUDGET {
                let Some(msg) = xs.recv(peer) else {
                    break;
                };
                handled += 1;
                match msg {
                    XsMsg::Rtp {
                        loan,
                        len,
                        track,
                        layer,
                    } => {
                        debug_assert!(usize::from(layer) < MAX_LAYERS);
                        let packet = xs.region(peer).read(&loan, usize::from(len));
                        self.mirror_rtp(packet, peer, track, now);
                        xs.give_back(loan);
                        returned = true;
                    }
                    XsMsg::SenderReport {
                        track,
                        layer,
                        ntp,
                        rtp,
                    } => {
                        debug_assert!(usize::from(layer) < MAX_LAYERS);
                        self.translate_sr_mirror(track, SrInfo { ntp, rtp });
                    }
                    XsMsg::KeyframeRequest { track, layer, from } => {
                        debug_assert!(usize::from(layer) < MAX_LAYERS && from == peer);
                        // The queue says who asked; `from` is only checked.
                        self.remote_keyframe_request(track, peer, now);
                    }
                }
            }
            // One wake per peer and drain, not per buffer.
            if returned {
                self.wake_mask |= bit(peer);
            }
        }
        self.counters.xs_rx += handled as u64;
        self.xs = Some(xs);
        handled
    }

    /// Forwards a peer's packet to the subscriptions of the track's mirror.
    fn mirror_rtp(&mut self, packet: &[u8], peer: ShardId, track: TrackId, now: Instant) {
        let Some(&midx) = self.mirror_ids.get(&track) else {
            // Unsubscribed here, or `AddRemoteShard` arrived first.
            self.counters.drop_xs_no_track += 1;
            return;
        };
        // A track has one publisher's shard: another peer's hand-off for it is
        // a bug there, dropped in release builds too.
        if self.mirrors.get(midx).source != peer {
            debug_assert!(false, "hand-off from a shard that is not the source");
            self.counters.drop_xs_no_track += 1;
            return;
        }
        // Parsed on the publisher's shard already: a failure is its bug.
        let Ok(header) = RtpHeader::parse(packet) else {
            debug_assert!(false, "handed-off RTP does not parse");
            self.counters.drop_xs_malformed += 1;
            return;
        };
        let count = self.mirrors.get(midx).subscribers.len();
        for i in 0..count {
            self.flush_if_full();
            let sidx = self.mirrors.get(midx).subscribers[i];
            self.forward(sidx, Src::Peer(packet), packet.len(), &header, now);
        }
    }

    /// A peer's SR for a mirrored track: translated for each subscription.
    fn translate_sr_mirror(&mut self, track: TrackId, sr: SrInfo) {
        let Some(&midx) = self.mirror_ids.get(&track) else {
            self.counters.drop_xs_no_track += 1;
            return;
        };
        // Copied once per SR (on the stack), not per subscriber.
        let cname = self.mirrors.get(midx).cname;
        let count = self.mirrors.get(midx).subscribers.len();
        for i in 0..count {
            self.flush_if_full();
            let sidx = self.mirrors.get(midx).subscribers[i];
            self.send_translated_sr(sidx, sr, &cname);
        }
    }

    /// A subscriber on `from` wants a keyframe of a local track. Ignored
    /// until `from` is one of the track's remote shards: the keyframe would
    /// not reach it, and the throttle would suppress the next request
    /// (`AddRemoteShard` asks for one itself).
    fn remote_keyframe_request(&mut self, track: TrackId, from: ShardId, now: Instant) {
        let Some(&tidx) = self.track_ids.get(&track) else {
            self.counters.drop_xs_no_track += 1;
            return;
        };
        if self.tracks.get(tidx).remote_shards & bit(from) == 0 {
            self.counters.xs_keyframe_ignored += 1;
            return;
        }
        self.request_keyframe(tidx, now);
    }

    /// Wakes each peer this iteration pushed to, once (a no-op unless it is
    /// parked).
    pub(super) fn wake_peers(&mut self) {
        let mask = std::mem::take(&mut self.wake_mask);
        for peer in shards_of(mask) {
            if let Some(wake) = self.peer_wakes.get(usize::from(peer.index())) {
                // A failed wake leaves the peer to its park timeout (≤ the
                // next housekeeping); nothing here can do better.
                let _ = wake.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shards_of_a_mask_lowest_first() {
        let ids: Vec<u8> = shards_of(0b1010_0110).map(ShardId::index).collect();
        assert_eq!(ids, [1, 2, 5, 7]);
        assert_eq!(shards_of(0).count(), 0);
        assert_eq!(shards_of(u64::MAX).count(), 64);
        assert_eq!(bit(ShardId::new(63)), 1 << 63);
    }
}
