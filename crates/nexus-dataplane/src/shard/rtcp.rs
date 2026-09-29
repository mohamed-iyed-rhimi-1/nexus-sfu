//! Inbound RTCP (note §12): SR translation toward subscribers and keyframe
//! requests toward publishers. No allocation: blocks are read into fixed
//! lists first, so the handlers can take pool buffers.

use std::time::{Duration, Instant};

use nexus_media::rtcp::{demux_compound, PliPacket, RtcpType, SenderReport};

use super::Shard;
use crate::command::EventSink;
use crate::ids::CnameValue;
use crate::pool::BufRef;
use crate::rtcp::{fir_targets, write_pli, write_sdes_cname, write_sr, SrInfo, FMT_FIR, FMT_PLI};
use crate::session::{FixedVec, SessionIdx, SubIdx, TrackIdx};
use crate::shard::io::{Datagram, DatagramIo};
use crate::subscription::SubTrack;
use crate::xs::XsMsg;

/// Keyframe requests per track are at least this far apart (note §12.3).
pub const PLI_THROTTLE: Duration = Duration::from_millis(500);

/// Most keyframe requests read from one compound (16 blocks, FIR entries).
const MAX_WANTED: usize = 32;

/// What one compound asks for.
#[derive(Default)]
struct Requests {
    srs: FixedVec<(u32, SrInfo), 16>,
    keyframes: FixedVec<u32, MAX_WANTED>,
}

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// Dispatches the authenticated compound in `buf[..len]` from session `idx`.
    pub(super) fn handle_rtcp_compound(
        &mut self,
        idx: SessionIdx,
        buf: BufRef,
        len: usize,
        now: Instant,
    ) {
        let Some(requests) = self.read_compound(buf, len) else {
            self.counters.drop_rtcp_malformed += 1;
            return;
        };
        for &(ssrc, sr) in requests.srs.as_slice() {
            self.translate_sr(idx, ssrc, sr);
        }
        for &media_ssrc in requests.keyframes.as_slice() {
            self.keyframe_wanted(idx, media_ssrc, now);
        }
    }

    /// Reads SRs and PLI/FIR targets; counts what Phase 1 ignores. `None`
    /// when a block is malformed or blocks beyond 16 were cut off.
    fn read_compound(&mut self, buf: BufRef, len: usize) -> Option<Requests> {
        let data = &self.pool.buf(buf)[..len];
        let compound = demux_compound(data).ok()?;
        let covered: usize = compound.iter().map(|e| e.data.len()).sum();
        if covered != len {
            return None;
        }
        let mut requests = Requests::default();
        let mut ignored = 0;
        for entry in compound.iter() {
            match (entry.header.packet_type, entry.header.count) {
                (RtcpType::SenderReport, _) => {
                    let sr = SenderReport::parse(entry.data).ok()?;
                    let info = SrInfo {
                        ntp: sr.ntp_timestamp,
                        rtp: sr.rtp_timestamp,
                    };
                    // One SR per SSRC and compound (the last): a compound
                    // of 16 SRs must not send 16 per subscriber.
                    let known = requests
                        .srs
                        .as_mut_slice()
                        .iter_mut()
                        .find(|(s, _)| *s == sr.ssrc);
                    match known {
                        Some(entry) => entry.1 = info,
                        None => {
                            requests.srs.push((sr.ssrc, info));
                        }
                    }
                }
                (RtcpType::PayloadFeedback, FMT_PLI) => {
                    let pli = PliPacket::parse(entry.data).ok()?;
                    requests.keyframes.push(pli.media_ssrc);
                }
                (RtcpType::PayloadFeedback, FMT_FIR) => {
                    for ssrc in fir_targets(entry.data) {
                        requests.keyframes.push(ssrc);
                    }
                }
                _ => ignored += 1,
            }
        }
        self.counters.rtcp_ignored += ignored;
        Some(requests)
    }

    /// A publisher's SR for one of its SSRCs: stored on the layer, a
    /// translated SR + SDES sent to every started subscription (note §12.2),
    /// and the SR handed to the track's remote shards, which translate it for
    /// theirs (plan 2.2).
    fn translate_sr(&mut self, publisher: SessionIdx, ssrc: u32, sr: SrInfo) {
        let Some(tidx) = self.sessions.get(publisher).track_of_ssrc(ssrc) else {
            return;
        };
        let track = self.tracks.get_mut(tidx);
        track.layers[0].last_sr = Some(sr);
        // Copied once per SR (on the stack), not per subscriber.
        let (id, remote, cname) = (track.id, track.remote_shards, track.spec.cname);
        let count = track.subscribers.len();
        for i in 0..count {
            self.flush_if_full();
            let sidx = self.tracks.get(tidx).subscribers[i];
            self.send_translated_sr(sidx, sr, &cname);
        }
        self.sr_to_remotes(id, remote, sr);
    }

    /// SR + SDES for one subscription, with its own timestamp offset and
    /// counters, if it started and can be sent to. `tx` has room.
    pub(super) fn send_translated_sr(&mut self, sidx: SubIdx, sr: SrInfo, cname: &CnameValue) {
        debug_assert!(!self.tx.is_full());
        let sub = self.subs.get(sidx);
        let session = self.sessions.get_mut(sub.session);
        let (Some(outbound), Some(addr)) = (session.srtp_out.as_mut(), session.addr) else {
            return;
        };
        if !sub.rewrite.started || sub.rewrite.layer != 0 {
            return;
        }
        let Some(out) = self.pool.take() else {
            self.counters.drop_pool_empty += 1;
            return;
        };
        let dst = self.pool.buf_mut(out);
        let ssrc = sub.rewrite.out_ssrc;
        let translated = SrInfo {
            ntp: sr.ntp,
            rtp: sr.rtp.wrapping_add(sub.rewrite.ts_offset),
        };
        let protected = write_sr(dst, ssrc, translated, sub.sent_packets, sub.sent_octets)
            .and_then(|n| Some(n + write_sdes_cname(&mut dst[n..], ssrc, cname)?))
            .and_then(|n| outbound.protect_rtcp(dst, n));
        match protected {
            Some(n) => {
                self.counters.sr_translated += 1;
                self.tx.push(Datagram {
                    buf: out,
                    len: n,
                    addr,
                });
            }
            None => {
                self.counters.drop_srtp_protect += 1;
                self.pool.put(out);
            }
        }
    }

    /// A subscriber's PLI or FIR for one of its out SSRCs.
    fn keyframe_wanted(&mut self, subscriber: SessionIdx, media_ssrc: u32, now: Instant) {
        let session = self.sessions.get(subscriber);
        // Bounded by MAX_SUBS_PER_SESSION.
        let sub = session
            .subs
            .iter()
            .find(|s| self.subs.get(**s).rewrite.out_ssrc == media_ssrc);
        if let Some(&sidx) = sub {
            let track = self.subs.get(sidx).track;
            self.keyframe_for(track, now);
        }
    }

    /// Asks for a keyframe of a subscription's track: on this shard directly,
    /// for a mirror through the publisher's shard, which throttles.
    pub(super) fn keyframe_for(&mut self, track: SubTrack, now: Instant) {
        match track {
            SubTrack::Local(tidx) => self.request_keyframe(tidx, now),
            SubTrack::Mirror(midx) => {
                let mirror = self.mirrors.get(midx);
                let msg = XsMsg::KeyframeRequest {
                    track: mirror.id,
                    layer: 0,
                    from: self.config.shard,
                };
                self.send_xs(mirror.source, msg);
            }
        }
    }

    /// Sends a PLI for the track's layer to its publisher, at most once per
    /// `PLI_THROTTLE` (note §12.3). A request inside the window is not lost:
    /// the track keeps one pending, sent when the window ends
    /// (`deferred_keyframe`). Nothing is sent, and the throttle is not
    /// armed, while the publisher has no SRTP, address or known SSRC.
    pub(super) fn request_keyframe(&mut self, tidx: TrackIdx, now: Instant) {
        self.flush_if_full();
        let track = self.tracks.get_mut(tidx);
        if track
            .last_pli
            .is_some_and(|last| now.saturating_duration_since(last) < PLI_THROTTLE)
        {
            self.counters.keyframe_throttled += 1;
            if !track.keyframe_pending {
                track.keyframe_pending = true;
                self.counters.keyframe_deferred += 1;
            }
            return;
        }
        let Some(media_ssrc) = track.layers[0].ssrc else {
            return;
        };
        let session = self.sessions.get_mut(track.session);
        let (Some(outbound), Some(addr)) = (session.srtp_out.as_mut(), session.addr) else {
            return;
        };
        let Some(out) = self.pool.take() else {
            self.counters.drop_pool_empty += 1;
            return;
        };
        let dst = self.pool.buf_mut(out);
        let protected = write_pli(dst, session.out_ssrc_base, media_ssrc)
            .and_then(|n| outbound.protect_rtcp(dst, n));
        let Some(n) = protected else {
            self.counters.drop_srtp_protect += 1;
            self.pool.put(out);
            return;
        };
        self.tx.push(Datagram {
            buf: out,
            len: n,
            addr,
        });
        let track = self.tracks.get_mut(tidx);
        track.last_pli = Some(now);
        track.keyframe_pending = false;
        self.counters.keyframe_requests += 1;
    }

    /// Sends the track's pending keyframe request once the throttle window
    /// ended. Checked on each of the track's packets (one load while none is
    /// pending) and by housekeeping, so a paused publisher still gets it
    /// within the sweep interval. A request that cannot be sent yet (empty
    /// pool) stays pending.
    pub(super) fn deferred_keyframe(&mut self, tidx: TrackIdx, now: Instant) {
        let track = self.tracks.get(tidx);
        if !track.keyframe_pending {
            return;
        }
        let due = track
            .last_pli
            .is_none_or(|last| now.saturating_duration_since(last) >= PLI_THROTTLE);
        if due {
            self.request_keyframe(tidx, now);
        }
    }
}
