//! Command handling (control path: allocation allowed, `assert!` for the
//! shard's own invariants).

use std::time::Instant;

use nexus_transport::srtp::{SrtpInbound, SrtpOutbound};

use super::Shard;
use crate::command::{
    Command, Event, EventSink, ExtMap, IceParams, RejectReason, SrtpInstall, SubSpec, TrackSpec,
};
use crate::ids::{SessionId, SubscriptionId, TrackId};
use crate::pool::BUF_SIZE;
use crate::session::{
    Session, SessionIdx, SubIdx, TrackIdx, MAX_OUT_SSRC_OFFSET, MAX_SUBS_PER_SESSION,
    MAX_TRACKS_PER_SESSION,
};
use crate::shard::io::DatagramIo;
use crate::subscription::{RewriteState, Subscription};
use crate::track::PublishedTrack;

type Outcome = Result<(), RejectReason>;

impl<I: DatagramIo, S: EventSink> Shard<I, S> {
    /// Handles up to `COMMAND_BUDGET` queued commands.
    pub(super) fn drain_commands(&mut self, now: Instant) -> usize {
        let mut handled = 0;
        while handled < super::COMMAND_BUDGET {
            let Some(command) = self.commands.pop() else {
                break;
            };
            self.handle_command(command, now);
            handled += 1;
        }
        handled
    }

    fn handle_command(&mut self, command: Command, now: Instant) {
        self.counters.commands += 1;
        let (id, outcome) = match command {
            Command::CreateSession {
                id,
                ice,
                out_ssrc_base,
            } => (Some(id), self.create_session(id, ice, out_ssrc_base, now)),
            Command::SendDatagram { id, bytes } => (Some(id), self.send_datagram(id, &bytes)),
            Command::InstallSrtp { id, keys } => (Some(id), self.install_srtp(id, &keys, now)),
            Command::AddTrack { id, track, spec } => (Some(id), self.add_track(id, track, &spec)),
            Command::RemoveTrack { track } => (None, self.remove_track_cmd(track)),
            Command::Subscribe {
                id,
                sub,
                track,
                spec,
            } => (Some(id), self.subscribe(id, sub, track, &spec, now)),
            Command::Unsubscribe { sub } => (None, self.unsubscribe(sub)),
            Command::CloseSession { id } => (Some(id), self.close_session(id)),
        };
        if let Err(reason) = outcome {
            self.counters.commands_rejected += 1;
            self.emit(Event::CommandRejected { id, reason });
        }
        self.check_tables();
    }

    fn session_idx(&self, id: SessionId) -> Result<SessionIdx, RejectReason> {
        self.session_ids
            .get(&id)
            .copied()
            .ok_or(RejectReason::UnknownSession)
    }

    fn create_session(
        &mut self,
        id: SessionId,
        ice: IceParams,
        base: u32,
        now: Instant,
    ) -> Outcome {
        if self.session_ids.contains_key(&id) || self.by_ufrag.contains_key(&ice.local_ufrag) {
            return Err(RejectReason::DuplicateId);
        }
        if self.sessions.len() >= self.config.max_sessions as usize {
            return Err(RejectReason::SessionLimit);
        }
        let idx = self.sessions.insert(Session::new(id, ice, base, now));
        self.session_ids.insert(id, idx);
        self.by_ufrag.insert(ice.local_ufrag, idx);
        Ok(())
    }

    fn send_datagram(&mut self, id: SessionId, bytes: &[u8]) -> Outcome {
        let idx = self.session_idx(id)?;
        let Some(addr) = self.sessions.get(idx).addr else {
            self.counters.drop_send_datagram += 1;
            return Ok(());
        };
        if bytes.is_empty() || bytes.len() > BUF_SIZE {
            self.counters.drop_send_datagram += 1;
            return Ok(());
        }
        let Some(buf) = self.pool.take() else {
            self.counters.drop_pool_empty += 1;
            return Ok(());
        };
        self.pool.buf_mut(buf)[..bytes.len()].copy_from_slice(bytes);
        self.send(buf, bytes.len(), addr);
        Ok(())
    }

    /// Builds both contexts, registers the RTCP SSRC then every existing out
    /// SSRC in offset order, pins the known track SSRCs. All or nothing.
    /// Then asks for a keyframe for each of the session's subscriptions.
    fn install_srtp(&mut self, id: SessionId, keys: &SrtpInstall, now: Instant) -> Outcome {
        let idx = self.session_idx(id)?;
        let session = self.sessions.get(idx);
        if session.srtp_in.is_some() {
            return Err(RejectReason::SrtpAlreadyInstalled);
        }
        assert!(session.srtp_out.is_none());
        let setup = |_| RejectReason::SrtpSetup;
        let mut inbound = SrtpInbound::new(&keys.remote).map_err(setup)?;
        let mut outbound = SrtpOutbound::new(&keys.local, session.out_ssrc_base).map_err(setup)?;
        outbound.register(session.rtcp_ssrc()).map_err(setup)?;
        for &sub in &session.subs {
            outbound
                .register(self.subs.get(sub).rewrite.out_ssrc)
                .map_err(setup)?;
        }
        for &(ssrc, _) in session.published.as_slice() {
            inbound.pin(ssrc).map_err(setup)?;
        }
        let session = self.sessions.get_mut(idx);
        session.srtp_in = Some(Box::new(inbound));
        session.srtp_out = Some(Box::new(outbound));
        // Bounded by MAX_SUBS_PER_SESSION; throttled per track.
        for i in 0..self.sessions.get(idx).subs.len() {
            let track = self.subs.get(self.sessions.get(idx).subs[i]).track;
            self.request_keyframe(track, now);
        }
        Ok(())
    }

    fn add_track(&mut self, id: SessionId, track: TrackId, spec: &TrackSpec) -> Outcome {
        let idx = self.session_idx(id)?;
        if self.track_ids.contains_key(&track) {
            return Err(RejectReason::DuplicateId);
        }
        let session = self.sessions.get_mut(idx);
        if session.track_count() >= MAX_TRACKS_PER_SESSION {
            return Err(RejectReason::TrackLimit);
        }
        if let Some(ssrc) = spec.ssrc {
            if session.track_of_ssrc(ssrc).is_some() {
                return Err(RejectReason::SsrcInUse);
            }
            if let Some(inbound) = session.srtp_in.as_mut() {
                inbound.pin(ssrc).map_err(|_| RejectReason::SrtpSetup)?;
            }
        }
        let tidx = self.tracks.insert(PublishedTrack::new(track, idx, *spec));
        let session = self.sessions.get_mut(idx);
        let added = match spec.ssrc {
            Some(ssrc) => session.published.push((ssrc, tidx)),
            None => session.unbound.push(tidx),
        };
        assert!(added, "track count checked above");
        self.track_ids.insert(track, tidx);
        Ok(())
    }

    fn remove_track_cmd(&mut self, track: TrackId) -> Outcome {
        let tidx = self
            .track_ids
            .get(&track)
            .copied()
            .ok_or(RejectReason::UnknownTrack)?;
        self.remove_track(tidx);
        Ok(())
    }

    /// Removes a track and every subscription to it.
    fn remove_track(&mut self, tidx: TrackIdx) {
        // Bounded: each pass removes one subscription.
        while let Some(&sub) = self.tracks.get(tidx).subscribers.last() {
            self.remove_subscription(sub);
        }
        let track = self.tracks.remove(tidx);
        let session = self.sessions.get_mut(track.session);
        let bound = session.published.swap_remove_where(|(_, t)| *t == tidx);
        let unbound = session.unbound.swap_remove_where(|t| *t == tidx);
        assert!(
            bound.is_some() != unbound.is_some(),
            "track listed exactly once"
        );
        if let (Some((ssrc, _)), Some(inbound)) = (bound, session.srtp_in.as_mut()) {
            inbound.unpin(ssrc);
        }
        let removed = self.track_ids.remove(&track.id);
        assert!(removed == Some(tidx));
    }

    fn subscribe(
        &mut self,
        id: SessionId,
        sub: SubscriptionId,
        track: TrackId,
        spec: &SubSpec,
        now: Instant,
    ) -> Outcome {
        let idx = self.session_idx(id)?;
        let tidx = self
            .track_ids
            .get(&track)
            .copied()
            .ok_or(RejectReason::UnknownTrack)?;
        if self.sub_ids.contains_key(&sub) {
            return Err(RejectReason::DuplicateId);
        }
        if spec.source.shard != self.config.shard || spec.source.track != track {
            return Err(RejectReason::WrongShard);
        }
        if !ext_map_is_valid(&spec.ext_map) {
            return Err(RejectReason::InvalidSpec);
        }
        let session = self.sessions.get_mut(idx);
        if session.subs.len() >= MAX_SUBS_PER_SESSION {
            return Err(RejectReason::SubscriptionLimit);
        }
        // Note §9.3: strictly above every earlier out SSRC of the session.
        let offset = session.out_ssrc_offset(spec.out_ssrc);
        if offset <= session.last_out_ssrc_offset || offset > MAX_OUT_SSRC_OFFSET {
            return Err(RejectReason::OutSsrcNotMonotonic);
        }
        if let Some(outbound) = session.srtp_out.as_mut() {
            outbound
                .register(spec.out_ssrc)
                .map_err(|_| RejectReason::SrtpSetup)?;
        }
        session.last_out_ssrc_offset = offset;
        let sidx = self.subs.insert(Subscription {
            id: sub,
            session: idx,
            track: tidx,
            rewrite: RewriteState::new(spec.out_ssrc),
            ext_map: spec.ext_map,
            pub_mid: self.tracks.get(tidx).spec.ext.mid,
            clock_rate: self.tracks.get(tidx).spec.codec.clock_rate,
            pt_map: spec.pt_map,
            mid: spec.mid,
            sent_packets: 0,
            sent_octets: 0,
        });
        self.sessions.get_mut(idx).subs.push(sidx);
        self.tracks.get_mut(tidx).subscribers.push(sidx);
        self.sub_ids.insert(sub, sidx);
        if self.sessions.get(idx).srtp_out.is_some() {
            self.request_keyframe(tidx, now);
        }
        Ok(())
    }

    fn unsubscribe(&mut self, sub: SubscriptionId) -> Outcome {
        let sidx = self
            .sub_ids
            .get(&sub)
            .copied()
            .ok_or(RejectReason::UnknownSubscription)?;
        self.remove_subscription(sidx);
        Ok(())
    }

    /// Removes a subscription; its out SSRC is retired and never sent again.
    fn remove_subscription(&mut self, sidx: SubIdx) {
        let sub = self.subs.remove(sidx);
        let session = self.sessions.get_mut(sub.session);
        if let Some(outbound) = session.srtp_out.as_mut() {
            outbound.retire(sub.rewrite.out_ssrc);
        }
        // Order kept: InstallSrtp registers in offset order.
        let pos = session
            .subs
            .iter()
            .position(|s| *s == sidx)
            .expect("listed on session");
        session.subs.remove(pos);
        let fan_out = &mut self.tracks.get_mut(sub.track).subscribers;
        let pos = fan_out
            .iter()
            .position(|s| *s == sidx)
            .expect("listed on track");
        fan_out.swap_remove(pos);
        let removed = self.sub_ids.remove(&sub.id);
        assert!(removed == Some(sidx));
    }

    fn close_session(&mut self, id: SessionId) -> Outcome {
        let idx = self.session_idx(id)?;
        // Bounded: ≤ MAX_TRACKS_PER_SESSION and ≤ MAX_SUBS_PER_SESSION passes.
        loop {
            let session = self.sessions.get(idx);
            let next = session.published.as_slice().first().map(|(_, t)| *t);
            let Some(tidx) = next.or_else(|| session.unbound.as_slice().first().copied()) else {
                break;
            };
            self.remove_track(tidx);
        }
        while let Some(&sub) = self.sessions.get(idx).subs.last() {
            self.remove_subscription(sub);
        }
        self.pending_switches.retain(|&s| s != idx);
        let session = self.sessions.remove(idx);
        for addr in [session.addr, session.prev_addr].into_iter().flatten() {
            if self.by_addr.get(&addr) == Some(&idx) {
                self.by_addr.remove(&addr);
            }
        }
        let ufrag = self.by_ufrag.remove(&session.ice.local_ufrag);
        assert!(ufrag == Some(idx));
        self.session_ids.remove(&id);
        Ok(())
    }

    /// The id maps and slabs agree (debug builds: every command).
    fn check_tables(&self) {
        assert!(self.session_ids.len() == self.sessions.len());
        assert!(self.by_ufrag.len() == self.sessions.len());
        assert!(self.track_ids.len() == self.tracks.len());
        assert!(self.sub_ids.len() == self.subs.len());
        assert!(self.by_addr.len() <= 2 * self.sessions.len());
    }
}

/// The rewrite writes these ids in the one-byte form, one element per id:
/// every id ≤ 14, publisher id 0 unmapped, and no subscriber id used twice
/// (including by `mid`).
fn ext_map_is_valid(ext_map: &ExtMap) -> bool {
    let mut used = [false; 16];
    let targets = ext_map.map.iter().chain([&ext_map.mid]).copied();
    for id in targets.filter(|id| *id != 0) {
        if id > 14 || used[id as usize] {
            return false;
        }
        used[id as usize] = true;
    }
    ext_map.map[0] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_map_validation() {
        let mut map = ExtMap::default();
        assert!(ext_map_is_valid(&map));
        map.map[2] = 5;
        map.mid = 1;
        assert!(ext_map_is_valid(&map));
        map.map[3] = 5;
        assert!(
            !ext_map_is_valid(&map),
            "two publisher ids to one subscriber id"
        );
        map.map[3] = 1;
        assert!(!ext_map_is_valid(&map), "collides with mid");
        map.map[3] = 15;
        assert!(!ext_map_is_valid(&map), "not one-byte");
        map.map[3] = 0;
        map.map[0] = 4;
        assert!(!ext_map_is_valid(&map), "publisher id 0");
    }
}
