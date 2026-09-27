//! The control-plane interface (note §5): commands in, events out.

use std::net::SocketAddr;

use nexus_core::MediaKind;
use nexus_transport::srtp::KeyMaterial;

use crate::ids::{CnameValue, MidValue, SessionId, SubscriptionId, TrackId, TrackRef};

/// Control plane → shard. Large payloads are boxed so the queue slots stay
/// small; allocation is fine here (control path, freed on the shard).
pub enum Command {
    /// A participant transport placed on this shard.
    CreateSession {
        /// Session id.
        id: SessionId,
        /// Local ICE credentials the peer's binding requests must use.
        ice: IceParams,
        /// Base of the session's outbound SSRCs (note §9.3). The session's
        /// RTCP sender SSRC is the base itself (offset 0).
        out_ssrc_base: u32,
    },
    /// Send DTLS records to the session's selected address.
    SendDatagram {
        /// Session id.
        id: SessionId,
        /// One datagram.
        bytes: Box<[u8]>,
    },
    /// DTLS completed: install both SRTP directions. Only once per session.
    InstallSrtp {
        /// Session id.
        id: SessionId,
        /// Key material by direction.
        keys: Box<SrtpInstall>,
    },
    /// A publish m-line of the session.
    AddTrack {
        /// Publisher session.
        id: SessionId,
        /// Track id.
        track: TrackId,
        /// What the publisher's answer said about the m-line.
        spec: Box<TrackSpec>,
    },
    /// Remove a track and every subscription to it.
    RemoveTrack {
        /// Track id.
        track: TrackId,
    },
    /// A subscribe m-line of the session was answered.
    Subscribe {
        /// Subscriber session.
        id: SessionId,
        /// Subscription id.
        sub: SubscriptionId,
        /// The track subscribed to.
        track: TrackId,
        /// Rewrite parameters from both answers.
        spec: Box<SubSpec>,
    },
    /// End a subscription; its outbound SSRC is retired for good.
    Unsubscribe {
        /// Subscription id.
        sub: SubscriptionId,
    },
    /// Remove the session, its tracks (and subscriptions to them) and its
    /// own subscriptions.
    CloseSession {
        /// Session id.
        id: SessionId,
    },
}

/// Key material of both directions, picked by DTLS role (note §9.2).
pub struct SrtpInstall {
    /// Our write key: protects what the shard sends to the peer.
    pub local: KeyMaterial,
    /// The peer's write key: unprotects what it sends.
    pub remote: KeyMaterial,
}

/// Local ICE credentials, fixed size (no `String`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IceParams {
    /// Local username fragment (16 characters).
    pub local_ufrag: [u8; 16],
    /// Local password (32 characters); the MESSAGE-INTEGRITY key.
    pub local_pwd: [u8; 32],
}

/// The publisher's codec on a track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecParams {
    /// Payload type in the publisher's answer.
    pub pt: u8,
    /// RTP clock rate.
    pub clock_rate: u32,
}

/// Header extension ids the publisher's answer accepted (0 = declined).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtIds {
    /// `urn:ietf:params:rtp-hdrext:sdes:mid` (SSRC learning; always stripped).
    pub mid: u8,
    /// `urn:ietf:params:rtp-hdrext:ssrc-audio-level`.
    pub audio_level: u8,
    /// `urn:3gpp:video-orientation`.
    pub video_orientation: u8,
}

/// A publish m-line as the publisher's answer described it.
#[derive(Clone, Copy, Debug)]
pub struct TrackSpec {
    /// Audio or video.
    pub kind: MediaKind,
    /// The m-line's mid.
    pub mid: MidValue,
    /// Primary SSRC from `a=ssrc`; `None`: learned from the mid extension.
    pub ssrc: Option<u32>,
    /// Codec.
    pub codec: CodecParams,
    /// Extension ids.
    pub ext: ExtIds,
    /// CNAME used in translated SRs.
    pub cname: CnameValue,
}

/// Publisher PT → subscriber PT, up to two pairs (codec, later RTX).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PtMap {
    pairs: [(u8, u8); 2],
    len: u8,
}

impl PtMap {
    /// Most pairs a map holds.
    pub const CAPACITY: usize = 2;

    /// Builds a map; `None` if there are more than two pairs, a PT is not a
    /// 7-bit value, or a publisher PT repeats.
    pub fn new(pairs: &[(u8, u8)]) -> Option<Self> {
        if pairs.len() > Self::CAPACITY {
            return None;
        }
        let mut map = Self::default();
        for &(from, to) in pairs {
            if from > 127 || to > 127 || map.map(from).is_some() {
                return None;
            }
            map.pairs[map.len as usize] = (from, to);
            map.len += 1;
        }
        Some(map)
    }

    /// The subscriber PT for a publisher PT.
    pub fn map(&self, pt: u8) -> Option<u8> {
        self.pairs[..self.len as usize]
            .iter()
            .find(|(from, _)| *from == pt)
            .map(|(_, to)| *to)
    }
}

/// Publisher one-byte extension id → subscriber id (note §11.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtMap {
    /// Index = publisher id (1-14), value = subscriber id or 0 to drop.
    pub map: [u8; 15],
    /// The subscriber's id for `mid` (0: its answer declined it).
    pub mid: u8,
}

/// A subscribe m-line, as both answers described it.
#[derive(Clone, Copy, Debug)]
pub struct SubSpec {
    /// The SFU-chosen SSRC announced in the subscriber's SDP.
    pub out_ssrc: u32,
    /// The subscriber m-line's mid.
    pub mid: MidValue,
    /// Payload type mapping.
    pub pt_map: PtMap,
    /// Header extension mapping.
    pub ext_map: ExtMap,
    /// The track's shard and id.
    pub source: TrackRef,
}

/// Shard → control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A DTLS datagram from the session's peer (until `PeerSrtpVerified`).
    DtlsDatagram {
        /// Session id.
        id: SessionId,
        /// The datagram.
        bytes: Box<[u8]>,
    },
    /// The session's selected address changed.
    AddressSelected {
        /// Session id.
        id: SessionId,
        /// New address.
        addr: SocketAddr,
        /// Why.
        reason: SelectReason,
    },
    /// First authenticated SRTP or SRTCP from the peer: DTLS state can go.
    PeerSrtpVerified {
        /// Session id.
        id: SessionId,
    },
    /// No authenticated traffic for the consent timeout.
    ConsentLost {
        /// Session id.
        id: SessionId,
    },
    /// A command could not be applied; nothing changed.
    CommandRejected {
        /// The command's session, when it names one.
        id: Option<SessionId>,
        /// Why.
        reason: RejectReason,
    },
}

/// Why a session's address was selected (note §8.3, §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectReason {
    /// A binding request with USE-CANDIDATE.
    Nominated,
    /// NAT rebinding: the old address was silent for `rebind_silence`.
    Rebound,
}

/// Why a command was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// No such session.
    UnknownSession,
    /// No such track.
    UnknownTrack,
    /// No such subscription.
    UnknownSubscription,
    /// The id (or ICE ufrag) is already in use.
    DuplicateId,
    /// The shard holds `max_sessions` sessions.
    SessionLimit,
    /// The session publishes the most tracks it may.
    TrackLimit,
    /// The session holds the most subscriptions it may.
    SubscriptionLimit,
    /// `InstallSrtp` for a session that has SRTP.
    SrtpAlreadyInstalled,
    /// SRTP contexts could not be built or updated.
    SrtpSetup,
    /// The out SSRC is not above every earlier one of the session (note §9.3).
    OutSsrcNotMonotonic,
    /// Another track of the session has this SSRC.
    SsrcInUse,
    /// The track lives on another shard (Phase 2).
    WrongShard,
    /// An extension id in the spec does not fit the one-byte form (> 14).
    InvalidSpec,
}

/// Where a shard puts its events. Implemented for a tokio sender in 1.3;
/// tests use a `Vec`.
pub trait EventSink {
    /// Hands the event over without blocking; gives it back when full.
    fn try_send(&mut self, event: Event) -> Result<(), Event>;
}

impl EventSink for Vec<Event> {
    fn try_send(&mut self, event: Event) -> Result<(), Event> {
        self.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_stays_small() {
        // The largest inline variant is CreateSession (48 bytes of ICE
        // credentials); everything bigger is boxed.
        assert!(std::mem::size_of::<Command>() <= 72);
    }

    #[test]
    fn pt_map_rules() {
        let map = PtMap::new(&[(111, 100), (96, 97)]).unwrap();
        assert_eq!(map.map(111), Some(100));
        assert_eq!(map.map(96), Some(97));
        assert_eq!(map.map(0), None);
        assert!(PtMap::new(&[(1, 2), (3, 4), (5, 6)]).is_none());
        assert!(PtMap::new(&[(1, 2), (1, 3)]).is_none());
        assert!(PtMap::new(&[(128, 2)]).is_none());
    }
}
