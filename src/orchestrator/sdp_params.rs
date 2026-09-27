//! Data-plane parameters from SDP answers (design note §6.1, §6.2, §11).
//!
//! Pure functions over parsed m-lines: `track_spec` reads a publisher's answered
//! publish m-line into a `TrackSpec` (`AddTrack`), `sub_spec` reads a subscriber's
//! answered subscribe m-line into a `SubSpec` (`Subscribe`). Mappings are built from the
//! answers, never assumed: an answer can decline or renumber an extension.

use nexus_core::MediaKind;
use nexus_dataplane::{
    CnameValue, CodecParams, ExtIds, ExtMap, MidValue, PtMap, SubSpec, TrackRef, TrackSpec,
};
use nexus_media::rtp::extensions;
use nexus_webrtc::sdp::{Direction, MediaDescription, MediaType, SsrcGroup};

/// Largest extension id the one-byte header form carries (15 is reserved).
pub const MAX_ONE_BYTE_EXT_ID: u8 = 14;

/// A codec by name and clock rate (how answers are matched, note §11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecId {
    /// `rtpmap` encoding name, compared case-insensitively.
    pub name: &'static str,
    /// RTP clock rate.
    pub clock_rate: u32,
}

/// The v1 audio codec (the one publish m-lines offer).
pub const OPUS: CodecId = CodecId {
    name: "opus",
    clock_rate: 48_000,
};
/// The v1 video codec.
pub const VP8: CodecId = CodecId {
    name: "VP8",
    clock_rate: 90_000,
};

/// The v1 codec of a kind.
pub fn v1_codec(kind: MediaKind) -> CodecId {
    match kind {
        MediaKind::Audio => OPUS,
        MediaKind::Video => VP8,
    }
}

/// Why an m-line could not be turned into a spec.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    /// Not an audio or video m-line.
    #[error("m-line is neither audio nor video")]
    UnsupportedMedia,
    /// The m-line has no usable `a=mid`.
    #[error("m-line has no mid of at most 16 bytes")]
    MissingMid,
    /// The answer does not contain the codec the SFU forwards.
    #[error("answer has no {0} codec")]
    NoCommonCodec(&'static str),
    /// A forwarded extension has an id the one-byte form cannot carry.
    #[error("extension {uri} has id {id} (> 14)")]
    ExtIdOutOfRange {
        /// Extension URI.
        uri: &'static str,
        /// The answer's id.
        id: u8,
    },
    /// Two used extensions share one id.
    #[error("extension id {0} used twice")]
    DuplicateExtId(u8),
    /// No `a=ssrc` and no mid extension: the shard could not find the stream.
    #[error("publish m-line has neither a=ssrc nor the mid extension")]
    NoSsrcSource,
    /// The CNAME given for the track is empty or longer than 255 bytes.
    #[error("no usable CNAME")]
    InvalidCname,
    /// The m-line announces a simulcast group (`a=ssrc-group:SIM`); v1 forwards one
    /// stream per m-line.
    #[error("simulcast (a=ssrc-group:SIM) is not supported")]
    Simulcast,
    /// A subscribe m-line of another kind than the track.
    #[error("m-line kind does not match the track")]
    KindMismatch,
}

/// The publisher's answered publish m-line as a `TrackSpec`. `Ok(None)` if the
/// publisher declined it (port 0) or does not send on it.
///
/// `cname` is the SFU's CNAME for the publisher (`nexus-{publisher}`, note §6.5), not
/// the publisher's own: it goes into the subscribers' offers and the translated SDES,
/// and a participant's CNAME is never shown to other participants.
pub fn track_spec(
    media: &MediaDescription,
    cname: &[u8],
) -> Result<Option<TrackSpec>, ParamsError> {
    if media.port == 0 || !matches!(media.direction, Direction::SendOnly | Direction::SendRecv) {
        return Ok(None);
    }
    let kind = kind_of(media)?;
    if has_simulcast_group(media) {
        return Err(ParamsError::Simulcast);
    }
    let codec = v1_codec(kind);
    let pt = find_pt(media, codec)?;
    let ext = ext_ids(media, kind)?;
    let ssrc = primary_ssrc(media);
    if ssrc.is_none() && ext.mid == 0 {
        return Err(ParamsError::NoSsrcSource);
    }
    let spec = TrackSpec {
        kind,
        mid: mid_of(media)?,
        ssrc,
        codec: CodecParams {
            pt,
            clock_rate: codec.clock_rate,
        },
        ext,
        cname: CnameValue::new(cname).ok_or(ParamsError::InvalidCname)?,
    };
    assert!(spec.codec.pt <= 127);
    Ok(Some(spec))
}

/// A subscriber's answered subscribe m-line for `track` as a `SubSpec`. `Ok(None)` if
/// the subscriber declined it (port 0) or does not receive on it (inactive).
pub fn sub_spec(
    media: &MediaDescription,
    track: &TrackSpec,
    out_ssrc: u32,
    source: TrackRef,
) -> Result<Option<SubSpec>, ParamsError> {
    if media.port == 0 || !matches!(media.direction, Direction::RecvOnly | Direction::SendRecv) {
        return Ok(None);
    }
    if kind_of(media)? != track.kind {
        return Err(ParamsError::KindMismatch);
    }
    let codec = CodecId {
        clock_rate: track.codec.clock_rate,
        ..v1_codec(track.kind)
    };
    let sub_pt = find_pt(media, codec)?;
    let pt_map = PtMap::new(&[(track.codec.pt, sub_pt)]).expect("7-bit PTs, one pair");
    let sub = ext_ids(media, track.kind)?;
    let ext_map = ext_map(&track.ext, &sub);
    let spec = SubSpec {
        out_ssrc,
        mid: mid_of(media)?,
        pt_map,
        ext_map,
        source,
    };
    assert_eq!(spec.pt_map.map(track.codec.pt), Some(sub_pt));
    Ok(Some(spec))
}

/// Publisher id → subscriber id for the forwarded extensions (audio level, video
/// orientation); the publisher's `mid` element is always dropped and the subscriber's
/// written (note §11.2). `ext_ids` already refused ids > 14 and duplicates.
fn ext_map(publisher: &ExtIds, subscriber: &ExtIds) -> ExtMap {
    let mut map = ExtMap {
        map: [0; 15],
        mid: subscriber.mid,
    };
    for (from, to) in [
        (publisher.audio_level, subscriber.audio_level),
        (publisher.video_orientation, subscriber.video_orientation),
    ] {
        if from != 0 && from != publisher.mid {
            map.map[from as usize] = to;
        }
    }
    debug_assert_eq!(map.map[0], 0);
    map
}

fn kind_of(media: &MediaDescription) -> Result<MediaKind, ParamsError> {
    match media.media_type {
        MediaType::Audio => Ok(MediaKind::Audio),
        MediaType::Video => Ok(MediaKind::Video),
        MediaType::Application => Err(ParamsError::UnsupportedMedia),
    }
}

fn mid_of(media: &MediaDescription) -> Result<MidValue, ParamsError> {
    let mid = media.mid.as_ref().ok_or(ParamsError::MissingMid)?;
    MidValue::new(mid.as_str().as_bytes()).ok_or(ParamsError::MissingMid)
}

/// The m-line's PT for `codec` (first match in answer order).
fn find_pt(media: &MediaDescription, codec: CodecId) -> Result<u8, ParamsError> {
    media
        .codecs
        .iter()
        .take(media.codec_count as usize)
        .flatten()
        .find(|c| c.name_str().eq_ignore_ascii_case(codec.name) && c.clock_rate == codec.clock_rate)
        .map(|c| c.payload_type)
        .filter(|&pt| pt <= 127)
        .ok_or(ParamsError::NoCommonCodec(codec.name))
}

/// The answer's ids for the table's extensions that apply to `kind` (0: declined).
fn ext_ids(media: &MediaDescription, kind: MediaKind) -> Result<ExtIds, ParamsError> {
    let mut ids = ExtIds::default();
    let wanted = [
        (extensions::MID, true),
        (extensions::AUDIO_LEVEL, kind == MediaKind::Audio),
        (extensions::VIDEO_ORIENTATION, kind == MediaKind::Video),
    ];
    for (table_id, applies) in wanted {
        if !applies {
            continue;
        }
        let uri = extensions::TABLE
            .iter()
            .find(|e| e.id == table_id)
            .expect("table entry")
            .uri;
        let Some(id) = extmap_id(media, uri) else {
            continue;
        };
        if id > MAX_ONE_BYTE_EXT_ID {
            return Err(ParamsError::ExtIdOutOfRange { uri, id });
        }
        if [ids.mid, ids.audio_level, ids.video_orientation].contains(&id) {
            return Err(ParamsError::DuplicateExtId(id));
        }
        match table_id {
            extensions::MID => ids.mid = id,
            extensions::AUDIO_LEVEL => ids.audio_level = id,
            _ => ids.video_orientation = id,
        }
    }
    Ok(ids)
}

fn extmap_id(media: &MediaDescription, uri: &str) -> Option<u8> {
    media
        .extmaps
        .iter()
        .take(media.extmap_count as usize)
        .flatten()
        .find(|e| e.uri_str() == uri)
        .map(|e| e.id)
}

fn ssrc_groups(media: &MediaDescription) -> impl Iterator<Item = &SsrcGroup> {
    media
        .ssrc_groups
        .iter()
        .take(media.ssrc_group_count as usize)
        .flatten()
}

fn has_simulcast_group(media: &MediaDescription) -> bool {
    ssrc_groups(media).any(|g| g.semantics_str().eq_ignore_ascii_case("SIM"))
}

/// The track's SSRC: the first `a=ssrc` that is not a later member of an
/// `a=ssrc-group` (FID's RTX SSRC; SIM groups are refused before). `None` without
/// `a=ssrc`.
fn primary_ssrc(media: &MediaDescription) -> Option<u32> {
    let secondaries: Vec<u32> = ssrc_groups(media)
        .flat_map(|g| g.ssrc_list().iter().skip(1).copied())
        .collect();
    media
        .ssrc_values
        .iter()
        .take(media.ssrc_values_count as usize)
        .copied()
        .find(|ssrc| *ssrc != 0 && !secondaries.contains(ssrc))
}

#[cfg(test)]
#[path = "sdp_params_tests.rs"]
mod tests;
