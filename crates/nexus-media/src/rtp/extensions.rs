//! RTP header extensions: the fixed ID table the SFU offers on every m-line
//! (design note §11.2).
//!
//! One definition, shared by the SDP negotiator (`nexus-webrtc`, which offers it) and
//! the data plane (`nexus-dataplane`, which reads and rewrites the elements).

use nexus_core::MediaKind;

/// `urn:ietf:params:rtp-hdrext:sdes:mid`.
pub const MID: u8 = 1;
/// `urn:ietf:params:rtp-hdrext:ssrc-audio-level`.
pub const AUDIO_LEVEL: u8 = 2;
/// `urn:3gpp:video-orientation`.
pub const VIDEO_ORIENTATION: u8 = 3;
/// Transport-wide congestion control (publish m-lines from Phase 3).
pub const TRANSPORT_CC: u8 = 4;
/// Absolute send time (reserved, not offered).
pub const ABS_SEND_TIME: u8 = 5;
/// RID (reserved for simulcast).
pub const RTP_STREAM_ID: u8 = 10;
/// Repaired RID (reserved for simulcast + RTX).
pub const REPAIRED_RTP_STREAM_ID: u8 = 11;

/// One entry of the fixed table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The one-byte ID the SFU offers.
    pub id: u8,
    /// Extension URI.
    pub uri: &'static str,
    /// Offered on audio m-lines.
    pub audio: bool,
    /// Offered on video m-lines.
    pub video: bool,
    /// Offered in Phase 1.
    pub offered: bool,
}

/// The fixed table (note §11.2). IDs are ≤ 14, so the one-byte form fits.
pub const TABLE: [Extension; 7] = [
    Extension {
        id: MID,
        uri: "urn:ietf:params:rtp-hdrext:sdes:mid",
        audio: true,
        video: true,
        offered: true,
    },
    Extension {
        id: AUDIO_LEVEL,
        uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
        audio: true,
        video: false,
        offered: true,
    },
    Extension {
        id: VIDEO_ORIENTATION,
        uri: "urn:3gpp:video-orientation",
        audio: false,
        video: true,
        offered: true,
    },
    Extension {
        id: TRANSPORT_CC,
        uri: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        audio: true,
        video: true,
        offered: false,
    },
    Extension {
        id: ABS_SEND_TIME,
        uri: "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
        audio: false,
        video: true,
        offered: false,
    },
    Extension {
        id: RTP_STREAM_ID,
        uri: "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        audio: false,
        video: true,
        offered: false,
    },
    Extension {
        id: REPAIRED_RTP_STREAM_ID,
        uri: "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
        audio: false,
        video: true,
        offered: false,
    },
];

/// Entries offered on an m-line of `kind` in Phase 1.
pub fn offered(kind: MediaKind) -> impl Iterator<Item = &'static Extension> {
    TABLE.iter().filter(move |e| {
        e.offered
            && match kind {
                MediaKind::Audio => e.audio,
                MediaKind::Video => e.video,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_ids_are_unique_and_one_byte() {
        for (i, a) in TABLE.iter().enumerate() {
            assert!((1..=14).contains(&a.id));
            assert!(TABLE[i + 1..].iter().all(|b| b.id != a.id));
        }
        let audio: Vec<u8> = offered(MediaKind::Audio).map(|e| e.id).collect();
        let video: Vec<u8> = offered(MediaKind::Video).map(|e| e.id).collect();
        assert_eq!(audio, vec![MID, AUDIO_LEVEL]);
        assert_eq!(video, vec![MID, VIDEO_ORIENTATION]);
    }
}
