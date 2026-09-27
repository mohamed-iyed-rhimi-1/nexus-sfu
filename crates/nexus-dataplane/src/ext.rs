//! RTP header extensions: the fixed ID table the SFU offers on every m-line
//! (note §11.2) and an allocation-free element iterator.
//!
//! The negotiator (1.4) takes its extmaps from `TABLE`.

use nexus_core::MediaKind;
use nexus_media::rtp::RtpHeader;

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

/// Most elements read from one packet.
pub const MAX_ELEMENTS: usize = 16;

/// Longest element the one-byte form can carry.
pub const MAX_ONE_BYTE_LEN: usize = 16;

/// One extension element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    /// Element ID.
    pub id: u8,
    /// Element data.
    pub data: &'a [u8],
}

/// Iterator over the extension elements of a packet, one-byte (`0xBEDE`)
/// or two-byte (`0x100X`) form, at most `MAX_ELEMENTS`.
pub struct Elements<'a> {
    block: &'a [u8],
    at: usize,
    two_byte: bool,
    seen: usize,
}

/// The elements of `packet` (parsed as `header`). Empty when X is clear or
/// the profile is neither form. `RtpHeader::parse` checked the block bounds.
pub fn elements<'a>(packet: &'a [u8], header: &RtpHeader) -> Elements<'a> {
    let empty = Elements {
        block: &[],
        at: 0,
        two_byte: false,
        seen: 0,
    };
    if !header.extension {
        return empty;
    }
    let start = 12 + 4 * header.csrc_count as usize;
    let end = header.header_len_bytes as usize;
    if end < start + 4 || end > packet.len() {
        return empty;
    }
    let profile = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let block = &packet[start + 4..end];
    match profile {
        0xBEDE => Elements {
            block,
            at: 0,
            two_byte: false,
            seen: 0,
        },
        p if p & 0xFFF0 == 0x1000 => Elements {
            block,
            at: 0,
            two_byte: true,
            seen: 0,
        },
        _ => empty,
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        if self.seen == MAX_ELEMENTS {
            return None;
        }
        // Padding between elements, bounded by the block length. In the
        // one-byte form any byte with ID 0 is one byte of padding, whatever
        // its length nibble (RFC 8285 §4.2 reserves ID 0; libwebrtc skips
        // it the same way).
        while let Some(&byte) = self.block.get(self.at) {
            let padding = if self.two_byte {
                byte == 0
            } else {
                byte >> 4 == 0
            };
            if !padding {
                break;
            }
            self.at += 1;
        }
        let first = *self.block.get(self.at)?;
        let (id, len, data_at) = if self.two_byte {
            (first, *self.block.get(self.at + 1)? as usize, self.at + 2)
        } else if first >> 4 == 15 {
            return None; // reserved ID: stop processing (RFC 8285 §4.2)
        } else {
            (first >> 4, (first & 0x0F) as usize + 1, self.at + 1)
        };
        let data = self.block.get(data_at..data_at + len)?;
        self.at = data_at + len;
        self.seen += 1;
        Some(Element { id, data })
    }
}

/// The data of element `id`, if present.
pub fn find<'a>(packet: &'a [u8], header: &RtpHeader, id: u8) -> Option<&'a [u8]> {
    if id == 0 {
        return None;
    }
    elements(packet, header)
        .find(|e| e.id == id)
        .map(|e| e.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_ext(profile: u16, ext: &[u8]) -> Vec<u8> {
        assert!(ext.len() % 4 == 0);
        let mut p = vec![0x90, 111, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2];
        p.extend_from_slice(&profile.to_be_bytes());
        p.extend_from_slice(&((ext.len() / 4) as u16).to_be_bytes());
        p.extend_from_slice(ext);
        p.extend_from_slice(b"payload");
        p
    }

    fn collect(p: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let h = RtpHeader::parse(p).unwrap();
        elements(p, &h).map(|e| (e.id, e.data.to_vec())).collect()
    }

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

    #[test]
    fn one_byte_form_with_padding() {
        let p = with_ext(0xBEDE, &[0x10, b'a', 0, 0x22, 1, 2, 3, 0]);
        assert_eq!(collect(&p), vec![(1, b"a".to_vec()), (2, vec![1, 2, 3])]);
        let h = RtpHeader::parse(&p).unwrap();
        assert_eq!(find(&p, &h, 2), Some(&[1u8, 2, 3][..]));
        assert_eq!(find(&p, &h, 3), None);
        assert_eq!(find(&p, &h, 0), None);
    }

    #[test]
    fn two_byte_form() {
        let p = with_ext(0x1000, &[1, 1, b'a', 0, 20, 2, 7, 8]);
        assert_eq!(collect(&p), vec![(1, b"a".to_vec()), (20, vec![7, 8])]);
    }

    #[test]
    fn id_15_stops_and_overrun_ends() {
        let p = with_ext(0xBEDE, &[0x10, b'a', 0xF0, 0x10]);
        assert_eq!(collect(&p), vec![(1, b"a".to_vec())]);
        // Element claims 16 bytes in a 4-byte block.
        let p = with_ext(0xBEDE, &[0x1F, 0, 0, 0]);
        assert_eq!(collect(&p), vec![]);
        // One-byte form: an ID-0 byte is padding even with a length nibble.
        let p = with_ext(0xBEDE, &[0x05, 0x10, b'a', 0]);
        assert_eq!(collect(&p), vec![(1, b"a".to_vec())]);
        // Unknown profile: no elements.
        let p = with_ext(0x1234, &[0x10, b'a', 0, 0]);
        assert_eq!(collect(&p), vec![]);
    }

    #[test]
    fn at_most_sixteen_elements() {
        let ext: Vec<u8> = (0..20).flat_map(|_| [0x10u8, 9]).collect();
        let p = with_ext(0xBEDE, &ext);
        assert_eq!(collect(&p).len(), MAX_ELEMENTS);
    }
}
