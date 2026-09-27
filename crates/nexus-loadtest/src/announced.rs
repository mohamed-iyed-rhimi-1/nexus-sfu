//! The SSRCs the SFU announces for the tracks it sends a client: the first
//! `a=ssrc` of every sendonly m-line of its latest offer, with the track id the
//! offer's `tracks` list gives that m-line. Tests compare what a client received
//! against them (the SFU rewrites SSRCs, so the publisher's are not what arrives).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nexus_signal::OfferTrack;

/// Most m-lines recorded per offer (the SFU's SDP limit is 32).
pub const MAX_ANNOUNCED: usize = 64;

/// One announced m-line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announced {
    /// The m-line's mid.
    pub mid: String,
    /// Track id from the offer's `tracks`, if listed.
    pub track_id: Option<u64>,
    /// First SSRC the m-line announces.
    pub ssrc: u32,
}

/// Shared by a client and its signaling task; replaced on every offer.
#[derive(Clone, Default)]
pub struct AnnouncedSsrcs {
    inner: Arc<Mutex<HashMap<String, Announced>>>,
}

impl AnnouncedSsrcs {
    /// Replace the record with the sendonly m-lines of `sdp`.
    pub fn update(&self, sdp: &str, tracks: &[OfferTrack]) {
        let parsed = parse_sendonly_ssrcs(sdp);
        let mut map = self.inner.lock().expect("announced lock");
        map.clear();
        for (mid, ssrc) in parsed {
            let track_id = tracks.iter().find(|t| t.mid == mid).map(|t| t.track_id);
            map.insert(
                mid.clone(),
                Announced {
                    mid,
                    track_id,
                    ssrc,
                },
            );
        }
        assert!(map.len() <= MAX_ANNOUNCED);
    }

    /// Every announced m-line, sorted by SSRC.
    pub fn snapshot(&self) -> Vec<Announced> {
        let map = self.inner.lock().expect("announced lock");
        let mut all: Vec<Announced> = map.values().cloned().collect();
        all.sort_by_key(|a| a.ssrc);
        all
    }
}

/// `(mid, first ssrc)` of every sendonly m-line of `sdp` that has both.
pub fn parse_sendonly_ssrcs(sdp: &str) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    // Text before the first m= is the session level.
    for section in sdp.split("\nm=").skip(1) {
        if found.len() >= MAX_ANNOUNCED {
            break;
        }
        let mut mid = None;
        let mut ssrc = None;
        let mut sendonly = false;
        for line in section.lines().map(str::trim_end) {
            if line == "a=sendonly" {
                sendonly = true;
            } else if let Some(value) = line.strip_prefix("a=mid:") {
                mid = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("a=ssrc:") {
                let number = value.split(' ').next().and_then(|n| n.parse::<u32>().ok());
                ssrc = ssrc.or(number);
            }
        }
        if let (true, Some(mid), Some(ssrc)) = (sendonly, mid, ssrc) {
            found.push((mid, ssrc));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
        m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=recvonly\r\na=mid:0\r\n\
        m=video 9 UDP/TLS/RTP/SAVPF 97\r\na=sendonly\r\na=mid:1\r\n\
        a=ssrc:1111 cname:nexus-3\r\na=ssrc:1111 msid:nexus-3 nexus-track-1\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=sendonly\r\na=ssrc:2222 cname:x\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=inactive\r\na=mid:3\r\na=ssrc:3333 cname:x\r\n";

    #[test]
    fn sendonly_mlines_with_their_first_ssrc() {
        assert_eq!(
            parse_sendonly_ssrcs(OFFER),
            vec![("1".to_string(), 1111), ("2".to_string(), 2222)]
        );
    }

    #[test]
    fn update_joins_track_ids_and_replaces() {
        let announced = AnnouncedSsrcs::default();
        let tracks = [OfferTrack {
            track_id: 9,
            mid: "1".to_string(),
        }];
        announced.update(OFFER, &tracks);
        let all = announced.snapshot();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].track_id, all[0].ssrc), (Some(9), 1111));
        assert_eq!((all[1].track_id, all[1].ssrc), (None, 2222));
        announced.update("v=0\r\n", &[]);
        assert!(announced.snapshot().is_empty());
    }
}
