//! The SSRCs the SFU announces for the tracks it sends a client: the first
//! `a=ssrc` of every sendonly m-line of its latest offer, with the track id the
//! offer's `tracks` list gives that m-line. Tests compare what a client received
//! against them (the SFU rewrites SSRCs, so the publisher's are not what arrives).
//! Every m-line ever announced is also kept in a bounded history, so a test can
//! check that a resubscription arrives on a new SSRC.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nexus_signal::OfferTrack;

/// Most m-lines recorded per offer (the SFU's SDP limit is 32).
pub const MAX_ANNOUNCED: usize = 64;

/// Most m-lines kept in the history; later ones are counted, not kept.
pub const MAX_HISTORY: usize = 256;

/// One announced m-line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announced {
    /// The m-line's mid.
    pub mid: String,
    /// `audio` or `video` (the m-line's media type).
    pub kind: String,
    /// Track id from the offer's `tracks`, if listed.
    pub track_id: Option<u64>,
    /// First SSRC the m-line announces.
    pub ssrc: u32,
    /// The `cname:` of that SSRC's `a=ssrc` lines, if any.
    pub cname: Option<String>,
}

#[derive(Default)]
struct Inner {
    latest: HashMap<String, Announced>,
    /// Distinct (mid, SSRC) pairs in the order first announced.
    history: Vec<Announced>,
    history_overflow: u64,
}

/// Shared by a client and its signaling task; replaced on every offer.
#[derive(Clone, Default)]
pub struct AnnouncedSsrcs {
    inner: Arc<Mutex<Inner>>,
}

impl AnnouncedSsrcs {
    /// Replace the record with the sendonly m-lines of `sdp`, and add the new
    /// ones to the history. Returns the new record, sorted by SSRC.
    pub fn update(&self, sdp: &str, tracks: &[OfferTrack]) -> Vec<Announced> {
        let mut parsed = parse_sendonly_ssrcs(sdp);
        for a in &mut parsed {
            a.track_id = tracks.iter().find(|t| t.mid == a.mid).map(|t| t.track_id);
        }
        let mut inner = self.inner.lock().expect("announced lock");
        inner.latest.clear();
        for a in &parsed {
            let known = inner
                .history
                .iter()
                .any(|h| h.mid == a.mid && h.ssrc == a.ssrc);
            if !known && inner.history.len() < MAX_HISTORY {
                inner.history.push(a.clone());
            } else if !known {
                inner.history_overflow += 1;
            }
            inner.latest.insert(a.mid.clone(), a.clone());
        }
        assert!(inner.latest.len() <= MAX_ANNOUNCED);
        assert!(inner.history.len() <= MAX_HISTORY);
        parsed.sort_by_key(|a| a.ssrc);
        parsed
    }

    /// Every m-line of the latest offer, sorted by SSRC.
    pub fn snapshot(&self) -> Vec<Announced> {
        let inner = self.inner.lock().expect("announced lock");
        let mut all: Vec<Announced> = inner.latest.values().cloned().collect();
        all.sort_by_key(|a| a.ssrc);
        all
    }

    /// Every m-line announced so far, in the order first seen, and how many
    /// did not fit.
    pub fn history(&self) -> (Vec<Announced>, u64) {
        let inner = self.inner.lock().expect("announced lock");
        (inner.history.clone(), inner.history_overflow)
    }
}

/// Every sendonly m-line of `sdp` that has a mid and an SSRC, with its first
/// SSRC and that SSRC's CNAME (`track_id` is left `None`).
pub fn parse_sendonly_ssrcs(sdp: &str) -> Vec<Announced> {
    let mut found = Vec::new();
    // Text before the first m= is the session level.
    for section in sdp.split("\nm=").skip(1) {
        if found.len() >= MAX_ANNOUNCED {
            break;
        }
        let kind = section.split(' ').next().unwrap_or("").to_string();
        let mut mid = None;
        let mut ssrc = None;
        let mut cname = None;
        let mut sendonly = false;
        for line in section.lines().map(str::trim_end) {
            if line == "a=sendonly" {
                sendonly = true;
            } else if let Some(value) = line.strip_prefix("a=mid:") {
                mid = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("a=ssrc:") {
                let (number, attr) = value.split_once(' ').unwrap_or((value, ""));
                let Ok(number) = number.parse::<u32>() else {
                    continue;
                };
                let first = *ssrc.get_or_insert(number);
                if let (true, Some(name)) = (first == number, attr.strip_prefix("cname:")) {
                    cname.get_or_insert_with(|| name.to_string());
                }
            }
        }
        if let (true, Some(mid), Some(ssrc)) = (sendonly, mid, ssrc) {
            found.push(Announced {
                mid,
                kind,
                track_id: None,
                ssrc,
                cname,
            });
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
        m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=sendonly\r\na=ssrc:2222 msid:x y\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=inactive\r\na=mid:3\r\na=ssrc:3333 cname:x\r\n";

    fn brief(all: &[Announced]) -> Vec<(&str, &str, u32, Option<&str>)> {
        all.iter()
            .map(|a| (a.mid.as_str(), a.kind.as_str(), a.ssrc, a.cname.as_deref()))
            .collect()
    }

    #[test]
    fn sendonly_mlines_with_their_first_ssrc_and_cname() {
        assert_eq!(
            brief(&parse_sendonly_ssrcs(OFFER)),
            vec![
                ("1", "video", 1111, Some("nexus-3")),
                ("2", "audio", 2222, None)
            ]
        );
    }

    #[test]
    fn update_joins_track_ids_and_replaces() {
        let announced = AnnouncedSsrcs::default();
        let tracks = [OfferTrack {
            track_id: 9,
            mid: "1".to_string(),
        }];
        let returned = announced.update(OFFER, &tracks);
        let all = announced.snapshot();
        assert_eq!(returned, all);
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].track_id, all[0].ssrc), (Some(9), 1111));
        assert_eq!((all[1].track_id, all[1].ssrc), (None, 2222));
        assert_eq!(
            (all[0].kind.as_str(), all[1].kind.as_str()),
            ("video", "audio")
        );
        announced.update("v=0\r\n", &[]);
        assert!(announced.snapshot().is_empty());
    }

    #[test]
    fn history_keeps_every_ssrc_a_mid_had() {
        let announced = AnnouncedSsrcs::default();
        announced.update(OFFER, &[]);
        announced.update(OFFER, &[]);
        // The same mid on a new SSRC (a resubscription) is a new entry.
        announced.update(&OFFER.replace("1111", "1112"), &[]);
        let (history, overflow) = announced.history();
        assert_eq!(overflow, 0);
        let ssrcs: Vec<u32> = history.iter().map(|a| a.ssrc).collect();
        assert_eq!(ssrcs, vec![1111, 2222, 1112]);
        assert_eq!(announced.snapshot().len(), 2);
    }
}
