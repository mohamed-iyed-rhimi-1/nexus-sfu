//! What a client receives over RTCP, for the e2e tests: keyframe requests
//! (PLI, FIR) reaching a publisher, and sender reports and CNAMEs reaching a
//! subscriber. Bounded; entries past the bounds are counted, not kept.

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use webrtc::rtcp::packet::Packet;
use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use webrtc::rtcp::sender_report::SenderReport;
use webrtc::rtcp::source_description::{SdesType, SourceDescription};

use crate::track_stats::{LastPacket, TrackStatsMap};

/// Most entries of each kind kept.
pub const MAX_ENTRIES: usize = 4096;

/// A PLI or FIR entry for one media SSRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyframeRequest {
    pub media_ssrc: u32,
    /// FIR (else PLI).
    pub fir: bool,
    pub at: Instant,
}

/// A received sender report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReportRx {
    pub ssrc: u32,
    /// 64-bit NTP timestamp (seconds since 1900 in the high word).
    pub ntp_time: u64,
    pub rtp_time: u32,
    pub packet_count: u32,
    pub at: SystemTime,
    /// The last media packet received on `ssrc` when the report arrived, if the
    /// reader was given the receive stats (`record_with_media`).
    pub last_packet: Option<LastPacket>,
}

#[derive(Debug, Default)]
struct Inner {
    keyframe_requests: Vec<KeyframeRequest>,
    sender_reports: Vec<SenderReportRx>,
    /// (SSRC, CNAME), each pair once.
    cnames: Vec<(u32, String)>,
    overflow: u64,
}

/// Shared between a client and its RTCP reader tasks.
#[derive(Clone, Debug, Default)]
pub struct RtcpLog {
    inner: Arc<Mutex<Inner>>,
}

impl RtcpLog {
    /// Record what matters in one compound packet read from a sender or receiver.
    pub fn record(&self, packets: &[Box<dyn Packet + Send + Sync>]) {
        self.record_with_media(packets, None);
    }

    /// As `record`; each sender report also gets the last media packet `media`
    /// holds for its SSRC at this moment, so its error can be measured against
    /// the packet that was current when it arrived.
    pub fn record_with_media(
        &self,
        packets: &[Box<dyn Packet + Send + Sync>],
        media: Option<&TrackStatsMap>,
    ) {
        let (now, wall) = (Instant::now(), SystemTime::now());
        // Before taking the log lock: the two locks are never held together.
        let last: Vec<(u32, Option<LastPacket>)> = packets
            .iter()
            .filter_map(|p| p.as_any().downcast_ref::<SenderReport>())
            .map(|sr| (sr.ssrc, media.and_then(|m| m.last_packet(sr.ssrc))))
            .collect();
        let mut inner = self.inner.lock().expect("rtcp log lock");
        for packet in packets {
            let any = packet.as_any();
            if let Some(pli) = any.downcast_ref::<PictureLossIndication>() {
                inner.push_request(pli.media_ssrc, false, now);
            } else if let Some(fir) = any.downcast_ref::<FullIntraRequest>() {
                for entry in &fir.fir {
                    inner.push_request(entry.ssrc, true, now);
                }
            } else if let Some(sr) = any.downcast_ref::<SenderReport>() {
                inner.push_report(SenderReportRx {
                    ssrc: sr.ssrc,
                    ntp_time: sr.ntp_time,
                    rtp_time: sr.rtp_time,
                    packet_count: sr.packet_count,
                    at: wall,
                    last_packet: last
                        .iter()
                        .find(|(ssrc, _)| *ssrc == sr.ssrc)
                        .and_then(|(_, p)| *p),
                });
            } else if let Some(sdes) = any.downcast_ref::<SourceDescription>() {
                for chunk in &sdes.chunks {
                    let cname = chunk
                        .items
                        .iter()
                        .find(|i| i.sdes_type == SdesType::SdesCname);
                    if let Some(item) = cname {
                        let text = String::from_utf8_lossy(&item.text).into_owned();
                        inner.push_cname(chunk.source, text);
                    }
                }
            }
        }
    }

    /// Keyframe requests (PLI and FIR) received so far, in arrival order.
    pub fn keyframe_requests(&self) -> Vec<KeyframeRequest> {
        self.inner
            .lock()
            .expect("rtcp log lock")
            .keyframe_requests
            .clone()
    }

    /// Sender reports received so far, in arrival order.
    pub fn sender_reports(&self) -> Vec<SenderReportRx> {
        self.inner
            .lock()
            .expect("rtcp log lock")
            .sender_reports
            .clone()
    }

    /// Every (SSRC, CNAME) pair received in SDES.
    pub fn cnames(&self) -> Vec<(u32, String)> {
        self.inner.lock().expect("rtcp log lock").cnames.clone()
    }

    /// Entries not kept because a table was full.
    pub fn overflow(&self) -> u64 {
        self.inner.lock().expect("rtcp log lock").overflow
    }
}

impl Inner {
    fn push_request(&mut self, media_ssrc: u32, fir: bool, at: Instant) {
        if self.keyframe_requests.len() >= MAX_ENTRIES {
            self.overflow += 1;
            return;
        }
        self.keyframe_requests.push(KeyframeRequest {
            media_ssrc,
            fir,
            at,
        });
    }

    fn push_report(&mut self, report: SenderReportRx) {
        if self.sender_reports.len() >= MAX_ENTRIES {
            self.overflow += 1;
            return;
        }
        self.sender_reports.push(report);
    }

    fn push_cname(&mut self, ssrc: u32, cname: String) {
        if self.cnames.iter().any(|(s, c)| *s == ssrc && *c == cname) {
            return;
        }
        if self.cnames.len() >= MAX_ENTRIES {
            self.overflow += 1;
            return;
        }
        self.cnames.push((ssrc, cname));
    }
}

/// Converts a 64-bit NTP timestamp to wall-clock time.
pub fn ntp_to_system_time(ntp: u64) -> SystemTime {
    /// Seconds from 1900-01-01 (NTP epoch) to 1970-01-01.
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
    let secs = (ntp >> 32).saturating_sub(NTP_UNIX_OFFSET);
    let nanos = ((ntp & 0xFFFF_FFFF) * 1_000_000_000) >> 32;
    SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, nanos as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc::rtcp::payload_feedbacks::full_intra_request::FirEntry;
    use webrtc::rtcp::source_description::{SourceDescriptionChunk, SourceDescriptionItem};

    #[test]
    fn records_requests_reports_and_cnames() {
        let log = RtcpLog::default();
        let sdes = SourceDescription {
            chunks: vec![SourceDescriptionChunk {
                source: 7,
                items: vec![SourceDescriptionItem {
                    sdes_type: SdesType::SdesCname,
                    text: "nexus-1".into(),
                }],
            }],
        };
        let packets: Vec<Box<dyn Packet + Send + Sync>> = vec![
            Box::new(PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: 5,
            }),
            Box::new(FullIntraRequest {
                sender_ssrc: 1,
                media_ssrc: 0,
                fir: vec![FirEntry {
                    ssrc: 6,
                    sequence_number: 1,
                }],
            }),
            Box::new(SenderReport {
                ssrc: 7,
                ntp_time: 1 << 32,
                rtp_time: 90,
                packet_count: 3,
                ..Default::default()
            }),
            Box::new(sdes.clone()),
            Box::new(sdes),
        ];
        log.record(&packets);
        let requests = log.keyframe_requests();
        let brief: Vec<(u32, bool)> = requests.iter().map(|r| (r.media_ssrc, r.fir)).collect();
        assert_eq!(brief, vec![(5, false), (6, true)]);
        let reports = log.sender_reports();
        assert_eq!(
            (reports.len(), reports[0].ssrc, reports[0].rtp_time),
            (1, 7, 90)
        );
        assert_eq!(log.cnames(), vec![(7, "nexus-1".to_string())]);
        assert_eq!(log.overflow(), 0);
    }

    #[test]
    fn sender_reports_carry_the_last_packet_when_given_media() {
        let media = TrackStatsMap::default();
        media.record(7, "video", "video/VP8", 10, 9_000);
        media.record(7, "video", "video/VP8", 12, 15_000);
        media.record(7, "video", "video/VP8", 11, 12_000); // reordered: not the last
        let log = RtcpLog::default();
        let sr = |ssrc| -> Vec<Box<dyn Packet + Send + Sync>> {
            vec![Box::new(SenderReport {
                ssrc,
                ..Default::default()
            })]
        };
        log.record_with_media(&sr(7), Some(&media));
        log.record_with_media(&sr(8), Some(&media));
        log.record(&sr(7));
        let reports = log.sender_reports();
        let last = reports[0].last_packet.expect("media on 7");
        assert_eq!(last.rtp_timestamp, 15_000);
        assert!(last.arrival <= reports[0].at);
        assert_eq!(reports[1].last_packet, None, "no media on 8");
        assert_eq!(reports[2].last_packet, None, "record: no media given");
    }

    #[test]
    fn ntp_converts_to_unix_time() {
        let unix = 1_700_000_000u64;
        let ntp = ((unix + 2_208_988_800) << 32) | (1 << 31); // + 0.5 s
        let t = ntp_to_system_time(ntp);
        let since = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(since.as_secs(), unix);
        assert_eq!(since.subsec_millis(), 500);
    }
}
