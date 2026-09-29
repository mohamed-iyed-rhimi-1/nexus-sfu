//! Tests for `sdp_params`, on answers shaped like Chrome's, Firefox's and webrtc-rs's
//! (reduced to the lines the functions read, plus the session lines the parser needs).

use super::*;
use nexus_dataplane::{ShardId, TrackId};
use nexus_webrtc::sdp::{SdpParser, SessionDescription};

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const ORIENT_URI: &str = "urn:3gpp:video-orientation";

fn parse(media: &str) -> SessionDescription {
    let fp = ["AB"; 32].join(":");
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
         a=ice-ufrag:testufrag\r\na=ice-pwd:testpwd12345678901234567890\r\n\
         a=fingerprint:sha-256 {fp}\r\na=setup:active\r\n{media}"
    );
    SdpParser::parse(&sdp).unwrap()
}

/// Chrome answering the SFU's publish offer: audio, then video with an RTX FID group.
fn chrome_publish() -> SessionDescription {
    parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
         a=extmap:1 {MID_URI}\r\na=extmap:2 {LEVEL_URI}\r\n\
         a=ssrc:1111 cname:chromecname\r\na=ssrc:1111 msid:stream audio-track\r\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:1\r\na=sendonly\r\n\
         a=rtpmap:96 VP8/90000\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\n\
         a=extmap:1 {MID_URI}\r\na=extmap:3 {ORIENT_URI}\r\n\
         a=ssrc-group:FID 2223 2222\r\n\
         a=ssrc:2223 cname:chromecname\r\na=ssrc:2222 cname:chromecname\r\n"
    ))
}

#[test]
fn chrome_publish_answer() {
    let sdp = chrome_publish();
    let audio = track_spec(&sdp.media[0], b"nexus-7").unwrap().unwrap();
    assert_eq!(audio.kind, MediaKind::Audio);
    assert_eq!(audio.mid.as_bytes(), b"0");
    assert_eq!(audio.ssrc, Some(1111));
    assert_eq!((audio.codec.pt, audio.codec.clock_rate), (111, 48_000));
    assert_eq!(
        (
            audio.ext.mid,
            audio.ext.audio_level,
            audio.ext.video_orientation
        ),
        (1, 2, 0)
    );
    // The SFU's CNAME for the publisher, never the publisher's own (note §6.5).
    assert_eq!(audio.cname.as_bytes(), b"nexus-7");

    let video = track_spec(&sdp.media[1], b"nexus-7").unwrap().unwrap();
    // The FID group's first SSRC is the track's; the RTX SSRC (second) is not.
    assert_eq!(video.ssrc, Some(2223));
    assert_eq!((video.codec.pt, video.codec.clock_rate), (96, 90_000));
    assert_eq!(
        (
            video.ext.mid,
            video.ext.audio_level,
            video.ext.video_orientation
        ),
        (1, 0, 3)
    );
}

#[test]
fn fid_secondary_listed_first_is_skipped() {
    let sdp = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v\r\na=sendonly\r\na=rtpmap:96 VP8/90000\r\n\
         a=ssrc-group:FID 10 20\r\na=ssrc:20 cname:c\r\na=ssrc:10 cname:c\r\n",
    );
    assert_eq!(
        track_spec(&sdp.media[0], b"f").unwrap().unwrap().ssrc,
        Some(10)
    );
}

/// v1 forwards one stream per m-line: a SIM group is refused, not cut to a layer.
#[test]
fn simulcast_group_is_refused() {
    let sdp = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v\r\na=sendonly\r\na=rtpmap:96 VP8/90000\r\n\
         a=ssrc-group:SIM 30 31 32\r\na=ssrc:30 cname:c\r\na=ssrc:31 cname:c\r\n\
         a=ssrc:32 cname:c\r\n",
    );
    assert_eq!(track_spec(&sdp.media[0], b"f"), Err(ParamsError::Simulcast));
}

/// Firefox: sendrecv-less `sendonly`, upper-case codec name case, extensions declined
/// except mid; a remapped PT.
#[test]
fn firefox_publish_answer() {
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 109\r\na=mid:a0\r\na=sendonly\r\n\
         a=rtpmap:109 OPUS/48000/2\r\na=extmap:1 {MID_URI}\r\n\
         a=ssrc:4242 cname:{{d3c1a1b2-firefox}}\r\n"
    ));
    let audio = track_spec(&sdp.media[0], b"nexus-8").unwrap().unwrap();
    assert_eq!(audio.codec.pt, 109);
    assert_eq!(audio.ext.audio_level, 0, "declined");
    assert_eq!(audio.ssrc, Some(4242));
    assert_eq!(audio.cname.as_bytes(), b"nexus-8", "not Firefox's cname");
}

/// webrtc-rs publisher: `a=ssrc` without extmaps.
#[test]
fn webrtc_rs_publish_answer_without_extensions() {
    let sdp = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=sendrecv\r\na=rtpmap:96 VP8/90000\r\n\
         a=ssrc:777 cname:loadtest-stream\r\na=ssrc:777 msid:loadtest-stream video-1\r\n",
    );
    let video = track_spec(&sdp.media[0], b"nexus-9").unwrap().unwrap();
    assert_eq!(video.ssrc, Some(777));
    assert_eq!(video.ext, ExtIds::default());
    assert_eq!(video.cname.as_bytes(), b"nexus-9");
}

#[test]
fn publish_answer_errors_and_declines() {
    // Neither a=ssrc nor the mid extension.
    let sdp = parse(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(
        track_spec(&sdp.media[0], b"f"),
        Err(ParamsError::NoSsrcSource)
    );
    // mid extension only: SSRC learned on the shard.
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\n\
         a=rtpmap:111 opus/48000/2\r\na=extmap:1 {MID_URI}\r\n"
    ));
    let spec = track_spec(&sdp.media[0], b"nexus-7").unwrap().unwrap();
    assert_eq!((spec.ssrc, spec.cname.as_bytes()), (None, &b"nexus-7"[..]));
    // Codec the SFU does not forward.
    let sdp = parse("m=video 9 UDP/TLS/RTP/SAVPF 98\r\na=mid:1\r\na=sendonly\r\na=rtpmap:98 VP9/90000\r\na=ssrc:5 cname:c\r\n");
    assert_eq!(
        track_spec(&sdp.media[0], b"f"),
        Err(ParamsError::NoCommonCodec("VP8"))
    );
    // Extension id 15: not carried by the one-byte form.
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\n\
         a=rtpmap:111 opus/48000/2\r\na=extmap:15 {LEVEL_URI}\r\na=ssrc:5 cname:c\r\n"
    ));
    assert_eq!(
        track_spec(&sdp.media[0], b"f"),
        Err(ParamsError::ExtIdOutOfRange {
            uri: LEVEL_URI,
            id: 15
        })
    );
    // Two extensions on one id.
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\n\
         a=rtpmap:111 opus/48000/2\r\na=extmap:2 {MID_URI}\r\na=extmap:2 {LEVEL_URI}\r\n\
         a=ssrc:5 cname:c\r\n"
    ));
    assert_eq!(
        track_spec(&sdp.media[0], b"f"),
        Err(ParamsError::DuplicateExtId(2))
    );
    // Rejected (port 0) and not-sending m-lines are not tracks.
    let sdp = parse(
        "m=audio 0 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(track_spec(&sdp.media[0], b"f"), Ok(None));
    let sdp = parse(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=inactive\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(track_spec(&sdp.media[0], b"f"), Ok(None));
    // An empty CNAME is refused.
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\n\
         a=rtpmap:111 opus/48000/2\r\na=extmap:1 {MID_URI}\r\n"
    ));
    assert_eq!(
        track_spec(&sdp.media[0], b""),
        Err(ParamsError::InvalidCname)
    );
}

fn source() -> TrackRef {
    TrackRef {
        shard: ShardId::new(0),
        track: TrackId::new(9),
    }
}

/// A subscriber (Chrome) answering a sendonly m-line whose PT the negotiator remapped
/// to 100, with audio level on another id than the publisher's.
#[test]
fn subscriber_answer_maps_pt_and_extensions() {
    let publisher = track_spec(&chrome_publish().media[0], b"f")
        .unwrap()
        .unwrap();
    let sdp = parse(&format!(
        "m=audio 9 UDP/TLS/RTP/SAVPF 100\r\na=mid:4\r\na=recvonly\r\n\
         a=rtpmap:100 opus/48000/2\r\na=extmap:1 {MID_URI}\r\na=extmap:6 {LEVEL_URI}\r\n"
    ));
    let sub = sub_spec(&sdp.media[0], &publisher, 0xABCD, source())
        .unwrap()
        .unwrap();
    assert_eq!(sub.out_ssrc, 0xABCD);
    assert_eq!(sub.mid.as_bytes(), b"4");
    assert_eq!(sub.pt_map.map(111), Some(100));
    assert_eq!(sub.ext_map.mid, 1);
    assert_eq!(
        sub.ext_map.map[2], 6,
        "publisher audio level 2 → subscriber 6"
    );
    assert_eq!(sub.ext_map.map[1], 0, "publisher mid is never forwarded");
    assert_eq!(sub.source, source());
    // What a shard serving the track from another shard needs (plan 2.2).
    assert_eq!(sub.clock_rate, publisher.codec.clock_rate);
    assert_eq!(sub.pub_mid, publisher.ext.mid);
    assert_eq!(sub.cname, publisher.cname);
}

#[test]
fn subscriber_declined_extension_maps_to_zero() {
    let publisher = track_spec(&chrome_publish().media[1], b"f")
        .unwrap()
        .unwrap();
    let sdp = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:5\r\na=recvonly\r\na=rtpmap:96 VP8/90000\r\n",
    );
    let sub = sub_spec(&sdp.media[0], &publisher, 7, source())
        .unwrap()
        .unwrap();
    assert_eq!(sub.ext_map.mid, 0);
    assert_eq!(sub.ext_map.map, [0; 15]);
}

#[test]
fn subscriber_answer_errors_and_declines() {
    let audio = track_spec(&chrome_publish().media[0], b"f")
        .unwrap()
        .unwrap();
    let video = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:5\r\na=recvonly\r\na=rtpmap:96 VP8/90000\r\n",
    );
    assert_eq!(
        sub_spec(&video.media[0], &audio, 7, source()),
        Err(ParamsError::KindMismatch)
    );
    let vp9 = parse(
        "m=video 9 UDP/TLS/RTP/SAVPF 98\r\na=mid:5\r\na=recvonly\r\na=rtpmap:98 VP9/90000\r\n",
    );
    let video_track = track_spec(&chrome_publish().media[1], b"f")
        .unwrap()
        .unwrap();
    assert_eq!(
        sub_spec(&vp9.media[0], &video_track, 7, source()),
        Err(ParamsError::NoCommonCodec("VP8"))
    );
    let inactive = parse(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:4\r\na=inactive\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(sub_spec(&inactive.media[0], &audio, 7, source()), Ok(None));
    let rejected = parse(
        "m=audio 0 UDP/TLS/RTP/SAVPF 111\r\na=mid:4\r\na=recvonly\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(sub_spec(&rejected.media[0], &audio, 7, source()), Ok(None));
}
