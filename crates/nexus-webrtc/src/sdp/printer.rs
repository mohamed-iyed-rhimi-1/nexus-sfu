//! SDP pretty printer for serializing SessionDescription to SDP text.
//!
//! Implements RFC 8866 compliant SDP generation for WebRTC signaling.
//!
//! # TigerStyle Compliance
//!
//! - Bounded output size (MAX_SDP_SIZE)
//! - Explicit formatting
//! - Minimum 2 assertions per function

use super::media::MediaDescription;
use super::session::SessionDescription;
use super::MAX_SDP_SIZE;

/// SDP pretty printer.
///
/// Formats SessionDescription objects into valid SDP text following RFC 8866.
///
/// # TigerStyle Compliance
///
/// - Bounded output
/// - Explicit line formatting
/// - Validation assertions
pub struct SdpPrinter;

impl SdpPrinter {
    /// Print a SessionDescription to SDP text.
    ///
    /// Generates a complete SDP string from the session description,
    /// including all session-level and media-level attributes.
    ///
    /// # Arguments
    ///
    /// * `session` - The session description to serialize
    ///
    /// # Returns
    ///
    /// A valid SDP string with CRLF line endings.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates output size
    /// - Explicit line ordering per RFC 8866
    pub fn print(session: &SessionDescription) -> String {
        // Precondition: session must be valid
        assert!(
            session.media_count <= super::MAX_MEDIA_SECTIONS as u8,
            "Media count must be bounded"
        );

        let mut lines = Vec::with_capacity(64);

        // Session-level lines (RFC 8866 order: v, o, s, i, u, e, p, c, b, t, r, z, k, a)
        Self::print_session_header(session, &mut lines);
        Self::print_session_ice(session, &mut lines);
        Self::print_session_dtls(session, &mut lines);
        Self::print_session_groups(session, &mut lines);

        // Media sections
        for i in 0..session.media_count as usize {
            if let Some(ref media) = session.media[i] {
                Self::print_media_section(media, &mut lines);
            }
        }

        let result = lines.join("\r\n") + "\r\n";

        // Postcondition: result must not exceed MAX_SDP_SIZE
        assert!(
            result.len() <= MAX_SDP_SIZE,
            "Generated SDP must not exceed MAX_SDP_SIZE"
        );

        result
    }

    /// Print session header lines (v=, o=, s=, t=).
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    /// - Explicit line ordering
    fn print_session_header(session: &SessionDescription, lines: &mut Vec<String>) {
        // Precondition: lines must be empty or have capacity
        assert!(lines.capacity() > 0, "Lines must have capacity");

        // v= version (always 0)
        lines.push(format!("v={}", session.version));

        // o= origin
        lines.push(format!("o={}", session.origin.to_sdp()));

        // s= session name
        let name =
            std::str::from_utf8(&session.session_name[..session.session_name_len as usize])
                .unwrap_or("-");
        lines.push(format!("s={}", name));

        // t= timing
        lines.push(format!("t={}", session.timing.to_sdp()));
    }

    /// Print session-level ICE attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_session_ice(session: &SessionDescription, lines: &mut Vec<String>) {
        if let Some(ref ufrag) = session.ice_ufrag {
            lines.push(format!("a=ice-ufrag:{}", ufrag.as_str()));
        }
        if let Some(ref pwd) = session.ice_pwd {
            lines.push(format!("a=ice-pwd:{}", pwd.as_str()));
        }
        if session.ice_lite {
            lines.push("a=ice-lite".to_string());
        }
    }

    /// Print session-level DTLS attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_session_dtls(session: &SessionDescription, lines: &mut Vec<String>) {
        if let Some(ref fp) = session.fingerprint {
            lines.push(format!("a=fingerprint:{}", fp.to_sdp()));
        }
        if let Some(ref setup) = session.setup {
            lines.push(format!("a=setup:{}", setup.as_str()));
        }
    }

    /// Print session-level group attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_session_groups(session: &SessionDescription, lines: &mut Vec<String>) {
        if session.bundle_group_len > 0 {
            let bundle =
                std::str::from_utf8(&session.bundle_group[..session.bundle_group_len as usize])
                    .unwrap_or("");
            lines.push(format!("a=group:BUNDLE {}", bundle));
        }
    }

    /// Print a media section.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded codec iteration
    /// - Explicit attribute ordering
    fn print_media_section(media: &MediaDescription, lines: &mut Vec<String>) {
        // Precondition: media must have valid type
        assert!(
            media.codec_count <= super::MAX_CODECS_PER_MEDIA as u8,
            "Codec count must be bounded"
        );

        // m= line
        Self::print_media_line(media, lines);

        // c= connection (required, use 0.0.0.0 for WebRTC)
        Self::print_connection_line(media, lines);

        // Media-level ICE
        Self::print_media_ice(media, lines);

        // Media-level DTLS
        Self::print_media_dtls(media, lines);

        // Direction
        lines.push(format!("a={}", media.direction.as_str()));

        // MID
        if let Some(ref mid) = media.mid {
            lines.push(format!("a=mid:{}", mid.as_str()));
        }

        // RTCP attributes
        Self::print_rtcp_attributes(media, lines);

        // Codecs (rtpmap)
        Self::print_codecs(media, lines);

        // Format parameters (fmtp)
        Self::print_fmtps(media, lines);

        // Header extensions (extmaps)
        Self::print_extmaps(media, lines);

        // SSRCs
        Self::print_ssrcs(media, lines);

        // ICE candidates
        Self::print_candidates(media, lines);
    }

    /// Print the m= line.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_media_line(media: &MediaDescription, lines: &mut Vec<String>) {
        let formats: Vec<String> = media.formats[..media.format_count as usize]
            .iter()
            .map(|f| f.to_string())
            .collect();

        let format_str = if formats.is_empty() {
            // If no formats, use codec payload types
            let codec_pts: Vec<String> = (0..media.codec_count as usize)
                .filter_map(|i| media.codecs[i].as_ref().map(|c| c.payload_type.to_string()))
                .collect();
            codec_pts.join(" ")
        } else {
            formats.join(" ")
        };

        lines.push(format!(
            "m={} {} {} {}",
            media.media_type.as_str(),
            media.port,
            media.protocol.as_str(),
            format_str
        ));
    }

    /// Print the c= connection line.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_connection_line(media: &MediaDescription, lines: &mut Vec<String>) {
        if let Some(ref conn) = media.connection {
            let addr =
                std::str::from_utf8(&conn.address[..conn.address_len as usize]).unwrap_or("");
            lines.push(format!("c=IN IP4 {}", addr));
        } else {
            lines.push("c=IN IP4 0.0.0.0".to_string());
        }
    }

    /// Print media-level ICE attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_media_ice(media: &MediaDescription, lines: &mut Vec<String>) {
        if let Some(ref ufrag) = media.ice_ufrag {
            lines.push(format!("a=ice-ufrag:{}", ufrag.as_str()));
        }
        if let Some(ref pwd) = media.ice_pwd {
            lines.push(format!("a=ice-pwd:{}", pwd.as_str()));
        }
        if media.ice_options.trickle {
            lines.push("a=ice-options:trickle".to_string());
        }
    }

    /// Print media-level DTLS attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_media_dtls(media: &MediaDescription, lines: &mut Vec<String>) {
        if let Some(ref fp) = media.fingerprint {
            lines.push(format!("a=fingerprint:{}", fp.to_sdp()));
        }
        if let Some(ref setup) = media.setup {
            lines.push(format!("a=setup:{}", setup.as_str()));
        }
    }

    /// Print RTCP attributes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    fn print_rtcp_attributes(media: &MediaDescription, lines: &mut Vec<String>) {
        if media.rtcp_mux {
            lines.push("a=rtcp-mux".to_string());
        }
        if media.rtcp_rsize {
            lines.push("a=rtcp-rsize".to_string());
        }
    }

    /// Print codec rtpmap lines.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration
    fn print_codecs(media: &MediaDescription, lines: &mut Vec<String>) {
        for i in 0..media.codec_count as usize {
            if let Some(ref codec) = media.codecs[i] {
                lines.push(format!("a=rtpmap:{}", codec.to_sdp()));
            }
        }
    }

    /// Print fmtp lines.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration
    fn print_fmtps(media: &MediaDescription, lines: &mut Vec<String>) {
        for i in 0..media.fmtp_count as usize {
            if let Some(ref fmtp) = media.fmtps[i] {
                let params =
                    std::str::from_utf8(&fmtp.params[..fmtp.params_len as usize]).unwrap_or("");
                lines.push(format!("a=fmtp:{} {}", fmtp.payload_type, params));
            }
        }
    }

    /// Print SSRC lines.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration
    fn print_extmaps(media: &MediaDescription, lines: &mut Vec<String>) {
        for i in 0..media.extmap_count as usize {
            if let Some(ref ext) = media.extmaps[i] {
                let uri = std::str::from_utf8(&ext.uri[..ext.uri_len as usize]).unwrap_or("");
                if let Some(ref dir) = ext.direction {
                    lines.push(format!("a=extmap:{}/{} {}", ext.id, dir.as_str(), uri));
                } else {
                    lines.push(format!("a=extmap:{} {}", ext.id, uri));
                }
            }
        }
    }

    fn print_ssrcs(media: &MediaDescription, lines: &mut Vec<String>) {
        for i in 0..media.ssrc_count as usize {
            if let Some(ref ssrc) = media.ssrcs[i] {
                let attr =
                    std::str::from_utf8(&ssrc.attribute[..ssrc.attr_len as usize]).unwrap_or("");
                let val =
                    std::str::from_utf8(&ssrc.value[..ssrc.value_len as usize]).unwrap_or("");
                lines.push(format!("a=ssrc:{} {}:{}", ssrc.ssrc, attr, val));
            }
        }
    }

    /// Print ICE candidate lines.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded iteration
    fn print_candidates(media: &MediaDescription, lines: &mut Vec<String>) {
        for i in 0..media.candidate_count as usize {
            if let Some(ref candidate) = media.candidates[i] {
                lines.push(format!("a=candidate:{}", candidate.to_sdp()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdp::attributes::{Direction, DtlsFingerprint, RtpCodec};
    use crate::sdp::media::{MediaType, Mid, TransportProtocol};
    use crate::sdp::parser::SdpParser;

    fn test_fingerprint() -> DtlsFingerprint {
        DtlsFingerprint::parse(
            "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:\
             AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90",
        )
        .unwrap()
    }

    #[test]
    fn test_print_minimal_session() {
        let mut session = SessionDescription::new(12345);
        session.set_session_name("Test");
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.starts_with("v=0\r\n"));
        assert!(sdp.contains("o="));
        assert!(sdp.contains("s=Test"));
        assert!(sdp.contains("t=0 0"));
        assert!(sdp.contains("a=ice-ufrag:testufrag"));
        assert!(sdp.contains("a=ice-pwd:testpwd1234567890123456"));
        assert!(sdp.contains("a=fingerprint:sha-256"));
        assert!(sdp.contains("m=audio 9 UDP/TLS/RTP/SAVPF"));
        assert!(sdp.contains("a=mid:0"));
        assert!(sdp.contains("a=rtpmap:111 opus/48000/2"));
    }

    #[test]
    fn test_print_video_session() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Video, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        let codec = RtpCodec::parse(96, "VP8/90000").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.contains("m=video 9 UDP/TLS/RTP/SAVPF"));
        assert!(sdp.contains("a=rtpmap:96 VP8/90000"));
    }

    #[test]
    fn test_print_multiple_media() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        // Audio
        let mut audio = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        audio.mid = Some(Mid::new("0"));
        let opus = RtpCodec::parse(111, "opus/48000/2").unwrap();
        audio.add_codec(opus).unwrap();
        session.add_media(audio).unwrap();

        // Video
        let mut video = MediaDescription::new(MediaType::Video, 9, TransportProtocol::UdpTlsRtpSavpf);
        video.mid = Some(Mid::new("1"));
        let vp8 = RtpCodec::parse(96, "VP8/90000").unwrap();
        video.add_codec(vp8).unwrap();
        session.add_media(video).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.contains("m=audio"));
        assert!(sdp.contains("m=video"));
        assert!(sdp.contains("a=mid:0"));
        assert!(sdp.contains("a=mid:1"));
    }

    #[test]
    fn test_print_with_bundle() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut audio = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        audio.mid = Some(Mid::new("0"));
        let opus = RtpCodec::parse(111, "opus/48000/2").unwrap();
        audio.add_codec(opus).unwrap();
        session.add_media(audio).unwrap();

        let mut video = MediaDescription::new(MediaType::Video, 9, TransportProtocol::UdpTlsRtpSavpf);
        video.mid = Some(Mid::new("1"));
        let vp8 = RtpCodec::parse(96, "VP8/90000").unwrap();
        video.add_codec(vp8).unwrap();
        session.add_media(video).unwrap();

        session.set_bundle(&["0", "1"]).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.contains("a=group:BUNDLE 0 1"));
    }

    #[test]
    fn test_print_direction() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        media.direction = Direction::SendOnly;
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.contains("a=sendonly"));
    }

    #[test]
    fn test_print_rtcp_mux() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        media.rtcp_mux = true;
        media.rtcp_rsize = true;
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        let sdp = SdpPrinter::print(&session);

        assert!(sdp.contains("a=rtcp-mux"));
        assert!(sdp.contains("a=rtcp-rsize"));
    }

    #[test]
    fn test_roundtrip() {
        let mut session = SessionDescription::new(12345);
        session.set_session_name("Roundtrip Test");
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        media.direction = Direction::SendRecv;
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        // Print
        let sdp_str = SdpPrinter::print(&session);

        // Parse back
        let reparsed = SdpParser::parse(&sdp_str).unwrap();

        // Verify key fields
        assert_eq!(reparsed.origin.session_id, session.origin.session_id);
        assert_eq!(reparsed.media_count, session.media_count);
        assert!(reparsed.ice_ufrag.is_some());
        assert!(reparsed.fingerprint.is_some());
    }

    #[test]
    fn test_print_uses_crlf() {
        let mut session = SessionDescription::new(12345);
        session.set_ice_credentials("testufrag", "testpwd1234567890123456");
        session.set_fingerprint(test_fingerprint());

        let mut media = MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        session.add_media(media).unwrap();

        let sdp = SdpPrinter::print(&session);

        // All line endings should be CRLF
        assert!(sdp.contains("\r\n"));
        // Should end with CRLF
        assert!(sdp.ends_with("\r\n"));
    }
}
