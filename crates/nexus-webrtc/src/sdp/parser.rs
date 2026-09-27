//! SDP parser.

use super::attributes::{
    Direction, DtlsFingerprint, DtlsSetup, ExtMap, FingerprintAlgorithm, Fmtp, IceCandidate,
    RtpCodec, SsrcInfo,
};
use super::error::SdpError;
use super::media::{IcePwd, IceUfrag, MediaDescription, MediaType, Mid, TransportProtocol};
use super::session::{Origin, SessionDescription, Timing};
use super::{
    MAX_ICE_PWD_LEN, MAX_ICE_UFRAG_LEN, MAX_MEDIA_SECTIONS, MAX_SDP_SIZE, MIN_ICE_PWD_LEN,
    MIN_ICE_UFRAG_LEN,
};

/// SDP parser.
pub struct SdpParser;

impl SdpParser {
    /// Parse an SDP string into a SessionDescription.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded parsing (max `MAX_MEDIA_SECTIONS` media sections)
    /// - Explicit error handling
    /// - Precondition/postcondition assertions
    pub fn parse(sdp: &str) -> Result<SessionDescription, SdpError> {
        if sdp.is_empty() {
            return Err(SdpError::InvalidFormat {
                reason: "empty SDP",
            });
        }

        if sdp.len() > MAX_SDP_SIZE {
            return Err(SdpError::TooLarge {
                size: sdp.len(),
                max: MAX_SDP_SIZE,
            });
        }

        let mut session = SessionDescription::default();
        let mut current_media: Option<MediaDescription> = None;
        let mut line_num = 0u32;
        // RFC 8866 §5: track mandatory SDP fields
        let mut has_version = false;
        let mut has_origin = false;

        for line in sdp.lines() {
            line_num += 1;

            // Bounded line processing
            if line_num > 10000 {
                return Err(SdpError::ParseError {
                    line: line_num as usize,
                    message: "too many lines".to_string(),
                });
            }

            Self::parse_line(
                line,
                line_num as usize,
                &mut session,
                &mut current_media,
                &mut has_version,
                &mut has_origin,
            )?;
        }

        // Save final media section
        if let Some(media) = current_media {
            session.add_media(media)?;
        }

        // RFC 8866 §5: validate mandatory SDP fields were present
        if !has_version {
            return Err(SdpError::MissingField {
                field: "v= (version)",
            });
        }
        if !has_origin {
            return Err(SdpError::MissingField {
                field: "o= (origin)",
            });
        }

        // Validate required WebRTC fields
        Self::validate_session(&session)?;

        // Postcondition: media count must be bounded
        assert!(
            session.media.len() <= MAX_MEDIA_SECTIONS,
            "Media count must be <= MAX_MEDIA_SECTIONS"
        );

        Ok(session)
    }

    /// Parse a single SDP line.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted from parse() for function length compliance
    /// - Explicit error handling for malformed lines
    fn parse_line(
        line: &str,
        line_num: usize,
        session: &mut SessionDescription,
        current_media: &mut Option<MediaDescription>,
        has_version: &mut bool,
        has_origin: &mut bool,
    ) -> Result<(), SdpError> {
        let line = line.trim();

        if line.is_empty() {
            return Ok(());
        }

        // The type is one ASCII byte followed by '='. Checking bytes (not chars) keeps
        // the slice below on a char boundary: a multi-byte first character such as
        // "€=x" must be an error, not a panic.
        let bytes = line.as_bytes();
        if bytes.len() < 2 || !bytes[0].is_ascii() || bytes[1] != b'=' {
            // Malformed line - return error instead of silently skipping
            return Err(SdpError::ParseError {
                line: line_num,
                message: "malformed line (expected 'x=')".to_string(),
            });
        }

        let type_char = bytes[0] as char;
        let value = &line[2..];

        match type_char {
            'v' => {
                Self::parse_version(value, line_num, session)?;
                *has_version = true;
            }
            'o' => {
                session.origin = Self::parse_origin(value, line_num)?;
                *has_origin = true;
            }
            's' => Self::parse_session_name(value, session),
            't' => session.timing = Self::parse_timing(value, line_num)?,
            'm' => Self::parse_media_section(value, line_num, session, current_media)?,
            'c' => {} // Connection info - skip for WebRTC (uses ICE)
            'a' => Self::parse_attribute(value, session, current_media, line_num)?,
            _ => {} // Ignore unknown types
        }

        Ok(())
    }

    /// Parse version line.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for clarity
    /// - Explicit version validation
    fn parse_version(
        value: &str,
        line_num: usize,
        session: &mut SessionDescription,
    ) -> Result<(), SdpError> {
        let version = value.parse::<u8>().map_err(|_| SdpError::ParseError {
            line: line_num,
            message: "invalid version".to_string(),
        })?;

        if version != 0 {
            return Err(SdpError::InvalidVersion { version });
        }

        session.version = version;
        Ok(())
    }

    /// Parse session name line.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for clarity
    /// - Bounded string copy
    fn parse_session_name(value: &str, session: &mut SessionDescription) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(64);
        session.session_name[..len].copy_from_slice(&bytes[..len]);
        session.session_name_len = len as u8;
    }

    /// Parse media section start.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for clarity
    /// - Enforces bounded media section count
    fn parse_media_section(
        value: &str,
        line_num: usize,
        session: &mut SessionDescription,
        current_media: &mut Option<MediaDescription>,
    ) -> Result<(), SdpError> {
        // Save previous media section
        if let Some(media) = current_media.take() {
            session.add_media(media)?;
        }

        // Enforce maximum media sections
        if session.media.len() >= MAX_MEDIA_SECTIONS {
            return Err(SdpError::TooManyMedia {
                count: session.media.len() + 1,
                max: MAX_MEDIA_SECTIONS,
            });
        }

        // Parse new media section
        *current_media = Some(Self::parse_media_line(value, line_num)?);
        Ok(())
    }

    /// Keep one fingerprint per level: sha-256 (the only one the SFU checks) over any
    /// other algorithm, else the first line.
    fn keep_preferred_fingerprint(slot: &mut Option<DtlsFingerprint>, fp: DtlsFingerprint) {
        let replace = match slot {
            None => true,
            Some(kept) => {
                kept.algorithm != FingerprintAlgorithm::Sha256
                    && fp.algorithm == FingerprintAlgorithm::Sha256
            }
        };
        if replace {
            *slot = Some(fp);
        }
        debug_assert!(slot.is_some());
    }

    /// Validate session has required WebRTC fields.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit validation of required fields
    /// - Clear error messages
    fn validate_session(session: &SessionDescription) -> Result<(), SdpError> {
        // For WebRTC, we need either session-level or media-level ICE credentials
        let has_session_ice = session.ice_ufrag.is_some() && session.ice_pwd.is_some();

        if !has_session_ice {
            // Check if all media sections have ICE credentials
            for media in &session.media {
                if media.ice_ufrag.is_none() || media.ice_pwd.is_none() {
                    return Err(SdpError::MissingIceCredentials {
                        field: "ice-ufrag or ice-pwd",
                    });
                }
            }
        }

        // Validate ICE credential lengths (session-level)
        if let Some(ref ufrag) = session.ice_ufrag {
            Self::validate_ice_ufrag(ufrag)?;
        }
        if let Some(ref pwd) = session.ice_pwd {
            Self::validate_ice_pwd(pwd)?;
        }

        // Validate ICE credential lengths (media-level) per RFC 8445
        // ice-ufrag must be at least 4 characters, ice-pwd at least 22 characters
        for media in &session.media {
            if let Some(ref ufrag) = media.ice_ufrag {
                Self::validate_ice_ufrag(ufrag)?;
            }
            if let Some(ref pwd) = media.ice_pwd {
                Self::validate_ice_pwd(pwd)?;
            }
        }

        // For WebRTC, we need either session-level or media-level fingerprint
        let has_session_fp = session.fingerprint.is_some();

        if !has_session_fp {
            // Check if all media sections have fingerprint
            if session.media.iter().any(|m| m.fingerprint.is_none()) {
                return Err(SdpError::MissingFingerprint);
            }
        }

        // Validate fingerprints are SHA-256
        if let Some(ref fp) = session.fingerprint {
            fp.validate()?;
        }

        for media in &session.media {
            if let Some(ref fp) = media.fingerprint {
                fp.validate()?;
            }
        }

        // Mids identify m-lines (RFC 5888 §4: unique within the session). Bounded:
        // at most MAX_MEDIA_SECTIONS² comparisons.
        for (i, media) in session.media.iter().enumerate() {
            if let Some(mid) = media.mid.as_ref() {
                let dup = session.media[..i]
                    .iter()
                    .any(|m| m.mid.as_ref().is_some_and(|m| m.as_str() == mid.as_str()));
                if dup {
                    return Err(SdpError::InvalidAttribute {
                        name: "mid".to_string(),
                        value: mid.as_str().to_string(),
                    });
                }
            }
        }

        // Validate BUNDLE group MIDs exist in media sections
        Self::validate_bundle_group(session)?;

        Ok(())
    }

    /// Validate BUNDLE group MIDs against existing media MIDs.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates all BUNDLE MIDs reference existing media sections
    /// - Returns InvalidBundleGroup error for missing MIDs
    fn validate_bundle_group(session: &SessionDescription) -> Result<(), SdpError> {
        // Parse BUNDLE MIDs and validate each exists. Bounded: the value is at most
        // MAX_BUNDLE_LEN bytes, and each check scans at most MAX_MEDIA_SECTIONS.
        for mid in session.bundle().split_whitespace() {
            if !session.has_media_with_mid(mid) {
                return Err(SdpError::InvalidBundleGroup {
                    mid: mid.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate ICE ufrag length.
    pub fn validate_ice_ufrag(ufrag: &IceUfrag) -> Result<(), SdpError> {
        let len = ufrag.len as usize;
        if !(MIN_ICE_UFRAG_LEN..=MAX_ICE_UFRAG_LEN).contains(&len) {
            return Err(SdpError::InvalidIceCredentialLength {
                field: "ice-ufrag",
                actual: len,
                min: MIN_ICE_UFRAG_LEN,
                max: MAX_ICE_UFRAG_LEN,
            });
        }
        Ok(())
    }

    /// Validate ICE pwd length.
    pub fn validate_ice_pwd(pwd: &IcePwd) -> Result<(), SdpError> {
        let len = pwd.len as usize;
        if !(MIN_ICE_PWD_LEN..=MAX_ICE_PWD_LEN).contains(&len) {
            return Err(SdpError::InvalidIceCredentialLength {
                field: "ice-pwd",
                actual: len,
                min: MIN_ICE_PWD_LEN,
                max: MAX_ICE_PWD_LEN,
            });
        }
        Ok(())
    }

    /// Parse origin line.
    fn parse_origin(value: &str, line_num: usize) -> Result<Origin, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(SdpError::ParseError {
                line: line_num,
                message: "invalid origin".to_string(),
            });
        }

        let mut origin = Origin::default();

        // Username
        let username_bytes = parts[0].as_bytes();
        let username_len = username_bytes.len().min(32);
        origin.username[..username_len].copy_from_slice(&username_bytes[..username_len]);
        origin.username_len = username_len as u8;

        // Session ID
        origin.session_id = parts[1].parse().map_err(|_| SdpError::ParseError {
            line: line_num,
            message: "invalid session id".to_string(),
        })?;

        // Session version
        origin.session_version = parts[2].parse().map_err(|_| SdpError::ParseError {
            line: line_num,
            message: "invalid session version".to_string(),
        })?;

        // Address
        let addr_bytes = parts[5].as_bytes();
        let addr_len = addr_bytes.len().min(64);
        origin.address[..addr_len].copy_from_slice(&addr_bytes[..addr_len]);
        origin.address_len = addr_len as u8;

        Ok(origin)
    }

    /// Parse timing line.
    fn parse_timing(value: &str, line_num: usize) -> Result<Timing, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(SdpError::ParseError {
                line: line_num,
                message: "invalid timing".to_string(),
            });
        }

        Ok(Timing {
            start: parts[0].parse().unwrap_or(0),
            stop: parts[1].parse().unwrap_or(0),
        })
    }

    /// Parse m= line.
    fn parse_media_line(value: &str, line_num: usize) -> Result<MediaDescription, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SdpError::ParseError {
                line: line_num,
                message: "invalid media line".to_string(),
            });
        }

        let media_type = MediaType::parse(parts[0]).ok_or(SdpError::InvalidMediaType {
            media_type: parts[0].to_string(),
        })?;

        let port = parts[1].parse::<u16>().map_err(|_| SdpError::ParseError {
            line: line_num,
            message: "invalid port".to_string(),
        })?;

        let protocol = TransportProtocol::parse(parts[2]).ok_or(SdpError::InvalidTransport {
            transport: parts[2].to_string(),
        })?;

        let mut media = MediaDescription::new(media_type, port, protocol);

        // Parse format list: RTP payload types (0-127) only. Other formats (e.g.
        // `webrtc-datachannel`) are skipped rather than stored as PT 0. Bounded by the
        // 32-entry array.
        for fmt in &parts[3..] {
            if media.format_count as usize >= media.formats.len() {
                break;
            }
            if let Some(pt) = fmt.parse::<u8>().ok().filter(|&pt| pt <= 127) {
                media.formats[media.format_count as usize] = pt;
                media.format_count += 1;
            }
        }

        Ok(media)
    }

    /// One `a=extmap` entry: id 1-255 (0 is invalid, RFC 8285 §5) and a URI of at most
    /// 128 bytes. Anything else is an error, never a truncated URI (the URI decides what
    /// the extension is).
    fn parse_extmap(
        id_str: &str,
        uri_str: &str,
        direction: Option<Direction>,
    ) -> Result<ExtMap, SdpError> {
        let invalid = || SdpError::InvalidAttribute {
            name: "extmap".to_string(),
            value: format!(
                "{} {}",
                id_str,
                uri_str.chars().take(64).collect::<String>()
            ),
        };
        let id = id_str
            .parse::<u8>()
            .ok()
            .filter(|&id| id != 0)
            .ok_or_else(invalid)?;
        if uri_str.is_empty() || uri_str.len() > 128 {
            return Err(invalid());
        }
        let mut uri = [0u8; 128];
        uri[..uri_str.len()].copy_from_slice(uri_str.as_bytes());
        Ok(ExtMap {
            id,
            direction,
            uri,
            uri_len: uri_str.len() as u8,
        })
    }

    /// Parse attribute line.
    fn parse_attribute(
        value: &str,
        session: &mut SessionDescription,
        current_media: &mut Option<MediaDescription>,
        _line_num: usize,
    ) -> Result<(), SdpError> {
        // Split attribute into name and value
        let (name, attr_value) = if let Some(colon_pos) = value.find(':') {
            (&value[..colon_pos], Some(&value[colon_pos + 1..]))
        } else {
            (value, None)
        };

        match name {
            // ICE attributes
            "ice-ufrag" => {
                if let Some(v) = attr_value {
                    let ufrag = IceUfrag::parse(v)?;
                    if let Some(ref mut media) = current_media {
                        media.ice_ufrag = Some(ufrag);
                    } else {
                        session.ice_ufrag = Some(ufrag);
                    }
                }
            }

            "ice-pwd" => {
                if let Some(v) = attr_value {
                    let pwd = IcePwd::parse(v)?;
                    if let Some(ref mut media) = current_media {
                        media.ice_pwd = Some(pwd);
                    } else {
                        session.ice_pwd = Some(pwd);
                    }
                }
            }

            "ice-options" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        media.ice_options.trickle = v.contains("trickle");
                    }
                }
            }

            "ice-lite" => {
                session.ice_lite = true;
            }

            // DTLS attributes
            "fingerprint" => {
                if let Some(v) = attr_value {
                    // RFC 8122 §5: a level may carry several fingerprints. A line with an
                    // algorithm we do not support (sha-1) is skipped; if none is usable,
                    // `validate_session` reports the fingerprint missing.
                    let fp = match DtlsFingerprint::parse(v) {
                        Ok(fp) => fp,
                        Err(SdpError::UnsupportedFingerprintAlgorithm { .. }) => return Ok(()),
                        Err(e) => return Err(e),
                    };
                    let slot = match current_media {
                        Some(ref mut media) => &mut media.fingerprint,
                        None => &mut session.fingerprint,
                    };
                    Self::keep_preferred_fingerprint(slot, fp);
                }
            }

            "setup" => {
                if let Some(v) = attr_value {
                    let setup = DtlsSetup::parse(v);
                    if setup.is_none() {
                        return Err(SdpError::InvalidAttribute {
                            name: "setup".to_string(),
                            value: v.to_string(),
                        });
                    }
                    if let Some(ref mut media) = current_media {
                        media.setup = setup;
                    } else {
                        session.setup = setup;
                    }
                }
            }

            // Direction
            "sendrecv" => {
                if let Some(ref mut media) = current_media {
                    media.direction = Direction::SendRecv;
                }
            }

            "sendonly" => {
                if let Some(ref mut media) = current_media {
                    media.direction = Direction::SendOnly;
                }
            }

            "recvonly" => {
                if let Some(ref mut media) = current_media {
                    media.direction = Direction::RecvOnly;
                }
            }

            "inactive" => {
                if let Some(ref mut media) = current_media {
                    media.direction = Direction::Inactive;
                }
            }

            // RTCP
            "rtcp-mux" => {
                if let Some(ref mut media) = current_media {
                    media.rtcp_mux = true;
                }
            }

            "rtcp-rsize" => {
                if let Some(ref mut media) = current_media {
                    media.rtcp_rsize = true;
                }
            }

            // MID
            "mid" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        media.mid = Some(Mid::parse(v)?);
                    }
                }
            }

            // Group
            "group" => {
                if let Some(v) = attr_value {
                    if let Some(bundle) = v.strip_prefix("BUNDLE ") {
                        // An over-long group is an error, never truncated.
                        session.set_bundle_value(bundle)?;
                    }
                }
            }

            // RTP
            "rtpmap" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        // Format: pt codec/rate[/channels]
                        if let Some(space_pos) = v.find(' ') {
                            if let Ok(pt) = v[..space_pos].parse::<u8>() {
                                if let Ok(codec) = RtpCodec::parse(pt, &v[space_pos + 1..]) {
                                    let _ = media.add_codec(codec);
                                }
                            }
                        }
                    }
                }
            }

            "fmtp" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        if let Ok(fmtp) = Fmtp::parse(v) {
                            if (media.fmtp_count as usize) < super::MAX_CODECS_PER_MEDIA {
                                media.fmtps[media.fmtp_count as usize] = Some(fmtp);
                                media.fmtp_count += 1;
                            }
                        }
                    }
                }
            }

            // SSRC
            "ssrc" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        // A malformed or over-long line is an error; entries beyond
                        // MAX_SSRCS_PER_MEDIA are still dropped (simulcast, after v1).
                        let _ = media.add_ssrc(SsrcInfo::parse(v)?);
                    }
                }
            }

            // RTP header extensions (required for mid/rid demuxing)
            "extmap" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        // Format: ID[/direction] URI [extensionattributes]
                        let parts: Vec<&str> = v.splitn(3, ' ').collect();
                        if parts.len() >= 2 {
                            let id_part = parts[0];
                            let uri_str = parts[1];

                            // Parse ID and optional direction from "ID" or "ID/direction"
                            let (id_str, direction) = if let Some(slash) = id_part.find('/') {
                                let dir = Direction::parse(&id_part[slash + 1..]);
                                (&id_part[..slash], dir)
                            } else {
                                (id_part, None)
                            };

                            let _ =
                                media.add_extmap(Self::parse_extmap(id_str, uri_str, direction)?);
                        }
                    }
                }
            }

            // ICE candidate
            "candidate" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        if let Ok(candidate) = IceCandidate::parse(v) {
                            let _ = media.add_candidate(candidate);
                        }
                    }
                }
            }

            // RTCP feedback (RFC 4585) — critical for NACK/PLI/FIR
            "rtcp-fb" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        if let Ok(fb) = super::attributes::RtcpFeedback::parse(v) {
                            let _ = media.add_rtcp_fb(fb);
                        }
                    }
                }
            }

            // SSRC group (RFC 5576) — needed for RTX and simulcast SSRC association
            "ssrc-group" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        let parts: Vec<&str> = v.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let mut semantics = [0u8; 16];
                            let sem_bytes = parts[0].as_bytes();
                            let sem_len = sem_bytes.len().min(16);
                            semantics[..sem_len].copy_from_slice(&sem_bytes[..sem_len]);

                            let mut ssrcs = [0u32; 8];
                            let mut ssrc_count = 0u8;
                            for &p in &parts[1..] {
                                if ssrc_count as usize >= 8 {
                                    break;
                                }
                                if let Ok(ssrc) = p.parse::<u32>() {
                                    ssrcs[ssrc_count as usize] = ssrc;
                                    ssrc_count += 1;
                                }
                            }

                            let group = super::media::SsrcGroup {
                                semantics,
                                semantics_len: sem_len as u8,
                                ssrcs,
                                ssrc_count,
                            };
                            let _ = media.add_ssrc_group(group);
                        }
                    }
                }
            }

            // RID (RFC 8851) — needed for modern simulcast
            "rid" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        // Format: id direction [restrictions]
                        let parts: Vec<&str> = v.splitn(3, ' ').collect();
                        if parts.len() >= 2 {
                            let mut id = [0u8; 32];
                            let id_bytes = parts[0].as_bytes();
                            let id_len = id_bytes.len().min(32);
                            id[..id_len].copy_from_slice(&id_bytes[..id_len]);

                            let direction =
                                Direction::parse(parts[1]).unwrap_or(Direction::SendRecv);

                            let rid = super::media::Rid {
                                id,
                                id_len: id_len as u8,
                                direction,
                            };
                            let _ = media.add_rid(rid);
                        }
                    }
                }
            }

            // Simulcast (RFC 8853)
            "simulcast" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        let mut value = [0u8; 256];
                        let bytes = v.as_bytes();
                        let len = bytes.len().min(256);
                        value[..len].copy_from_slice(&bytes[..len]);
                        media.simulcast = Some(super::media::SimulcastAttr {
                            value,
                            value_len: len as u16,
                        });
                    }
                }
            }

            // Standalone msid (RFC 8830)
            "msid" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        // Over-long ids are an error (Msid::new), never cut.
                        let (stream_id, track_id) = v.split_once(' ').unwrap_or((v, ""));
                        media.msid = Some(super::media::Msid::new(stream_id, track_id)?);
                    }
                }
            }

            // RTCP-mux-only (RFC 8858)
            "rtcp-mux-only" => {
                if let Some(ref mut media) = current_media {
                    media.rtcp_mux_only = true;
                    media.rtcp_mux = true; // rtcp-mux-only implies rtcp-mux
                }
            }

            // extmap-allow-mixed (RFC 8285)
            "extmap-allow-mixed" => {
                if let Some(ref mut media) = current_media {
                    media.extmap_allow_mixed = true;
                }
            }

            // end-of-candidates (RFC 8838)
            "end-of-candidates" => {
                if let Some(ref mut media) = current_media {
                    media.end_of_candidates = true;
                }
            }

            _ => {
                // Ignore unknown attributes
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::media::Mid;
    use super::super::{MAX_BUNDLE_LEN, MAX_MID_LEN};
    use super::*;

    // ========================================================================
    // Basic Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_simple_sdp() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendrecv
a=rtcp-mux
"#;

        let parsed = SdpParser::parse(sdp).unwrap();

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.origin.session_id, 12345);
        assert!(parsed.ice_ufrag.is_some());
        assert_eq!(parsed.media.len(), 1);

        let media = &parsed.media[0];
        assert_eq!(media.media_type, MediaType::Audio);
        assert!(media.rtcp_mux);
    }

    #[test]
    fn test_parse_with_candidates() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=ice-ufrag:testufrag
a=ice-pwd:testpwd123456789012345678
a=candidate:1 1 udp 2130706431 192.168.1.1 54321 typ host
"#;

        let parsed = SdpParser::parse(sdp).unwrap();

        let media = &parsed.media[0];
        assert_eq!(media.candidate_count, 1);
    }

    #[test]
    fn test_parse_with_fingerprint() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=setup:actpass
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let parsed = SdpParser::parse(sdp).unwrap();

        assert!(parsed.fingerprint.is_some());
        assert_eq!(parsed.setup, Some(DtlsSetup::Actpass));
    }

    #[test]
    fn test_parse_bundle() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=group:BUNDLE 0 1
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:1
"#;

        let parsed = SdpParser::parse(sdp).unwrap();

        assert!(parsed.bundle_group_len > 0);
        assert_eq!(parsed.media.len(), 2);
    }

    // ========================================================================
    // Bounds and Limits Tests (TigerStyle)
    // ========================================================================

    #[test]
    fn test_parse_enforces_max_media_sections() {
        let mut sdp = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
        sdp.push_str("a=ice-ufrag:testufrag\na=ice-pwd:testpwd1234567890123456\n");
        sdp.push_str("a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n");

        // Add MAX_MEDIA_SECTIONS + 1 media sections
        for i in 0..MAX_MEDIA_SECTIONS + 1 {
            sdp.push_str(&format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:{}\n", i));
        }

        let result = SdpParser::parse(&sdp);
        assert!(matches!(result, Err(SdpError::TooManyMedia { .. })));
    }

    #[test]
    fn test_parse_at_max_media_sections() {
        let mut sdp = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
        sdp.push_str("a=ice-ufrag:testufrag\na=ice-pwd:testpwd1234567890123456\n");
        sdp.push_str("a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n");

        // Add exactly MAX_MEDIA_SECTIONS (32)
        for i in 0..MAX_MEDIA_SECTIONS {
            sdp.push_str(&format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:{}\n", i));
        }

        let result = SdpParser::parse(&sdp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().media.len(), MAX_MEDIA_SECTIONS);
    }

    /// A valid session header followed by `count` audio m-lines with mids from `mid`,
    /// and a BUNDLE line naming all of them.
    fn sdp_with_mlines(count: usize, mid: impl Fn(usize) -> String) -> String {
        let mut sdp = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
        sdp.push_str("a=ice-ufrag:testufrag\na=ice-pwd:testpwd1234567890123456\n");
        sdp.push_str("a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n");
        let mids: Vec<String> = (0..count).map(&mid).collect();
        sdp.push_str(&format!("a=group:BUNDLE {}\n", mids.join(" ")));
        for m in &mids {
            sdp.push_str(&format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:{}\n", m));
        }
        sdp
    }

    #[test]
    fn test_bundle_keeps_all_32_mids() {
        // Numeric mids and 16-character mids: the longest group that must fit.
        let long = |i: usize| format!("{:0>16}", i);
        for mid in [
            &(|i: usize| i.to_string()) as &dyn Fn(usize) -> String,
            &long,
        ] {
            let parsed = SdpParser::parse(&sdp_with_mlines(MAX_MEDIA_SECTIONS, mid)).unwrap();
            let bundle: Vec<&str> = parsed.bundle().split(' ').collect();
            assert_eq!(bundle.len(), MAX_MEDIA_SECTIONS);
            for (i, m) in bundle.iter().enumerate() {
                assert_eq!(*m, mid(i));
                assert_eq!(parsed.media[i].mid.as_ref().unwrap().as_str(), mid(i));
            }
        }
    }

    #[test]
    fn test_overlong_bundle_is_an_error_not_a_truncation() {
        let mut sdp = sdp_with_mlines(1, |i| i.to_string());
        let group = format!("a=group:BUNDLE 0{}\n", " 0".repeat(MAX_BUNDLE_LEN));
        sdp = sdp.replace("a=group:BUNDLE 0\n", &group);
        assert!(matches!(
            SdpParser::parse(&sdp),
            Err(SdpError::TooLarge { .. })
        ));
    }

    #[test]
    fn test_overlong_mid_is_an_error_not_a_truncation() {
        let ok = sdp_with_mlines(1, |_| "a".repeat(MAX_MID_LEN));
        assert!(SdpParser::parse(&ok).is_ok());
        let too_long = sdp_with_mlines(1, |_| "a".repeat(MAX_MID_LEN + 1));
        assert!(matches!(
            SdpParser::parse(&too_long),
            Err(SdpError::InvalidAttribute { .. })
        ));
    }

    /// `sdp_with_mlines(1, ..)` with `extra` lines appended to its one m-line.
    fn one_mline_with(extra: &str) -> String {
        format!("{}{}", sdp_with_mlines(1, |i| i.to_string()), extra)
    }

    #[test]
    fn test_fields_over_capacity_are_errors_not_cuts() {
        let ok = one_mline_with("");
        assert!(SdpParser::parse(&ok).is_ok());
        let cases = [
            // ICE credentials: > 256 bytes, or not ice-char (RFC 8445 §5.3)
            ok.replace(
                "a=ice-ufrag:testufrag",
                &format!("a=ice-ufrag:{}", "u".repeat(257)),
            ),
            ok.replace("a=ice-pwd:", &format!("a=ice-pwd:{}", "p".repeat(257))),
            ok.replace("a=ice-ufrag:testufrag", "a=ice-ufrag:test-ufrag"),
            ok.replace("a=ice-pwd:testpwd", "a=ice-pwd:testpwé"),
            // msid ids > 128 bytes
            one_mline_with(&format!("a=msid:{} t\n", "s".repeat(129))),
            one_mline_with(&format!("a=msid:s {}\n", "t".repeat(129))),
            // ssrc attribute value > 256 bytes (cname), attribute name > 32
            one_mline_with(&format!("a=ssrc:1 cname:{}\n", "c".repeat(257))),
            one_mline_with(&format!("a=ssrc:1 {}:x\n", "a".repeat(33))),
            // extmap URI > 128 bytes, id 0
            one_mline_with(&format!("a=extmap:1 urn:{}\n", "x".repeat(125))),
            one_mline_with("a=extmap:0 urn:ietf:params:rtp-hdrext:sdes:mid\n"),
        ];
        for sdp in &cases {
            assert!(SdpParser::parse(sdp).is_err(), "accepted: {sdp:?}");
        }
        // At capacity: accepted and stored whole.
        let at = one_mline_with(&format!(
            "a=msid:{} {}\na=ssrc:1 cname:{}\na=extmap:14 urn:{}\n",
            "s".repeat(128),
            "t".repeat(128),
            "c".repeat(256),
            "x".repeat(124)
        ));
        let parsed = SdpParser::parse(&at).unwrap();
        let media = &parsed.media[0];
        let msid = media.msid.as_ref().unwrap();
        assert_eq!((msid.stream_id().len(), msid.track_id().len()), (128, 128));
        assert_eq!(media.ssrcs[0].as_ref().unwrap().value_len, 256);
        assert_eq!(media.extmaps[0].as_ref().unwrap().uri_len, 128);
    }

    #[test]
    fn test_mid_must_be_a_unique_token() {
        let base = sdp_with_mlines(2, |i| i.to_string());
        assert!(SdpParser::parse(&base).is_ok());
        let bad = [
            base.replace("a=mid:1", "a=mid:0")
                .replace("BUNDLE 0 1", "BUNDLE 0"),
            base.replace("a=mid:1", "a=mid:a\"b")
                .replace("BUNDLE 0 1", "BUNDLE 0"),
            base.replace("a=mid:1", "a=mid:é")
                .replace("BUNDLE 0 1", "BUNDLE 0"),
            base.replace("a=mid:1", "a=mid:a(b")
                .replace("BUNDLE 0 1", "BUNDLE 0"),
        ];
        for sdp in &bad {
            assert!(SdpParser::parse(sdp).is_err(), "accepted: {sdp:?}");
        }
        // Token characters other than alphanumerics are fine.
        let ok = base
            .replace("a=mid:1", "a=mid:v-1.x_~")
            .replace("BUNDLE 0 1", "BUNDLE 0 v-1.x_~");
        assert!(SdpParser::parse(&ok).is_ok());
    }

    #[test]
    fn test_format_list_skips_non_payload_types() {
        let base = sdp_with_mlines(1, |i| i.to_string());
        let parse = |line: &str| {
            let sdp = base.replace("m=audio 9 UDP/TLS/RTP/SAVPF 111", line);
            let parsed = SdpParser::parse(&sdp).unwrap();
            let m = &parsed.media[0];
            m.formats[..m.format_count as usize].to_vec()
        };
        assert_eq!(
            parse("m=audio 9 UDP/TLS/RTP/SAVPF 111 abc 96 200"),
            [111, 96]
        );
        assert!(parse("m=application 9 UDP/DTLS/SCTP webrtc-datachannel").is_empty());
        // A payload type above 127 in rtpmap is not a codec.
        let sdp = one_mline_with("a=rtpmap:200 opus/48000/2\na=rtpmap:111 opus/48000/2\n");
        let parsed = SdpParser::parse(&sdp).unwrap();
        assert_eq!(parsed.media[0].codec_count, 1);
        assert_eq!(
            parsed.media[0].codecs[0].as_ref().unwrap().payload_type,
            111
        );
    }

    #[test]
    fn test_non_ascii_input_is_an_error_not_a_panic() {
        let base = sdp_with_mlines(1, |i| i.to_string());
        let cases = [
            // Multi-byte type character: byte 2 is inside it.
            format!("{}€=x\n", base),
            format!("{}é\n", base),
            // Non-ASCII fingerprint of even byte length.
            base.replace("a=fingerprint:sha-256 AB", "a=fingerprint:sha-256 Aé:A"),
            base.replace("a=fingerprint:sha-256 AB:CD", "a=fingerprint:sha-256 éé:CD"),
        ];
        for sdp in &cases {
            assert!(SdpParser::parse(sdp).is_err(), "accepted: {sdp:?}");
        }
    }

    // ========================================================================
    // ICE Credential Validation Tests
    // ========================================================================

    #[test]
    fn test_parse_validates_ice_credentials() {
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:abc
a=ice-pwd:short
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let result = SdpParser::parse(sdp);
        assert!(matches!(
            result,
            Err(SdpError::InvalidIceCredentialLength { .. })
        ));
    }

    #[test]
    fn test_parse_validates_ufrag_min_length() {
        // ICE ufrag minimum is 4 chars per RFC 5245
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:abc
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let result = SdpParser::parse(sdp);
        assert!(matches!(
            result,
            Err(SdpError::InvalidIceCredentialLength { .. })
        ));
    }

    #[test]
    fn test_parse_validates_pwd_min_length() {
        // ICE pwd minimum is 22 chars per RFC 5245
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:short
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let result = SdpParser::parse(sdp);
        assert!(matches!(
            result,
            Err(SdpError::InvalidIceCredentialLength { .. })
        ));
    }

    // ========================================================================
    // Fingerprint Validation Tests
    // ========================================================================

    #[test]
    fn test_parse_validates_fingerprint_algorithm() {
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd1234567890123456
a=fingerprint:sha-1 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        // The sha-1 line is skipped, which leaves no usable fingerprint.
        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::MissingFingerprint)));
    }

    fn fingerprint_line(algorithm: &str, bytes: usize, byte: u8) -> String {
        let hex: Vec<String> = (0..bytes).map(|_| format!("{:02X}", byte)).collect();
        format!("a=fingerprint:{} {}", algorithm, hex.join(":"))
    }

    fn sdp_with_fingerprints(lines: &[String]) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
             a=ice-ufrag:testufrag\r\na=ice-pwd:testpwd1234567890123456\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n{}\r\n",
            lines.join("\r\n")
        )
    }

    #[test]
    fn test_several_fingerprints_keep_sha256() {
        use super::super::attributes::FingerprintAlgorithm;
        let sha1 = fingerprint_line("sha-1", 20, 0x11);
        let sha256 = fingerprint_line("sha-256", 32, 0x22);
        let sha384 = fingerprint_line("sha-384", 48, 0x33);
        let sha512 = fingerprint_line("sha-512", 64, 0x44);

        let kept = |lines: &[String]| {
            let session = SdpParser::parse(&sdp_with_fingerprints(lines)).unwrap();
            session.media[0].fingerprint.clone().unwrap()
        };
        // sha-1 first is skipped, sha-256 kept.
        let fp = kept(&[sha1.clone(), sha256.clone()]);
        assert_eq!(fp.algorithm, FingerprintAlgorithm::Sha256);
        assert_eq!(fp.value[..32], [0x22; 32]);
        // sha-256 wins over a later sha-384 and an earlier sha-512.
        assert_eq!(
            kept(&[sha256.clone(), sha384.clone()]).algorithm,
            FingerprintAlgorithm::Sha256
        );
        assert_eq!(
            kept(&[sha512.clone(), sha256]).algorithm,
            FingerprintAlgorithm::Sha256
        );
        // Without sha-256 the first usable line is kept, whole (no truncation).
        let fp = kept(&[sha384, sha512]);
        assert_eq!(fp.algorithm, FingerprintAlgorithm::Sha384);
        assert_eq!(fp.value_len, 48);
        // Only unsupported algorithms: no usable fingerprint.
        assert!(matches!(
            SdpParser::parse(&sdp_with_fingerprints(&[sha1])),
            Err(SdpError::MissingFingerprint)
        ));
    }

    #[test]
    fn test_parse_requires_fingerprint() {
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd1234567890123456
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::MissingFingerprint)));
    }

    #[test]
    fn test_parse_requires_ice_credentials() {
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let result = SdpParser::parse(sdp);
        assert!(matches!(
            result,
            Err(SdpError::MissingIceCredentials { .. })
        ));
    }

    // ========================================================================
    // Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_sdp_roundtrip() {
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        use super::super::session::SessionDescription;

        let mut sdp = SessionDescription::new(12345);
        sdp.set_session_name("Test");
        sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");

        let fp = DtlsFingerprint::parse(
            "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
        ).unwrap();
        sdp.set_fingerprint(fp);

        let mut media =
            MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
        media.mid = Some(Mid::new("0"));
        // Add a codec to have at least one format
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        sdp.add_media(media).unwrap();

        // Serialize
        let serialized = sdp.to_sdp().unwrap();

        // Parse back
        let reparsed = SdpParser::parse(&serialized).unwrap();

        // Verify
        assert_eq!(reparsed.media.len(), 1);
        assert!(reparsed.ice_ufrag.is_some());
        assert!(reparsed.fingerprint.is_some());
    }

    #[test]
    fn test_roundtrip_preserves_media_type() {
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        use super::super::session::SessionDescription;

        for media_type in [MediaType::Audio, MediaType::Video] {
            let mut sdp = SessionDescription::new(12345);
            sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
            let fp = DtlsFingerprint::parse(
                "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
            ).unwrap();
            sdp.set_fingerprint(fp);

            let mut media = MediaDescription::new(media_type, 9, TransportProtocol::UdpTlsRtpSavpf);
            media.mid = Some(Mid::new("0"));
            let pt = if media_type == MediaType::Audio {
                111
            } else {
                96
            };
            let codec_str = if media_type == MediaType::Audio {
                "opus/48000/2"
            } else {
                "VP8/90000"
            };
            let codec = RtpCodec::parse(pt, codec_str).unwrap();
            media.add_codec(codec).unwrap();
            sdp.add_media(media).unwrap();

            let serialized = sdp.to_sdp().unwrap();
            let reparsed = SdpParser::parse(&serialized).unwrap();

            assert_eq!(reparsed.media[0].media_type, media_type);
        }
    }

    #[test]
    fn test_roundtrip_preserves_direction() {
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        use super::super::session::SessionDescription;

        for direction in [
            Direction::SendRecv,
            Direction::SendOnly,
            Direction::RecvOnly,
            Direction::Inactive,
        ] {
            let mut sdp = SessionDescription::new(12345);
            sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
            let fp = DtlsFingerprint::parse(
                "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
            ).unwrap();
            sdp.set_fingerprint(fp);

            let mut media =
                MediaDescription::new(MediaType::Audio, 9, TransportProtocol::UdpTlsRtpSavpf);
            media.mid = Some(Mid::new("0"));
            media.direction = direction;
            let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
            media.add_codec(codec).unwrap();
            sdp.add_media(media).unwrap();

            let serialized = sdp.to_sdp().unwrap();
            let reparsed = SdpParser::parse(&serialized).unwrap();

            assert_eq!(reparsed.media[0].direction, direction);
        }
    }

    // ========================================================================
    // Malformed Input Tests
    // ========================================================================

    #[test]
    fn test_parse_malformed_line() {
        let sdp = "v=0\nmalformed line without equals\n";
        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::ParseError { .. })));
    }

    #[test]
    fn test_parse_invalid_version() {
        let sdp = "v=1\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n";
        let result = SdpParser::parse(sdp);
        assert!(matches!(
            result,
            Err(SdpError::InvalidVersion { version: 1 })
        ));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = SdpParser::parse("");
        // Empty SDP must be rejected — no valid session can come from nothing
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_whitespace_only() {
        let result = SdpParser::parse("   \n\n   \n");
        // RFC 8866 §5: whitespace-only SDP is missing mandatory v= and o= lines
        assert!(matches!(result, Err(SdpError::MissingField { .. })));
    }

    // ========================================================================
    // Media Type Tests
    // ========================================================================

    #[test]
    fn test_parse_audio_media() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        assert_eq!(parsed.media[0].media_type, MediaType::Audio);
    }

    #[test]
    fn test_parse_video_media() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:0
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        assert_eq!(parsed.media[0].media_type, MediaType::Video);
    }

    // ========================================================================
    // Codec Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_rtpmap() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=rtpmap:111 opus/48000/2
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert!(media.codec_count >= 1);
    }

    // ========================================================================
    // DTLS Setup Tests
    // ========================================================================

    #[test]
    fn test_parse_setup_active() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=setup:active
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        assert_eq!(parsed.setup, Some(DtlsSetup::Active));
    }

    #[test]
    fn test_parse_setup_passive() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=setup:passive
m=audio 9 UDP/TLS/RTP/SAVPF 111
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        assert_eq!(parsed.setup, Some(DtlsSetup::Passive));
    }

    // ========================================================================
    // SSRC Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_ssrc() {
        let sdp = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=ssrc:12345 cname:test
"#;

        let parsed = SdpParser::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert!(media.ssrc_count >= 1);
    }

    // ========================================================================
    // Media-Level ICE Credential Validation Tests (RFC 8445)
    // ========================================================================

    #[test]
    fn test_parse_validates_media_level_ufrag_min_length() {
        // ICE ufrag minimum is 4 chars per RFC 8445
        // This test verifies media-level ICE credentials are validated
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=ice-ufrag:abc
a=ice-pwd:testpwd12345678901234567890
"#;

        let result = SdpParser::parse(sdp);
        assert!(
            matches!(
                result,
                Err(SdpError::InvalidIceCredentialLength {
                    field: "ice-ufrag",
                    ..
                })
            ),
            "Expected InvalidIceCredentialLength for ice-ufrag, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_validates_media_level_pwd_min_length() {
        // ICE pwd minimum is 22 chars per RFC 8445
        // This test verifies media-level ICE credentials are validated
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=ice-ufrag:testufrag
a=ice-pwd:short
"#;

        let result = SdpParser::parse(sdp);
        assert!(
            matches!(
                result,
                Err(SdpError::InvalidIceCredentialLength {
                    field: "ice-pwd",
                    ..
                })
            ),
            "Expected InvalidIceCredentialLength for ice-pwd, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_accepts_valid_media_level_ice_credentials() {
        // Valid media-level ICE credentials should be accepted
        let sdp = r#"v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
"#;

        let result = SdpParser::parse(sdp);
        assert!(
            result.is_ok(),
            "Expected valid SDP to parse successfully, got {:?}",
            result
        );

        let parsed = result.unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.ice_ufrag.as_ref().unwrap().as_str(), "testufrag");
        assert_eq!(
            media.ice_pwd.as_ref().unwrap().as_str(),
            "testpwd12345678901234567890"
        );
    }

    // ========================================================================
    // RFC 8866 §5 — mandatory field validation
    // ========================================================================

    #[test]
    fn test_missing_version_line() {
        // SDP without v= line should fail
        let sdp = "o=- 12345 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::MissingField { field }) if field.contains("v=")));
    }

    #[test]
    fn test_missing_origin_line() {
        // SDP without o= line should fail
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\n";
        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::MissingField { field }) if field.contains("o=")));
    }

    // ========================================================================
    // Property-Based Tests (proptest)
    // ========================================================================

    #[cfg(test)]
    pub(crate) mod property_tests {
        use super::*;
        use proptest::prelude::*;

        // `PROPTEST_CASES` overrides the per-run default (e.g. 20000 for a deep run).
        pub(crate) fn env_cases(default: u32) -> u32 {
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        // Strategy for valid session IDs
        fn valid_session_id() -> impl Strategy<Value = u64> {
            1..u64::MAX
        }

        /// A valid session header and one m-line, then `lines`.
        fn with_header(lines: &[String]) -> String {
            let mut sdp = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
            sdp.push_str("m=audio 9 UDP/TLS/RTP/SAVPF 111\n");
            for line in lines {
                sdp.push_str(line);
                sdp.push('\n');
            }
            sdp
        }

        // Strategy for attribute values: any text, printable ASCII, or the
        // "<number> <token>[:<rest>]" shape of ssrc/extmap/rtpmap/fmtp/rtcp-fb values,
        // with lengths past every field's capacity (the longest is 256 bytes).
        pub(crate) fn attr_value() -> impl Strategy<Value = String> {
            prop_oneof![
                ".{0,300}",
                "[ -~]{0,300}",
                "[0-9]{1,11}(/[a-z]{1,8})? [a-z0-9:/.-]{1,300}( [ -~]{0,40})?",
                "[0-9]{1,11} [a-z-]{1,40}:[ -~]{0,300}",
            ]
        }

        // Strategy for attribute names: every name the parser handles, or a random one
        pub(crate) fn attr_name() -> impl Strategy<Value = String> {
            const NAMES: [&str; 27] = [
                "ice-ufrag",
                "ice-pwd",
                "ice-options",
                "ice-lite",
                "fingerprint",
                "setup",
                "sendrecv",
                "sendonly",
                "recvonly",
                "inactive",
                "rtcp-mux",
                "rtcp-rsize",
                "mid",
                "group",
                "rtpmap",
                "fmtp",
                "ssrc",
                "extmap",
                "candidate",
                "rtcp-fb",
                "ssrc-group",
                "rid",
                "simulcast",
                "msid",
                "rtcp-mux-only",
                "extmap-allow-mixed",
                "end-of-candidates",
            ];
            prop_oneof![
                3 => prop::sample::select(&NAMES[..]).prop_map(str::to_string),
                1 => "[a-z-]{1,14}",
            ]
        }

        // Strategy for valid ICE ufrag
        fn valid_ufrag() -> impl Strategy<Value = String> {
            prop::string::string_regex("[a-zA-Z0-9]{4,256}")
                .unwrap()
                .prop_filter("ufrag length", |s| {
                    s.len() >= MIN_ICE_UFRAG_LEN && s.len() <= MAX_ICE_UFRAG_LEN
                })
        }

        // Strategy for valid ICE pwd
        fn valid_pwd() -> impl Strategy<Value = String> {
            prop::string::string_regex("[a-zA-Z0-9]{22,256}")
                .unwrap()
                .prop_filter("pwd length", |s| {
                    s.len() >= MIN_ICE_PWD_LEN && s.len() <= MAX_ICE_PWD_LEN
                })
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: env_cases(50),
                ..ProptestConfig::default()
            })]

            #[test]
            fn prop_roundtrip_session_id(session_id in valid_session_id()) {
                use super::super::super::session::SessionDescription;
                use super::super::super::attributes::{DtlsFingerprint, RtpCodec};

                let mut sdp = SessionDescription::new(session_id);
                sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
                let fp = DtlsFingerprint::parse(
                    "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
                ).unwrap();
                sdp.set_fingerprint(fp);

                let mut media = MediaDescription::new(
                    MediaType::Audio,
                    9,
                    TransportProtocol::UdpTlsRtpSavpf,
                );
                media.mid = Some(Mid::new("0"));
                let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
                media.add_codec(codec).unwrap();
                sdp.add_media(media).unwrap();

                let serialized = sdp.to_sdp().unwrap();
                let reparsed = SdpParser::parse(&serialized).unwrap();

                prop_assert_eq!(reparsed.origin.session_id, session_id);
            }

            #[test]
            fn prop_roundtrip_ice_credentials(ufrag in valid_ufrag(), pwd in valid_pwd()) {
                use super::super::super::session::SessionDescription;
                use super::super::super::attributes::{DtlsFingerprint, RtpCodec};

                let mut sdp = SessionDescription::new(12345);
                sdp.set_ice_credentials(&ufrag, &pwd);
                let fp = DtlsFingerprint::parse(
                    "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
                ).unwrap();
                sdp.set_fingerprint(fp);

                let mut media = MediaDescription::new(
                    MediaType::Audio,
                    9,
                    TransportProtocol::UdpTlsRtpSavpf,
                );
                media.mid = Some(Mid::new("0"));
                let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
                media.add_codec(codec).unwrap();
                sdp.add_media(media).unwrap();

                let serialized = sdp.to_sdp().unwrap();
                let reparsed = SdpParser::parse(&serialized).unwrap();

                let parsed_ufrag = reparsed.ice_ufrag.as_ref().unwrap();
                prop_assert_eq!(parsed_ufrag.as_str(), ufrag.as_str());
            }

            /// Arbitrary lines (any Unicode) after a valid header never panic the parser
            /// (network input, exit criterion 6). The parser stops at the first error, so
            /// each shape of line gets its own property.
            #[test]
            fn prop_arbitrary_lines_never_panic(lines in prop::collection::vec(".{0,300}", 1..4)) {
                let _ = SdpParser::parse(&with_header(&lines));
            }

            /// "<any char>=<value>" lines reach the type dispatch with multi-byte types.
            #[test]
            fn prop_typed_lines_never_panic(
                typed in prop::collection::vec((any::<char>(), ".{0,300}"), 1..4),
            ) {
                let lines: Vec<String> =
                    typed.iter().map(|(c, v)| format!("{}={}", c, v)).collect();
                let _ = SdpParser::parse(&with_header(&lines));
            }

            /// Every attribute the parser handles, with arbitrary values.
            #[test]
            fn prop_attributes_never_panic(
                attrs in prop::collection::vec((attr_name(), attr_value()), 1..4),
            ) {
                let lines: Vec<String> =
                    attrs.iter().map(|(n, v)| format!("a={}:{}", n, v)).collect();
                let _ = SdpParser::parse(&with_header(&lines));
            }

            /// Fingerprint values after a valid algorithm name (the hex decoder).
            #[test]
            fn prop_fingerprint_values_never_panic(value in ".{0,300}") {
                let lines = [format!("a=fingerprint:sha-256 {}", value)];
                let _ = SdpParser::parse(&with_header(&lines));
            }

            #[test]
            fn prop_media_count_bounded(count in 1usize..=MAX_MEDIA_SECTIONS) {
                use super::super::super::session::SessionDescription;
                use super::super::super::attributes::{DtlsFingerprint, RtpCodec};

                let mut sdp = SessionDescription::new(12345);
                sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
                let fp = DtlsFingerprint::parse(
                    "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
                ).unwrap();
                sdp.set_fingerprint(fp);

                for i in 0..count {
                    let mut media = MediaDescription::new(
                        MediaType::Audio,
                        9,
                        TransportProtocol::UdpTlsRtpSavpf,
                    );
                    media.mid = Some(Mid::new(&i.to_string()));
                    let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
                    media.add_codec(codec).unwrap();
                    sdp.add_media(media).unwrap();
                }

                let serialized = sdp.to_sdp().unwrap();
                let reparsed = SdpParser::parse(&serialized).unwrap();

                prop_assert_eq!(reparsed.media.len(), count);
                prop_assert!(reparsed.media.len() <= MAX_MEDIA_SECTIONS);
            }

            #[test]
            fn prop_invalid_ufrag_rejected(ufrag in "[a-z]{1,3}") {
                // Ufrag too short should be rejected
                let sdp = format!(
                    "v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n\
                     a=ice-ufrag:{}\na=ice-pwd:testpwd1234567890123456\n\
                     a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n\
                     m=audio 9 UDP/TLS/RTP/SAVPF 111\n",
                    ufrag
                );

                let result = SdpParser::parse(&sdp);
                prop_assert!(result.is_err());
            }
        }
    }
}
