//! SDP parser.

use super::attributes::{
    IceCandidate, DtlsFingerprint, DtlsSetup, RtpCodec, SsrcInfo, Fmtp, Direction, ExtMap,
};
use super::error::SdpError;
use super::media::{MediaDescription, MediaType, TransportProtocol, IceUfrag, IcePwd, Mid};
use super::session::{SessionDescription, Origin, Timing};
use super::{MAX_SDP_SIZE, MAX_MEDIA_SECTIONS, MIN_ICE_UFRAG_LEN, MAX_ICE_UFRAG_LEN, MIN_ICE_PWD_LEN, MAX_ICE_PWD_LEN};

/// SDP parser.
pub struct SdpParser;

impl SdpParser {
    /// Parse an SDP string into a SessionDescription.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded parsing (max 8 media sections)
    /// - Explicit error handling
    /// - Precondition/postcondition assertions
    pub fn parse(sdp: &str) -> Result<SessionDescription, SdpError> {
        // Precondition: SDP must not exceed maximum size
        assert!(sdp.len() <= MAX_SDP_SIZE,
            "SDP size must be <= MAX_SDP_SIZE");
        
        if sdp.len() > MAX_SDP_SIZE {
            return Err(SdpError::TooLarge { 
                size: sdp.len(), 
                max: MAX_SDP_SIZE 
            });
        }
        
        let mut session = SessionDescription::default();
        let mut current_media: Option<MediaDescription> = None;
        let mut line_num = 0u32;
        
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
            )?;
        }
        
        // Save final media section
        if let Some(media) = current_media {
            session.add_media(media)?;
        }
        
        // Validate required fields
        Self::validate_session(&session)?;
        
        // Postcondition: media count must be bounded
        assert!(session.media_count <= MAX_MEDIA_SECTIONS as u8,
            "Media count must be <= MAX_MEDIA_SECTIONS");
        
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
    ) -> Result<(), SdpError> {
        let line = line.trim();
        
        if line.is_empty() {
            return Ok(());
        }
        
        if line.len() < 2 || line.chars().nth(1) != Some('=') {
            // Malformed line - return error instead of silently skipping
            return Err(SdpError::ParseError {
                line: line_num,
                message: "malformed line (expected 'x=')".to_string(),
            });
        }
        
        let type_char = line.chars().next().unwrap();
        let value = &line[2..];
        
        match type_char {
            'v' => Self::parse_version(value, line_num, session)?,
            'o' => session.origin = Self::parse_origin(value, line_num)?,
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
        let version = value.parse::<u8>()
            .map_err(|_| SdpError::ParseError { 
                line: line_num, 
                message: "invalid version".to_string() 
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
        if session.media_count >= MAX_MEDIA_SECTIONS as u8 {
            return Err(SdpError::TooManyMedia {
                count: session.media_count as usize + 1,
                max: MAX_MEDIA_SECTIONS,
            });
        }
        
        // Parse new media section
        *current_media = Some(Self::parse_media_line(value, line_num)?);
        Ok(())
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
            for i in 0..session.media_count as usize {
                if let Some(ref media) = session.media[i] {
                    if media.ice_ufrag.is_none() || media.ice_pwd.is_none() {
                        return Err(SdpError::MissingIceCredentials {
                            field: "ice-ufrag or ice-pwd",
                        });
                    }
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
        for i in 0..session.media_count as usize {
            if let Some(ref media) = session.media[i] {
                if let Some(ref ufrag) = media.ice_ufrag {
                    Self::validate_ice_ufrag(ufrag)?;
                }
                if let Some(ref pwd) = media.ice_pwd {
                    Self::validate_ice_pwd(pwd)?;
                }
            }
        }
        
        // For WebRTC, we need either session-level or media-level fingerprint
        let has_session_fp = session.fingerprint.is_some();
        
        if !has_session_fp {
            // Check if all media sections have fingerprint
            for i in 0..session.media_count as usize {
                if let Some(ref media) = session.media[i] {
                    if media.fingerprint.is_none() {
                        return Err(SdpError::MissingFingerprint);
                    }
                }
            }
        }
        
        // Validate fingerprints are SHA-256
        if let Some(ref fp) = session.fingerprint {
            fp.validate()?;
        }
        
        for i in 0..session.media_count as usize {
            if let Some(ref media) = session.media[i] {
                if let Some(ref fp) = media.fingerprint {
                    fp.validate()?;
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
        if session.bundle_group_len == 0 {
            return Ok(());
        }
        
        let bundle_str = std::str::from_utf8(
            &session.bundle_group[..session.bundle_group_len as usize]
        ).unwrap_or("");
        
        // Parse BUNDLE MIDs and validate each exists
        for mid in bundle_str.split_whitespace() {
            let mut found = false;
            for i in 0..session.media_count as usize {
                if let Some(ref media) = session.media[i] {
                    if let Some(ref media_mid) = media.mid {
                        if media_mid.as_str() == mid {
                            found = true;
                            break;
                        }
                    }
                }
            }
            
            if !found {
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
                message: "invalid origin".to_string() 
            });
        }
        
        let mut origin = Origin::default();
        
        // Username
        let username_bytes = parts[0].as_bytes();
        let username_len = username_bytes.len().min(32);
        origin.username[..username_len].copy_from_slice(&username_bytes[..username_len]);
        origin.username_len = username_len as u8;
        
        // Session ID
        origin.session_id = parts[1].parse()
            .map_err(|_| SdpError::ParseError { 
                line: line_num, 
                message: "invalid session id".to_string() 
            })?;
        
        // Session version
        origin.session_version = parts[2].parse()
            .map_err(|_| SdpError::ParseError { 
                line: line_num, 
                message: "invalid session version".to_string() 
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
                message: "invalid timing".to_string() 
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
                message: "invalid media line".to_string() 
            });
        }
        
        let media_type = MediaType::parse(parts[0])
            .ok_or(SdpError::InvalidMediaType { media_type: parts[0].to_string() })?;
        
        let port = parts[1].parse::<u16>()
            .map_err(|_| SdpError::ParseError { 
                line: line_num, 
                message: "invalid port".to_string() 
            })?;
        
        let protocol = TransportProtocol::parse(parts[2])
            .ok_or(SdpError::InvalidTransport { transport: parts[2].to_string() })?;
        
        let mut media = MediaDescription::new(media_type, port, protocol);
        
        // Parse format list
        for (i, fmt) in parts[3..].iter().enumerate() {
            if i >= 32 {
                break;
            }
            if let Ok(pt) = fmt.parse::<u8>() {
                media.formats[i] = pt;
                media.format_count = (i + 1) as u8;
            }
        }
        
        Ok(media)
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
                    if let Some(ref mut media) = current_media {
                        media.ice_ufrag = Some(IceUfrag::new(v));
                    } else {
                        session.ice_ufrag = Some(IceUfrag::new(v));
                    }
                }
            }
            
            "ice-pwd" => {
                if let Some(v) = attr_value {
                    if let Some(ref mut media) = current_media {
                        media.ice_pwd = Some(IcePwd::new(v));
                    } else {
                        session.ice_pwd = Some(IcePwd::new(v));
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
                    let fp = DtlsFingerprint::parse(v)?;
                    if let Some(ref mut media) = current_media {
                        media.fingerprint = Some(fp);
                    } else {
                        session.fingerprint = Some(fp);
                    }
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
                        media.mid = Some(Mid::new(v));
                    }
                }
            }
            
            // Group
            "group" => {
                if let Some(v) = attr_value {
                    if let Some(bundle) = v.strip_prefix("BUNDLE ") {
                        let bytes = bundle.as_bytes();
                        let len = bytes.len().min(64);
                        session.bundle_group[..len].copy_from_slice(&bytes[..len]);
                        session.bundle_group_len = len as u8;
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
                        if let Ok(ssrc) = SsrcInfo::parse(v) {
                            let _ = media.add_ssrc(ssrc);
                        }
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

                            if let Ok(id) = id_str.parse::<u8>() {
                                let uri_bytes = uri_str.as_bytes();
                                let uri_len = uri_bytes.len().min(128);
                                let mut uri = [0u8; 128];
                                uri[..uri_len].copy_from_slice(&uri_bytes[..uri_len]);

                                let extmap = ExtMap {
                                    id,
                                    direction,
                                    uri,
                                    uri_len: uri_len as u8,
                                };
                                let _ = media.add_extmap(extmap);
                            }
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
            
            _ => {
                // Ignore unknown attributes
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::media::Mid;
    
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
        assert_eq!(parsed.media_count, 1);
        
        let media = parsed.media[0].as_ref().unwrap();
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
        
        let media = parsed.media[0].as_ref().unwrap();
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
        assert_eq!(parsed.media_count, 2);
    }

    // ========================================================================
    // Bounds and Limits Tests (TigerStyle)
    // ========================================================================

    #[test]
    fn test_parse_enforces_max_media_sections() {
        let mut sdp = String::from("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
        sdp.push_str("a=ice-ufrag:testufrag\na=ice-pwd:testpwd1234567890123456\n");
        sdp.push_str("a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90\n");
        
        // Add 9 media sections (exceeds limit of 8)
        for i in 0..9 {
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
        
        // Add exactly MAX_MEDIA_SECTIONS (8)
        for i in 0..MAX_MEDIA_SECTIONS {
            sdp.push_str(&format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:{}\n", i));
        }
        
        let result = SdpParser::parse(&sdp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().media_count, MAX_MEDIA_SECTIONS as u8);
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
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { .. })));
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
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { .. })));
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
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { .. })));
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
        
        let result = SdpParser::parse(sdp);
        assert!(matches!(result, Err(SdpError::UnsupportedFingerprintAlgorithm { .. })));
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
        assert!(matches!(result, Err(SdpError::MissingIceCredentials { .. })));
    }

    // ========================================================================
    // Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_sdp_roundtrip() {
        use super::super::session::SessionDescription;
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        
        let mut sdp = SessionDescription::new(12345);
        sdp.set_session_name("Test");
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
        // Add a codec to have at least one format
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        media.add_codec(codec).unwrap();
        sdp.add_media(media).unwrap();
        
        // Serialize
        let serialized = sdp.to_sdp();
        
        // Parse back
        let reparsed = SdpParser::parse(&serialized).unwrap();
        
        // Verify
        assert_eq!(reparsed.media_count, 1);
        assert!(reparsed.ice_ufrag.is_some());
        assert!(reparsed.fingerprint.is_some());
    }

    #[test]
    fn test_roundtrip_preserves_media_type() {
        use super::super::session::SessionDescription;
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        
        for media_type in [MediaType::Audio, MediaType::Video] {
            let mut sdp = SessionDescription::new(12345);
            sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
            let fp = DtlsFingerprint::parse(
                "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
            ).unwrap();
            sdp.set_fingerprint(fp);
            
            let mut media = MediaDescription::new(
                media_type,
                9,
                TransportProtocol::UdpTlsRtpSavpf,
            );
            media.mid = Some(Mid::new("0"));
            let pt = if media_type == MediaType::Audio { 111 } else { 96 };
            let codec_str = if media_type == MediaType::Audio { "opus/48000/2" } else { "VP8/90000" };
            let codec = RtpCodec::parse(pt, codec_str).unwrap();
            media.add_codec(codec).unwrap();
            sdp.add_media(media).unwrap();
            
            let serialized = sdp.to_sdp();
            let reparsed = SdpParser::parse(&serialized).unwrap();
            
            assert_eq!(reparsed.media[0].as_ref().unwrap().media_type, media_type);
        }
    }

    #[test]
    fn test_roundtrip_preserves_direction() {
        use super::super::session::SessionDescription;
        use super::super::attributes::{DtlsFingerprint, RtpCodec};
        
        for direction in [Direction::SendRecv, Direction::SendOnly, Direction::RecvOnly, Direction::Inactive] {
            let mut sdp = SessionDescription::new(12345);
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
            media.direction = direction;
            let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
            media.add_codec(codec).unwrap();
            sdp.add_media(media).unwrap();
            
            let serialized = sdp.to_sdp();
            let reparsed = SdpParser::parse(&serialized).unwrap();
            
            assert_eq!(reparsed.media[0].as_ref().unwrap().direction, direction);
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
        assert!(matches!(result, Err(SdpError::InvalidVersion { version: 1 })));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = SdpParser::parse("");
        // Empty SDP currently succeeds with default values (no mandatory field validation)
        // This is acceptable for WebRTC where validation focuses on ICE/DTLS
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_whitespace_only() {
        let result = SdpParser::parse("   \n\n   \n");
        // Whitespace-only SDP is parsed as empty lines
        assert!(result.is_ok());
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
        assert_eq!(parsed.media[0].as_ref().unwrap().media_type, MediaType::Audio);
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
        assert_eq!(parsed.media[0].as_ref().unwrap().media_type, MediaType::Video);
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
        let media = parsed.media[0].as_ref().unwrap();
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
        let media = parsed.media[0].as_ref().unwrap();
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
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { field: "ice-ufrag", .. })),
            "Expected InvalidIceCredentialLength for ice-ufrag, got {:?}", result);
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
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { field: "ice-pwd", .. })),
            "Expected InvalidIceCredentialLength for ice-pwd, got {:?}", result);
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
        assert!(result.is_ok(), "Expected valid SDP to parse successfully, got {:?}", result);
        
        let parsed = result.unwrap();
        let media = parsed.media[0].as_ref().unwrap();
        assert_eq!(media.ice_ufrag.as_ref().unwrap().as_str(), "testufrag");
        assert_eq!(media.ice_pwd.as_ref().unwrap().as_str(), "testpwd12345678901234567890");
    }

    // ========================================================================
    // Property-Based Tests (proptest)
    // ========================================================================

    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        
        // Strategy for valid session IDs
        fn valid_session_id() -> impl Strategy<Value = u64> {
            1..u64::MAX
        }
        
        // Strategy for valid ICE ufrag
        fn valid_ufrag() -> impl Strategy<Value = String> {
            prop::string::string_regex("[a-zA-Z0-9]{4,256}")
                .unwrap()
                .prop_filter("ufrag length", |s| s.len() >= MIN_ICE_UFRAG_LEN && s.len() <= MAX_ICE_UFRAG_LEN)
        }
        
        // Strategy for valid ICE pwd
        fn valid_pwd() -> impl Strategy<Value = String> {
            prop::string::string_regex("[a-zA-Z0-9]{22,256}")
                .unwrap()
                .prop_filter("pwd length", |s| s.len() >= MIN_ICE_PWD_LEN && s.len() <= MAX_ICE_PWD_LEN)
        }
        
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            
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
                
                let serialized = sdp.to_sdp();
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
                
                let serialized = sdp.to_sdp();
                let reparsed = SdpParser::parse(&serialized).unwrap();
                
                let parsed_ufrag = reparsed.ice_ufrag.as_ref().unwrap();
                prop_assert_eq!(parsed_ufrag.as_str(), ufrag.as_str());
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
                
                let serialized = sdp.to_sdp();
                let reparsed = SdpParser::parse(&serialized).unwrap();
                
                prop_assert_eq!(reparsed.media_count as usize, count);
                prop_assert!(reparsed.media_count <= MAX_MEDIA_SECTIONS as u8);
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
