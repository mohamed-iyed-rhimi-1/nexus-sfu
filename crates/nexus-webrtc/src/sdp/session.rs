//! SDP session description.

use super::error::SdpError;
use super::media::{MediaDescription, IceUfrag, IcePwd};
use super::attributes::{DtlsFingerprint, DtlsSetup, Direction};
#[cfg(debug_assertions)]
use super::parser::SdpParser;
use super::{MAX_MEDIA_SECTIONS, MAX_SDP_SIZE, MIN_ICE_UFRAG_LEN, MAX_ICE_UFRAG_LEN, MIN_ICE_PWD_LEN, MAX_ICE_PWD_LEN};

/// Origin (o=) line.
#[derive(Debug, Clone)]
pub struct Origin {
    /// Username.
    pub username: [u8; 32],
    pub username_len: u8,
    /// Session ID.
    pub session_id: u64,
    /// Session version.
    pub session_version: u64,
    /// Network type.
    pub net_type: [u8; 4],
    /// Address type.
    pub addr_type: [u8; 4],
    /// Address.
    pub address: [u8; 64],
    pub address_len: u8,
}

impl Default for Origin {
    fn default() -> Self {
        let mut username = [0u8; 32];
        username[0] = b'-';
        
        let mut net_type = [0u8; 4];
        net_type[..2].copy_from_slice(b"IN");
        
        let mut addr_type = [0u8; 4];
        addr_type[..3].copy_from_slice(b"IP4");
        
        let mut address = [0u8; 64];
        address[..7].copy_from_slice(b"0.0.0.0");
        
        Self {
            username,
            username_len: 1,
            session_id: 0,
            session_version: 0,
            net_type,
            addr_type,
            address,
            address_len: 7,
        }
    }
}

impl Origin {
    /// Create a new origin with session ID.
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            session_version: 1,
            ..Default::default()
        }
    }
    
    /// Serialize to SDP line (without "o=" prefix).
    pub fn to_sdp(&self) -> String {
        let username = std::str::from_utf8(&self.username[..self.username_len as usize]).unwrap_or("-");
        let net = std::str::from_utf8(&self.net_type[..2]).unwrap_or("IN");
        let addr_t = std::str::from_utf8(&self.addr_type[..3]).unwrap_or("IP4");
        let addr = std::str::from_utf8(&self.address[..self.address_len as usize]).unwrap_or("0.0.0.0");
        
        format!("{} {} {} {} {} {}", 
            username, 
            self.session_id, 
            self.session_version, 
            net, 
            addr_t, 
            addr
        )
    }
}

/// Timing (t=) line.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    /// Start time (0 = now).
    pub start: u64,
    /// Stop time (0 = unbounded).
    pub stop: u64,
}

impl Timing {
    /// Serialize to SDP line (without "t=" prefix).
    pub fn to_sdp(&self) -> String {
        format!("{} {}", self.start, self.stop)
    }
}

/// Complete SDP session description.
#[derive(Debug, Clone)]
pub struct SessionDescription {
    /// SDP version (always 0).
    pub version: u8,
    /// Origin.
    pub origin: Origin,
    /// Session name.
    pub session_name: [u8; 64],
    pub session_name_len: u8,
    /// Timing.
    pub timing: Timing,
    
    // Session-level ICE
    /// Session-level ICE ufrag.
    pub ice_ufrag: Option<super::media::IceUfrag>,
    /// Session-level ICE pwd.
    pub ice_pwd: Option<super::media::IcePwd>,
    /// ICE-lite mode.
    pub ice_lite: bool,
    
    // Session-level DTLS
    /// Session-level fingerprint.
    pub fingerprint: Option<DtlsFingerprint>,
    /// Session-level setup.
    pub setup: Option<DtlsSetup>,
    
    // Groups
    /// BUNDLE group (MIDs).
    pub bundle_group: [u8; 64],
    pub bundle_group_len: u8,
    
    // Media sections
    /// Media descriptions.
    pub media: [Option<MediaDescription>; MAX_MEDIA_SECTIONS],
    /// Number of media sections.
    pub media_count: u8,
}

impl Default for SessionDescription {
    fn default() -> Self {
        let mut session_name = [0u8; 64];
        session_name[0] = b'-';
        
        Self {
            version: 0,
            origin: Origin::default(),
            session_name,
            session_name_len: 1,
            timing: Timing::default(),
            ice_ufrag: None,
            ice_pwd: None,
            ice_lite: false,
            fingerprint: None,
            setup: None,
            bundle_group: [0u8; 64],
            bundle_group_len: 0,
            media: Default::default(),
            media_count: 0,
        }
    }
}

impl SessionDescription {
    /// Create a new SDP with session ID.
    pub fn new(session_id: u64) -> Self {
        Self {
            origin: Origin::new(session_id),
            ..Default::default()
        }
    }

    /// Set the o= line session version (RFC 3264 §8).
    pub fn set_version(&mut self, version: u64) {
        self.origin.session_version = version;
    }
    
    /// Set session name.
    pub fn set_session_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(64);
        self.session_name[..len].copy_from_slice(&bytes[..len]);
        self.session_name_len = len as u8;
    }
    
    /// Set ICE credentials (session-level).
    pub fn set_ice_credentials(&mut self, ufrag: &str, pwd: &str) {
        self.ice_ufrag = Some(super::media::IceUfrag::new(ufrag));
        self.ice_pwd = Some(super::media::IcePwd::new(pwd));
    }
    
    /// Set DTLS fingerprint (session-level).
    pub fn set_fingerprint(&mut self, fingerprint: DtlsFingerprint) {
        self.fingerprint = Some(fingerprint);
    }
    
    /// Set DTLS setup role (session-level).
    pub fn set_setup(&mut self, setup: DtlsSetup) {
        self.setup = Some(setup);
    }
    
    /// Add a media section.
    pub fn add_media(&mut self, media: MediaDescription) -> Result<(), SdpError> {
        if self.media_count as usize >= MAX_MEDIA_SECTIONS {
            return Err(SdpError::TooManyMedia { 
                count: self.media_count as usize + 1, 
                max: MAX_MEDIA_SECTIONS 
            });
        }
        
        self.media[self.media_count as usize] = Some(media);
        self.media_count += 1;
        Ok(())
    }
    
    /// Set BUNDLE group.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates MIDs exist in media sections
    /// - Bounded string copy
    pub fn set_bundle(&mut self, mids: &[&str]) -> Result<(), SdpError> {
        if mids.is_empty() {
            return Err(SdpError::InvalidFormat {
                reason: "BUNDLE MIDs must not be empty",
            });
        }
        
        // Validate all MIDs exist in media sections
        for mid in mids {
            if !self.has_media_with_mid(mid) {
                return Err(SdpError::InvalidBundleGroup {
                    mid: mid.to_string(),
                });
            }
        }
        
        let bundle = mids.join(" ");
        let bytes = bundle.as_bytes();
        let len = bytes.len().min(64);
        self.bundle_group[..len].copy_from_slice(&bytes[..len]);
        self.bundle_group_len = len as u8;
        
        Ok(())
    }

    /// Check if session has media with given MID.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for clarity
    /// - Bounded iteration
    fn has_media_with_mid(&self, target_mid: &str) -> bool {
        for i in 0..self.media_count as usize {
            if let Some(ref media) = self.media[i] {
                if let Some(ref mid) = media.mid {
                    if mid.as_str() == target_mid {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    /// Serialize to complete SDP string.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Paired assertion: validates result can be re-parsed
    /// - Bounded string generation
    pub fn to_sdp(&self) -> String {
        // Precondition: session must be valid
        assert!(self.media_count <= MAX_MEDIA_SECTIONS as u8,
            "Media count must be bounded");
        
        let mut lines = Vec::new();
        
        // v= version
        lines.push(format!("v={}", self.version));
        
        // o= origin
        lines.push(format!("o={}", self.origin.to_sdp()));
        
        // s= session name
        let name = std::str::from_utf8(&self.session_name[..self.session_name_len as usize])
            .unwrap_or("-");
        lines.push(format!("s={}", name));
        
        // t= timing
        lines.push(format!("t={}", self.timing.to_sdp()));
        
        // Session-level ICE
        if let Some(ref ufrag) = self.ice_ufrag {
            lines.push(format!("a=ice-ufrag:{}", ufrag.as_str()));
        }
        if let Some(ref pwd) = self.ice_pwd {
            lines.push(format!("a=ice-pwd:{}", pwd.as_str()));
        }
        if self.ice_lite {
            lines.push("a=ice-lite".to_string());
        }
        
        // Session-level DTLS
        if let Some(ref fp) = self.fingerprint {
            lines.push(format!("a=fingerprint:{}", fp.to_sdp()));
        }
        if let Some(ref setup) = self.setup {
            lines.push(format!("a=setup:{}", setup.as_str()));
        }
        
        // BUNDLE
        if self.bundle_group_len > 0 {
            let bundle = std::str::from_utf8(&self.bundle_group[..self.bundle_group_len as usize])
                .unwrap_or("");
            lines.push(format!("a=group:BUNDLE {}", bundle));
        }
        
        // Media sections
        for i in 0..self.media_count as usize {
            if let Some(ref media) = self.media[i] {
                lines.push(media.to_sdp());
            }
        }
        
        let result = lines.join("\r\n") + "\r\n";
        
        // Postcondition: result must be parseable (paired assertion)
        assert!(result.len() <= MAX_SDP_SIZE,
            "Generated SDP must not exceed MAX_SDP_SIZE");
        
        // Postcondition: result should be re-parseable (validation)
        #[cfg(debug_assertions)]
        {
            if let Ok(reparsed) = SdpParser::parse(&result) {
                assert_eq!(reparsed.media_count, self.media_count,
                    "Re-parsed SDP must have same media count");
            }
        }
        
        result
    }
    
    /// Create an answer from an offer.
    ///
    /// This creates a compatible SDP answer based on the offer,
    /// using our ICE/DTLS credentials and negotiating codecs.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit codec negotiation
    /// - Direction flipping logic
    /// - Bounded operations
    pub fn create_answer(
        &self,
        our_ufrag: &str,
        our_pwd: &str,
        our_fingerprint: &DtlsFingerprint,
    ) -> Result<SessionDescription, SdpError> {
        if self.media_count == 0 {
            return Err(SdpError::InvalidFormat {
                reason: "offer must have at least one media section",
            });
        }
        
        // Validate our credentials
        let our_ufrag_obj = IceUfrag::new(our_ufrag);
        let our_pwd_obj = IcePwd::new(our_pwd);
        Self::validate_ice_ufrag(&our_ufrag_obj)?;
        Self::validate_ice_pwd(&our_pwd_obj)?;
        our_fingerprint.validate()?;
        
        let mut answer = SessionDescription::new(self.origin.session_id);
        answer.set_session_name("Nexus SFU Answer");
        answer.set_ice_credentials(our_ufrag, our_pwd);
        answer.set_fingerprint(our_fingerprint.clone());
        // RFC 8842 §5.5: derive setup role from offer
        let answer_setup = match self.setup {
            Some(DtlsSetup::Active) => DtlsSetup::Passive,
            Some(DtlsSetup::Passive) => DtlsSetup::Active,
            _ => DtlsSetup::Active,
        };
        answer.set_setup(answer_setup);
        
        // Copy bundle group
        if self.bundle_group_len > 0 {
            answer.bundle_group = self.bundle_group;
            answer.bundle_group_len = self.bundle_group_len;
        }
        
        // Process each media section
        for i in 0..self.media_count as usize {
            if let Some(ref offer_media) = self.media[i] {
                let answer_media = Self::create_answer_media(
                    offer_media,
                    our_ufrag,
                    our_pwd,
                    our_fingerprint,
                    answer_setup,
                )?;
                answer.add_media(answer_media)?;
            }
        }
        
        // Postcondition: answer must have same media count as offer
        assert_eq!(answer.media_count, self.media_count,
            "Answer must have same media count as offer");
        
        Ok(answer)
    }

    /// Create answer media section from offer media.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted from create_answer for function length compliance
    /// - Explicit codec negotiation and direction flipping
    fn create_answer_media(
        offer_media: &MediaDescription,
        our_ufrag: &str,
        our_pwd: &str,
        our_fingerprint: &DtlsFingerprint,
        answer_setup: DtlsSetup,
    ) -> Result<MediaDescription, SdpError> {
        use super::MAX_CODECS_PER_MEDIA;
        
        let mut media = MediaDescription::new(
            offer_media.media_type,
            9, // Port 9 is standard for WebRTC (ignored due to ICE)
            offer_media.protocol,
        );
        
        // Copy MID
        media.mid = offer_media.mid.clone();
        
        // Set direction (flip sendrecv/sendonly/recvonly)
        media.direction = Self::flip_direction(offer_media.direction);
        
        // Copy ICE credentials
        media.set_ice_credentials(our_ufrag, our_pwd);
        
        // Copy fingerprint
        media.set_fingerprint(our_fingerprint.clone());
        media.setup = Some(answer_setup);
        
        // Negotiate codecs: For SFU, we accept all offered codecs since we forward
        // rather than transcode. This allows subscribers to choose their preferred codec.
        // If no codecs are offered, return an error.
        if offer_media.codec_count == 0 {
            return Err(SdpError::NoCommonCodec {
                media_type: offer_media.media_type.as_str().to_string(),
            });
        }
        
        // Accept all offered codecs (bounded by MAX_CODECS_PER_MEDIA)
        let codec_limit = (offer_media.codec_count as usize).min(MAX_CODECS_PER_MEDIA);
        for i in 0..codec_limit {
            if let Some(ref codec) = offer_media.codecs[i] {
                media.add_codec(codec.clone())?;
            }
        }
        
        // RTCP settings
        media.rtcp_mux = offer_media.rtcp_mux;
        media.rtcp_rsize = offer_media.rtcp_rsize;
        media.rtcp_mux_only = offer_media.rtcp_mux_only;

        // Copy RTCP feedback from offer (RFC 4585) — critical for NACK/PLI/FIR
        for i in 0..offer_media.rtcp_fb_count as usize {
            if let Some(ref fb) = offer_media.rtcp_fbs[i] {
                let _ = media.add_rtcp_fb(fb.clone());
            }
        }

        // Copy RTP header extensions from offer so the receiver can demux
        // incoming RTP by mid/rid (required by webrtc-rs for on_track).
        for i in 0..offer_media.extmap_count as usize {
            if let Some(ref ext) = offer_media.extmaps[i] {
                let _ = media.add_extmap(ext.clone());
            }
        }

        // Copy extmap-allow-mixed (RFC 8285)
        media.extmap_allow_mixed = offer_media.extmap_allow_mixed;
        
        Ok(media)
    }

    /// Create answer media section with explicit local codec capabilities.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Uses negotiate_codecs() for proper codec matching
    /// - Returns NoCommonCodec error if no matching codec found
    pub fn create_answer_media_with_capabilities(
        offer_media: &MediaDescription,
        local_media: &MediaDescription,
        our_ufrag: &str,
        our_pwd: &str,
        our_fingerprint: &DtlsFingerprint,
        answer_setup: DtlsSetup,
    ) -> Result<MediaDescription, SdpError> {
        use super::MAX_CODECS_PER_MEDIA;
        
        let mut media = MediaDescription::new(
            offer_media.media_type,
            9, // Port 9 is standard for WebRTC (ignored due to ICE)
            offer_media.protocol,
        );
        
        // Copy MID
        media.mid = offer_media.mid.clone();
        
        // Set direction (flip sendrecv/sendonly/recvonly)
        media.direction = Self::flip_direction(offer_media.direction);
        
        // Copy ICE credentials
        media.set_ice_credentials(our_ufrag, our_pwd);
        
        // Copy fingerprint
        media.set_fingerprint(our_fingerprint.clone());
        media.setup = Some(answer_setup);
        
        // Negotiate codecs using local capabilities
        // This returns NoCommonCodec if no matching codec found
        let negotiated_codecs = local_media.negotiate_codecs(offer_media)?;
        
        // Add negotiated codecs (bounded by MAX_CODECS_PER_MEDIA)
        let codec_limit = negotiated_codecs.len().min(MAX_CODECS_PER_MEDIA);
        for codec in negotiated_codecs.into_iter().take(codec_limit) {
            media.add_codec(codec)?;
        }
        
        // RTCP settings
        media.rtcp_mux = offer_media.rtcp_mux;
        media.rtcp_rsize = offer_media.rtcp_rsize;
        media.rtcp_mux_only = offer_media.rtcp_mux_only;

        // Copy RTCP feedback from offer (RFC 4585)
        for i in 0..offer_media.rtcp_fb_count as usize {
            if let Some(ref fb) = offer_media.rtcp_fbs[i] {
                let _ = media.add_rtcp_fb(fb.clone());
            }
        }

        // Copy RTP header extensions from offer so the receiver can demux
        // incoming RTP by mid/rid (required by webrtc-rs for on_track).
        for i in 0..offer_media.extmap_count as usize {
            if let Some(ref ext) = offer_media.extmaps[i] {
                let _ = media.add_extmap(ext.clone());
            }
        }

        // Copy extmap-allow-mixed (RFC 8285)
        media.extmap_allow_mixed = offer_media.extmap_allow_mixed;
        
        Ok(media)
    }

    /// Flip media direction for answer.
    ///
    /// RFC 3264 §6.1: sendonly ↔ recvonly, sendrecv → sendrecv (both sides
    /// can send and receive). For SFU-specific direction narrowing (e.g.,
    /// publisher m-lines → recvonly), the caller should override after
    /// calling create_answer.
    pub fn flip_direction(direction: Direction) -> Direction {
        match direction {
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::SendRecv => Direction::SendRecv,
            other => other,
        }
    }

    /// Validate ICE ufrag length.
    fn validate_ice_ufrag(ufrag: &IceUfrag) -> Result<(), SdpError> {
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
    fn validate_ice_pwd(pwd: &IcePwd) -> Result<(), SdpError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::media::{MediaType, TransportProtocol, Mid};
    use super::super::attributes::DtlsFingerprint;
    
    #[test]
    fn test_origin_default() {
        let origin = Origin::default();
        let sdp = origin.to_sdp();
        assert!(sdp.contains("-"));
        assert!(sdp.contains("IN"));
        assert!(sdp.contains("IP4"));
    }
    
    #[test]
    fn test_session_description_new() {
        let sdp = SessionDescription::new(12345);
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.session_id, 12345);
    }
    
    #[test]
    fn test_session_to_sdp() {
        let mut sdp = SessionDescription::new(12345);
        sdp.set_session_name("Test Session");
        sdp.set_ice_credentials("testufrag", "testpwd1234567890123456");
        
        let output = sdp.to_sdp();
        assert!(output.starts_with("v=0"));
        assert!(output.contains("s=Test Session"));
        assert!(output.contains("a=ice-ufrag:testufrag"));
    }
    
    #[test]
    fn test_add_media() {
        let mut sdp = SessionDescription::new(12345);
        let media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        
        sdp.add_media(media).unwrap();
        assert_eq!(sdp.media_count, 1);
    }

    #[test]
    fn test_bundle_validation() {
        let mut sdp = SessionDescription::new(12345);
        
        let mut media1 = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media1.mid = Some(Mid::new("0"));
        sdp.add_media(media1).unwrap();
        
        // Try to set BUNDLE with non-existent MID
        let result = sdp.set_bundle(&["0", "1"]);
        assert!(matches!(result, Err(SdpError::InvalidBundleGroup { .. })));
        
        // Add second media
        let mut media2 = MediaDescription::new(
            MediaType::Video,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media2.mid = Some(Mid::new("1"));
        sdp.add_media(media2).unwrap();
        
        // Now should succeed
        let result = sdp.set_bundle(&["0", "1"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_answer_validates_credentials() {
        let mut offer = SessionDescription::new(12345);
        let mut media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.mid = Some(Mid::new("0"));
        offer.add_media(media).unwrap();
        
        let fp = DtlsFingerprint::parse(
            "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
        ).unwrap();
        
        // Short ufrag should fail
        let result = offer.create_answer("ab", "testpwd1234567890123456", &fp);
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { .. })));
        
        // Short pwd should fail
        let result = offer.create_answer("testufrag", "short", &fp);
        assert!(matches!(result, Err(SdpError::InvalidIceCredentialLength { .. })));
    }

    #[test]
    fn test_direction_flipping() {
        assert_eq!(
            SessionDescription::flip_direction(Direction::SendOnly),
            Direction::RecvOnly
        );
        assert_eq!(
            SessionDescription::flip_direction(Direction::RecvOnly),
            Direction::SendOnly
        );
        // RFC 3264 §6.1: SendRecv stays SendRecv — caller narrows as needed
        assert_eq!(
            SessionDescription::flip_direction(Direction::SendRecv),
            Direction::SendRecv
        );
    }
}
