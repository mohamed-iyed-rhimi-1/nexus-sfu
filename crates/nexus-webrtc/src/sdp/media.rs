//! SDP media description.

use super::attributes::{
    IceCandidate, DtlsFingerprint, DtlsSetup, RtpCodec, RtcpFeedback,
    SsrcInfo, ExtMap, Fmtp, Direction,
};
use super::error::SdpError;
use super::{MAX_CODECS_PER_MEDIA, MAX_CANDIDATES_PER_MEDIA, MAX_SSRCS_PER_MEDIA, MAX_EXTMAPS_PER_MEDIA,
            MAX_RTCP_FB_PER_MEDIA, MAX_SSRC_GROUPS_PER_MEDIA, MAX_RIDS_PER_MEDIA};

/// Media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Application,
}

impl MediaType {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "audio" => Some(MediaType::Audio),
            "video" => Some(MediaType::Video),
            "application" => Some(MediaType::Application),
            _ => None,
        }
    }
    
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::Audio => "audio",
            MediaType::Video => "video",
            MediaType::Application => "application",
        }
    }
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// UDP/TLS/RTP/SAVPF (WebRTC standard).
    UdpTlsRtpSavpf,
    /// RTP/SAVPF.
    RtpSavpf,
    /// RTP/AVP.
    RtpAvp,
    /// DTLS/SCTP (DataChannel).
    DtlsSctp,
    /// UDP/DTLS/SCTP (newer DataChannel).
    UdpDtlsSctp,
}

impl TransportProtocol {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "UDP/TLS/RTP/SAVPF" => Some(TransportProtocol::UdpTlsRtpSavpf),
            "RTP/SAVPF" => Some(TransportProtocol::RtpSavpf),
            "RTP/AVP" => Some(TransportProtocol::RtpAvp),
            "DTLS/SCTP" => Some(TransportProtocol::DtlsSctp),
            "UDP/DTLS/SCTP" => Some(TransportProtocol::UdpDtlsSctp),
            _ => None,
        }
    }
    
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportProtocol::UdpTlsRtpSavpf => "UDP/TLS/RTP/SAVPF",
            TransportProtocol::RtpSavpf => "RTP/SAVPF",
            TransportProtocol::RtpAvp => "RTP/AVP",
            TransportProtocol::DtlsSctp => "DTLS/SCTP",
            TransportProtocol::UdpDtlsSctp => "UDP/DTLS/SCTP",
        }
    }
}

/// Media description (m= section).
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type.
    pub media_type: MediaType,
    /// Port number.
    pub port: u16,
    /// Number of ports (usually 1).
    pub num_ports: u16,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Format/payload type list.
    pub formats: [u8; 32],
    /// Number of formats.
    pub format_count: u8,
    
    // Connection info
    /// Connection address.
    pub connection: Option<ConnectionInfo>,
    
    // ICE attributes
    /// ICE ufrag.
    pub ice_ufrag: Option<IceUfrag>,
    /// ICE pwd.
    pub ice_pwd: Option<IcePwd>,
    /// ICE options.
    pub ice_options: IceOptions,
    /// ICE candidates.
    pub candidates: [Option<IceCandidate>; MAX_CANDIDATES_PER_MEDIA],
    /// Number of candidates.
    pub candidate_count: u8,
    
    // DTLS attributes
    /// DTLS fingerprint.
    pub fingerprint: Option<DtlsFingerprint>,
    /// DTLS setup role.
    pub setup: Option<DtlsSetup>,
    
    // Media direction
    /// Direction.
    pub direction: Direction,
    
    // MID
    /// Media ID.
    pub mid: Option<Mid>,
    
    // RTP/RTCP attributes
    /// Codecs.
    pub codecs: [Option<RtpCodec>; MAX_CODECS_PER_MEDIA],
    /// Number of codecs.
    pub codec_count: u8,
    /// Format parameters.
    pub fmtps: [Option<Fmtp>; MAX_CODECS_PER_MEDIA],
    /// Number of fmtps.
    pub fmtp_count: u8,
    /// SSRC info.
    pub ssrcs: [Option<SsrcInfo>; MAX_SSRCS_PER_MEDIA],
    /// Number of SSRCs.
    pub ssrc_count: u8,
    /// SSRC values extracted for easy access (used by orchestrator).
    /// Bounded to MAX_SSRCS_PER_MEDIA (10).
    pub ssrc_values: [u32; MAX_SSRCS_PER_MEDIA],
    /// Number of SSRC values.
    pub ssrc_values_count: u8,
    /// Header extensions.
    pub extmaps: [Option<ExtMap>; MAX_EXTMAPS_PER_MEDIA],
    /// Number of extmaps.
    pub extmap_count: u8,
    
    // RTCP feedback (RFC 4585)
    /// RTCP feedback entries.
    pub rtcp_fbs: [Option<RtcpFeedback>; MAX_RTCP_FB_PER_MEDIA],
    /// Number of rtcp-fb entries.
    pub rtcp_fb_count: u8,
    
    // SSRC groups (RFC 5576)
    /// SSRC group entries (e.g., FID for RTX, SIM for simulcast).
    pub ssrc_groups: [Option<SsrcGroup>; MAX_SSRC_GROUPS_PER_MEDIA],
    /// Number of SSRC groups.
    pub ssrc_group_count: u8,
    
    // RID (RFC 8851)
    /// RID entries for simulcast.
    pub rids: [Option<Rid>; MAX_RIDS_PER_MEDIA],
    /// Number of RID entries.
    pub rid_count: u8,
    
    // Simulcast (RFC 8853)
    /// Simulcast attribute value (raw).
    pub simulcast: Option<SimulcastAttr>,
    
    // Standalone msid (RFC 8830)
    /// Media stream ID.
    pub msid: Option<Msid>,
    
    // RTCP
    /// RTCP-mux enabled.
    pub rtcp_mux: bool,
    /// RTCP-rsize enabled.
    pub rtcp_rsize: bool,
    /// RTCP-mux-only (RFC 8858).
    pub rtcp_mux_only: bool,
    
    // Misc
    /// extmap-allow-mixed (RFC 8285).
    pub extmap_allow_mixed: bool,
    /// end-of-candidates (RFC 8838).
    pub end_of_candidates: bool,
}

/// ICE ufrag (RFC 8445 §5.3: up to 256 ice-chars).
#[derive(Debug, Clone)]
pub struct IceUfrag {
    pub value: [u8; 256],
    pub len: u16,
}

impl IceUfrag {
    pub fn new(s: &str) -> Self {
        let mut value = [0u8; 256];
        let bytes = s.as_bytes();
        let len = bytes.len().min(256);
        value[..len].copy_from_slice(&bytes[..len]);
        Self { value, len: len as u16 }
    }
    
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.value[..self.len as usize]).unwrap_or("")
    }
}

/// ICE pwd (RFC 8445 §5.3: up to 256 ice-chars).
#[derive(Debug, Clone)]
pub struct IcePwd {
    pub value: [u8; 256],
    pub len: u16,
}

impl IcePwd {
    pub fn new(s: &str) -> Self {
        let mut value = [0u8; 256];
        let bytes = s.as_bytes();
        let len = bytes.len().min(256);
        value[..len].copy_from_slice(&bytes[..len]);
        Self { value, len: len as u16 }
    }
    
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.value[..self.len as usize]).unwrap_or("")
    }
}

/// ICE options.
#[derive(Debug, Clone, Default)]
pub struct IceOptions {
    pub trickle: bool,
    pub ice_lite: bool,
}

/// Media ID.
#[derive(Debug, Clone)]
pub struct Mid {
    pub value: [u8; 16],
    pub len: u8,
}

impl Mid {
    pub fn new(s: &str) -> Self {
        let mut value = [0u8; 16];
        let bytes = s.as_bytes();
        let len = bytes.len().min(16);
        value[..len].copy_from_slice(&bytes[..len]);
        Self { value, len: len as u8 }
    }
    
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.value[..self.len as usize]).unwrap_or("")
    }
}

/// SSRC group (RFC 5576, e.g., FID for RTX, SIM for simulcast).
#[derive(Debug, Clone, PartialEq)]
pub struct SsrcGroup {
    /// Semantics (e.g., "FID", "SIM").
    pub semantics: [u8; 16],
    pub semantics_len: u8,
    /// SSRC values in the group.
    pub ssrcs: [u32; 8],
    pub ssrc_count: u8,
}

/// RID entry (RFC 8851).
#[derive(Debug, Clone, PartialEq)]
pub struct Rid {
    /// RID identifier.
    pub id: [u8; 32],
    pub id_len: u8,
    /// Direction (send or recv).
    pub direction: Direction,
}

/// Simulcast attribute (RFC 8853).
#[derive(Debug, Clone, PartialEq)]
pub struct SimulcastAttr {
    /// Raw simulcast value.
    pub value: [u8; 256],
    pub value_len: u16,
}

/// Standalone msid (RFC 8830).
#[derive(Debug, Clone, PartialEq)]
pub struct Msid {
    /// Stream ID.
    pub stream_id: [u8; 128],
    pub stream_id_len: u8,
    /// Track ID (optional).
    pub track_id: [u8; 128],
    pub track_id_len: u8,
}

/// Connection info.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Network type (always "IN").
    pub net_type: [u8; 4],
    /// Address type ("IP4" or "IP6").
    pub addr_type: [u8; 4],
    /// Address.
    pub address: [u8; 64],
    pub address_len: u8,
}

impl Default for MediaDescription {
    fn default() -> Self {
        Self {
            media_type: MediaType::Audio,
            port: 9,
            num_ports: 1,
            protocol: TransportProtocol::UdpTlsRtpSavpf,
            formats: [0u8; 32],
            format_count: 0,
            connection: None,
            ice_ufrag: None,
            ice_pwd: None,
            ice_options: IceOptions::default(),
            candidates: Default::default(),
            candidate_count: 0,
            fingerprint: None,
            setup: None,
            direction: Direction::SendRecv,
            mid: None,
            codecs: Default::default(),
            codec_count: 0,
            fmtps: Default::default(),
            fmtp_count: 0,
            ssrcs: Default::default(),
            ssrc_count: 0,
            ssrc_values: [0u32; MAX_SSRCS_PER_MEDIA],
            ssrc_values_count: 0,
            extmaps: Default::default(),
            extmap_count: 0,
            rtcp_fbs: Default::default(),
            rtcp_fb_count: 0,
            ssrc_groups: Default::default(),
            ssrc_group_count: 0,
            rids: Default::default(),
            rid_count: 0,
            simulcast: None,
            msid: None,
            rtcp_mux: true,
            rtcp_rsize: false,
            rtcp_mux_only: false,
            extmap_allow_mixed: false,
            end_of_candidates: false,
        }
    }
}

impl MediaDescription {
    /// Create a new media description.
    pub fn new(media_type: MediaType, port: u16, protocol: TransportProtocol) -> Self {
        Self {
            media_type,
            port,
            protocol,
            ..Default::default()
        }
    }
    
    /// Add a codec.
    pub fn add_codec(&mut self, codec: RtpCodec) -> Result<(), SdpError> {
        if self.codec_count as usize >= MAX_CODECS_PER_MEDIA {
            return Err(SdpError::TooManyCodecs { 
                count: self.codec_count as usize + 1, 
                max: MAX_CODECS_PER_MEDIA 
            });
        }
        
        // Also add the payload type to formats list
        if (self.format_count as usize) < 32 {
            self.formats[self.format_count as usize] = codec.payload_type;
            self.format_count += 1;
        }
        
        self.codecs[self.codec_count as usize] = Some(codec);
        self.codec_count += 1;
        Ok(())
    }
    
    /// Add a format parameter (fmtp).
    pub fn add_fmtp(&mut self, fmtp: Fmtp) -> Result<(), SdpError> {
        if self.fmtp_count as usize >= MAX_CODECS_PER_MEDIA {
            return Err(SdpError::TooManyCodecs { 
                count: self.fmtp_count as usize + 1, 
                max: MAX_CODECS_PER_MEDIA 
            });
        }
        
        self.fmtps[self.fmtp_count as usize] = Some(fmtp);
        self.fmtp_count += 1;
        Ok(())
    }
    
    /// Add an ICE candidate.
    pub fn add_candidate(&mut self, candidate: IceCandidate) -> Result<(), SdpError> {
        if self.candidate_count as usize >= MAX_CANDIDATES_PER_MEDIA {
            return Err(SdpError::TooManyCandidates { 
                count: self.candidate_count as usize + 1, 
                max: MAX_CANDIDATES_PER_MEDIA 
            });
        }
        
        self.candidates[self.candidate_count as usize] = Some(candidate);
        self.candidate_count += 1;
        Ok(())
    }
    
    /// Add SSRC info.
    pub fn add_ssrc(&mut self, ssrc: SsrcInfo) -> Result<(), SdpError> {
        if self.ssrc_count as usize >= MAX_SSRCS_PER_MEDIA {
            return Err(SdpError::TooManyCodecs { 
                count: self.ssrc_count as usize + 1, 
                max: MAX_SSRCS_PER_MEDIA 
            });
        }
        
        // Add to detailed SSRC info
        self.ssrcs[self.ssrc_count as usize] = Some(ssrc.clone());
        
        // Add to values array for easy access (deduplicate)
        if (self.ssrc_values_count as usize) < MAX_SSRCS_PER_MEDIA {
            let ssrc_val = ssrc.ssrc;
            if !self.ssrc_values[..self.ssrc_values_count as usize].contains(&ssrc_val) {
                self.ssrc_values[self.ssrc_values_count as usize] = ssrc_val;
                self.ssrc_values_count += 1;
            }
        }
        
        self.ssrc_count += 1;
        Ok(())
    }
    
    /// Get SSRC values as a vector for easy access.
    ///
    /// Returns a vector of unique SSRC values from this media description.
    /// Used by the orchestrator for track registration.
    ///
    /// # Returns
    ///
    /// Vector of SSRC values (bounded to MAX_SSRCS_PER_MEDIA).
    pub fn get_ssrc_values(&self) -> Vec<u32> {
        assert!(self.ssrc_values_count <= MAX_SSRCS_PER_MEDIA as u8,
            "SSRC values count must be bounded");
        
        self.ssrc_values[..self.ssrc_values_count as usize].to_vec()
    }
    
    /// Set ICE credentials.
    pub fn set_ice_credentials(&mut self, ufrag: &str, pwd: &str) {
        self.ice_ufrag = Some(IceUfrag::new(ufrag));
        self.ice_pwd = Some(IcePwd::new(pwd));
    }
    
    /// Set DTLS fingerprint.
    pub fn set_fingerprint(&mut self, fingerprint: DtlsFingerprint) {
        self.fingerprint = Some(fingerprint);
    }

    /// Add an RTP header extension mapping.
    pub fn add_extmap(&mut self, extmap: ExtMap) -> Result<(), SdpError> {
        if self.extmap_count as usize >= MAX_EXTMAPS_PER_MEDIA {
            return Err(SdpError::TooManyCodecs {
                count: self.extmap_count as usize + 1,
                max: MAX_EXTMAPS_PER_MEDIA,
            });
        }

        self.extmaps[self.extmap_count as usize] = Some(extmap);
        self.extmap_count += 1;
        Ok(())
    }

    /// Add an RTCP feedback entry (RFC 4585).
    pub fn add_rtcp_fb(&mut self, fb: RtcpFeedback) -> Result<(), SdpError> {
        if self.rtcp_fb_count as usize >= MAX_RTCP_FB_PER_MEDIA {
            return Ok(()); // Silently drop excess — not fatal
        }
        self.rtcp_fbs[self.rtcp_fb_count as usize] = Some(fb);
        self.rtcp_fb_count += 1;
        Ok(())
    }

    /// Add an SSRC group (RFC 5576).
    pub fn add_ssrc_group(&mut self, group: SsrcGroup) -> Result<(), SdpError> {
        if self.ssrc_group_count as usize >= MAX_SSRC_GROUPS_PER_MEDIA {
            return Ok(());
        }
        self.ssrc_groups[self.ssrc_group_count as usize] = Some(group);
        self.ssrc_group_count += 1;
        Ok(())
    }

    /// Add a RID entry (RFC 8851).
    pub fn add_rid(&mut self, rid: Rid) -> Result<(), SdpError> {
        if self.rid_count as usize >= MAX_RIDS_PER_MEDIA {
            return Ok(());
        }
        self.rids[self.rid_count as usize] = Some(rid);
        self.rid_count += 1;
        Ok(())
    }

    /// Find matching codec from offer.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit codec matching logic
    /// - Bounded iteration over codecs
    /// - Returns first match (simple negotiation)
    pub fn find_matching_codec(&self, offer_codec: &RtpCodec) -> Option<RtpCodec> {
        // Precondition: codec count must be bounded
        assert!(self.codec_count <= MAX_CODECS_PER_MEDIA as u8,
            "Codec count must be bounded");
        
        for i in 0..self.codec_count as usize {
            if let Some(ref codec) = self.codecs[i] {
                if Self::codecs_match(codec, offer_codec) {
                    return Some(codec.clone());
                }
            }
        }
        
        None
    }

    /// Check if two codecs match.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for clarity
    /// - Explicit matching criteria
    pub fn codecs_match(a: &RtpCodec, b: &RtpCodec) -> bool {
        // Match by name and clock rate
        let a_name = std::str::from_utf8(&a.name[..a.name_len as usize])
            .unwrap_or("");
        let b_name = std::str::from_utf8(&b.name[..b.name_len as usize])
            .unwrap_or("");
        
        a_name.eq_ignore_ascii_case(b_name) && a.clock_rate == b.clock_rate
    }

    /// Negotiate codecs with offer.
    ///
    /// Returns list of common codecs in preference order.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded result (max 16 codecs)
    /// - Explicit negotiation logic
    pub fn negotiate_codecs(
        &self,
        offer_media: &MediaDescription,
    ) -> Result<Vec<RtpCodec>, SdpError> {
        if self.codec_count == 0 {
            return Err(SdpError::NoCommonCodec {
                media_type: self.media_type.as_str().to_string(),
            });
        }
        if offer_media.codec_count == 0 {
            return Err(SdpError::NoCommonCodec {
                media_type: offer_media.media_type.as_str().to_string(),
            });
        }
        
        let mut common_codecs = Vec::new();
        
        // Iterate through offer codecs (their preference order)
        for i in 0..offer_media.codec_count as usize {
            if let Some(ref offer_codec) = offer_media.codecs[i] {
                if let Some(matching) = self.find_matching_codec(offer_codec) {
                    common_codecs.push(matching);
                    
                    // Bounded result
                    if common_codecs.len() >= MAX_CODECS_PER_MEDIA {
                        break;
                    }
                }
            }
        }
        
        if common_codecs.is_empty() {
            return Err(SdpError::NoCommonCodec {
                media_type: self.media_type.as_str().to_string(),
            });
        }
        
        // Postcondition: result must be bounded
        assert!(common_codecs.len() <= MAX_CODECS_PER_MEDIA,
            "Common codecs must be bounded");
        
        Ok(common_codecs)
    }
    
    /// Serialize to SDP lines.
    pub fn to_sdp(&self) -> String {
        let mut lines = Vec::new();
        
        // m= line
        let formats: Vec<String> = self.formats[..self.format_count as usize]
            .iter()
            .map(|f| f.to_string())
            .collect();
        lines.push(format!(
            "m={} {} {} {}",
            self.media_type.as_str(),
            self.port,
            self.protocol.as_str(),
            formats.join(" ")
        ));
        
        // c= line
        if let Some(ref conn) = self.connection {
            let addr = std::str::from_utf8(&conn.address[..conn.address_len as usize]).unwrap_or("");
            lines.push(format!("c=IN IP4 {}", addr));
        } else {
            lines.push("c=IN IP4 0.0.0.0".to_string());
        }
        
        // ICE attributes
        if let Some(ref ufrag) = self.ice_ufrag {
            lines.push(format!("a=ice-ufrag:{}", ufrag.as_str()));
        }
        if let Some(ref pwd) = self.ice_pwd {
            lines.push(format!("a=ice-pwd:{}", pwd.as_str()));
        }
        if self.ice_options.trickle {
            lines.push("a=ice-options:trickle".to_string());
        }
        
        // DTLS attributes
        if let Some(ref fp) = self.fingerprint {
            lines.push(format!("a=fingerprint:{}", fp.to_sdp()));
        }
        if let Some(ref setup) = self.setup {
            lines.push(format!("a=setup:{}", setup.as_str()));
        }
        
        // Direction
        lines.push(format!("a={}", self.direction.as_str()));
        
        // MID
        if let Some(ref mid) = self.mid {
            lines.push(format!("a=mid:{}", mid.as_str()));
        }
        
        // RTCP
        if self.rtcp_mux {
            lines.push("a=rtcp-mux".to_string());
        }
        if self.rtcp_rsize {
            lines.push("a=rtcp-rsize".to_string());
        }
        
        // Codecs
        for i in 0..self.codec_count as usize {
            if let Some(ref codec) = self.codecs[i] {
                lines.push(format!("a=rtpmap:{}", codec.to_sdp()));
            }
        }
        
        // Fmtps
        for i in 0..self.fmtp_count as usize {
            if let Some(ref fmtp) = self.fmtps[i] {
                let params = std::str::from_utf8(&fmtp.params[..fmtp.params_len as usize]).unwrap_or("");
                lines.push(format!("a=fmtp:{} {}", fmtp.payload_type, params));
            }
        }
        
        // SSRCs
        for i in 0..self.ssrc_count as usize {
            if let Some(ref ssrc) = self.ssrcs[i] {
                let attr = std::str::from_utf8(&ssrc.attribute[..ssrc.attr_len as usize]).unwrap_or("");
                let val = std::str::from_utf8(&ssrc.value[..ssrc.value_len as usize]).unwrap_or("");
                lines.push(format!("a=ssrc:{} {}:{}", ssrc.ssrc, attr, val));
            }
        }
        
        // Header extensions (extmaps)
        for i in 0..self.extmap_count as usize {
            if let Some(ref ext) = self.extmaps[i] {
                let uri = std::str::from_utf8(&ext.uri[..ext.uri_len as usize]).unwrap_or("");
                lines.push(format!("a=extmap:{} {}", ext.id, uri));
            }
        }

        // Candidates
        for i in 0..self.candidate_count as usize {
            if let Some(ref candidate) = self.candidates[i] {
                lines.push(format!("a=candidate:{}", candidate.to_sdp()));
            }
        }
        
        lines.join("\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::attributes::RtpCodec;
    
    #[test]
    fn test_media_type_parse() {
        assert_eq!(MediaType::parse("audio"), Some(MediaType::Audio));
        assert_eq!(MediaType::parse("video"), Some(MediaType::Video));
        assert_eq!(MediaType::parse("application"), Some(MediaType::Application));
    }
    
    #[test]
    fn test_transport_protocol_parse() {
        assert_eq!(
            TransportProtocol::parse("UDP/TLS/RTP/SAVPF"),
            Some(TransportProtocol::UdpTlsRtpSavpf)
        );
    }
    
    #[test]
    fn test_media_description_default() {
        let media = MediaDescription::default();
        assert_eq!(media.media_type, MediaType::Audio);
        assert!(media.rtcp_mux);
    }
    
    #[test]
    fn test_ice_credentials() {
        let mut media = MediaDescription::default();
        media.set_ice_credentials("testufrag", "testpwd123456789012345678");
        
        assert_eq!(media.ice_ufrag.as_ref().unwrap().as_str(), "testufrag");
        assert!(media.ice_pwd.as_ref().unwrap().as_str().starts_with("testpwd"));
    }

    #[test]
    fn test_codec_matching() {
        let codec1 = RtpCodec::parse(111, "opus/48000/2").unwrap();
        let codec2 = RtpCodec::parse(112, "opus/48000/2").unwrap();
        let codec3 = RtpCodec::parse(113, "PCMU/8000").unwrap();
        
        assert!(MediaDescription::codecs_match(&codec1, &codec2));
        assert!(!MediaDescription::codecs_match(&codec1, &codec3));
    }

    #[test]
    fn test_codec_negotiation() {
        let mut offer_media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        offer_media.add_codec(RtpCodec::parse(111, "opus/48000/2").unwrap()).unwrap();
        offer_media.add_codec(RtpCodec::parse(0, "PCMU/8000").unwrap()).unwrap();
        
        let mut answer_media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        answer_media.add_codec(RtpCodec::parse(0, "PCMU/8000").unwrap()).unwrap();
        answer_media.add_codec(RtpCodec::parse(111, "opus/48000/2").unwrap()).unwrap();
        
        let common = answer_media.negotiate_codecs(&offer_media).unwrap();
        
        // Should have 2 common codecs in offer's preference order
        assert_eq!(common.len(), 2);
        assert_eq!(common[0].payload_type, 111); // opus first (offer's preference)
    }

    #[test]
    fn test_ssrc_values_extraction() {
        let mut media = MediaDescription::new(
            MediaType::Video,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        
        // Add SSRC info
        let ssrc1 = SsrcInfo::parse("12345 cname:test1").unwrap();
        let ssrc2 = SsrcInfo::parse("12346 cname:test2").unwrap();
        let ssrc3 = SsrcInfo::parse("12345 msid:test3").unwrap(); // Duplicate SSRC
        
        media.add_ssrc(ssrc1).unwrap();
        media.add_ssrc(ssrc2).unwrap();
        media.add_ssrc(ssrc3).unwrap(); // Should be deduplicated
        
        // Check SSRC values
        let values = media.get_ssrc_values();
        assert_eq!(values.len(), 2); // Should deduplicate
        assert!(values.contains(&12345));
        assert!(values.contains(&12346));
        
        // Check counts
        assert_eq!(media.ssrc_count, 3); // All SSRC info entries
        assert_eq!(media.ssrc_values_count, 2); // Unique values
    }

    #[test]
    fn test_ssrc_values_empty() {
        let media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        
        let values = media.get_ssrc_values();
        assert_eq!(values.len(), 0);
        assert_eq!(media.ssrc_values_count, 0);
    }

    #[test]
    fn test_ssrc_values_max_limit() {
        use super::MAX_SSRCS_PER_MEDIA;
        
        let mut media = MediaDescription::new(
            MediaType::Video,
            1,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        
        // Add maximum SSRCs (MAX_SSRCS_PER_MEDIA = 8)
        for i in 1..=MAX_SSRCS_PER_MEDIA {
            let ssrc = SsrcInfo::parse(&format!("{} cname:test", i * 1000)).unwrap();
            media.add_ssrc(ssrc).unwrap();
        }
        
        let values = media.get_ssrc_values();
        assert_eq!(values.len(), MAX_SSRCS_PER_MEDIA);
        assert_eq!(media.ssrc_values_count, MAX_SSRCS_PER_MEDIA as u8);
        
        // Try to add one more (should fail)
        let extra_ssrc = SsrcInfo::parse("99999 cname:extra").unwrap();
        let result = media.add_ssrc(extra_ssrc);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_matching_codec() {
        let mut media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        media.add_codec(RtpCodec::parse(111, "opus/48000/2").unwrap()).unwrap();
        media.add_codec(RtpCodec::parse(0, "PCMU/8000").unwrap()).unwrap();
        
        let offer_codec = RtpCodec::parse(99, "opus/48000/2").unwrap();
        let matching = media.find_matching_codec(&offer_codec);
        
        assert!(matching.is_some());
        assert_eq!(matching.unwrap().payload_type, 111);
    }

    #[test]
    fn test_no_common_codec_error() {
        let mut offer_media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        offer_media.add_codec(RtpCodec::parse(111, "opus/48000/2").unwrap()).unwrap();
        
        let mut answer_media = MediaDescription::new(
            MediaType::Audio,
            9,
            TransportProtocol::UdpTlsRtpSavpf,
        );
        answer_media.add_codec(RtpCodec::parse(0, "PCMU/8000").unwrap()).unwrap();
        
        let result = answer_media.negotiate_codecs(&offer_media);
        assert!(matches!(result, Err(SdpError::NoCommonCodec { .. })));
    }
}
