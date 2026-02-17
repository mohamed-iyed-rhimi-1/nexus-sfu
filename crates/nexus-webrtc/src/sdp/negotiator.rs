//! SDP offer/answer negotiation for WebRTC.
//!
//! Implements RFC 3264 offer/answer model with codec negotiation,
//! ICE credential exchange, and DTLS fingerprint handling.
//!
//! # TigerStyle Compliance
//!
//! - Bounded codec lists (max 16 per media)
//! - Explicit error handling
//! - Minimum 2 assertions per function

use super::attributes::{DtlsFingerprint, DtlsSetup, RtpCodec};
use super::error::SdpError;
use super::media::{MediaDescription, MediaType};
use super::parser::SdpParser;
use super::printer::SdpPrinter;
use super::session::SessionDescription;
use super::MAX_CODECS_PER_MEDIA;

/// Supported codec types for negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecType {
    /// Opus audio codec (RFC 6716).
    Opus,
    /// VP8 video codec.
    Vp8,
    /// VP9 video codec.
    Vp9,
    /// H.264 video codec.
    H264,
    /// AV1 video codec.
    Av1,
}

impl CodecType {
    /// Get codec name as used in SDP rtpmap.
    pub fn name(&self) -> &'static str {
        match self {
            CodecType::Opus => "opus",
            CodecType::Vp8 => "VP8",
            CodecType::Vp9 => "VP9",
            CodecType::H264 => "H264",
            CodecType::Av1 => "AV1",
        }
    }

    /// Get default clock rate for codec.
    pub fn clock_rate(&self) -> u32 {
        match self {
            CodecType::Opus => 48000,
            CodecType::Vp8 | CodecType::Vp9 | CodecType::H264 | CodecType::Av1 => 90000,
        }
    }

    /// Get default channels (for audio codecs).
    pub fn channels(&self) -> Option<u8> {
        match self {
            CodecType::Opus => Some(2),
            _ => None,
        }
    }

    /// Check if this is an audio codec.
    pub fn is_audio(&self) -> bool {
        matches!(self, CodecType::Opus)
    }

    /// Check if this is a video codec.
    pub fn is_video(&self) -> bool {
        !self.is_audio()
    }

    /// Parse codec type from name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "opus" => Some(CodecType::Opus),
            "vp8" => Some(CodecType::Vp8),
            "vp9" => Some(CodecType::Vp9),
            "h264" => Some(CodecType::H264),
            "av1" => Some(CodecType::Av1),
            _ => None,
        }
    }
}

/// Codec capability for negotiation.
#[derive(Debug, Clone)]
pub struct CodecCapability {
    /// Codec type.
    pub codec_type: CodecType,
    /// Preferred payload type.
    pub payload_type: u8,
    /// Clock rate.
    pub clock_rate: u32,
    /// Number of channels (audio only).
    pub channels: Option<u8>,
    /// Format parameters (fmtp).
    pub fmtp: Option<String>,
}

impl CodecCapability {
    /// Create a new codec capability.
    pub fn new(codec_type: CodecType, payload_type: u8) -> Self {
        Self {
            codec_type,
            payload_type,
            clock_rate: codec_type.clock_rate(),
            channels: codec_type.channels(),
            fmtp: None,
        }
    }

    /// Create with format parameters.
    pub fn with_fmtp(mut self, fmtp: &str) -> Self {
        self.fmtp = Some(fmtp.to_string());
        self
    }

    /// Convert to RtpCodec for SDP.
    pub fn to_rtp_codec(&self) -> RtpCodec {
        let codec_str = if let Some(ch) = self.channels {
            format!("{}/{}/{}", self.codec_type.name(), self.clock_rate, ch)
        } else {
            format!("{}/{}", self.codec_type.name(), self.clock_rate)
        };
        RtpCodec::parse(self.payload_type, &codec_str)
            .expect("CodecCapability should produce valid RtpCodec")
    }
}

/// Default supported codecs for Nexus SFU.
pub fn default_supported_codecs() -> Vec<CodecCapability> {
    vec![
        // Audio
        CodecCapability::new(CodecType::Opus, 111),
        // Video (in preference order)
        CodecCapability::new(CodecType::Vp8, 96),
        CodecCapability::new(CodecType::Vp9, 98),
        CodecCapability::new(CodecType::H264, 102),
        CodecCapability::new(CodecType::Av1, 35),
    ]
}

/// Recycled m-line descriptor for renegotiation offers.
///
/// Contains the exact codecs and extensions negotiated in the initial
/// offer/answer exchange, per JSEP §5.2.2.
#[derive(Debug, Clone)]
pub struct RecycledMline<'a> {
    pub mid: &'a str,
    pub media_kind: u8,
    pub codecs: &'a [RtpCodec],
    pub fmtps: &'a [super::Fmtp],
    /// All PTs from the client's original offer for this m-line.
    /// Chrome's BUNDLE demuxer may still associate these with this m-line
    /// even if our answer didn't include them (RFC 8843 §9.2).
    pub offer_pts: &'a [u8],
    pub extmaps: &'a [super::ExtMap],
    /// Direction from the server's answer. Recycled m-lines must preserve
    /// this so Chrome doesn't reject direction changes on existing transceivers.
    pub direction: super::Direction,
}

/// SDP negotiator for WebRTC offer/answer.
///
/// Handles codec negotiation, ICE credential exchange, and DTLS setup.
///
/// # TigerStyle Compliance
///
/// - Bounded codec lists
/// - Explicit error handling
/// - Precondition/postcondition assertions
pub struct SdpNegotiator {
    /// Supported codecs for negotiation.
    supported_codecs: Vec<CodecCapability>,
    /// Our ICE ufrag.
    ice_ufrag: String,
    /// Our ICE pwd.
    ice_pwd: String,
    /// Our DTLS fingerprint.
    dtls_fingerprint: DtlsFingerprint,
    /// Local ICE candidates to include in SDP.
    local_candidates: Vec<super::IceCandidate>,
}

impl SdpNegotiator {
    /// Create a new SDP negotiator.
    ///
    /// # Arguments
    ///
    /// * `codecs` - Supported codec capabilities
    /// * `ice_ufrag` - Our ICE username fragment
    /// * `ice_pwd` - Our ICE password
    /// * `fingerprint` - Our DTLS certificate fingerprint
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates all inputs
    /// - Bounded codec list
    pub fn new(
        codecs: Vec<CodecCapability>,
        ice_ufrag: String,
        ice_pwd: String,
        fingerprint: DtlsFingerprint,
    ) -> Result<Self, SdpError> {
        // Precondition: must have at least one codec
        assert!(!codecs.is_empty(), "Must have at least one supported codec");
        
        // Precondition: codecs must be bounded
        assert!(
            codecs.len() <= MAX_CODECS_PER_MEDIA,
            "Codec count must be <= MAX_CODECS_PER_MEDIA"
        );

        // Validate ICE credentials
        if ice_ufrag.len() < super::MIN_ICE_UFRAG_LEN
            || ice_ufrag.len() > super::MAX_ICE_UFRAG_LEN
        {
            return Err(SdpError::InvalidIceCredentialLength {
                field: "ice-ufrag",
                actual: ice_ufrag.len(),
                min: super::MIN_ICE_UFRAG_LEN,
                max: super::MAX_ICE_UFRAG_LEN,
            });
        }

        if ice_pwd.len() < super::MIN_ICE_PWD_LEN || ice_pwd.len() > super::MAX_ICE_PWD_LEN {
            return Err(SdpError::InvalidIceCredentialLength {
                field: "ice-pwd",
                actual: ice_pwd.len(),
                min: super::MIN_ICE_PWD_LEN,
                max: super::MAX_ICE_PWD_LEN,
            });
        }

        // Validate fingerprint
        fingerprint.validate()?;

        Ok(Self {
            supported_codecs: codecs,
            ice_ufrag,
            ice_pwd,
            dtls_fingerprint: fingerprint,
            local_candidates: Vec::new(),
        })
    }

    /// Create negotiator with default codecs.
    pub fn with_defaults(
        ice_ufrag: String,
        ice_pwd: String,
        fingerprint: DtlsFingerprint,
    ) -> Result<Self, SdpError> {
        Self::new(default_supported_codecs(), ice_ufrag, ice_pwd, fingerprint)
    }

    /// Add local ICE candidates to include in the SDP answer.
    ///
    /// These candidates will be added to each media section in the answer.
    pub fn with_candidates(mut self, candidates: Vec<super::IceCandidate>) -> Self {
        self.local_candidates = candidates;
        self
    }

    /// Add a single local ICE candidate.
    pub fn add_candidate(&mut self, candidate: super::IceCandidate) {
        self.local_candidates.push(candidate);
    }

    /// Negotiate an SDP offer and generate an answer.
    ///
    /// Parses the offer, computes codec intersection with supported codecs,
    /// includes our ICE credentials and DTLS fingerprint, and generates
    /// an SDP answer string.
    ///
    /// # Arguments
    ///
    /// * `offer_sdp` - The SDP offer string
    ///
    /// # Returns
    ///
    /// The SDP answer string on success.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates offer before processing
    /// - Bounded codec negotiation
    /// - Explicit error handling
    pub fn negotiate(&self, offer_sdp: &str) -> Result<String, SdpError> {
        if offer_sdp.is_empty() {
            return Err(SdpError::InvalidFormat { reason: "empty offer SDP" });
        }

        // Parse the offer
        let offer = SdpParser::parse(offer_sdp)?;

        // Generate answer
        let answer = self.create_answer(&offer)?;

        // Serialize to SDP string
        let answer_sdp = SdpPrinter::print(&answer);

        // Postcondition: answer must be valid SDP
        assert!(
            !answer_sdp.is_empty(),
            "Generated answer must not be empty"
        );

        Ok(answer_sdp)
    }

    /// Create an SDP answer from an offer.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded media section processing
    /// - Explicit codec negotiation
    fn create_answer(&self, offer: &SessionDescription) -> Result<SessionDescription, SdpError> {
        // Precondition: offer must have media sections
        // Return error instead of panicking for graceful error handling
        if offer.media_count == 0 {
            return Err(SdpError::InvalidFormat {
                reason: "Offer must have at least one media section",
            });
        }
        // TigerStyle: secondary assertion for bounded media count
        debug_assert!(
            offer.media_count <= super::MAX_MEDIA_SECTIONS as u8,
            "Media count must be bounded"
        );

        let mut answer = SessionDescription::new(offer.origin.session_id);
        answer.set_session_name("Nexus SFU");
        answer.set_ice_credentials(&self.ice_ufrag, &self.ice_pwd);
        answer.set_fingerprint(self.dtls_fingerprint.clone());
        // RFC 8842 §5.5: answerer role depends on offerer's setup attribute.
        let answer_setup = match offer.setup {
            Some(DtlsSetup::Active) => DtlsSetup::Passive,
            Some(DtlsSetup::Passive) => DtlsSetup::Active,
            _ => DtlsSetup::Active, // actpass or absent → default to active
        };
        answer.set_setup(answer_setup);

        // RFC 8858: WebRTC mandates rtcp-mux. Reject offers without it.
        for i in 0..offer.media_count as usize {
            if let Some(ref m) = offer.media[i] {
                if !m.rtcp_mux {
                    return Err(SdpError::InvalidFormat {
                        reason: "WebRTC requires rtcp-mux on all media sections (RFC 8858)",
                    });
                }
            }
        }

        // Copy BUNDLE group if present
        if offer.bundle_group_len > 0 {
            answer.bundle_group = offer.bundle_group;
            answer.bundle_group_len = offer.bundle_group_len;
        }

        // Process each media section
        for i in 0..offer.media_count as usize {
            if let Some(ref offer_media) = offer.media[i] {
                let answer_media = self.create_answer_media(offer_media, answer_setup)?;
                answer.add_media(answer_media)?;
            }
        }

        // Postcondition: answer must have same media count as offer
        assert_eq!(
            answer.media_count, offer.media_count,
            "Answer must have same media count as offer"
        );

        Ok(answer)
    }

    /// Create answer media section from offer media.
    ///
    /// Includes local ICE candidates in the answer per RFC 8829 (JSEP).
    /// The candidates are added to each media section to enable
    /// connectivity checks to begin immediately.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit codec negotiation
    /// - Direction flipping
    /// - Bounded operations (MAX_CANDIDATES_PER_MEDIA)
    /// - ≥2 assertions
    ///
    /// # Requirements
    ///
    /// - 4.1: Include all gathered local ICE candidates
    /// - 4.2: Include ice-ufrag and ice-pwd attributes
    /// - 4.3: Include DTLS fingerprint
    /// - 4.5: Follow RFC 8829 JSEP format
    fn create_answer_media(
        &self,
        offer_media: &MediaDescription,
        answer_setup: DtlsSetup,
    ) -> Result<MediaDescription, SdpError> {
        // Precondition: offer media must have codecs
        assert!(
            offer_media.codec_count > 0 || offer_media.format_count > 0,
            "Offer media must have codecs or formats"
        );

        let mut media = MediaDescription::new(
            offer_media.media_type,
            9, // Port 9 is standard for WebRTC (ignored due to ICE)
            offer_media.protocol,
        );

        // Copy MID
        media.mid = offer_media.mid.clone();

        // Flip direction
        media.direction = SessionDescription::flip_direction(offer_media.direction);

        // Set ICE credentials (Requirement 4.2)
        media.set_ice_credentials(&self.ice_ufrag, &self.ice_pwd);

        // Enable trickle ICE (RFC 8838) - indicates we support incremental candidate delivery
        media.ice_options.trickle = true;

        // Set DTLS fingerprint (Requirement 4.3)
        media.set_fingerprint(self.dtls_fingerprint.clone());
        media.setup = Some(answer_setup);

        // Negotiate codecs
        let negotiated = self.negotiate_codecs(offer_media)?;
        let mut negotiated_pts: [u8; 16] = [0; 16];
        let mut negotiated_pt_count = 0usize;
        for codec in &negotiated {
            if negotiated_pt_count < 16 {
                negotiated_pts[negotiated_pt_count] = codec.payload_type;
                negotiated_pt_count += 1;
            }
        }
        for codec in negotiated {
            media.add_codec(codec)?;
        }

        // Echo RTX codecs (RFC 4588) whose apt fmtp points to a negotiated PT.
        // Without RTX in the answer, browsers won't use retransmission.
        for i in 0..offer_media.codec_count as usize {
            if let Some(ref offer_codec) = offer_media.codecs[i] {
                if offer_codec.name_str().eq_ignore_ascii_case("rtx") {
                    // Find the apt=<pt> in fmtp for this RTX codec
                    if let Some(primary_pt) = Self::find_rtx_apt(offer_media, offer_codec.payload_type) {
                        if negotiated_pts[..negotiated_pt_count].contains(&primary_pt) {
                            let _ = media.add_codec(offer_codec.clone());
                            // Echo the fmtp line too
                            for j in 0..offer_media.fmtp_count as usize {
                                if let Some(ref fmtp) = offer_media.fmtps[j] {
                                    if fmtp.payload_type == offer_codec.payload_type {
                                        let _ = media.add_fmtp(fmtp.clone());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
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

        // Add local ICE candidates to answer (Requirement 4.1)
        // Bounded by MAX_CANDIDATES_PER_MEDIA per TigerStyle
        for candidate in &self.local_candidates {
            if media.candidate_count as usize >= super::MAX_CANDIDATES_PER_MEDIA {
                break;
            }
            // Ignore errors from add_candidate - we've already checked the bound
            let _ = media.add_candidate(candidate.clone());
        }

        // Postcondition: answer media must have at least one codec
        assert!(
            media.codec_count > 0,
            "Answer media must have at least one codec"
        );

        Ok(media)
    }

    /// Negotiate codecs between offer and our supported codecs.
    ///
    /// Returns the intersection of offered and supported codecs,
    /// in the offer's preference order.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Bounded result (max 16 codecs)
    /// - Explicit matching logic
    fn negotiate_codecs(
        &self,
        offer_media: &MediaDescription,
    ) -> Result<Vec<RtpCodec>, SdpError> {
        // Precondition: must have supported codecs
        assert!(
            !self.supported_codecs.is_empty(),
            "Must have supported codecs"
        );

        let mut negotiated = Vec::new();

        // Filter supported codecs by media type
        let supported_for_type: Vec<&CodecCapability> = self
            .supported_codecs
            .iter()
            .filter(|c| match offer_media.media_type {
                MediaType::Audio => c.codec_type.is_audio(),
                MediaType::Video => c.codec_type.is_video(),
                MediaType::Application => false, // DataChannel doesn't use codecs
            })
            .collect();

        // Iterate through offer codecs (their preference order)
        for i in 0..offer_media.codec_count as usize {
            if let Some(ref offer_codec) = offer_media.codecs[i] {
                // Find matching supported codec
                if let Some(matching) = self.find_matching_codec(offer_codec, &supported_for_type)
                {
                    // Use offer's payload type with our codec parameters
                    let mut result_codec = matching.to_rtp_codec();
                    result_codec.payload_type = offer_codec.payload_type;
                    negotiated.push(result_codec);

                    // Bounded result
                    if negotiated.len() >= MAX_CODECS_PER_MEDIA {
                        break;
                    }
                }
            }
        }

        if negotiated.is_empty() {
            return Err(SdpError::NoCommonCodec {
                media_type: offer_media.media_type.as_str().to_string(),
            });
        }

        // Postcondition: result must be bounded
        assert!(
            negotiated.len() <= MAX_CODECS_PER_MEDIA,
            "Negotiated codecs must be bounded"
        );

        Ok(negotiated)
    }

    /// Extract the `apt` value from an RTX codec's fmtp line.
    /// Returns the primary codec's payload type that this RTX codec retransmits.
    fn find_rtx_apt(media: &MediaDescription, rtx_pt: u8) -> Option<u8> {
        for i in 0..media.fmtp_count as usize {
            if let Some(ref fmtp) = media.fmtps[i] {
                if fmtp.payload_type == rtx_pt {
                    let params = std::str::from_utf8(&fmtp.params[..fmtp.params_len as usize])
                        .unwrap_or("");
                    for param in params.split(';') {
                        let param = param.trim();
                        if let Some(val) = param.strip_prefix("apt=") {
                            return val.trim().parse::<u8>().ok();
                        }
                    }
                }
            }
        }
        None
    }

    /// Find a matching codec from our supported list.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit matching criteria
    /// - Bounded iteration
    fn find_matching_codec<'a>(
        &self,
        offer_codec: &RtpCodec,
        supported: &[&'a CodecCapability],
    ) -> Option<&'a CodecCapability> {
        let offer_name = offer_codec.name_str().to_lowercase();

        for cap in supported {
            let cap_name = cap.codec_type.name().to_lowercase();
            if offer_name == cap_name && offer_codec.clock_rate == cap.clock_rate {
                return Some(cap);
            }
        }

        None
    }

    /// Extract ICE candidates from a parsed SDP.
    ///
    /// Extracts candidates from all media sections, respecting bounds
    /// per RFC 8839 and TigerStyle requirements.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions (precondition and postcondition)
    /// - Bounded iteration (MAX_CANDIDATES_PER_MEDIA, MAX_TOTAL_CANDIDATES)
    /// - Returns owned candidates
    ///
    /// # Arguments
    ///
    /// * `sdp` - Parsed session description
    ///
    /// # Returns
    ///
    /// Vector of ICE candidates extracted from all media sections,
    /// bounded by MAX_TOTAL_CANDIDATES.
    pub fn extract_candidates(sdp: &SessionDescription) -> Vec<super::attributes::IceCandidate> {
        const MAX_TOTAL_CANDIDATES: usize = 128;
        
        // Precondition: SDP must be valid with bounded media count
        assert!(
            sdp.media_count <= super::MAX_MEDIA_SECTIONS as u8,
            "Media count must be bounded by MAX_MEDIA_SECTIONS"
        );

        let mut candidates = Vec::with_capacity(MAX_TOTAL_CANDIDATES);

        // Iterate through all media sections
        for i in 0..sdp.media_count as usize {
            if let Some(ref media) = sdp.media[i] {
                // Respect MAX_CANDIDATES_PER_MEDIA bound per media section
                let media_candidate_limit = (media.candidate_count as usize)
                    .min(super::MAX_CANDIDATES_PER_MEDIA);
                
                for j in 0..media_candidate_limit {
                    // Check total candidates bound
                    if candidates.len() >= MAX_TOTAL_CANDIDATES {
                        break;
                    }
                    
                    if let Some(ref candidate) = media.candidates[j] {
                        candidates.push(candidate.clone());
                    }
                }
                
                // Early exit if we've hit the total limit
                if candidates.len() >= MAX_TOTAL_CANDIDATES {
                    break;
                }
            }
        }

        // Postcondition: result must be bounded
        assert!(
            candidates.len() <= MAX_TOTAL_CANDIDATES,
            "Extracted candidates must be bounded by MAX_TOTAL_CANDIDATES"
        );

        candidates
    }

    /// Get our ICE ufrag.
    pub fn ice_ufrag(&self) -> &str {
        &self.ice_ufrag
    }

    /// Get our ICE pwd.
    pub fn ice_pwd(&self) -> &str {
        &self.ice_pwd
    }

    /// Get our DTLS fingerprint.
    pub fn dtls_fingerprint(&self) -> &DtlsFingerprint {
        &self.dtls_fingerprint
    }

    /// Get supported codecs.
    pub fn supported_codecs(&self) -> &[CodecCapability] {
        &self.supported_codecs
    }

    /// Create a server-initiated renegotiation offer (RFC 3264 §8).
    ///
    /// Builds an SDP offer that includes SSRC information for tracks the
    /// subscriber has subscribed to. This allows the client's WebRTC stack
    /// to map incoming RTP packets to transceivers and fire `on_track`.
    ///
    /// # TigerStyle Compliance
    ///
    /// - ≥2 assertions validating preconditions and postconditions
    /// - Bounded track count (MAX_MEDIA_SECTIONS)
    /// - No dynamic allocation beyond String building
    #[allow(clippy::too_many_arguments)]
    pub fn create_renegotiation_offer(
        &self,
        session_id: u64,
        session_version: u64,
        existing_mids: &[RecycledMline<'_>],
        tracks: &[(u32, u8, &str)],
        mid_ext_id: u8,
        video_extmaps: &[(u8, &str)],
        audio_extmaps: &[(u8, &str)],
        negotiated_video_codec: Option<&RtpCodec>,
        negotiated_audio_codec: Option<&RtpCodec>,
        negotiated_video_fmtp: Option<&super::Fmtp>,
        negotiated_audio_fmtp: Option<&super::Fmtp>,
    ) -> Result<(String, Vec<u8>), SdpError> {
        // Precondition: must have at least one track
        assert!(!tracks.is_empty(), "Must have at least one track for renegotiation");
        // Precondition: bounded track count
        assert!(
            existing_mids.len() + tracks.len() <= super::MAX_MEDIA_SECTIONS,
            "Total media sections must be <= MAX_MEDIA_SECTIONS"
        );

        let mut offer = SessionDescription::new(session_id);
        // RFC 3264 §8: o= version MUST be incremented on each new offer
        offer.set_version(session_version);
        offer.set_session_name("Nexus SFU");
        offer.set_ice_credentials(&self.ice_ufrag, &self.ice_pwd);
        offer.set_fingerprint(self.dtls_fingerprint.clone());
        // RFC 8842 §5.5: offerer MUST use actpass.
        offer.set_setup(DtlsSetup::Actpass);

        let mut bundle_mids: Vec<&str> = Vec::with_capacity(existing_mids.len() + tracks.len());

        // Collect all PTs used by recycled m-lines so new sendonly m-lines
        // can avoid conflicts. RFC 8843 §9.2 requires unique PT-to-MID
        // mapping within a BUNDLE group; Chrome enforces this strictly
        // regardless of direction.
        //
        // CRITICAL: Include ALL PTs from the client's original offer, not just
        // the answer's PTs. Chrome's BUNDLE demuxer retains PT→MID associations
        // from the original offer even for PTs the SFU's answer didn't include.
        // Reusing such a PT for a new m-line causes "Failed to set up demuxing"
        // errors (ERROR_CONTENT).
        let mut used_pts: [bool; 128] = [false; 128];
        for recycled in existing_mids {
            for codec in recycled.codecs {
                used_pts[codec.payload_type as usize] = true;
            }
            for &pt in recycled.offer_pts {
                if (pt as usize) < 128 {
                    used_pts[pt as usize] = true;
                }
            }
        }

        // First: include existing m-lines recycled per JSEP §5.2.2.
        // Use the exact codecs and extensions from the initial negotiation.
        for recycled in existing_mids {
            let media_type = if recycled.media_kind == 0 {
                super::MediaType::Audio
            } else {
                super::MediaType::Video
            };
            let mut media = super::MediaDescription::new(
                media_type,
                9,
                super::TransportProtocol::UdpTlsRtpSavpf,
            );
            media.mid = Some(super::Mid::new(recycled.mid));
            media.direction = recycled.direction;
            media.set_ice_credentials(&self.ice_ufrag, &self.ice_pwd);
            media.ice_options.trickle = true;
            media.set_fingerprint(self.dtls_fingerprint.clone());
            media.setup = Some(DtlsSetup::Actpass);
            media.rtcp_mux = true;

            // Use the previously negotiated codecs (with browser's PTs)
            for codec in recycled.codecs {
                let _ = media.add_codec(codec.clone());
            }

            // Use the previously negotiated fmtp lines (required for H264 etc.)
            for fmtp in recycled.fmtps {
                let _ = media.add_fmtp(fmtp.clone());
            }

            // Use the previously negotiated extensions
            for ext in recycled.extmaps {
                let _ = media.add_extmap(ext.clone());
            }

            // Ensure MID extension is present (may already be in extmaps)
            let has_mid_ext = recycled.extmaps.iter().any(|e| {
                let uri = std::str::from_utf8(&e.uri[..e.uri_len as usize]).unwrap_or("");
                uri.contains("sdes:mid")
            });
            if !has_mid_ext {
                let _ = media.add_extmap(super::ExtMap {
                    id: mid_ext_id,
                    uri: {
                        let mut buf = [0u8; 128];
                        let s = b"urn:ietf:params:rtp-hdrext:sdes:mid";
                        buf[..s.len()].copy_from_slice(s);
                        buf
                    },
                    uri_len: 35,
                    direction: None,
                });
            }

            offer.add_media(media)?;
            bundle_mids.push(recycled.mid);
        }

        // Track the actual PT assigned to each new sendonly m-line.
        // Index corresponds to the tracks slice.
        let mut track_pts: Vec<u8> = Vec::with_capacity(tracks.len());

        for &(ssrc, media_kind, mid) in tracks {
            // Precondition: SSRC must be non-zero
            assert!(ssrc != 0, "SSRC must be non-zero");

            let media_type = if media_kind == 0 {
                super::MediaType::Audio
            } else {
                super::MediaType::Video
            };

            let mut media = super::MediaDescription::new(
                media_type,
                9,
                super::TransportProtocol::UdpTlsRtpSavpf,
            );

            media.mid = Some(super::Mid::new(mid));
            // SFU sends media to subscriber
            media.direction = super::Direction::SendOnly;

            media.set_ice_credentials(&self.ice_ufrag, &self.ice_pwd);
            media.ice_options.trickle = true;
            media.set_fingerprint(self.dtls_fingerprint.clone());
            media.setup = Some(DtlsSetup::Actpass);

            // Use the negotiated codec for this media type (RFC 3264 §8).
            // If the negotiated PT conflicts with a recycled m-line, pick an
            // unused dynamic PT (96-127) to satisfy BUNDLE uniqueness (RFC 8843 §9.2).
            let negotiated_codec = if media_kind == 0 {
                negotiated_audio_codec
            } else {
                negotiated_video_codec
            };
            let negotiated_fmtp = if media_kind == 0 {
                negotiated_audio_fmtp
            } else {
                negotiated_video_fmtp
            };
            if let Some(codec) = negotiated_codec {
                let mut c = codec.clone();
                let original_pt = c.payload_type;
                if used_pts[c.payload_type as usize] {
                    // Find an unused dynamic PT (96-127, RFC 3551 §6)
                    let mut new_pt = None;
                    for pt in 96..=127u8 {
                        if !used_pts[pt as usize] {
                            new_pt = Some(pt);
                            break;
                        }
                    }
                    match new_pt {
                        Some(pt) => c.payload_type = pt,
                        None => return Err(SdpError::TooManyMedia {
                            count: existing_mids.len() + tracks.len(),
                            max: 32, // dynamic PT space exhausted
                        }),
                    }
                }
                used_pts[c.payload_type as usize] = true;
                track_pts.push(c.payload_type);
                let _ = media.add_codec(c.clone());

                // Add fmtp for the codec if available (required for H264 etc.)
                if let Some(fmtp) = negotiated_fmtp {
                    let mut f = fmtp.clone();
                    // Update fmtp PT to match the (possibly remapped) codec PT
                    if f.payload_type == original_pt {
                        f.payload_type = c.payload_type;
                    }
                    let _ = media.add_fmtp(f);
                }
            } else {
                track_pts.push(0); // no override needed
                // Fallback: use our default codecs if no negotiation happened yet
                for codec_cap in &self.supported_codecs {
                    let is_audio = codec_cap.codec_type.is_audio();
                    let want_audio = media_kind == 0;
                    if is_audio == want_audio {
                        let _ = media.add_codec(codec_cap.to_rtp_codec());
                    }
                }
            }

            // RTCP-mux is mandatory for WebRTC (RFC 8858)
            media.rtcp_mux = true;
            media.rtcp_rsize = true;

            // Add RTCP feedback capabilities so the subscriber's browser
            // sends NACK, PLI, REMB, and transport-cc (RFC 4585, RFC 8888).
            // Without these, the browser won't send any feedback for subscribed tracks.
            if negotiated_codec.is_some() {
                let pt = media.codecs.iter()
                    .filter_map(|c| c.as_ref())
                    .next()
                    .map(|c| c.payload_type);
                if let Some(pt) = pt {
                    let pt_str = pt.to_string();
                    if media_kind != 0 {
                        // Video: nack, nack pli, goog-remb, transport-cc
                        let _ = media.add_rtcp_fb(super::RtcpFeedback::parse(&format!("{} nack", pt_str)).unwrap());
                        let _ = media.add_rtcp_fb(super::RtcpFeedback::parse(&format!("{} nack pli", pt_str)).unwrap());
                        let _ = media.add_rtcp_fb(super::RtcpFeedback::parse(&format!("{} goog-remb", pt_str)).unwrap());
                        let _ = media.add_rtcp_fb(super::RtcpFeedback::parse(&format!("{} transport-cc", pt_str)).unwrap());
                    } else {
                        // Audio: transport-cc
                        let _ = media.add_rtcp_fb(super::RtcpFeedback::parse(&format!("{} transport-cc", pt_str)).unwrap());
                    }
                }
            }

            // Use negotiated extmap IDs from the initial exchange (RFC 8843 §9.1).
            // In a BUNDLE, all m-lines share the same ID space, but each media
            // type only includes its own applicable extensions. This prevents
            // audio-only extensions (e.g. ssrc-audio-level) from appearing on
            // video m-lines, which Chrome correctly rejects.
            let type_extmaps = if media_kind == 0 { audio_extmaps } else { video_extmaps };
            for &(ext_id, ext_uri) in type_extmaps {
                let uri_bytes = ext_uri.as_bytes();
                let uri_len = uri_bytes.len().min(128);
                let mut buf = [0u8; 128];
                buf[..uri_len].copy_from_slice(&uri_bytes[..uri_len]);
                let _ = media.add_extmap(super::ExtMap {
                    id: ext_id,
                    uri: buf,
                    uri_len: uri_len as u8,
                    direction: None,
                });
            }

            // Add SSRC with cname and msid attributes (RFC 5576)
            let cname_str = format!("nexus-{}", ssrc);
            let msid_str = format!("nexus-stream-{} nexus-track-{}", ssrc, mid);

            let _ = media.add_ssrc(super::SsrcInfo::parse(
                &format!("{} cname:{}", ssrc, cname_str),
            )?);
            let _ = media.add_ssrc(super::SsrcInfo::parse(
                &format!("{} msid:{}", ssrc, msid_str),
            )?);

            // Add local ICE candidates — bounded by MAX_CANDIDATES_PER_MEDIA
            for candidate in &self.local_candidates {
                if media.candidate_count as usize >= super::MAX_CANDIDATES_PER_MEDIA {
                    break;
                }
                let _ = media.add_candidate(candidate.clone());
            }

            // Postcondition: media must have at least one codec
            assert!(
                media.codec_count > 0,
                "Renegotiation offer media must have at least one codec"
            );

            offer.add_media(media)?;
            bundle_mids.push(mid);
        }

        // Set BUNDLE group (any non-empty set of mids)
        if !bundle_mids.is_empty() {
            offer.set_bundle(&bundle_mids)?;
        }

        let offer_sdp = SdpPrinter::print(&offer);

        // Postcondition: offer must be valid SDP
        assert!(
            !offer_sdp.is_empty(),
            "Generated renegotiation offer must not be empty"
        );
        // Postcondition: offer must contain SSRC lines
        debug_assert!(
            offer_sdp.contains("a=ssrc:"),
            "Renegotiation offer must contain SSRC attributes"
        );

        Ok((offer_sdp, track_pts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fingerprint() -> DtlsFingerprint {
        DtlsFingerprint::parse(
            "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:\
             AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90",
        )
        .unwrap()
    }

    fn test_negotiator() -> SdpNegotiator {
        SdpNegotiator::with_defaults(
            "testufrag".to_string(),
            "testpwd1234567890123456".to_string(),
            test_fingerprint(),
        )
        .unwrap()
    }

    #[test]
    fn test_codec_type_properties() {
        assert!(CodecType::Opus.is_audio());
        assert!(!CodecType::Opus.is_video());
        assert!(CodecType::Vp8.is_video());
        assert!(!CodecType::Vp8.is_audio());
        assert_eq!(CodecType::Opus.clock_rate(), 48000);
        assert_eq!(CodecType::Vp8.clock_rate(), 90000);
    }

    #[test]
    fn test_codec_type_from_name() {
        assert_eq!(CodecType::from_name("opus"), Some(CodecType::Opus));
        assert_eq!(CodecType::from_name("OPUS"), Some(CodecType::Opus));
        assert_eq!(CodecType::from_name("VP8"), Some(CodecType::Vp8));
        assert_eq!(CodecType::from_name("vp9"), Some(CodecType::Vp9));
        assert_eq!(CodecType::from_name("h264"), Some(CodecType::H264));
        assert_eq!(CodecType::from_name("av1"), Some(CodecType::Av1));
        assert_eq!(CodecType::from_name("unknown"), None);
    }

    #[test]
    fn test_default_supported_codecs() {
        let codecs = default_supported_codecs();
        assert!(!codecs.is_empty());
        assert!(codecs.iter().any(|c| c.codec_type == CodecType::Opus));
        assert!(codecs.iter().any(|c| c.codec_type == CodecType::Vp8));
    }

    #[test]
    fn test_negotiator_creation() {
        let negotiator = test_negotiator();
        assert_eq!(negotiator.ice_ufrag(), "testufrag");
        assert!(!negotiator.supported_codecs().is_empty());
    }

    #[test]
    fn test_negotiator_validates_ufrag() {
        let result = SdpNegotiator::with_defaults(
            "ab".to_string(), // Too short
            "testpwd1234567890123456".to_string(),
            test_fingerprint(),
        );
        assert!(matches!(
            result,
            Err(SdpError::InvalidIceCredentialLength { .. })
        ));
    }

    #[test]
    fn test_negotiator_validates_pwd() {
        let result = SdpNegotiator::with_defaults(
            "testufrag".to_string(),
            "short".to_string(), // Too short
            test_fingerprint(),
        );
        assert!(matches!(
            result,
            Err(SdpError::InvalidIceCredentialLength { .. })
        ));
    }

    #[test]
    fn test_negotiate_audio_offer() {
        let negotiator = test_negotiator();

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
"#;

        let answer = negotiator.negotiate(offer).unwrap();

        assert!(answer.contains("v=0"));
        assert!(answer.contains("a=ice-ufrag:testufrag"));
        assert!(answer.contains("a=ice-pwd:testpwd1234567890123456"));
        assert!(answer.contains("a=ice-options:trickle"), "Answer must include trickle ICE option");
        assert!(answer.contains("m=audio"));
        assert!(answer.contains("opus"));
    }

    #[test]
    fn test_negotiate_video_offer() {
        let negotiator = test_negotiator();

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:96 VP8/90000
"#;

        let answer = negotiator.negotiate(offer).unwrap();

        assert!(answer.contains("m=video"));
        assert!(answer.contains("VP8"));
    }

    #[test]
    fn test_negotiate_multiple_codecs() {
        let negotiator = test_negotiator();

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 98 102
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:96 VP8/90000
a=rtpmap:98 VP9/90000
a=rtpmap:102 H264/90000
"#;

        let answer = negotiator.negotiate(offer).unwrap();

        // Should include all matching codecs
        assert!(answer.contains("VP8"));
        assert!(answer.contains("VP9"));
        assert!(answer.contains("H264"));
    }

    #[test]
    fn test_negotiate_no_common_codec() {
        let negotiator = test_negotiator();

        // Offer with unsupported codec
        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 0
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:0 PCMU/8000
"#;

        let result = negotiator.negotiate(offer);
        assert!(matches!(result, Err(SdpError::NoCommonCodec { .. })));
    }

    #[test]
    fn test_direction_flipping() {
        let negotiator = test_negotiator();

        // Offer with sendonly should result in recvonly answer
        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendonly
a=rtcp-mux
a=rtpmap:111 opus/48000/2
"#;

        let answer = negotiator.negotiate(offer).unwrap();
        assert!(answer.contains("a=recvonly"));
    }

    #[test]
    fn test_extract_candidates() {
        let sdp_str = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=candidate:1 1 udp 2130706431 192.168.1.1 54321 typ host
a=candidate:2 1 udp 1694498815 203.0.113.1 54322 typ srflx
"#;

        let sdp = SdpParser::parse(sdp_str).unwrap();
        let candidates = SdpNegotiator::extract_candidates(&sdp);

        assert_eq!(candidates.len(), 2);
        
        // Verify first candidate
        assert_eq!(candidates[0].component, 1);
        assert_eq!(candidates[0].priority, 2130706431);
        
        // Verify second candidate
        assert_eq!(candidates[1].priority, 1694498815);
    }

    #[test]
    fn test_extract_candidates_multiple_media() {
        let sdp_str = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=candidate:1 1 udp 2130706431 192.168.1.1 54321 typ host
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:1
a=candidate:2 1 udp 2130706431 192.168.1.1 54322 typ host
a=candidate:3 1 udp 1694498815 203.0.113.1 54323 typ srflx
"#;

        let sdp = SdpParser::parse(sdp_str).unwrap();
        let candidates = SdpNegotiator::extract_candidates(&sdp);

        // Should extract candidates from both media sections
        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn test_extract_candidates_empty() {
        let sdp_str = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:testufrag
a=ice-pwd:testpwd12345678901234567890
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
"#;

        let sdp = SdpParser::parse(sdp_str).unwrap();
        let candidates = SdpNegotiator::extract_candidates(&sdp);

        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_codec_capability_to_rtp_codec() {
        let cap = CodecCapability::new(CodecType::Opus, 111);
        let codec = cap.to_rtp_codec();

        assert_eq!(codec.payload_type, 111);
        assert_eq!(codec.name_str(), "opus");
        assert_eq!(codec.clock_rate, 48000);
        assert_eq!(codec.channels, Some(2));
    }

    #[test]
    fn test_answer_includes_local_candidates() {
        use super::super::attributes::IceCandidate;
        use std::net::SocketAddr;

        // Create negotiator with local candidates
        let mut negotiator = test_negotiator();
        
        // Create a local ICE candidate
        let candidate = IceCandidate {
            foundation: {
                let mut f = [0u8; 32];
                f[..1].copy_from_slice(b"1");
                f
            },
            foundation_len: 1,
            component: 1,
            transport: super::super::attributes::CandidateTransport::Udp,
            priority: 2130706431,
            address: "192.168.1.100:54321".parse::<SocketAddr>().unwrap(),
            typ: super::super::attributes::CandidateType::Host,
            related_addr: None,
        };
        
        negotiator.add_candidate(candidate);

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
"#;

        let answer = negotiator.negotiate(offer).unwrap();

        // Verify answer contains our local candidate
        assert!(answer.contains("a=candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host"),
            "Answer should contain local ICE candidate. Answer:\n{}", answer);
        
        // Verify answer contains ICE credentials (Requirement 4.2)
        assert!(answer.contains("a=ice-ufrag:testufrag"));
        assert!(answer.contains("a=ice-pwd:testpwd1234567890123456"));
        
        // Verify answer contains DTLS fingerprint (Requirement 4.3)
        assert!(answer.contains("a=fingerprint:sha-256"));
    }

    #[test]
    fn test_answer_includes_multiple_candidates() {
        use super::super::attributes::IceCandidate;
        use std::net::SocketAddr;

        let mut negotiator = test_negotiator();
        
        // Add host candidate
        let host_candidate = IceCandidate {
            foundation: {
                let mut f = [0u8; 32];
                f[..1].copy_from_slice(b"1");
                f
            },
            foundation_len: 1,
            component: 1,
            transport: super::super::attributes::CandidateTransport::Udp,
            priority: 2130706431,
            address: "192.168.1.100:54321".parse::<SocketAddr>().unwrap(),
            typ: super::super::attributes::CandidateType::Host,
            related_addr: None,
        };
        
        // Add srflx candidate
        let srflx_candidate = IceCandidate {
            foundation: {
                let mut f = [0u8; 32];
                f[..1].copy_from_slice(b"2");
                f
            },
            foundation_len: 1,
            component: 1,
            transport: super::super::attributes::CandidateTransport::Udp,
            priority: 1694498815,
            address: "203.0.113.50:54322".parse::<SocketAddr>().unwrap(),
            typ: super::super::attributes::CandidateType::Srflx,
            related_addr: Some("192.168.1.100:54321".parse::<SocketAddr>().unwrap()),
        };
        
        negotiator.add_candidate(host_candidate);
        negotiator.add_candidate(srflx_candidate);

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
"#;

        let answer = negotiator.negotiate(offer).unwrap();

        // Verify both candidates are in the answer
        assert!(answer.contains("typ host"), "Answer should contain host candidate");
        assert!(answer.contains("typ srflx"), "Answer should contain srflx candidate");
        assert!(answer.contains("raddr 192.168.1.100 rport 54321"), 
            "srflx candidate should have related address");
    }

    #[test]
    fn test_with_candidates_builder() {
        use super::super::attributes::IceCandidate;
        use std::net::SocketAddr;

        let candidate = IceCandidate {
            foundation: {
                let mut f = [0u8; 32];
                f[..1].copy_from_slice(b"1");
                f
            },
            foundation_len: 1,
            component: 1,
            transport: super::super::attributes::CandidateTransport::Udp,
            priority: 2130706431,
            address: "192.168.1.100:54321".parse::<SocketAddr>().unwrap(),
            typ: super::super::attributes::CandidateType::Host,
            related_addr: None,
        };

        let negotiator = SdpNegotiator::with_defaults(
            "testufrag".to_string(),
            "testpwd1234567890123456".to_string(),
            test_fingerprint(),
        )
        .unwrap()
        .with_candidates(vec![candidate]);

        let offer = r#"v=0
o=- 12345 1 IN IP4 127.0.0.1
s=-
t=0 0
a=ice-ufrag:remoteufrag
a=ice-pwd:remotepwd1234567890123456
a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
"#;

        let answer = negotiator.negotiate(offer).unwrap();
        assert!(answer.contains("a=candidate:"), "Answer should contain candidate");
    }
}
