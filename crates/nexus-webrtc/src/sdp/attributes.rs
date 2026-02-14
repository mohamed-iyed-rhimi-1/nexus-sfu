//! SDP attributes for WebRTC.

use std::net::SocketAddr;

use super::error::SdpError;

use super::{SHA256_FINGERPRINT_LEN};

/// ICE candidate from SDP a=candidate line.
#[derive(Debug, Clone, PartialEq)]
pub struct IceCandidate {
    /// Foundation string.
    pub foundation: [u8; 32],
    /// Foundation length.
    pub foundation_len: u8,
    /// Component ID (1 = RTP, 2 = RTCP).
    pub component: u8,
    /// Transport protocol.
    pub transport: CandidateTransport,
    /// Priority value.
    pub priority: u32,
    /// Connection address.
    pub address: SocketAddr,
    /// Candidate type.
    pub typ: CandidateType,
    /// Related address (for srflx/relay).
    pub related_addr: Option<SocketAddr>,
}

/// ICE candidate transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateTransport {
    Udp,
    Tcp,
}

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    Srflx,
    Prflx,
    Relay,
}

impl IceCandidate {
    /// Parse ICE candidate from SDP attribute value.
    ///
    /// Format: foundation component transport priority address port typ type [raddr rport]
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        
        if parts.len() < 8 {
            return Err(SdpError::InvalidCandidate { reason: "too few fields" });
        }
        
        // Parse foundation
        let mut foundation = [0u8; 32];
        let foundation_bytes = parts[0].as_bytes();
        let foundation_len = foundation_bytes.len().min(32);
        foundation[..foundation_len].copy_from_slice(&foundation_bytes[..foundation_len]);
        
        // Parse component
        let component = parts[1].parse::<u8>()
            .map_err(|_| SdpError::InvalidCandidate { reason: "invalid component" })?;
        
        // Parse transport
        let transport = match parts[2].to_lowercase().as_str() {
            "udp" => CandidateTransport::Udp,
            "tcp" => CandidateTransport::Tcp,
            _ => return Err(SdpError::InvalidCandidate { reason: "unknown transport" }),
        };
        
        // Parse priority
        let priority = parts[3].parse::<u32>()
            .map_err(|_| SdpError::InvalidCandidate { reason: "invalid priority" })?;
        
        // Parse address and port
        let addr = parts[4];
        let port = parts[5].parse::<u16>()
            .map_err(|_| SdpError::InvalidCandidate { reason: "invalid port" })?;
        
        let address: SocketAddr = format!("{}:{}", addr, port)
            .parse()
            .map_err(|_| SdpError::InvalidCandidate { reason: "invalid address" })?;
        
        // parts[6] should be "typ"
        if parts[6] != "typ" {
            return Err(SdpError::InvalidCandidate { reason: "expected 'typ'" });
        }
        
        // Parse type
        let typ = match parts[7] {
            "host" => CandidateType::Host,
            "srflx" => CandidateType::Srflx,
            "prflx" => CandidateType::Prflx,
            "relay" => CandidateType::Relay,
            _ => return Err(SdpError::InvalidCandidate { reason: "unknown type" }),
        };
        
        // Parse optional related address
        let related_addr = if parts.len() >= 12 && parts[8] == "raddr" && parts[10] == "rport" {
            let raddr = parts[9];
            if let Ok(rport) = parts[11].parse::<u16>() {
                format!("{}:{}", raddr, rport).parse().ok()
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(Self {
            foundation,
            foundation_len: foundation_len as u8,
            component,
            transport,
            priority,
            address,
            typ,
            related_addr,
        })
    }
    
    /// Serialize to SDP attribute value.
    pub fn to_sdp(&self) -> String {
        let foundation = std::str::from_utf8(&self.foundation[..self.foundation_len as usize])
            .unwrap_or("unknown");
        let transport = match self.transport {
            CandidateTransport::Udp => "udp",
            CandidateTransport::Tcp => "tcp",
        };
        let typ = match self.typ {
            CandidateType::Host => "host",
            CandidateType::Srflx => "srflx",
            CandidateType::Prflx => "prflx",
            CandidateType::Relay => "relay",
        };
        
        let mut result = format!(
            "{} {} {} {} {} {} typ {}",
            foundation,
            self.component,
            transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            typ
        );
        
        if let Some(raddr) = self.related_addr {
            result.push_str(&format!(" raddr {} rport {}", raddr.ip(), raddr.port()));
        }
        
        result
    }
}

/// DTLS fingerprint from SDP a=fingerprint line.
#[derive(Debug, Clone, PartialEq)]
pub struct DtlsFingerprint {
    /// Hash algorithm (sha-256, sha-384, sha-512).
    pub algorithm: FingerprintAlgorithm,
    /// Fingerprint bytes.
    pub value: [u8; 32],
    /// Fingerprint length.
    pub value_len: u8,
}

/// Fingerprint hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DtlsFingerprint {
    /// Parse from SDP attribute value.
    ///
    /// Format: algorithm hex:bytes
    ///
    /// # TigerStyle Compliance
    ///
    /// - Validates SHA-256 only (production requirement)
    /// - Bounded fingerprint length check
    /// - Paired assertion for parse result
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        // Precondition: value must not be empty
        assert!(!value.is_empty(), "Fingerprint value must not be empty");
        
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(SdpError::InvalidFingerprint { 
                reason: "expected algorithm and fingerprint" 
            });
        }
        
        // Only SHA-256 is allowed for production WebRTC
        let algorithm = match parts[0].to_lowercase().as_str() {
            "sha-256" => FingerprintAlgorithm::Sha256,
            other => {
                return Err(SdpError::UnsupportedFingerprintAlgorithm {
                    algorithm: other.to_string(),
                });
            }
        };
        
        // Parse hex fingerprint (format: XX:XX:XX:...)
        let hex_str = parts[1].replace(':', "");
        let bytes = Self::parse_hex_bytes(&hex_str)?;
        
        // SHA-256 must be exactly 32 bytes
        if bytes.len() != SHA256_FINGERPRINT_LEN as usize {
            return Err(SdpError::InvalidFingerprint { 
                reason: "SHA-256 fingerprint must be 32 bytes" 
            });
        }
        
        let mut value_buf = [0u8; 32];
        value_buf[..bytes.len()].copy_from_slice(&bytes);
        
        let result = Self {
            algorithm,
            value: value_buf,
            value_len: bytes.len() as u8,
        };
        
        // Postcondition: result must have correct length
        assert_eq!(result.value_len, SHA256_FINGERPRINT_LEN,
            "Parsed fingerprint must be 32 bytes");
        
        Ok(result)
    }

    /// Parse hex string to bytes.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Extracted helper for function length compliance
    /// - Explicit error handling
    /// - Validates even-length hex string to prevent panic
    fn parse_hex_bytes(hex_str: &str) -> Result<Vec<u8>, SdpError> {
        // Check for odd-length hex string which would cause panic during parsing
        if hex_str.len() % 2 != 0 {
            return Err(SdpError::InvalidFingerprint { 
                reason: "hex string has odd length" 
            });
        }
        
        let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i+2], 16))
            .collect();
        
        bytes.map_err(|_| SdpError::InvalidFingerprint { reason: "invalid hex" })
    }

    /// Validate fingerprint is production-ready.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Explicit validation for SHA-256 only
    /// - Assertion for length bounds
    pub fn validate(&self) -> Result<(), SdpError> {
        // Only SHA-256 allowed
        if self.algorithm != FingerprintAlgorithm::Sha256 {
            return Err(SdpError::UnsupportedFingerprintAlgorithm {
                algorithm: format!("{:?}", self.algorithm),
            });
        }
        
        // Must be exactly 32 bytes
        assert_eq!(self.value_len, SHA256_FINGERPRINT_LEN,
            "Fingerprint length must be 32 bytes");
        
        if self.value_len != SHA256_FINGERPRINT_LEN {
            return Err(SdpError::InvalidFingerprint {
                reason: "SHA-256 must be 32 bytes",
            });
        }
        
        Ok(())
    }
    
    /// Serialize to SDP attribute value.
    pub fn to_sdp(&self) -> String {
        let algo = match self.algorithm {
            FingerprintAlgorithm::Sha256 => "sha-256",
            FingerprintAlgorithm::Sha384 => "sha-384",
            FingerprintAlgorithm::Sha512 => "sha-512",
        };
        
        let hex: Vec<String> = self.value[..self.value_len as usize]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        
        format!("{} {}", algo, hex.join(":"))
    }
}

/// DTLS setup role from SDP a=setup line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsSetup {
    Active,
    Passive,
    Actpass,
    Holdconn,
}

impl DtlsSetup {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(DtlsSetup::Active),
            "passive" => Some(DtlsSetup::Passive),
            "actpass" => Some(DtlsSetup::Actpass),
            "holdconn" => Some(DtlsSetup::Holdconn),
            _ => None,
        }
    }
    
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            DtlsSetup::Active => "active",
            DtlsSetup::Passive => "passive",
            DtlsSetup::Actpass => "actpass",
            DtlsSetup::Holdconn => "holdconn",
        }
    }
}

/// RTP codec from SDP a=rtpmap line.
#[derive(Debug, Clone, PartialEq)]
pub struct RtpCodec {
    /// Payload type.
    pub payload_type: u8,
    /// Codec name.
    pub name: [u8; 32],
    /// Name length.
    pub name_len: u8,
    /// Clock rate.
    pub clock_rate: u32,
    /// Number of channels (for audio).
    pub channels: Option<u8>,
}

impl RtpCodec {
    /// Parse from rtpmap value.
    ///
    /// Format: payload_type name/clock_rate[/channels]
    pub fn parse(payload_type: u8, value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() < 2 {
            return Err(SdpError::InvalidAttribute { 
                name: "rtpmap".to_string(), 
                value: value.to_string() 
            });
        }
        
        let mut name = [0u8; 32];
        let name_bytes = parts[0].as_bytes();
        let name_len = name_bytes.len().min(32);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);
        
        let clock_rate = parts[1].parse::<u32>()
            .map_err(|_| SdpError::InvalidAttribute { 
                name: "rtpmap".to_string(), 
                value: value.to_string() 
            })?;
        
        let channels = parts.get(2)
            .and_then(|s| s.parse::<u8>().ok());
        
        Ok(Self {
            payload_type,
            name,
            name_len: name_len as u8,
            clock_rate,
            channels,
        })
    }
    
    /// Get codec name as string.
    pub fn name_str(&self) -> &str {
        std::str::from_utf8(&self.name[..self.name_len as usize])
            .unwrap_or("unknown")
    }
    
    /// Serialize to rtpmap value.
    pub fn to_sdp(&self) -> String {
        let name = self.name_str();
        if let Some(ch) = self.channels {
            format!("{} {}/{}/{}", self.payload_type, name, self.clock_rate, ch)
        } else {
            format!("{} {}/{}", self.payload_type, name, self.clock_rate)
        }
    }
}

/// RTCP feedback from SDP a=rtcp-fb line.
#[derive(Debug, Clone, PartialEq)]
pub struct RtcpFeedback {
    /// Payload type (* for all).
    pub payload_type: Option<u8>,
    /// Feedback type.
    pub fb_type: [u8; 32],
    /// Type length.
    pub fb_type_len: u8,
    /// Feedback parameters.
    pub params: [u8; 64],
    /// Params length.
    pub params_len: u8,
}

/// SSRC information from SDP a=ssrc line.
#[derive(Debug, Clone, PartialEq)]
pub struct SsrcInfo {
    /// SSRC value.
    pub ssrc: u32,
    /// Attribute name.
    pub attribute: [u8; 32],
    /// Attribute name length.
    pub attr_len: u8,
    /// Attribute value.
    pub value: [u8; 128],
    /// Value length.
    pub value_len: u8,
}

impl SsrcInfo {
    /// Parse from ssrc attribute value.
    ///
    /// Format: ssrc attribute:value
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let space_pos = value.find(' ')
            .ok_or(SdpError::InvalidAttribute { 
                name: "ssrc".to_string(), 
                value: value.to_string() 
            })?;
        
        let ssrc = value[..space_pos].parse::<u32>()
            .map_err(|_| SdpError::InvalidAttribute { 
                name: "ssrc".to_string(), 
                value: value.to_string() 
            })?;
        
        let rest = &value[space_pos + 1..];
        let (attr, val) = if let Some(colon_pos) = rest.find(':') {
            (&rest[..colon_pos], &rest[colon_pos + 1..])
        } else {
            (rest, "")
        };
        
        let mut attribute = [0u8; 32];
        let attr_bytes = attr.as_bytes();
        let attr_len = attr_bytes.len().min(32);
        attribute[..attr_len].copy_from_slice(&attr_bytes[..attr_len]);
        
        let mut value_buf = [0u8; 128];
        let val_bytes = val.as_bytes();
        let value_len = val_bytes.len().min(128);
        value_buf[..value_len].copy_from_slice(&val_bytes[..value_len]);
        
        Ok(Self {
            ssrc,
            attribute,
            attr_len: attr_len as u8,
            value: value_buf,
            value_len: value_len as u8,
        })
    }
}

/// RTP header extension mapping from SDP a=extmap line.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtMap {
    /// Extension ID (1-14 for one-byte, 1-255 for two-byte).
    pub id: u8,
    /// Direction (optional).
    pub direction: Option<Direction>,
    /// Extension URI.
    pub uri: [u8; 128],
    /// URI length.
    pub uri_len: u8,
}

/// Media direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sendrecv" => Some(Direction::SendRecv),
            "sendonly" => Some(Direction::SendOnly),
            "recvonly" => Some(Direction::RecvOnly),
            "inactive" => Some(Direction::Inactive),
            _ => None,
        }
    }
    
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }
}

/// Format parameters from SDP a=fmtp line.
#[derive(Debug, Clone, PartialEq)]
pub struct Fmtp {
    /// Payload type.
    pub payload_type: u8,
    /// Format parameters.
    pub params: [u8; 256],
    /// Params length.
    pub params_len: u16,
}

impl Fmtp {
    /// Parse from fmtp value.
    ///
    /// Format: payload_type parameters
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let space_pos = value.find(' ')
            .ok_or(SdpError::InvalidAttribute { 
                name: "fmtp".to_string(), 
                value: value.to_string() 
            })?;
        
        let payload_type = value[..space_pos].parse::<u8>()
            .map_err(|_| SdpError::InvalidAttribute { 
                name: "fmtp".to_string(), 
                value: value.to_string() 
            })?;
        
        let params_str = &value[space_pos + 1..];
        let mut params = [0u8; 256];
        let params_bytes = params_str.as_bytes();
        let params_len = params_bytes.len().min(256);
        params[..params_len].copy_from_slice(&params_bytes[..params_len]);
        
        Ok(Self {
            payload_type,
            params,
            params_len: params_len as u16,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ice_candidate_parse() {
        let candidate = "1 1 udp 2130706431 192.168.1.1 54321 typ host";
        let parsed = IceCandidate::parse(candidate).unwrap();
        
        assert_eq!(parsed.component, 1);
        assert_eq!(parsed.transport, CandidateTransport::Udp);
        assert_eq!(parsed.priority, 2130706431);
        assert_eq!(parsed.typ, CandidateType::Host);
    }
    
    #[test]
    fn test_ice_candidate_roundtrip() {
        let candidate = "1 1 udp 2130706431 192.168.1.1 54321 typ host";
        let parsed = IceCandidate::parse(candidate).unwrap();
        let serialized = parsed.to_sdp();
        
        assert!(serialized.contains("192.168.1.1"));
        assert!(serialized.contains("54321"));
        assert!(serialized.contains("host"));
    }
    
    #[test]
    fn test_dtls_fingerprint_parse() {
        let fp = "sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90";
        let parsed = DtlsFingerprint::parse(fp).unwrap();
        
        assert_eq!(parsed.algorithm, FingerprintAlgorithm::Sha256);
        assert_eq!(parsed.value_len, 32);
        assert_eq!(parsed.value[0], 0xAB);
        assert_eq!(parsed.value[1], 0xCD);
    }
    
    #[test]
    fn test_dtls_setup_parse() {
        assert_eq!(DtlsSetup::parse("active"), Some(DtlsSetup::Active));
        assert_eq!(DtlsSetup::parse("passive"), Some(DtlsSetup::Passive));
        assert_eq!(DtlsSetup::parse("actpass"), Some(DtlsSetup::Actpass));
    }
    
    #[test]
    fn test_rtp_codec_parse() {
        let codec = RtpCodec::parse(111, "opus/48000/2").unwrap();
        
        assert_eq!(codec.payload_type, 111);
        assert_eq!(codec.name_str(), "opus");
        assert_eq!(codec.clock_rate, 48000);
        assert_eq!(codec.channels, Some(2));
    }
    
    #[test]
    fn test_ssrc_info_parse() {
        let ssrc = SsrcInfo::parse("1234567890 cname:test").unwrap();
        
        assert_eq!(ssrc.ssrc, 1234567890);
    }
    
    #[test]
    fn test_direction() {
        assert_eq!(Direction::parse("sendrecv"), Some(Direction::SendRecv));
        assert_eq!(Direction::SendOnly.as_str(), "sendonly");
    }
}
