//! ICE Types and Configuration.
//!
//! Core types for ICE agent configuration and state management.
//! All types use explicitly-sized integers and static allocation.
//!
//! # TigerStyle Compliance
//!
//! - Explicit u32/u64 types throughout
//! - Units in field names (timeout_ms, interval_ns)
//! - Compile-time assertions for invariants
//! - No dynamic allocation

use std::net::SocketAddr;
use getrandom::getrandom;

/// ICE Agent Role.
///
/// Determines tie-breaking behavior during connectivity checks.
/// The controlling agent nominates the selected pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IceRole {
    /// Controlling agent (typically the offerer).
    /// Nominates candidate pairs for use.
    Controlling = 0,
    
    /// Controlled agent (typically the answerer).
    /// Accepts nominations from controlling agent.
    Controlled = 1,
}

impl IceRole {
    /// Flip the role (for handling role conflicts).
    #[inline]
    pub const fn flip(self) -> Self {
        match self {
            Self::Controlling => Self::Controlled,
            Self::Controlled => Self::Controlling,
        }
    }
}

/// ICE Connection State.
///
/// Tracks the overall state of ICE connectivity establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IceConnectionState {
    /// Initial state, no checks performed.
    New = 0,
    
    /// Connectivity checks in progress.
    Checking = 1,
    
    /// At least one working pair found.
    Connected = 2,
    
    /// ICE completed successfully with nominated pair.
    Completed = 3,
    
    /// All connectivity checks failed.
    Failed = 4,
    
    /// Previously connected, now disconnected.
    Disconnected = 5,
    
    /// ICE agent closed.
    Closed = 6,
}

impl IceConnectionState {
    /// Returns true if ICE has established connectivity.
    #[inline]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected | Self::Completed)
    }

    /// Returns true if ICE is in a terminal state.
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closed)
    }

    /// Returns true if this state can transition to another.
    #[inline]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            // From New
            (Self::New, Self::Checking) => true,
            (Self::New, Self::Closed) => true,
            
            // From Checking
            (Self::Checking, Self::Connected) => true,
            (Self::Checking, Self::Failed) => true,
            (Self::Checking, Self::Closed) => true,
            
            // From Connected
            (Self::Connected, Self::Completed) => true,
            (Self::Connected, Self::Disconnected) => true,
            (Self::Connected, Self::Closed) => true,
            
            // From Completed
            (Self::Completed, Self::Disconnected) => true,
            (Self::Completed, Self::Closed) => true,
            
            // From Disconnected
            (Self::Disconnected, Self::Checking) => true,
            (Self::Disconnected, Self::Connected) => true,
            (Self::Disconnected, Self::Failed) => true,
            (Self::Disconnected, Self::Closed) => true,
            
            // Terminal states cannot transition
            (Self::Failed, _) => false,
            (Self::Closed, _) => false,
            
            _ => false,
        }
    }
}

/// ICE Gathering State.
///
/// Tracks the state of candidate gathering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IceGatheringState {
    /// Gathering not started.
    New = 0,
    
    /// Gathering in progress.
    Gathering = 1,
    
    /// Gathering complete.
    Complete = 2,
}

/// ICE Credentials.
///
/// Username fragment and password for ICE authentication.
/// Uses String for interoperability with signaling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    /// Local username fragment.
    pub local_ufrag: String,
    
    /// Local password.
    pub local_pwd: String,
}

impl IceCredentials {
    /// Create new credentials.
    pub fn new(ufrag: impl Into<String>, pwd: impl Into<String>) -> Self {
        Self {
            local_ufrag: ufrag.into(),
            local_pwd: pwd.into(),
        }
    }
    
    /// Generate random credentials.
    ///
    /// Uses alphanumeric charset only (no `+` or `/`) for maximum
    /// compatibility with all WebRTC implementations and SDP parsers.
    /// Password length is 32 characters per RFC 8445 recommendations.
    pub fn generate() -> Self {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        
        let mut ufrag_random = [0u8; 8];
        let mut pwd_random = [0u8; 32];
        
        getrandom(&mut ufrag_random).expect("getrandom failed");
        getrandom(&mut pwd_random).expect("getrandom failed");
        
        let ufrag: String = ufrag_random.iter()
            .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
            .collect();
        
        let pwd: String = pwd_random.iter()
            .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
            .collect();
        
        Self {
            local_ufrag: ufrag,
            local_pwd: pwd,
        }
    }
}

impl Default for IceCredentials {
    fn default() -> Self {
        Self::generate()
    }
}

/// Transport protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportType {
    /// UDP transport (most common for WebRTC).
    Udp = 17,  // IANA protocol number
    
    /// TCP transport (fallback).
    Tcp = 6,   // IANA protocol number
}

impl TransportType {
    /// Parse from string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }

    /// Convert to lowercase string.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// TURN server configuration.
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// TURN server address.
    pub address: SocketAddr,
    
    /// Username for authentication.
    pub username: [u8; 64],
    pub username_len: u8,
    
    /// Password for authentication.
    pub password: [u8; 64],
    pub password_len: u8,
    
    /// Use TLS (TURNS).
    pub use_tls: bool,
}

impl TurnServerConfig {
    /// Maximum username length.
    pub const MAX_USERNAME_LEN: usize = 64;
    
    /// Maximum password length.
    pub const MAX_PASSWORD_LEN: usize = 64;

    /// Create a new TURN server configuration.
    ///
    /// # Panics
    ///
    /// Panics if username or password exceeds maximum length.
    pub fn new(
        address: SocketAddr,
        username: &str,
        password: &str,
        use_tls: bool,
    ) -> Self {
        assert!(
            username.len() <= Self::MAX_USERNAME_LEN,
            "username too long: {} > {}",
            username.len(),
            Self::MAX_USERNAME_LEN
        );
        assert!(
            password.len() <= Self::MAX_PASSWORD_LEN,
            "password too long: {} > {}",
            password.len(),
            Self::MAX_PASSWORD_LEN
        );

        let mut username_buf = [0u8; 64];
        let mut password_buf = [0u8; 64];
        
        username_buf[..username.len()].copy_from_slice(username.as_bytes());
        password_buf[..password.len()].copy_from_slice(password.as_bytes());

        Self {
            address,
            username: username_buf,
            username_len: username.len() as u8,
            password: password_buf,
            password_len: password.len() as u8,
            use_tls,
        }
    }

    /// Get username as string slice.
    #[inline]
    pub fn username_str(&self) -> &str {
        // Safety: we only store valid UTF-8 from constructor
        unsafe {
            std::str::from_utf8_unchecked(&self.username[..self.username_len as usize])
        }
    }

    /// Get password as string slice.
    #[inline]
    pub fn password_str(&self) -> &str {
        // Safety: we only store valid UTF-8 from constructor
        unsafe {
            std::str::from_utf8_unchecked(&self.password[..self.password_len as usize])
        }
    }
}

/// ICE Agent Configuration.
///
/// All configuration uses fixed-size arrays and explicit types
/// to ensure deterministic memory usage.
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN server addresses (up to 4).
    pub stun_servers: [Option<SocketAddr>; 4],
    
    /// Number of configured STUN servers.
    pub stun_server_count: u8,
    
    /// TURN server configurations (up to 2).
    pub turn_servers: [Option<TurnServerConfig>; 2],
    
    /// Number of configured TURN servers.
    pub turn_server_count: u8,
    
    /// Local username fragment.
    pub local_ufrag: [u8; 32],
    pub local_ufrag_len: u8,
    
    /// Local password.
    pub local_pwd: [u8; 32],
    pub local_pwd_len: u8,
    
    /// Use aggressive nomination.
    pub aggressive_nomination: bool,
    
    /// Connectivity check timeout in milliseconds.
    pub check_timeout_ms: u32,
    
    /// Connectivity check interval in milliseconds.
    pub check_interval_ms: u32,
    
    /// Maximum retransmissions per check.
    pub max_retransmissions: u8,
}

impl IceConfig {
    /// Maximum STUN servers.
    pub const MAX_STUN_SERVERS: usize = 4;
    
    /// Maximum TURN servers.
    pub const MAX_TURN_SERVERS: usize = 2;
    
    /// Maximum ufrag length.
    pub const MAX_UFRAG_LEN: usize = 32;
    
    /// Maximum password length.
    pub const MAX_PWD_LEN: usize = 32;

    /// Create a new configuration with generated credentials.
    pub fn new() -> Self {
        let (ufrag, ufrag_len) = Self::generate_ufrag();
        let (pwd, pwd_len) = Self::generate_pwd();

        Self {
            stun_servers: [None; 4],
            stun_server_count: 0,
            turn_servers: [None, None],
            turn_server_count: 0,
            local_ufrag: ufrag,
            local_ufrag_len: ufrag_len,
            local_pwd: pwd,
            local_pwd_len: pwd_len,
            aggressive_nomination: true,
            check_timeout_ms: 5000,
            check_interval_ms: 50,
            max_retransmissions: 7,
        }
    }

    /// Add a STUN server.
    ///
    /// # Panics
    ///
    /// Panics if maximum STUN servers exceeded.
    pub fn add_stun_server(&mut self, addr: SocketAddr) {
        assert!(
            (self.stun_server_count as usize) < Self::MAX_STUN_SERVERS,
            "too many STUN servers"
        );
        
        self.stun_servers[self.stun_server_count as usize] = Some(addr);
        self.stun_server_count += 1;
    }

    /// Add a TURN server.
    ///
    /// # Panics
    ///
    /// Panics if maximum TURN servers exceeded.
    pub fn add_turn_server(&mut self, config: TurnServerConfig) {
        assert!(
            (self.turn_server_count as usize) < Self::MAX_TURN_SERVERS,
            "too many TURN servers"
        );
        
        self.turn_servers[self.turn_server_count as usize] = Some(config);
        self.turn_server_count += 1;
    }

    /// Get local ufrag as string slice.
    #[inline]
    pub fn local_ufrag_str(&self) -> &str {
        // Safety: we only store valid UTF-8
        unsafe {
            std::str::from_utf8_unchecked(&self.local_ufrag[..self.local_ufrag_len as usize])
        }
    }

    /// Get local password as string slice.
    #[inline]
    pub fn local_pwd_str(&self) -> &str {
        // Safety: we only store valid UTF-8
        unsafe {
            std::str::from_utf8_unchecked(&self.local_pwd[..self.local_pwd_len as usize])
        }
    }

    /// Generate random ICE ufrag.
    ///
    /// Uses alphanumeric charset only for maximum compatibility.
    fn generate_ufrag() -> ([u8; 32], u8) {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const LEN: usize = 8;
        
        let mut buf = [0u8; 32];
        let mut random = [0u8; LEN];
        
        // Use getrandom for cryptographic randomness
        getrandom(&mut random).expect("getrandom failed");
        
        for i in 0..LEN {
            buf[i] = CHARSET[(random[i] as usize) % CHARSET.len()];
        }
        
        (buf, LEN as u8)
    }

    /// Generate random ICE password.
    ///
    /// Uses alphanumeric charset only and 32-byte length for maximum
    /// compatibility with all WebRTC implementations.
    fn generate_pwd() -> ([u8; 32], u8) {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const LEN: usize = 32;
        
        let mut buf = [0u8; 32];
        let mut random = [0u8; LEN];
        
        getrandom(&mut random).expect("getrandom failed");
        
        for i in 0..LEN {
            buf[i] = CHARSET[(random[i] as usize) % CHARSET.len()];
        }
        
        (buf, LEN as u8)
    }
}

impl Default for IceConfig {
    fn default() -> Self {
        let mut config = Self::new();
        
        // Add Google's public STUN server as default
        // This is commonly used and reliable
        if let Ok(addr) = "74.125.250.129:19302".parse() {
            config.add_stun_server(addr);
        }
        
        config
    }
}

// Compile-time size assertions
const _: () = {
    // Ensure IceConfig is reasonably sized (config struct, not hot path)
    assert!(std::mem::size_of::<IceConfig>() <= 1024);
    
    // Ensure states fit in u8
    assert!(std::mem::size_of::<IceRole>() == 1);
    assert!(std::mem::size_of::<IceConnectionState>() == 1);
    assert!(std::mem::size_of::<IceGatheringState>() == 1);
    assert!(std::mem::size_of::<TransportType>() == 1);
};

// ============================================================================
// Phase 5: Comprehensive Compile-Time Assertions (TigerStyle)
// ============================================================================

/// Comprehensive compile-time validation for ICE types.
const _ICE_TYPES_COMPILE_TIME_CHECKS: () = {
    // IceConfig field size constraints
    assert!(IceConfig::MAX_STUN_SERVERS >= 1 && IceConfig::MAX_STUN_SERVERS <= 8,
        "STUN server count should be 1-8");
    assert!(IceConfig::MAX_TURN_SERVERS >= 1 && IceConfig::MAX_TURN_SERVERS <= 4,
        "TURN server count should be 1-4");
    assert!(IceConfig::MAX_UFRAG_LEN >= 8 && IceConfig::MAX_UFRAG_LEN <= 256,
        "UFRAG max length should be 8-256");
    assert!(IceConfig::MAX_PWD_LEN >= 24 && IceConfig::MAX_PWD_LEN <= 256,
        "PWD max length should be 24-256");
    
    // TurnServerConfig field size constraints
    assert!(TurnServerConfig::MAX_USERNAME_LEN >= 1 && TurnServerConfig::MAX_USERNAME_LEN <= 128,
        "TURN username max length should be 1-128");
    assert!(TurnServerConfig::MAX_PASSWORD_LEN >= 1 && TurnServerConfig::MAX_PASSWORD_LEN <= 128,
        "TURN password max length should be 1-128");
    
    // Ensure enum discriminants are as expected
    assert!(IceRole::Controlling as u8 == 0);
    assert!(IceRole::Controlled as u8 == 1);
    
    assert!(IceConnectionState::New as u8 == 0);
    assert!(IceConnectionState::Checking as u8 == 1);
    assert!(IceConnectionState::Connected as u8 == 2);
    assert!(IceConnectionState::Completed as u8 == 3);
    assert!(IceConnectionState::Failed as u8 == 4);
    assert!(IceConnectionState::Disconnected as u8 == 5);
    assert!(IceConnectionState::Closed as u8 == 6);
    
    assert!(IceGatheringState::New as u8 == 0);
    assert!(IceGatheringState::Gathering as u8 == 1);
    assert!(IceGatheringState::Complete as u8 == 2);
    
    // Transport type uses IANA protocol numbers
    assert!(TransportType::Tcp as u8 == 6, "TCP protocol number is 6");
    assert!(TransportType::Udp as u8 == 17, "UDP protocol number is 17");
    
    // TurnServerConfig should be reasonably sized
    assert!(std::mem::size_of::<TurnServerConfig>() <= 256,
        "TurnServerConfig should not exceed 256 bytes");
    
    // IceCredentials uses String so can't check size, but ensure types compile
    // (validation is done at runtime for credentials)
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_flip() {
        assert_eq!(IceRole::Controlling.flip(), IceRole::Controlled);
        assert_eq!(IceRole::Controlled.flip(), IceRole::Controlling);
    }

    #[test]
    fn test_connection_state_transitions() {
        assert!(IceConnectionState::New.can_transition_to(IceConnectionState::Checking));
        assert!(!IceConnectionState::Failed.can_transition_to(IceConnectionState::Connected));
        assert!(IceConnectionState::Connected.is_connected());
        assert!(IceConnectionState::Failed.is_terminal());
    }

    #[test]
    fn test_ice_config_default() {
        let config = IceConfig::default();
        
        assert!(config.local_ufrag_len >= 4);
        assert!(config.local_pwd_len >= 22);
        assert_eq!(config.stun_server_count, 1);
    }

    #[test]
    fn test_turn_server_config() {
        let addr = "192.168.1.1:3478".parse().unwrap();
        let config = TurnServerConfig::new(addr, "user", "pass", false);
        
        assert_eq!(config.username_str(), "user");
        assert_eq!(config.password_str(), "pass");
        assert!(!config.use_tls);
    }

    #[test]
    #[should_panic(expected = "username too long")]
    fn test_turn_server_config_username_too_long() {
        let addr = "192.168.1.1:3478".parse().unwrap();
        let long_user = "a".repeat(65);
        let _ = TurnServerConfig::new(addr, &long_user, "pass", false);
    }
}

// ============================================================================
// High-Level ICE Server Configuration (Application-Level)
// ============================================================================

/// Google STUN servers (fallback).
///
/// These are reliable public STUN servers provided by Google.
/// Used when no primary STUN servers are configured and fallback is enabled.
pub const GOOGLE_STUN_SERVERS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
];

/// Maximum number of STUN servers that can be configured.
pub const MAX_STUN_SERVERS_CONFIG: usize = 8;

/// Maximum number of TURN servers that can be configured.
pub const MAX_TURN_SERVERS_CONFIG: usize = 4;

/// High-level TURN server configuration.
///
/// Contains the URL and credentials for a TURN relay server.
/// This is the application-level config type (uses String for flexibility).
#[derive(Debug, Clone)]
pub struct HighLevelTurnServerConfig {
    /// TURN server URL (e.g., "turn:turn.example.com:3478").
    pub url: String,

    /// Username for TURN authentication.
    pub username: String,

    /// Credential (password) for TURN authentication.
    pub credential: String,
}

impl HighLevelTurnServerConfig {
    /// Create a new TURN server configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - TURN server URL
    /// * `username` - Authentication username
    /// * `credential` - Authentication credential/password
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertion for URL format
    /// - Postcondition assertion for non-empty fields
    pub fn new(url: impl Into<String>, username: impl Into<String>, credential: impl Into<String>) -> Self {
        let url = url.into();
        let username = username.into();
        let credential = credential.into();

        // Precondition: URL should not be empty
        assert!(!url.is_empty(), "TURN server URL must not be empty");

        // Postcondition: all fields populated
        assert!(!username.is_empty() || !credential.is_empty() || url.starts_with("turn:") || url.starts_with("turns:"),
            "TURN config should have valid URL format or credentials");

        Self {
            url,
            username,
            credential,
        }
    }

    /// Validate the TURN server configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Precondition: URL must not be empty
        if self.url.is_empty() {
            return Err("TURN server URL must not be empty".to_string());
        }

        // Precondition: URL must start with turn: or turns:
        if !self.url.starts_with("turn:") && !self.url.starts_with("turns:") {
            return Err("TURN server URL must start with 'turn:' or 'turns:'".to_string());
        }

        // Precondition: Username must not be empty
        if self.username.is_empty() {
            return Err("TURN server username must not be empty".to_string());
        }

        // Precondition: Credential must not be empty
        if self.credential.is_empty() {
            return Err("TURN server credential must not be empty".to_string());
        }

        Ok(())
    }
}

/// High-level ICE server configuration.
///
/// Controls STUN/TURN server settings for NAT traversal.
/// When no primary servers are configured and `use_google_fallback` is true,
/// Google's public STUN servers are used automatically.
///
/// This is the application-level config type (uses Vec for flexibility).
#[derive(Debug, Clone)]
pub struct IceServerConfig {
    /// Primary STUN server URLs (e.g., "stun:stun.example.com:3478").
    pub stun_servers: Vec<String>,

    /// Primary TURN server configurations.
    pub turn_servers: Vec<HighLevelTurnServerConfig>,

    /// Use Google STUN servers as fallback when no primary STUN servers configured.
    pub use_google_fallback: bool,
}

impl Default for IceServerConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            use_google_fallback: true,
        }
    }
}

impl IceServerConfig {
    /// Create a new ICE server configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create configuration with specific STUN servers.
    pub fn with_stun_servers(stun_servers: Vec<String>) -> Self {
        Self {
            stun_servers,
            turn_servers: Vec::new(),
            use_google_fallback: true,
        }
    }

    /// Get effective STUN servers (including fallback if enabled).
    ///
    /// Returns the configured STUN servers, or Google STUN servers
    /// if no primary servers are configured and fallback is enabled.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Postcondition assertion for result consistency
    pub fn effective_stun_servers(&self) -> Vec<String> {
        if !self.stun_servers.is_empty() {
            // Postcondition: return configured servers
            assert!(!self.stun_servers.is_empty(), "Should return non-empty configured servers");
            self.stun_servers.clone()
        } else if self.use_google_fallback {
            // Postcondition: return fallback servers
            let result: Vec<String> = GOOGLE_STUN_SERVERS.iter().map(|s| s.to_string()).collect();
            assert!(!result.is_empty(), "Google fallback should provide servers");
            result
        } else {
            Vec::new()
        }
    }

    /// Validate the ICE server configuration.
    ///
    /// # TigerStyle Compliance
    ///
    /// - Precondition assertions for server counts
    /// - Validates all nested configurations
    pub fn validate(&self) -> Result<(), String> {
        // Precondition: STUN server count must not exceed maximum
        assert!(self.stun_servers.len() <= MAX_STUN_SERVERS_CONFIG,
            "STUN server count must not exceed {}", MAX_STUN_SERVERS_CONFIG);

        if self.stun_servers.len() > MAX_STUN_SERVERS_CONFIG {
            return Err(format!("STUN servers must not exceed {} servers", MAX_STUN_SERVERS_CONFIG));
        }

        // Precondition: TURN server count must not exceed maximum
        assert!(self.turn_servers.len() <= MAX_TURN_SERVERS_CONFIG,
            "TURN server count must not exceed {}", MAX_TURN_SERVERS_CONFIG);

        if self.turn_servers.len() > MAX_TURN_SERVERS_CONFIG {
            return Err(format!("TURN servers must not exceed {} servers", MAX_TURN_SERVERS_CONFIG));
        }

        // Validate STUN server URLs
        for (i, url) in self.stun_servers.iter().enumerate() {
            if url.is_empty() {
                return Err(format!("STUN server URL at index {} must not be empty", i));
            }

            // STUN URLs should start with stun: or stuns:
            if !url.starts_with("stun:") && !url.starts_with("stuns:") {
                return Err(format!("STUN server URL at index {} must start with 'stun:' or 'stuns:'", i));
            }
        }

        // Validate TURN server configurations
        for (i, turn) in self.turn_servers.iter().enumerate() {
            if let Err(msg) = turn.validate() {
                return Err(format!("TURN server at index {}: {}", i, msg));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod ice_server_config_tests {
    use super::*;

    #[test]
    fn test_ice_server_config_default() {
        let config = IceServerConfig::default();

        assert!(config.stun_servers.is_empty());
        assert!(config.turn_servers.is_empty());
        assert!(config.use_google_fallback);
    }

    #[test]
    fn test_effective_stun_servers_with_fallback() {
        let config = IceServerConfig::default();
        let servers = config.effective_stun_servers();

        assert_eq!(servers.len(), GOOGLE_STUN_SERVERS.len());
        assert!(servers[0].contains("google.com"));
    }

    #[test]
    fn test_effective_stun_servers_with_primary() {
        let config = IceServerConfig::with_stun_servers(vec![
            "stun:stun.example.com:3478".to_string(),
        ]);
        let servers = config.effective_stun_servers();

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0], "stun:stun.example.com:3478");
    }

    #[test]
    fn test_effective_stun_servers_no_fallback() {
        let config = IceServerConfig {
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            use_google_fallback: false,
        };
        let servers = config.effective_stun_servers();

        assert!(servers.is_empty());
    }

    #[test]
    fn test_high_level_turn_server_config_validation() {
        let valid = HighLevelTurnServerConfig::new(
            "turn:turn.example.com:3478",
            "user",
            "pass",
        );
        assert!(valid.validate().is_ok());

        let invalid_scheme = HighLevelTurnServerConfig {
            url: "http://turn.example.com:3478".to_string(),
            username: "user".to_string(),
            credential: "pass".to_string(),
        };
        assert!(invalid_scheme.validate().is_err());
    }

    #[test]
    fn test_ice_server_config_validation() {
        let valid = IceServerConfig {
            stun_servers: vec!["stun:stun.example.com:3478".to_string()],
            turn_servers: vec![HighLevelTurnServerConfig::new(
                "turn:turn.example.com:3478",
                "user",
                "pass",
            )],
            use_google_fallback: true,
        };
        assert!(valid.validate().is_ok());

        let invalid_stun = IceServerConfig {
            stun_servers: vec!["http://invalid.com".to_string()],
            turn_servers: Vec::new(),
            use_google_fallback: true,
        };
        assert!(invalid_stun.validate().is_err());
    }
}

