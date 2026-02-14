//! ICE Server Configuration.
//!
//! Configuration for STUN/TURN servers used in ICE candidate gathering.
//! Supports configurable primary servers with Google STUN fallback.
//!
//! # TigerStyle Compliance
//!
//! - Explicit types throughout
//! - Bounded arrays for server lists
//! - Comprehensive validation

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Maximum number of STUN servers that can be configured.
pub const MAX_STUN_SERVERS: usize = 8;

/// Maximum number of TURN servers that can be configured.
pub const MAX_TURN_SERVERS: usize = 4;

/// Google STUN servers (fallback).
///
/// These are reliable public STUN servers provided by Google.
/// Used when no primary STUN servers are configured and fallback is enabled.
pub const GOOGLE_STUN_SERVERS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
];

/// TURN server configuration.
///
/// Contains the URL and credentials for a TURN relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServerConfig {
    /// TURN server URL (e.g., "turn:turn.example.com:3478").
    pub url: String,
    
    /// Username for TURN authentication.
    pub username: String,
    
    /// Credential (password) for TURN authentication.
    pub credential: String,
}

impl TurnServerConfig {
    /// Create a new TURN server configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - TURN server URL
    /// * `username` - Authentication username
    /// * `credential` - Authentication credential/password
    pub fn new(url: impl Into<String>, username: impl Into<String>, credential: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            credential: credential.into(),
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

/// ICE server configuration.
///
/// Controls STUN/TURN server settings for NAT traversal.
/// When no primary servers are configured and `use_google_fallback` is true,
/// Google's public STUN servers are used automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServerConfig {
    /// Primary STUN server URLs (e.g., "stun:stun.example.com:3478").
    #[serde(default)]
    pub stun_servers: Vec<String>,
    
    /// Primary TURN server configurations.
    #[serde(default)]
    pub turn_servers: Vec<TurnServerConfig>,
    
    /// Use Google STUN servers as fallback when no primary STUN servers configured.
    #[serde(default = "default_use_google_fallback")]
    pub use_google_fallback: bool,
}

/// Default value for use_google_fallback (true).
fn default_use_google_fallback() -> bool {
    true
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
    pub fn effective_stun_servers(&self) -> Vec<String> {
        if !self.stun_servers.is_empty() {
            self.stun_servers.clone()
        } else if self.use_google_fallback {
            GOOGLE_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    /// Validate the ICE server configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Precondition: STUN server count must not exceed maximum
        assert!(self.stun_servers.len() <= MAX_STUN_SERVERS,
            "STUN server count must not exceed {}", MAX_STUN_SERVERS);
        
        if self.stun_servers.len() > MAX_STUN_SERVERS {
            return Err(ConfigError::invalid(
                "ice_servers.stun_servers",
                &format!("must not exceed {} servers", MAX_STUN_SERVERS),
            ));
        }

        // Precondition: TURN server count must not exceed maximum
        assert!(self.turn_servers.len() <= MAX_TURN_SERVERS,
            "TURN server count must not exceed {}", MAX_TURN_SERVERS);
        
        if self.turn_servers.len() > MAX_TURN_SERVERS {
            return Err(ConfigError::invalid(
                "ice_servers.turn_servers",
                &format!("must not exceed {} servers", MAX_TURN_SERVERS),
            ));
        }

        // Validate STUN server URLs
        for (i, url) in self.stun_servers.iter().enumerate() {
            if url.is_empty() {
                return Err(ConfigError::invalid(
                    &format!("ice_servers.stun_servers[{}]", i),
                    "URL must not be empty",
                ));
            }
            
            // STUN URLs should start with stun: or stuns:
            if !url.starts_with("stun:") && !url.starts_with("stuns:") {
                return Err(ConfigError::invalid(
                    &format!("ice_servers.stun_servers[{}]", i),
                    "URL must start with 'stun:' or 'stuns:'",
                ));
            }
        }

        // Validate TURN server configurations
        for (i, turn) in self.turn_servers.iter().enumerate() {
            if let Err(msg) = turn.validate() {
                return Err(ConfigError::invalid(
                    &format!("ice_servers.turn_servers[{}]", i),
                    &msg,
                ));
            }
        }

        // Postcondition: Must have STUN servers or fallback enabled
        // (warning only, not an error - some deployments may use TURN only)
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    fn test_turn_server_config_validation() {
        let valid = TurnServerConfig::new(
            "turn:turn.example.com:3478",
            "user",
            "pass",
        );
        assert!(valid.validate().is_ok());

        let invalid_url = TurnServerConfig::new("", "user", "pass");
        assert!(invalid_url.validate().is_err());

        let invalid_scheme = TurnServerConfig::new(
            "http://turn.example.com:3478",
            "user",
            "pass",
        );
        assert!(invalid_scheme.validate().is_err());

        let invalid_user = TurnServerConfig::new(
            "turn:turn.example.com:3478",
            "",
            "pass",
        );
        assert!(invalid_user.validate().is_err());
    }

    #[test]
    fn test_ice_server_config_validation() {
        let valid = IceServerConfig {
            stun_servers: vec!["stun:stun.example.com:3478".to_string()],
            turn_servers: vec![TurnServerConfig::new(
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

    #[test]
    fn test_ice_server_config_serde_roundtrip() {
        let config = IceServerConfig {
            stun_servers: vec!["stun:stun.example.com:3478".to_string()],
            turn_servers: vec![TurnServerConfig::new(
                "turn:turn.example.com:3478",
                "user",
                "pass",
            )],
            use_google_fallback: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: IceServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.stun_servers, decoded.stun_servers);
        assert_eq!(config.turn_servers.len(), decoded.turn_servers.len());
        assert_eq!(config.turn_servers[0].url, decoded.turn_servers[0].url);
        assert_eq!(config.use_google_fallback, decoded.use_google_fallback);
    }
}
