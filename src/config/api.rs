//! API server configuration.
//!
//! Configuration for the HTTP REST API server including JWT authentication.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Minimum JWT secret length (256 bits)
pub const MIN_JWT_SECRET_LEN: usize = 32;

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Bind address for the API server
    pub bind_addr: String,
    /// JWT secret for authentication (minimum 32 characters)
    pub jwt_secret: String,
    /// Enable API server
    pub enabled: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8081".to_string(),
            // Default secret for development only - MUST be overridden in production
            jwt_secret: "dev-secret-minimum-32-characters-long".to_string(),
            enabled: true,
        }
    }
}

impl ApiConfig {
    /// Validate API configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - bind_addr is not a valid socket address
    /// - jwt_secret is shorter than 32 characters
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate bind address
        if self.bind_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::invalid(
                "api.bind_addr",
                "must be valid socket address",
            ));
        }

        // Validate JWT secret length
        if self.jwt_secret.len() < MIN_JWT_SECRET_LEN {
            return Err(ConfigError::invalid(
                "api.jwt_secret",
                &format!(
                    "must be at least {} characters for security",
                    MIN_JWT_SECRET_LEN
                ),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = ApiConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_bind_addr() {
        let config = ApiConfig {
            bind_addr: "not-an-address".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_short_jwt_secret() {
        let config = ApiConfig {
            jwt_secret: "short".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("jwt_secret"));
    }

    #[test]
    fn test_valid_custom_config() {
        let config = ApiConfig {
            bind_addr: "0.0.0.0:9000".to_string(),
            jwt_secret: "a-very-long-secret-that-is-at-least-32-chars".to_string(),
            enabled: true,
        };
        assert!(config.validate().is_ok());
    }
}
