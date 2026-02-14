//! JWT authentication for nexus-api.
//!
//! Provides JWT token validation using HS256 algorithm.
//!
//! # TigerStyle Compliance
//!
//! - Assertions: secret.len() >= 32, token.len() > 0
//! - Explicit error handling with ApiError::Unauthorized

use crate::error::ApiError;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

/// Minimum required secret length for security (256 bits)
pub const MIN_SECRET_LEN: usize = 32;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user identifier)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at time (Unix timestamp)
    #[serde(default)]
    pub iat: u64,
}

/// JWT token validator using HS256 algorithm.
///
/// # TigerStyle
///
/// - Pre-allocated decoding key
/// - Explicit validation configuration
/// - No dynamic allocation on validate()
#[derive(Clone)]
pub struct JwtValidator {
    /// Pre-computed decoding key from secret
    decoding_key: DecodingKey,
    /// Validation configuration
    validation: Validation,
}

impl JwtValidator {
    /// Create a new JWT validator with the given secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - HMAC secret for HS256 algorithm
    ///
    /// # Assertions
    ///
    /// - secret.len() >= 32 (256 bits minimum for security)
    ///
    /// # Panics
    ///
    /// Panics if secret is too short.
    pub fn new(secret: &str) -> Self {
        // TigerStyle: Precondition assertion
        assert!(
            secret.len() >= MIN_SECRET_LEN,
            "JWT secret must be at least {} characters, got {}",
            MIN_SECRET_LEN,
            secret.len()
        );

        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        // Require exp claim
        validation.required_spec_claims.insert("exp".to_string());
        // Validate expiration
        validation.validate_exp = true;

        // TigerStyle: Postcondition assertion
        assert!(
            validation.algorithms.contains(&Algorithm::HS256),
            "Validation must use HS256 algorithm"
        );

        Self {
            decoding_key,
            validation,
        }
    }

    /// Validate a JWT token and extract claims.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string (without "Bearer " prefix)
    ///
    /// # Returns
    ///
    /// - `Ok(Claims)` if token is valid and not expired
    /// - `Err(ApiError::Unauthorized)` if token is invalid or expired
    ///
    /// # Assertions
    ///
    /// - token.len() > 0
    pub fn validate(&self, token: &str) -> Result<Claims, ApiError> {
        // TigerStyle: Precondition assertion
        assert!(!token.is_empty(), "Token must not be empty");

        // Decode and validate token
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| ApiError::Unauthorized {
                reason: format!("invalid token: {}", e),
            })?;

        // TigerStyle: Postcondition assertion
        assert!(
            !token_data.claims.sub.is_empty(),
            "Claims must have non-empty subject"
        );

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn create_test_secret() -> String {
        "this-is-a-test-secret-with-32-chars!".to_string()
    }

    fn create_valid_token(secret: &str, exp_offset_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (now as i64 + exp_offset_secs) as u64,
            iat: now,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_validator_creation() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        // Validator should be created successfully
        assert!(validator.validation.validate_exp);
    }

    #[test]
    #[should_panic(expected = "JWT secret must be at least")]
    fn test_validator_short_secret_panics() {
        JwtValidator::new("short");
    }

    #[test]
    fn test_valid_token() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        let token = create_valid_token(&secret, 3600); // 1 hour from now

        let result = validator.validate(&token);
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, "test-user");
    }

    #[test]
    fn test_expired_token() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        let token = create_valid_token(&secret, -3600); // 1 hour ago

        let result = validator.validate(&token);
        assert!(result.is_err());
        match result {
            Err(ApiError::Unauthorized { reason }) => {
                assert!(reason.contains("invalid token"));
            }
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_invalid_token() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);

        let result = validator.validate("not.a.valid.token");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let secret = create_test_secret();
        let wrong_secret = "different-secret-with-32-chars!!";
        let validator = JwtValidator::new(wrong_secret);
        let token = create_valid_token(&secret, 3600);

        let result = validator.validate(&token);
        assert!(result.is_err());
    }
}
