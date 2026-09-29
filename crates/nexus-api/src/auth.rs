//! JWT authentication for nexus-api.
//!
//! Provides JWT token validation using HS256 algorithm.
//!
//! # TigerStyle Compliance
//!
//! - Assertions: secret.len() >= 32, token.len() > 0
//! - Explicit error handling with ApiError::Unauthorized

use crate::error::ApiError;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Minimum required secret length for security (256 bits)
pub const MIN_SECRET_LEN: usize = 32;

/// Most room names one token may carry in its `rooms` claim.
pub const MAX_TOKEN_ROOMS: usize = 16;

/// The `rooms` entry that grants every room, including unnamed ones.
pub const ROOM_WILDCARD: &str = "*";

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
    /// Names of the rooms the holder may create, join or manage; `"*"` grants every
    /// room. Missing or empty grants none (the token still authenticates).
    #[serde(default)]
    pub rooms: Vec<String>,
}

impl Claims {
    /// The rooms these claims grant.
    pub fn room_grant(&self) -> RoomGrant {
        assert!(self.rooms.len() <= MAX_TOKEN_ROOMS, "validated claims");
        if self.rooms.iter().any(|r| r == ROOM_WILDCARD) {
            return RoomGrant::Any;
        }
        RoomGrant::Names(self.rooms.clone().into_boxed_slice())
    }
}

/// The rooms a token grants, kept per connection by the orchestrator and per request
/// by the REST API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomGrant {
    /// Every room, named or not (`"*"`).
    Any,
    /// Only rooms with exactly these names.
    Names(Box<[String]>),
}

impl RoomGrant {
    /// Grants no room.
    pub fn none() -> Self {
        RoomGrant::Names(Box::new([]))
    }

    /// Whether a room with this name may be used. `None` or `""` is an unnamed room,
    /// which only `Any` grants.
    pub fn allows(&self, name: Option<&str>) -> bool {
        match (self, name) {
            (RoomGrant::Any, _) => true,
            (RoomGrant::Names(_), None | Some("")) => false,
            (RoomGrant::Names(names), Some(name)) => names.iter().any(|n| n == name),
        }
    }
}

/// Checks the `rooms` claim, which comes from the client: bounded count, each name
/// non-empty and no longer than a room name can be.
fn check_rooms(rooms: &[String]) -> Result<(), ApiError> {
    let reason = if rooms.len() > MAX_TOKEN_ROOMS {
        format!("token names more than {MAX_TOKEN_ROOMS} rooms")
    } else if rooms.iter().any(|r| r.is_empty()) {
        "token names an empty room".to_string()
    } else if rooms
        .iter()
        .any(|r| r.len() > nexus_state::MAX_ROOM_NAME_LEN)
    {
        let max = nexus_state::MAX_ROOM_NAME_LEN;
        format!("token names a room longer than {max} bytes")
    } else {
        return Ok(());
    };
    Err(ApiError::Unauthorized { reason })
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
    /// The token comes from untrusted clients, so malformed input (including an
    /// empty token or empty subject) is rejected with an error, never a panic.
    pub fn validate(&self, token: &str) -> Result<Claims, ApiError> {
        if token.is_empty() {
            return Err(ApiError::Unauthorized {
                reason: "empty token".to_string(),
            });
        }
        // TigerStyle: Precondition assertion (guaranteed by the check above)
        assert!(!token.is_empty(), "Token must not be empty");

        // Decode and validate token
        let token_data =
            decode::<Claims>(token, &self.decoding_key, &self.validation).map_err(|e| {
                ApiError::Unauthorized {
                    reason: format!("invalid token: {}", e),
                }
            })?;

        if token_data.claims.sub.is_empty() {
            return Err(ApiError::Unauthorized {
                reason: "token has empty subject".to_string(),
            });
        }
        // TigerStyle: Postcondition assertion (guaranteed by the check above)
        assert!(
            !token_data.claims.sub.is_empty(),
            "Claims must have non-empty subject"
        );
        check_rooms(&token_data.claims.rooms)?;

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
            rooms: vec!["demo".to_string()],
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
    fn test_validate_empty_token_is_rejected_not_panic() {
        let validator = JwtValidator::new("test-secret-that-is-at-least-32-chars-long");
        assert!(matches!(
            validator.validate(""),
            Err(ApiError::Unauthorized { .. })
        ));
    }

    #[test]
    fn test_validate_empty_subject_is_rejected_not_panic() {
        let secret = "test-secret-that-is-at-least-32-chars-long";
        let validator = JwtValidator::new(secret);
        let claims = Claims {
            sub: String::new(),
            exp: u64::MAX / 2,
            iat: 0,
            rooms: Vec::new(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        assert!(matches!(
            validator.validate(&token),
            Err(ApiError::Unauthorized { .. })
        ));
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
        assert_eq!(claims.rooms, vec!["demo".to_string()]);
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

    fn token_with_rooms(secret: &str, rooms: serde_json::Value) -> String {
        let claims = serde_json::json!({ "sub": "u", "exp": u64::MAX / 2, "rooms": rooms });
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    #[test]
    fn test_missing_rooms_claim_grants_nothing() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        let claims = serde_json::json!({ "sub": "u", "exp": u64::MAX / 2 });
        let key = EncodingKey::from_secret(secret.as_bytes());
        let token = encode(&Header::default(), &claims, &key).unwrap();
        let claims = validator.validate(&token).expect("authenticates");
        assert!(claims.rooms.is_empty());
        assert_eq!(claims.room_grant(), RoomGrant::none());
        assert!(!claims.room_grant().allows(Some("demo")));
    }

    #[test]
    fn test_rooms_claim_limits_are_refused_not_panic() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        let too_many: Vec<String> = (0..=MAX_TOKEN_ROOMS).map(|i| format!("r{i}")).collect();
        let too_long = "x".repeat(nexus_state::MAX_ROOM_NAME_LEN + 1);
        let longest = "x".repeat(nexus_state::MAX_ROOM_NAME_LEN);
        for rooms in [
            serde_json::json!(too_many),
            serde_json::json!([""]),
            serde_json::json!([too_long]),
            serde_json::json!("demo"),
            serde_json::json!([1]),
        ] {
            let token = token_with_rooms(&secret, rooms.clone());
            assert!(
                matches!(
                    validator.validate(&token),
                    Err(ApiError::Unauthorized { .. })
                ),
                "{rooms} must be refused"
            );
        }
        let at_limit: Vec<String> = (0..MAX_TOKEN_ROOMS).map(|i| format!("r{i}")).collect();
        let token = token_with_rooms(&secret, serde_json::json!(at_limit));
        assert_eq!(
            validator.validate(&token).unwrap().rooms.len(),
            MAX_TOKEN_ROOMS
        );
        let token = token_with_rooms(&secret, serde_json::json!([longest]));
        assert!(validator.validate(&token).is_ok());
    }

    #[test]
    fn test_room_grant_allows() {
        let names = RoomGrant::Names(vec!["demo".to_string(), "b".to_string()].into());
        assert!(names.allows(Some("demo")));
        assert!(names.allows(Some("b")));
        assert!(!names.allows(Some("Demo")));
        assert!(!names.allows(Some("demo2")));
        assert!(!names.allows(Some("")));
        assert!(!names.allows(None));
        assert!(RoomGrant::Any.allows(None));
        assert!(RoomGrant::Any.allows(Some("")));
        assert!(RoomGrant::Any.allows(Some("anything")));
        assert!(!RoomGrant::none().allows(Some("demo")));
        assert!(!RoomGrant::none().allows(None));
    }

    #[test]
    fn test_wildcard_among_names_grants_every_room() {
        let secret = create_test_secret();
        let validator = JwtValidator::new(&secret);
        let token = token_with_rooms(&secret, serde_json::json!(["demo", ROOM_WILDCARD]));
        let grant = validator.validate(&token).unwrap().room_grant();
        assert_eq!(grant, RoomGrant::Any);
    }
}
