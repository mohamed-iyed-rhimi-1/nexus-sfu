//! API error types for nexus-api.
//!
//! Wraps nexus-core::ApiError with HTTP response conversion for axum.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// JSON error response body
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error type identifier
    pub error: &'static str,
    /// Human-readable error message
    pub message: String,
}

/// API-specific errors for the HTTP REST server.
///
/// This is a local wrapper around nexus_core::ApiError to enable
/// implementing IntoResponse (orphan rule compliance).
#[derive(Debug, Error)]
pub enum ApiError {
    /// Unauthorized — missing or invalid JWT token
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// Resource not found
    #[error("not found: {resource}")]
    NotFound { resource: String },

    /// Bad request — invalid input
    #[error("bad request: {message}")]
    BadRequest { message: String },

    /// Internal server error
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    /// Convert ApiError to HTTP response.
    ///
    /// Maps error variants to appropriate HTTP status codes:
    /// - Unauthorized → 401
    /// - NotFound → 404
    /// - BadRequest → 400
    /// - Internal → 500
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            ApiError::Unauthorized { .. } => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            ApiError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            ApiError::BadRequest { .. } => {
                (StatusCode::BAD_REQUEST, "bad_request")
            }
            ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };

        let body = ErrorResponse {
            error: error_type,
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthorized_status() {
        let err = ApiError::Unauthorized {
            reason: "invalid token".to_string(),
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_not_found_status() {
        let err = ApiError::NotFound {
            resource: "room 42".to_string(),
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_bad_request_status() {
        let err = ApiError::BadRequest {
            message: "invalid input".to_string(),
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_internal_error_status() {
        let err = ApiError::Internal("database error".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
