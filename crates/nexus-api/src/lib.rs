//! nexus-api: HTTP REST API for Nexus SFU
//!
//! Provides health checks, metrics export, and room management endpoints
//! with JWT authentication.
//!
//! # Endpoints
//!
//! - `GET /health` - Health check (no auth)
//! - `GET /ready` - Readiness check (no auth)
//! - `GET /metrics` - Prometheus metrics (no auth)
//! - `POST /rooms` - Create room (JWT required)
//! - `GET /rooms` - List rooms (JWT required)
//! - `GET /rooms/:id` - Get room details (JWT required)
//! - `DELETE /rooms/:id` - Delete room (JWT required)
//!

#![deny(warnings)]
//! # TigerStyle Compliance
//!
//! - Minimum 2 assertions per public function
//! - Maximum 70 lines per function
//! - Maximum 100 columns per line
//! - Explicit error handling

pub mod auth;
pub mod error;
pub mod rest;

pub use auth::JwtValidator;
pub use error::ApiError;
pub use rest::ApiServer;
