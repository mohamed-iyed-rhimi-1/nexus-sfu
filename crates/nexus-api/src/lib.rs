//! nexus-api: HTTP REST API for Nexus SFU
//!
//! Provides health checks, metrics export, room management, and
//! recording control endpoints with JWT authentication.
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
//! - `POST /rooms/:id/recording/start` - Start recording (JWT required)
//! - `POST /rooms/:id/recording/pause` - Pause recording (JWT required)
//! - `POST /rooms/:id/recording/resume` - Resume recording (JWT required)
//! - `POST /rooms/:id/recording/stop` - Stop recording (JWT required)
//! - `GET /rooms/:id/recording` - Get recording status (JWT required)
//! - `GET /recordings` - List all recordings (JWT required)
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
pub mod recording;
pub mod rest;

pub use auth::JwtValidator;
pub use error::ApiError;
pub use recording::{recording_routes, SharedRecordingManager};
pub use rest::ApiServer;
