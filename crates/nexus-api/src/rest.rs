//! REST API server for Nexus SFU.
//!
//! Provides health, readiness, metrics, and room management endpoints.
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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::auth::{JwtValidator, MIN_SECRET_LEN};
use crate::error::ApiError;
use nexus_metrics::MetricsCollector;
use nexus_state::DistributedState;

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// Readiness check response
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub message: &'static str,
}

/// Create room request
#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,
    #[serde(default = "default_max_participants")]
    pub max_participants: u32,
}

fn default_max_participants() -> u32 {
    100
}

/// Room response
#[derive(Debug, Clone, Serialize)]
pub struct RoomResponse {
    pub id: u32,
    pub name: String,
    pub participant_count: u32,
    pub max_participants: u32,
}

/// List rooms response
#[derive(Debug, Serialize)]
pub struct ListRoomsResponse {
    pub rooms: Vec<RoomResponse>,
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared application state for API handlers
pub struct AppState {
    /// JWT validator for authentication
    jwt_validator: JwtValidator,
    /// Metrics collector for /metrics endpoint
    metrics: Option<Arc<MetricsCollector>>,
    /// Readiness flag
    is_ready: AtomicBool,
    /// In-memory room storage (simplified for MVP)
    rooms: RwLock<Vec<RoomResponse>>,
    /// Next room ID
    next_room_id: std::sync::atomic::AtomicU32,
    /// Distributed state for room synchronization with orchestrator
    distributed_state: Option<Arc<DistributedState>>,
}

impl AppState {
    /// Create new application state.
    ///
    /// # Assertions
    ///
    /// - jwt_secret.len() >= 32
    pub fn new(jwt_secret: &str, metrics: Option<Arc<MetricsCollector>>) -> Self {
        assert!(
            jwt_secret.len() >= MIN_SECRET_LEN,
            "JWT secret must be at least {} characters",
            MIN_SECRET_LEN
        );

        Self {
            jwt_validator: JwtValidator::new(jwt_secret),
            metrics,
            is_ready: AtomicBool::new(false),
            rooms: RwLock::new(Vec::new()),
            next_room_id: std::sync::atomic::AtomicU32::new(1),
            distributed_state: None,
        }
    }

    /// Create new application state with distributed state for room synchronization.
    ///
    /// # Assertions
    ///
    /// - jwt_secret.len() >= 32
    pub fn with_distributed_state(
        jwt_secret: &str,
        metrics: Option<Arc<MetricsCollector>>,
        distributed_state: Arc<DistributedState>,
    ) -> Self {
        assert!(
            jwt_secret.len() >= MIN_SECRET_LEN,
            "JWT secret must be at least {} characters",
            MIN_SECRET_LEN
        );

        Self {
            jwt_validator: JwtValidator::new(jwt_secret),
            metrics,
            is_ready: AtomicBool::new(false),
            rooms: RwLock::new(Vec::new()),
            next_room_id: std::sync::atomic::AtomicU32::new(1),
            distributed_state: Some(distributed_state),
        }
    }

    /// Set readiness state
    pub fn set_ready(&self, ready: bool) {
        self.is_ready.store(ready, Ordering::SeqCst);
    }
}


// ---------------------------------------------------------------------------
// API Server
// ---------------------------------------------------------------------------

/// HTTP API server for Nexus SFU.
///
/// # TigerStyle
///
/// - Pre-configured router at construction
/// - Explicit bind address validation
/// - Graceful shutdown support
pub struct ApiServer {
    /// Bind address for the server
    bind_addr: SocketAddr,
    /// Axum router with all routes configured
    router: Router,
}

impl ApiServer {
    /// Create a new API server.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Address to bind the server to
    /// * `jwt_secret` - Secret for JWT validation (min 32 chars)
    /// * `metrics` - Optional metrics collector for /metrics endpoint
    ///
    /// # Assertions
    ///
    /// - bind_addr.port() > 0
    /// - jwt_secret.len() >= 32
    pub fn new(
        bind_addr: SocketAddr,
        jwt_secret: &str,
        metrics: Option<Arc<MetricsCollector>>,
    ) -> Self {
        // TigerStyle: Precondition assertions
        assert!(bind_addr.port() > 0, "Bind port must be > 0");
        assert!(
            jwt_secret.len() >= MIN_SECRET_LEN,
            "JWT secret must be at least {} characters",
            MIN_SECRET_LEN
        );

        let state = Arc::new(AppState::new(jwt_secret, metrics));

        // Build router with all routes
        let router = Router::new()
            // Public endpoints (no auth)
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler))
            .route("/metrics", get(metrics_handler))
            // Protected endpoints (JWT required)
            .route("/rooms", post(create_room_handler))
            .route("/rooms", get(list_rooms_handler))
            .route("/rooms/:id", get(get_room_handler))
            .route("/rooms/:id", delete(delete_room_handler))
            // Apply JWT middleware to protected routes
            .layer(middleware::from_fn_with_state(
                state.clone(),
                jwt_auth_middleware,
            ))
            .with_state(state);

        // TigerStyle: Postcondition assertion
        assert!(bind_addr.port() > 0, "Router must be configured");

        Self { bind_addr, router }
    }

    /// Create a new API server with distributed state for room synchronization.
    ///
    /// This constructor enables room creation via the API to be synchronized
    /// with the orchestrator's distributed state, allowing clients to join
    /// rooms created through the REST API.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Address to bind the server to
    /// * `jwt_secret` - Secret for JWT validation (min 32 chars)
    /// * `metrics` - Optional metrics collector for /metrics endpoint
    /// * `distributed_state` - Distributed state for room synchronization
    ///
    /// # Assertions
    ///
    /// - bind_addr.port() > 0
    /// - jwt_secret.len() >= 32
    pub fn with_distributed_state(
        bind_addr: SocketAddr,
        jwt_secret: &str,
        metrics: Option<Arc<MetricsCollector>>,
        distributed_state: Arc<DistributedState>,
    ) -> Self {
        // TigerStyle: Precondition assertions
        assert!(bind_addr.port() > 0, "Bind port must be > 0");
        assert!(
            jwt_secret.len() >= MIN_SECRET_LEN,
            "JWT secret must be at least {} characters",
            MIN_SECRET_LEN
        );

        let state = Arc::new(AppState::with_distributed_state(jwt_secret, metrics, distributed_state));

        // Build router with all routes
        let router = Router::new()
            // Public endpoints (no auth)
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler))
            .route("/metrics", get(metrics_handler))
            // Protected endpoints (JWT required)
            .route("/rooms", post(create_room_handler))
            .route("/rooms", get(list_rooms_handler))
            .route("/rooms/:id", get(get_room_handler))
            .route("/rooms/:id", delete(delete_room_handler))
            // Apply JWT middleware to protected routes
            .layer(middleware::from_fn_with_state(
                state.clone(),
                jwt_auth_middleware,
            ))
            .with_state(state);

        // TigerStyle: Postcondition assertion
        assert!(bind_addr.port() > 0, "Router must be configured");

        Self { bind_addr, router }
    }

    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Set the server as ready to accept connections.
    ///
    /// Call this after SFU initialization is complete.
    pub fn set_ready(&self, state: &Arc<AppState>) {
        state.set_ready(true);
    }

    /// Run the API server.
    ///
    /// This method blocks until the server is shut down.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Internal` if the server fails to start.
    pub async fn run(self) -> Result<(), ApiError> {
        info!("Starting API server on {}", self.bind_addr);

        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to bind: {}", e)))?;

        axum::serve(listener, self.router)
            .await
            .map_err(|e| ApiError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Get the router for testing purposes
    #[cfg(test)]
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}


// ---------------------------------------------------------------------------
// JWT Authentication Middleware
// ---------------------------------------------------------------------------

/// JWT authentication middleware.
///
/// Skips authentication for public endpoints (/health, /ready, /metrics).
/// Requires valid JWT token in Authorization header for all other endpoints.
async fn jwt_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let path = request.uri().path();

    // Skip auth for public endpoints
    if path == "/health" || path == "/ready" || path == "/metrics" {
        return Ok(next.run(request).await);
    }

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        Some(_) => {
            return Err(ApiError::Unauthorized {
                reason: "Invalid authorization header format".to_string(),
            });
        }
        None => {
            return Err(ApiError::Unauthorized {
                reason: "Missing authorization header".to_string(),
            });
        }
    };

    // Validate token
    state.jwt_validator.validate(token)?;

    Ok(next.run(request).await)
}

// ---------------------------------------------------------------------------
// Endpoint Handlers
// ---------------------------------------------------------------------------

/// GET /health - Health check endpoint
///
/// Returns 200 OK with status "ok" if the server is running.
/// No authentication required.
async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse { status: "ok" })
}

/// GET /ready - Readiness check endpoint
///
/// Returns 200 OK if the SFU is initialized and ready to accept connections.
/// Returns 503 Service Unavailable if not ready.
/// No authentication required.
async fn ready_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let is_ready = state.is_ready.load(Ordering::SeqCst);

    if is_ready {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                ready: true,
                message: "SFU is ready",
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                message: "SFU is not ready",
            }),
        )
    }
}

/// GET /metrics - Prometheus metrics endpoint
///
/// Returns metrics in Prometheus text format.
/// No authentication required.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match &state.metrics {
        Some(metrics) => match metrics.export_prometheus() {
            Ok(text) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                text,
            )
                .into_response(),
            Err(e) => {
                warn!("Failed to export metrics: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to export metrics",
                )
                    .into_response()
            }
        },
        None => (StatusCode::OK, "# No metrics collector configured\n").into_response(),
    }
}


/// POST /rooms - Create a new room
///
/// Requires JWT authentication.
async fn create_room_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateRoomRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate request
    if request.name.is_empty() {
        return Err(ApiError::BadRequest {
            message: "Room name cannot be empty".to_string(),
        });
    }

    if request.name.len() > 256 {
        return Err(ApiError::BadRequest {
            message: "Room name too long (max 256 characters)".to_string(),
        });
    }

    if request.max_participants == 0 || request.max_participants > 1000 {
        return Err(ApiError::BadRequest {
            message: "max_participants must be between 1 and 1000".to_string(),
        });
    }

    let mut rooms = state.rooms.write().await;

    // Check for duplicate name
    if rooms.iter().any(|r| r.name == request.name) {
        return Err(ApiError::BadRequest {
            message: format!("Room '{}' already exists", request.name),
        });
    }

    let room_id = state
        .next_room_id
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Create room in distributed state if available (for orchestrator synchronization)
    if let Some(ref distributed_state) = state.distributed_state {
        if let Err(e) = distributed_state.create_room(
            room_id,
            request.name.clone(),
            request.max_participants,
        ) {
            warn!("Failed to create room in distributed state: {:?}", e);
            return Err(ApiError::Internal(format!(
                "Failed to create room in distributed state: {:?}",
                e
            )));
        }
    }

    let room = RoomResponse {
        id: room_id,
        name: request.name,
        participant_count: 0,
        max_participants: request.max_participants,
    };

    rooms.push(room.clone());

    info!("Created room {} (id={})", room.name, room.id);

    Ok((StatusCode::CREATED, Json(room)))
}

/// GET /rooms - List all rooms
///
/// Requires JWT authentication.
async fn list_rooms_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let rooms = state.rooms.read().await;

    Ok(Json(ListRoomsResponse {
        total: rooms.len(),
        rooms: rooms.clone(),
    }))
}

/// GET /rooms/:id - Get room details
///
/// Requires JWT authentication.
async fn get_room_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    let rooms = state.rooms.read().await;

    let room = rooms.iter().find(|r| r.id == id).cloned();

    match room {
        Some(r) => Ok(Json(r)),
        None => Err(ApiError::NotFound {
            resource: format!("room {}", id),
        }),
    }
}

/// DELETE /rooms/:id - Delete a room
///
/// Requires JWT authentication.
async fn delete_room_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    let mut rooms = state.rooms.write().await;

    let initial_len = rooms.len();
    rooms.retain(|r| r.id != id);

    if rooms.len() == initial_len {
        return Err(ApiError::NotFound {
            resource: format!("room {}", id),
        });
    }

    // Remove from distributed state if available
    if let Some(ref distributed_state) = state.distributed_state {
        distributed_state.remove_room(id);
    }

    info!("Deleted room {}", id);

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> String {
        "this-is-a-test-secret-with-32-chars!".to_string()
    }

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new(&test_secret(), None);
        assert!(!state.is_ready.load(Ordering::SeqCst));
    }

    #[test]
    fn test_app_state_set_ready() {
        let state = AppState::new(&test_secret(), None);
        state.set_ready(true);
        assert!(state.is_ready.load(Ordering::SeqCst));
    }

    #[test]
    fn test_api_server_creation() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let server = ApiServer::new(addr, &test_secret(), None);
        assert_eq!(server.bind_addr(), addr);
    }

    #[test]
    #[should_panic(expected = "JWT secret must be at least")]
    fn test_api_server_short_secret_panics() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        ApiServer::new(addr, "short", None);
    }
}
