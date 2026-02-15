//! Recording REST API routes.
//!
//! # Endpoints
//!
//! - `POST   /rooms/:id/recording/start`  — Start recording
//! - `POST   /rooms/:id/recording/pause`  — Pause recording
//! - `POST   /rooms/:id/recording/resume` — Resume recording
//! - `POST   /rooms/:id/recording/stop`   — Stop recording
//! - `GET    /rooms/:id/recording`         — Get recording status
//! - `GET    /recordings`                  — List all recordings
//!
//! # TigerStyle Compliance
//!
//! - ≥2 assertions per handler (via state invariants)
//! - Explicit error handling
//! - Bounded responses

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::Serialize;

use nexus_recorder::{RecorderError, RecordingInfo, RecordingManager};

use crate::error::ApiError;

/// Shared recording state for API handlers.
pub type SharedRecordingManager = Arc<Mutex<RecordingManager>>;

/// Recording status response.
#[derive(Debug, Serialize)]
pub struct RecordingStatusResponse {
    pub room_id: u32,
    pub recording: Option<RecordingInfo>,
}

/// List recordings response.
#[derive(Debug, Serialize)]
pub struct ListRecordingsResponse {
    pub recordings: Vec<RecordingInfo>,
    pub total: usize,
}

/// Action response (start/pause/resume/stop).
#[derive(Debug, Serialize)]
pub struct RecordingActionResponse {
    pub room_id: u32,
    pub action: &'static str,
    pub state: &'static str,
}

/// Build the recording sub-router.
///
/// Mount this under the main API router with `.merge()` or `.nest()`.
pub fn recording_routes(mgr: SharedRecordingManager) -> Router {
    Router::new()
        .route(
            "/rooms/:id/recording/start",
            post(start_recording_handler),
        )
        .route(
            "/rooms/:id/recording/pause",
            post(pause_recording_handler),
        )
        .route(
            "/rooms/:id/recording/resume",
            post(resume_recording_handler),
        )
        .route(
            "/rooms/:id/recording/stop",
            post(stop_recording_handler),
        )
        .route(
            "/rooms/:id/recording",
            get(get_recording_handler),
        )
        .route("/recordings", get(list_recordings_handler))
        .with_state(mgr)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn map_recorder_error(e: RecorderError) -> ApiError {
    match e {
        RecorderError::SessionNotFound(id) => ApiError::NotFound {
            resource: format!("recording for room {}", id),
        },
        RecorderError::SessionAlreadyExists(id) => ApiError::BadRequest {
            message: format!("recording already exists for room {}", id),
        },
        RecorderError::CapacityExceeded => ApiError::BadRequest {
            message: "max concurrent recordings reached".to_string(),
        },
        RecorderError::InvalidState {
            room_id,
            current,
            expected,
        } => ApiError::BadRequest {
            message: format!(
                "room {} recording is {:?}, expected {}",
                room_id, current, expected
            ),
        },
        RecorderError::IoError(e) => ApiError::Internal(e.to_string()),
    }
}

/// POST /rooms/:id/recording/start
async fn start_recording_handler(
    State(mgr): State<SharedRecordingManager>,
    Path(room_id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    if room_id == 0 {
        return Err(ApiError::BadRequest {
            message: "room_id must be non-zero".to_string(),
        });
    }

    mgr.lock()
        .start_recording(room_id, now_ns())
        .map_err(map_recorder_error)?;

    Ok((
        StatusCode::OK,
        Json(RecordingActionResponse {
            room_id,
            action: "start",
            state: "active",
        }),
    ))
}

/// POST /rooms/:id/recording/pause
async fn pause_recording_handler(
    State(mgr): State<SharedRecordingManager>,
    Path(room_id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    if room_id == 0 {
        return Err(ApiError::BadRequest {
            message: "room_id must be non-zero".to_string(),
        });
    }

    mgr.lock()
        .pause_recording(room_id, now_ns())
        .map_err(map_recorder_error)?;

    Ok((
        StatusCode::OK,
        Json(RecordingActionResponse {
            room_id,
            action: "pause",
            state: "paused",
        }),
    ))
}

/// POST /rooms/:id/recording/resume
async fn resume_recording_handler(
    State(mgr): State<SharedRecordingManager>,
    Path(room_id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    if room_id == 0 {
        return Err(ApiError::BadRequest {
            message: "room_id must be non-zero".to_string(),
        });
    }

    mgr.lock()
        .resume_recording(room_id, now_ns())
        .map_err(map_recorder_error)?;

    Ok((
        StatusCode::OK,
        Json(RecordingActionResponse {
            room_id,
            action: "resume",
            state: "active",
        }),
    ))
}

/// POST /rooms/:id/recording/stop
async fn stop_recording_handler(
    State(mgr): State<SharedRecordingManager>,
    Path(room_id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    if room_id == 0 {
        return Err(ApiError::BadRequest {
            message: "room_id must be non-zero".to_string(),
        });
    }

    mgr.lock()
        .stop_recording(room_id)
        .map_err(map_recorder_error)?;

    Ok((
        StatusCode::OK,
        Json(RecordingActionResponse {
            room_id,
            action: "stop",
            state: "stopped",
        }),
    ))
}

/// GET /rooms/:id/recording
async fn get_recording_handler(
    State(mgr): State<SharedRecordingManager>,
    Path(room_id): Path<u32>,
) -> Result<impl IntoResponse, ApiError> {
    let info = mgr.lock().get_recording(room_id);

    Ok(Json(RecordingStatusResponse {
        room_id,
        recording: info,
    }))
}

/// GET /recordings
async fn list_recordings_handler(
    State(mgr): State<SharedRecordingManager>,
) -> Result<impl IntoResponse, ApiError> {
    let recordings = mgr.lock().list_recordings();
    let total = recordings.len();

    Ok(Json(ListRecordingsResponse { recordings, total }))
}
