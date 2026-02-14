//! Protocol Buffer generated types for Nexus SFU
//!
//! This module exposes the generated Protocol Buffer types for:
//! - `nexus.api.v1` - gRPC API service definitions
//! - `nexus.metrics.v1` - Metrics message types
//!
//! These types are generated at build time from:
//! - `proto/api.proto` - SFU management API
//! - `proto/metrics.proto` - Metrics export schema
//!
//! # Usage
//!
//! ```ignore
//! use nexus_sfu::proto::api::*;
//! use nexus_sfu::proto::metrics::*;
//! ```

/// gRPC API service definitions
///
/// Contains message types for room, participant, and track management.
/// See `proto/api.proto` for the schema definition.
pub mod api {
    include!(concat!(env!("OUT_DIR"), "/nexus.api.v1.rs"));
}

/// Metrics message types
///
/// Contains detailed metrics types matching the nexus-metrics crate exports.
/// See `proto/metrics.proto` for the schema definition.
pub mod metrics {
    include!(concat!(env!("OUT_DIR"), "/nexus.metrics.v1.rs"));
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_types_accessible() {
        // Verify we can create API message types
        let request = api::CreateRoomRequest {
            name: "test-room".to_string(),
            max_participants: 100,
            metadata: String::new(),
        };
        assert_eq!(request.name, "test-room");
        assert_eq!(request.max_participants, 100);
    }

    #[test]
    fn test_metrics_types_accessible() {
        // Verify we can create metrics message types
        let counters = metrics::PacketCounters {
            received_total: 1000,
            forwarded_total: 950,
            dropped_total: 50,
            ..Default::default()
        };
        assert_eq!(counters.received_total, 1000);
        assert_eq!(counters.forwarded_total, 950);
    }

    #[test]
    fn test_room_message() {
        let room = api::Room {
            id: 1,
            name: "conference".to_string(),
            participant_count: 10,
            max_participants: 100,
            track_count: 20,
            created_at_ns: 1234567890,
            last_activity_ns: 1234567900,
            metadata: String::new(),
        };
        assert_eq!(room.id, 1);
        assert_eq!(room.participant_count, 10);
    }

    #[test]
    fn test_health_status_enum() {
        // Verify enum values are accessible
        assert_eq!(api::HealthStatus::Unspecified as i32, 0);
        assert_eq!(api::HealthStatus::Healthy as i32, 1);
        assert_eq!(api::HealthStatus::Degraded as i32, 2);
        assert_eq!(api::HealthStatus::Unhealthy as i32, 3);
    }

    #[test]
    fn test_media_type_enum() {
        assert_eq!(metrics::MediaType::Unspecified as i32, 0);
        assert_eq!(metrics::MediaType::Audio as i32, 1);
        assert_eq!(metrics::MediaType::Video as i32, 2);
    }
}
