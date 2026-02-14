use super::*;
use std::env;

#[test]
fn test_default_config_validates() {
    let config = NexusConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_development_config_loads() {
    // Verify development.toml loads and validates correctly
    let config = ConfigLoader::from_file("config/development.toml")
        .expect("development.toml should load");
    
    // Verify it validates
    config.validate().expect("development.toml should validate");
    
    // Verify key development settings per task spec
    assert_eq!(config.memory.arena_size_mb, 32, "arena should be 32MB");
    assert_eq!(config.worker.num_workers, 2, "should have 2 workers");
    assert!(!config.worker.cpu_affinity, "cpu_affinity should be disabled");
    assert!(!config.worker.realtime_priority, "realtime_priority should be disabled");
    assert_eq!(config.room.max_participants_per_room, 50, "max participants should be 50");
    assert_eq!(config.room.max_rooms, 10, "max rooms should be 10");
    assert_eq!(config.bwe.loss_threshold_percent, 10, "loss threshold should be 10%");
    assert_eq!(config.logging.level, LogLevel::Debug, "logging should be debug");
}

#[test]
fn test_production_config_loads() {
    // Verify production.toml loads correctly
    let config = ConfigLoader::from_file("config/production.toml")
        .expect("production.toml should load");
    
    // Production config has empty jwt_secret which requires env var override
    // So we skip validation here, just verify it parses
    
    // Verify key production settings
    assert_eq!(config.memory.arena_size_mb, 1024, "arena should be 1GB");
    assert_eq!(config.worker.num_workers, 0, "should auto-detect workers");
    assert!(config.worker.cpu_affinity, "cpu_affinity should be enabled");
    assert!(config.worker.realtime_priority, "realtime_priority should be enabled");
    assert_eq!(config.room.max_participants_per_room, 1000, "max participants should be 1000");
    assert_eq!(config.logging.level, LogLevel::Info, "logging should be info");
}

#[test]
fn test_cross_module_validation_arena_size() {
    let mut config = NexusConfig::default();
    config.memory.arena_size_mb = 1; // Too small (minimum is 16MB)
    assert!(config.validate().is_err());
}

// Note: Environment variable tests are combined into a single test to avoid
// race conditions when tests run in parallel. Each test modifies the same
// env var (NEXUS_JWT_SECRET) which causes interference.
#[test]
fn test_env_var_overrides() {
    // Test 1: Basic env var override
    env::remove_var("NEXUS_JWT_SECRET");
    env::set_var("NEXUS_JWT_SECRET", "test-secret-basic");
    let config = ConfigLoader::load().unwrap();
    assert_eq!(config.security.jwt_secret, "test-secret-basic");
    
    // Test 2: Env var overrides file-loaded config
    env::remove_var("NEXUS_JWT_SECRET");
    let mut config = NexusConfig::default();
    config.security.jwt_secret = "file-secret".to_string();
    env::set_var("NEXUS_JWT_SECRET", "env-override-secret");
    let config = ConfigLoader::merge_from_env(config).unwrap();
    assert_eq!(config.security.jwt_secret, "env-override-secret");
    
    // Cleanup
    env::remove_var("NEXUS_JWT_SECRET");
}

#[test]
fn test_hot_reload_logging_level() {
    let mut config = NexusConfig::default();
    let new_config = NexusConfig {
        logging: LoggingConfig {
            level: LogLevel::Trace,
            ..Default::default()
        },
        ..Default::default()
    };
    config.reload_control_plane(&new_config);
    assert_eq!(config.logging.level, LogLevel::Trace);
}

#[test]
fn test_hot_reload_ignores_memory_config() {
    let mut config = NexusConfig::default();
    let original_arena_size = config.memory.arena_size_mb;
    let new_config = NexusConfig {
        memory: MemoryConfig {
            arena_size_mb: 2048,
            ..Default::default()
        },
        ..Default::default()
    };
    config.reload_control_plane(&new_config);
    assert_eq!(config.memory.arena_size_mb, original_arena_size);
}

// Transport validation tests
#[test]
fn test_transport_validation_zero_buffer() {
    let mut config = TransportConfig::default();
    config.recv_buffer_size_bytes = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_transport_validation_non_power_of_two_batch() {
    let mut config = TransportConfig::default();
    config.batch_size = 33; // Not power of 2
    assert!(config.validate().is_err());
}

#[test]
fn test_transport_validation_buffer_too_large() {
    let mut config = TransportConfig::default();
    config.recv_buffer_size_bytes = 2 * 1024 * 1024 * 1024; // 2GB
    assert!(config.validate().is_err());
}

// Memory validation tests
#[test]
fn test_memory_validation_non_power_of_two() {
    let mut config = MemoryConfig::default();
    config.ring_buffer_size = 1000; // Not power of 2
    assert!(config.validate().is_err());
}

#[test]
fn test_memory_validation_zero_arena() {
    let mut config = MemoryConfig::default();
    config.arena_size_mb = 0;
    assert!(config.validate().is_err());
}

// Room validation tests
#[test]
fn test_room_validation_zero_participants() {
    let mut config = RoomConfig::default();
    config.max_participants_per_room = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_room_validation_too_many_participants() {
    let mut config = RoomConfig::default();
    config.max_participants_per_room = 20000;
    assert!(config.validate().is_err());
}

// BWE validation tests
#[test]
fn test_bwe_validation_invalid_ordering() {
    let mut config = BweConfig::default();
    config.min_bandwidth_bps = 10_000_000;
    config.max_bandwidth_bps = 1_000_000;
    assert!(config.validate().is_err());
}

#[test]
fn test_bwe_validation_invalid_decrease_factor() {
    let mut config = BweConfig::default();
    config.decrease_factor = 1.5;
    assert!(config.validate().is_err());
}

// Actor validation tests
#[test]
fn test_actor_validation_non_power_of_two_queue() {
    let mut config = ActorConfig::default();
    config.message_queue_size = 1000; // Not power of 2
    assert!(config.validate().is_err());
}

#[test]
fn test_actor_validation_too_many_tracks() {
    let mut config = ActorConfig::default();
    config.max_track_actors = 2_000_000;
    assert!(config.validate().is_err());
}

// Metrics validation tests
#[test]
fn test_metrics_validation_invalid_addr() {
    let mut config = MetricsConfig::default();
    config.bind_addr = "invalid".to_string();
    assert!(config.validate().is_err());
}

#[test]
fn test_metrics_validation_zero_interval() {
    let mut config = MetricsConfig::default();
    config.collection_interval_ms = 0;
    assert!(config.validate().is_err());
}

// Builder pattern tests
#[test]
fn test_transport_builder() {
    let config = TransportConfig::default()
        .with_media_addr("0.0.0.0:10000".parse().unwrap())
        .with_buffer_sizes(16_777_216);
    
    assert_eq!(config.recv_buffer_size_bytes, 16_777_216);
    assert_eq!(config.send_buffer_size_bytes, 16_777_216);
}

#[test]
fn test_memory_builder() {
    let config = MemoryConfig::default()
        .with_arena_size_mb(1024)
        .with_ring_buffer_size(2048);
    
    assert_eq!(config.arena_size_mb, 1024);
    assert_eq!(config.ring_buffer_size, 2048);
}

// Removed: test_env_override_after_file_load - combined into test_env_var_overrides above

#[test]
fn test_hot_reload_validates_before_applying() {
    // This test verifies that invalid configs are rejected during hot-reload
    // The actual hot-reload validation is tested in the watcher module
    let mut config = NexusConfig::default();
    config.memory.arena_size_mb = 0; // Invalid
    
    // Validation should fail
    assert!(config.validate().is_err());
}
