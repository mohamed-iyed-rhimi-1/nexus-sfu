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
    let config =
        ConfigLoader::from_file("config/development.toml").expect("development.toml should load");

    // Verify it validates
    config.validate().expect("development.toml should validate");

    // Verify key development settings per task spec
    assert_eq!(config.dataplane.shards, 1, "one shard");
    assert!(
        !config.dataplane.cpu_affinity,
        "cpu_affinity should be disabled"
    );
    assert!(
        !config.dataplane.realtime_priority,
        "realtime_priority should be disabled"
    );
    assert_eq!(
        config.room.max_participants_per_room, 50,
        "max participants should be 50"
    );
    assert_eq!(config.room.max_rooms, 10, "max rooms should be 10");
    assert_eq!(
        config.bwe.loss_threshold_percent, 10,
        "loss threshold should be 10%"
    );
    assert_eq!(
        config.logging.level,
        LogLevel::Debug,
        "logging should be debug"
    );
}

#[test]
fn test_production_config_loads() {
    // Verify production.toml loads correctly
    let config =
        ConfigLoader::from_file("config/production.toml").expect("production.toml should load");

    // Production config has empty jwt_secret which requires env var override
    // So we skip validation here, just verify it parses

    // Verify key production settings
    assert_eq!(config.dataplane.shards, 1, "one shard in Phase 1");
    assert_eq!(config.dataplane.busy_poll_rounds, 256, "busy polling");
    assert!(
        config.dataplane.cpu_affinity,
        "cpu_affinity should be enabled"
    );
    assert!(
        !config.dataplane.realtime_priority,
        "SCHED_FIFO stays off with busy polling"
    );
    assert_eq!(
        config.room.max_participants_per_room, 1000,
        "max participants should be 1000"
    );
    assert_eq!(
        config.logging.level,
        LogLevel::Info,
        "logging should be info"
    );
}

// Note: Environment variable tests are combined into a single test to avoid
// race conditions when tests run in parallel. Each test modifies the same
// env var (NEXUS_JWT_SECRET) which causes interference.
#[test]
fn test_env_var_overrides() {
    // Test 1: Basic env var override (>= 32 chars for validation)
    env::remove_var("NEXUS_JWT_SECRET");
    env::set_var("NEXUS_JWT_SECRET", "test-secret-basic-at-least-32-chars!");
    let config = ConfigLoader::load().unwrap();
    assert_eq!(
        config.security.jwt_secret,
        "test-secret-basic-at-least-32-chars!"
    );

    // Test 2: Env var overrides file-loaded config
    env::remove_var("NEXUS_JWT_SECRET");
    let mut config = NexusConfig::default();
    config.security.jwt_secret = "file-secret-needs-32-chars-too!!".to_string();
    env::set_var("NEXUS_JWT_SECRET", "env-override-secret-at-least-32ch!");
    let config = ConfigLoader::merge_from_env(config).unwrap();
    assert_eq!(
        config.security.jwt_secret,
        "env-override-secret-at-least-32ch!"
    );
    // The API secret is validated separately; the env var must fill it too
    assert_eq!(config.api.jwt_secret, "env-override-secret-at-least-32ch!");

    // Test 3: TLS paths reach the fields the signaling server reads
    env::set_var("NEXUS_TLS_CERT_PATH", "/tmp/test-cert.pem");
    env::set_var("NEXUS_TLS_KEY_PATH", "/tmp/test-key.pem");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    assert_eq!(config.transport.tls_cert_path, "/tmp/test-cert.pem");
    assert_eq!(config.transport.tls_key_path, "/tmp/test-key.pem");
    assert_eq!(config.quic.cert_path, "/tmp/test-cert.pem");

    // Test 4: announced IPs, comma-separated
    env::set_var("NEXUS_ANNOUNCED_IPS", " 203.0.113.7, 2001:db8::1 ,");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    assert_eq!(
        config.transport.announced_ips,
        vec![
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap(),
            "2001:db8::1".parse().unwrap()
        ]
    );
    env::set_var("NEXUS_ANNOUNCED_IPS", "203.0.113.7,not-an-ip");
    assert!(ConfigLoader::merge_from_env(NexusConfig::default()).is_err());
    env::set_var("NEXUS_ANNOUNCED_IPS", "0.0.0.0");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    assert!(
        config.validate().is_err(),
        "unspecified IP must fail validation"
    );

    // Test 5: shard count
    env::set_var("NEXUS_SHARDS", "1");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    assert_eq!(config.dataplane.shards, 1);
    env::set_var("NEXUS_SHARDS", "many");
    assert!(ConfigLoader::merge_from_env(NexusConfig::default()).is_err());
    env::set_var("NEXUS_SHARDS", "2");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    // `validate_dataplane` alone: the unspecified announced IP above is still set.
    assert!(config.validate_dataplane().is_ok(), "several shards run");
    let dp = config.to_dataplane_config().unwrap();
    assert_eq!(
        dp.shard.pool_buffers, 2_048,
        "the default pool follows the shards"
    );
    assert_eq!(
        dp.shard.max_sessions,
        config.transport.max_webrtc_sessions.div_ceil(2)
    );
    env::set_var("NEXUS_SHARDS", "17");
    let config = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap();
    assert!(config.validate_dataplane().is_err(), "above the shard cap");
    env::remove_var("NEXUS_SHARDS");

    // Test 6: the old data plane's variables are refused, not ignored
    for name in ["NEXUS_WORKER_COUNT", "NEXUS_ARENA_SIZE_MB"] {
        env::set_var(name, "4");
        let err = ConfigLoader::merge_from_env(NexusConfig::default()).unwrap_err();
        assert!(err.to_string().contains(name), "{err}");
        env::remove_var(name);
    }

    // Cleanup
    env::remove_var("NEXUS_SHARDS");
    env::remove_var("NEXUS_ANNOUNCED_IPS");
    env::remove_var("NEXUS_JWT_SECRET");
    env::remove_var("NEXUS_TLS_CERT_PATH");
    env::remove_var("NEXUS_TLS_KEY_PATH");
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
fn test_hot_reload_ignores_dataplane_config() {
    let mut config = NexusConfig::default();
    let original = config.dataplane.pool_buffers;
    let new_config = NexusConfig {
        dataplane: DataplaneSettings {
            pool_buffers: Some(4_096),
            ..Default::default()
        },
        ..Default::default()
    };
    config.reload_control_plane(&new_config);
    assert_eq!(config.dataplane.pool_buffers, original);
}

// Transport validation tests
#[test]
fn test_transport_validation_zero_buffer() {
    let config = TransportConfig {
        recv_buffer_size_bytes: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_transport_validation_buffer_too_large() {
    let config = TransportConfig {
        recv_buffer_size_bytes: 2 * 1024 * 1024 * 1024, // 2GB
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

// Room validation tests
#[test]
fn test_room_validation_zero_participants() {
    let config = RoomConfig {
        max_participants_per_room: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_room_validation_too_many_participants() {
    let config = RoomConfig {
        max_participants_per_room: 20000,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

// BWE validation tests
#[test]
fn test_bwe_validation_invalid_ordering() {
    let config = BweConfig {
        min_bandwidth_bps: 10_000_000,
        max_bandwidth_bps: 1_000_000,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_bwe_validation_invalid_decrease_factor() {
    let config = BweConfig {
        decrease_factor: 1.5,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

// Metrics validation tests
#[test]
fn test_metrics_validation_invalid_addr() {
    let config = MetricsConfig {
        bind_addr: "invalid".to_string(),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_metrics_validation_zero_interval() {
    let config = MetricsConfig {
        collection_interval_ms: 0,
        ..Default::default()
    };
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

// Removed: test_env_override_after_file_load - combined into test_env_var_overrides above

#[test]
fn test_hot_reload_validates_before_applying() {
    // This test verifies that invalid configs are rejected during hot-reload
    // The actual hot-reload validation is tested in the watcher module
    let config = NexusConfig {
        drain_timeout_ms: 0, // Invalid
        ..Default::default()
    };

    // Validation should fail
    assert!(config.validate().is_err());
}

/// The old data plane's sections and `[transport]` fields are refused, not
/// silently ignored (Phase 1 C7).
#[test]
fn test_removed_sections_and_fields_are_refused() {
    let base = toml::to_string(&NexusConfig::default()).unwrap();
    assert!(toml::from_str::<NexusConfig>(&base).is_ok());
    for section in [
        "[worker]\nnum_workers = 2\n",
        "[memory]\narena_size_mb = 32\n",
        "[actor]\nmax_room_actors = 10\n",
    ] {
        let text = format!("{base}\n{section}");
        let err = toml::from_str::<NexusConfig>(&text)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{section}: {err}");
    }
    for field in [
        "batch_size = 32",
        "batch_flush_interval_us = 1000",
        "stun_servers = []",
    ] {
        let text = base.replacen("[transport]\n", &format!("[transport]\n{field}\n"), 1);
        assert_ne!(text, base, "the default config has a [transport] section");
        let err = toml::from_str::<NexusConfig>(&text)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{field}: {err}");
    }
}

#[test]
fn test_shipped_configs_validate() {
    // Every config file in the repo must load; production.toml never
    // started before because of an out-of-range actor limit.
    for name in ["development", "production", "loadtest", "default"] {
        let path = format!("{}/config/{}.toml", env!("CARGO_MANIFEST_DIR"), name);
        let mut config = ConfigLoader::from_file(&path)
            .unwrap_or_else(|e| panic!("{name}.toml failed to load: {e}"));
        // production.toml leaves secrets empty for NEXUS_JWT_SECRET to fill.
        let secret = "0123456789abcdef0123456789abcdef".to_string();
        config.api.jwt_secret = secret.clone();
        config.security.jwt_secret = secret;
        config
            .validate()
            .unwrap_or_else(|e| panic!("{name}.toml is invalid: {e}"));
    }
}

#[test]
fn test_dataplane_section_is_optional() {
    // development.toml without its [dataplane] section still loads, with defaults.
    let path = format!("{}/config/development.toml", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    let mut kept = String::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.starts_with('[') {
            skipping = line.trim() == "[dataplane]";
        }
        if !skipping {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    assert!(!kept.contains("[dataplane]"));
    let config: NexusConfig = toml::from_str(&kept).unwrap();
    assert_eq!(config.dataplane, DataplaneSettings::default());
}

#[test]
fn test_dataplane_config_mapping() {
    let mut config = NexusConfig::default();
    config.transport.media_bind_addr = "0.0.0.0:20000".parse().unwrap();
    config.transport.signaling_bind_addr = "0.0.0.0:8080".parse().unwrap();
    config.transport.recv_buffer_size_bytes = 1 << 20;
    config.transport.send_buffer_size_bytes = 2 << 20;
    config.transport.max_webrtc_sessions = 999;
    config.api.enabled = true;
    config.api.bind_addr = "127.0.0.1:8081".to_string();
    config.metrics.bind_addr = "127.0.0.1:9090".to_string();
    config.dataplane.busy_poll_rounds = 7;
    config.dataplane.pool_buffers = Some(4096);
    config.dataplane.consent_timeout_ms = 20_000;
    config.dataplane.rebind_silence_ms = 1_500;
    config.dataplane.cpu_affinity = true;
    config.dataplane.realtime_priority = true;
    config.dataplane.realtime_priority_level = 50;

    let dp = config.to_dataplane_config().unwrap();
    assert_eq!(dp.shards, 1);
    assert_eq!(dp.bind_addr, config.transport.media_bind_addr);
    assert_eq!(dp.recv_buffer_bytes, 1 << 20);
    assert_eq!(dp.send_buffer_bytes, 2 << 20);
    assert_eq!(dp.busy_poll_rounds, 7);
    assert!(dp.cpu_affinity);
    assert_eq!(dp.realtime_priority, Some(50));
    assert_eq!(dp.reserved_ports, vec![8080, 8081, 9090]);
    assert_eq!(dp.rng_seed, None);
    assert_eq!(dp.shard.pool_buffers, 4096);
    assert_eq!(dp.shard.max_sessions, 999);
    assert_eq!(dp.shard.consent_timeout, std::time::Duration::from_secs(20));
    assert_eq!(
        dp.shard.rebind_silence,
        std::time::Duration::from_millis(1_500)
    );
    assert!(config.validate().is_ok());

    // Realtime off → no priority; a level that does not fit u8 is an error.
    config.dataplane.realtime_priority = false;
    assert_eq!(
        config.to_dataplane_config().unwrap().realtime_priority,
        None
    );
    config.dataplane.realtime_priority = true;
    config.dataplane.realtime_priority_level = 300;
    assert!(config.to_dataplane_config().is_err());
    config.dataplane.realtime_priority_level = 0;
    assert!(config.validate().is_err(), "priority 0 is out of 1..=99");
}

#[test]
fn test_dataplane_reserved_ports() {
    let mut config = NexusConfig::default();
    config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.api.enabled = false;
    config.api.bind_addr = "127.0.0.1:8081".to_string();
    config.metrics.bind_addr = "127.0.0.1:9090".to_string();
    // Ephemeral signaling port and a disabled API reserve nothing.
    assert_eq!(config.reserved_ports().unwrap(), vec![9090]);

    config.api.enabled = true;
    config.api.bind_addr = "127.0.0.1:9090".to_string();
    assert_eq!(config.reserved_ports().unwrap(), vec![9090]);

    config.metrics.bind_addr = "not-an-address".to_string();
    assert!(config.reserved_ports().is_err());
}

#[test]
fn test_dataplane_accepts_several_shards() {
    for shards in 2..=4u16 {
        let mut config = NexusConfig::default();
        config.dataplane.shards = shards;
        config.validate().expect("valid");
        let dp = config.to_dataplane_config().unwrap();
        assert_eq!(dp.shards, shards);
        assert_eq!(
            dp.shard.pool_buffers,
            nexus_dataplane::default_pool_buffers(shards)
        );
        config.dataplane.pool_buffers = Some(nexus_dataplane::min_pool_buffers(shards));
        config.validate().expect("the minimum is enough");
    }
    let mut config = NexusConfig::default();
    config.dataplane.shards = nexus_dataplane::MAX_SHARDS_SUPPORTED + 1;
    let err = config.validate().expect_err("above the cap").to_string();
    let range = format!("1..={}", nexus_dataplane::MAX_SHARDS_SUPPORTED);
    assert!(err.contains(&range), "{err}");
}

#[test]
fn test_dataplane_rejects_invalid_settings() {
    let refused = |f: &dyn Fn(&mut NexusConfig)| {
        let mut config = NexusConfig::default();
        f(&mut config);
        let err = config.validate().expect_err("must be refused");
        assert!(err.to_string().contains("dataplane"), "{err}");
    };
    refused(&|c| c.dataplane.shards = 0);
    refused(&|c| c.dataplane.shards = 17);
    refused(&|c| c.dataplane.shards = 65);
    refused(&|c| c.dataplane.pool_buffers = Some(1));
    // Two shards need a credit of loans on top of the batches.
    refused(&|c| {
        c.dataplane.shards = 2;
        c.dataplane.pool_buffers = Some(1_343);
    });
    // Shard 2's port would be the signaling port.
    refused(&|c| {
        c.dataplane.shards = 4;
        c.transport.media_bind_addr = "0.0.0.0:8078".parse().unwrap();
        c.transport.signaling_bind_addr = "0.0.0.0:8080".parse().unwrap();
    });
    refused(&|c| c.dataplane.rebind_silence_ms = c.dataplane.consent_timeout_ms);
    // The media port must not be the signaling, API or metrics port.
    refused(&|c| {
        c.transport.media_bind_addr = "0.0.0.0:8080".parse().unwrap();
        c.transport.signaling_bind_addr = "0.0.0.0:8080".parse().unwrap();
    });
    refused(&|c| {
        c.transport.media_bind_addr = "0.0.0.0:9090".parse().unwrap();
        c.metrics.bind_addr = "127.0.0.1:9090".to_string();
    });
}
