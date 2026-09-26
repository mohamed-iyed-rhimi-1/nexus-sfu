use crate::config::{validation::ConfigError, NexusConfig};
use std::env;
use std::fs;
use std::path::Path;

pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration with precedence: env vars > file > defaults
    ///
    /// This method is used when no CLI arguments are provided.
    /// For full CLI > env > file > defaults precedence, use the
    /// `load_config()` function in main.rs which applies CLI overrides
    /// after calling this method.
    ///
    /// # Precedence Order
    ///
    /// 1. Environment variables (highest in this method)
    /// 2. Config file (if NEXUS_CONFIG_PATH is set)
    /// 3. Default values (lowest)
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 13.2: Config precedence (partial - env > file > defaults)
    pub fn load() -> Result<NexusConfig, ConfigError> {
        // Step 1: Start with defaults
        let mut config = NexusConfig::default();

        // Step 2: Load from file if NEXUS_CONFIG_PATH is set (file > defaults)
        if let Ok(path) = env::var("NEXUS_CONFIG_PATH") {
            config = Self::from_file(&path)?;
        }

        // Step 3: Apply environment variable overrides (env > file > defaults)
        config = Self::merge_from_env(config)?;

        // Step 4: Validate entire configuration
        config.validate()?;

        Ok(config)
    }

    /// Load from specific file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<NexusConfig, ConfigError> {
        let contents = fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::load_error(&format!("failed to read config file: {}", e)))?;

        let config: NexusConfig = toml::from_str(&contents)
            .map_err(|e| ConfigError::load_error(&format!("failed to parse config file: {}", e)))?;

        Ok(config)
    }

    /// Merge configuration from environment variables.
    ///
    /// This method applies environment variable overrides to an existing
    /// configuration. It should be called after loading from file but
    /// before applying CLI overrides.
    ///
    /// # Supported Environment Variables
    ///
    /// - `NEXUS_JWT_SECRET`: JWT secret for authentication (security.jwt_secret
    ///   and api.jwt_secret; both are validated, and production.toml leaves
    ///   both empty for this variable to fill)
    /// - `NEXUS_TLS_CERT_PATH`: TLS certificate path (quic.cert_path, requires nexus-signal)
    /// - `NEXUS_TLS_KEY_PATH`: TLS key path (quic.key_path, requires nexus-signal)
    /// - `NEXUS_WORKER_COUNT`: Number of worker threads (worker.num_workers)
    /// - `NEXUS_ARENA_SIZE_MB`: Packet arena size in MB (memory.arena_size_mb)
    /// - `NEXUS_LOG_LEVEL`: Log level (logging.level)
    /// - `NEXUS_METRICS_ADDR`: Metrics bind address (metrics.bind_addr)
    /// - `NEXUS_ANNOUNCED_IPS`: comma-separated IPs advertised as ICE host
    ///   candidates (transport.announced_ips); empty clears the list
    ///
    /// # Requirements Coverage
    ///
    /// - Requirement 13.2: Config precedence (env > file > defaults)
    pub fn merge_from_env(mut config: NexusConfig) -> Result<NexusConfig, ConfigError> {
        // Security settings from environment (sensitive data)
        if let Ok(jwt_secret) = env::var("NEXUS_JWT_SECRET") {
            config.api.jwt_secret = jwt_secret.clone();
            config.security.jwt_secret = jwt_secret;
        }

        // TLS paths: the signaling server reads transport.tls_*; QUIC config
        // keeps its own copy. Set both so the override actually applies.
        if let Ok(cert_path) = env::var("NEXUS_TLS_CERT_PATH") {
            config.transport.tls_cert_path = cert_path.clone();
            config.quic.cert_path = cert_path;
        }
        if let Ok(key_path) = env::var("NEXUS_TLS_KEY_PATH") {
            config.transport.tls_key_path = key_path.clone();
            config.quic.key_path = key_path;
        }

        // Numeric overrides with validation
        if let Ok(workers) = env::var("NEXUS_WORKER_COUNT") {
            config.worker.num_workers = workers
                .parse()
                .map_err(|_| ConfigError::invalid("NEXUS_WORKER_COUNT", "must be u32"))?;
        }

        if let Ok(arena_mb) = env::var("NEXUS_ARENA_SIZE_MB") {
            config.memory.arena_size_mb = arena_mb
                .parse()
                .map_err(|_| ConfigError::invalid("NEXUS_ARENA_SIZE_MB", "must be u32"))?;
        }

        // Log level override
        if let Ok(level) = env::var("NEXUS_LOG_LEVEL") {
            config.logging.level = level
                .parse()
                .map_err(|e: String| ConfigError::invalid("NEXUS_LOG_LEVEL", &e))?;
        }

        // Metrics address override
        if let Ok(addr) = env::var("NEXUS_METRICS_ADDR") {
            config.metrics.bind_addr = addr;
        }

        if let Ok(ips) = env::var("NEXUS_ANNOUNCED_IPS") {
            config.transport.announced_ips =
                parse_ip_list(&ips).map_err(|e| ConfigError::invalid("NEXUS_ANNOUNCED_IPS", &e))?;
        }

        Ok(config)
    }
}

/// Parse a comma-separated IP list; blank entries are skipped.
fn parse_ip_list(value: &str) -> Result<Vec<std::net::IpAddr>, String> {
    let mut ips = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if ips.len() >= nexus_core::MAX_ANNOUNCED_IPS {
            return Err(format!(
                "at most {} addresses",
                nexus_core::MAX_ANNOUNCED_IPS
            ));
        }
        ips.push(
            part.parse()
                .map_err(|_| format!("'{part}' is not an IP address"))?,
        );
    }
    Ok(ips)
}
