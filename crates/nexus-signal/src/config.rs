use serde::{Deserialize, Serialize};

/// QUIC signaling server configuration.
///
/// # TigerStyle Compliance
/// - All fields explicitly-sized types
/// - Bounded limits with runtime validation
/// - Units included in field names
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Bind address for the QUIC server.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Maximum concurrent connections (bounded).
    pub max_connections: u32,
    /// Maximum session tickets to store (LRU eviction).
    pub max_session_tickets: u32,
    /// Session ticket TTL in seconds.
    pub session_ticket_ttl_secs: u32,
    /// Maximum bidirectional streams per connection.
    pub max_bi_streams: u32,
    /// Maximum unidirectional streams per connection.
    pub max_uni_streams: u32,
    /// Stream receive window size in bytes.
    pub stream_recv_window_bytes: u32,
    /// Connection receive window size in bytes.
    pub connection_recv_window_bytes: u32,
    /// Keep-alive interval in milliseconds.
    pub keep_alive_interval_ms: u64,
    /// Idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Enable 0-RTT (early data).
    pub enable_0rtt: bool,
    /// Path to TLS certificate (PEM).
    pub cert_path: String,
    /// Path to TLS private key (PEM).
    pub key_path: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:4433".to_string()
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            max_connections: 10_000,
            max_session_tickets: 10_000,
            session_ticket_ttl_secs: 86_400, // 24 hours
            max_bi_streams: 100,
            max_uni_streams: 100,
            stream_recv_window_bytes: 1_024 * 1_024, // 1MB
            connection_recv_window_bytes: 8 * 1_024 * 1_024, // 8MB
            keep_alive_interval_ms: 30_000,          // 30 seconds
            idle_timeout_ms: 60_000,                 // 60 seconds
            enable_0rtt: true,
            cert_path: "/etc/nexus/tls/cert.pem".to_string(),
            key_path: "/etc/nexus/tls/key.pem".to_string(),
        }
    }
}

impl QuicConfig {
    /// Validate configuration values.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, `Err(String)` with description if invalid.
    pub fn validate(&self) -> Result<(), String> {
        // Validate bind_addr
        if self.bind_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err("bind_addr must be a valid socket address".to_string());
        }

        // Validate max_connections
        if self.max_connections == 0 {
            return Err("max_connections must be > 0".to_string());
        }
        if self.max_connections > 100_000 {
            return Err("max_connections must be <= 100,000".to_string());
        }

        // Validate max_session_tickets
        if self.max_session_tickets == 0 {
            return Err("max_session_tickets must be > 0".to_string());
        }

        // Validate session_ticket_ttl_secs (min 1 hour)
        if self.session_ticket_ttl_secs < 3600 {
            return Err("session_ticket_ttl_secs must be >= 3600 (1 hour)".to_string());
        }

        // Validate stream limits
        if self.max_bi_streams == 0 {
            return Err("max_bi_streams must be > 0".to_string());
        }
        if self.max_uni_streams == 0 {
            return Err("max_uni_streams must be > 0".to_string());
        }

        // Validate window sizes
        if self.stream_recv_window_bytes == 0 {
            return Err("stream_recv_window_bytes must be > 0".to_string());
        }
        if self.connection_recv_window_bytes == 0 {
            return Err("connection_recv_window_bytes must be > 0".to_string());
        }
        if self.connection_recv_window_bytes < self.stream_recv_window_bytes {
            return Err(
                "connection_recv_window_bytes must be >= stream_recv_window_bytes".to_string(),
            );
        }

        // Validate timeouts
        if self.keep_alive_interval_ms == 0 {
            return Err("keep_alive_interval_ms must be > 0".to_string());
        }
        if self.idle_timeout_ms == 0 {
            return Err("idle_timeout_ms must be > 0".to_string());
        }
        if self.idle_timeout_ms <= self.keep_alive_interval_ms {
            return Err("idle_timeout_ms must be > keep_alive_interval_ms".to_string());
        }

        // Validate paths are not empty
        if self.cert_path.is_empty() {
            return Err("cert_path must not be empty".to_string());
        }
        if self.key_path.is_empty() {
            return Err("key_path must not be empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = QuicConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_max_connections() {
        let mut config = QuicConfig::default();

        config.max_connections = 0;
        assert!(config.validate().is_err());

        config.max_connections = 100_001;
        assert!(config.validate().is_err());

        config.max_connections = 10_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_timeouts() {
        let mut config = QuicConfig::default();

        // idle_timeout must be > keep_alive_interval
        config.idle_timeout_ms = config.keep_alive_interval_ms;
        assert!(config.validate().is_err());

        config.idle_timeout_ms = config.keep_alive_interval_ms + 1;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_session_ticket_ttl() {
        let mut config = QuicConfig::default();

        config.session_ticket_ttl_secs = 3599;
        assert!(config.validate().is_err());

        config.session_ticket_ttl_secs = 3600;
        assert!(config.validate().is_ok());
    }
}
