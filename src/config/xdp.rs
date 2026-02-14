//! XDP/BPF kernel bypass configuration.
//!
//! This module provides configuration for XDP-based packet processing,
//! which enables kernel-bypass forwarding for high-performance RTP routing.
//!
//! # Requirements Coverage
//!
//! - Requirement 19.9: XDP fallback configuration
//! - Requirement 19.10: XDP initialization configuration

use crate::config::validation::ConfigError;
use serde::{Deserialize, Serialize};

/// XDP/BPF kernel bypass configuration.
///
/// XDP (eXpress Data Path) enables packet processing at the NIC driver level,
/// bypassing the kernel network stack for significantly higher throughput.
///
/// # Platform Support
///
/// XDP is only available on Linux with appropriate kernel support (4.8+).
/// On other platforms or when disabled, the system falls back to io_uring/kqueue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpConfig {
    /// Enable XDP kernel bypass (Linux only).
    /// When false, uses io_uring/kqueue path.
    pub enabled: bool,

    /// Network interface name for XDP attachment.
    /// Example: "eth0", "ens192"
    pub interface: String,

    /// NIC queue ID to bind AF_XDP socket to.
    /// Use 0 for single-queue NICs.
    pub queue_id: u32,

    /// Path to pinned BPF forward table map.
    /// The XDP program must be loaded and this map pinned before SFU starts.
    pub forward_table_path: String,

    /// Path to pinned BPF statistics map.
    pub stats_map_path: String,

    /// Number of frames in AF_XDP UMEM.
    /// Must be power of 2. Higher values allow more in-flight packets.
    pub umem_num_frames: u32,

    /// Size of each UMEM frame in bytes.
    /// Must be >= 2048 to accommodate MTU + headroom.
    pub umem_frame_size: u32,

    /// Size of fill ring (frames available for kernel to fill).
    /// Must be power of 2.
    pub fill_ring_size: u32,

    /// Size of completion ring (frames returned after TX).
    /// Must be power of 2.
    pub comp_ring_size: u32,

    /// Size of RX ring (received packets).
    /// Must be power of 2.
    pub rx_ring_size: u32,

    /// Size of TX ring (packets to transmit).
    /// Must be power of 2.
    pub tx_ring_size: u32,

    /// Maximum packets per batch operation.
    /// Must be <= 64.
    pub batch_size: u32,

    /// Poll timeout in milliseconds for AF_XDP socket.
    pub poll_timeout_ms: u32,

    /// XDP program attach mode.
    /// - "native": Attach in native driver mode (fastest, requires driver support)
    /// - "generic": Attach in generic/SKB mode (slower, works with any driver)
    /// - "offload": Attach in hardware offload mode (requires NIC support)
    pub attach_mode: String,

    /// Network interface index for XDP forwarding.
    /// If None, will be resolved from interface name at runtime.
    /// Set explicitly when interface name resolution is not available.
    pub ifindex: Option<u32>,

    /// Automatically fall back to io_uring if XDP fails to initialize.
    /// When false, XDP initialization failure is a fatal error.
    pub fallback_on_failure: bool,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: String::new(),
            queue_id: 0,
            forward_table_path: "/sys/fs/bpf/nexus/forward_table".to_string(),
            stats_map_path: "/sys/fs/bpf/nexus/stats_map".to_string(),
            umem_num_frames: 4096,
            umem_frame_size: 4096,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
            batch_size: 64,
            poll_timeout_ms: 100,
            attach_mode: "native".to_string(),
            ifindex: None,
            fallback_on_failure: true,
        }
    }
}

impl XdpConfig {
    /// Validate the XDP configuration.
    ///
    /// # Assertions
    ///
    /// * If enabled, interface must not be empty
    /// * All ring sizes must be powers of 2
    /// * Frame size must be >= 2048
    /// * Batch size must be <= 64
    pub fn validate(&self) -> Result<(), ConfigError> {
        // If disabled, no further validation needed
        if !self.enabled {
            return Ok(());
        }

        // Interface must be specified when enabled
        if self.interface.is_empty() {
            return Err(ConfigError::invalid(
                "xdp.interface",
                "must be specified when XDP is enabled",
            ));
        }

        // Ring sizes must be powers of 2
        if !self.umem_num_frames.is_power_of_two() {
            return Err(ConfigError::invalid(
                "xdp.umem_num_frames",
                "must be power of 2",
            ));
        }
        if !self.fill_ring_size.is_power_of_two() {
            return Err(ConfigError::invalid(
                "xdp.fill_ring_size",
                "must be power of 2",
            ));
        }
        if !self.comp_ring_size.is_power_of_two() {
            return Err(ConfigError::invalid(
                "xdp.comp_ring_size",
                "must be power of 2",
            ));
        }
        if !self.rx_ring_size.is_power_of_two() {
            return Err(ConfigError::invalid(
                "xdp.rx_ring_size",
                "must be power of 2",
            ));
        }
        if !self.tx_ring_size.is_power_of_two() {
            return Err(ConfigError::invalid(
                "xdp.tx_ring_size",
                "must be power of 2",
            ));
        }

        // Frame size must be reasonable
        if self.umem_frame_size < 2048 {
            return Err(ConfigError::invalid(
                "xdp.umem_frame_size",
                "must be >= 2048",
            ));
        }
        if self.umem_frame_size > 65536 {
            return Err(ConfigError::invalid(
                "xdp.umem_frame_size",
                "must be <= 65536",
            ));
        }

        // Batch size must be reasonable
        if self.batch_size == 0 {
            return Err(ConfigError::invalid("xdp.batch_size", "must be > 0"));
        }
        if self.batch_size > 64 {
            return Err(ConfigError::invalid("xdp.batch_size", "must be <= 64"));
        }

        // Poll timeout must be reasonable
        if self.poll_timeout_ms == 0 {
            return Err(ConfigError::invalid("xdp.poll_timeout_ms", "must be > 0"));
        }
        if self.poll_timeout_ms > 10000 {
            return Err(ConfigError::invalid(
                "xdp.poll_timeout_ms",
                "must be <= 10000 (10 seconds)",
            ));
        }

        // Attach mode must be valid
        match self.attach_mode.as_str() {
            "native" | "generic" | "offload" => {}
            _ => {
                return Err(ConfigError::invalid(
                    "xdp.attach_mode",
                    "must be 'native', 'generic', or 'offload'",
                ));
            }
        }

        // Forward table path must be specified
        if self.forward_table_path.is_empty() {
            return Err(ConfigError::invalid(
                "xdp.forward_table_path",
                "must be specified when XDP is enabled",
            ));
        }

        Ok(())
    }

    /// Check if XDP is available on this platform.
    ///
    /// Returns true only on Linux with the xdp feature enabled.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    pub fn is_available() -> bool {
        true
    }

    #[cfg(not(all(target_os = "linux", feature = "xdp")))]
    pub fn is_available() -> bool {
        false
    }

    /// Create a configuration for development/testing.
    ///
    /// XDP is disabled by default in development.
    pub fn development() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create a configuration for production with XDP enabled.
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    pub fn production(interface: &str) -> Self {
        Self {
            enabled: true,
            interface: interface.to_string(),
            fallback_on_failure: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_config_default() {
        let config = XdpConfig::default();
        assert!(!config.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_xdp_config_enabled_requires_interface() {
        let mut config = XdpConfig::default();
        config.enabled = true;
        assert!(config.validate().is_err());

        config.interface = "eth0".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_xdp_config_ring_size_power_of_two() {
        let mut config = XdpConfig::default();
        config.enabled = true;
        config.interface = "eth0".to_string();
        config.fill_ring_size = 1000; // Not power of 2
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_xdp_config_batch_size_bounds() {
        let mut config = XdpConfig::default();
        config.enabled = true;
        config.interface = "eth0".to_string();
        
        config.batch_size = 0;
        assert!(config.validate().is_err());
        
        config.batch_size = 65;
        assert!(config.validate().is_err());
        
        config.batch_size = 64;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_xdp_config_attach_mode() {
        let mut config = XdpConfig::default();
        config.enabled = true;
        config.interface = "eth0".to_string();
        
        config.attach_mode = "invalid".to_string();
        assert!(config.validate().is_err());
        
        config.attach_mode = "native".to_string();
        assert!(config.validate().is_ok());
        
        config.attach_mode = "generic".to_string();
        assert!(config.validate().is_ok());
        
        config.attach_mode = "offload".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_xdp_config_development() {
        let config = XdpConfig::development();
        assert!(!config.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_xdp_config_production() {
        let config = XdpConfig::production("eth0");
        assert!(config.enabled);
        assert_eq!(config.interface, "eth0");
        assert!(config.fallback_on_failure);
        assert!(config.validate().is_ok());
    }
}
