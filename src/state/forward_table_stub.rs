//! Stub ForwardTable for non-Linux platforms or when XDP feature is disabled.
//!
//! This module provides placeholder types that allow the codebase to compile
//! on platforms where XDP is not available (macOS, Windows, etc.).
//!
//! All operations return `XdpError::NotAvailable`.

use std::path::Path;
use thiserror::Error;

/// Maximum entries in the forward table (stub value)
pub const MAX_FORWARD_ENTRIES: u32 = 65536;

/// Maximum batch size for batch operations (stub value)
#[allow(dead_code)] // Reserved for API compatibility with real ForwardTable
pub const MAX_BATCH_SIZE: usize = 256;

/// XDP-specific errors (stub version)
#[derive(Debug, Error)]
pub enum XdpError {
    /// BPF map operation failed
    #[error("BPF map operation failed: {0}")]
    MapError(String),

    /// BPF map file not found
    #[error("BPF map not found at path: {path}")]
    MapNotFound { path: String },

    /// BPF map open failed
    #[error("failed to open BPF map: {0}")]
    OpenFailed(#[from] std::io::Error),

    /// Forward table is full
    #[error("forward table full: {count}/{max}")]
    TableFull { count: u32, max: u32 },

    /// Invalid SSRC (zero)
    #[error("invalid SSRC: SSRC cannot be zero")]
    InvalidSsrc,

    /// Batch size exceeded
    #[error("batch size {size} exceeds maximum {max}")]
    BatchTooLarge { size: usize, max: usize },

    /// Entry not found
    #[error("entry not found for SSRC {ssrc}")]
    NotFound { ssrc: u32 },

    /// XDP not available on this platform
    #[error("XDP not available on this platform")]
    NotAvailable,

    /// AF_XDP socket error
    #[error("AF_XDP socket error: {0}")]
    SocketError(String),

    /// XDP program load failed
    #[error("XDP program load failed: {0}")]
    LoadError(String),
}

/// Forward table entry (stub version).
///
/// This struct matches the layout of the real ForwardEntry for API compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForwardEntry {
    /// Destination MAC address (6 bytes)
    pub dst_mac: [u8; 6],
    /// Padding for alignment
    _pad: u16,
    /// Destination IP address (network byte order)
    pub dst_ip: u32,
    /// Destination UDP port (network byte order)
    pub dst_port: u16,
    /// Padding for alignment
    _pad2: u16,
    /// Output interface index for redirect
    pub ifindex: u32,
}

impl ForwardEntry {
    /// Create a new forward entry (stub).
    pub fn new(dst_mac: [u8; 6], dst_ip: u32, dst_port: u16, ifindex: u32) -> Self {
        Self {
            dst_mac,
            _pad: 0,
            dst_ip,
            dst_port,
            _pad2: 0,
            ifindex,
        }
    }

    /// Create a forward entry from IPv4 address components (stub).
    pub fn from_ipv4(
        dst_mac: [u8; 6],
        ip_octets: [u8; 4],
        port: u16,
        ifindex: u32,
    ) -> Self {
        let dst_ip = u32::from_be_bytes(ip_octets);
        let dst_port = port.to_be();
        Self::new(dst_mac, dst_ip, dst_port, ifindex)
    }
}

/// ForwardTable stub for non-Linux platforms.
///
/// All operations return `XdpError::NotAvailable`.
pub struct ForwardTable {
    _private: (),
}

impl ForwardTable {
    /// Open an existing BPF map by pinned path (stub - always fails).
    pub fn open<P: AsRef<Path>>(_path: P) -> Result<Self, XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Insert an SSRC -> destination mapping (stub - always fails).
    pub fn insert(&self, _ssrc: u32, _entry: ForwardEntry) -> Result<(), XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Remove an SSRC mapping (stub - always fails).
    pub fn remove(&self, _ssrc: u32) -> Result<(), XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Batch insert multiple SSRC -> destination mappings (stub - always fails).
    pub fn insert_batch(&self, _entries: &[(u32, ForwardEntry)]) -> Result<u32, XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Batch remove multiple SSRC mappings (stub - always fails).
    pub fn remove_batch(&self, _ssrcs: &[u32]) -> Result<u32, XdpError> {
        Err(XdpError::NotAvailable)
    }

    /// Get the current number of entries in the table (stub - always 0).
    pub fn entry_count(&self) -> u32 {
        0
    }

    /// Get the maximum number of entries allowed (stub).
    pub fn max_entries(&self) -> u32 {
        MAX_FORWARD_ENTRIES
    }

    /// Check if the table is full (stub - always false).
    pub fn is_full(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_entry_stub() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let entry = ForwardEntry::new(mac, 0x0A000001, 5000, 1);
        assert_eq!(entry.dst_mac, mac);
    }

    #[test]
    fn test_forward_table_not_available() {
        let result = ForwardTable::open("/nonexistent");
        assert!(matches!(result, Err(XdpError::NotAvailable)));
    }

    #[test]
    fn test_xdp_error_display() {
        let err = XdpError::NotAvailable;
        assert!(err.to_string().contains("not available"));
    }
}
