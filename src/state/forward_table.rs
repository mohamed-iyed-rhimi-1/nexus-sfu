//! ForwardTable: BPF map wrapper for XDP packet forwarding.
//!
//! This module provides a Rust interface to the BPF hash map used by
//! the XDP program for kernel-space RTP packet forwarding.
//!
//! # Requirements Coverage
//!
//! - Requirement 19.4: ForwardTable manages BPF map entries for SSRC-to-destination mappings
//! - Requirement 19.5: ForwardTable supports batch insert and remove operations
//!
//! # TigerStyle Compliance
//!
//! - Assertions: ssrc != 0, entry_count < max_entries, batch size <= 256
//! - Fixed bounds: MAX_BATCH_SIZE = 256
//! - Explicit types: All sizes use u32/u64

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

/// Maximum entries in the forward table (must match BPF map definition)
pub const MAX_FORWARD_ENTRIES: u32 = 65536;

/// Maximum batch size for batch operations
pub const MAX_BATCH_SIZE: usize = 256;

/// XDP-specific errors
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
    OpenFailed(#[from] io::Error),

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

/// Forward table entry: destination for RTP packet forwarding.
///
/// This struct must match the layout of `struct forward_entry` in the BPF program.
/// Size: 20 bytes (with padding for alignment)
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
    /// Create a new forward entry.
    ///
    /// # Arguments
    ///
    /// * `dst_mac` - Destination MAC address
    /// * `dst_ip` - Destination IP address (network byte order)
    /// * `dst_port` - Destination UDP port (network byte order)
    /// * `ifindex` - Output interface index
    ///
    /// # Assertions
    ///
    /// * `ifindex > 0` - Interface index must be valid
    pub fn new(dst_mac: [u8; 6], dst_ip: u32, dst_port: u16, ifindex: u32) -> Self {
        assert!(ifindex > 0, "ifindex must be > 0");
        
        Self {
            dst_mac,
            _pad: 0,
            dst_ip,
            dst_port,
            _pad2: 0,
            ifindex,
        }
    }

    /// Create a forward entry from IPv4 address components.
    ///
    /// # Arguments
    ///
    /// * `dst_mac` - Destination MAC address
    /// * `ip_octets` - IPv4 address as [a, b, c, d]
    /// * `port` - Destination port (host byte order, will be converted)
    /// * `ifindex` - Output interface index
    pub fn from_ipv4(
        dst_mac: [u8; 6],
        ip_octets: [u8; 4],
        port: u16,
        ifindex: u32,
    ) -> Self {
        assert!(ifindex > 0, "ifindex must be > 0");
        
        // Convert IP to network byte order (big-endian)
        let dst_ip = u32::from_be_bytes(ip_octets);
        // Convert port to network byte order
        let dst_port = port.to_be();
        
        Self::new(dst_mac, dst_ip, dst_port, ifindex)
    }
}

/// ForwardTable manages BPF map entries for XDP packet forwarding.
///
/// This struct wraps a BPF hash map file descriptor and provides
/// safe Rust methods for inserting, removing, and batch-updating
/// SSRC-to-destination mappings.
///
/// # Thread Safety
///
/// ForwardTable is thread-safe. The entry_count is tracked with atomic
/// operations, and BPF map operations are inherently thread-safe.
pub struct ForwardTable {
    /// BPF map file descriptor
    map_fd: RawFd,
    /// File handle to keep the map open
    _file: File,
    /// Current number of entries (atomic for thread safety)
    entry_count: AtomicU32,
    /// Maximum entries allowed
    max_entries: u32,
}

impl ForwardTable {
    /// Open an existing BPF map by pinned path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the pinned BPF map (e.g., "/sys/fs/bpf/forward_table")
    ///
    /// # Assertions
    ///
    /// * Path must exist and be a valid BPF map
    ///
    /// # Errors
    ///
    /// Returns `XdpError::MapNotFound` if the path doesn't exist.
    /// Returns `XdpError::OpenFailed` if the file can't be opened.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, XdpError> {
        let path_ref = path.as_ref();
        
        // Assertion: path must exist
        if !path_ref.exists() {
            return Err(XdpError::MapNotFound {
                path: path_ref.display().to_string(),
            });
        }
        
        let file = File::open(path_ref)?;
        let map_fd = file.as_raw_fd();
        
        // Assertion: file descriptor must be valid
        assert!(map_fd >= 0, "BPF map file descriptor must be >= 0");
        
        Ok(Self {
            map_fd,
            _file: file,
            entry_count: AtomicU32::new(0),
            max_entries: MAX_FORWARD_ENTRIES,
        })
    }

    /// Create a ForwardTable from an existing file descriptor.
    ///
    /// # Safety
    ///
    /// The caller must ensure the file descriptor is a valid BPF map.
    ///
    /// # Arguments
    ///
    /// * `fd` - BPF map file descriptor
    /// * `file` - File handle to keep the map open
    /// * `max_entries` - Maximum entries in the map
    pub fn from_fd(fd: RawFd, file: File, max_entries: u32) -> Self {
        assert!(fd >= 0, "BPF map file descriptor must be >= 0");
        assert!(max_entries > 0, "max_entries must be > 0");
        
        Self {
            map_fd: fd,
            _file: file,
            entry_count: AtomicU32::new(0),
            max_entries,
        }
    }

    /// Insert an SSRC -> destination mapping.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC (must be non-zero)
    /// * `entry` - Destination information
    ///
    /// # Assertions
    ///
    /// * `ssrc != 0` - SSRC cannot be zero
    /// * `entry_count < max_entries` - Table must not be full
    ///
    /// # Errors
    ///
    /// Returns `XdpError::InvalidSsrc` if SSRC is zero.
    /// Returns `XdpError::TableFull` if the table is at capacity.
    /// Returns `XdpError::MapError` if the BPF map update fails.
    pub fn insert(&self, ssrc: u32, entry: ForwardEntry) -> Result<(), XdpError> {
        // Assertion: SSRC must be non-zero
        if ssrc == 0 {
            return Err(XdpError::InvalidSsrc);
        }
        
        // Assertion: table must not be full
        let count = self.entry_count.load(Ordering::Relaxed);
        if count >= self.max_entries {
            return Err(XdpError::TableFull {
                count,
                max: self.max_entries,
            });
        }
        
        // Perform BPF map update
        self.bpf_map_update(ssrc, &entry)?;
        
        // Increment entry count
        self.entry_count.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }

    /// Remove an SSRC mapping.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - RTP SSRC to remove
    ///
    /// # Errors
    ///
    /// Returns `XdpError::InvalidSsrc` if SSRC is zero.
    /// Returns `XdpError::NotFound` if the SSRC doesn't exist.
    /// Returns `XdpError::MapError` if the BPF map delete fails.
    pub fn remove(&self, ssrc: u32) -> Result<(), XdpError> {
        // Assertion: SSRC must be non-zero
        if ssrc == 0 {
            return Err(XdpError::InvalidSsrc);
        }
        
        // Perform BPF map delete
        self.bpf_map_delete(ssrc)?;
        
        // Decrement entry count (saturating to avoid underflow)
        let _ = self.entry_count.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |x| if x > 0 { Some(x - 1) } else { Some(0) },
        );
        
        Ok(())
    }

    /// Batch insert multiple SSRC -> destination mappings.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of (SSRC, ForwardEntry) pairs
    ///
    /// # Assertions
    ///
    /// * `entries.len() <= 256` - Batch size must not exceed maximum
    /// * All SSRCs must be non-zero
    ///
    /// # Returns
    ///
    /// Number of entries successfully inserted.
    ///
    /// # Errors
    ///
    /// Returns `XdpError::BatchTooLarge` if batch exceeds maximum size.
    pub fn insert_batch(&self, entries: &[(u32, ForwardEntry)]) -> Result<u32, XdpError> {
        // Assertion: batch size must not exceed maximum
        if entries.len() > MAX_BATCH_SIZE {
            return Err(XdpError::BatchTooLarge {
                size: entries.len(),
                max: MAX_BATCH_SIZE,
            });
        }
        
        let mut inserted = 0u32;
        
        // Insert each entry individually
        // WHY: BPF batch operations require specific kernel support;
        // falling back to individual inserts ensures compatibility
        for (ssrc, entry) in entries {
            // Skip zero SSRCs
            if *ssrc == 0 {
                continue;
            }
            
            // Check capacity
            let count = self.entry_count.load(Ordering::Relaxed);
            if count >= self.max_entries {
                break;
            }
            
            // Try to insert
            if self.bpf_map_update(*ssrc, entry).is_ok() {
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                inserted += 1;
            }
        }
        
        Ok(inserted)
    }

    /// Batch remove multiple SSRC mappings.
    ///
    /// # Arguments
    ///
    /// * `ssrcs` - Slice of SSRCs to remove
    ///
    /// # Assertions
    ///
    /// * `ssrcs.len() <= 256` - Batch size must not exceed maximum
    ///
    /// # Returns
    ///
    /// Number of entries successfully removed.
    ///
    /// # Errors
    ///
    /// Returns `XdpError::BatchTooLarge` if batch exceeds maximum size.
    pub fn remove_batch(&self, ssrcs: &[u32]) -> Result<u32, XdpError> {
        // Assertion: batch size must not exceed maximum
        if ssrcs.len() > MAX_BATCH_SIZE {
            return Err(XdpError::BatchTooLarge {
                size: ssrcs.len(),
                max: MAX_BATCH_SIZE,
            });
        }
        
        let mut removed = 0u32;
        
        // Remove each entry individually
        for ssrc in ssrcs {
            // Skip zero SSRCs
            if *ssrc == 0 {
                continue;
            }
            
            // Try to remove
            if self.bpf_map_delete(*ssrc).is_ok() {
                let _ = self.entry_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |x| if x > 0 { Some(x - 1) } else { Some(0) },
                );
                removed += 1;
            }
        }
        
        Ok(removed)
    }

    /// Get the current number of entries in the table.
    pub fn entry_count(&self) -> u32 {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Get the maximum number of entries allowed.
    pub fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Check if the table is full.
    pub fn is_full(&self) -> bool {
        self.entry_count.load(Ordering::Relaxed) >= self.max_entries
    }

    /// Get the BPF map file descriptor.
    pub fn map_fd(&self) -> RawFd {
        self.map_fd
    }

    // ========================================================================
    // Private BPF Map Operations
    // ========================================================================

    /// Update a BPF map entry using the bpf() syscall.
    fn bpf_map_update(&self, ssrc: u32, entry: &ForwardEntry) -> Result<(), XdpError> {
        // Use libc to call bpf() syscall for map update
        // BPF_MAP_UPDATE_ELEM = 2
        const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
        const BPF_ANY: u64 = 0;
        
        #[repr(C)]
        struct BpfMapUpdateAttr {
            map_fd: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        
        let attr = BpfMapUpdateAttr {
            map_fd: self.map_fd as u32,
            key: &ssrc as *const u32 as u64,
            value: entry as *const ForwardEntry as u64,
            flags: BPF_ANY,
        };
        
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_UPDATE_ELEM,
                &attr as *const BpfMapUpdateAttr,
                std::mem::size_of::<BpfMapUpdateAttr>(),
            )
        };
        
        if ret < 0 {
            let err = io::Error::last_os_error();
            return Err(XdpError::MapError(format!(
                "BPF map update failed for SSRC {}: {}",
                ssrc, err
            )));
        }
        
        Ok(())
    }

    /// Delete a BPF map entry using the bpf() syscall.
    fn bpf_map_delete(&self, ssrc: u32) -> Result<(), XdpError> {
        // BPF_MAP_DELETE_ELEM = 3
        const BPF_MAP_DELETE_ELEM: libc::c_int = 3;
        
        #[repr(C)]
        struct BpfMapDeleteAttr {
            map_fd: u32,
            key: u64,
            _value: u64,
            _flags: u64,
        }
        
        let attr = BpfMapDeleteAttr {
            map_fd: self.map_fd as u32,
            key: &ssrc as *const u32 as u64,
            _value: 0,
            _flags: 0,
        };
        
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_DELETE_ELEM,
                &attr as *const BpfMapDeleteAttr,
                std::mem::size_of::<BpfMapDeleteAttr>(),
            )
        };
        
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Err(XdpError::NotFound { ssrc });
            }
            return Err(XdpError::MapError(format!(
                "BPF map delete failed for SSRC {}: {}",
                ssrc, err
            )));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_entry_new() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let entry = ForwardEntry::new(mac, 0x0A000001, 5000u16.to_be(), 1);
        
        assert_eq!(entry.dst_mac, mac);
        assert_eq!(entry.dst_ip, 0x0A000001);
        assert_eq!(entry.ifindex, 1);
    }

    #[test]
    fn test_forward_entry_from_ipv4() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let entry = ForwardEntry::from_ipv4(mac, [10, 0, 0, 1], 5000, 1);
        
        assert_eq!(entry.dst_mac, mac);
        // 10.0.0.1 in network byte order
        assert_eq!(entry.dst_ip, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(entry.dst_port, 5000u16.to_be());
        assert_eq!(entry.ifindex, 1);
    }

    #[test]
    fn test_forward_entry_size() {
        // Verify struct size matches BPF definition (20 bytes)
        assert_eq!(std::mem::size_of::<ForwardEntry>(), 20);
    }

    #[test]
    fn test_xdp_error_display() {
        let err = XdpError::TableFull { count: 100, max: 100 };
        assert!(err.to_string().contains("100"));
        
        let err = XdpError::InvalidSsrc;
        assert!(err.to_string().contains("zero"));
        
        let err = XdpError::BatchTooLarge { size: 300, max: 256 };
        assert!(err.to_string().contains("300"));
        assert!(err.to_string().contains("256"));
    }

    #[test]
    #[should_panic(expected = "ifindex must be > 0")]
    fn test_forward_entry_invalid_ifindex() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let _ = ForwardEntry::new(mac, 0x0A000001, 5000, 0);
    }
}
